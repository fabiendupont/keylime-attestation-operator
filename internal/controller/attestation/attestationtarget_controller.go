/*
Copyright 2023 Keylime Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package attestation

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

const (
	conditionCollectorReady = "CollectorReady"
	conditionTargetReady    = "Ready"

	// caFingerprintAnnotation marks a TLS secret with the fingerprint of the
	// CA that issued the certificate, so that certificates are re-issued
	// when the CA changes (same mechanism as the operand server cert).
	caFingerprintAnnotation = "attestation.keylime.dev/ca-fingerprint"
)

// AttestationTargetReconciler reconciles an AttestationTarget object: it
// provisions a collector Deployment (with a swtpm sidecar) that attests a
// machine's BMC out-of-band and reports to the Keylime CR the target
// references. It also mirrors the attestation state of the Agent CR the
// collector feeds into the target's status.
type AttestationTargetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Mapper is used to detect whether the BaremetalHost CRDs are
	// installed (for the light MachineAPI integration).
	Mapper meta.RESTMapper
	// Recorder emits Kubernetes Events on the mapped nodes whenever the
	// AttestationFailed node condition is set or cleared.
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=attestationtargets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=attestationtargets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=attestationtargets/finalizers,verbs=update
//+kubebuilder:rbac:groups=metal3.io,resources=baremetalhosts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=nodes/status,verbs=get;patch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile moves the cluster towards the desired state of an
// AttestationTarget CR: a collector Deployment and its swtpm state PVC, a
// client certificate minted from the referenced Keylime CR's CA, and the BMC
// credential config, all owned by the CR.
func (r *AttestationTargetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var target attestationv1alpha1.AttestationTarget
	if err := r.Get(ctx, req.NamespacedName, &target); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// resolve the Keylime CR the collector reports to
	keylime, err := r.resolveKeylime(ctx, &target)
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, err)
	}

	// its service endpoints (only set once the operands are deployed)
	verifierHost, verifierPort, registrarHost, err := keylimeEndpoints(keylime)
	if err != nil {
		r.setTargetConditionFalse(&target, conditionTargetReady, "KeylimeNotReady", err.Error())
		return ctrl.Result{RequeueAfter: keylimeRetryInterval}, r.updateStatus(ctx, &target, nil)
	}

	// the agent UUID: explicit or derived from the namespaced name
	agentUUID, err := targetAgentUUID(&target)
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, err)
	}
	target.Status.AgentUUID = agentUUID

	// the CA of the Keylime trust domain (BYO or operator-generated)
	caCert, caKey, fingerprint, err := r.keylimeCA(ctx, keylime)
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, err)
	}

	// a client certificate for the collector, signed by that CA: the
	// verifier and registrar trust it by construction
	if err := r.reconcileClientCert(ctx, &target, caCert, caKey, fingerprint); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, err)
	}

	// BMC credentials from the referenced secret, rendered as a keylime
	// config file in an owned secret (the collector reads them via
	// KEYLIME_OOB_CONFIG, keeping them out of the pod spec)
	credentials, err := r.bmcCredentials(ctx, &target)
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, err)
	}
	if credentials != nil {
		configSecret := renderCollectorConfigSecret(&target, *credentials)
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, configSecret, func() error {
			rendered := renderCollectorConfigSecret(&target, *credentials)
			configSecret.StringData = rendered.StringData
			return controllerutil.SetControllerReference(&target, configSecret, r.Scheme)
		}); err != nil {
			return ctrl.Result{}, r.updateStatus(ctx, &target, fmt.Errorf("unable to reconcile the collector config secret: %w", err))
		}
	}

	// the swtpm state PVC (the collector's TPM identity)
	pvc := renderSwtpmStatePVC(&target)
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, pvc, func() error {
		rendered := renderSwtpmStatePVC(&target)
		pvc.Spec.AccessModes = rendered.Spec.AccessModes
		pvc.Spec.Resources = rendered.Spec.Resources
		return controllerutil.SetControllerReference(&target, pvc, r.Scheme)
	}); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, fmt.Errorf("unable to reconcile the swtpm state PVC: %w", err))
	}

	// the collector Deployment (Recreate strategy, service links off)
	deployment := renderCollectorDeployment(&target, collectorParams{
		AgentUUID:     agentUUID,
		VerifierHost:  verifierHost,
		VerifierPort:  verifierPort,
		RegistrarHost: registrarHost,
		Credentials:   credentials,
		BMCCAFilename: bmcCAFilename(&target),
		CertChainKey:  certChainKey(&target),
	})
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		rendered := renderCollectorDeployment(&target, collectorParams{
			AgentUUID:     agentUUID,
			VerifierHost:  verifierHost,
			VerifierPort:  verifierPort,
			RegistrarHost: registrarHost,
			Credentials:   credentials,
			BMCCAFilename: bmcCAFilename(&target),
			CertChainKey:  certChainKey(&target),
		})
		// note: the selector is immutable; the labels it is built from are
		// stable for a given target so the rendered one always matches
		deployment.Spec.Strategy = rendered.Spec.Strategy
		deployment.Spec.Template = rendered.Spec.Template
		return controllerutil.SetControllerReference(&target, deployment, r.Scheme)
	}); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &target, fmt.Errorf("unable to reconcile the collector deployment: %w", err))
	}

	// light MachineAPI integration: match the BMC against BaremetalHosts
	// when the CRDs are installed (skipped silently otherwise), falling
	// back to the manual spec.nodes mapping
	if err := r.reconcileMachineMapping(ctx, &target); err != nil {
		// the mapping is informational only: do not fail the reconcile
		logf.FromContext(ctx).Error(err, "BaremetalHost mapping failed")
		target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
			Available: false,
			Reason:    fmt.Sprintf("BaremetalHost mapping failed: %v", err),
		}
		applyManualMapping(&target)
	}

	// mirror the Agent CR the collector feeds into the status
	r.mirrorAgent(ctx, &target)

	// compute the target's health from the mirrored attestation state and
	// set/clear the AttestationFailed node condition on the mapped nodes
	r.reconcileNodeConditions(ctx, &target)

	// conditions from the observed state
	reconcileErr := r.updateTargetConditions(ctx, &target)

	// requeue on a timer of our own so staleness is detected even when no
	// watched resource changes
	return ctrl.Result{RequeueAfter: recheckInterval(&target)}, r.updateStatus(ctx, &target, reconcileErr)
}

const keylimeRetryInterval = 10 * time.Second

// resolveKeylime returns the Keylime CR the target references: the named one,
// or the single one in the namespace when no name is given.
func (r *AttestationTargetReconciler) resolveKeylime(ctx context.Context, target *attestationv1alpha1.AttestationTarget) (*attestationv1alpha1.Keylime, error) {
	if ref := target.Spec.KeylimeRef; ref != "" {
		keylime := &attestationv1alpha1.Keylime{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: ref}, keylime); err != nil {
			return nil, fmt.Errorf("unable to get the referenced Keylime CR %s: %w", ref, err)
		}
		return keylime, nil
	}

	var list attestationv1alpha1.KeylimeList
	if err := r.List(ctx, &list, client.InNamespace(target.Namespace)); err != nil {
		return nil, fmt.Errorf("unable to list the Keylime CRs in namespace %s: %w", target.Namespace, err)
	}
	switch len(list.Items) {
	case 1:
		return &list.Items[0], nil
	case 0:
		return nil, fmt.Errorf("no Keylime CR found in namespace %s and spec.keylimeRef is unset", target.Namespace)
	default:
		return nil, fmt.Errorf("several Keylime CRs found in namespace %s and spec.keylimeRef is unset", target.Namespace)
	}
}

// keylimeEndpoints extracts the verifier and registrar service hostnames
// (and the verifier port) from the Keylime CR's status. The registrar is
// always reached over its fixed plain HTTP port (8890): the collector
// registers with it as a keylime agent would.
func keylimeEndpoints(keylime *attestationv1alpha1.Keylime) (verifierHost, verifierPort, registrarHost string, err error) {
	if keylime.Status.VerifierService == "" || keylime.Status.RegistrarService == "" {
		return "", "", "", fmt.Errorf("the Keylime CR %s does not report service endpoints yet", keylime.Name)
	}
	verifierURL, err := url.Parse(keylime.Status.VerifierService)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to parse the verifier service URL %q: %w", keylime.Status.VerifierService, err)
	}
	registrarURL, err := url.Parse(keylime.Status.RegistrarService)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to parse the registrar service URL %q: %w", keylime.Status.RegistrarService, err)
	}
	verifierPort = verifierURL.Port()
	if verifierPort == "" {
		verifierPort = "8881"
	}
	return verifierURL.Hostname(), verifierPort, registrarURL.Hostname(), nil
}

// targetAgentUUID returns the agent UUID of the target: the explicitly
// configured one, or the deterministic UUIDv5 derived from the namespaced
// name (stable across collector reinstalls).
func targetAgentUUID(target *attestationv1alpha1.AttestationTarget) (string, error) {
	if explicit := target.Spec.AgentUUID; explicit != "" {
		if err := validateAgentUUID(explicit); err != nil {
			return "", err
		}
		return strings.ToLower(explicit), nil
	}
	return deriveAgentUUID(target.Namespace, target.Name), nil
}

// keylimeCA returns the CA certificate, key and fingerprint of the Keylime
// trust domain: the BYO CA secret when configured, the operator-generated
// one otherwise (same resolution as the Keylime controller itself).
func (r *AttestationTargetReconciler) keylimeCA(ctx context.Context, keylime *attestationv1alpha1.Keylime) ([]byte, []byte, string, error) {
	name := keylime.Spec.TLS.CASecretRef
	if name == "" {
		name = keylime.Name + "-ca"
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: name}, secret); err != nil {
		return nil, nil, "", fmt.Errorf("unable to get the CA secret %s of the Keylime CR %s: %w", name, keylime.Name, err)
	}
	caCert, ok := secret.Data["ca.crt"]
	if !ok {
		return nil, nil, "", fmt.Errorf("the CA secret %s does not contain a %q key", name, "ca.crt")
	}
	caKey, ok := secret.Data["ca.key"]
	if !ok {
		return nil, nil, "", fmt.Errorf("the CA secret %s does not contain a %q key", name, "ca.key")
	}
	fingerprint, err := caFingerprint(caCert)
	if err != nil {
		return nil, nil, "", err
	}
	return caCert, caKey, fingerprint, nil
}

// reconcileClientCert mints the collector's client certificate, signed by
// the Keylime CR's CA, and keeps it in an owned secret mounted into the
// collector pod. The certificate is re-issued when the CA changes.
func (r *AttestationTargetReconciler) reconcileClientCert(ctx context.Context, target *attestationv1alpha1.AttestationTarget, caCert, caKey []byte, fingerprint string) error {
	secret := &corev1.Secret{ObjectMeta: collectorObjectMeta(target, collectorClientTLSSecretName(target))}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Annotations == nil || secret.Annotations[caFingerprintAnnotation] != fingerprint ||
			len(secret.Data[collectorCertFile]) == 0 || len(secret.Data[collectorKeyFile]) == 0 {
			// the collector's identity: the CA chains it to the Keylime
			// trust domain, the organizational unit names the target
			certPEM, keyPEM, err := generateClientCert(caCert, caKey, target.Namespace+"/"+target.Name)
			if err != nil {
				return err
			}
			secret.Data = map[string][]byte{
				collectorCertFile: certPEM,
				collectorKeyFile:  keyPEM,
				collectorCAFile:   caCert,
			}
			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}
			secret.Annotations[caFingerprintAnnotation] = fingerprint
		}
		return controllerutil.SetControllerReference(target, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("unable to reconcile the collector client certificate secret: %w", err)
	}
	logf.FromContext(ctx).Info("collector client certificate secret reconciled", "operation", op)
	return nil
}

// bmcCredentials reads the BMC credentials from the referenced secret.
func (r *AttestationTargetReconciler) bmcCredentials(ctx context.Context, target *attestationv1alpha1.AttestationTarget) (*bmcCredentials, error) {
	ref := target.Spec.BMC.CredentialsSecretRef
	if ref == "" {
		return nil, nil
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: ref}, secret); err != nil {
		return nil, fmt.Errorf("unable to get the BMC credentials secret %s: %w", ref, err)
	}
	username, ok := secret.Data["username"]
	if !ok {
		return nil, fmt.Errorf("the BMC credentials secret %s does not contain a %q key", ref, "username")
	}
	password, ok := secret.Data["password"]
	if !ok {
		return nil, fmt.Errorf("the BMC credentials secret %s does not contain a %q key", ref, "password")
	}
	return &bmcCredentials{Username: string(username), Password: string(password)}, nil
}

// bmcCAFilename returns the file name of the mounted BMC CA certificate, or
// an empty string when the target does not reference one.
func bmcCAFilename(target *attestationv1alpha1.AttestationTarget) string {
	if ref := target.Spec.BMC.CACertRef; ref != nil {
		return sanitize(ref.Key)
	}
	return ""
}

// certChainKey returns the key of the referenced SPDM certificate chain
// blob, or an empty string when the target does not reference one.
func certChainKey(target *attestationv1alpha1.AttestationTarget) string {
	if ref := target.Spec.SPDMCertChain; ref != nil && ref.SecretRef != "" && ref.Key != "" {
		return ref.Key
	}
	return ""
}

// baremetalHostGVK is the GVK of the Metal3 BaremetalHost resource matched
// against the target's BMC in the light MachineAPI integration.
var baremetalHostGVK = schema.GroupVersionKind{Group: "metal3.io", Version: "v1alpha1", Kind: "BaremetalHost"}

// reconcileMachineMapping matches the target's BMC host against the
// BaremetalHosts of the cluster and records the result in the status. When
// the BaremetalHost CRDs are not installed (e.g. on a single-node cluster
// without any bare-metal workers) the mapping is marked unavailable and the
// reconcile continues; the manual spec.nodes fallback is then applied so
// that the mapping can still resolve nodes.
func (r *AttestationTargetReconciler) reconcileMachineMapping(ctx context.Context, target *attestationv1alpha1.AttestationTarget) error {
	if err := r.reconcileBMHMapping(ctx, target); err != nil {
		return err
	}
	applyManualMapping(target)
	return nil
}

// reconcileBMHMapping is the MachineAPI part of the mapping: matching the
// target's BMC host against the cluster's BaremetalHosts.
func (r *AttestationTargetReconciler) reconcileBMHMapping(ctx context.Context, target *attestationv1alpha1.AttestationTarget) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(baremetalHostGVK)
	if err := r.List(ctx, list); err != nil {
		if meta.IsNoMatchError(err) || runtime.IsNotRegisteredError(err) {
			target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
				Available: false,
				Reason:    "the BaremetalHost CRDs are not installed on this cluster",
			}
			return nil
		}
		return err
	}

	// match the host part (without the port) against the BMH BMC addresses
	host := target.Spec.BMC.Host
	if idx := strings.LastIndex(host, ":"); idx != -1 && !strings.Contains(host, "]") {
		host = host[:idx]
	}
	host = strings.Trim(host, "[]")

	nodeRefs := []attestationv1alpha1.AttestationNodeRef{}
	for i := range list.Items {
		bmh := &list.Items[i]
		address, _, _ := unstructured.NestedString(bmh.Object, "spec", "bmc", "address")
		if address == "" || !strings.Contains(address, host) {
			continue
		}
		nodeRefs = append(nodeRefs, attestationv1alpha1.AttestationNodeRef{
			BaremetalHost: bmh.GetName(),
			Node:          bmhNodeName(bmh),
		})
	}
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: true,
		Source:    mappingSourceMachineAPI,
		NodeRefs:  nodeRefs,
	}
	return nil
}

// applyManualMapping resolves the mapping via the admin-provided
// spec.nodes fallback when the MachineAPI mapping yielded no node, so that
// attestation targets on clusters without the MachineAPI (management
// clusters attesting externally-managed bare metal) still map to nodes.
func applyManualMapping(target *attestationv1alpha1.AttestationTarget) {
	if len(target.Spec.Nodes) == 0 {
		return
	}
	if mapping := target.Status.MachineMapping; mapping != nil {
		for _, ref := range mapping.NodeRefs {
			if ref.Node != "" {
				return // the MachineAPI mapping already resolved nodes
			}
		}
	}
	nodeRefs := make([]attestationv1alpha1.AttestationNodeRef, 0, len(target.Spec.Nodes))
	for _, node := range target.Spec.Nodes {
		nodeRefs = append(nodeRefs, attestationv1alpha1.AttestationNodeRef{Node: node})
	}
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: true,
		Source:    mappingSourceManual,
		NodeRefs:  nodeRefs,
	}
}

// bmhNodeName resolves the node provisioned from a BaremetalHost when it is
// recorded on the host (Metal3 labels the BMH with the Metal3Machine during
// provisioning; deeper Machine-based resolution is deferred to the
// node-conditions phase).
func bmhNodeName(bmh *unstructured.Unstructured) string {
	labels, _, _ := unstructured.NestedStringMap(bmh.Object, "metadata", "labels")
	if labels == nil {
		return ""
	}
	for _, key := range []string{"metal3.io/node", "metal3.io/node-name"} {
		if node := labels[key]; node != "" {
			return node
		}
	}
	return ""
}

// mirrorAgent copies the attestation summary of the Agent CR the collector
// feeds (named by the agent UUID, cluster-scoped) into the target's status.
func (r *AttestationTargetReconciler) mirrorAgent(ctx context.Context, target *attestationv1alpha1.AttestationTarget) {
	agent := &attestationv1alpha1.Agent{}
	if err := r.Get(ctx, types.NamespacedName{Name: target.Status.AgentUUID}, agent); err != nil {
		return
	}
	target.Status.AgentRef = agent.Name
	target.Status.AgentPhase = string(agent.Status.Phase)
	target.Status.VerifierState = ""
	target.Status.AttestationStage = ""
	target.Status.AttestationEvaluation = ""
	target.Status.Components = nil
	if agent.Status.Verifier != nil {
		target.Status.VerifierState = agent.Status.Verifier.OperationalState
		target.Status.AttestationStage = agent.Status.Verifier.AttestationStage
		target.Status.AttestationEvaluation = agent.Status.Verifier.AttestationEvaluation
		target.Status.Components = agent.Status.Verifier.AttestationComponents
		if !agent.Status.Verifier.LastSuccessfulAttestation.IsZero() {
			successful := agent.Status.Verifier.LastSuccessfulAttestation
			// a new successful attestation means the collector completed a
			// new cycle since we last looked
			if target.Status.LastSuccessfulAttestation == nil || successful.After(target.Status.LastSuccessfulAttestation.Time) {
				now := metav1.Now()
				target.Status.LastCollectionTimestamp = &now
			}
			target.Status.LastSuccessfulAttestation = &successful
		}
	}
}

// updateTargetConditions sets the CollectorReady and Ready conditions from
// the observed state of the collector Deployment, and returns an error when
// the target is not ready (so that the condition is persisted before
// retrying).
func (r *AttestationTargetReconciler) updateTargetConditions(ctx context.Context, target *attestationv1alpha1.AttestationTarget) error {
	now := metav1.Now()

	deployment := &appsv1.Deployment{}
	collectorReady := false
	if err := r.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: collectorDeploymentName(target)}, deployment); err == nil {
		collectorReady = deployment.Status.ReadyReplicas > 0
	}
	r.setTargetCondition(target, conditionCollectorReady, collectorReady, now)

	// the target is ready when its collector runs and the agent it feeds is
	// in the verifying loop
	agentVerifying := target.Status.AgentPhase == string(attestationv1alpha1.AgentVerifying)
	ready := collectorReady && agentVerifying
	condition := metav1.Condition{
		Type:               conditionTargetReady,
		Status:             metav1.ConditionFalse,
		Reason:             "NotReady",
		Message:            "The collector is not ready or the agent is not verifying yet",
		LastTransitionTime: now,
		ObservedGeneration: target.Generation,
	}
	if ready {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Ready"
		condition.Message = "The collector is ready and the agent is verifying"
	}
	meta.SetStatusCondition(&target.Status.Conditions, condition)

	if !ready {
		return fmt.Errorf("the collector or the agent of target %s is not ready yet", target.Name)
	}
	return nil
}

func (r *AttestationTargetReconciler) setTargetConditionFalse(target *attestationv1alpha1.AttestationTarget, conditionType, reason, message string) {
	meta.SetStatusCondition(&target.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: target.Generation,
	})
}

func (r *AttestationTargetReconciler) setTargetCondition(target *attestationv1alpha1.AttestationTarget, conditionType string, status bool, now metav1.Time) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             metav1.ConditionFalse,
		Reason:             "NotReady",
		Message:            "The collector is not ready",
		LastTransitionTime: now,
		ObservedGeneration: target.Generation,
	}
	if status {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Ready"
		condition.Message = "The collector is ready"
	}
	meta.SetStatusCondition(&target.Status.Conditions, condition)
}

// updateStatus persists the status if it changed.
func (r *AttestationTargetReconciler) updateStatus(ctx context.Context, target *attestationv1alpha1.AttestationTarget, reconcileErr error) error {
	l := logf.FromContext(ctx)
	if reconcileErr != nil {
		meta.SetStatusCondition(&target.Status.Conditions, metav1.Condition{
			Type:               conditionTargetReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ReconcileError",
			Message:            reconcileErr.Error(),
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: target.Generation,
		})
	}
	var current attestationv1alpha1.AttestationTarget
	if err := r.Get(ctx, types.NamespacedName{Namespace: target.Namespace, Name: target.Name}, &current); err != nil {
		return err
	}
	if !reflect.DeepEqual(current.Status, target.Status) {
		if err := r.Status().Update(ctx, target); err != nil {
			l.Error(err, "status update failed")
			return err
		}
	}
	return reconcileErr
}

// SetupWithManager sets up the controller with the manager. Next to the
// resources it owns, the controller watches the Agent CRs (to mirror
// attestation progress into the target status) and the Keylime CRs (whose
// service endpoints and CA the collectors depend on).
func (r *AttestationTargetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("attestation-operator")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&attestationv1alpha1.AttestationTarget{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Watches(&attestationv1alpha1.Agent{}, handler.EnqueueRequestsFromMapFunc(r.targetsForAgent)).
		Watches(&attestationv1alpha1.Keylime{}, handler.EnqueueRequestsFromMapFunc(r.targetsForKeylime)).
		Complete(r)
}

// targetsForAgent maps an Agent CR event to the AttestationTargets whose
// agent UUID (explicit or derived) is the agent's name.
func (r *AttestationTargetReconciler) targetsForAgent(ctx context.Context, obj client.Object) []reconcile.Request {
	var targets attestationv1alpha1.AttestationTargetList
	if err := r.List(ctx, &targets); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for i := range targets.Items {
		target := &targets.Items[i]
		uuid, err := targetAgentUUID(target)
		if err != nil || uuid != obj.GetName() {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: target.Namespace,
			Name:      target.Name,
		}})
	}
	return requests
}

// targetsForKeylime maps a Keylime CR event to the AttestationTargets in its
// namespace.
func (r *AttestationTargetReconciler) targetsForKeylime(ctx context.Context, obj client.Object) []reconcile.Request {
	var targets attestationv1alpha1.AttestationTargetList
	if err := r.List(ctx, &targets, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var requests []reconcile.Request
	for i := range targets.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: targets.Items[i].Namespace,
			Name:      targets.Items[i].Name,
		}})
	}
	return requests
}
