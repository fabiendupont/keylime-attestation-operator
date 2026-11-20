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
	"net"
	"reflect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

const (
	keylimeFinalizer = "attestation.keylime.dev/keylime"

	conditionVerifierReady  = "VerifierReady"
	conditionRegistrarReady = "RegistrarReady"
	conditionAgentReady     = "AgentReady"
	conditionReady          = "Ready"

	defaultVerifierImage  = "quay.io/fdupont-redhat/keylime-verifier:master-oob"
	defaultRegistrarImage = "quay.io/fdupont-redhat/keylime-registrar:master-oob"
	defaultAgentImage     = "quay.io/keylime/keylime_agent:master"
)

// KeylimeReconciler reconciles a Keylime object
type KeylimeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=keylimes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=keylimes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=attestation.keylime.dev,resources=keylimes/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services;configmaps;secrets;persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete

// Reconcile moves the cluster towards the desired state of a Keylime CR: a
// verifier StatefulSet with a PVC, a registrar Deployment with a PVC, an
// optional agent DaemonSet, services, configuration and TLS material, all
// owned by the CR.
func (r *KeylimeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	var keylime attestationv1alpha1.Keylime
	if err := r.Get(ctx, req.NamespacedName, &keylime); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// resolve defaults that are easier to handle in code than in CRD defaults
	if keylime.Spec.Images.VerifierImage == "" {
		keylime.Spec.Images.VerifierImage = defaultVerifierImage
	}
	if keylime.Spec.Images.RegistrarImage == "" {
		keylime.Spec.Images.RegistrarImage = defaultRegistrarImage
	}
	if keylime.Spec.Images.AgentImage == "" {
		keylime.Spec.Images.AgentImage = defaultAgentImage
	}

	// CA material (brought by the user or generated once and kept)
	caCert, caKey, caFingerprint, err := r.reconcileCA(ctx, &keylime)
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// server certificate with SANs matching the service DNS names
	if err := r.reconcileServerCert(ctx, &keylime, caCert, caKey, caFingerprint); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// database URLs
	verifierDB, registrarDB, err := r.databaseURLs(ctx, &keylime)
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// configuration
	if err := r.reconcileConfigMaps(ctx, &keylime, verifierDB, registrarDB); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// services
	if err := r.reconcileServices(ctx, &keylime); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// registrar
	if err := r.reconcileRegistrar(ctx, &keylime); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// verifier
	if err := r.reconcileVerifier(ctx, &keylime); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	// agent (opt-in)
	if err := r.reconcileAgent(ctx, &keylime); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &keylime, err)
	}

	keylime.Status.VerifierService = fmt.Sprintf("https://%s-verifier.%s.svc:8881", keylime.Name, keylime.Namespace)
	keylime.Status.RegistrarService = fmt.Sprintf("https://%s-registrar.%s.svc:8891", keylime.Name, keylime.Namespace)
	keylime.Status.CAFingerprint = caFingerprint

	return ctrl.Result{}, r.updateStatus(ctx, &keylime, r.updateConditions(ctx, &keylime))
}

// updateConditions sets the per-operand conditions from the observed state of
// the workloads and returns an error if an operand is not ready (so that the
// condition is persisted before retrying).
func (r *KeylimeReconciler) updateConditions(ctx context.Context, keylime *attestationv1alpha1.Keylime) error {
	now := metav1.Now()

	verifier := &appsv1.StatefulSet{}
	verifierReady := false
	if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: keylime.Name + "-verifier"}, verifier); err == nil {
		verifierReady = verifier.Status.ReadyReplicas == derefInt32(verifier.Spec.Replicas) && verifier.Status.ReadyReplicas > 0
	}
	r.setCondition(keylime, conditionVerifierReady, verifierReady, now)

	registrar := &appsv1.Deployment{}
	registrarReady := false
	if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: keylime.Name + "-registrar"}, registrar); err == nil {
		registrarReady = registrar.Status.ReadyReplicas > 0
	}
	r.setCondition(keylime, conditionRegistrarReady, registrarReady, now)

	agentDesired := keylime.Spec.Agent.Enabled
	agent := &appsv1.DaemonSet{}
	agentReady := false
	if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: keylime.Name + "-agent"}, agent); err == nil {
		agentReady = agent.Status.DesiredNumberScheduled > 0 && agent.Status.NumberReady == agent.Status.DesiredNumberScheduled
	}
	if agentDesired {
		r.setCondition(keylime, conditionAgentReady, agentReady, now)
	} else {
		meta.RemoveStatusCondition(&keylime.Status.Conditions, conditionAgentReady)
	}

	ready := verifierReady && registrarReady && (!agentDesired || agentReady)
	r.setCondition(keylime, conditionReady, ready, now)

	if !ready {
		return fmt.Errorf("keylime operands are not ready yet")
	}
	return nil
}

func (r *KeylimeReconciler) setCondition(keylime *attestationv1alpha1.Keylime, conditionType string, status bool, now metav1.Time) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             metav1.ConditionFalse,
		Reason:             "NotReady",
		Message:            "The operand is not ready",
		LastTransitionTime: now,
		ObservedGeneration: keylime.Generation,
	}
	if status {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Ready"
		condition.Message = "The operand is ready"
	}
	meta.SetStatusCondition(&keylime.Status.Conditions, condition)
}

// updateStatus persists the status if it changed.
func (r *KeylimeReconciler) updateStatus(ctx context.Context, keylime *attestationv1alpha1.Keylime, reconcileErr error) error {
	l := log.FromContext(ctx)
	if reconcileErr != nil {
		meta.SetStatusCondition(&keylime.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ReconcileError",
			Message:            reconcileErr.Error(),
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: keylime.Generation,
		})
	}
	var current attestationv1alpha1.Keylime
	if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: keylime.Name}, &current); err != nil {
		return err
	}
	if !reflect.DeepEqual(current.Status, keylime.Status) {
		if err := r.Status().Update(ctx, keylime); err != nil {
			l.Error(err, "status update failed")
			return err
		}
	}
	return reconcileErr
}

// reconcileCA returns the CA certificate, key and fingerprint. The CA is
// either brought by the user (spec.tls.caSecretRef, keys "ca.crt" and "ca.key")
// or generated once by the operator and kept in a secret for the lifetime of
// the CR.
func (r *KeylimeReconciler) reconcileCA(ctx context.Context, keylime *attestationv1alpha1.Keylime) ([]byte, []byte, string, error) {
	if ref := keylime.Spec.TLS.CASecretRef; ref != "" {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: ref}, secret); err != nil {
			return nil, nil, "", fmt.Errorf("unable to get the CA secret %s: %w", ref, err)
		}
		caCert, ok := secret.Data["ca.crt"]
		if !ok {
			return nil, nil, "", fmt.Errorf("the CA secret %s does not contain a %q key", ref, "ca.crt")
		}
		caKey, ok := secret.Data["ca.key"]
		if !ok {
			return nil, nil, "", fmt.Errorf("the CA secret %s does not contain a %q key", ref, "ca.key")
		}
		if _, _, err := parseCAPEM(caCert, caKey); err != nil {
			return nil, nil, "", fmt.Errorf("the CA secret %s is not usable: %w", ref, err)
		}
		fingerprint, err := caFingerprint(caCert)
		if err != nil {
			return nil, nil, "", err
		}
		return caCert, caKey, fingerprint, nil
	}

	// generate the CA once, keep it in an owned secret
	secretName := keylime.Name + "-ca"
	secret := &corev1.Secret{ObjectMeta: objectMeta(keylime, secretName)}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if len(secret.Data) == 0 {
			caCert, caKey, err := generateCA()
			if err != nil {
				return err
			}
			secret.Data = map[string][]byte{
				"ca.crt": caCert,
				"ca.key": caKey,
			}
		}
		return controllerutil.SetControllerReference(keylime, secret, r.Scheme)
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to reconcile the CA secret: %w", err)
	}
	log.FromContext(ctx).Info("CA secret reconciled", "operation", op)

	caCert := secret.Data["ca.crt"]
	caKey := secret.Data["ca.key"]
	fingerprint, err := caFingerprint(caCert)
	if err != nil {
		return nil, nil, "", err
	}
	return caCert, caKey, fingerprint, nil
}

// reconcileServerCert issues the shared server certificate for the verifier
// and registrar, with SANs matching the service DNS names so that clients can
// verify the server certificates (instead of skipping verification).
func (r *KeylimeReconciler) reconcileServerCert(ctx context.Context, keylime *attestationv1alpha1.Keylime, caCert, caKey []byte, caFingerprint string) error {
	secretName := keylime.Name + "-tls"
	dnsNames := serverDNSNames(keylime)
	ipAddresses := serverIPAddresses()

	secret := &corev1.Secret{ObjectMeta: objectMeta(keylime, secretName)}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if needsServerCert(secret, dnsNames, ipAddresses, caFingerprint) {
			certPEM, keyPEM, err := generateServerCert(caCert, caKey, dnsNames, ipAddresses)
			if err != nil {
				return err
			}
			secret.Data = map[string][]byte{
				serverCertFile: certPEM,
				serverKeyFile:  keyPEM,
				caCertFile:     caCert,
			}
			// marker for the CA the cert was issued by (used above)
			secret.Annotations = map[string]string{"attestation.keylime.dev/ca-fingerprint": caFingerprint}
		}
		return controllerutil.SetControllerReference(keylime, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("unable to reconcile the server certificate secret: %w", err)
	}
	log.FromContext(ctx).Info("server certificate secret reconciled", "operation", op)
	return nil
}

// needsServerCert returns true if the secret has no usable server certificate
// for the given SANs and CA. This keeps the certificate stable across
// reconciliations but re-issues it when the service names or the CA change.
func needsServerCert(secret *corev1.Secret, dnsNames []string, ipAddresses []net.IP, caFingerprint string) bool {
	if secret.Annotations == nil || secret.Annotations["attestation.keylime.dev/ca-fingerprint"] != caFingerprint {
		return true
	}
	certPEM := secret.Data[serverCertFile]
	if len(certPEM) == 0 || len(secret.Data[serverKeyFile]) == 0 {
		return true
	}
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return true
	}
	if !reflect.DeepEqual(cert.DNSNames, dnsNames) || !reflect.DeepEqual(cert.IPAddresses, ipAddresses) {
		return true
	}
	return false
}

// databaseURLs resolves the SQLAlchemy database URLs for the verifier and the
// registrar from the spec.
func (r *KeylimeReconciler) databaseURLs(ctx context.Context, keylime *attestationv1alpha1.Keylime) (string, string, error) {
	if keylime.Spec.Database.Type == attestationv1alpha1.ExternalDatabase || keylime.Spec.Database.External != nil {
		external := keylime.Spec.Database.External
		if external == nil || external.SecretRef == "" {
			return "", "", fmt.Errorf("spec.database.external.secretRef must be set when spec.database.type is external")
		}
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: keylime.Namespace, Name: external.SecretRef}, secret); err != nil {
			return "", "", fmt.Errorf("unable to get the database URL secret %s: %w", external.SecretRef, err)
		}
		verifierURL, ok := secret.Data["verifier-url"]
		if !ok {
			return "", "", fmt.Errorf("the database URL secret %s does not contain a %q key", external.SecretRef, "verifier-url")
		}
		registrarURL, ok := secret.Data["registrar-url"]
		if !ok {
			return "", "", fmt.Errorf("the database URL secret %s does not contain a %q key", external.SecretRef, "registrar-url")
		}
		return string(verifierURL), string(registrarURL), nil
	}
	return sqliteDatabaseURL(verifierDataDir, verifierDatabaseFile), sqliteDatabaseURL(registrarDataDir, registrarDatabaseFile), nil
}

// reconcileConfigMaps renders the keylime configuration snippets.
func (r *KeylimeReconciler) reconcileConfigMaps(ctx context.Context, keylime *attestationv1alpha1.Keylime, verifierDB, registrarDB string) error {
	verifierCM := &corev1.ConfigMap{ObjectMeta: objectMeta(keylime, keylime.Name+"-verifier-config")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, verifierCM, func() error {
		verifierCM.Data = map[string]string{verifierConfigFile: renderVerifierConfig(keylime, verifierDB)}
		return controllerutil.SetControllerReference(keylime, verifierCM, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the verifier configmap: %w", err)
	}

	registrarCM := &corev1.ConfigMap{ObjectMeta: objectMeta(keylime, keylime.Name+"-registrar-config")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, registrarCM, func() error {
		registrarCM.Data = map[string]string{registrarConfigFile: renderRegistrarConfig(keylime, registrarDB)}
		return controllerutil.SetControllerReference(keylime, registrarCM, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the registrar configmap: %w", err)
	}

	if keylime.Spec.Agent.Enabled {
		agentCM := &corev1.ConfigMap{ObjectMeta: objectMeta(keylime, keylime.Name+"-agent-config")}
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, agentCM, func() error {
			agentCM.Data = map[string]string{verifierConfigFile: renderAgentConfig(keylime)}
			return controllerutil.SetControllerReference(keylime, agentCM, r.Scheme)
		}); err != nil {
			return fmt.Errorf("unable to reconcile the agent configmap: %w", err)
		}
	}
	return nil
}

// reconcileServices creates the stable, DNS-named services for the operands.
func (r *KeylimeReconciler) reconcileServices(ctx context.Context, keylime *attestationv1alpha1.Keylime) error {
	verifierSvc := &corev1.Service{ObjectMeta: objectMeta(keylime, keylime.Name+"-verifier")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, verifierSvc, func() error {
		verifierSvc.Spec.Type = corev1.ServiceTypeClusterIP
		verifierSvc.Spec.Selector = componentLabels(keylime, "verifier")
		verifierSvc.Spec.Ports = []corev1.ServicePort{{
			Name:       "verifier",
			Port:       8881,
			TargetPort: intstrFromInt(8881),
			Protocol:   corev1.ProtocolTCP,
		}}
		return controllerutil.SetControllerReference(keylime, verifierSvc, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the verifier service: %w", err)
	}

	registrarSvc := &corev1.Service{ObjectMeta: objectMeta(keylime, keylime.Name+"-registrar")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, registrarSvc, func() error {
		registrarSvc.Spec.Type = corev1.ServiceTypeClusterIP
		registrarSvc.Spec.Selector = componentLabels(keylime, "registrar")
		registrarSvc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "registrar",
				Port:       8890,
				TargetPort: intstrFromInt(8890),
				Protocol:   corev1.ProtocolTCP,
			},
			{
				Name:       "registrar-tls",
				Port:       8891,
				TargetPort: intstrFromInt(8891),
				Protocol:   corev1.ProtocolTCP,
			},
		}
		return controllerutil.SetControllerReference(keylime, registrarSvc, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the registrar service: %w", err)
	}
	return nil
}

// reconcileRegistrar deploys the registrar as a Deployment with a PVC.
func (r *KeylimeReconciler) reconcileRegistrar(ctx context.Context, keylime *attestationv1alpha1.Keylime) error {
	storageSize := keylime.Spec.Registrar.StorageSize.String()
	if storageSize == "0" {
		storageSize = "1Gi"
	}

	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: objectMeta(keylime, keylime.Name+"-registrar-data")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, pvc, func() error {
		if len(pvc.Spec.AccessModes) == 0 {
			pvc.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
		}
		pvc.Spec.Resources.Requests = corev1.ResourceList{corev1.ResourceStorage: mustParseQuantity(storageSize)}
		return controllerutil.SetControllerReference(keylime, pvc, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the registrar data PVC: %w", err)
	}

	deployment := &appsv1.Deployment{ObjectMeta: objectMeta(keylime, keylime.Name+"-registrar")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		deployment.Spec.Replicas = int32Ptr(1)
		deployment.Spec.Selector = &metav1.LabelSelector{MatchLabels: componentLabels(keylime, "registrar")}
		deployment.Spec.Template = corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: componentLabels(keylime, "registrar")},
			Spec: corev1.PodSpec{
				// the service names would otherwise inject KEYLIME_*_PORT
				// service link environment variables that keylime's
				// environment override mechanism picks up as config values
				EnableServiceLinks: boolPtr(false),
				Containers: []corev1.Container{{
					Name:            "registrar",
					Image:           keylime.Spec.Images.RegistrarImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Ports: []corev1.ContainerPort{
						{Name: "registrar", ContainerPort: 8890, Protocol: corev1.ProtocolTCP},
						{Name: "registrar-tls", ContainerPort: 8891, Protocol: corev1.ProtocolTCP},
					},
					ReadinessProbe: tcpProbe(8890),
					LivenessProbe:  tcpProbe(8890),
					VolumeMounts:   registrarVolumeMounts(keylime),
				}},
				Volumes: operandVolumes(keylime, registrarDataVolName),
			},
		}
		return controllerutil.SetControllerReference(keylime, deployment, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the registrar deployment: %w", err)
	}
	return nil
}

// reconcileVerifier deploys the verifier as a StatefulSet whose database lives
// on a volume claim template (persistent SQLite enrollments).
func (r *KeylimeReconciler) reconcileVerifier(ctx context.Context, keylime *attestationv1alpha1.Keylime) error {
	replicas := int32Ptr(1)
	if keylime.Spec.Verifier.Replicas != nil {
		replicas = keylime.Spec.Verifier.Replicas
	}
	storageSize := keylime.Spec.Verifier.StorageSize.String()
	if storageSize == "0" {
		storageSize = "1Gi"
	}

	statefulset := &appsv1.StatefulSet{ObjectMeta: objectMeta(keylime, keylime.Name+"-verifier")}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, statefulset, func() error {
		statefulset.Spec.Replicas = replicas
		statefulset.Spec.ServiceName = keylime.Name + "-verifier"
		statefulset.Spec.Selector = &metav1.LabelSelector{MatchLabels: componentLabels(keylime, "verifier")}
		statefulset.Spec.Template = corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: componentLabels(keylime, "verifier")},
			Spec: corev1.PodSpec{
				// see the registrar: avoid KEYLIME_*_PORT service links
				EnableServiceLinks: boolPtr(false),
				Containers: []corev1.Container{{
					Name:  "verifier",
					Image: keylime.Spec.Images.VerifierImage,
					Env: []corev1.EnvVar{{
						Name: "KEYLIME_VERIFIER_UUID",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
						},
					}},
					ImagePullPolicy: corev1.PullIfNotPresent,
					Ports: []corev1.ContainerPort{
						{Name: "verifier", ContainerPort: 8881, Protocol: corev1.ProtocolTCP},
					},
					ReadinessProbe: tcpProbe(8881),
					LivenessProbe:  tcpProbe(8881),
					VolumeMounts:   verifierVolumeMounts(keylime),
				}},
				Volumes: operandVolumes(keylime, ""),
			},
		}
		// volumeClaimTemplates are immutable on update: only set them at
		// creation time. Size changes require deleting the StatefulSet.
		if len(statefulset.Spec.VolumeClaimTemplates) == 0 {
			statefulset.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: verifierDataVolName, Labels: componentLabels(keylime, "verifier")},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{corev1.ResourceStorage: mustParseQuantity(storageSize)},
					},
				},
			}}
		}
		return controllerutil.SetControllerReference(keylime, statefulset, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the verifier statefulset: %w", err)
	}
	return nil
}

// reconcileAgent deploys the keylime agent as a DaemonSet when enabled.
func (r *KeylimeReconciler) reconcileAgent(ctx context.Context, keylime *attestationv1alpha1.Keylime) error {
	daemonset := &appsv1.DaemonSet{ObjectMeta: objectMeta(keylime, keylime.Name+"-agent")}
	if !keylime.Spec.Agent.Enabled {
		// opt-out: remove a previously deployed DaemonSet
		if err := r.Delete(ctx, daemonset); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("unable to delete the agent daemonset: %w", err)
		}
		return nil
	}

	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, daemonset, func() error {
		daemonset.Spec.Selector = &metav1.LabelSelector{MatchLabels: componentLabels(keylime, "agent")}
		podSpec := corev1.PodSpec{
			EnableServiceLinks: boolPtr(false),
			NodeSelector:       keylime.Spec.Agent.NodeSelector,
			Tolerations:        keylime.Spec.Agent.Tolerations,
			Containers: []corev1.Container{{
				Name:            "agent",
				Image:           keylime.Spec.Images.AgentImage,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Ports: []corev1.ContainerPort{
					{Name: "agent", ContainerPort: 9002, Protocol: corev1.ProtocolTCP},
				},
				VolumeMounts: agentVolumeMounts(),
			}},
			Volumes: agentVolumes(keylime),
		}
		if daemonset.Spec.Template.Labels == nil {
			daemonset.Spec.Template.Labels = componentLabels(keylime, "agent")
		}
		daemonset.Spec.Template.Spec = podSpec
		return controllerutil.SetControllerReference(keylime, daemonset, r.Scheme)
	}); err != nil {
		return fmt.Errorf("unable to reconcile the agent daemonset: %w", err)
	}
	return nil
}

// SetupWithManager sets up the controller with the manager.
func (r *KeylimeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&attestationv1alpha1.Keylime{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// objectMeta returns the metadata for an object owned by the Keylime CR.
func objectMeta(keylime *attestationv1alpha1.Keylime, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: keylime.Namespace,
		Labels: map[string]string{
			"app.kubernetes.io/name":       "keylime",
			"app.kubernetes.io/instance":   keylime.Name,
			"app.kubernetes.io/part-of":    "keylime",
			"app.kubernetes.io/managed-by": "attestation-operator",
		},
	}
}

// componentLabels returns the labels (and selector) for one operand.
func componentLabels(keylime *attestationv1alpha1.Keylime, component string) map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/name":       "keylime",
		"app.kubernetes.io/instance":   keylime.Name,
		"app.kubernetes.io/component":  component,
		"app.kubernetes.io/part-of":    "keylime",
		"app.kubernetes.io/managed-by": "attestation-operator",
	}
	return labels
}

const (
	verifierDataVolName  = "verifier-data"
	registrarDataVolName = "registrar-data"
)

// operandVolumes returns the (non-database) volumes shared by the verifier and
// registrar pods. The database volume name is only set for the registrar
// (the verifier's database lives in a volume claim template).
func operandVolumes(keylime *attestationv1alpha1.Keylime, registrarDataVol string) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  keylime.Name + "-tls",
					DefaultMode: int32Ptr(0o400),
				},
			},
		},
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: componentConfigName(keylime, registrarDataVol),
					},
				},
			},
		},
		// the verifier's SPDM engine reads the registrar section
		// (spdm_cert_store) from registrar.conf
		{
			Name: "registrar-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: keylime.Name + "-registrar-config",
					},
				},
			},
		},
	}

	// additional trusted client CAs (e.g. a legacy CA during migration)
	for _, ref := range keylime.Spec.TLS.TrustedClientCASecretRefs {
		volumes = append(volumes, corev1.Volume{
			Name: "trusted-ca-" + ref.SecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: ref.SecretName,
					Items: []corev1.KeyToPath{{
						Key:  ref.Key,
						Path: sanitize(ref.Key) + ".crt",
					}},
					DefaultMode: int32Ptr(0o400),
				},
			},
		})
	}

	if ts := keylime.Spec.TrustStores.TPMCertStore; ts != nil {
		volumes = append(volumes, trustStoreVolume("tpm-cert-store", ts))
	}
	if ts := keylime.Spec.TrustStores.SPDMCertStore; ts != nil {
		volumes = append(volumes, trustStoreVolume("spdm-cert-store", ts))
	}
	if ts := keylime.Spec.TrustStores.CORIMSigners; ts != nil {
		volumes = append(volumes, trustStoreVolume("corim-signers", ts))
	}
	if ts := keylime.Spec.Appraisal.CORIM; ts != nil {
		volumes = append(volumes, trustStoreVolume("corim", ts))
	}

	if registrarDataVol != "" {
		volumes = append(volumes, corev1.Volume{
			Name: registrarDataVol,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: keylime.Name + "-registrar-data",
				},
			},
		})
	}
	return volumes
}

func componentConfigName(keylime *attestationv1alpha1.Keylime, registrarDataVol string) string {
	if registrarDataVol != "" {
		return keylime.Name + "-registrar-config"
	}
	return keylime.Name + "-verifier-config"
}

func trustStoreVolume(name string, ts *attestationv1alpha1.TrustStoreSource) corev1.Volume {
	volume := corev1.Volume{Name: name}
	if ts.ConfigMapName != "" {
		volume.VolumeSource = corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: ts.ConfigMapName},
			},
		}
	} else {
		volume.VolumeSource = corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: ts.SecretName,
			},
		}
	}
	return volume
}

func registrarVolumeMounts(keylime *attestationv1alpha1.Keylime) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: "tls", MountPath: tlsDir, ReadOnly: true},
		{Name: "config", MountPath: "/etc/keylime/registrar.conf.d", ReadOnly: true},
	}
	mounts = append(mounts, trustedAndTrustStoreMounts(keylime)...)
	return append(mounts, corev1.VolumeMount{Name: registrarDataVolName, MountPath: registrarDataDir})
}

func verifierVolumeMounts(keylime *attestationv1alpha1.Keylime) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: "tls", MountPath: tlsDir, ReadOnly: true},
		{Name: "config", MountPath: "/etc/keylime/verifier.conf.d", ReadOnly: true},
		// the verifier's SPDM engine reads the registrar section
		// (spdm_cert_store) from registrar.conf, so it needs that snippet too
		{Name: "registrar-config", MountPath: "/etc/keylime/registrar.conf.d", ReadOnly: true},
	}
	mounts = append(mounts, trustedAndTrustStoreMounts(keylime)...)
	return append(mounts, corev1.VolumeMount{Name: verifierDataVolName, MountPath: verifierDataDir})
}

// trustedAndTrustStoreMounts returns the mounts for the additional trusted
// client CAs and the trust stores.
func trustedAndTrustStoreMounts(keylime *attestationv1alpha1.Keylime) []corev1.VolumeMount {
	var mounts []corev1.VolumeMount
	for _, ref := range keylime.Spec.TLS.TrustedClientCASecretRefs {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "trusted-ca-" + ref.SecretName,
			MountPath: trustedCADir + "/trusted-ca-" + ref.SecretName,
			ReadOnly:  true,
		})
	}
	if keylime.Spec.TrustStores.TPMCertStore != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: "tpm-cert-store", MountPath: tpmCertStoreDir, ReadOnly: true})
	}
	if keylime.Spec.TrustStores.SPDMCertStore != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: "spdm-cert-store", MountPath: spdmCertStoreDir, ReadOnly: true})
	}
	if keylime.Spec.TrustStores.CORIMSigners != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: "corim-signers", MountPath: corimSignersDir, ReadOnly: true})
	}
	if keylime.Spec.Appraisal.CORIM != nil {
		mounts = append(mounts, corev1.VolumeMount{Name: "corim", MountPath: corimDir, ReadOnly: true})
	}
	return mounts
}

func agentVolumes(keylime *attestationv1alpha1.Keylime) []corev1.Volume {
	return []corev1.Volume{
		{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  keylime.Name + "-tls",
					DefaultMode: int32Ptr(0o400),
				},
			},
		},
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: keylime.Name + "-agent-config",
					},
				},
			},
		},
	}
}

func agentVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{Name: "tls", MountPath: tlsDir, ReadOnly: true},
		{Name: "config", MountPath: "/etc/keylime/agent.conf.d", ReadOnly: true},
	}
}

func tcpProbe(port int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{
				Port: intstrFromInt(port),
			},
		},
		InitialDelaySeconds: 5,
		PeriodSeconds:       10,
	}
}
