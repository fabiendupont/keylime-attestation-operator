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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

const (
	// nodeConditionAttestationFailed is the node condition type the operator
	// sets on the nodes a target maps to when the target is unhealthy. The
	// operator's contract ends at this signal: remediation belongs to
	// Workload Availability (Node Health Check + a remediation template of
	// the admin's choosing), configured by the admin.
	nodeConditionAttestationFailed = "AttestationFailed"

	// Node condition reasons.
	reasonAttestationEvaluationFailed = "AttestationEvaluationFailed"
	reasonAttestationStale            = "AttestationStale"
	reasonAttestationPassed           = "AttestationPassed"

	// Machine mapping sources (status.machineMapping.source).
	mappingSourceMachineAPI = "MachineAPI"
	mappingSourceManual     = "Manual"

	// conditionTargetHealthy is the AttestationTarget condition reflecting
	// the health computed from the agent's attestation state.
	conditionTargetHealthy = "AttestationHealthy"

	// defaultStaleMultiplier is how many collection intervals the last
	// successful attestation may age before the target is stale, when
	// spec.staleThresholdSeconds is unset.
	defaultStaleMultiplier = 3
)

// targetHealthState is the outcome of the unhealthy computation.
type targetHealthState string

const (
	healthUnhealthyFailed targetHealthState = "fail"
	healthUnhealthyStale  targetHealthState = "stale"
	healthHealthy         targetHealthState = "pass"
	healthUnknown         targetHealthState = "unknown"
)

// targetHealth is the result of evaluating a target's attestation state.
type targetHealth struct {
	state   targetHealthState
	reason  string
	message string
}

func (h targetHealth) unhealthy() bool {
	return h.state == healthUnhealthyFailed || h.state == healthUnhealthyStale
}

// staleThreshold returns how old the agent's last successful attestation may
// be before the target is considered stale: spec.staleThresholdSeconds when
// set, 3x the collection interval otherwise. A dead collector silently means
// no attestation, which must not read as healthy.
func staleThreshold(target *attestationv1alpha1.AttestationTarget) time.Duration {
	if spec := target.Spec.StaleThresholdSeconds; spec != nil && *spec > 0 {
		return time.Duration(*spec) * time.Second
	}
	interval := target.Spec.IntervalSeconds
	if interval <= 0 {
		interval = 300
	}
	return time.Duration(defaultStaleMultiplier*interval) * time.Second
}

// attestationHealth computes whether the target is currently healthy. A
// target is unhealthy when its agent CR's attestation evaluation is "fail",
// or when its last successful attestation is older than the stale threshold.
// While an attestation is still being evaluated (and the previous success is
// recent) the health is unknown and the previously emitted signal is left
// untouched.
func attestationHealth(target *attestationv1alpha1.AttestationTarget, now time.Time) targetHealth {
	targetRef := fmt.Sprintf("AttestationTarget %s/%s", target.Namespace, target.Name)

	if target.Status.AttestationEvaluation == "fail" {
		message := fmt.Sprintf("%s failed attestation evaluation", targetRef)
		if components := target.Status.Components; len(components) > 0 {
			message = fmt.Sprintf("%s (components: %s)", message, joinComponents(components))
		}
		return targetHealth{
			state:   healthUnhealthyFailed,
			reason:  reasonAttestationEvaluationFailed,
			message: message,
		}
	}

	if last := target.Status.LastSuccessfulAttestation; last != nil && now.Sub(last.Time) > staleThreshold(target) {
		return targetHealth{
			state:   healthUnhealthyStale,
			reason:  reasonAttestationStale,
			message: fmt.Sprintf("%s is stale: no successful attestation since %s (threshold %s)", targetRef, last.UTC().Format(time.RFC3339), staleThreshold(target)),
		}
	}

	if target.Status.AttestationEvaluation == "pass" {
		return targetHealth{
			state:   healthHealthy,
			reason:  reasonAttestationPassed,
			message: fmt.Sprintf("%s passed attestation evaluation", targetRef),
		}
	}

	return targetHealth{state: healthUnknown}
}

// joinComponents renders the component list for condition and event messages.
func joinComponents(components []string) string {
	out := ""
	for i, c := range components {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}

// desiredNodeCondition returns the node condition the operator should set
// for the target's current health, or nil when the health state does not
// warrant writing the condition (unknown health never fights the signal
// already present on the node).
func desiredNodeCondition(target *attestationv1alpha1.AttestationTarget, health targetHealth, now metav1.Time) *corev1.NodeCondition {
	if health.state == healthUnknown {
		return nil
	}
	condition := &corev1.NodeCondition{
		Type:               nodeConditionAttestationFailed,
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	if health.unhealthy() {
		condition.Status = corev1.ConditionTrue
		condition.Reason = health.reason
		condition.Message = health.message
	} else {
		condition.Status = corev1.ConditionFalse
		condition.Reason = reasonAttestationPassed
		condition.Message = health.message
	}
	return condition
}

// nodeConditionNeedsUpdate reports whether the desired condition differs
// from the one currently on the node: the node status is only patched when
// the condition actually changes, so the operator never fights other
// writers (and does not churn heartbeats).
func nodeConditionNeedsUpdate(node *corev1.Node, desired corev1.NodeCondition) bool {
	for i := range node.Status.Conditions {
		current := &node.Status.Conditions[i]
		if current.Type != desired.Type {
			continue
		}
		return current.Status != desired.Status || current.Reason != desired.Reason
	}
	return true
}

// mappedNodes resolves the node names the target's attestation-failure
// signal applies to, and the mapping source used: the MachineAPI
// (BaremetalHost) mapping takes precedence, with the admin-provided
// spec.nodes list as the manual fallback for clusters without the
// MachineAPI.
func mappedNodes(target *attestationv1alpha1.AttestationTarget) ([]string, string) {
	if mapping := target.Status.MachineMapping; mapping != nil && mapping.Available {
		var nodes []string
		for _, ref := range mapping.NodeRefs {
			if ref.Node != "" {
				nodes = append(nodes, ref.Node)
			}
		}
		if len(nodes) > 0 {
			return nodes, mapping.Source
		}
	}
	if manual := target.Spec.Nodes; len(manual) > 0 {
		return manual, mappingSourceManual
	}
	return nil, ""
}

// reconcileNodeConditions computes the target's health, records it as the
// AttestationHealthy status condition, and sets or clears the
// AttestationFailed node condition on every mapped node (idempotently: the
// node status is only patched when the condition actually changes). A
// Kubernetes Event is emitted on the node for auditability whenever the
// condition is written.
func (r *AttestationTargetReconciler) reconcileNodeConditions(ctx context.Context, target *attestationv1alpha1.AttestationTarget) {
	l := logf.FromContext(ctx)
	now := metav1.Now()
	health := attestationHealth(target, now.Time)

	// record the health on the target's status
	condition := metav1.Condition{
		Type:               conditionTargetHealthy,
		Status:             metav1.ConditionUnknown,
		Reason:             "AttestationPending",
		Message:            "The latest attestation is still being evaluated",
		LastTransitionTime: now,
		ObservedGeneration: target.Generation,
	}
	switch health.state {
	case healthHealthy:
		condition.Status = metav1.ConditionTrue
		condition.Reason = reasonAttestationPassed
		condition.Message = health.message
	case healthUnhealthyFailed, healthUnhealthyStale:
		condition.Status = metav1.ConditionFalse
		condition.Reason = health.reason
		condition.Message = health.message
	}
	meta.SetStatusCondition(&target.Status.Conditions, condition)

	nodes, _ := mappedNodes(target)
	if len(nodes) == 0 {
		if health.unhealthy() {
			l.Info("target is unhealthy but no node mapping is resolved; cannot emit the node condition", "reason", health.reason)
		}
		return
	}

	desired := desiredNodeCondition(target, health, now)
	if desired == nil {
		return
	}

	for _, name := range nodes {
		node := &corev1.Node{}
		if err := r.Get(ctx, types.NamespacedName{Name: name}, node); err != nil {
			if !apierrors.IsNotFound(err) {
				l.Error(err, "unable to get the mapped node", "node", name)
			}
			continue
		}
		if !nodeConditionNeedsUpdate(node, *desired) {
			continue
		}
		base := node.DeepCopy()
		setNodeCondition(node, *desired)
		if err := r.Status().Patch(ctx, node, client.MergeFrom(base)); err != nil {
			l.Error(err, "unable to patch the AttestationFailed node condition", "node", name)
			continue
		}
		eventType := corev1.EventTypeNormal
		if health.unhealthy() {
			eventType = corev1.EventTypeWarning
		}
		if r.Recorder != nil {
			r.Recorder.Eventf(node, eventType, desired.Reason, "%s", desired.Message)
		}
		l.Info("AttestationFailed node condition updated",
			"node", name, "status", desired.Status, "reason", desired.Reason)
	}
}

// setNodeCondition sets (or replaces) the condition on the node in place.
func setNodeCondition(node *corev1.Node, desired corev1.NodeCondition) {
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == desired.Type {
			desired.LastTransitionTime = node.Status.Conditions[i].LastTransitionTime
			node.Status.Conditions[i] = desired
			return
		}
	}
	node.Status.Conditions = append(node.Status.Conditions, desired)
}

// recheckInterval returns how often the target should be re-reconciled even
// without watched events, so that staleness is detected on its own schedule.
func recheckInterval(target *attestationv1alpha1.AttestationTarget) time.Duration {
	interval := time.Duration(target.Spec.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 300 * time.Second
	}
	after := interval
	if threshold := staleThreshold(target); threshold < after {
		after = threshold
	}
	after /= 3
	if after < 10*time.Second {
		after = 10 * time.Second
	}
	return after
}
