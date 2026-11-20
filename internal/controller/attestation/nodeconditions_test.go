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
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
	"github.com/keylime/attestation-operator/pkg/client/verifier"
)

func TestStaleThreshold(t *testing.T) {
	threshold := int32(120)
	target := &attestationv1alpha1.AttestationTarget{
		Spec: attestationv1alpha1.AttestationTargetSpec{
			IntervalSeconds:       300,
			StaleThresholdSeconds: &threshold,
		},
	}
	if got := staleThreshold(target); got != 120*time.Second {
		t.Errorf("explicit threshold not honored: %v", got)
	}

	// default: 3x the interval
	target = &attestationv1alpha1.AttestationTarget{
		Spec: attestationv1alpha1.AttestationTargetSpec{IntervalSeconds: 300},
	}
	if got := staleThreshold(target); got != 900*time.Second {
		t.Errorf("default threshold = %v, want 900s", got)
	}

	// default interval (300s) when unset
	target = &attestationv1alpha1.AttestationTarget{}
	if got := staleThreshold(target); got != 900*time.Second {
		t.Errorf("default-interval threshold = %v, want 900s", got)
	}
}

func healthyTarget() *attestationv1alpha1.AttestationTarget {
	lastSuccess := metav1.NewTime(time.Now().Add(-60 * time.Second))
	return &attestationv1alpha1.AttestationTarget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "keylime", Name: "vbmc"},
		Spec:       attestationv1alpha1.AttestationTargetSpec{IntervalSeconds: 300},
		Status: attestationv1alpha1.AttestationTargetStatus{
			AttestationEvaluation:     "pass",
			LastSuccessfulAttestation: &lastSuccess,
		},
	}
}

func TestAttestationHealth(t *testing.T) {
	now := time.Now()

	// healthy: pass and recent
	health := attestationHealth(healthyTarget(), now)
	if health.state != healthHealthy {
		t.Errorf("recent pass: state = %q, want pass", health.state)
	}

	// unhealthy: evaluation fail (even when fresh)
	target := healthyTarget()
	target.Status.AttestationEvaluation = "fail"
	target.Status.Components = []string{"ci-0", "ci-1"}
	health = attestationHealth(target, now)
	if health.state != healthUnhealthyFailed || health.reason != reasonAttestationEvaluationFailed {
		t.Errorf("fail evaluation: %+v", health)
	}
	if !strings.Contains(health.message, "keylime/vbmc") || !strings.Contains(health.message, "ci-0") {
		t.Errorf("fail message must name the target and components: %q", health.message)
	}

	// unhealthy: stale (no new attestation within the threshold)
	target = healthyTarget()
	stale := metav1.NewTime(now.Add(-901 * time.Second))
	target.Status.LastSuccessfulAttestation = &stale
	health = attestationHealth(target, now)
	if health.state != healthUnhealthyStale || health.reason != reasonAttestationStale {
		t.Errorf("stale: %+v", health)
	}

	// boundary: exactly at the threshold is not stale
	target = healthyTarget()
	edge := metav1.NewTime(now.Add(-900 * time.Second))
	target.Status.LastSuccessfulAttestation = &edge
	health = attestationHealth(target, now)
	if health.state != healthHealthy {
		t.Errorf("exactly at threshold: state = %q, want pass", health.state)
	}

	// stale wins over pending evaluation (a dead collector must not read
	// healthy just because the last attestation is stuck pending)
	target = healthyTarget()
	target.Status.AttestationEvaluation = "pending"
	stale = metav1.NewTime(now.Add(-901 * time.Second))
	target.Status.LastSuccessfulAttestation = &stale
	health = attestationHealth(target, now)
	if health.state != healthUnhealthyStale {
		t.Errorf("stale pending: state = %q, want stale", health.state)
	}

	// unknown: pending evaluation with a recent success
	target = healthyTarget()
	target.Status.AttestationEvaluation = "pending"
	health = attestationHealth(target, now)
	if health.state != healthUnknown {
		t.Errorf("pending: state = %q, want unknown", health.state)
	}

	// unknown: no attestation recorded yet
	target = healthyTarget()
	target.Status.AttestationEvaluation = ""
	target.Status.LastSuccessfulAttestation = nil
	health = attestationHealth(target, now)
	if health.state != healthUnknown {
		t.Errorf("no attestation: state = %q, want unknown", health.state)
	}
}

func TestDesiredNodeCondition(t *testing.T) {
	now := metav1.Now()
	target := healthyTarget()

	// unknown health never writes the condition
	if desired := desiredNodeCondition(target, targetHealth{state: healthUnknown}, now); desired != nil {
		t.Errorf("unknown health must not produce a condition, got %+v", desired)
	}

	// unhealthy: True with the failure reason
	unhealthy := attestationHealth(func() *attestationv1alpha1.AttestationTarget {
		t := healthyTarget()
		t.Status.AttestationEvaluation = "fail"
		return t
	}(), time.Now())
	desired := desiredNodeCondition(target, unhealthy, now)
	if desired == nil || desired.Type != nodeConditionAttestationFailed || desired.Status != corev1.ConditionTrue ||
		desired.Reason != reasonAttestationEvaluationFailed {
		t.Errorf("unhealthy condition = %+v", desired)
	}

	// healthy: False / AttestationPassed
	desired = desiredNodeCondition(target, attestationHealth(target, time.Now()), now)
	if desired == nil || desired.Status != corev1.ConditionFalse || desired.Reason != reasonAttestationPassed {
		t.Errorf("healthy condition = %+v", desired)
	}
}

func TestNodeConditionNeedsUpdate(t *testing.T) {
	now := metav1.Now()
	desired := corev1.NodeCondition{
		Type:               nodeConditionAttestationFailed,
		Status:             corev1.ConditionTrue,
		Reason:             reasonAttestationStale,
		Message:            "stale",
		LastTransitionTime: now,
	}

	// no condition of the type on the node yet: update needed
	node := &corev1.Node{}
	if !nodeConditionNeedsUpdate(node, desired) {
		t.Error("absent condition must require an update")
	}

	// same status and reason: no update (only-on-change, no heartbeat churn)
	node.Status.Conditions = []corev1.NodeCondition{desired}
	if nodeConditionNeedsUpdate(node, desired) {
		t.Error("unchanged condition must not require an update")
	}

	// same status, different reason: update
	changed := desired
	changed.Reason = reasonAttestationEvaluationFailed
	if !nodeConditionNeedsUpdate(node, changed) {
		t.Error("reason change must require an update")
	}

	// cleared: False vs the True on the node
	cleared := desired
	cleared.Status = corev1.ConditionFalse
	cleared.Reason = reasonAttestationPassed
	if !nodeConditionNeedsUpdate(node, cleared) {
		t.Error("status change must require an update")
	}

	// other writers' conditions of a different type are ignored
	node.Status.Conditions = []corev1.NodeCondition{{
		Type:   corev1.NodeReady,
		Status: corev1.ConditionTrue,
	}}
	if !nodeConditionNeedsUpdate(node, desired) {
		t.Error("condition of another type must not satisfy the update")
	}
}

func TestSetNodeCondition(t *testing.T) {
	earlier := metav1.NewTime(time.Now().Add(-time.Hour))
	node := &corev1.Node{}
	node.Status.Conditions = []corev1.NodeCondition{{
		Type:               nodeConditionAttestationFailed,
		Status:             corev1.ConditionTrue,
		Reason:             reasonAttestationStale,
		LastTransitionTime: earlier,
	}}
	desired := corev1.NodeCondition{
		Type:               nodeConditionAttestationFailed,
		Status:             corev1.ConditionFalse,
		Reason:             reasonAttestationPassed,
		LastTransitionTime: metav1.Now(),
	}
	setNodeCondition(node, desired)
	if len(node.Status.Conditions) != 1 {
		t.Fatalf("condition replaced, not appended: %+v", node.Status.Conditions)
	}
	set := node.Status.Conditions[0]
	if set.Status != corev1.ConditionFalse || set.Reason != reasonAttestationPassed {
		t.Errorf("condition not updated: %+v", set)
	}
	if !set.LastTransitionTime.Equal(&earlier) {
		t.Errorf("LastTransitionTime must not change when the status does not: %+v", set.LastTransitionTime)
	}
}

func TestMappedNodes(t *testing.T) {
	// MachineAPI mapping takes precedence
	target := healthyTarget()
	target.Spec.Nodes = []string{"manual-node"}
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: true,
		Source:    mappingSourceMachineAPI,
		NodeRefs: []attestationv1alpha1.AttestationNodeRef{
			{BaremetalHost: "bmo-host", Node: "machine-node"},
		},
	}
	nodes, source := mappedNodes(target)
	if !reflect.DeepEqual(nodes, []string{"machine-node"}) || source != mappingSourceMachineAPI {
		t.Errorf("MachineAPI precedence: %v / %q", nodes, source)
	}

	// manual fallback when the mapping is unavailable (no BMH CRDs)
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: false,
		Reason:    "the BaremetalHost CRDs are not installed on this cluster",
	}
	nodes, source = mappedNodes(target)
	if !reflect.DeepEqual(nodes, []string{"manual-node"}) || source != mappingSourceManual {
		t.Errorf("manual fallback: %v / %q", nodes, source)
	}

	// manual fallback when the MachineAPI mapping resolves no node
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: true,
		Source:    mappingSourceMachineAPI,
		NodeRefs:  []attestationv1alpha1.AttestationNodeRef{{BaremetalHost: "bmo-host"}},
	}
	nodes, source = mappedNodes(target)
	if !reflect.DeepEqual(nodes, []string{"manual-node"}) || source != mappingSourceManual {
		t.Errorf("manual fallback without BMH node: %v / %q", nodes, source)
	}

	// no mapping at all
	target.Spec.Nodes = nil
	target.Status.MachineMapping = nil
	if nodes, source = mappedNodes(target); nodes != nil || source != "" {
		t.Errorf("unmapped: %v / %q", nodes, source)
	}
}

func TestApplyManualMapping(t *testing.T) {
	// the manual mapping fills an unresolved MachineAPI mapping
	target := healthyTarget()
	target.Spec.Nodes = []string{"sno", "worker-0"}
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: false,
		Reason:    "the BaremetalHost CRDs are not installed on this cluster",
	}
	applyManualMapping(target)
	if !target.Status.MachineMapping.Available || target.Status.MachineMapping.Source != mappingSourceManual {
		t.Errorf("manual mapping not applied: %+v", target.Status.MachineMapping)
	}
	want := []attestationv1alpha1.AttestationNodeRef{{Node: "sno"}, {Node: "worker-0"}}
	if !reflect.DeepEqual(target.Status.MachineMapping.NodeRefs, want) {
		t.Errorf("manual NodeRefs = %+v, want %+v", target.Status.MachineMapping.NodeRefs, want)
	}

	// a resolved MachineAPI mapping is left alone
	target = healthyTarget()
	target.Spec.Nodes = []string{"sno"}
	target.Status.MachineMapping = &attestationv1alpha1.MachineMappingStatus{
		Available: true,
		Source:    mappingSourceMachineAPI,
		NodeRefs:  []attestationv1alpha1.AttestationNodeRef{{BaremetalHost: "bmo-host", Node: "machine-node"}},
	}
	applyManualMapping(target)
	if target.Status.MachineMapping.Source != mappingSourceMachineAPI {
		t.Errorf("MachineAPI mapping must take precedence: %+v", target.Status.MachineMapping)
	}

	// no manual nodes configured: nothing to do
	target = healthyTarget()
	target.Status.MachineMapping = nil
	applyManualMapping(target)
	if target.Status.MachineMapping != nil {
		t.Errorf("manual mapping must not invent a mapping: %+v", target.Status.MachineMapping)
	}
}

func TestRecheckInterval(t *testing.T) {
	// a third of the interval, so staleness is caught within the threshold
	target := &attestationv1alpha1.AttestationTarget{
		Spec: attestationv1alpha1.AttestationTargetSpec{IntervalSeconds: 300},
	}
	if got := recheckInterval(target); got != 100*time.Second {
		t.Errorf("recheckInterval = %v, want 100s", got)
	}

	// small thresholds shrink the requeue and never go below 10s
	threshold := int32(3)
	target.Spec.StaleThresholdSeconds = &threshold
	if got := recheckInterval(target); got != 10*time.Second {
		t.Errorf("recheckInterval = %v, want 10s", got)
	}
}

func TestToAttestationVerifierStatusComponents(t *testing.T) {
	attestation := &verifier.Attestation{
		Stage:      "verification_complete",
		Evaluation: "pass",
		Components: []string{"ci-0", "ci-1"},
	}
	status := toAttestationVerifierStatus(attestation)
	if !reflect.DeepEqual(status.AttestationComponents, []string{"ci-0", "ci-1"}) {
		t.Errorf("components not mirrored: %+v", status.AttestationComponents)
	}
}
