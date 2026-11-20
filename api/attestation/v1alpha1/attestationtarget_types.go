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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AttestationTargetSpec defines the desired state of AttestationTarget: the
// out-of-band attestation of one machine whose BMC is polled by an
// operator-provisioned collector Deployment.
type AttestationTargetSpec struct {
	// BMC describes the Redfish endpoint of the BMC of the machine to attest.
	BMC BMCSpec `json:"bmc"`

	// KeylimeRef is the name of the Keylime CR in the same namespace whose
	// verifier and registrar the collector reports to. If empty, the single
	// Keylime CR in the namespace is used (and an error is reported if there
	// are none or several).
	KeylimeRef string `json:"keylimeRef,omitempty"`

	// IntervalSeconds is the interval at which the collector attests the
	// machine, in seconds.
	//+kubebuilder:default:=300
	//+kubebuilder:validation:Minimum=1
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// Components optionally restricts attestation to the listed
	// ComponentIntegrity IDs of the BMC. An empty list means all
	// SPDM-capable components discovered on the BMC.
	// NOTE: the collector image currently attests all discovered components;
	// enforcing this filter requires a collector update (planned for the
	// node-conditions phase of the redesign).
	Components []string `json:"components,omitempty"`

	// AgentUUID optionally pins the UUID of the agent this target feeds.
	// If empty, a deterministic UUID (v5) derived from the target's
	// namespaced name is used, so the identity of the machine is stable
	// across collector reinstalls (the collector's swtpm identity is
	// re-created from scratch on every reinstall).
	//+kubebuilder:validation:Pattern=`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	AgentUUID string `json:"agentUUID,omitempty"`

	// SPDMCertChain optionally references the device's SPDM certificate
	// chain blob (DMTF DSP0274, Base64 or raw) in a secret. It is used as a
	// fallback when the BMC does not serve the chain alongside the signed
	// measurements. If unset, the collector relies on the BMC providing the
	// chain via the Redfish Certificate resource or an inline property.
	SPDMCertChain *CertChainSource `json:"spdmCertChain,omitempty"`
}

// BMCSpec describes the BMC of the machine to attest.
type BMCSpec struct {
	// Host is the host (with optional ":port") of the BMC's Redfish endpoint.
	Host string `json:"host"`

	// Insecure skips the verification of the BMC's TLS certificate
	// (self-signed certificates, e.g. virtual BMCs in test setups).
	Insecure bool `json:"insecure,omitempty"`

	// CACertRef optionally references a secret or configmap holding the CA
	// certificate to verify the BMC's TLS certificate. Takes precedence
	// over Insecure.
	CACertRef *BMCReference `json:"caCertRef,omitempty"`

	// CredentialsSecretRef is the name of a secret in the same namespace as
	// the AttestationTarget holding the BMC's Redfish credentials, under the
	// keys "username" and "password". If unset, the collector's defaults
	// (empty credentials) are used.
	CredentialsSecretRef string `json:"credentialsSecretRef,omitempty"`
}

// BMCReference references a single key of a secret or configmap.
type BMCReference struct {
	// SecretName is the name of a secret holding the referenced data.
	SecretName string `json:"secretName,omitempty"`

	// ConfigMapName is the name of a configmap holding the referenced data.
	ConfigMapName string `json:"configMapName,omitempty"`

	// Key is the key of the data inside the secret or configmap.
	Key string `json:"key"`
}

// CertChainSource references the SPDM certificate chain blob of a device.
type CertChainSource struct {
	// SecretRef is the name of a secret in the same namespace as the
	// AttestationTarget holding the certificate chain blob.
	SecretRef string `json:"secretRef"`

	// Key is the key of the certificate chain blob inside the secret.
	Key string `json:"key"`
}

// AttestationNodeRef records a BaremetalHost matched to the target's BMC,
// and the node it provisioned when known.
type AttestationNodeRef struct {
	// BaremetalHost is the name of the matched BaremetalHost.
	BaremetalHost string `json:"baremetalHost"`

	// Node is the name of the node provisioned from the BaremetalHost, when
	// it could be determined.
	Node string `json:"node,omitempty"`
}

// MachineMappingStatus records the result of matching the target's BMC
// against the BaremetalHosts of the cluster.
type MachineMappingStatus struct {
	// Available is false when the mapping could not be computed, e.g.
	// because the BaremetalHost CRDs are not installed on this cluster.
	Available bool `json:"available"`

	// Reason explains why the mapping is unavailable.
	Reason string `json:"reason,omitempty"`

	// NodeRefs lists the BaremetalHosts whose BMC address matches the
	// target's BMC host (empty if none match).
	NodeRefs []AttestationNodeRef `json:"nodeRefs,omitempty"`
}

// AttestationTargetStatus defines the observed state of AttestationTarget.
// The per-component and per-tray detail is deliberately deferred to the
// node-conditions phase of the redesign.
type AttestationTargetStatus struct {
	// Conditions represent the readiness of the collector and of the target.
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// AgentUUID is the agent UUID the collector uses (explicit or derived).
	AgentUUID string `json:"agentUUID,omitempty"`

	// AgentRef is the name of the Agent CR this target feeds, once the
	// collector has registered with the registrar.
	AgentRef string `json:"agentRef,omitempty"`

	// AgentPhase mirrors the phase of the Agent CR (e.g. Registered,
	// Verifying).
	AgentPhase string `json:"agentPhase,omitempty"`

	// VerifierState mirrors the agent's operational state in the verifier
	// (e.g. GET_QUOTE, quoting).
	VerifierState string `json:"verifierState,omitempty"`

	// AttestationStage and AttestationEvaluation mirror the agent's latest
	// attestation as reported by the verifier's v3 push-mode attestation
	// API (e.g. verification_complete / pass).
	AttestationStage      string `json:"attestationStage,omitempty"`
	AttestationEvaluation string `json:"attestationEvaluation,omitempty"`

	// LastSuccessfulAttestation mirrors the agent's last successful
	// attestation timestamp.
	LastSuccessfulAttestation *metav1.Time `json:"lastSuccessfulAttestation,omitempty"`

	// LastCollectionTimestamp is when the controller last observed a new
	// successful attestation from the collector.
	LastCollectionTimestamp *metav1.Time `json:"lastCollectionTimestamp,omitempty"`

	// MachineMapping records the result of matching the target's BMC
	// against the cluster's BaremetalHosts (when the CRDs are installed).
	MachineMapping *MachineMappingStatus `json:"machineMapping,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced
//+kubebuilder:printcolumn:name="Agent UUID",type=string,JSONPath=`.status.agentUUID`
//+kubebuilder:printcolumn:name="Agent Phase",type=string,JSONPath=`.status.agentPhase`
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.verifierState`
//+kubebuilder:printcolumn:name="Stage",type=string,JSONPath=`.status.attestationStage`
//+kubebuilder:printcolumn:name="Evaluation",type=string,JSONPath=`.status.attestationEvaluation`
//+kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// AttestationTarget is the Schema for the attestationtargets API. It is the
// desired state for the out-of-band attestation of one machine: from it, the
// operator provisions a collector Deployment (with a swtpm sidecar) that
// polls the machine's BMC over Redfish and pushes SPDM measurements to the
// verifier of the referenced Keylime CR.
type AttestationTarget struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AttestationTargetSpec   `json:"spec,omitempty"`
	Status AttestationTargetStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AttestationTargetList contains a list of AttestationTarget
type AttestationTargetList struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ListMeta   `json:"metadata,omitempty"`
	Items             []AttestationTarget `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AttestationTarget{}, &AttestationTargetList{})
}
