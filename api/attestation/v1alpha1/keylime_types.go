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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KeylimeSpec defines the desired state of Keylime
type KeylimeSpec struct {
	// Images contains the container images used for the keylime components.
	Images KeylimeImages `json:"images,omitempty"`

	// Database contains the database configuration for the verifier and the registrar.
	//+kubebuilder:default:={type:sqlite}
	Database KeylimeDatabaseSpec `json:"database,omitempty"`

	// Verifier contains the configuration of the keylime verifier.
	Verifier KeylimeVerifierSpec `json:"verifier,omitempty"`

	// Registrar contains the configuration of the keylime registrar.
	Registrar KeylimeRegistrarSpec `json:"registrar,omitempty"`

	// Agent contains the configuration of the keylime agent DaemonSet.
	Agent KeylimeAgentSpec `json:"agent,omitempty"`

	// TLS contains the PKI configuration for the keylime components.
	TLS KeylimeTLSSpec `json:"tls,omitempty"`

	// TrustStores contains references to the certificate stores used to verify
	// device identities and appraisal material (mounted into the verifier).
	TrustStores KeylimeTrustStoresSpec `json:"trustStores,omitempty"`

	// Appraisal contains the verifier's CoRIM-based appraisal configuration.
	Appraisal KeylimeAppraisalSpec `json:"appraisal,omitempty"`
}

// KeylimeImages defines the container images of the keylime components.
type KeylimeImages struct {
	// VerifierImage is the container image for the keylime verifier.
	//+kubebuilder:default:="quay.io/fdupont-redhat/keylime-verifier:master-oob"
	VerifierImage string `json:"verifierImage,omitempty"`

	// RegistrarImage is the container image for the keylime registrar.
	//+kubebuilder:default:="quay.io/fdupont-redhat/keylime-registrar:master-oob"
	RegistrarImage string `json:"registrarImage,omitempty"`

	// AgentImage is the container image for the keylime agent.
	//+kubebuilder:default:="quay.io/keylime/keylime_agent:master"
	AgentImage string `json:"agentImage,omitempty"`
}

// KeylimeDatabaseType describes where the verifier and registrar store their state.
// +kubebuilder:validation:Enum=sqlite;external
type KeylimeDatabaseType string

const (
	// SQLiteDatabase stores the component state in a SQLite database file on a
	// persistent volume provisioned by the operator.
	SQLiteDatabase KeylimeDatabaseType = "sqlite"

	// ExternalDatabase stores the component state in an external database whose
	// SQLAlchemy URL is taken from a secret.
	ExternalDatabase KeylimeDatabaseType = "external"
)

// KeylimeDatabaseSpec defines the database used by the verifier and the registrar.
type KeylimeDatabaseSpec struct {
	// Type selects between an operator-managed SQLite database on a persistent
	// volume (default) and an external database.
	//+kubebuilder:default:=sqlite
	Type KeylimeDatabaseType `json:"type,omitempty"`

	// External defines the secret holding the SQLAlchemy URLs when Type is "external".
	// The secret must contain the keys "verifier-url" and "registrar-url".
	External *KeylimeExternalDatabaseSpec `json:"external,omitempty"`
}

// KeylimeExternalDatabaseSpec points at the secret with the external database URLs.
type KeylimeExternalDatabaseSpec struct {
	// SecretRef is the name of a secret in the same namespace as the Keylime CR.
	SecretRef string `json:"secretRef"`
}

// KeylimeVerifierSpec defines the desired state of the keylime verifier.
type KeylimeVerifierSpec struct {
	// Replicas is the number of verifier pods. Note that with SQLite only one
	// replica is supported.
	//+kubebuilder:default:=1
	Replicas *int32 `json:"replicas,omitempty"`

	// StorageSize is the size of the persistent volume holding the verifier
	// database (only used with the SQLite database type).
	//+kubebuilder:default:="1Gi"
	StorageSize resource.Quantity `json:"storageSize,omitempty"`
}

// KeylimeRegistrarSpec defines the desired state of the keylime registrar.
type KeylimeRegistrarSpec struct {
	// StorageSize is the size of the persistent volume holding the registrar
	// database (only used with the SQLite database type).
	//+kubebuilder:default:="1Gi"
	StorageSize resource.Quantity `json:"storageSize,omitempty"`
}

// KeylimeAgentSpec defines the desired state of the keylime agent DaemonSet.
type KeylimeAgentSpec struct {
	// Enabled deploys the keylime agent as a DaemonSet. Disabled by default:
	// attesting in-band Kubernetes nodes is opt-in, and agents that live
	// outside the cluster register themselves with the registrar.
	Enabled bool `json:"enabled,omitempty"`

	// NodeSelector restricts the agent DaemonSet to a pool of nodes.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations are tolerations for the agent DaemonSet pods.
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// KeylimeTLSSpec defines the PKI used by the keylime components.
type KeylimeTLSSpec struct {
	// CASecretRef is the name of a secret in the same namespace as the Keylime
	// CR containing the certificate authority to sign the server certificates
	// with: key "ca.crt" holds the CA certificate (PEM) and key "ca.key" holds
	// the CA private key (PEM). If empty, the operator generates its own CA.
	// Reusing an existing CA means existing client certificates keep working.
	CASecretRef string `json:"caSecretRef,omitempty"`

	// TrustedClientCASecretRefs lists secrets (name and key of a PEM CA
	// certificate) whose client certificates should additionally be accepted
	// by the verifier and the registrar, next to the CA above. This allows
	// trusting e.g. a legacy CA during a migration.
	TrustedClientCASecretRefs []KeylimeTrustedClientCA `json:"trustedClientCASecretRefs,omitempty"`
}

// KeylimeTrustedClientCA references a single CA certificate inside a secret.
type KeylimeTrustedClientCA struct {
	// SecretName is the name of the secret holding the CA certificate.
	SecretName string `json:"secretName"`

	// Key is the key of the CA certificate (PEM) inside the secret.
	Key string `json:"key"`
}

// KeylimeTrustStoresSpec defines the trust stores mounted into the verifier.
type KeylimeTrustStoresSpec struct {
	// TPMCertStore is a secret or configmap with the trusted TPM EK/IDevID/IAK
	// CA certificates, mounted into the verifier (verifier/tpm_cert_store).
	TPMCertStore *TrustStoreSource `json:"tpmCertStore,omitempty"`

	// SPDMCertStore is a secret or configmap with the trusted SPDM device
	// certificate chain CAs, mounted into the verifier (registrar/spdm_cert_store).
	SPDMCertStore *TrustStoreSource `json:"spdmCertStore,omitempty"`

	// CORIMSigners is a secret or configmap with the trusted CoRIM signer
	// certificates, mounted into the verifier (verifier/spdm_corim_signers).
	CORIMSigners *TrustStoreSource `json:"corimSigners,omitempty"`
}

// TrustStoreSource references a secret or configmap whose contents are mounted
// as a trust store directory.
type TrustStoreSource struct {
	// SecretName is the name of a secret holding the trust store contents.
	SecretName string `json:"secretName,omitempty"`

	// ConfigMapName is the name of a configmap holding the trust store contents.
	ConfigMapName string `json:"configMapName,omitempty"`
}

// KeylimeAppraisalSpec defines the vendor-manifest (CoRIM) appraisal of the verifier.
type KeylimeAppraisalSpec struct {
	// CORIM is a secret or configmap containing the signed CoRIM manifest to
	// appraise devices against (verifier/spdm_corim). The manifest must be
	// stored under the key "corim.cbor".
	CORIM *TrustStoreSource `json:"corim,omitempty"`
}

// KeylimeStatus defines the observed state of Keylime
type KeylimeStatus struct {
	// Conditions represent the per-operand readiness of the deployment.
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// VerifierService is the URL under which the verifier's REST API can be reached.
	VerifierService string `json:"verifierService,omitempty"`

	// RegistrarService is the URL under which the registrar's TLS REST API can be reached.
	RegistrarService string `json:"registrarService,omitempty"`

	// CAFingerprint is the SHA-256 fingerprint of the certificate authority in use.
	CAFingerprint string `json:"caFingerprint,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Namespaced
//+kubebuilder:printcolumn:name="Verifier",type=string,JSONPath=`.status.verifierService`
//+kubebuilder:printcolumn:name="Registrar",type=string,JSONPath=`.status.registrarService`
//+kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
//+kubebuilder:printcolumn:name="CA Fingerprint",type=string,JSONPath=`.status.caFingerprint`

// Keylime is the Schema for the keylimes API. It deploys and configures the
// keylime verifier, registrar and (optionally) agent for one trust domain.
type Keylime struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeylimeSpec   `json:"spec,omitempty"`
	Status KeylimeStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KeylimeList contains a list of Keylime
type KeylimeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Keylime `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Keylime{}, &KeylimeList{})
}
