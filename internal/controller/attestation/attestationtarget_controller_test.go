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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

func TestDeriveAgentUUID(t *testing.T) {
	// stability: the same namespaced name always derives the same UUID
	first := deriveAgentUUID("keylime", "vbmc")
	second := deriveAgentUUID("keylime", "vbmc")
	if first != second {
		t.Errorf("UUID derivation is not stable: %q != %q", first, second)
	}

	// distinct inputs derive distinct UUIDs
	if first == deriveAgentUUID("keylime", "other") {
		t.Error("distinct targets derive the same UUID")
	}
	if first == deriveAgentUUID("other", "vbmc") {
		t.Error("distinct namespaces derive the same UUID")
	}

	// format: canonical lower-case 8-4-4-4-12
	uuid := deriveAgentUUID("keylime", "vbmc")
	if err := validateAgentUUID(uuid); err != nil {
		t.Errorf("derived UUID is not valid: %v", err)
	}
	if uuid != strings.ToLower(uuid) {
		t.Errorf("derived UUID is not lower-case: %q", uuid)
	}

	// version 5 (name-based, SHA-1) and RFC 4122 variant
	if uuid[14] != '5' {
		t.Errorf("derived UUID is not version 5: %q", uuid)
	}
	if uuid[19] != '8' && uuid[19] != '9' && uuid[19] != 'a' && uuid[19] != 'b' {
		t.Errorf("derived UUID does not have the RFC 4122 variant: %q", uuid)
	}
}

func TestValidateAgentUUID(t *testing.T) {
	for _, valid := range []string{
		"94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01",
		"94C56A96-1D2F-4A08-8B6C-6F8B1E2A9D01",
	} {
		if err := validateAgentUUID(valid); err != nil {
			t.Errorf("expected %q to be valid: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"",
		"not-a-uuid",
		"94c56a961d2f4a088b6c6f8b1e2a9d01",
		"94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d0",
		"94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d0g",
		"94c56a96_1d2f-4a08-8b6c-6f8b1e2a9d01",
	} {
		if err := validateAgentUUID(invalid); err == nil {
			t.Errorf("expected %q to be invalid", invalid)
		}
	}
}

func TestTargetAgentUUID(t *testing.T) {
	target := &attestationv1alpha1.AttestationTarget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "keylime", Name: "vbmc"},
	}

	derived, err := targetAgentUUID(target)
	if err != nil {
		t.Fatalf("targetAgentUUID failed: %v", err)
	}
	if derived != deriveAgentUUID("keylime", "vbmc") {
		t.Errorf("expected the derived UUID %q, got %q", deriveAgentUUID("keylime", "vbmc"), derived)
	}

	// explicit UUID wins and is normalized to lower case
	target.Spec.AgentUUID = "94C56A96-1D2F-4A08-8B6C-6F8B1E2A9D01"
	explicit, err := targetAgentUUID(target)
	if err != nil {
		t.Fatalf("targetAgentUUID failed: %v", err)
	}
	if explicit != "94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01" {
		t.Errorf("unexpected explicit UUID %q", explicit)
	}

	target.Spec.AgentUUID = "bogus"
	if _, err := targetAgentUUID(target); err == nil {
		t.Error("expected an error for an invalid explicit UUID")
	}
}

func sampleTarget() *attestationv1alpha1.AttestationTarget {
	return &attestationv1alpha1.AttestationTarget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "keylime", Name: "vbmc"},
		Spec: attestationv1alpha1.AttestationTargetSpec{
			BMC: attestationv1alpha1.BMCSpec{
				Host:     "vbmc.keylime.svc:8943",
				Insecure: true,
			},
			IntervalSeconds: 300,
		},
	}
}

func findArg(args []string, flag string) (string, bool) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1], true
		}
	}
	return "", false
}

func TestRenderCollectorDeployment(t *testing.T) {
	target := sampleTarget()
	uuid := deriveAgentUUID("keylime", "vbmc")
	deployment := renderCollectorDeployment(target, collectorParams{
		AgentUUID:     uuid,
		VerifierHost:  "keylime-verifier.keylime.svc",
		VerifierPort:  "8881",
		RegistrarHost: "keylime-registrar.keylime.svc",
		Credentials:   &bmcCredentials{Username: "admin", Password: "s3cr3t"},
	})

	if deployment.Name != "vbmc-collector" {
		t.Errorf("unexpected deployment name %q", deployment.Name)
	}
	if deployment.Namespace != "keylime" {
		t.Errorf("unexpected deployment namespace %q", deployment.Namespace)
	}

	// the swtpm sidecar holds a state-dir lock that deadlocks rolling
	// updates: the strategy must be Recreate
	if deployment.Spec.Strategy.Type != "Recreate" {
		t.Errorf("expected the Recreate strategy, got %q", deployment.Spec.Strategy.Type)
	}

	// service link env vars collide with keylime's env-based config
	if deployment.Spec.Template.Spec.EnableServiceLinks == nil || *deployment.Spec.Template.Spec.EnableServiceLinks {
		t.Error("expected service links to be disabled")
	}

	if len(deployment.Spec.Template.Spec.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(deployment.Spec.Template.Spec.Containers))
	}
	collector := deployment.Spec.Template.Spec.Containers[0]
	swtpm := deployment.Spec.Template.Spec.Containers[1]
	if collector.Name != "collector" || swtpm.Name != "swtpm" {
		t.Errorf("unexpected container names %q/%q", collector.Name, swtpm.Name)
	}
	if collector.Image != defaultCollectorImage {
		t.Errorf("unexpected collector image %q", collector.Image)
	}
	if !strings.Contains(strings.Join(swtpm.Command, " "), "swtpm socket --tpm2") {
		t.Errorf("unexpected swtpm command %v", swtpm.Command)
	}

	// arguments
	for flag, expected := range map[string]string{
		"--agent-uuid":     uuid,
		"--bmc-host":       "vbmc.keylime.svc:8943",
		"--verifier-host":  "keylime-verifier.keylime.svc",
		"--verifier-port":  "8881",
		"--registrar-host": "keylime-registrar.keylime.svc",
		"--registrar-port": "8890",
		"--swtpm-socket":   "/swtpm/tpm.sock",
		"--tls-cert":       "/etc/keylime/oob/client-cert.crt",
		"--tls-key":        "/etc/keylime/oob/client-private.pem",
		"--tls-ca-cert":    "/etc/keylime/oob/ca.crt",
		"--interval":       "300",
	} {
		if got, ok := findArg(collector.Args, flag); !ok || got != expected {
			t.Errorf("expected %s %s, got %q (ok=%v)", flag, expected, got, ok)
		}
	}
	if findFlag(collector.Args, "--enroll") < 0 {
		t.Error("expected the --enroll flag")
	}
	if findFlag(collector.Args, "--insecure") < 0 {
		t.Error("expected the --insecure flag for an insecure target")
	}
	if findFlag(collector.Args, "--bmc-ca-cert") >= 0 {
		t.Error("did not expect --bmc-ca-cert for an insecure target")
	}
	if findFlag(collector.Args, "--cert-chain") >= 0 {
		t.Error("did not expect --cert-chain without a reference")
	}

	// credentials go through the keylime config file, not the pod spec
	if len(collector.Env) != 1 || collector.Env[0].Name != "KEYLIME_OOB_CONFIG" ||
		collector.Env[0].Value != "/etc/keylime/oob-config/oob.conf" {
		t.Errorf("unexpected collector env %v", collector.Env)
	}
	for _, arg := range collector.Args {
		if strings.Contains(arg, "s3cr3t") || strings.Contains(arg, "admin") {
			t.Errorf("credentials leaked into the pod spec: %q", arg)
		}
	}

	// volumes: swtpm socket, swtpm state, client TLS, oob config
	volumeNames := map[string]bool{}
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		volumeNames[volume.Name] = true
	}
	for _, expected := range []string{"swtpm", "swtpm-state", "collector-tls", "oob-config"} {
		if !volumeNames[expected] {
			t.Errorf("expected volume %q, got %v", expected, volumeNames)
		}
	}
}

func findFlag(args []string, flag string) int {
	for i, arg := range args {
		if arg == flag {
			return i
		}
	}
	return -1
}

func TestRenderCollectorDeploymentBMCCA(t *testing.T) {
	target := sampleTarget()
	target.Spec.BMC.Insecure = false
	target.Spec.BMC.CACertRef = &attestationv1alpha1.BMCReference{
		SecretName: "bmc-ca",
		Key:        "cacert.crt",
	}
	deployment := renderCollectorDeployment(target, collectorParams{
		AgentUUID:     "00000000-0000-5000-8000-000000000000",
		VerifierHost:  "verifier", VerifierPort: "8881", RegistrarHost: "registrar",
		BMCCAFilename: "cacert.crt",
	})

	collector := deployment.Spec.Template.Spec.Containers[0]
	if findFlag(collector.Args, "--insecure") >= 0 {
		t.Error("did not expect --insecure with a BMC CA reference")
	}
	if got, ok := findArg(collector.Args, "--bmc-ca-cert"); !ok || got != "/etc/keylime/bmc-ca/cacert.crt" {
		t.Errorf("unexpected --bmc-ca-cert %q (ok=%v)", got, ok)
	}
}

func TestRenderCollectorDeploymentCertChainAndDefaults(t *testing.T) {
	target := sampleTarget()
	target.Spec.IntervalSeconds = 0 // defaults to 300
	target.Spec.SPDMCertChain = &attestationv1alpha1.CertChainSource{
		SecretRef: "device-chain",
		Key:       "chain.blob",
	}
	deployment := renderCollectorDeployment(target, collectorParams{
		AgentUUID:    "00000000-0000-5000-8000-000000000000",
		VerifierHost: "verifier", VerifierPort: "8881", RegistrarHost: "registrar",
		CertChainKey: "chain.blob",
	})

	collector := deployment.Spec.Template.Spec.Containers[0]
	if got, ok := findArg(collector.Args, "--interval"); !ok || got != "300" {
		t.Errorf("expected the default interval 300, got %q (ok=%v)", got, ok)
	}
	if got, ok := findArg(collector.Args, "--cert-chain"); !ok || got != "/etc/keylime/spdm/cert-chain.blob" {
		t.Errorf("unexpected --cert-chain %q (ok=%v)", got, ok)
	}

	// no credentials: no config env, no config volume
	if len(collector.Env) != 0 {
		t.Errorf("unexpected collector env %v", collector.Env)
	}
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.Name == "oob-config" {
			t.Error("did not expect the oob-config volume without credentials")
		}
	}
}

func TestRenderCollectorConfigSecret(t *testing.T) {
	target := sampleTarget()
	secret := renderCollectorConfigSecret(target, bmcCredentials{Username: "admin", Password: "s3cr3t"})
	if secret.Name != "vbmc-collector-config" || secret.Namespace != "keylime" {
		t.Errorf("unexpected secret %s/%s", secret.Namespace, secret.Name)
	}
	config := secret.StringData["oob.conf"]
	if !strings.Contains(config, "[oob]\n") ||
		!strings.Contains(config, "bmc_username = admin\n") ||
		!strings.Contains(config, "bmc_password = s3cr3t\n") {
		t.Errorf("unexpected config file %q", config)
	}
}

func TestGenerateClientCertChainsToCA(t *testing.T) {
	caCertPEM, caKeyPEM := mustGenerateCA(t)

	certPEM, keyPEM, err := generateClientCert(caCertPEM, caKeyPEM, "keylime/vbmc")
	if err != nil {
		t.Fatalf("generateClientCert failed: %v", err)
	}

	cert := decodeCert(t, certPEM)
	key := decodeKey(t, keyPEM)
	caCert := decodeCert(t, caCertPEM)

	// client auth usage and the collector's identity
	foundClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("client certificate does not allow client auth")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("unexpected key usage %v", cert.KeyUsage)
	}
	if cert.Subject.CommonName != collectorClientCommonName {
		t.Errorf("unexpected common name %q", cert.Subject.CommonName)
	}
	if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, []string{"keylime/vbmc"}) {
		t.Errorf("unexpected organizational unit %v", cert.Subject.OrganizationalUnit)
	}

	// the certificate chains to the Keylime CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client certificate does not verify against the CA: %v", err)
	}

	// the key matches the certificate
	if key, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("unexpected key type %T", key)
	} else if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("client key does not match the client certificate")
	}
}

func TestKeylimeEndpoints(t *testing.T) {
	keylime := &attestationv1alpha1.Keylime{
		ObjectMeta: metav1.ObjectMeta{Namespace: "keylime", Name: "keylime"},
		Status: attestationv1alpha1.KeylimeStatus{
			VerifierService:  "https://keylime-verifier.keylime.svc:8881",
			RegistrarService: "https://keylime-registrar.keylime.svc:8891",
		},
	}
	verifierHost, verifierPort, registrarHost, err := keylimeEndpoints(keylime)
	if err != nil {
		t.Fatalf("keylimeEndpoints failed: %v", err)
	}
	// the registrar is reached over its plain port, not the TLS one
	if verifierHost != "keylime-verifier.keylime.svc" || verifierPort != "8881" ||
		registrarHost != "keylime-registrar.keylime.svc" {
		t.Errorf("unexpected endpoints %s:%s %s", verifierHost, verifierPort, registrarHost)
	}

	keylime.Status.VerifierService = ""
	if _, _, _, err := keylimeEndpoints(keylime); err == nil {
		t.Error("expected an error when the endpoints are not reported yet")
	}
}

// decodeCertKeyPair is a small helper re-exported for PEM sanity checks.
func TestClientCertPEMEncoding(t *testing.T) {
	caCertPEM, caKeyPEM := mustGenerateCA(t)
	certPEM, keyPEM, err := generateClientCert(caCertPEM, caKeyPEM, "ns/name")
	if err != nil {
		t.Fatalf("generateClientCert failed: %v", err)
	}
	if block, _ := pem.Decode(certPEM); block == nil || block.Type != "CERTIFICATE" {
		t.Error("client certificate is not PEM encoded")
	}
	if block, _ := pem.Decode(keyPEM); block == nil || block.Type != "EC PRIVATE KEY" {
		t.Error("client key is not PEM encoded")
	}
}
