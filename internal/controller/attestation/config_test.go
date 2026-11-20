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
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

func testKeylime() *attestationv1alpha1.Keylime {
	return &attestationv1alpha1.Keylime{
		ObjectMeta: metav1.ObjectMeta{Name: "keylime", Namespace: "keylime"},
	}
}

// confValue parses a rendered INI snippet (no multi-line values needed here)
// and returns the value of an option in a section.
func confValue(t *testing.T, rendered, section, option string) string {
	t.Helper()
	lines := strings.Split(rendered, "\n")
	inSection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = strings.TrimSpace(line[1:len(line)-1]) == section
			continue
		}
		if inSection {
			key, value, found := strings.Cut(line, "=")
			if !found {
				t.Fatalf("invalid config line %q", line)
			}
			if strings.TrimSpace(key) == option {
				return strings.TrimSpace(value)
			}
		}
	}
	t.Fatalf("option %s/%s not found in rendered config:\n%s", section, option, rendered)
	return ""
}

func TestRenderVerifierConfigDefaults(t *testing.T) {
	cr := testKeylime()
	rendered := renderVerifierConfig(cr, sqliteDatabaseURL(verifierDataDir, verifierDatabaseFile))

	for option, want := range map[string]string{
		"port":              "8881",
		"mode":              "push",
		"enable_agent_mtls": "false",
		"tls_dir":           "/etc/keylime/tls",
		"server_cert":       "server-cert.crt",
		"server_key":        "server-private.pem",
		"trusted_client_ca": "['ca.crt']",
		"database_url":      "sqlite:////var/lib/keylime/verifier-data/cv_data.sqlite",
	} {
		if got := confValue(t, rendered, "verifier", option); got != want {
			t.Errorf("verifier/%s = %q, want %q", option, got, want)
		}
	}

	// optional trust stores must not be set when not configured
	for _, option := range []string{"tpm_cert_store", "spdm_corim_signers", "spdm_corim"} {
		if strings.Contains(rendered, option) {
			t.Errorf("verifier/%s should not be set when unconfigured", option)
		}
	}
}

func TestRenderVerifierConfigTrustStores(t *testing.T) {
	cr := testKeylime()
	cr.Spec.TrustStores.TPMCertStore = &attestationv1alpha1.TrustStoreSource{SecretName: "tpm-certs"}
	cr.Spec.TrustStores.CORIMSigners = &attestationv1alpha1.TrustStoreSource{ConfigMapName: "corim-signers"}
	cr.Spec.Appraisal.CORIM = &attestationv1alpha1.TrustStoreSource{SecretName: "corim"}
	rendered := renderVerifierConfig(cr, "sqlite:////var/lib/keylime/verifier-data/cv_data.sqlite")

	if got := confValue(t, rendered, "verifier", "tpm_cert_store"); got != "/var/lib/keylime/tpm-cert-store" {
		t.Errorf("verifier/tpm_cert_store = %q", got)
	}
	if got := confValue(t, rendered, "verifier", "spdm_corim_signers"); got != "/var/lib/keylime/corim-signers" {
		t.Errorf("verifier/spdm_corim_signers = %q", got)
	}
	if got := confValue(t, rendered, "verifier", "spdm_corim"); got != "/var/lib/keylime/corim/corim.cbor" {
		t.Errorf("verifier/spdm_corim = %q", got)
	}
}

func TestRenderRegistrarConfigDefaults(t *testing.T) {
	cr := testKeylime()
	rendered := renderRegistrarConfig(cr, sqliteDatabaseURL(registrarDataDir, registrarDatabaseFile))

	for option, want := range map[string]string{
		"ip":                "0.0.0.0",
		"port":              "8890",
		"tls_port":          "8891",
		"tls_dir":           "/etc/keylime/tls",
		"server_cert":       "server-cert.crt",
		"server_key":        "server-private.pem",
		"trusted_client_ca": "['ca.crt']",
		"database_url":      "sqlite:////var/lib/keylime/registrar-data/reg_data.sqlite",
	} {
		if got := confValue(t, rendered, "registrar", option); got != want {
			t.Errorf("registrar/%s = %q, want %q", option, got, want)
		}
	}
}

func TestRenderRegistrarConfigSPDMStore(t *testing.T) {
	cr := testKeylime()
	cr.Spec.TrustStores.SPDMCertStore = &attestationv1alpha1.TrustStoreSource{SecretName: "spdm-certs"}
	rendered := renderRegistrarConfig(cr, "sqlite:////var/lib/keylime/registrar-data/reg_data.sqlite")
	if got := confValue(t, rendered, "registrar", "spdm_cert_store"); got != "/var/lib/keylime/spdm-cert-store" {
		t.Errorf("registrar/spdm_cert_store = %q", got)
	}
}

func TestRenderConfigExternalDatabase(t *testing.T) {
	cr := testKeylime()
	verifier := renderVerifierConfig(cr, "mysql://user:pass@db/verifier")
	registrar := renderRegistrarConfig(cr, "mysql://user:pass@db/registrar")
	if got := confValue(t, verifier, "verifier", "database_url"); got != "mysql://user:pass@db/verifier" {
		t.Errorf("verifier/database_url = %q", got)
	}
	if got := confValue(t, registrar, "registrar", "database_url"); got != "mysql://user:pass@db/registrar" {
		t.Errorf("registrar/database_url = %q", got)
	}
}

func TestRenderConfigTrustedClientCAs(t *testing.T) {
	cr := testKeylime()
	cr.Spec.TLS.TrustedClientCASecretRefs = []attestationv1alpha1.KeylimeTrustedClientCA{
		{SecretName: "legacy-ca", Key: "cacert.crt"},
	}
	rendered := renderVerifierConfig(cr, "sqlite:////var/lib/keylime/verifier-data/cv_data.sqlite")
	want := "['ca.crt', '/etc/keylime/trusted-ca/trusted-ca-legacy-ca/cacert-crt.crt']"
	if got := confValue(t, rendered, "verifier", "trusted_client_ca"); got != want {
		t.Errorf("verifier/trusted_client_ca = %q, want %q", got, want)
	}
}

func TestRenderAgentConfig(t *testing.T) {
	cr := testKeylime()
	rendered := renderAgentConfig(cr)
	for option, want := range map[string]string{
		"ip":                    "0.0.0.0",
		"registrar_ip":          "keylime-registrar.keylime.svc",
		"registrar_port":        "8890",
		"registrar_tls_port":    "8891",
		"registrar_tls_enabled": "false",
		"enable_agent_mtls":     "false",
		"verifier_url":          "https://keylime-verifier.keylime.svc:8881",
	} {
		if got := confValue(t, rendered, "agent", option); got != want {
			t.Errorf("agent/%s = %q, want %q", option, got, want)
		}
	}
}

func TestServerDNSNames(t *testing.T) {
	cr := testKeylime()
	names := serverDNSNames(cr)
	want := []string{
		"keylime-verifier.keylime.svc",
		"keylime-verifier.keylime.svc.cluster.local",
		"keylime-verifier-0.keylime-verifier.keylime.svc",
		"keylime-registrar.keylime.svc",
		"keylime-registrar.keylime.svc.cluster.local",
		"localhost",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Errorf("serverDNSNames = %v, want %v", names, want)
	}
}

func TestSQLiteDatabaseURL(t *testing.T) {
	if got := sqliteDatabaseURL("/var/lib/keylime/verifier-data", "cv_data.sqlite"); got != "sqlite:////var/lib/keylime/verifier-data/cv_data.sqlite" {
		t.Errorf("sqliteDatabaseURL = %q", got)
	}
	// a trailing slash on the directory must not result in a double slash
	if got := sqliteDatabaseURL("/var/lib/keylime/verifier-data/", "cv_data.sqlite"); got != "sqlite:////var/lib/keylime/verifier-data/cv_data.sqlite" {
		t.Errorf("sqliteDatabaseURL = %q", got)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"cacert.crt":   "cacert-crt",
		"ca cert .pem": "ca-cert-pem",
		"plain":        "plain",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderedConfigIsINI(t *testing.T) {
	// the rendered snippets must be valid enough for Python's configparser:
	// no duplicate sections or options within one file
	cr := testKeylime()
	cr.Spec.TrustStores.SPDMCertStore = &attestationv1alpha1.TrustStoreSource{SecretName: "spdm-certs"}
	for _, rendered := range []string{
		renderVerifierConfig(cr, "sqlite:////x"),
		renderRegistrarConfig(cr, "sqlite:////x"),
		renderAgentConfig(cr),
	} {
		seen := map[string]bool{}
		section := ""
		for _, line := range strings.Split(rendered, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			key := strings.SplitN(line, "=", 2)[0]
			id := fmt.Sprintf("%s/%s", section, key)
			if seen[id] {
				t.Errorf("duplicate option %q in rendered config:\n%s", id, rendered)
			}
			seen[id] = true
		}
	}
}
