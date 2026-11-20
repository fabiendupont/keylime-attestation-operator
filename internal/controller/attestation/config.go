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
	"net"
	"sort"
	"strings"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

// Mount points and file names used by the keylime operand pods. The conf.d
// mechanism of keylime's config parser merges these snippets over the
// defaults baked into the container images.
const (
	verifierConfigFile    = "50-operator.conf"
	registrarConfigFile   = "50-operator.conf"
	tlsDir                = "/etc/keylime/tls"
	verifierDataDir       = "/var/lib/keylime/verifier-data"
	registrarDataDir      = "/var/lib/keylime/registrar-data"
	tpmCertStoreDir       = "/var/lib/keylime/tpm-cert-store"
	spdmCertStoreDir      = "/var/lib/keylime/spdm-cert-store"
	corimSignersDir       = "/var/lib/keylime/corim-signers"
	corimDir              = "/var/lib/keylime/corim"
	corimFile             = "corim.cbor"
	serverCertFile        = "server-cert.crt"
	serverKeyFile         = "server-private.pem"
	caCertFile            = "ca.crt"
	trustedCADir          = "/etc/keylime/trusted-ca"
	verifierDatabaseFile  = "cv_data.sqlite"
	registrarDatabaseFile = "reg_data.sqlite"
	sqliteURLPrefix       = "sqlite:///"
)

// sqliteDatabaseURL renders the SQLAlchemy URL for a SQLite database file in
// the given directory. Four slashes: sqlalchemy "sqlite:///" + absolute path.
func sqliteDatabaseURL(dir, file string) string {
	return sqliteURLPrefix + strings.TrimSuffix(dir, "/") + "/" + file
}

// trustedClientCAs returns the trusted client CA list for the given Keylime
// CR, as a Python list literal (keylime's config parser expects one for list
// options). Relative paths are resolved against the TLS directory by keylime,
// absolute paths are used as-is.
func trustedClientCAs(cr *attestationv1alpha1.Keylime) string {
	cas := []string{caCertFile}
	for _, ref := range cr.Spec.TLS.TrustedClientCASecretRefs {
		cas = append(cas, fmt.Sprintf("%s/%s/%s.crt", trustedCADir, "trusted-ca-"+ref.SecretName, sanitize(ref.Key)))
	}
	quoted := make([]string, 0, len(cas))
	for _, ca := range cas {
		quoted = append(quoted, "'"+ca+"'")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func sanitize(name string) string {
	replaced := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, name)
	// collapse separator runs and trim them
	for strings.Contains(replaced, "--") {
		replaced = strings.ReplaceAll(replaced, "--", "-")
	}
	return strings.Trim(replaced, "-")
}

// renderVerifierConfig renders the verifier.conf.d snippet for the given CR.
// The databaseURL parameter is the resolved SQLAlchemy URL (from the spec for
// external databases, or the PVC-backed SQLite path otherwise).
func renderVerifierConfig(cr *attestationv1alpha1.Keylime, databaseURL string) string {
	var b strings.Builder
	b.WriteString("# Rendered by the attestation-operator; overrides verifier.conf defaults.\n")
	b.WriteString("[verifier]\n")
	fmt.Fprintf(&b, "ip = %s\n", "0.0.0.0")
	fmt.Fprintf(&b, "port = %d\n", 8881)
	fmt.Fprintf(&b, "mode = push\n")
	fmt.Fprintf(&b, "enable_agent_mtls = false\n")
	fmt.Fprintf(&b, "tls_dir = %s\n", tlsDir)
	fmt.Fprintf(&b, "server_cert = %s\n", serverCertFile)
	fmt.Fprintf(&b, "server_key = %s\n", serverKeyFile)
	fmt.Fprintf(&b, "trusted_client_ca = %s\n", trustedClientCAs(cr))
	fmt.Fprintf(&b, "database_url = %s\n", databaseURL)
	if cr.Spec.TrustStores.TPMCertStore != nil {
		fmt.Fprintf(&b, "tpm_cert_store = %s\n", tpmCertStoreDir)
	}
	if cr.Spec.TrustStores.CORIMSigners != nil {
		fmt.Fprintf(&b, "spdm_corim_signers = %s\n", corimSignersDir)
	}
	if cr.Spec.Appraisal.CORIM != nil {
		fmt.Fprintf(&b, "spdm_corim = %s/%s\n", corimDir, corimFile)
	}
	return b.String()
}

// renderRegistrarConfig renders the registrar.conf.d snippet for the given CR.
func renderRegistrarConfig(cr *attestationv1alpha1.Keylime, databaseURL string) string {
	var b strings.Builder
	b.WriteString("# Rendered by the attestation-operator; overrides registrar.conf defaults.\n")
	b.WriteString("[registrar]\n")
	fmt.Fprintf(&b, "ip = %s\n", "0.0.0.0")
	fmt.Fprintf(&b, "port = %d\n", 8890)
	fmt.Fprintf(&b, "tls_port = %d\n", 8891)
	fmt.Fprintf(&b, "tls_dir = %s\n", tlsDir)
	fmt.Fprintf(&b, "server_cert = %s\n", serverCertFile)
	fmt.Fprintf(&b, "server_key = %s\n", serverKeyFile)
	fmt.Fprintf(&b, "trusted_client_ca = %s\n", trustedClientCAs(cr))
	fmt.Fprintf(&b, "database_url = %s\n", databaseURL)
	if cr.Spec.TrustStores.SPDMCertStore != nil {
		fmt.Fprintf(&b, "spdm_cert_store = %s\n", spdmCertStoreDir)
	}
	return b.String()
}

// renderAgentConfig renders the agent.conf.d snippet for the given CR. Agents
// register with the registrar over its plain HTTP port.
func renderAgentConfig(cr *attestationv1alpha1.Keylime) string {
	var b strings.Builder
	b.WriteString("# Rendered by the attestation-operator; overrides agent.conf defaults.\n")
	b.WriteString("[agent]\n")
	fmt.Fprintf(&b, "ip = %s\n", "0.0.0.0")
	fmt.Fprintf(&b, "registrar_ip = %s-registrar.%s.svc\n", cr.Name, cr.Namespace)
	fmt.Fprintf(&b, "registrar_port = %d\n", 8890)
	fmt.Fprintf(&b, "registrar_tls_port = %d\n", 8891)
	fmt.Fprintf(&b, "registrar_tls_enabled = false\n")
	fmt.Fprintf(&b, "enable_agent_mtls = false\n")
	fmt.Fprintf(&b, "verifier_url = https://%s-verifier.%s.svc:8881\n", cr.Name, cr.Namespace)
	return b.String()
}

// serverDNSNames returns the SAN entries for the shared server certificate:
// the stable service DNS names of both operands (with and without the
// cluster-local suffix) plus localhost.
func serverDNSNames(cr *attestationv1alpha1.Keylime) []string {
	ns := cr.Namespace
	base := []string{
		fmt.Sprintf("%s-verifier.%s.svc", cr.Name, ns),
		fmt.Sprintf("%s-verifier.%s.svc.cluster.local", cr.Name, ns),
		fmt.Sprintf("%s-verifier-0.%s-verifier.%s.svc", cr.Name, cr.Name, ns),
		fmt.Sprintf("%s-registrar.%s.svc", cr.Name, ns),
		fmt.Sprintf("%s-registrar.%s.svc.cluster.local", cr.Name, ns),
		"localhost",
	}
	sort.Strings(base)
	return base
}

// serverIPAddresses returns the SAN IP entries for the server certificate.
func serverIPAddresses() []net.IP {
	return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
}
