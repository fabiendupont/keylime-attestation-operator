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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"
)

func mustGenerateCA(t *testing.T) (caCertPEM, caKeyPEM []byte) {
	t.Helper()
	caCertPEM, caKeyPEM, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}
	return caCertPEM, caKeyPEM
}

func decodeCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("unable to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("unable to parse certificate: %v", err)
	}
	return cert
}

func decodeKey(t *testing.T, keyPEM []byte) any {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatalf("unable to decode key PEM")
	}
	key, err := parseKeyPEM(block)
	if err != nil {
		t.Fatalf("unable to parse key: %v", err)
	}
	return key
}

// TestGenerateCABasic checks that a generated CA parses and is a CA.
func TestGenerateCABasic(t *testing.T) {
	caCertPEM, _ := mustGenerateCA(t)
	ca := decodeCert(t, caCertPEM)
	if !ca.IsCA {
		t.Error("generated certificate is not a CA")
	}
	if ca.Subject.CommonName != caCommonName {
		t.Errorf("unexpected CA common name %q", ca.Subject.CommonName)
	}
	if !ca.BasicConstraintsValid {
		t.Error("basic constraints not valid on the CA")
	}
}

// TestServerCertSANs is the regression test for the InsecureSkipVerify era:
// the server certificate must carry the DNS names of the services it is
// served under, so that clients can verify the hostname instead of skipping
// certificate verification.
func TestServerCertSANs(t *testing.T) {
	caCertPEM, caKeyPEM := mustGenerateCA(t)

	dnsNames := []string{
		"keylime-verifier.keylime.svc",
		"keylime-verifier.keylime.svc.cluster.local",
		"keylime-registrar.keylime.svc",
	}
	ips := []net.IP{net.ParseIP("127.0.0.1")}

	certPEM, keyPEM, err := generateServerCert(caCertPEM, caKeyPEM, dnsNames, ips)
	if err != nil {
		t.Fatalf("generateServerCert failed: %v", err)
	}
	cert := decodeCert(t, certPEM)

	got := append([]string{}, cert.DNSNames...)
	sort.Strings(got)
	want := append([]string{}, dnsNames...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("certificate SANs = %v, want %v", got, want)
	}
	if len(cert.IPAddresses) != len(ips) {
		t.Fatalf("certificate IP SANs = %v, want %v", cert.IPAddresses, ips)
	}
	for i, ip := range ips {
		if !cert.IPAddresses[i].Equal(ip) {
			t.Errorf("certificate IP SANs = %v, want %v", cert.IPAddresses, ips)
		}
	}

	// the SANs must actually verify: this is what a TLS client (previously
	// forced to InsecureSkipVerify) checks
	for _, name := range dnsNames {
		if err := cert.VerifyHostname(name); err != nil {
			t.Errorf("hostname %q does not verify against the certificate: %v", name, err)
		}
	}
	if err := cert.VerifyHostname("evil.example.com"); err == nil {
		t.Error("an unrelated hostname unexpectedly verified")
	}

	// ExtKeyUsage must allow server authentication
	foundServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
		}
	}
	if !foundServerAuth {
		t.Error("certificate does not allow server authentication")
	}

	// the key must be usable and match the certificate
	key, ok := decodeKey(t, keyPEM).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("server key has unexpected type %T", key)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("server certificate public key does not match the server key")
	}
}

// TestServerCertChainsToCA checks that the server certificate chains to the
// CA that signed it, i.e. that presenting the CA to clients lets them verify
// the server certificate.
func TestServerCertChainsToCA(t *testing.T) {
	caCertPEM, caKeyPEM := mustGenerateCA(t)
	ca := decodeCert(t, caCertPEM)

	certPEM, _, err := generateServerCert(caCertPEM, caKeyPEM, []string{"keylime-verifier.keylime.svc"}, nil)
	if err != nil {
		t.Fatalf("generateServerCert failed: %v", err)
	}
	cert := decodeCert(t, certPEM)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "keylime-verifier.keylime.svc",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("server certificate does not verify against the CA: %v", err)
	}
}

// TestServerCertChainsToBYOCA checks that a CA brought by the user (for
// example a PEM CA generated with openssl, RSA or PKCS#8) can sign the server
// certificate.
func TestServerCertChainsToBYOCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "byo-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("unable to create CA: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("unable to marshal key: %v", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	certPEM, _, err := generateServerCert(caCertPEM, caKeyPEM, []string{"keylime-verifier.keylime.svc"}, nil)
	if err != nil {
		t.Fatalf("generateServerCert with a BYO CA failed: %v", err)
	}

	ca := decodeCert(t, caCertPEM)
	cert := decodeCert(t, certPEM)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "keylime-verifier.keylime.svc"}); err != nil {
		t.Errorf("server certificate does not verify against the BYO CA: %v", err)
	}
}

// TestCAFingerprint checks the fingerprint format (openssl-compatible,
// colon-separated uppercase hex).
func TestCAFingerprint(t *testing.T) {
	caCertPEM, _ := mustGenerateCA(t)
	fingerprint, err := caFingerprint(caCertPEM)
	if err != nil {
		t.Fatalf("caFingerprint failed: %v", err)
	}
	if len(fingerprint) != 95 { // 32 bytes, 2 hex digits + 31 colons
		t.Errorf("unexpected fingerprint length %d: %q", len(fingerprint), fingerprint)
	}
	again, _ := caFingerprint(caCertPEM)
	if fingerprint != again {
		t.Error("fingerprint is not stable")
	}
	other, _, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA failed: %v", err)
	}
	otherFingerprint, _ := caFingerprint(other)
	if fingerprint == otherFingerprint {
		t.Error("two CAs have the same fingerprint")
	}
}
