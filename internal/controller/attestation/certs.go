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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	caCommonName              = "attestation-operator-ca"
	serverCommonName          = "keylime-server"
	collectorClientCommonName = "keylime-collector"
	certificateDuration       = 10 * 365 * 24 * time.Hour
	caMaxSerial         int64 = 1 << 48
)

// generateCA creates a new self-signed certificate authority. It returns the
// CA certificate and private key, both PEM encoded.
func generateCA() (caCert []byte, caKey []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(caMaxSerial))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCommonName, Organization: []string{"attestation-operator"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certificateDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create CA certificate: %w", err)
	}

	caCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal CA key: %w", err)
	}
	caKey = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return caCert, caKey, nil
}

// generateServerCert creates a server certificate signed by the given CA with
// SANs for the given DNS names and IP addresses. This is what allows the
// keylime components to be reached over TLS without disabling certificate
// verification (the historical InsecureSkipVerify workaround).
func generateServerCert(caCertPEM, caKeyPEM []byte, dnsNames []string, ipAddresses []net.IP) ([]byte, []byte, error) {
	caCert, caKey, err := parseCAPEM(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate server key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(caMaxSerial))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate server serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverCommonName, Organization: []string{"attestation-operator"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certificateDuration),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateClientCert creates a client certificate signed by the given CA,
// carrying the identity of an operator-managed collector (organization,
// organizational unit). The verifier and registrar trust the same CA by
// construction, so this replaces the legacy client certificate dependency
// for operator-managed collectors.
func generateClientCert(caCertPEM, caKeyPEM []byte, organizationalUnit string) ([]byte, []byte, error) {
	caCert, caKey, err := parseCAPEM(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate client key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(caMaxSerial))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate client serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         collectorClientCommonName,
			Organization:       []string{"attestation-operator"},
			OrganizationalUnit: []string{organizationalUnit},
		},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(certificateDuration),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal client key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// parseCAPEM decodes PEM encoded CA certificate and private key material. Both
// EC and PKCS#8/RSA/PKCS#1 (via the generic x509.ParsePKCS8PrivateKey path
// where applicable) keys are supported; the key just has to be usable for
// signing by the standard library.
func parseCAPEM(caCertPEM, caKeyPEM []byte) (*x509.Certificate, any, error) {
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("unable to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("the provided CA certificate is not a certificate authority")
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("unable to decode CA key PEM")
	}
	caKey, err := parseKeyPEM(keyBlock)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

func parseKeyPEM(block *pem.Block) (any, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse EC private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse RSA private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse PKCS#8 private key: %w", err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
}

// caFingerprint returns the colon-separated hex SHA-256 fingerprint of a PEM
// encoded certificate, mirroring `openssl x509 -fingerprint -sha256`.
func caFingerprint(caCertPEM []byte) (string, error) {
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return "", fmt.Errorf("unable to decode certificate PEM")
	}
	sum := sha256.Sum256(certBlock.Bytes)
	fingerprint := make([]byte, 0, len(sum)*3)
	for _, b := range sum {
		if len(fingerprint) > 0 {
			fingerprint = append(fingerprint, ':')
		}
		fingerprint = append(fingerprint, hexDigit(b>>4), hexDigit(b&0xf))
	}
	return string(fingerprint), nil
}

func hexDigit(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'A' + v - 10
}
