// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package registrar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	khttp "github.com/keylime/attestation-operator/pkg/client/http"
)

// newTestClientCertificate generates an ephemeral self-signed certificate and
// key in a temporary directory and returns a Keylime HTTP client configured
// with them. This keeps the tests self-contained (no hardcoded host paths).
func newTestClientCertificate(t *testing.T) *http.Client {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate certificate serial: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Keylime"},
			CommonName:   "test-client",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	certFile := filepath.Join(t.TempDir(), "client-cert.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write test certificate: %v", err)
	}

	keyFile := filepath.Join(t.TempDir(), "client-private.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal test key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	hc, err := khttp.NewKeylimeHTTPClient(
		khttp.ClientCertificate(certFile, keyFile),
		khttp.InsecureSkipVerify(),
	)
	if err != nil {
		t.Fatalf("failed to create Keylime HTTP client: %v", err)
	}
	return hc
}

func Test_registrarClient_ListAgents(t *testing.T) {
	tests := []struct {
		name    string
		want    []string
		wantErr bool
	}{
		{
			name: "success",
			want: []string{"81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c", "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.EscapedPath() != "/v2.1/agents/" {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {"uuids": ["81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c", "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8"]}}`)
			}))
			defer ts.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc := newTestClientCertificate(t)
			c, err := New(ctx, hc, ts.URL)
			if err != nil {
				t.Fatalf("failed to create registrar client: %v", err)
			}
			got, err := c.ListAgents(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.ListAgents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("registrarClient.ListAgents() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_registrarClient_GetAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success1",
			args: args{
				uuid: "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8",
			},
		},
		{
			name: "success2",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The registrar response contains an EK certificate (DER) and an
			// mTLS certificate (PEM) that must parse, so generate a real one.
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate test key: %v", err)
			}
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if err != nil {
				t.Fatalf("failed to generate certificate serial: %v", err)
			}
			template := x509.Certificate{
				SerialNumber: serial,
				Subject: pkix.Name{
					Organization: []string{"Keylime"},
					CommonName:   "test-agent",
				},
				NotBefore:   time.Now().Add(-time.Hour),
				NotAfter:    time.Now().Add(time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
			if err != nil {
				t.Fatalf("failed to create test certificate: %v", err)
			}
			ekCertB64 := base64.StdEncoding.EncodeToString(der)
			mtlsCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				agentJSON := fmt.Sprintf(`{"code": 200, "status": "Success", "results": {"aik_tpm": %q, "ek_tpm": %q, "ekcert": %q, "mtls_cert": %q, "ip": "10.244.0.165", "port": 9002, "regcount": 1}}`,
					base64.StdEncoding.EncodeToString([]byte("aik-tpm")), base64.StdEncoding.EncodeToString([]byte("ek-tpm")), ekCertB64, mtlsCert)
				fmt.Fprint(w, agentJSON)
			}))
			defer ts.Close()
			url, err := url.Parse(ts.URL)
			if err != nil {
				panic(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &registrarClient{
				http:              ts.Client(),
				url:               url,
				internalCtx:       ctx,
				internalCtxCancel: cancel,
			}

			got, err := c.GetAgent(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.GetAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && got.UUID != tt.args.uuid {
				t.Errorf("registrarClient.GetAgent() UUID = %v, want %v", got.UUID, tt.args.uuid)
			}
		})
	}
}

func Test_registrarClient_DeleteAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "a25bd3603bd6d838824fcb9c7ba835bf4f7604609b4d5019bba6d7628cebf6c8",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {}}`)
			}))
			defer ts.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc := newTestClientCertificate(t)
			c, err := New(ctx, hc, ts.URL)
			if err != nil {
				t.Fatalf("failed to create registrar client: %v", err)
			}
			if err := c.DeleteAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("registrarClient.DeleteAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_registrarClient_GetAgentSPDM(t *testing.T) {
	// An agent registered with an SPDM device certificate chain has no EK certificate
	// and no mTLS certificate; parsing must succeed and expose the chain
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {"aik_tpm": "", "ek_tpm": "", "spdm_cert_chain": "BGgDAAKAbgM=", "ip": "10.244.0.166", "port": 0, "regcount": 1}}`)
	}))
	defer ts.Close()

	url, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &registrarClient{
		http:              ts.Client(),
		url:               url,
		internalCtx:       ctx,
		internalCtxCancel: cancel,
	}

	agent, err := c.GetAgent(ctx, "94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01")
	if err != nil {
		t.Errorf("registrarClient.GetAgent() error = %v, wantErr false", err)
		return
	}
	if len(agent.SPDMCertChain) != 8 {
		t.Errorf("SPDMCertChain = %v, want 8 bytes", agent.SPDMCertChain)
	}
	if agent.EKCert != nil || agent.MTLSCert != nil {
		t.Errorf("EKCert/MTLSCert should be nil for an SPDM-only agent")
	}
}

func Test_registrarClient_GetAgentNoIdentity(t *testing.T) {
	// An agent without EK certificate, mTLS certificate and SPDM chain is malformed
	// and must still be rejected
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {"aik_tpm": "", "ek_tpm": "", "ip": "10.244.0.166", "port": 0, "regcount": 1}}`)
	}))
	defer ts.Close()

	url, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &registrarClient{
		http:              ts.Client(),
		url:               url,
		internalCtx:       ctx,
		internalCtxCancel: cancel,
	}

	if _, err := c.GetAgent(ctx, "94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01"); err == nil {
		t.Errorf("registrarClient.GetAgent() error = nil, wantErr true")
	}
}
