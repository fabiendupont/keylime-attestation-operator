// Copyright 2023 The Keylime Authors
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	ctrl "sigs.k8s.io/controller-runtime"
)

var logger = ctrl.Log.WithName("unittest")

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

	dir := t.TempDir()
	certFile := filepath.Join(dir, "client-cert.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write test certificate: %v", err)
	}

	keyFile := filepath.Join(dir, "client-private.pem")
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

func Test_verifierClient_GetAgent(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		want    *Agent
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"code": 200, "status": "Success", "results": {"operational_state": 7, "v": "yyNnlWwFRz1ZUzSe2YEpz9A5urtv6oywgttTF7VbBP4=", "ip": "127.0.0.1", "port": 9002, "tpm_policy": "{}", "vtpm_policy": "{}", "meta_data": "{}", "has_mb_refstate": 0, "has_runtime_policy": 0, "accept_tpm_hash_algs": ["sha256"], "accept_tpm_encryption_algs": ["rsa"], "accept_tpm_signing_algs": ["rsassa"], "hash_alg": "sha256", "enc_alg": "rsa", "sign_alg": "rsassa", "verifier_id": "default", "verifier_ip": "127.0.0.1", "verifier_port": 8881, "severity_level": 5, "last_event_id": "mock_agent", "attestation_count": 1, "last_received_quote": 1689071853, "last_successful_attestation": 1689071853}}`)
			}))
			defer ts.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc := newTestClientCertificate(t)
			c, _, err := New(ctx, logger, hc, ts.URL)
			if err != nil {
				t.Fatalf("failed to create verifier client: %v", err)
			}
			got, err := c.GetAgent(ctx, tt.args.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.GetAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifierClient.GetAgent() = %v, want %v", got, tt.want)
			}
			if err == nil && got == nil {
				t.Errorf("verifierClient.GetAgent() = nil, want an agent")
			}
		})
	}
}

func Test_verifierClient_StopAgent(t *testing.T) {
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
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
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
			c, _, err := New(ctx, logger, hc, ts.URL)
			if err != nil {
				t.Fatalf("failed to create verifier client: %v", err)
			}
			if err := c.StopAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.StopAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_verifierClient_ReactivateAgent(t *testing.T) {
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
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
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
			c, _, err := New(ctx, logger, hc, ts.URL)
			if err != nil {
				t.Fatalf("failed to create verifier client: %v", err)
			}
			if err := c.ReactivateAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.ReactivateAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_verifierClient_DeleteAgent(t *testing.T) {
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
				uuid: "81c40e8ad10b15efe65dfad61614dca80e675d4b95ef00d11d239624435e258c",
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
			c, _, err := New(ctx, logger, hc, ts.URL)
			if err != nil {
				t.Fatalf("failed to create verifier client: %v", err)
			}
			if err := c.DeleteAgent(ctx, tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("verifierClient.DeleteAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_verifierClient_GetLatestAttestation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v3/agents/94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01/attestations/latest" {
			t.Errorf("unexpected request path: %s", r.URL.EscapedPath())
		}
		// the verifier answers GETs of the /latest alias with 201 + Location; both
		// 200 and 201 must be accepted
		w.Header().Set("Location", "/v3/agents/94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01/attestations/23")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"data": {"attributes": {"stage": "verification_complete", "evaluation": "pass", "evidence_received_at": "2026-11-19T19:54:06.391938+00:00"}}}`)
	}))
	defer ts.Close()

	url, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &verifierClient{
		http:              ts.Client(),
		url:               url,
		internalCtx:       ctx,
		internalCtxCancel: cancel,
	}

	attestation, err := c.GetLatestAttestation(ctx, "94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01")
	if err != nil {
		t.Errorf("verifierClient.GetLatestAttestation() error = %v, wantErr false", err)
		return
	}
	if attestation.Stage != "verification_complete" || attestation.Evaluation != "pass" {
		t.Errorf("stage/evaluation = %s/%s, want verification_complete/pass", attestation.Stage, attestation.Evaluation)
	}
	if attestation.EvidenceReceivedAt == nil || attestation.EvidenceReceivedAt.Year() != 2026 {
		t.Errorf("evidenceReceivedAt = %v, want 2026-11-19", attestation.EvidenceReceivedAt)
	}
}

func Test_verifierClient_GetLatestAttestationNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errors": [{"code": "not_found"}]}`)
	}))
	defer ts.Close()

	url, err := url.Parse(ts.URL)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &verifierClient{
		http:              ts.Client(),
		url:               url,
		internalCtx:       ctx,
		internalCtxCancel: cancel,
	}

	if _, err := c.GetLatestAttestation(ctx, "94c56a96-1d2f-4a08-8b6c-6f8b1e2a9d01"); !khttp.IsNotFoundError(err) {
		t.Errorf("verifierClient.GetLatestAttestation() error = %v, want not-found", err)
	}
}
