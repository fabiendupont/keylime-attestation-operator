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
	"crypto/x509"
	"encoding/pem"
	"errors"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// parseCertificatePEM decodes a single PEM encoded certificate.
func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("unable to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func int32Ptr(v int32) *int32 {
	return &v
}

func derefInt32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func mustParseQuantity(s string) resource.Quantity {
	return resource.MustParse(s)
}

func intstrFromInt(v int32) intstr.IntOrString {
	return intstr.FromInt32(v)
}

func boolPtr(v bool) *bool {
	return &v
}
