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
	"crypto/sha1" //nolint:gosec // UUIDv5 is specified in terms of SHA-1 (RFC 4122)
	"encoding/hex"
	"fmt"
	"strings"
)

// agentUUIDNamespace is the fixed UUID namespace used to derive agent UUIDs
// from the namespaced names of AttestationTargets. It is the standard "OID"
// namespace from RFC 4122 (6ba7b810-9dad-11d1-80b4-00c04fd430c8); any fixed
// value would do, but a standard one documents the choice.
var agentUUIDNamespace = [16]byte{
	0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

// deriveAgentUUID returns the deterministic agent UUID of an
// AttestationTarget: UUIDv5 (SHA-1, RFC 4122 section 4.3) of
// "namespace/name" under the fixed OID namespace. Deriving the identity from
// the namespaced name (instead of letting the collector make one up, or
// keeping it in the swtpm's state) keeps it stable across collector
// reinstalls: the collector's swtpm identity is ephemeral, but the Agent CR
// and the verifier enrollment follow the UUID.
func deriveAgentUUID(namespace, name string) string {
	h := sha1.New() //nolint:gosec // see agentUUIDNamespace
	h.Write(agentUUIDNamespace[:])
	h.Write([]byte(namespace + "/" + name))
	sum := h.Sum(nil)[:16]

	// version 5, RFC 4122 variant
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80

	var uuid [16]byte
	copy(uuid[:], sum)
	return formatUUID(uuid)
}

// formatUUID renders 16 bytes as the canonical 8-4-4-4-12 lower-case hex form.
func formatUUID(b [16]byte) string {
	var s strings.Builder
	hexed := hex.EncodeToString(b[:])
	for i, group := range []int{8, 4, 4, 4, 12} {
		if i > 0 {
			s.WriteByte('-')
		}
		s.WriteString(hexed[:group])
		hexed = hexed[group:]
	}
	return s.String()
}

// validateAgentUUID checks that an explicitly configured agent UUID has the
// canonical UUID format (the CRD pattern already enforces this; this is the
// controller-side check for programmatic use).
func validateAgentUUID(uuid string) error {
	if len(uuid) != 36 {
		return fmt.Errorf("invalid agent UUID %q: expected 36 characters", uuid)
	}
	for i, c := range uuid {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return fmt.Errorf("invalid agent UUID %q: expected '-' at position %d", uuid, i)
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return fmt.Errorf("invalid agent UUID %q: unexpected character %q", uuid, c)
		}
	}
	return nil
}
