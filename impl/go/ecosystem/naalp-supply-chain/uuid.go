// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"crypto/rand"
	"encoding/hex"
)

// newUUIDv4 generates an RFC 4122 version-4 (random) UUID, formatted as the canonical
// 8-4-4-4-12 hex string (no braces, no "urn:uuid:" prefix — the caller adds that prefix
// where CycloneDX's serialNumber field requires it). RFC 4122 §4.4 defines version 4: all
// bits random except the 4-bit version field (set to 0100) and the 2-bit variant field of
// octet 8 (set to 10). This draws its randomness from crypto/rand (cryptographically
// secure), never math/rand.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	buf := make([]byte, 36)
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf), nil
}
