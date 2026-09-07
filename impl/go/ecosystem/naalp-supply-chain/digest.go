// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// DigestSet is a set of hex-encoded cryptographic digests keyed by algorithm name, in the
// in-toto ResourceDescriptor "digest" shape (spec/v1/resource_descriptor.md, fetched this
// session: `{"<ALGORITHM>": "<HEX_VALUE>", ...}`, e.g. {"sha256": "7f4714fd..."}). The
// algorithm names used here ("sha256", "sha384") match the in-toto DigestSet convention
// (lower-case, no hyphen) — distinct from CycloneDX's own hash-alg enum spelling
// ("SHA-256"), which sbom.go uses separately for CycloneDX component hashes.
type DigestSet map[string]string

// DigestBytes computes the SHA-256 and SHA-384 digests of data and returns them as a
// DigestSet. It is a pure function of data: replacing data with any other byte slice
// changes both digest values (A4 — a digest function that ignores its input is not a
// digest function).
func DigestBytes(data []byte) DigestSet {
	sum256 := sha256.Sum256(data)
	sum384 := sha512.Sum384(data)
	return DigestSet{
		"sha256": hex.EncodeToString(sum256[:]),
		"sha384": hex.EncodeToString(sum384[:]),
	}
}

// DigestReader streams r through SHA-256 and SHA-384 simultaneously (io.MultiWriter over
// both hash.Hash sinks, one pass over r) and returns the resulting DigestSet. A nil r is
// rejected before any read (ErrEmptyInput) — there is no well-defined digest of "no
// reader", as opposed to the digest of an empty byte slice, which DigestBytes(nil)
// computes as the well-known SHA-256/SHA-384 empty-input constants.
func DigestReader(r io.Reader) (DigestSet, error) {
	if r == nil {
		return nil, ErrEmptyInput
	}
	h256 := sha256.New()
	h384 := sha512.New384()
	mw := io.MultiWriter(h256, h384)
	if _, err := io.Copy(mw, r); err != nil {
		return nil, err
	}
	return DigestSet{
		"sha256": hex.EncodeToString(h256.Sum(nil)),
		"sha384": hex.EncodeToString(h384.Sum(nil)),
	}, nil
}

// Equal reports whether two DigestSets agree on every algorithm both sets carry, and that
// at least one algorithm is shared. It is deliberately NOT a strict map-equality check: a
// producer and a consumer may compute a different (overlapping) set of algorithms, and
// SLSA's own guidance (in-toto ResourceDescriptor semantics) is that a digest match is
// established per-algorithm, not by requiring the whole set to be identical.
func (d DigestSet) Equal(other DigestSet) bool {
	if len(d) == 0 || len(other) == 0 {
		return false
	}
	shared := false
	for alg, val := range d {
		ov, ok := other[alg]
		if !ok {
			continue
		}
		shared = true
		if val != ov {
			return false
		}
	}
	return shared
}
