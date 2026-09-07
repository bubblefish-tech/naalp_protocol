// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// FuzzEnvelopeDecode fuzzes arbitrary bytes into the top-level object BODY decode path
// (decodeAndCheck -> cbor.DecodeBounded -> objectFromMap), which runs BEFORE signature
// verification (design.md §3.4: bounds must reject before authentication, so an attacker
// cannot force expensive ML-DSA verification with an oversized/malformed body). The
// protected header is held FIXED to a real, validly-signed header (so the fuzzer's budget is
// spent on the body decode path this residual targets, not on re-discovering protected-header
// framing from scratch) while the payload -- everything cbor.DecodeBounded and objectFromMap
// actually parse -- is fully arbitrary.
//
// Two properties are checked, both independent of decodeAndCheck's own bookkeeping:
//  1. It never panics on adversarial input (RFC 8949 §10; the crash-safety half of R7).
//  2. Whenever it accepts (returns a nil error), the resulting Object's Causes/Ext/Cext
//     cardinalities never exceed MaxCauses/MaxExt/MaxCext -- re-checked here by directly
//     counting the returned slices/maps, not by trusting objectFromMap's internal comparison
//     (the same independent-recount discipline FuzzDecodeBounded's actualDepth uses).
func FuzzEnvelopeDecode(f *testing.F) {
	signer := fuzzSigner()
	fixedProt := realProtectedHeader(f, signer)

	seeds := [][]byte{
		fuzzPayloadFor(f, signer, buildFuzzObject(0, 0, 0)),                       // ordinary, no extensions
		fuzzPayloadFor(f, signer, buildFuzzObject(MaxCauses, 0, 0)),               // causes AT the limit
		fuzzPayloadFor(f, signer, buildFuzzObject(MaxCauses+1, 0, 0)),             // causes ONE past it
		fuzzPayloadFor(f, signer, buildFuzzObject(0, MaxExt, 0)),                  // ext AT the limit
		fuzzPayloadFor(f, signer, buildFuzzObject(0, MaxExt+1, 0)),                // ext ONE past it
		fuzzPayloadFor(f, signer, buildFuzzObject(0, 0, MaxCext)),                 // cext AT the limit
		fuzzPayloadFor(f, signer, buildFuzzObject(0, 0, MaxCext+1)),               // cext ONE past it
		{},                     // empty payload
		{0x00},                 // a bare scalar, not a map
		[]byte("not-cbor-at-all"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		o, _, err := decodeAndCheck(fixedProt, payload, nil)
		if err != nil {
			return // rejection is always an acceptable outcome for untrusted input
		}
		if len(o.Causes) > MaxCauses {
			t.Fatalf("decodeAndCheck accepted %d causes (> MaxCauses=%d): %x", len(o.Causes), MaxCauses, payload)
		}
		if len(o.Ext) > MaxExt {
			t.Fatalf("decodeAndCheck accepted %d ext entries (> MaxExt=%d): %x", len(o.Ext), MaxExt, payload)
		}
		if len(o.Cext) > MaxCext {
			t.Fatalf("decodeAndCheck accepted %d cext entries (> MaxCext=%d): %x", len(o.Cext), MaxCext, payload)
		}
	})
}

// fuzzSigner derives a fixed ML-DSA-65 signer, mirroring testSigner in envelope_test.go but
// kept local to this file (and taking no *testing.T/F) so the fuzz target has no ordering
// dependency on other _test.go helpers and can also be called from f.Add-time seed builders.
func fuzzSigner() cose.Signer {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}
}

// buildFuzzObject builds an otherwise-valid Object with nCauses/nExt/nCext entries, matching
// bounds_test.go's makeCauses/makeExtMap shape (a content-id-shaped bstr per cause; distinct
// unknown non-critical keys per extension entry).
func buildFuzzObject(nCauses, nExt, nCext int) *Object {
	o := &Object{
		Kind: 2, Channel: 4, Tier: 1, Signer: []byte{0xaa}, Created: 1, Effect: 0, Profile: 1,
		Body: cbor.Tstr("seed"),
	}
	for i := 0; i < nCauses; i++ {
		b := make([]byte, 50)
		b[0], b[1] = 0x20, 0x30
		o.Causes = append(o.Causes, b)
	}
	if nExt > 0 {
		m := make(cbor.Map, nExt)
		for i := 0; i < nExt; i++ {
			m[i] = cbor.Pair{K: cbor.Uint(uint64(500 + i)), V: cbor.Uint(0)}
		}
		o.Ext = m
	}
	if nCext > 0 {
		m := make(cbor.Map, nCext)
		for i := 0; i < nCext; i++ {
			// Field values are non-critical-recognized-elsewhere placeholder keys; objectFromMap
			// only checks CARDINALITY, not recognition, so any distinct uint keys are fine here.
			m[i] = cbor.Pair{K: cbor.Uint(uint64(700 + i)), V: cbor.Uint(0)}
		}
		o.Cext = m
	}
	return o
}

// fuzzPayloadFor signs o and extracts its real, canonically-encoded payload bytes via
// cose.ParseSign1Raw -- the same bytes decodeAndCheck's payload argument receives in
// production, so every seed is a genuine (not hand-assembled) payload.
func fuzzPayloadFor(f *testing.F, signer cose.Signer, o *Object) []byte {
	f.Helper()
	obj, err := Sign(o, signer)
	if err != nil {
		f.Fatalf("sign seed object: %v", err)
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		f.Fatalf("parse seed object: %v", err)
	}
	return payload
}

// realProtectedHeader signs a trivial object and returns its real protected-header bytes,
// held fixed across every fuzz iteration so decodeAndCheck's protected-header argument is
// always well-formed and fuzzing budget concentrates on the payload/body decode path.
func realProtectedHeader(f *testing.F, signer cose.Signer) []byte {
	f.Helper()
	obj, err := Sign(buildFuzzObject(0, 0, 0), signer)
	if err != nil {
		f.Fatalf("sign for protected header: %v", err)
	}
	prot, _, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		f.Fatalf("parse for protected header: %v", err)
	}
	return prot
}
