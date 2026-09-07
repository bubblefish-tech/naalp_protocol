// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package envelope

import (
	"fmt"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// #277 residual A: suite-declaration downgrade/strip resistance (design.md §4.2, field 14).
//
// PROPERTY UNDER TEST: can an attacker holding genuine keys strip a composite signature down
// to pure, flip the signed suite id (field 14), or otherwise present a self-consistent but
// semantically-wrong (alg, Suite) pairing without invalidating the signature? The exhaustive
// matrix below drives EVERY (alg, Suite, signature-validity) combination through Verify and
// asserts accept iff alg-is-composite <=> Suite==SuiteMLDSA65Ed25519 <=> the signature is
// genuinely valid over the exact, unmodified signed representative -- i.e. field 14 cannot be
// forged, stripped, or mismatched against alg while still verifying, REGARDLESS of the
// signature otherwise being a real, correctly-computed signature over that exact payload (this
// is the strip/downgrade attack: an attacker with real keys signs a self-consistent but
// mismatched payload, not a forger without keys).
//
// F3 NON-CIRCULAR AUTHORITY (never derived from envelope.go's own Verify implementation):
//   - RFC 9052 §4.4 (Sig_structure): the COSE protected header and payload are both fed into
//     the signed representative; field 14 (Suite) lives in the payload, so ANY value it takes
//     is inside what the signature covers, by construction of the wire format itself.
//   - design.md §4.2's own CDDL presence rule: field 14 is PRESENT iff the object is composite,
//     ABSENT for a pure object -- an independent, spec-level correlation rule this test checks
//     Verify's actual decision against, not a restatement of Verify's switch statement.
//   - draft-ietf-lamps-pq-composite-sigs rev-19's non-separability property (already
//     re-witnessed 2026-08-16 against the LAMPS-WG reference generator, design.md §4.2's own
//     verify-relay note): a composite signature is one atomic value over one message
//     representative, not two independently-strippable legs.
//
// This test uses signWhitebox (envelope_test.go), which signs the object's CALLER-SET Suite
// field directly, bypassing Sign()'s auto-derive -- exactly what is needed to construct the
// self-consistent-but-wrong combinations an attacker with real keys could produce.
//
// HONEST ADAPTATION from the #277 grounding survey's framing ("alg ∈ {pure ML-DSA-44/65/87,
// composite}"): this codebase implements exactly two pure algs (AlgMLDSA65, AlgMLDSA87; no
// AlgMLDSA44 exists -- grepped this session) plus one composite alg (AlgComposite65Ed25519), so
// the matrix below is 3 algs x 4 Suite values x 2 (valid/tampered) = 24 cases, not the
// originally-estimated ~40 -- smaller because the alg space is smaller, not because any cell of
// the real space was dropped.
func TestSuiteDowngradeStripExhaustive(t *testing.T) {
	c := load(t)
	pureSigner, pureVerifier := testSigner(t) // AlgMLDSA65
	compSigner, compVerifier := compositeTestKeys(t)

	var mSeed [mldsa87.SeedSize]byte
	for i := range mSeed {
		mSeed[i] = byte(200 + i)
	}
	pure87Pub, pure87Priv := mldsa87.NewKeyFromSeed(&mSeed)
	pure87Signer := cose.MLDSA87Signer{SK: pure87Priv}
	pure87Verifier := cose.MLDSA87Verifier{PK: pure87Pub}

	type algCase struct {
		name     string
		signer   cose.Signer
		verifier cose.Verifier
	}
	algs := []algCase{
		{"pure-MLDSA65", pureSigner, pureVerifier},
		{"pure-MLDSA87", pure87Signer, pure87Verifier},
		{"composite-MLDSA65-Ed25519", compSigner, compVerifier},
	}
	suites := []uint64{0, SuiteMLDSA65Ed25519, 2, 99}

	// The independent oracle: never derived from Verify's implementation, only from the F3
	// authorities named above.
	expectAccept := func(alg int, suite uint64, tampered bool) bool {
		if tampered {
			return false
		}
		switch alg {
		case cose.AlgComposite65Ed25519:
			return suite == SuiteMLDSA65Ed25519
		case cose.AlgMLDSA65, cose.AlgMLDSA87:
			return suite == 0
		default:
			return false
		}
	}

	for _, a := range algs {
		a := a
		for _, suite := range suites {
			suite := suite
			for _, tampered := range []bool{false, true} {
				tampered := tampered
				t.Run(caseLabel(a.name, suite, tampered), func(t *testing.T) {
					o := buildObject(t, c)
					o.Suite = suite
					obj := signWhitebox(t, o, a.signer)
					if tampered {
						obj = append([]byte(nil), obj...)
						obj[len(obj)-1] ^= 0xFF // flip the last signature byte
					}
					_, err := Verify(cose.ProfilePublic, a.verifier, acceptKind, nil, obj)
					accepted := err == nil
					want := expectAccept(a.signer.Alg(), suite, tampered)
					if accepted != want {
						t.Fatalf("alg=%s suite=%d tampered=%v: want accept=%v, got accept=%v (err=%v)",
							a.name, suite, tampered, want, accepted, err)
					}
					// Where a specific error is unambiguously determinable from the F3 rule alone
					// (a Suite value that disagrees with alg, untampered), pin the exact named
					// error too -- not merely "any rejection" -- so the test also proves the
					// CORRECT diagnosis, not just a correct accept/reject bit.
					if !want && !tampered {
						ce, ok := err.(*cose.Error)
						if !ok || ce.Kind != "SuiteMismatch" {
							t.Fatalf("alg=%s suite=%d: want SuiteMismatch specifically, got %v", a.name, suite, err)
						}
					}
				})
			}
		}
	}
}

func caseLabel(alg string, suite uint64, tampered bool) string {
	label := alg + "/suite=" + suiteLabel(suite)
	if tampered {
		label += "/tampered"
	} else {
		label += "/valid-sig"
	}
	return label
}

func suiteLabel(suite uint64) string {
	switch suite {
	case 0:
		return "absent(0)"
	case SuiteMLDSA65Ed25519:
		return "MLDSA65Ed25519(1)"
	default:
		return fmt.Sprintf("garbage(%d)", suite)
	}
}
