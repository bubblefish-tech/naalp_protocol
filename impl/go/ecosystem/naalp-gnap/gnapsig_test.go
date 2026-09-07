// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ---- key material (deterministic, matches the impl/go/delegation_test.go pattern) --------

func sigTestKey(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

// ---- RequiredComponents --------------------------------------------------------------------

func TestRequiredComponents_Combinations(t *testing.T) {
	cases := []struct {
		hasBody, hasAuth bool
		want             []string
	}{
		{false, false, []string{"@method", "@target-uri"}},
		{true, false, []string{"@method", "@target-uri", "content-digest"}},
		{false, true, []string{"@method", "@target-uri", "authorization"}},
		{true, true, []string{"@method", "@target-uri", "content-digest", "authorization"}},
	}
	for _, c := range cases {
		got := RequiredComponents(c.hasBody, c.hasAuth)
		if len(got) != len(c.want) {
			t.Fatalf("hasBody=%v hasAuth=%v: got %v, want %v", c.hasBody, c.hasAuth, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("hasBody=%v hasAuth=%v: got %v, want %v", c.hasBody, c.hasAuth, got, c.want)
			}
		}
	}
}

// ---- BuildSignatureBase, against a HAND-CONSTRUCTED oracle (RFC 9421 §2.3/§2.5 format) -----

// TestBuildSignatureBase_MatchesHandConstructedOracle: the expected string is typed by hand
// from the RFC 9421 §2.3/§2.5 format description (one `"<component>": <value>` line per
// covered component, terminated by the `"@signature-params": (<ordered list>)<params>`
// line) — an independent constructor, never derived by calling BuildSignatureBase itself
// (F3/A7 non-circularity). Mutation: a constant/field-ignoring base builder diverges from
// this exact byte string.
func TestBuildSignatureBase_MatchesHandConstructedOracle(t *testing.T) {
	components := []string{"@method", "@target-uri"}
	values := map[string]string{
		"@method":     "POST",
		"@target-uri": "https://as.example.net/gnap",
	}
	params := SignatureParams{Created: 1735689600, KeyID: "test-key"}

	want := "\"@method\": POST\n" +
		"\"@target-uri\": https://as.example.net/gnap\n" +
		"\"@signature-params\": (\"@method\" \"@target-uri\");created=1735689600;keyid=\"test-key\""

	got, err := BuildSignatureBase(components, values, params)
	if err != nil {
		t.Fatalf("BuildSignatureBase: %v", err)
	}
	if string(got) != want {
		t.Fatalf("signature base =\n%q\nwant\n%q", string(got), want)
	}
}

// TestBuildSignatureBase_RejectsMissingComponentValue: a component named without a value
// entry is refused (fail-closed) rather than silently treated as empty.
func TestBuildSignatureBase_RejectsMissingComponentValue(t *testing.T) {
	_, err := BuildSignatureBase([]string{"@method", "content-digest"}, map[string]string{"@method": "GET"}, SignatureParams{})
	if err != ErrUnknownComponent {
		t.Fatalf("err = %v, want ErrUnknownComponent", err)
	}
}

// ---- Sign / Verify, real ML-DSA-65 keys ----------------------------------------------------

func testComponentsValues(target string) ([]string, map[string]string) {
	components := []string{"@method", "@target-uri", "content-digest"}
	values := map[string]string{
		"@method":        "POST",
		"@target-uri":    target,
		"content-digest": ContentDigest([]byte(`{"access_token":{"access":[{"type":"naalp-effect"}]}}`)),
	}
	return components, values
}

func TestSignThenVerify_RoundTrip(t *testing.T) {
	signer, verifier := sigTestKey(t, 0x01)
	components, values := testComponentsValues("https://as.example.net/gnap")
	params := SignatureParams{Created: 1735689600, KeyID: "agent-b", Alg: "ml-dsa-65"}

	_, sig, err := Sign(signer, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(verifier, components, values, params, sig); err != nil {
		t.Fatalf("Verify(genuine): %v", err)
	}
}

// TestVerify_RejectsTamperedSignature is the primary mutation-witnessed test for this
// package (RED-EVIDENCE.md M1): a bit-flipped signature byte MUST be rejected. Mutating
// Verify to skip the VerifyRaw check (accept unconditionally) flips this test RED.
func TestVerify_RejectsTamperedSignature(t *testing.T) {
	signer, verifier := sigTestKey(t, 0x02)
	components, values := testComponentsValues("https://as.example.net/gnap")
	params := SignatureParams{Created: 1735689600}

	_, sig, err := Sign(signer, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF // flip one byte of the signature value

	if err := Verify(verifier, components, values, params, tampered); err != ErrKeyProofMismatch {
		t.Fatalf("Verify(tampered signature) = %v, want ErrKeyProofMismatch", err)
	}
}

// TestVerify_RejectsTamperedCoveredValue: changing a covered component's VALUE after
// signing (e.g. an on-path attacker swapping @target-uri) must also be rejected — the
// signature base is recomputed from the presented values, not cached from signing time.
func TestVerify_RejectsTamperedCoveredValue(t *testing.T) {
	signer, verifier := sigTestKey(t, 0x03)
	components, values := testComponentsValues("https://as.example.net/gnap")
	params := SignatureParams{Created: 1735689600}

	_, sig, err := Sign(signer, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tamperedValues := map[string]string{
		"@method":        values["@method"],
		"@target-uri":    "https://attacker.example.net/gnap", // swapped target
		"content-digest": values["content-digest"],
	}
	if err := Verify(verifier, components, tamperedValues, params, sig); err != ErrKeyProofMismatch {
		t.Fatalf("Verify(tampered @target-uri) = %v, want ErrKeyProofMismatch", err)
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	signer, _ := sigTestKey(t, 0x04)
	_, otherVerifier := sigTestKey(t, 0x05) // a DIFFERENT key pair
	components, values := testComponentsValues("https://as.example.net/gnap")
	params := SignatureParams{}

	_, sig, err := Sign(signer, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(otherVerifier, components, values, params, sig); err != ErrKeyProofMismatch {
		t.Fatalf("Verify(wrong key) = %v, want ErrKeyProofMismatch", err)
	}
}

// ---- AlgTag ----------------------------------------------------------------------------------

func TestAlgTag_KnownAndUnknown(t *testing.T) {
	cases := []struct {
		alg  int
		want string
	}{
		{cose.AlgMLDSA65, "ml-dsa-65"},
		{cose.AlgMLDSA87, "ml-dsa-87"},
		{cose.AlgEd25519, "ed25519"},
	}
	for _, c := range cases {
		got, err := AlgTag(c.alg)
		if err != nil {
			t.Fatalf("AlgTag(%d): %v", c.alg, err)
		}
		if got != c.want {
			t.Errorf("AlgTag(%d) = %q, want %q", c.alg, got, c.want)
		}
	}
	if _, err := AlgTag(-999); err != ErrUnknownAlg {
		t.Fatalf("AlgTag(unknown) = %v, want ErrUnknownAlg", err)
	}
}

// ---- ContentDigest, against an independently (non-Go) computed SHA-512 digest -------------

// TestContentDigest_MatchesIndependentSHA512 checks ContentDigest("abc") against the
// base64 SHA-512 digest of "abc" computed via .NET's System.Security.Cryptography.SHA512
// (PowerShell, this session) — a DIFFERENT implementation stack from Go's crypto/sha512,
// so the digest bytes are not sourced from the code under test (F3/A7 non-circularity).
// This checks ContentDigest's OWN contribution — the "sha-512=:...:" RFC 9530 formatting —
// against a hash value this package's own code never computed.
func TestContentDigest_MatchesIndependentSHA512(t *testing.T) {
	const wantB64 = "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
	want := "sha-512=:" + wantB64 + ":"

	got := ContentDigest([]byte("abc"))
	if got != want {
		t.Fatalf("ContentDigest(\"abc\") = %q, want %q", got, want)
	}
}

// ---- header builders, against hand-constructed oracles -------------------------------------

func TestBuildSignatureInputHeader_MatchesHandConstructedOracle(t *testing.T) {
	got := BuildSignatureInputHeader("sig1", []string{"@method", "@target-uri"}, SignatureParams{Created: 1735689600, KeyID: "test-key"})
	want := `sig1=("@method" "@target-uri");created=1735689600;keyid="test-key"`
	if got != want {
		t.Fatalf("Signature-Input = %q, want %q", got, want)
	}
}

func TestBuildSignatureHeader_MatchesHandConstructedOracle(t *testing.T) {
	got := BuildSignatureHeader("sig1", []byte{0x01, 0x02, 0x03})
	want := "sig1=:AQID:" // base64.StdEncoding("\x01\x02\x03"), computed independently by hand
	if got != want {
		t.Fatalf("Signature header = %q, want %q", got, want)
	}
}
