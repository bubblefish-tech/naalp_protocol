// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// The N-AALP non-regression guard (T2.1). Each test names one of the three ways the
// design's core guarantees could regress and FAILS if that regression is (re)introduced. Every test is
// mutation-surviving: reintroducing a session-token-accepts path, a classical-only
// governed selection, or a JSON canonicalizer on a signing path flips its test pass->fail.
package nonregression

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// kindOf extracts the stable error Kind from an N-AALP error, "" if err is nil or not one.
func kindOf(err error) string {
	if ce, ok := err.(*cose.Error); ok {
		return ce.Kind
	}
	return ""
}

// -------------------------------------------------------------------------------------
// (1) SESSION-TOKEN-CANNOT-AUTHORIZE
// -------------------------------------------------------------------------------------

// TestSessionTokenCannotAuthorize fails if any object authorization can be satisfied by a
// transport/session token (or any other self-asserted, non-signature identity) instead of
// the required signature-derived credential. It attempts authorization with each
// non-signature source — a TLS/session peer tag, a foreign X-Agent-ID header, a
// self-asserted clientInfo.name — while naming the EXACT grant principal and carrying an
// in-ceiling effect (the conditions under which a naive check would wave it through), and
// asserts every one is REJECTED with UnauthenticatedPrincipal. The signature source is the
// positive control.
//
// Mutation: change ResolveAuthPrincipal to accept a transport/session source (the erosion)
// and the non-signature loop below flips from reject to allow -> this test fails.
func TestSessionTokenCannotAuthorize(t *testing.T) {
	// A maximally-permissive grant to the principal "signer-A": nothing here limits by
	// effect, so the ONLY thing that can deny is the source-of-identity gate.
	g := policy.Grant{Principal: "signer-A", MaxEffect: policy.Destructive}

	// Positive control: the signature-derived principal, in-ceiling, IS authorized.
	if err := g.AuthorizeObject(policy.SourceSignature, "signer-A", uint64(policy.ReadOnly)); err != nil {
		t.Fatalf("positive control: signature-derived principal must authorize, got %v", err)
	}

	// The erosion surface: a session/transport token, a foreign header, a client-asserted
	// name. Each names the exact grant principal and an in-ceiling effect, yet MUST be
	// refused — a self-asserted transport identity is never an authorization principal.
	sessionLike := []struct {
		name string
		src  policy.PrincipalSource
	}{
		{"transport/session token", policy.SourceTransportMetadata},
		{"foreign X-Agent-ID header", policy.SourceForeignHeader},
		{"self-asserted clientInfo.name", policy.SourceClientName},
	}
	for _, tc := range sessionLike {
		err := g.AuthorizeObject(tc.src, "signer-A", uint64(policy.ReadOnly))
		if err == nil {
			t.Fatalf("MOAT EROSION: %s authorized an object (authority collapsed to a session token)", tc.name)
		}
		if got := kindOf(err); got != "UnauthenticatedPrincipal" {
			t.Fatalf("%s: want UnauthenticatedPrincipal, got %q (%v)", tc.name, got, err)
		}
		// The resolver itself must refuse the source, even before any grant matching.
		if _, rerr := policy.ResolveAuthPrincipal(tc.src, "signer-A"); kindOf(rerr) != "UnauthenticatedPrincipal" {
			t.Fatalf("%s: ResolveAuthPrincipal must refuse it, got %v", tc.name, rerr)
		}
	}

	// A signature source with an EMPTY id is still not a principal (no anonymous authority).
	if _, err := policy.ResolveAuthPrincipal(policy.SourceSignature, ""); kindOf(err) != "UnauthenticatedPrincipal" {
		t.Fatalf("empty signature id must not resolve to a principal, got %v", err)
	}
}

// -------------------------------------------------------------------------------------
// (2) NO-CLASSICAL-ONLY-ON-GOVERNED-TIER
// -------------------------------------------------------------------------------------

// dummyVerifier is a Verifier whose VerifyRaw always fails; it lets Verify1/VerifyHybrid be
// exercised for the profile-floor decision, which is checked BEFORE any signature.
type dummyVerifier struct{ alg int }

func (d dummyVerifier) Alg() int                   { return d.alg }
func (d dummyVerifier) VerifyRaw(_, _ []byte) bool { return false }
func (d dummyVerifier) PubKey() []byte             { return nil }

// TestNoClassicalOnlyOnGovernedTier fails if a downgrade/negotiation can select a
// classical-only signature suite on a governed N-AALP profile. Every N-AALP crypto profile
// is a governed tier with a post-quantum floor (level >= 3; Sovereign requires level 5);
// the classical Ed25519 suite (level 0) is below the floor everywhere. The test attempts
// the downgrade three ways and asserts the governed tier refuses classical-only each time.
//
// Mutation: raise algLevel(Ed25519) to a PQC level, or drop profileMinLevel below 3 (the
// erosion) — the structural and behavioral assertions below flip -> this test fails.
func TestNoClassicalOnlyOnGovernedTier(t *testing.T) {
	profiles := []struct {
		name string
		id   int
	}{
		{"Public", cose.ProfilePublic},
		{"Enterprise", cose.ProfileEnterprise},
		{"Sovereign", cose.ProfileSovereign},
	}
	payload := []byte{0xa1, 0x07, 0x00}

	// Structural: Ed25519 is a registered but classical (level 0) suite, and level 0 is
	// below the floor of EVERY governed profile.
	edLevel, known := cose.AlgLevel(cose.AlgEd25519)
	if !known {
		t.Fatal("Ed25519 must be a registered suite (as a hybrid leg)")
	}
	if edLevel != 0 {
		t.Fatalf("Ed25519 must be classical level 0, got %d", edLevel)
	}
	for _, p := range profiles {
		if min := cose.ProfileMinLevel(p.id); edLevel >= min {
			t.Fatalf("MOAT EROSION: classical Ed25519 (level %d) meets the %s floor (min %d)", edLevel, p.name, min)
		}
	}

	// A real post-quantum key for the positive control and as the verifier the downgrade
	// path is offered (the floor check precedes the key/signature checks).
	var seed [32]byte
	seed[0] = 0x11
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	mlV := cose.MLDSA65Verifier{PK: pk}

	// Positive control: a genuine ML-DSA-65 (post-quantum) object verifies at Public.
	pqObj, err := cose.Sign1(cose.MLDSA65Signer{SK: sk}, payload)
	if err != nil {
		t.Fatalf("sign ML-DSA-65: %v", err)
	}
	if err := cose.Verify1(cose.ProfilePublic, mlV, pqObj); err != nil {
		t.Fatalf("positive control: post-quantum signature must verify at Public, got %v", err)
	}

	// Behavioral downgrade #1: a COSE_Sign1 carrying a classical-only Ed25519 header is
	// refused with ProfileDowngrade at EVERY governed profile.
	edProt, err := cbor.Encode(cbor.Map{{K: cbor.Uint(1), V: cbor.Nint(int64(cose.AlgEd25519))}})
	if err != nil {
		t.Fatalf("encode ed25519 protected header: %v", err)
	}
	edObj, err := cose.AssembleSign1Raw(edProt, payload, make([]byte, 64))
	if err != nil {
		t.Fatalf("assemble ed-only COSE_Sign1: %v", err)
	}
	for _, p := range profiles {
		if got := kindOf(cose.Verify1(p.id, mlV, edObj)); got != "ProfileDowngrade" {
			t.Fatalf("MOAT EROSION: %s accepted a classical-only COSE_Sign1 (want ProfileDowngrade, got %q)", p.name, got)
		}
	}

	// Behavioral downgrade #2: a hybrid stripped to only its classical Ed25519 leg is
	// refused (the PQC leg is missing) — HybridIncomplete, never a classical-only accept.
	edOnlyHybrid, err := cbor.Encode(cbor.Tag{Number: cose.TagSign, Content: cbor.Arr{
		cbor.Bstr(nil), cbor.Map{}, cbor.Bstr(payload),
		cbor.Arr{cbor.Arr{cbor.Bstr(edProt), cbor.Map{}, cbor.Bstr(make([]byte, 64))}},
	}})
	if err != nil {
		t.Fatalf("encode ed-only hybrid: %v", err)
	}
	if got := kindOf(cose.VerifyHybrid(cose.ProfilePublic, dummyVerifier{cose.AlgEd25519}, mlV, edOnlyHybrid)); got != "HybridIncomplete" {
		t.Fatalf("MOAT EROSION: a classical-only hybrid was not refused (want HybridIncomplete, got %q)", got)
	}

	// Behavioral downgrade #3: a hybrid whose PQC leg is below the governed top tier's
	// floor (ML-DSA-65 leg at Sovereign, which requires level 5) is refused ProfileDowngrade.
	mlProt, err := cbor.Encode(cbor.Map{{K: cbor.Uint(1), V: cbor.Nint(int64(cose.AlgMLDSA65))}})
	if err != nil {
		t.Fatalf("encode ml-dsa-65 protected header: %v", err)
	}
	subFloorHybrid, err := cbor.Encode(cbor.Tag{Number: cose.TagSign, Content: cbor.Arr{
		cbor.Bstr(nil), cbor.Map{}, cbor.Bstr(payload),
		cbor.Arr{cbor.Arr{cbor.Bstr(mlProt), cbor.Map{}, cbor.Bstr(make([]byte, 64))}},
	}})
	if err != nil {
		t.Fatalf("encode sub-floor hybrid: %v", err)
	}
	if got := kindOf(cose.VerifyHybrid(cose.ProfileSovereign, dummyVerifier{cose.AlgEd25519}, mlV, subFloorHybrid)); got != "ProfileDowngrade" {
		t.Fatalf("MOAT EROSION: Sovereign accepted a sub-floor PQC hybrid leg (want ProfileDowngrade, got %q)", got)
	}
}

// -------------------------------------------------------------------------------------
// (3) NO-JSON-CANONICALIZER-ON-SIGNING-PATH
// -------------------------------------------------------------------------------------

// jsonCanonicalizerTokens are the source markers of a JSON / JSON-LD canonicalizer or
// serializer. None may appear in any signing-path source file. "encoding/json" catches an
// import regardless of alias; the JCS/JSON-LD/RDF markers catch a canonicalizer library.
// The bare word "json" is intentionally NOT forbidden — carriage legitimately names a
// JSONRPC carriage class, which is a foreign-protocol label, not a signing canonicalizer.
var jsonCanonicalizerTokens = []string{
	"encoding/json",
	"json.Marshal",
	"json.Unmarshal",
	"json.NewEncoder",
	"json.NewDecoder",
	"jcs",
	"canonicaljson",
	"JSON-LD",
	"jsonld",
	"URDNA2015",
	"RFC 8785",
	"RFC8785",
}

// implGoRoot walks up from this test file to the impl/go module root (the dir with go.mod).
func implGoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate the impl/go module root (go.mod)")
		}
		dir = parent
	}
}

// signingPathGoFiles is every non-test production .go file in the impl/go object library —
// the entire signing/verification surface — minus the cmd/ CLIs, which do stdout I/O and
// legitimately use encoding/json (they are not on a signing path).
func signingPathGoFiles(t *testing.T) []string {
	root := implGoRoot(t)
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "cmd":
				return filepath.SkipDir // CLI I/O, not a signing path
			case "ecosystem":
				// adoption/interop layer (DID/JWK per RFC 9964, MCP, A2A) legitimately handles FOREIGN
				// JSON formats; it is not the N-AALP object library, and any ecosystem package that signs
				// an N-AALP object does so THROUGH the core cose/envelope packages (which ARE scanned).
				return filepath.SkipDir
			case "nonregression", "conformance":
				return filepath.SkipDir // meta guard/gate packages, not signing paths (they name the markers)
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk impl/go: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("found no signing-path source files to scan")
	}
	return files
}

// TestNoJSONCanonicalizerOnSigningPath fails if any signing path invokes a JSON
// canonicalizer. It proves the invariant two ways:
//
//	(a) structurally on the bytes: the COSE_Sign1 ToBeSigned input is deterministic CBOR —
//	    a CBOR array whose first element is the tstr "Signature1" (RFC 9052 §4.4) — and it
//	    re-encodes byte-identically (canonical). A JSON document could not satisfy this.
//	(b) structurally on the source: no signing-path source file contains a JSON/JSON-LD
//	    canonicalizer marker. Reintroducing `encoding/json` + json.Marshal (or a JCS /
//	    URDNA2015 canonicalizer) on any signing-path file trips this scan.
//
// Mutation: add a JSON canonicalizer call on a signing path (e.g. import encoding/json and
// json.Marshal the body in envelope.go before signing) and the source scan below fails.
func TestNoJSONCanonicalizerOnSigningPath(t *testing.T) {
	// (a) the signing input is canonical CBOR, first element the tstr "Signature1".
	payload := []byte{0xa1, 0x07, 0x00}
	tbs, err := cose.ToBeSigned(cose.AlgMLDSA65, payload)
	if err != nil {
		t.Fatalf("ToBeSigned: %v", err)
	}
	v, err := cbor.Decode(tbs)
	if err != nil {
		t.Fatalf("the signed input is not valid CBOR (JSON on the signing path?): %v", err)
	}
	arr, ok := v.(cbor.Arr)
	if !ok || len(arr) < 1 {
		t.Fatalf("the COSE Sig_structure must be a CBOR array, got %T", v)
	}
	if s, ok := arr[0].(cbor.Tstr); !ok || string(s) != "Signature1" {
		t.Fatalf("first Sig_structure element must be the tstr \"Signature1\", got %v", arr[0])
	}
	reencoded, err := cbor.Encode(v)
	if err != nil {
		t.Fatalf("re-encode signing input: %v", err)
	}
	if !bytes.Equal(reencoded, tbs) {
		t.Fatal("the signing input is not canonical CBOR (re-encode differs)")
	}

	// (b) no signing-path source file carries a JSON/JSON-LD canonicalizer marker.
	for _, f := range signingPathGoFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		for _, tok := range jsonCanonicalizerTokens {
			if strings.Contains(src, tok) {
				rel, _ := filepath.Rel(implGoRoot(t), f)
				t.Fatalf("MOAT EROSION: signing-path file %s references JSON-canonicalizer marker %q", rel, tok)
			}
		}
	}
}
