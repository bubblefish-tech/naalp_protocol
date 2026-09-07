// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package delegation_test

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/delegation"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/delegation/cases.json"

// ---- corpus shapes -----------------------------------------------------------------------

type grantVec struct {
	Name         string `json:"name"`
	Subject      string `json:"subject"`
	EffectCap    uint64 `json:"effect_cap"`
	MaxDepth     uint64 `json:"max_depth"`
	NotBefore    uint64 `json:"not_before"`
	NotAfter     uint64 `json:"not_after"`
	Scope        string `json:"scope"`
	BodyHex      string `json:"body_hex"`
	ContentIDHex string `json:"content_id_hex"`
}

type scopeRow struct {
	Child     string `json:"child"`
	Parent    string `json:"parent"`
	Contained bool   `json:"contained"`
}

type scGrant struct {
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	EffectCap uint64 `json:"effect_cap"`
	MaxDepth  uint64 `json:"max_depth"`
	NotBefore uint64 `json:"not_before"`
	NotAfter  uint64 `json:"not_after"`
	Scope     string `json:"scope"`
	Causes    []int  `json:"causes"`
}

type scAction struct {
	Signer string `json:"signer"`
	Effect uint64 `json:"effect"`
	Scope  string `json:"scope"`
	Causes []int  `json:"causes"`
}

type scRevoked struct {
	Grant int    `json:"grant"`
	Pos   uint64 `json:"pos"`
}

type scenario struct {
	Name    string      `json:"name"`
	Grants  []scGrant   `json:"grants"`
	Action  scAction    `json:"action"`
	Anchors []string    `json:"anchors"`
	Revoked []scRevoked `json:"revoked"`
	Now     uint64      `json:"now"`
	Expect  string      `json:"expect"`
}

type cases struct {
	Grants           []grantVec `json:"grants"`
	ScopeContainment []scopeRow `json:"scope_containment"`
	Scenarios        []scenario `json:"scenarios"`
}

func load(t *testing.T) cases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c cases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// ---- key material ------------------------------------------------------------------------

type ak struct {
	signer   cose.MLDSA65Signer
	verifier cose.MLDSA65Verifier
	pub      []byte
	id       string
}

func mkKey(t *testing.T, seed byte) ak {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	id, err := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())
	if err != nil {
		t.Fatalf("signer id: %v", err)
	}
	return ak{cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pk.Bytes(), id}
}

// contentIDOf is the T1 content-id framing over arbitrary bytes: multihash(0x20, SHA-384(b)),
// used to mint a stand-in "action args" content id an approval binds.
func contentIDOf(b []byte) []byte {
	d := sha512.Sum384(b)
	out := []byte{0x20, 0x30}
	return append(out, d[:]...)
}

// ---- the byte + scope grading (Go == oracle == Rust) -------------------------------------

// TestGrantBytesMatchOracle: every DelegationGrant body and its content id are byte-identical to
// the independent oracle (⟹ Go == Rust on the wire). Mutation: a constant/field-ignoring encoder
// diverges from the pinned hex, and an omitted-vs-present scope field flips the content id.
func TestGrantBytesMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.Grants) == 0 {
		t.Fatal("no grant byte vectors")
	}
	for _, gj := range c.Grants {
		g := delegation.Grant{
			Subject: gj.Subject, EffectCap: policy.Effect(gj.EffectCap), MaxDepth: gj.MaxDepth,
			NotBefore: gj.NotBefore, NotAfter: gj.NotAfter, Scope: gj.Scope,
		}
		if got := hex.EncodeToString(g.Bytes()); got != gj.BodyHex {
			t.Errorf("grant %s body\n got %s\nwant %s", gj.Name, got, gj.BodyHex)
		}
		if got := hex.EncodeToString(g.ContentID()); got != gj.ContentIDHex {
			t.Errorf("grant %s content-id\n got %s\nwant %s", gj.Name, got, gj.ContentIDHex)
		}
	}
}

// TestScopeContainmentMatchesOracle grades the D2 path-prefix containment rule directly against
// the independent truth table (both allows and denies, so a constant predicate fails).
func TestScopeContainmentMatchesOracle(t *testing.T) {
	c := load(t)
	if len(c.ScopeContainment) == 0 {
		t.Fatal("no scope-containment rows")
	}
	for _, r := range c.ScopeContainment {
		if got := delegation.ScopeContained(r.Child, r.Parent); got != r.Contained {
			t.Errorf("ScopeContained(%q, %q) = %v, want %v", r.Child, r.Parent, got, r.Contained)
		}
	}
}

// ---- the chain-verdict grading (Go == oracle == Rust over REAL signed chains) ------------

// TestChainScenariosMatchOracle drives every oracle scenario as a REAL ML-DSA-65 signed grant
// chain (each grant a signed COSE_Sign1 whose issuer is its verified signer, real envelope content
// ids wired into `causes`) and asserts the verifier's verdict equals the oracle's independently
// computed verdict. The scenario set contains both authorized outcomes and every named deny, so a
// constant-nil verifier fails the denies and a constant-error verifier fails the allows
// (mutation-surviving). Three independent D3 implementations agree: oracle == Go == Rust.
func TestChainScenariosMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.Scenarios) == 0 {
		t.Fatal("no scenarios")
	}
	for _, sc := range c.Scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			keys := assignKeys(t, sc)
			set := delegation.GrantSet{}
			grantCID := make([][]byte, len(sc.Grants))
			for i, gj := range sc.Grants {
				ik := keys[gj.Issuer]
				sk := keys[gj.Subject]
				g := delegation.Grant{
					Subject: sk.id, EffectCap: policy.Effect(gj.EffectCap), MaxDepth: gj.MaxDepth,
					NotBefore: gj.NotBefore, NotAfter: gj.NotAfter, Scope: gj.Scope,
				}
				var causes [][]byte
				for _, ci := range gj.Causes {
					causes = append(causes, grantCID[ci])
				}
				obj, err := g.EnvelopeObject([]byte(ik.id), 1, uint64(cose.ProfilePublic), causes)
				if err != nil {
					t.Fatalf("grant %d build: %v", i, err)
				}
				signed, err := envelope.Sign(obj, ik.signer)
				if err != nil {
					t.Fatalf("grant %d sign: %v", i, err)
				}
				res, err := delegation.VerifyGrantObject(cose.ProfilePublic, ik.verifier, ik.pub, signed)
				if err != nil {
					t.Fatalf("grant %d verify (D3 step 3): %v", i, err)
				}
				grantCID[i] = res.ContentID
				set[string(res.ContentID)] = res
			}

			action := buildAction(t, keys[sc.Action.Signer], sc.Action.Effect, sc.Action.Scope, grantCauses(grantCID, sc.Action.Causes))

			anchors := map[string]bool{}
			for _, a := range sc.Anchors {
				anchors[keys[a].id] = true
			}
			revoked := delegation.Revocations{}
			for _, r := range sc.Revoked {
				revoked[string(grantCID[r.Grant])] = r.Pos
			}

			err := delegation.VerifyChain(action, set, anchors, revoked, sc.Now)
			assertVerdict(t, sc.Name, err, sc.Expect)
		})
	}
}

func grantCauses(grantCID [][]byte, idx []int) [][]byte {
	var out [][]byte
	for _, i := range idx {
		out = append(out, grantCID[i])
	}
	return out
}

// buildAction builds, SIGNS, and VERIFIES a real action object by B (grading R-DEL-2 / D3 step 1
// with real crypto), then constructs the Action from the verified object. The action is a plain
// baseline object (Memory MemoryWrite) carrying B as its signer, the scenario effect, and the
// scenario causes; envelope.Verify proves B actually signed it before its authority is checked.
func buildAction(t *testing.T, signer ak, effect uint64, scope string, causes [][]byte) delegation.Action {
	t.Helper()
	obj := &envelope.Object{
		Kind: 2, Channel: 0x0001, Tier: 0, Signer: []byte(signer.id), Created: 1,
		Effect: effect, Causes: causes, Profile: uint64(cose.ProfilePublic), Body: cbor.Tstr("action"),
	}
	signed, err := envelope.Sign(obj, signer.signer)
	if err != nil {
		t.Fatalf("action sign: %v", err)
	}
	o, err := envelope.Verify(cose.ProfilePublic, signer.verifier, delegation.ComposedKindValidator, nil, signed)
	if err != nil {
		t.Fatalf("action verify (R-DEL-2, D3 step 1): %v", err)
	}
	if string(o.Signer) != signer.id {
		t.Fatalf("action signer %q != authenticated id %q", o.Signer, signer.id)
	}
	return delegation.Action{Signer: string(o.Signer), Effect: policy.Effect(o.Effect), Scope: scope, Causes: o.Causes}
}

func assignKeys(t *testing.T, sc scenario) map[string]ak {
	t.Helper()
	m := map[string]ak{}
	seed := byte(100)
	assign := func(label string) {
		if _, ok := m[label]; ok {
			return
		}
		m[label] = mkKey(t, seed)
		seed++
	}
	for _, g := range sc.Grants {
		assign(g.Issuer)
		assign(g.Subject)
	}
	assign(sc.Action.Signer)
	for _, a := range sc.Anchors {
		assign(a)
	}
	return m
}

func assertVerdict(t *testing.T, name string, err error, expect string) {
	t.Helper()
	if expect == "authorized" {
		if err != nil {
			t.Errorf("%s: want authorized, got %v", name, err)
		}
		return
	}
	ce, ok := err.(*cose.Error)
	if !ok {
		t.Errorf("%s: want error %s, got %v", name, expect, err)
		return
	}
	if ce.Kind != expect {
		t.Errorf("%s: want error %s, got %s", name, expect, ce.Kind)
	}
}

// ---- dedicated behavioural deny paths (real crypto) --------------------------------------

// chain2 builds a valid A -> M -> B two-hop chain (all in-window, effects/depths attenuating) and
// returns the verified grant set, the signed leaf-grant bytes, the leaf issuer's key, the action,
// and the trust anchors, so tamper/forge tests can perturb one element.
type builtChain struct {
	set        delegation.GrantSet
	anchors    map[string]bool
	action     delegation.Action
	leafSigned []byte
	leafKey    ak // M (the leaf grant's issuer)
	b          ak // the actor
}

func buildValid2Hop(t *testing.T, effect policy.Effect) builtChain {
	t.Helper()
	a := mkKey(t, 10) // trust anchor / root issuer
	m := mkKey(t, 11) // middle
	b := mkKey(t, 12) // actor
	// root grant A -> M
	rootG := delegation.Grant{Subject: m.id, EffectCap: policy.Destructive, MaxDepth: 2, NotBefore: 0, NotAfter: 1_000_000}
	rootObj, err := rootG.EnvelopeObject([]byte(a.id), 1, uint64(cose.ProfilePublic), nil)
	if err != nil {
		t.Fatal(err)
	}
	rootSigned, err := envelope.Sign(rootObj, a.signer)
	if err != nil {
		t.Fatal(err)
	}
	rootRes, err := delegation.VerifyGrantObject(cose.ProfilePublic, a.verifier, a.pub, rootSigned)
	if err != nil {
		t.Fatalf("root grant verify: %v", err)
	}
	// leaf grant M -> B naming the root as its parent
	leafG := delegation.Grant{Subject: b.id, EffectCap: policy.Destructive, MaxDepth: 1, NotBefore: 0, NotAfter: 1_000_000}
	leafObj, err := leafG.EnvelopeObject([]byte(m.id), 1, uint64(cose.ProfilePublic), [][]byte{rootRes.ContentID})
	if err != nil {
		t.Fatal(err)
	}
	leafSigned, err := envelope.Sign(leafObj, m.signer)
	if err != nil {
		t.Fatal(err)
	}
	leafRes, err := delegation.VerifyGrantObject(cose.ProfilePublic, m.verifier, m.pub, leafSigned)
	if err != nil {
		t.Fatalf("leaf grant verify: %v", err)
	}
	set := delegation.NewGrantSet(rootRes, leafRes)
	action := buildAction(t, b, uint64(effect), "", [][]byte{leafRes.ContentID})
	return builtChain{set: set, anchors: map[string]bool{a.id: true}, action: action, leafSigned: leafSigned, leafKey: m, b: b}
}

// TestValid2HopAuthorized is the happy path with real crypto (independent of the vector loop):
// a full A->M->B chain authorizes a non_idempotent_write action.
func TestValid2HopAuthorized(t *testing.T) {
	bc := buildValid2Hop(t, policy.NonIdempotentWrite)
	if err := delegation.VerifyChain(bc.action, bc.set, bc.anchors, nil, 500); err != nil {
		t.Fatalf("valid chain denied: %v", err)
	}
}

// TestTamperedGrantSignatureRejected: flipping a byte of a grant's signature makes it an
// unverifiable link (D3 step 3) — VerifyGrantObject rejects it BadSignature. Mutation: if the
// signature were not checked, the tampered grant would resolve and the chain would pass.
func TestTamperedGrantSignatureRejected(t *testing.T) {
	bc := buildValid2Hop(t, policy.NonIdempotentWrite)
	tampered := append([]byte(nil), bc.leafSigned...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := delegation.VerifyGrantObject(cose.ProfilePublic, bc.leafKey.verifier, bc.leafKey.pub, tampered); err == nil {
		t.Fatal("tampered grant signature accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "BadSignature" {
		t.Fatalf("want BadSignature, got %v", err)
	}
}

// TestForgedIssuerRejected: a grant whose envelope signer field claims an issuer id NOT derived
// from the signing key is rejected SignerMismatch (R-DEL-3: the issuer is the verified signer, not
// a claimed field). Mutation: if the issuer were taken from the body/header without binding it to
// the key, the forgery would pass.
func TestForgedIssuerRejected(t *testing.T) {
	realKey := mkKey(t, 20)
	victim := mkKey(t, 21) // the id the forger tries to impersonate
	subject := mkKey(t, 22)
	g := delegation.Grant{Subject: subject.id, EffectCap: policy.NonIdempotentWrite, MaxDepth: 1, NotBefore: 0, NotAfter: 1_000_000}
	// Claim the VICTIM as issuer but sign with realKey. The header/body signer copies agree
	// (both victim.id), so envelope.Verify passes; the issuer-to-key binding must still reject.
	obj, err := g.EnvelopeObject([]byte(victim.id), 1, uint64(cose.ProfilePublic), nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := envelope.Sign(obj, realKey.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := delegation.VerifyGrantObject(cose.ProfilePublic, realKey.verifier, realKey.pub, signed); err == nil {
		t.Fatal("forged issuer accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "SignerMismatch" {
		t.Fatalf("want SignerMismatch, got %v", err)
	}
}

// TestBaselineVerifierRejectsGrantKind: a frozen baseline verifier (no tier licensed) rejects the
// tier-1 DelegationGrant kind as UnknownKind (fail-closed), exactly as the tier model requires.
func TestBaselineVerifierRejectsGrantKind(t *testing.T) {
	issuer := mkKey(t, 30)
	subject := mkKey(t, 31)
	g := delegation.Grant{Subject: subject.id, EffectCap: policy.NonIdempotentWrite, MaxDepth: 1, NotBefore: 0, NotAfter: 1_000_000}
	obj, err := g.EnvelopeObject([]byte(issuer.id), 1, uint64(cose.ProfilePublic), nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := envelope.Sign(obj, issuer.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Verify(cose.ProfilePublic, issuer.verifier, channels.KindValidator, nil, signed); err == nil {
		t.Fatal("baseline verifier accepted a tier-1 DelegationGrant")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownKind" {
		t.Fatalf("want UnknownKind, got %v", err)
	}
}

// TestNonNFCSubjectRejected: a non-NFC subject/scope is rejected at build (fail-closed).
func TestNonNFCSubjectRejected(t *testing.T) {
	issuer := mkKey(t, 40)
	nonNFC := "é" // "é" as e + combining acute (NFD, not NFC)
	g := delegation.Grant{Subject: nonNFC, EffectCap: policy.ReadOnly, MaxDepth: 0, NotBefore: 0, NotAfter: 1}
	if _, err := g.EnvelopeObject([]byte(issuer.id), 1, uint64(cose.ProfilePublic), nil); err == nil {
		t.Fatal("non-NFC subject accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "NonNFC" {
		t.Fatalf("want NonNFC, got %v", err)
	}
}

// ---- D4 composition with per-action approval (R-DEL-8) -----------------------------------

// setupDestructive builds a valid destructive chain (leaf effect_cap admits destructive), a fresh
// consume ledger, and a valid approval by an independent approver over the action's args content
// id (granted effect destructive, consumed by B). It returns the pieces so each composition test
// perturbs exactly one variable.
type destructiveSetup struct {
	bc        builtChain
	ledger    *approval.Ledger
	appr      approval.ApprovalRecord
	approverV cose.MLDSA65Verifier
	apprSig   []byte
	argsCID   []byte
}

func setupDestructive(t *testing.T) destructiveSetup {
	t.Helper()
	bc := buildValid2Hop(t, policy.Destructive)
	ledger, err := approval.OpenLedger(filepath.Join(t.TempDir(), "consume.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	approver := mkKey(t, 50)
	argsCID := contentIDOf([]byte("the exact canonical action args"))
	appr := approval.ApprovalRecord{
		Approves: argsCID, Approver: approver.id, Grant: uint64(policy.Destructive),
		Nonce: []byte{1, 2, 3, 4}, NotAfter: 1_000_000,
	}
	sig, err := approval.SignApproval(appr, approver.signer)
	if err != nil {
		t.Fatal(err)
	}
	return destructiveSetup{bc: bc, ledger: ledger, appr: appr, approverV: approver.verifier, apprSig: sig, argsCID: argsCID}
}

// TestCompositionBothGatesAuthorizeAndConsume: a destructive action with BOTH a valid chain and a
// valid approval is authorized, and the approval is CONSUMED exactly once, keyed by B.
func TestCompositionBothGatesAuthorizeAndConsume(t *testing.T) {
	s := setupDestructive(t)
	err := delegation.AuthorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, nil, 500,
		s.appr, s.approverV, s.apprSig, s.argsCID, s.ledger)
	if err != nil {
		t.Fatalf("both gates valid but denied: %v", err)
	}
	if !s.ledger.IsConsumed(s.appr.ID()) {
		t.Fatal("approval not consumed after authorization")
	}
}

// TestCompositionChainWithoutApproval: a valid chain but no VALID approval (here a mismatched
// approval) denies ApprovalRequired and makes NO ledger append (fail-closed). Mutation: if the
// approval gate were skipped, the destructive action would be authorized on the chain alone.
func TestCompositionChainWithoutApproval(t *testing.T) {
	s := setupDestructive(t)
	otherArgs := contentIDOf([]byte("some other args the approval does not bind"))
	err := delegation.AuthorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, nil, 500,
		s.appr, s.approverV, s.apprSig, otherArgs, s.ledger)
	if err == nil {
		t.Fatal("destructive action authorized with no matching approval")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalRequired" {
		t.Fatalf("want ApprovalRequired, got %v", err)
	}
	if s.ledger.Len() != 0 {
		t.Fatal("ledger appended on a rejected action")
	}
}

// TestCompositionApprovalWithBrokenChain: a valid approval but a broken chain (untrusted root)
// denies with the D3 error (UntrustedChainRoot), NOT ApprovalRequired, and consumes nothing — the
// chain is checked first, so a broken chain wins even when an approval is present.
func TestCompositionApprovalWithBrokenChain(t *testing.T) {
	s := setupDestructive(t)
	noAnchors := map[string]bool{} // the root is now untrusted
	err := delegation.AuthorizeDestructive(s.bc.action, s.bc.set, noAnchors, nil, 500,
		s.appr, s.approverV, s.apprSig, s.argsCID, s.ledger)
	if err == nil {
		t.Fatal("destructive action authorized on a broken chain")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UntrustedChainRoot" {
		t.Fatalf("want UntrustedChainRoot (chain checked first), got %v", err)
	}
	if s.ledger.Len() != 0 {
		t.Fatal("ledger appended when the chain gate failed")
	}
}

// TestCompositionApprovalReplayRejected: an approval is single-use — a second destructive action
// consuming the same approval is denied AlreadyConsumed (a spent approval is not fresh authority).
func TestCompositionApprovalReplayRejected(t *testing.T) {
	s := setupDestructive(t)
	if err := delegation.AuthorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, nil, 500,
		s.appr, s.approverV, s.apprSig, s.argsCID, s.ledger); err != nil {
		t.Fatalf("first authorization denied: %v", err)
	}
	err := delegation.AuthorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, nil, 500,
		s.appr, s.approverV, s.apprSig, s.argsCID, s.ledger)
	if err == nil {
		t.Fatal("approval replayed on a second destructive action")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "AlreadyConsumed" {
		t.Fatalf("want AlreadyConsumed, got %v", err)
	}
}

// TestPartitionLedgerUnreachableDeniesSpendButNotVerify proves the distributed-systems property
// (draft Approval + Security Considerations, Panel IV): the consume ledger is on the path for a
// single-use approval SPEND only, not for every object. Verifying an approval consults no ledger,
// so ordinary verification stays available under partition; only the spend reaches the ledger, and
// an executor that cannot reach it denies THAT spend fail-closed with no local spend-and-reconcile.
func TestPartitionLedgerUnreachableDeniesSpendButNotVerify(t *testing.T) {
	// (1) Availability under partition: verifying an approval object needs no ledger at all.
	s := setupDestructive(t)
	if err := approval.VerifyApproval(s.appr, s.approverV, s.apprSig, s.argsCID, 500); err != nil {
		t.Fatalf("verifying an approval must need no ledger (available under partition): %v", err)
	}

	// (2) Positive control: with a REACHABLE ledger the spend goes through exactly once, so the
	// deny-on-unreachable assertion below is not vacuous.
	if err := delegation.AuthorizeDestructive(s.bc.action, s.bc.set, s.bc.anchors, nil, 500,
		s.appr, s.approverV, s.apprSig, s.argsCID, s.ledger); err != nil {
		t.Fatalf("reachable ledger: both gates valid but spend denied: %v", err)
	}
	if !s.ledger.IsConsumed(s.appr.ID()) {
		t.Fatal("reachable ledger: approval not consumed after a successful spend")
	}

	// (3) Fail-closed spend under an UNREACHABLE ledger: model the partition by making the durable
	// ledger unwritable (Close its WAL). A fresh setup so the approval is unspent going in; both
	// gates still hold (they touch no ledger), so control reaches the spend, where the write fails.
	p := setupDestructive(t)
	if err := p.ledger.Close(); err != nil {
		t.Fatalf("close ledger (model unreachable): %v", err)
	}
	err := delegation.AuthorizeDestructive(p.bc.action, p.bc.set, p.bc.anchors, nil, 500,
		p.appr, p.approverV, p.apprSig, p.argsCID, p.ledger)
	if err == nil {
		t.Fatal("spend authorized while the ledger was unreachable (must fail closed)")
	}
	if p.ledger.IsConsumed(p.appr.ID()) || p.ledger.Len() != 0 {
		t.Fatal("local spend recorded while the ledger was unreachable (must be no state change)")
	}
}
