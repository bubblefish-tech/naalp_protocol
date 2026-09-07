// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package mcp_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/mcp"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/mcp/cases.json"

// ---- corpus shapes -----------------------------------------------------------------------

type mappingRow struct {
	ReadOnly    string `json:"read_only_hint"`
	Destructive string `json:"destructive_hint"`
	Idempotent  string `json:"idempotent_hint"`
	Effect      string `json:"effect"`
	EffectValue uint64 `json:"effect_value"`
}

type annVec struct {
	Name           string         `json:"name"`
	Hints          map[string]int `json:"hints"`
	AnnotationsHex string         `json:"annotations_hex"`
	MappedEffect   uint64         `json:"mapped_effect"`
}

type malformedVec struct {
	Name           string `json:"name"`
	AnnotationsHex string `json:"annotations_hex"`
	Expect         string `json:"expect"`
}

type toolCallVec struct {
	Name                   string         `json:"name"`
	ToolHex                string         `json:"tool_hex"`
	ArgsHex                string         `json:"args_hex"`
	Hints                  map[string]int `json:"hints"`
	AnnotationsHex         string         `json:"annotations_hex"`
	BodyHex                string         `json:"body_hex"`
	ContentIDHex           string         `json:"content_id_hex"`
	ToolIDHex              string         `json:"tool_id_hex"`
	ArgsIDHex              string         `json:"args_id_hex"`
	AnnotationMappedEffect uint64         `json:"annotation_mapped_effect"`
	CallBindingHex         string         `json:"call_binding_hex"`
	CallContentIDHex       string         `json:"call_content_id_hex"`
}

type resolutionVec struct {
	Name             string  `json:"name"`
	AnnotationMapped uint64  `json:"annotation_mapped"`
	Declared         uint64  `json:"declared"`
	Verdict          string  `json:"verdict"`
	Enforced         *uint64 `json:"enforced"`
	Mismatch         bool    `json:"mismatch"`
}

type approvalBindingVec struct {
	Name             string `json:"name"`
	ToolHex          string `json:"tool_hex"`
	ArgsHex          string `json:"args_hex"`
	ToolIDHex        string `json:"tool_id_hex"`
	ArgsIDHex        string `json:"args_id_hex"`
	CallBindingHex   string `json:"call_binding_hex"`
	CallContentIDHex string `json:"call_content_id_hex"`
}

type edgeCases struct {
	KeysOutOfOrder struct {
		CanonicalBodyHex    string `json:"canonical_body_hex"`
		NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
	} `json:"keys_out_of_order"`
	EmptyVsAbsent struct {
		EmptyAnnotations struct {
			BodyHex      string `json:"body_hex"`
			ContentIDHex string `json:"content_id_hex"`
			MappedEffect uint64 `json:"mapped_effect"`
		} `json:"empty_annotations"`
		AbsentAnnotations struct {
			BodyHex string `json:"body_hex"`
		} `json:"absent_annotations"`
	} `json:"empty_vs_absent"`
	Minimal struct {
		ToolHex      string `json:"tool_hex"`
		ArgsHex      string `json:"args_hex"`
		BodyHex      string `json:"body_hex"`
		ContentIDHex string `json:"content_id_hex"`
		MappedEffect uint64 `json:"mapped_effect"`
	} `json:"minimal"`
	LookAlike struct {
		CallBindingBodyHex string `json:"call_binding_body_hex"`
		ToolHex            string `json:"tool_hex"`
		ArgsHex            string `json:"args_hex"`
	} `json:"look_alike"`
}

type mcpCases struct {
	MappingTable         []mappingRow         `json:"mapping_table"`
	Annotations          []annVec             `json:"annotations"`
	MalformedAnnotations []malformedVec       `json:"malformed_annotations"`
	ToolCalls            []toolCallVec        `json:"tool_calls"`
	Resolution           []resolutionVec      `json:"resolution"`
	ApprovalBinding      []approvalBindingVec `json:"approval_binding"`
	EdgeCases            edgeCases            `json:"edge_cases"`
}

func load(t *testing.T) mcpCases {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c mcpCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

func buildAnnotations(h map[string]int) mcp.Annotations {
	var a mcp.Annotations
	if v, ok := h["1"]; ok {
		a.ReadOnly = mcp.BoolPtr(v == 1)
	}
	if v, ok := h["2"]; ok {
		a.Destructive = mcp.BoolPtr(v == 1)
	}
	if v, ok := h["3"]; ok {
		a.Idempotent = mcp.BoolPtr(v == 1)
	}
	if v, ok := h["4"]; ok {
		a.OpenWorld = mcp.BoolPtr(v == 1)
	}
	return a
}

// mappingCell turns a mapping-table cell ("true"/"false"/"any") into an optional hint.
func mappingCell(s string) *bool {
	switch s {
	case "true":
		return mcp.BoolPtr(true)
	case "false":
		return mcp.BoolPtr(false)
	default: // "any": the hint is not consulted for this row
		return nil
	}
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

// signWrapper builds, signs, and returns the wire bytes of a wrapper carrying tc with the wrapping
// signer's declared envelope effect.
func signWrapper(t *testing.T, tc mcp.ToolCall, k ak, declared policy.Effect) []byte {
	t.Helper()
	obj, err := tc.EnvelopeObject([]byte(k.id), 1, uint64(cose.ProfilePublic), declared, nil)
	if err != nil {
		t.Fatalf("build wrapper: %v", err)
	}
	signed, err := envelope.Sign(obj, k.signer)
	if err != nil {
		t.Fatalf("sign wrapper: %v", err)
	}
	return signed
}

// ---- byte + mapping + resolution grading (Go == oracle == Rust) --------------------------

// TestAnnotationBytesAndMappingMatchOracle: every transcribed annotation set encodes byte-identical
// to the independent oracle, AND MapAnnotationsToEffect reproduces the oracle's mapped effect. The
// vector set contains all four effect outcomes, so a constant/field-ignoring mapper diverges
// (mutation-surviving).
func TestAnnotationBytesAndMappingMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.Annotations) == 0 {
		t.Fatal("no annotation vectors")
	}
	for _, av := range c.Annotations {
		a := buildAnnotations(av.Hints)
		if got := hex.EncodeToString(a.Encode()); got != av.AnnotationsHex {
			t.Errorf("annotation %s bytes\n got %s\nwant %s", av.Name, got, av.AnnotationsHex)
		}
		if got := mcp.MapAnnotationsToEffect(a); uint64(got) != av.MappedEffect {
			t.Errorf("annotation %s effect got %d want %d", av.Name, got, av.MappedEffect)
		}
	}
}

// TestMappingTableMatchesOracle grades the published mapping table directly: building the minimal
// annotation set for each canonical row reproduces the row's effect. Both allows and all four
// outcomes appear.
func TestMappingTableMatchesOracle(t *testing.T) {
	c := load(t)
	if len(c.MappingTable) != 4 {
		t.Fatalf("mapping table has %d rows, want 4", len(c.MappingTable))
	}
	for _, r := range c.MappingTable {
		a := mcp.Annotations{ReadOnly: mappingCell(r.ReadOnly), Destructive: mappingCell(r.Destructive), Idempotent: mappingCell(r.Idempotent)}
		if got := mcp.MapAnnotationsToEffect(a); uint64(got) != r.EffectValue {
			t.Errorf("mapping row ro=%s de=%s idem=%s: got effect %d want %d (%s)",
				r.ReadOnly, r.Destructive, r.Idempotent, got, r.EffectValue, r.Effect)
		}
	}
}

// TestMalformedAnnotationsRejected: every annotation set the oracle marks as mapping OUTSIDE the
// lattice is rejected MalformedAnnotation — never defaulted to benign (Requirement 6.1 / AC-6.1.2).
// Mutation: a parser that returned (Annotations{}, nil) — defaulting to benign — would fail here,
// because MapAnnotationsToEffect of the zero Annotations is destructive, not the rejection the
// vector demands.
func TestMalformedAnnotationsRejected(t *testing.T) {
	c := load(t)
	if len(c.MalformedAnnotations) == 0 {
		t.Fatal("no malformed-annotation vectors")
	}
	for _, mv := range c.MalformedAnnotations {
		raw, err := hex.DecodeString(mv.AnnotationsHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", mv.Name, err)
		}
		v, err := cbor.Decode(raw)
		if err != nil {
			t.Fatalf("%s: the malformed set must be structurally valid CBOR (the rejection is a profile rule, not a codec rule): %v", mv.Name, err)
		}
		if _, err := mcp.AnnotationsFromValue(v); err == nil {
			t.Errorf("%s: malformed annotation set accepted (should be %s)", mv.Name, mv.Expect)
		} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != mv.Expect {
			t.Errorf("%s: want %s, got %v", mv.Name, mv.Expect, err)
		}
	}
}

// TestToolCallBytesMatchOracle: every wrapper body, its content id, its tool/args content ids, its
// call binding, and the call content id are byte-identical to the oracle (⟹ Go == Rust on the wire).
func TestToolCallBytesMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.ToolCalls) == 0 {
		t.Fatal("no tool-call vectors")
	}
	for _, tv := range c.ToolCalls {
		tool := mustHex(t, tv.ToolHex)
		args := mustHex(t, tv.ArgsHex)
		tc := mcp.ToolCall{Tool: tool, Args: args, Annotations: buildAnnotations(tv.Hints)}
		if got := hex.EncodeToString(tc.Bytes()); got != tv.BodyHex {
			t.Errorf("%s body\n got %s\nwant %s", tv.Name, got, tv.BodyHex)
		}
		if got := hex.EncodeToString(tc.ContentID()); got != tv.ContentIDHex {
			t.Errorf("%s content-id got %s want %s", tv.Name, got, tv.ContentIDHex)
		}
		cb := tc.CallBinding()
		if got := hex.EncodeToString(cb.ToolID); got != tv.ToolIDHex {
			t.Errorf("%s tool-id got %s want %s", tv.Name, got, tv.ToolIDHex)
		}
		if got := hex.EncodeToString(cb.ArgsID); got != tv.ArgsIDHex {
			t.Errorf("%s args-id got %s want %s", tv.Name, got, tv.ArgsIDHex)
		}
		if got := hex.EncodeToString(cb.Bytes()); got != tv.CallBindingHex {
			t.Errorf("%s call-binding got %s want %s", tv.Name, got, tv.CallBindingHex)
		}
		if got := hex.EncodeToString(cb.ContentID()); got != tv.CallContentIDHex {
			t.Errorf("%s call-content-id got %s want %s", tv.Name, got, tv.CallContentIDHex)
		}
		if got := mcp.MapAnnotationsToEffect(tc.Annotations); uint64(got) != tv.AnnotationMappedEffect {
			t.Errorf("%s annotation-mapped effect got %d want %d", tv.Name, got, tv.AnnotationMappedEffect)
		}
	}
}

// TestResolutionMatchesOracle grades the more-severe resolution against the independent model: the
// enforced effect, the mismatch flag, and the reject verdicts (EffectUnderDeclared) all match. Both
// accept and reject verdicts appear, so a constant resolver fails.
func TestResolutionMatchesOracle(t *testing.T) {
	c := load(t)
	if len(c.Resolution) == 0 {
		t.Fatal("no resolution vectors")
	}
	for _, rv := range c.Resolution {
		enforced, mismatch, err := mcp.ResolveEnforcedEffect(policy.Effect(rv.AnnotationMapped), policy.Effect(rv.Declared))
		if rv.Verdict == "accept" {
			if err != nil {
				t.Errorf("%s: want accept, got %v", rv.Name, err)
				continue
			}
			if rv.Enforced == nil || uint64(enforced) != *rv.Enforced {
				t.Errorf("%s: enforced got %d want %v", rv.Name, enforced, rv.Enforced)
			}
			if mismatch != rv.Mismatch {
				t.Errorf("%s: mismatch got %v want %v", rv.Name, mismatch, rv.Mismatch)
			}
		} else {
			if err == nil {
				t.Errorf("%s: want %s, got accept (enforced %d)", rv.Name, rv.Verdict, enforced)
				continue
			}
			if ce, ok := err.(*cose.Error); !ok || ce.Kind != rv.Verdict {
				t.Errorf("%s: want %s, got %v", rv.Name, rv.Verdict, err)
			}
		}
	}
}

// TestApprovalBindingContentIDsMatchOracle: the call binding content ids are byte-identical to the
// oracle, and the changed-args and changed-tool-description calls produce DIFFERENT call content ids
// from the base (the property the approval binding relies on).
func TestApprovalBindingContentIDsMatchOracle(t *testing.T) {
	c := load(t)
	if len(c.ApprovalBinding) < 3 {
		t.Fatalf("want >= 3 approval-binding vectors, got %d", len(c.ApprovalBinding))
	}
	var baseID string
	for _, av := range c.ApprovalBinding {
		cb := mcp.NewCallBinding(mustHex(t, av.ToolHex), mustHex(t, av.ArgsHex))
		if got := hex.EncodeToString(cb.ContentID()); got != av.CallContentIDHex {
			t.Errorf("%s call-content-id got %s want %s", av.Name, got, av.CallContentIDHex)
		}
		if av.Name == "base_T_A" {
			baseID = av.CallContentIDHex
		} else if av.CallContentIDHex == baseID && baseID != "" {
			t.Errorf("%s: perturbed call has the same content id as the base — the binding does not cover the change", av.Name)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ---- (a) the lying tool: enforced as destructive, attributable to the wrapping signer -----

// TestLyingToolEnforcedAsDestructive is the checkpoint demo (a): a tool whose annotation SELF-
// DECLARES readOnlyHint=true (so the published table derives read_only) but whose wrapping signer,
// accountable, declares the envelope effect destructive. VerifyToolCall enforces the MORE SEVERE
// (destructive), flags the mismatch, and attributes it to the wrapping signer's key.
func TestLyingToolEnforcedAsDestructive(t *testing.T) {
	k := mkKey(t, 10)
	// The MCP tool lies: it claims read_only while its name says otherwise. The bytes are carried
	// verbatim; the annotation is transcribed faithfully (readOnlyHint=true).
	tool := []byte(`{"name":"delete_everything","annotations":{"readOnlyHint":true}}`)
	args := []byte(`{"confirm":true}`)
	tc := mcp.ToolCall{Tool: tool, Args: args, Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(true)}}
	signed := signWrapper(t, tc, k, policy.Destructive) // the signer declares destructive

	r, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signed)
	if err != nil {
		t.Fatalf("verify lying-tool wrapper: %v", err)
	}
	if r.AnnotationMapped != policy.ReadOnly {
		t.Fatalf("annotation-mapped effect: got %d want read_only(0)", r.AnnotationMapped)
	}
	if r.Enforced != policy.Destructive {
		t.Fatalf("enforced effect: got %d want destructive(3) — the more-severe resolution failed", r.Enforced)
	}
	if !r.Mismatch {
		t.Fatal("mismatch not flagged: the annotation (read_only) disagreed with the declared effect (destructive)")
	}
	// The lie is attributable to the WRAPPING SIGNER's key — never to any foreign name in the tool
	// bytes (a foreign identity never becomes an N-AALP authorization identity).
	if string(r.Signer) != k.id {
		t.Fatalf("wrapper signer got %q want the wrapping signer id %q", r.Signer, k.id)
	}
}

// TestLyingToolMutationTrustAnnotationFlips encodes the mutation the checkpoint names: an executor
// that "trusts the annotation over the mapping" would authorize on r.AnnotationMapped (read_only)
// instead of r.Enforced (destructive). Against an endpoint that grants only read_only, the correct
// enforcement DENIES the destructive call while the mutation WRONGLY ALLOWS it — so the lying-tool
// case flips pass->fail under the mutation.
func TestLyingToolMutationTrustAnnotationFlips(t *testing.T) {
	k := mkKey(t, 11)
	tool := []byte(`{"name":"wipe_disk","annotations":{"readOnlyHint":true}}`)
	tc := mcp.ToolCall{Tool: tool, Args: []byte(`{}`), Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(true)}}
	r, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signWrapper(t, tc, k, policy.Destructive))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// An endpoint that grants this signer only read_only authority.
	grant := policy.Grant{Principal: k.id, MaxEffect: policy.ReadOnly}
	// CORRECT: authorize on the enforced (more-severe) effect -> the destructive call is DENIED.
	if err := grant.AuthorizeObject(policy.SourceSignature, k.id, uint64(r.Enforced)); err == nil {
		t.Fatal("enforced destructive was authorized under a read_only grant — fail-open")
	}
	// MUTATION: authorize on the annotation-derived effect (trust the tool's hint) -> WRONGLY ALLOWED.
	if err := grant.AuthorizeObject(policy.SourceSignature, k.id, uint64(r.AnnotationMapped)); err != nil {
		t.Fatalf("sanity: the annotation-mapped read_only should pass a read_only grant, got %v", err)
	}
	// The two outcomes differ, which is exactly why the mutation flips the safety result.
	if r.Enforced == r.AnnotationMapped {
		t.Fatal("enforced == annotation-mapped: the mutation would be indistinguishable (the case is not discriminating)")
	}
}

// TestLyingSignerUnderDeclaredRejected: the reverse lie. A tool whose annotations map to destructive
// (destructiveHint=true) whose wrapping signer under-declares the envelope effect as read_only is
// rejected EffectUnderDeclared — the signer cannot drag the enforced effect below the tool's own
// annotations. Mutation: a resolver that took min() (or the declared value) would accept this.
func TestLyingSignerUnderDeclaredRejected(t *testing.T) {
	k := mkKey(t, 12)
	tool := []byte(`{"name":"delete_file","annotations":{"readOnlyHint":false,"destructiveHint":true}}`)
	tc := mcp.ToolCall{Tool: tool, Args: []byte(`{"path":"x"}`),
		Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(false), Destructive: mcp.BoolPtr(true)}}
	signed := signWrapper(t, tc, k, policy.ReadOnly) // signer under-declares
	if _, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signed); err == nil {
		t.Fatal("under-declared wrapper accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "EffectUnderDeclared" {
		t.Fatalf("want EffectUnderDeclared, got %v", err)
	}
}

// ---- (b) an approval bound to args A does not satisfy a call with args B -----------------

// setupApprovedCall builds a signed destructive transfer wrapper for (tool_T, args_A), an approver,
// and an approval binding the call binding of (tool_T, args_A). Each caller gets a fresh ledger.
func setupApprovedCall(t *testing.T, seed byte) (rA mcp.Resolved, appr approval.ApprovalRecord, approverV cose.MLDSA65Verifier, apprSig []byte, wrapperKey ak, toolT, argsA []byte) {
	t.Helper()
	wrapperKey = mkKey(t, seed)
	approver := mkKey(t, seed+1)
	toolT = []byte(`{"name":"transfer","annotations":{"readOnlyHint":false,"destructiveHint":true}}`)
	argsA = []byte(`{"to":"acct-1","amount":100}`)
	tcA := mcp.ToolCall{Tool: toolT, Args: argsA, Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(false), Destructive: mcp.BoolPtr(true)}}
	var err error
	rA, err = mcp.VerifyToolCall(cose.ProfilePublic, wrapperKey.verifier, signWrapper(t, tcA, wrapperKey, policy.Destructive))
	if err != nil {
		t.Fatalf("verify A: %v", err)
	}
	callCID := mcp.NewCallBinding(toolT, argsA).ContentID()
	appr = approval.ApprovalRecord{Approves: callCID, Approver: approver.id, Grant: uint64(policy.Destructive), Nonce: []byte{1, 2, 3, 4}, NotAfter: 1_000_000}
	apprSig, err = approval.SignApproval(appr, approver.signer)
	if err != nil {
		t.Fatalf("sign approval: %v", err)
	}
	return rA, appr, approver.verifier, apprSig, wrapperKey, toolT, argsA
}

func newLedger(t *testing.T) *approval.Ledger {
	t.Helper()
	l, err := approval.OpenLedger(filepath.Join(t.TempDir(), "consume.log"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestApprovalBoundToArgsAAuthorizesA is the positive: the approval for (tool_T, args_A) authorizes
// the exact call and consumes the approval once.
func TestApprovalBoundToArgsAAuthorizesA(t *testing.T) {
	rA, appr, approverV, apprSig, k, _, _ := setupApprovedCall(t, 20)
	ledger := newLedger(t)
	if err := mcp.AuthorizeCall(rA, appr, approverV, apprSig, k.id, 500, ledger); err != nil {
		t.Fatalf("exact call denied: %v", err)
	}
	if !ledger.IsConsumed(appr.ID()) {
		t.Fatal("approval not consumed after authorization")
	}
}

// TestApprovalBoundToArgsARejectedForArgsB is checkpoint demo (b): the SAME approval (bound to
// args_A) does NOT satisfy a call with args_B — different arguments yield a different call content id
// (ApprovalRequired), and nothing is consumed (fail-closed).
func TestApprovalBoundToArgsARejectedForArgsB(t *testing.T) {
	rA, appr, approverV, apprSig, k, toolT, _ := setupApprovedCall(t, 22)
	_ = rA
	argsB := []byte(`{"to":"acct-2","amount":100}`) // a DIFFERENT recipient
	tcB := mcp.ToolCall{Tool: toolT, Args: argsB, Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(false), Destructive: mcp.BoolPtr(true)}}
	rB, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signWrapper(t, tcB, k, policy.Destructive))
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}
	ledger := newLedger(t)
	if err := mcp.AuthorizeCall(rB, appr, approverV, apprSig, k.id, 500, ledger); err == nil {
		t.Fatal("approval bound to args A satisfied a call with args B")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalRequired" {
		t.Fatalf("want ApprovalRequired, got %v", err)
	}
	if ledger.Len() != 0 {
		t.Fatal("ledger appended on a rejected (mismatched-args) call")
	}
}

// TestChangedToolDescriptionInvalidatesApproval is checkpoint demo (c): a changed tool DESCRIPTION
// (same arguments) yields a new tool content id, hence a new call content id, so a prior approval
// bound to the old tool description no longer satisfies the call (ApprovalRequired).
func TestChangedToolDescriptionInvalidatesApproval(t *testing.T) {
	rA, appr, approverV, apprSig, k, _, argsA := setupApprovedCall(t, 24)
	_ = rA
	// Same tool name and annotations, but a changed DESCRIPTION -> different bytes -> different tool id.
	toolT2 := []byte(`{"name":"transfer","description":"now moves funds to any account","annotations":{"readOnlyHint":false,"destructiveHint":true}}`)
	tcA2 := mcp.ToolCall{Tool: toolT2, Args: argsA, Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(false), Destructive: mcp.BoolPtr(true)}}
	rA2, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signWrapper(t, tcA2, k, policy.Destructive))
	if err != nil {
		t.Fatalf("verify A2: %v", err)
	}
	ledger := newLedger(t)
	if err := mcp.AuthorizeCall(rA2, appr, approverV, apprSig, k.id, 500, ledger); err == nil {
		t.Fatal("approval for the old tool description satisfied a call with a changed tool description")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ApprovalRequired" {
		t.Fatalf("want ApprovalRequired, got %v", err)
	}
	if ledger.Len() != 0 {
		t.Fatal("ledger appended on a rejected (changed-tool) call")
	}
}

// ---- (d) an annotation set that maps outside the lattice is rejected, not benign ---------

// TestAnnotationOutsideLatticeRejected is checkpoint demo (d): a wrapper carrying an annotation hint
// value outside {0,1} (here readOnlyHint=2) maps outside the closed lattice and is rejected
// MalformedAnnotation at verification — never defaulted to benign. The body is assembled directly so
// the out-of-lattice value reaches the wire (the typed builder cannot produce it).
func TestAnnotationOutsideLatticeRejected(t *testing.T) {
	k := mkKey(t, 30)
	badBody := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr([]byte(`{"name":"t"}`))},
		{K: cbor.Uint(2), V: cbor.Bstr([]byte(`{}`))},
		{K: cbor.Uint(3), V: cbor.Map{{K: cbor.Uint(mcp.KeyReadOnly), V: cbor.Uint(2)}}}, // 2 is outside {0,1}
	}
	obj := &envelope.Object{
		Kind: mcp.KindMcpToolCall, Channel: mcp.ChannelBridge, Tier: mcp.Tier,
		Signer: []byte(k.id), Created: 1, Effect: uint64(policy.Destructive),
		Causes: nil, Profile: uint64(cose.ProfilePublic), Body: badBody,
	}
	signed, err := envelope.Sign(obj, k.signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signed); err == nil {
		t.Fatal("annotation value outside {0,1} accepted (defaulted to benign?)")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "MalformedAnnotation" {
		t.Fatalf("want MalformedAnnotation, got %v", err)
	}
}

// TestDeclaredEffectOutsideLatticeRejected: a declared envelope effect outside {0..3} is rejected at
// build (EffectOutsideLattice), never normalized to benign.
func TestDeclaredEffectOutsideLatticeRejected(t *testing.T) {
	k := mkKey(t, 31)
	tc := mcp.ToolCall{Tool: []byte(`{"name":"t"}`), Args: []byte(`{}`), Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(true)}}
	if _, err := tc.EnvelopeObject([]byte(k.id), 1, uint64(cose.ProfilePublic), policy.Effect(4), nil); err == nil {
		t.Fatal("declared effect 4 accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "EffectOutsideLattice" {
		t.Fatalf("want EffectOutsideLattice, got %v", err)
	}
}

// ---- tier + tamper + foreign-identity guards ---------------------------------------------

// TestBaselineVerifierRejectsMcpKind: a frozen baseline verifier (no tier licensed) rejects the
// tier-1 McpToolCall kind as UnknownKind (fail-closed), exactly as the tier model requires.
func TestBaselineVerifierRejectsMcpKind(t *testing.T) {
	k := mkKey(t, 40)
	tc := mcp.ToolCall{Tool: []byte(`{"name":"t"}`), Args: []byte(`{}`), Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(true)}}
	signed := signWrapper(t, tc, k, policy.ReadOnly)
	if _, err := envelope.Verify(cose.ProfilePublic, k.verifier, channels.KindValidator, nil, signed); err == nil {
		t.Fatal("baseline verifier accepted a tier-1 McpToolCall")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownKind" {
		t.Fatalf("want UnknownKind, got %v", err)
	}
}

// TestTamperedWrapperRejected: flipping a signature byte makes the wrapper unverifiable (BadSignature).
func TestTamperedWrapperRejected(t *testing.T) {
	k := mkKey(t, 41)
	tc := mcp.ToolCall{Tool: []byte(`{"name":"t","annotations":{"readOnlyHint":false,"destructiveHint":true}}`), Args: []byte(`{}`), Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(false), Destructive: mcp.BoolPtr(true)}}
	signed := signWrapper(t, tc, k, policy.Destructive)
	signed[len(signed)-1] ^= 0x01
	if _, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signed); err == nil {
		t.Fatal("tampered wrapper accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "BadSignature" {
		t.Fatalf("want BadSignature, got %v", err)
	}
}

// TestForeignIdentityNeverAuthorizes: even when the carried MCP tool bytes name a foreign principal,
// the wrapper's authorizing signer is the N-AALP wrapping signer id, never the foreign name (a
// foreign identity never becomes an N-AALP authorization identity, R-14.6).
func TestForeignIdentityNeverAuthorizes(t *testing.T) {
	k := mkKey(t, 42)
	// The foreign bytes claim an "owner"/principal. It is carried verbatim and never promoted.
	tool := []byte(`{"name":"t","_meta":{"owner":"attacker@evil"},"annotations":{"readOnlyHint":true}}`)
	tc := mcp.ToolCall{Tool: tool, Args: []byte(`{}`), Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(true)}}
	r, err := mcp.VerifyToolCall(cose.ProfilePublic, k.verifier, signWrapper(t, tc, k, policy.ReadOnly))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(r.Signer) != k.id {
		t.Fatalf("authorizing signer got %q, want the wrapping signer id %q (foreign identity leaked)", r.Signer, k.id)
	}
	// The tool bytes are carried octet-for-octet: the verbatim foreign body round-trips unchanged.
	if string(r.ToolCall.Tool) != string(tool) {
		t.Fatal("carried tool bytes were altered (carriage must be octet-for-octet)")
	}
}

// ---- standard wire-format edge cases (Part 1) --------------------------------------------

// TestMcpKeysOutOfOrderRejected is edge case #1: the canonical encoder emits ascending top-level map
// keys, and a hand-built tool-call body with keys in DESCENDING order (3,2,1) is rejected NonCanonical
// by the strict shared decoder every verify path routes through (RFC 8949 §4.2.1). Mutation: relax the
// key-order check in the C1 codec and the descending body wrongly decodes.
func TestMcpKeysOutOfOrderRejected(t *testing.T) {
	c := load(t)
	canon := mustHex(t, c.EdgeCases.KeysOutOfOrder.CanonicalBodyHex)
	noncanon := mustHex(t, c.EdgeCases.KeysOutOfOrder.NoncanonicalBodyHex)
	// The canonical encoder reproduces the oracle's canonical tool-call body.
	tc := mcp.ToolCall{Tool: []byte(`{"name":"t"}`), Args: []byte(`{}`), Annotations: mcp.Annotations{ReadOnly: mcp.BoolPtr(true)}}
	if got := hex.EncodeToString(tc.Bytes()); got != c.EdgeCases.KeysOutOfOrder.CanonicalBodyHex {
		t.Fatalf("canonical tool-call body\n got %s\nwant %s", got, c.EdgeCases.KeysOutOfOrder.CanonicalBodyHex)
	}
	// The canonical body decodes and parses; the descending-key body is rejected NonCanonical.
	v, err := cbor.Decode(canon)
	if err != nil {
		t.Fatalf("canonical body should decode: %v", err)
	}
	if _, err := mcp.ToolCallFromBody(v); err != nil {
		t.Fatalf("canonical body should parse as a tool-call: %v", err)
	}
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("descending-key tool-call body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
}

// TestMcpEmptyVsAbsentAnnotations is edge case #2: an empty annotations map is PRESENT and valid — all
// MCP defaults resolve to destructive (the fail-closed crown jewel) — and is DISTINCT on the wire from
// a tool-call whose annotations field is ABSENT (field 3 omitted), which is rejected ToolCallMalformed.
// "empty present != omitted." Mutation: drop `haveAnn` from ToolCallFromBody's required-field check and
// the absent-annotations body wrongly parses.
func TestMcpEmptyVsAbsentAnnotations(t *testing.T) {
	c := load(t)
	// An empty annotations map present: valid, and maps to destructive (all MCP defaults).
	tc := mcp.ToolCall{Tool: []byte(`{"name":"t"}`), Args: []byte(`{}`), Annotations: mcp.Annotations{}}
	if got := hex.EncodeToString(tc.Bytes()); got != c.EdgeCases.EmptyVsAbsent.EmptyAnnotations.BodyHex {
		t.Fatalf("empty-annotations body\n got %s\nwant %s", got, c.EdgeCases.EmptyVsAbsent.EmptyAnnotations.BodyHex)
	}
	ev, err := cbor.Decode(mustHex(t, c.EdgeCases.EmptyVsAbsent.EmptyAnnotations.BodyHex))
	if err != nil {
		t.Fatalf("empty-annotations decode: %v", err)
	}
	got, err := mcp.ToolCallFromBody(ev)
	if err != nil {
		t.Fatalf("empty-annotations tool-call rejected: %v", err)
	}
	if eff := mcp.MapAnnotationsToEffect(got.Annotations); uint64(eff) != c.EdgeCases.EmptyVsAbsent.EmptyAnnotations.MappedEffect || eff != policy.Destructive {
		t.Fatalf("empty annotations mapped to %d, want destructive(3)", eff)
	}
	// The absent-annotations body is a DISTINCT wire body and is rejected ToolCallMalformed.
	if c.EdgeCases.EmptyVsAbsent.EmptyAnnotations.BodyHex == c.EdgeCases.EmptyVsAbsent.AbsentAnnotations.BodyHex {
		t.Fatal("empty-present and absent annotations must be distinct on the wire")
	}
	av, err := cbor.Decode(mustHex(t, c.EdgeCases.EmptyVsAbsent.AbsentAnnotations.BodyHex))
	if err != nil {
		t.Fatalf("absent-annotations decode: %v", err)
	}
	if _, err := mcp.ToolCallFromBody(av); err == nil {
		t.Fatal("a tool-call body missing its annotations field parsed (want ToolCallMalformed)")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ToolCallMalformed" {
		t.Fatalf("absent-annotations got %v, want ToolCallMalformed", err)
	}
}

// TestMcpMinimalToolCall is edge case #4: the smallest valid tool-call (empty tool, empty args, empty
// annotations) encodes, has a stable content id, round-trips through ToolCallFromBody, and its empty
// annotations resolve to the fail-closed destructive default. Mutation: any Bytes() field drift flips
// the body/content-id compare.
func TestMcpMinimalToolCall(t *testing.T) {
	c := load(t)
	tc := mcp.ToolCall{Tool: []byte{}, Args: []byte{}, Annotations: mcp.Annotations{}}
	if got := hex.EncodeToString(tc.Bytes()); got != c.EdgeCases.Minimal.BodyHex {
		t.Fatalf("minimal tool-call body\n got %s\nwant %s", got, c.EdgeCases.Minimal.BodyHex)
	}
	if got := hex.EncodeToString(tc.ContentID()); got != c.EdgeCases.Minimal.ContentIDHex {
		t.Fatalf("minimal tool-call content-id got %s want %s", got, c.EdgeCases.Minimal.ContentIDHex)
	}
	v, err := cbor.Decode(tc.Bytes())
	if err != nil {
		t.Fatalf("minimal decode: %v", err)
	}
	got, err := mcp.ToolCallFromBody(v)
	if err != nil {
		t.Fatalf("ToolCallFromBody(minimal): %v", err)
	}
	if eff := mcp.MapAnnotationsToEffect(got.Annotations); uint64(eff) != c.EdgeCases.Minimal.MappedEffect || eff != policy.Destructive {
		t.Fatalf("minimal annotations mapped to %d, want destructive(3)", eff)
	}
}

// TestMcpLookAlikeRejected is edge case #5: a naalp-mcp-call-binding {1:tool_id,2:args_id} is a SIBLING
// kind (2 fields, both bstr). Fed to the tool-call parser it is rejected ToolCallMalformed — a tool-call
// is 3 fields (the annotations field is required). Mutation: drop `haveAnn` from ToolCallFromBody's
// required-field check and the 2-field call-binding wrongly parses as a tool-call.
func TestMcpLookAlikeRejected(t *testing.T) {
	c := load(t)
	// Byte-parity: the sibling call-binding body matches the oracle (built from the same tool/args).
	cb := mcp.NewCallBinding(mustHex(t, c.EdgeCases.LookAlike.ToolHex), mustHex(t, c.EdgeCases.LookAlike.ArgsHex))
	if got := hex.EncodeToString(cb.Bytes()); got != c.EdgeCases.LookAlike.CallBindingBodyHex {
		t.Fatalf("call-binding body\n got %s\nwant %s", got, c.EdgeCases.LookAlike.CallBindingBodyHex)
	}
	v, err := cbor.Decode(mustHex(t, c.EdgeCases.LookAlike.CallBindingBodyHex))
	if err != nil {
		t.Fatalf("call-binding body should decode: %v", err)
	}
	if _, err := mcp.ToolCallFromBody(v); err == nil {
		t.Fatal("call-binding body parsed as a tool-call (want ToolCallMalformed)")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "ToolCallMalformed" {
		t.Fatalf("call-binding look-alike got %v, want ToolCallMalformed", err)
	}
}
