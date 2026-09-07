// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package mcp implements the NAALP-MCP binding profile (design.md §19; Companion-Spec
// Program Requirement 6.1), a draft-01
// ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding, signature,
// identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object (envelope §2)
// on the Bridge channel, and it REUSES the closed effect lattice (policy), the approval + single-use
// consume ledger (approval), and the T1 content-id framing (§2.3) unchanged.
//
// What the profile adds is the governance MCP itself lacks. The MCP specification states plainly
// that a tool's annotations are unenforced hints a malicious server can lie about — "clients MUST
// consider tool annotations to be untrusted unless they come from trusted servers" (MCP tools page,
// 2025-06-18 and 2025-11-25). This profile turns that anonymous, untrusted hint into a SIGNED effect
// claim by a named key:
//
//   - CARRIAGE, NOT ADOPTION. The MCP tool definition bytes and the tool-call argument bytes are
//     carried OCTET-FOR-OCTET (never re-serialized, canonicalized, or rewritten). A foreign identity
//     inside them never becomes an N-AALP authorization identity — the wrapping signer is the
//     authority (R-14.6).
//   - PUBLISHED MAPPING TABLE. The tool's annotations are mapped to the closed four-effect lattice
//     (read_only < idempotent_write < non_idempotent_write < destructive) by MapAnnotationsToEffect,
//     the table in vectors/registry/mcp.csv. Because the N-AALP spine carries no CBOR boolean
//     (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT hint takes its MCP
//     default. destructiveHint's default of TRUE is why an un-annotated write maps to destructive —
//     the same fail-closed rule as "absent effect on a state-changing object => destructive" (§6.1).
//   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
//     DECLARED effect, under the signer's ML-DSA signature. A verifier independently recomputes the
//     annotation-derived effect and enforces the MORE SEVERE of the two (ResolveEnforcedEffect — the
//     good-regulator attenuator: a disagreeing input collapses UP, never down). A disagreement is a
//     mismatch attributable to the wrapping signer's key. A signer that DECLARES BELOW its own
//     carried annotations is rejected fail-closed (EffectUnderDeclared); an annotation set that maps
//     outside the lattice is rejected (MalformedAnnotation), never defaulted to benign.
//   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
//     (tool_id + args_id). A changed tool description or changed arguments yields a new content id
//     and invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
//
// Every check is fail-closed (§15): an object failing any check is rejected whole, returns its named
// error, and causes no state change.
package mcp

import (
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// Channel binding, the tier-1 kind code, and the tier for the MCP wrapper (design.md §6.1 / the
// NAALP-MCP component). McpToolCall is kind 1 on the Bridge channel — a named escalation over the
// frozen baseline Carriage kind (0), which stays untouched (R-15A.2).
const (
	ChannelBridge   uint64 = 0x000D // Bridge channel (foreign carriage lives here)
	KindMcpToolCall uint64 = 1      // tier-1 kind code (baseline Carriage is kind 0)
	Tier            uint64 = 1      // a named escalation adding the governed MCP wrapper (R-15A.2)
)

// Annotation CBOR keys inside a naalp-mcp-annotations map. These transcribe the MCP ToolAnnotations
// field names; the value is the uint 1 (true) / 0 (false) — the N-AALP spine carries no CBOR boolean
// (design §3.1).
const (
	KeyReadOnly    uint64 = 1 // MCP readOnlyHint
	KeyDestructive uint64 = 2 // MCP destructiveHint
	KeyIdempotent  uint64 = 3 // MCP idempotentHint
	KeyOpenWorld   uint64 = 4 // MCP openWorldHint (ADVISORY — not an effect determinant)
)

// The MCP documented defaults for an ABSENT hint (read this session from the MCP ToolAnnotations
// contract; see tools/mcp_oracle.py mcp_annotation_contract). destructiveHint defaults to TRUE, so
// an un-annotated write maps to destructive — the fail-closed default.
const (
	DefaultReadOnly    = false // readOnlyHint default false
	DefaultDestructive = true  // destructiveHint default true
	DefaultIdempotent  = false // idempotentHint default false
)

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind. EffectDeclaration-
// Mismatch, EffectNotAuthorized, ApprovalRequired, ApprovalMismatch, and AlreadyConsumed are EXISTING
// errors reused unchanged.
var (
	ErrMalformedAnnotation = &cose.Error{Kind: "MalformedAnnotation", Msg: "an annotation hint value is outside {0,1}, an annotation key is outside the closed mapping, or the annotation set is not a map — it maps outside the lattice and is rejected, never defaulted to benign"}
	ErrEffectUnderDeclared = &cose.Error{Kind: "EffectUnderDeclared", Msg: "the wrapper's declared envelope effect is below the effect its own carried annotations map to; the more-severe resolution requires declared >= annotation-mapped"}
	ErrEffectOutsideLattice = &cose.Error{Kind: "EffectOutsideLattice", Msg: "a declared effect class outside the closed four-effect lattice is rejected, not defaulted to benign"}
	ErrToolCallMalformed   = &cose.Error{Kind: "ToolCallMalformed", Msg: "mcp tool-call body is not {1:tool bstr, 2:args bstr, 3:annotations map} or the object is not a tier-1 Bridge McpToolCall"}
)

// contentID is the T1 content-id framing over arbitrary bytes: multihash(0x20, SHA-384(b)). The
// 50-byte id is 0x20 0x30 || digest (design §2.3), identical to the spine's framing.
func contentID(b []byte) []byte {
	d := sha512.Sum384(b)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30)
	return append(out, d[:]...)
}

// ---- the transcribed MCP annotation set (naalp-mcp-annotations) ------------------------------

// Annotations is the wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is
// OPTIONAL: nil means the hint was absent (the MCP default applies in the mapping), so an absent hint
// and a present false are distinct on the wire though they may resolve to the same effect. openWorld
// is carried for accountability but never enters the effect mapping (design §5).
type Annotations struct {
	ReadOnly    *bool // MCP readOnlyHint
	Destructive *bool // MCP destructiveHint
	Idempotent  *bool // MCP idempotentHint
	OpenWorld   *bool // MCP openWorldHint (advisory only)
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// boolPtr is a helper for constructing Annotations in callers/tests.
func boolPtr(b bool) *bool { return &b }

// BoolPtr returns a pointer to b, for building an Annotations literal.
func BoolPtr(b bool) *bool { return boolPtr(b) }

// toValue encodes the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1.
func (a Annotations) toValue() cbor.Value {
	m := cbor.Map{}
	if a.ReadOnly != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(KeyReadOnly), V: cbor.Uint(b2u(*a.ReadOnly))})
	}
	if a.Destructive != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(KeyDestructive), V: cbor.Uint(b2u(*a.Destructive))})
	}
	if a.Idempotent != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(KeyIdempotent), V: cbor.Uint(b2u(*a.Idempotent))})
	}
	if a.OpenWorld != nil {
		m = append(m, cbor.Pair{K: cbor.Uint(KeyOpenWorld), V: cbor.Uint(b2u(*a.OpenWorld))})
	}
	return m
}

// Encode returns the deterministic-CBOR bytes of the annotation map (keys sorted by Encode).
func (a Annotations) Encode() []byte {
	b, _ := cbor.Encode(a.toValue())
	return b
}

// AnnotationsFromValue parses a naalp-mcp-annotations map. It rejects (MalformedAnnotation, fail-
// closed): a non-map, a non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes
// no boolean), or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map
// outside the closed lattice, so it is rejected, never defaulted to benign (Requirement 6.1 /
// AC-6.1.2).
func AnnotationsFromValue(v cbor.Value) (Annotations, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return Annotations{}, ErrMalformedAnnotation
	}
	var a Annotations
	seen := map[uint64]bool{}
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return Annotations{}, ErrMalformedAnnotation
		}
		u, ok := p.V.(cbor.Uint)
		if !ok || uint64(u) > 1 { // a hint value outside {0,1} maps outside the lattice
			return Annotations{}, ErrMalformedAnnotation
		}
		key := uint64(k)
		if seen[key] {
			return Annotations{}, ErrMalformedAnnotation
		}
		seen[key] = true
		val := uint64(u) == 1
		switch key {
		case KeyReadOnly:
			a.ReadOnly = &val
		case KeyDestructive:
			a.Destructive = &val
		case KeyIdempotent:
			a.Idempotent = &val
		case KeyOpenWorld:
			ov := val
			a.OpenWorld = &ov
		default:
			return Annotations{}, ErrMalformedAnnotation // key outside the closed mapping
		}
	}
	return a, nil
}

// ---- the published annotation -> effect mapping table (design §6.1) --------------------------

// MapAnnotationsToEffect maps a tool's transcribed annotations to the closed four-effect lattice by
// the published table (vectors/registry/mcp.csv), applying the MCP default for each absent hint:
//
//	readOnlyHint true                                  -> read_only            (does not modify env)
//	readOnlyHint false, destructiveHint true           -> destructive          (may destroy)
//	readOnlyHint false, destructiveHint false, idem T  -> idempotent_write     (additive, repeatable)
//	readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write (additive)
//
// An absent readOnlyHint defaults to false (a write, never read_only); an absent destructiveHint
// defaults to true (destructive) — so a tool with no annotations at all maps to destructive, the
// fail-closed collapse to the most-severe. openWorldHint is never consulted (design §5). The result
// is always in the closed lattice for a well-formed Annotations (malformed sets are rejected at
// AnnotationsFromValue), so this function does not fail.
func MapAnnotationsToEffect(a Annotations) policy.Effect {
	ro := DefaultReadOnly
	if a.ReadOnly != nil {
		ro = *a.ReadOnly
	}
	de := DefaultDestructive
	if a.Destructive != nil {
		de = *a.Destructive
	}
	idem := DefaultIdempotent
	if a.Idempotent != nil {
		idem = *a.Idempotent
	}
	if ro {
		return policy.ReadOnly
	}
	if de {
		return policy.Destructive
	}
	if idem {
		return policy.IdempotentWrite
	}
	return policy.NonIdempotentWrite
}

// ResolveEnforcedEffect is the more-severe resolution (the good-regulator attenuator). Given the
// annotation-derived effect and the wrapping signer's declared effect, it returns the enforced
// effect (the MORE SEVERE), whether the two disagreed (a mismatch attributable to the wrapping
// signer), and a named error. A declared value outside the closed lattice is EffectOutsideLattice; a
// declared value BELOW the annotation-derived effect is EffectUnderDeclared (a wrapper's declared
// effect can never sit under the effect its own carried annotations map to). On success the enforced
// effect equals the declared effect (which is therefore >= the annotation-derived effect), so a
// downstream C5 authorization reading envelope field 7 sees the correct, most-severe value.
func ResolveEnforcedEffect(annotationMapped, declared policy.Effect) (enforced policy.Effect, mismatch bool, err error) {
	if declared > policy.Destructive {
		return 0, declared != annotationMapped, ErrEffectOutsideLattice
	}
	if declared < annotationMapped {
		return 0, true, ErrEffectUnderDeclared
	}
	// declared >= annotationMapped: the enforced effect is the more severe, which is `declared`.
	return declared, declared != annotationMapped, nil
}

// ---- the wrapper body (naalp-mcp-tool-call) --------------------------------------------------

// ToolCall is the wrapper body (envelope field 10). Tool and Args are the foreign MCP bytes, carried
// octet-for-octet (carriage, not adoption); Annotations is the wrapping signer's transcription of
// the tool's hints, on which the mapping operates. The wrapper's OWN effect is the envelope field 7,
// not a body field.
type ToolCall struct {
	Tool        []byte
	Args        []byte
	Annotations Annotations
}

func (tc ToolCall) toMap() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(tc.Tool)},
		{K: cbor.Uint(2), V: cbor.Bstr(tc.Args)},
		{K: cbor.Uint(3), V: tc.Annotations.toValue()},
	}
}

// Bytes is the deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.
func (tc ToolCall) Bytes() []byte {
	b, _ := cbor.Encode(tc.toMap())
	return b
}

// ContentID is the tool-call body's content id (T1 framing): multihash(0x20, SHA-384(body)).
func (tc ToolCall) ContentID() []byte { return contentID(tc.Bytes()) }

// CallBinding returns the (tool_id, args_id) binding whose content id an approval binds for this
// call (Requirement 6.1). It is computed from the carried tool and args bytes.
func (tc ToolCall) CallBinding() CallBinding { return NewCallBinding(tc.Tool, tc.Args) }

// ToolCallFromBody parses an envelope object body (field 10) into a ToolCall. A body that is not
// exactly {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed;
// a malformed annotation set is MalformedAnnotation. Fail-closed.
func ToolCallFromBody(v cbor.Value) (ToolCall, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return ToolCall{}, ErrToolCallMalformed
	}
	var tc ToolCall
	var haveTool, haveArgs, haveAnn bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return ToolCall{}, ErrToolCallMalformed
		}
		switch uint64(k) {
		case 1:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return ToolCall{}, ErrToolCallMalformed
			}
			tc.Tool = []byte(b)
			haveTool = true
		case 2:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return ToolCall{}, ErrToolCallMalformed
			}
			tc.Args = []byte(b)
			haveArgs = true
		case 3:
			a, err := AnnotationsFromValue(p.V)
			if err != nil {
				return ToolCall{}, err // MalformedAnnotation
			}
			tc.Annotations = a
			haveAnn = true
		default:
			return ToolCall{}, ErrToolCallMalformed
		}
	}
	if !(haveTool && haveArgs && haveAnn) {
		return ToolCall{}, ErrToolCallMalformed
	}
	return tc, nil
}

// EnvelopeObject builds the (unsigned) N-AALP envelope object that carries this tool call: tier 1,
// Bridge channel, kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call
// body as field 10, and `causes` (may be empty). The caller signs it with envelope.Sign; the signer
// BECOMES accountable for the declared effect and the annotation transcription. A declared effect
// outside the closed lattice is rejected fail-closed. Under-declaration (declared below the
// annotation-derived effect) is NOT rejected here — it is a signed, attributable claim whose
// inconsistency VerifyToolCall surfaces as EffectUnderDeclared at the enforcement point.
func (tc ToolCall) EnvelopeObject(signer []byte, created, profile uint64, declared policy.Effect, causes [][]byte) (*envelope.Object, error) {
	if declared > policy.Destructive {
		return nil, ErrEffectOutsideLattice
	}
	return &envelope.Object{
		Kind: KindMcpToolCall, Channel: ChannelBridge, Tier: Tier,
		Signer: signer, Created: created, Effect: uint64(declared),
		Causes: causes, Profile: profile, Body: tc.toMap(),
	}, nil
}

// ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

// CallBinding names the exact tool call by content id: the tool bytes' content id AND the args
// bytes' content id. The approval binds the content id of THIS binding, so a changed tool
// description (new ToolID) OR changed arguments (new ArgsID) yields a new call content id and
// invalidates a prior approval bound to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
type CallBinding struct {
	ToolID []byte // multihash(0x20, SHA-384(tool bytes))
	ArgsID []byte // multihash(0x20, SHA-384(args bytes))
}

// NewCallBinding computes the binding from the raw tool and args bytes.
func NewCallBinding(tool, args []byte) CallBinding {
	return CallBinding{ToolID: contentID(tool), ArgsID: contentID(args)}
}

func (cb CallBinding) toMap() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(cb.ToolID)},
		{K: cbor.Uint(2), V: cbor.Bstr(cb.ArgsID)},
	}
}

// Bytes is the deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.
func (cb CallBinding) Bytes() []byte {
	b, _ := cbor.Encode(cb.toMap())
	return b
}

// ContentID is the call content id an approval binds: multihash(0x20, SHA-384(binding)).
func (cb CallBinding) ContentID() []byte { return contentID(cb.Bytes()) }

// ---- kind validation (composes with the frozen baseline) -------------------------------------

// KindValidator accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).
func KindValidator(channel, kind uint64) bool {
	return channel == ChannelBridge && kind == KindMcpToolCall
}

// ComposedKindValidator accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator
// an MCP-aware endpoint passes to envelope.Verify. A baseline-only endpoint using
// channels.KindValidator alone correctly rejects an McpToolCall as UnknownKind (fail-closed).
func ComposedKindValidator(channel, kind uint64) bool {
	return channels.KindValidator(channel, kind) || KindValidator(channel, kind)
}

// ---- verified tool call --------------------------------------------------------------------

// Resolved is an MCP tool call that has passed envelope verification and the effect resolution. It
// carries the enforced effect (the more-severe value C5 authorizes on), whether the annotation and
// the declared effect disagreed (Mismatch — attributable to Signer), and the parsed tool call.
type Resolved struct {
	ContentID        []byte
	Signer           []byte
	ToolCall         ToolCall
	AnnotationMapped policy.Effect // the effect the published table derives from the annotations
	Declared         policy.Effect // the wrapping signer's declared envelope effect (field 7)
	Enforced         policy.Effect // the enforced effect: max(AnnotationMapped, Declared) == Declared
	Mismatch         bool          // AnnotationMapped != Declared (attributable to Signer)
}

// VerifyToolCall verifies a signed MCP wrapper end-to-end and resolves its enforced effect. It (1)
// verifies the signed object with real crypto (envelope.Verify against the composed validator —
// content id, ranges, header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge
// McpToolCall; (3) parses the tool-call body (rejecting a malformed annotation set); (4) recomputes
// the annotation-derived effect from the CARRIED annotations, independent of the declared effect;
// (5) resolves the enforced effect to the MORE SEVERE, rejecting under-declaration. The enforced
// effect equals the declared envelope effect on success, so the object's field 7 is the correct C5
// authorization input. Any failure returns its named error and authorizes nothing (fail-closed).
func VerifyToolCall(profile int, v cose.Verifier, signedObj []byte) (Resolved, error) {
	o, err := envelope.Verify(profile, v, ComposedKindValidator, nil, signedObj)
	if err != nil {
		return Resolved{}, err
	}
	if o.Channel != ChannelBridge || o.Kind != KindMcpToolCall || o.Tier != Tier {
		return Resolved{}, ErrToolCallMalformed
	}
	tc, err := ToolCallFromBody(o.Body)
	if err != nil {
		return Resolved{}, err
	}
	mapped := MapAnnotationsToEffect(tc.Annotations)
	declared := policy.Effect(o.Effect) // envelope.Verify already range-checked field 7 to 0..3
	enforced, mismatch, err := ResolveEnforcedEffect(mapped, declared)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{
		ContentID: o.ID, Signer: o.Signer, ToolCall: tc,
		AnnotationMapped: mapped, Declared: declared, Enforced: enforced, Mismatch: mismatch,
	}, nil
}

// ---- the per-call approval gate (reuses §7 approval + consume ledger) ------------------------

// AuthorizeCall enforces the profile's per-call approval gate for a verified tool call. The approval
// MUST bind the EXACT call binding content id (tool_id + args_id) — so it satisfies neither a call
// with different arguments nor a call whose tool description changed (Requirement 6.1) — its granted
// effect must cover the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it
// is consumed single-use by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror
// the spine: a non-matching or under-granting approval denies ApprovalRequired with no ledger
// append; an already-spent approval denies AlreadyConsumed; the consume (the single state change)
// happens only when every check holds.
func AuthorizeCall(r Resolved, appr approval.ApprovalRecord, approverV cose.Verifier, apprSig []byte, by string, now uint64, ledger *approval.Ledger) error {
	callCID := r.ToolCall.CallBinding().ContentID()
	if err := approval.VerifyApproval(appr, approverV, apprSig, callCID, now); err != nil {
		// A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
		if err == approval.ErrApprovalMismatch {
			return approval.ErrApprovalRequired
		}
		return err
	}
	if !policy.Effect(appr.Grant).Authorizes(r.Enforced) {
		return approval.ErrApprovalRequired // the approval's granted effect does not cover the call
	}
	if _, err := ledger.Consume(appr.ID(), by); err != nil {
		return err // AlreadyConsumed (or IO) — fail-closed, no double-spend
	}
	return nil
}
