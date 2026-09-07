// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package delegation implements C15 — multi-hop AGENT delegation (design.md §18; requirements
// R-DEL-1..8), a Phase-3 draft-01 ADDITIVE tier-1 surface over the frozen spine (design.md
// §2..§10). It introduces NO new envelope, encoding, signature, identity, or audit mechanism
// (R-11.3): a DelegationGrant is a normal N-AALP object (envelope §2), and the mechanism REUSES
// the -00 CapDelegate substrate — parent-by-content-id in `causes` (§8.2) and the
// `CapExceedsParent` attenuation (§6.1 lattice) — rather than a parallel mechanism (D5). The only
// additions over CapDelegate are the body's `subject`, `max_depth`, and validity window.
//
// Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
// terminates at a trust anchor — distinct from the -00 tier-0 CAPABILITY delegation
// (CapIssue/CapDelegate), which answers WHAT a token may do in a single hop. Both share the one
// `CapExceedsParent` attenuation rule.
//
// The two graded surfaces:
//   - the DelegationGrant wire body (byte-graded Go == Rust == oracle: Grant.Bytes/ContentID);
//   - the 12-step leaf->root chain verifier (behaviour-graded Go == Rust == oracle: VerifyChain
//     reproduces the oracle's verdict for every scenario, run over REAL ML-DSA-65 signed chains).
//
// Every check is fail-closed (§15): an action that fails any step is rejected whole, returns its
// named error, and causes no state change. There is no partial credit and no fail-open path.
package delegation

import (
	"crypto/sha512"
	"strings"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// Channel binding (R-1.2), the tier-1 kind code, and the tier for agent-delegation
// (design.md §18.1). DelegationGrant is kind 4 — the next free code on the Capability channel
// after CapIssue/CapDelegate/CapRevoke/CapLookup (0..3).
const (
	ChannelCapability   uint64 = 0x0002 // Capability channel (reuses the CapDelegate substrate)
	KindDelegationGrant uint64 = 4      // tier-1 kind code (design.md §18.1)
	Tier                uint64 = 1      // a named escalation adding multi-hop capability (R-15A.2)
)

// GrantEffect is the grant's OWN envelope effect (field 7): issuing a grant is a
// non_idempotent_write. This is separate from the body's effect_cap, which is the ceiling the
// grant CONFERS on its subject (design.md §18.1).
const GrantEffect = policy.NonIdempotentWrite

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind. The six
// delegation-chain errors are new to the N-AALP vocabulary (design.md §18.6). `ChainBroken`
// deliberately shares its Kind with the §8.6 receipt-chain error (both denote "a named link in a
// content/hash-chained structure failed to resolve"); the two are unambiguous by channel context.
// `CapExceedsParent` (channels), `EffectNotAuthorized` (policy), and `ApprovalRequired` (approval)
// are EXISTING errors reused unchanged.
var (
	ErrChainBroken             = &cose.Error{Kind: "ChainBroken", Msg: "a delegation-chain link is missing, ambiguous, or unverifiable"}
	ErrGrantExpired            = &cose.Error{Kind: "GrantExpired", Msg: "grant is past its not_after at the action's ordering position"}
	ErrGrantNotYetValid        = &cose.Error{Kind: "GrantNotYetValid", Msg: "grant is before its not_before at the action's ordering position"}
	ErrGrantRevoked            = &cose.Error{Kind: "GrantRevoked", Msg: "grant is revoked at or before the action's ordering position"}
	ErrUntrustedChainRoot      = &cose.Error{Kind: "UntrustedChainRoot", Msg: "the chain root's issuer is not in the trust-anchor set"}
	ErrDelegationDepthExceeded = &cose.Error{Kind: "DelegationDepthExceeded", Msg: "declared or realized delegation depth exceeds max_depth"}
	ErrNonNFC                  = &cose.Error{Kind: "NonNFC", Msg: "subject/scope string is not Unicode NFC"}
	ErrGrantMalformed          = &cose.Error{Kind: "GrantMalformed", Msg: "delegation-grant body is not the {1..5,?6} shape or has an out-of-range field"}
)

// ---- the DelegationGrant object body (design.md §18.1, §18.5) --------------------------------

// Grant is the signed body (envelope field 10) of a DelegationGrant. It carries exactly what
// agent-delegation adds over CapDelegate and no more: the delegatee `Subject`, the `EffectCap`
// ceiling it confers, the `MaxDepth` onward-delegation bound, and the validity window. The
// ISSUER (agent A) is NOT a body field — it is the verified envelope signer (R-DEL-3), and the
// delegation PARENT is named by content id in the envelope `causes` (§8.2), not here.
type Grant struct {
	Subject   string        // delegatee agent id (agent B), signer-id form (§5.1); MUST be NFC
	EffectCap policy.Effect // max effect this grant conveys (§6.1 lattice); child <= this else CapExceedsParent
	MaxDepth  uint64        // max FURTHER delegation hops below this grant (0 = act, not re-delegate)
	NotBefore uint64        // validity-window start, epoch ms (GrantNotYetValid before)
	NotAfter  uint64        // validity-window end, epoch ms (GrantExpired after)
	Scope     string        // OPTIONAL NFC resource scope; "" = absent (unconstrained). Contained else CapExceedsParent
}

func (g Grant) toMap() cbor.Map {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(g.Subject)},
		{K: cbor.Uint(2), V: cbor.Uint(uint64(g.EffectCap))},
		{K: cbor.Uint(3), V: cbor.Uint(g.MaxDepth)},
		{K: cbor.Uint(4), V: cbor.Uint(g.NotBefore)},
		{K: cbor.Uint(5), V: cbor.Uint(g.NotAfter)},
	}
	if g.Scope != "" { // "" == absent (field 6 omitted); an empty scope is not a distinct value
		m = append(m, cbor.Pair{K: cbor.Uint(6), V: cbor.Tstr(g.Scope)})
	}
	return m
}

// Bytes is the deterministic-CBOR encoding of the grant body
// {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}.
func (g Grant) Bytes() []byte {
	b, _ := cbor.Encode(g.toMap())
	return b
}

// ContentID is the grant body's content id in the T1 framing (design §2.3): multihash(0x20,
// SHA-384(body)). This is the body's self-address; the ENVELOPE content id (from envelope.Sign)
// is what the delegation chain wires into `causes`.
func (g Grant) ContentID() []byte {
	d := sha512.Sum384(g.Bytes())
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30) // multihash: sha2-384 code 0x20, length 48 = 0x30
	return append(out, d[:]...)
}

// EnvelopeObject builds the (unsigned) N-AALP envelope object that carries this grant: tier 1,
// Capability channel, kind DelegationGrant, the grant's own effect non_idempotent_write, the grant
// body as field 10, and `causes` naming the delegation parent by content id (empty for a root
// grant). The caller signs it with envelope.Sign; the signer BECOMES the grant's issuer (R-DEL-3).
// A non-NFC subject/scope or an out-of-range effect_cap is rejected fail-closed.
func (g Grant) EnvelopeObject(issuer []byte, created, profile uint64, causes [][]byte) (*envelope.Object, error) {
	if err := identity.RequireNFC(g.Subject); err != nil {
		return nil, ErrNonNFC
	}
	if g.Scope != "" {
		if err := identity.RequireNFC(g.Scope); err != nil {
			return nil, ErrNonNFC
		}
	}
	if uint64(g.EffectCap) > uint64(policy.Destructive) {
		return nil, ErrGrantMalformed // an effect_cap outside the closed lattice is not a valid ceiling
	}
	return &envelope.Object{
		Kind: KindDelegationGrant, Channel: ChannelCapability, Tier: Tier,
		Signer: issuer, Created: created, Effect: uint64(GrantEffect),
		Causes: causes, Profile: profile, Body: g.toMap(),
	}, nil
}

// GrantFromBody parses an envelope object body (field 10) back into a Grant. A body that is not
// exactly the {1,2,3,4,5,?6} map with the right value types and an in-range effect_cap is an
// unverifiable/malformed grant link and is rejected ChainBroken (fail-closed, D3 step 3). An
// out-of-range effect_cap is NEVER normalized up (that would widen a ceiling — fail-open); it is
// rejected.
func GrantFromBody(v cbor.Value) (Grant, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return Grant{}, ErrChainBroken
	}
	var g Grant
	var seen [7]bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok || uint64(k) < 1 || uint64(k) > 6 {
			return Grant{}, ErrChainBroken
		}
		switch uint64(k) {
		case 1:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return Grant{}, ErrChainBroken
			}
			g.Subject = string(s)
		case 2:
			u, ok := p.V.(cbor.Uint)
			if !ok || uint64(u) > uint64(policy.Destructive) {
				return Grant{}, ErrChainBroken
			}
			g.EffectCap = policy.Effect(u)
		case 3:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return Grant{}, ErrChainBroken
			}
			g.MaxDepth = uint64(u)
		case 4:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return Grant{}, ErrChainBroken
			}
			g.NotBefore = uint64(u)
		case 5:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return Grant{}, ErrChainBroken
			}
			g.NotAfter = uint64(u)
		case 6:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return Grant{}, ErrChainBroken
			}
			g.Scope = string(s)
		}
		seen[k] = true
	}
	if !(seen[1] && seen[2] && seen[3] && seen[4] && seen[5]) { // scope (6) is optional
		return Grant{}, ErrChainBroken
	}
	return g, nil
}

// ---- kind validation (composes with the frozen baseline) -------------------------------------

// KindValidator accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant).
func KindValidator(channel, kind uint64) bool {
	return channel == ChannelCapability && kind == KindDelegationGrant
}

// ComposedKindValidator accepts the frozen baseline kinds OR the tier-1 DelegationGrant — the
// validator a delegation-aware endpoint passes to envelope.Verify. It leaves the frozen registry
// untouched (R-11.1); a baseline-only endpoint using channels.KindValidator alone correctly
// rejects a DelegationGrant as UnknownKind (fail-closed), exactly as the tier model requires.
func ComposedKindValidator(channel, kind uint64) bool {
	return channels.KindValidator(channel, kind) || KindValidator(channel, kind)
}

// ---- verified grants + the trust/revocation inputs -------------------------------------------

// Resolved is a DelegationGrant that has passed envelope verification and integrity binding
// (D3 step 3): its ENVELOPE content id (what `causes` point to), its verified issuer id (the
// envelope signer — NOT a body field, R-DEL-3), the parsed grant body, and the grant's own
// `causes` (used to resolve ITS delegation parent).
type Resolved struct {
	ContentID []byte // the grant's envelope content id (§2.3)
	Issuer    string // the verified envelope signer id (the grant's issuer)
	Grant     Grant  // the parsed grant body
	Causes    [][]byte
}

// VerifyGrantObject performs D3 step 3 for one grant: it verifies the signed object end-to-end
// with real crypto (envelope.Verify against the composed validator), confirms it is a tier-1
// Capability DelegationGrant whose own effect is non_idempotent_write, binds the claimed issuer id
// to the verifying key (identity.SignerID — a self-asserted issuer that does not derive from the
// authenticated key confers nothing, R-DEL-3/R-5.1), and parses the grant body. Any failure is an
// unverifiable link (ChainBroken / SignerMismatch / the envelope's named error), fail-closed.
func VerifyGrantObject(profile int, v cose.Verifier, pubkey, signedObj []byte) (Resolved, error) {
	o, err := envelope.Verify(profile, v, ComposedKindValidator, nil, signedObj)
	if err != nil {
		return Resolved{}, err
	}
	if o.Channel != ChannelCapability || o.Kind != KindDelegationGrant || o.Tier != Tier {
		return Resolved{}, ErrChainBroken
	}
	if o.Effect != uint64(GrantEffect) { // a DelegationGrant's own effect is non_idempotent_write
		return Resolved{}, ErrChainBroken
	}
	issuer, err := identity.SignerID(v.Alg(), pubkey)
	if err != nil {
		return Resolved{}, err
	}
	if string(o.Signer) != issuer { // the envelope signer field MUST be the authenticated id
		return Resolved{}, identity.ErrSignerMismatch
	}
	g, err := GrantFromBody(o.Body)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{ContentID: o.ID, Issuer: issuer, Grant: g, Causes: o.Causes}, nil
}

// GrantSet indexes verified grants by their envelope content id (as a string key), so the chain
// walk can resolve a parent named in `causes`.
type GrantSet map[string]Resolved

// NewGrantSet builds a GrantSet from verified grants, keyed by envelope content id.
func NewGrantSet(grants ...Resolved) GrantSet {
	s := make(GrantSet, len(grants))
	for _, g := range grants {
		s[string(g.ContentID)] = g
	}
	return s
}

// Revocations maps a revoked grant's envelope content id (as a string key) to the ordering
// position at which its CapRevoke was recorded. A grant counts as revoked at `now` iff a revoke
// naming it is ordered at or before `now` (design.md §18.2 step 5).
type Revocations map[string]uint64

// RevokedAt reports whether the grant named by content id `cid` is revoked as of `now`.
func (r Revocations) RevokedAt(cid []byte, now uint64) bool {
	p, ok := r[string(cid)]
	return ok && p <= now
}

// Action is the verified action whose delegated authority is being checked (D3 step 1 is graded
// by the caller verifying the action's own signature under B). It carries the acting agent B, the
// action's own effect and resource scope (the running child at the leaf hop), and the action's
// `causes` (from which the leaf grant is located).
type Action struct {
	Signer string        // agent B — the verified signer of the action object (R-DEL-2)
	Effect policy.Effect // the action's own effect (the leaf childEffect)
	Scope  string        // the action's resource scope ("" = unconstrained; the leaf childScope)
	Causes [][]byte      // the action's envelope causes (to locate the unique leaf grant)
}

// ---- D2 scope containment (design.md §18.1) --------------------------------------------------

// ScopeContained reports whether `child` is contained in `parent` under the D2 path-prefix rule
// (design.md §18.1): an absent parent scope ("") is unconstrained (any child, including "", is
// contained); otherwise the child must equal the parent or begin with parent + "/". A missing
// child scope ("") under a scoped parent WIDENS authority and is NOT contained.
func ScopeContained(child, parent string) bool {
	if parent == "" {
		return true // unconstrained parent
	}
	if child == "" {
		return false // missing child scope under a scoped parent widens authority
	}
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+"/")
}

// matchingCauses returns the distinct verified grants named in `causes` whose subject equals
// `subject` (the parent/leaf resolution predicate). Duplicate content ids are counted once.
func matchingCauses(causes [][]byte, subject string, grants GrantSet) []Resolved {
	seen := make(map[string]bool, len(causes))
	var out []Resolved
	for _, c := range causes {
		key := string(c)
		if seen[key] {
			continue
		}
		if r, ok := grants[key]; ok && r.Grant.Subject == subject {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

// ---- D3 chain verification (design.md §18.2) -------------------------------------------------

// VerifyChain runs the 12-step leaf->root delegation-chain walk (design.md §18.2), fail-closed
// with no partial credit. `grants` are the verified grants (VerifyGrantObject); `anchors` is the
// verifier's configured trust-anchor issuer set; `revoked` is the known revocation set; `now` is
// the action's authoritative ordering position (§8.1 receipt seq/at, NOT the signer's clock). It
// returns nil iff the chain terminates at a trusted root with every hop holding; otherwise the
// specific named error and no authorization.
//
// The step numbering matches §18.2: (1) action signature — graded by the caller/VerifyGrantObject;
// (2) locate the unique leaf grant; (3) grant integrity — graded by VerifyGrantObject; (4) validity
// window; (5) revocation; (6) attenuation (effect + scope, CapExceedsParent); (7) resolve parent;
// (8) declared depth; (9) realized depth; (10) trusted-root termination; (11) untrusted root;
// (12) fail-closed result.
func VerifyChain(action Action, grants GrantSet, anchors map[string]bool, revoked Revocations, now uint64) error {
	// step 2 — locate the unique leaf grant among the action's causes whose subject == B.
	leaves := matchingCauses(action.Causes, action.Signer, grants)
	switch len(leaves) {
	case 0:
		return policy.ErrEffectNotAuthorized // no delegation authorizes this action (existing error)
	case 1:
		// the unique leaf; fall through
	default:
		return ErrChainBroken // more than one authorizing grant is ambiguous
	}
	g := leaves[0]
	childEffect := action.Effect
	childScope := action.Scope
	pos := uint64(0) // realized delegation hops beneath the current grant
	visited := make(map[string]bool)

	for {
		key := string(g.ContentID)
		if visited[key] { // a content-id cycle (infeasible for a real hash chain) — fail-closed
			return ErrChainBroken
		}
		visited[key] = true

		// step 4 — validity window at `now`.
		if now < g.Grant.NotBefore {
			return ErrGrantNotYetValid
		}
		if now > g.Grant.NotAfter {
			return ErrGrantExpired
		}
		// step 5 — revocation at `now`.
		if revoked.RevokedAt(g.ContentID, now) {
			return ErrGrantRevoked
		}
		// step 6 — attenuation (the existing CapExceedsParent): effect ceiling AND scope containment.
		if !g.Grant.EffectCap.Authorizes(childEffect) {
			return channels.ErrCapExceedsParent
		}
		if !ScopeContained(childScope, g.Grant.Scope) {
			return channels.ErrCapExceedsParent
		}
		// step 9 — realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
		if pos > g.Grant.MaxDepth {
			return ErrDelegationDepthExceeded
		}
		// step 7 — resolve g's delegation parent (the unique cause whose subject == g's issuer).
		parents := matchingCauses(g.Causes, g.Issuer, grants)
		if len(parents) > 1 {
			return ErrChainBroken // ambiguous parent
		}
		if len(parents) == 0 {
			// steps 10 / 11 — root test: g has no delegation parent.
			if anchors[g.Issuer] {
				return nil // terminated at a trusted root (steps 10, 12): authorized
			}
			return ErrUntrustedChainRoot
		}
		p := parents[0]
		// step 8 — declared depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned underflow;
		// a parent with max_depth 0 admits no child grant).
		if p.Grant.MaxDepth == 0 || g.Grant.MaxDepth >= p.Grant.MaxDepth {
			return ErrDelegationDepthExceeded
		}
		childEffect = g.Grant.EffectCap
		childScope = g.Grant.Scope
		g = p
		pos++
	}
}

// ---- D4 composition with per-action approval (design.md §18.3, R-DEL-8) -----------------------

// AuthorizeDestructive enforces the D4 two-gate composition: a destructive-effect action requires
// BOTH gates, evaluated independently and fail-closed. It is the normative floor for `destructive`
// and MAY be used as a stricter policy for a lower effect.
//
//   - Gate 1 — a valid delegation chain (D3, VerifyChain) terminating at a trusted root whose leaf
//     effect_cap admits the action's effect (VerifyChain enforces childEffect <= leaf.effect_cap at
//     step 6, so a destructive action against a lower ceiling is denied CapExceedsParent).
//   - Gate 2 — a valid, unconsumed, exact-bytes §7 approval whose `approves` == argsContentID,
//     whose granted effect covers the action's effect, not expired at `now`, CONSUMED by the acting
//     agent B (the ledger entry's `by` is action.Signer), so accountability binds to B.
//
// Precedence (design §18.3): the chain is checked first, so a broken chain denies with its D3 error
// even when an approval is present; a valid chain with no valid approval denies ApprovalRequired
// (the §7.3 held outcome). The approval is CONSUMED (the single state change) only when both gates
// hold; a rejected action makes no ledger append. A valid-but-already-consumed approval denies
// AlreadyConsumed (a spent approval is not fresh authority).
func AuthorizeDestructive(
	action Action, grants GrantSet, anchors map[string]bool, revoked Revocations, now uint64,
	appr approval.ApprovalRecord, approverV cose.Verifier, apprSig, argsContentID []byte, ledger *approval.Ledger,
) error {
	// Gate 1 — the delegation chain (D3). A broken chain denies with its named D3 error.
	if err := VerifyChain(action, grants, anchors, revoked, now); err != nil {
		return err
	}
	// Gate 2 — a valid, unconsumed, exact-bytes approval over the action's args, consumed by B.
	if err := approval.VerifyApproval(appr, approverV, apprSig, argsContentID, now); err != nil {
		return approval.ErrApprovalRequired // no valid approval on a destructive action (held §7.3)
	}
	if !policy.Effect(appr.Grant).Authorizes(action.Effect) {
		return approval.ErrApprovalRequired // the approval's granted effect does not cover the action
	}
	if _, err := ledger.Consume(appr.ID(), action.Signer); err != nil {
		return err // AlreadyConsumed (or an IO error) — fail-closed, no double-spend
	}
	return nil
}
