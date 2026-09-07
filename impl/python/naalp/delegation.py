# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C15 multi-hop agent delegation for the Python SDK (design.md §18; R-DEL-1..8).

Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
terminates at a trust anchor. A DelegationGrant is a normal N-AALP envelope object (a tier-1
Capability surface, kind 4); it introduces NO new envelope, encoding, signature, identity, or audit
mechanism. Its body carries exactly what agent-delegation adds over a single-hop capability: the
delegatee `subject`, the `effect_cap` ceiling it confers, the `max_depth` onward-delegation bound,
and the validity window (plus an optional `scope`). The ISSUER is NOT a body field -- it is the
verified envelope signer (R-DEL-3); the delegation PARENT is named by content id in the envelope
`causes`.

The two graded surfaces: the DelegationGrant wire body (byte-graded == oracle), and the 12-step
leaf->root chain verifier (verdict-graded == oracle, over REAL ML-DSA-65 signed chains). Every check
is fail-closed (§15): an action that fails any step is rejected whole, returns its named error, and
causes no state change. Ported from impl/go/delegation; graded against vectors/delegation/cases.json.

The D4 composition (authorize_destructive) reuses the new approval module's single-use consume
ledger for the per-action approval gate -- a real wiring of delegation onto approval, not a stub.
"""
from . import channels, envelope, identity, policy
from .cbor import U, T, M

# Channel binding, the tier-1 kind code, and the tier for agent-delegation (design §18.1).
CHANNEL_CAPABILITY = 0x0002     # Capability channel (reuses the CapDelegate substrate)
KIND_DELEGATION_GRANT = 4       # tier-1 kind code, the next free code after CapIssue/Delegate/Revoke/Lookup
TIER = 1                        # a named escalation adding multi-hop capability

# A grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write. This is
# separate from the body's effect_cap, which is the ceiling the grant CONFERS on its subject.
GRANT_EFFECT = policy.NON_IDEMPOTENT_WRITE


class DelegationError(ValueError):
    """A named, fail-closed delegation error; .kind is the stable error kind (§18.6, §15). Kinds
    reused from other layers (CapExceedsParent, EffectNotAuthorized, ApprovalRequired, SignerMismatch)
    carry those exact kind strings so a verifier's verdict is identical to the Go reference."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


# ---- the DelegationGrant object body (design §18.1, §18.5) ------------------------------------

class Grant:
    """The signed body of a DelegationGrant. `subject` is the delegatee agent id (signer-id form,
    MUST be NFC); `effect_cap` is the max effect this grant conveys; `max_depth` the max FURTHER
    delegation hops below it; `not_before`/`not_after` the validity window; `scope` an OPTIONAL NFC
    resource scope ("" = absent/unconstrained, field 6 omitted)."""

    __slots__ = ("subject", "effect_cap", "max_depth", "not_before", "not_after", "scope")

    def __init__(self, subject, effect_cap, max_depth, not_before, not_after, scope=""):
        self.subject = subject
        self.effect_cap = int(effect_cap)
        self.max_depth = int(max_depth)
        self.not_before = int(not_before)
        self.not_after = int(not_after)
        self.scope = scope

    def _to_map(self):
        pairs = [
            (U(1), T(self.subject)),
            (U(2), U(self.effect_cap)),
            (U(3), U(self.max_depth)),
            (U(4), U(self.not_before)),
            (U(5), U(self.not_after)),
        ]
        if self.scope != "":     # "" == absent (field 6 omitted); an empty scope is not a distinct value
            pairs.append((U(6), T(self.scope)))
        return M(pairs)

    def bytes(self):
        """Deterministic-CBOR encoding {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,
        ?6:scope}."""
        from . import cbor
        return cbor.encode(self._to_map())

    def content_id(self):
        """The grant body's content id: multihash(0x20, SHA-384(body)). This is the body's
        self-address; the ENVELOPE content id is what a delegation chain wires into `causes`."""
        from . import cbor
        return cbor.content_id(self.bytes())

    def envelope_object(self, issuer, created, profile, causes):
        """Build the (unsigned) N-AALP envelope object carrying this grant: tier 1, Capability
        channel, kind DelegationGrant, the grant's own effect non_idempotent_write, the grant body as
        the object body, and `causes` naming the delegation parent by content id (empty for a root
        grant). A non-NFC subject/scope or an out-of-range effect_cap is rejected fail-closed."""
        try:
            identity.require_nfc(self.subject)
        except identity.NonNFC:
            raise DelegationError("NonNFC", "subject is not Unicode NFC")
        if self.scope != "":
            try:
                identity.require_nfc(self.scope)
            except identity.NonNFC:
                raise DelegationError("NonNFC", "scope is not Unicode NFC")
        if self.effect_cap > policy.DESTRUCTIVE:
            raise DelegationError("GrantMalformed", "effect_cap outside the closed lattice")
        return envelope.Object(
            kind=KIND_DELEGATION_GRANT, channel=CHANNEL_CAPABILITY, tier=TIER,
            signer=bytes(issuer), created=created, effect=GRANT_EFFECT,
            causes=list(causes), profile=profile, body=self._to_map())


def sign_grant(obj, alg, seed):
    """Sign a DelegationGrant envelope object with a real deterministic ML-DSA key; the signer
    BECOMES the grant's issuer (R-DEL-3)."""
    return envelope.sign(obj, alg, seed)


def grant_from_body(v):
    """Parse an envelope object body back into a Grant. A body that is not exactly the {1,2,3,4,5,?6}
    map with the right value types and an in-range effect_cap is an unverifiable/malformed grant link
    and is rejected ChainBroken (fail-closed). An out-of-range effect_cap is NEVER normalized up
    (that would widen a ceiling -- fail-open); it is rejected."""
    if not isinstance(v, M):
        raise DelegationError("ChainBroken", "grant body is not a map")
    g = Grant("", 0, 0, 0, 0, "")
    seen = set()
    for k, val in v.pairs:
        if not isinstance(k, U) or k.v < 1 or k.v > 6:
            raise DelegationError("ChainBroken", "grant body has an out-of-range field")
        if k.v == 1:
            if not isinstance(val, T):
                raise DelegationError("ChainBroken", "subject is not a tstr")
            g.subject = val.v
        elif k.v == 2:
            if not isinstance(val, U) or val.v > policy.DESTRUCTIVE:
                raise DelegationError("ChainBroken", "effect_cap absent or out of range")
            g.effect_cap = val.v
        elif k.v == 3:
            if not isinstance(val, U):
                raise DelegationError("ChainBroken", "max_depth is not a uint")
            g.max_depth = val.v
        elif k.v == 4:
            if not isinstance(val, U):
                raise DelegationError("ChainBroken", "not_before is not a uint")
            g.not_before = val.v
        elif k.v == 5:
            if not isinstance(val, U):
                raise DelegationError("ChainBroken", "not_after is not a uint")
            g.not_after = val.v
        elif k.v == 6:
            if not isinstance(val, T):
                raise DelegationError("ChainBroken", "scope is not a tstr")
            g.scope = val.v
        seen.add(k.v)
    if not {1, 2, 3, 4, 5}.issubset(seen):     # scope (6) is optional
        raise DelegationError("ChainBroken", "grant body is missing a mandatory field")
    return g


# ---- kind validation (composes with the frozen baseline) -------------------------------------

def kind_validator(channel, kind):
    """Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant)."""
    return channel == CHANNEL_CAPABILITY and kind == KIND_DELEGATION_GRANT


def _baseline_kind_validator(channel, kind):
    try:
        channels.lookup(channel, kind)
        return True
    except channels.UnknownKind:
        return False


def composed_kind_validator(channel, kind):
    """Accepts the frozen baseline kinds OR the tier-1 DelegationGrant -- the validator a
    delegation-aware endpoint passes to envelope.verify. A baseline-only endpoint using the baseline
    validator alone correctly rejects a DelegationGrant as UnknownKind (fail-closed)."""
    return _baseline_kind_validator(channel, kind) or kind_validator(channel, kind)


# ---- verified grants + the trust/revocation inputs -------------------------------------------

class Resolved:
    """A DelegationGrant that has passed envelope verification and integrity binding: its ENVELOPE
    content id (what `causes` point to), its verified issuer id (the envelope signer -- NOT a body
    field, R-DEL-3), the parsed grant body, and the grant's own `causes`."""

    __slots__ = ("content_id", "issuer", "grant", "causes")

    def __init__(self, content_id, issuer, grant, causes):
        self.content_id = bytes(content_id)
        self.issuer = issuer
        self.grant = grant
        self.causes = [bytes(c) for c in causes]


def verify_grant_object(profile, alg, pubkey, signed_obj):
    """Verify a signed DelegationGrant end-to-end with real crypto (envelope.verify against the
    composed validator), confirm it is a tier-1 Capability DelegationGrant whose own effect is
    non_idempotent_write, bind the claimed issuer id to the verifying key (a self-asserted issuer
    that does not derive from the authenticated key confers nothing, R-DEL-3), and parse the grant
    body. Any failure is an unverifiable link (ChainBroken / SignerMismatch / the envelope's named
    error), fail-closed."""
    o = envelope.verify(profile, alg, pubkey, composed_kind_validator, signed_obj)
    if o.channel != CHANNEL_CAPABILITY or o.kind != KIND_DELEGATION_GRANT or o.tier != TIER:
        raise DelegationError("ChainBroken", "not a tier-1 Capability DelegationGrant")
    if o.effect != GRANT_EFFECT:
        raise DelegationError("ChainBroken", "a DelegationGrant's own effect must be non_idempotent_write")
    issuer = identity.signer_id(alg, pubkey)
    if o.signer != issuer.encode():           # the envelope signer field MUST be the authenticated id
        raise DelegationError("SignerMismatch", "issuer id does not derive from the verifying key")
    g = grant_from_body(o.body)
    return Resolved(o.id, issuer, g, o.causes)


class GrantSet(dict):
    """Verified grants indexed by their envelope content id (as bytes keys), so the chain walk can
    resolve a parent named in `causes`."""


def new_grant_set(*grants):
    """Build a GrantSet from verified grants, keyed by envelope content id."""
    s = GrantSet()
    for g in grants:
        s[bytes(g.content_id)] = g
    return s


def revoked_at(revocations, cid, now):
    """Whether the grant named by content id `cid` is revoked as of `now` (a revoke ordered at or
    before `now`)."""
    p = revocations.get(bytes(cid))
    return p is not None and p <= now


class Action:
    """The verified action whose delegated authority is being checked. It carries the acting agent
    (the verified signer of the action object), the action's own effect and resource scope (the
    running child at the leaf hop), and the action's `causes` (from which the leaf grant is located)."""

    __slots__ = ("signer", "effect", "scope", "causes")

    def __init__(self, signer, effect, scope, causes):
        self.signer = signer
        self.effect = int(effect)
        self.scope = scope
        self.causes = [bytes(c) for c in causes]


# ---- D2 scope containment (design §18.1) -----------------------------------------------------

def scope_contained(child, parent):
    """Whether `child` is contained in `parent` under the D2 path-prefix rule: an absent parent
    scope ("") is unconstrained; otherwise the child must equal the parent or begin with parent + "/".
    A missing child scope ("") under a scoped parent WIDENS authority and is NOT contained."""
    if parent == "":
        return True                    # unconstrained parent
    if child == "":
        return False                   # missing child scope under a scoped parent widens authority
    if child == parent:
        return True
    return child.startswith(parent + "/")


def _matching_causes(causes, subject, grants):
    """The distinct verified grants named in `causes` whose subject equals `subject` (the parent/leaf
    resolution predicate). Duplicate content ids are counted once."""
    seen = set()
    out = []
    for c in causes:
        key = bytes(c)
        if key in seen:
            continue
        r = grants.get(key)
        if r is not None and r.grant.subject == subject:
            seen.add(key)
            out.append(r)
    return out


# ---- D3 chain verification (design §18.2) ----------------------------------------------------

def verify_chain(action, grants, anchors, revoked, now):
    """The 12-step leaf->root delegation-chain walk, fail-closed with no partial credit. `grants` are
    the verified grants; `anchors` is the trust-anchor issuer-id set; `revoked` maps a revoked grant's
    content id to its revoke position; `now` is the action's authoritative ordering position. Returns
    None iff the chain terminates at a trusted root with every hop holding; otherwise raises the
    specific named error and authorizes nothing."""
    # step 2 -- locate the unique leaf grant among the action's causes whose subject == the actor.
    leaves = _matching_causes(action.causes, action.signer, grants)
    if len(leaves) == 0:
        raise DelegationError("EffectNotAuthorized", "no delegation authorizes this action")
    if len(leaves) > 1:
        raise DelegationError("ChainBroken", "more than one authorizing grant is ambiguous")
    g = leaves[0]
    child_effect = action.effect
    child_scope = action.scope
    pos = 0                            # realized delegation hops beneath the current grant
    visited = set()

    while True:
        key = bytes(g.content_id)
        if key in visited:             # a content-id cycle (infeasible for a real hash chain)
            raise DelegationError("ChainBroken", "content-id cycle in the delegation chain")
        visited.add(key)

        # step 4 -- validity window at `now`.
        if now < g.grant.not_before:
            raise DelegationError("GrantNotYetValid", "grant is before its not_before at this position")
        if now > g.grant.not_after:
            raise DelegationError("GrantExpired", "grant is past its not_after at this position")
        # step 5 -- revocation at `now`.
        if revoked_at(revoked, g.content_id, now):
            raise DelegationError("GrantRevoked", "grant is revoked at or before this position")
        # step 6 -- attenuation (CapExceedsParent): effect ceiling AND scope containment.
        if not policy.authorizes(g.grant.effect_cap, child_effect):
            raise DelegationError("CapExceedsParent", "child effect exceeds this grant's effect_cap")
        if not scope_contained(child_scope, g.grant.scope):
            raise DelegationError("CapExceedsParent", "child scope is not contained in this grant's scope")
        # step 9 -- realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
        if pos > g.grant.max_depth:
            raise DelegationError("DelegationDepthExceeded", "realized delegation depth exceeds max_depth")
        # step 7 -- resolve g's delegation parent (the unique cause whose subject == g's issuer).
        parents = _matching_causes(g.causes, g.issuer, grants)
        if len(parents) > 1:
            raise DelegationError("ChainBroken", "ambiguous delegation parent")
        if len(parents) == 0:
            # steps 10 / 11 -- root test: g has no delegation parent.
            if g.issuer in anchors:
                return None            # terminated at a trusted root: authorized
            raise DelegationError("UntrustedChainRoot", "the chain root's issuer is not a trust anchor")
        p = parents[0]
        # step 8 -- declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned underflow;
        # a parent with max_depth 0 admits no child grant).
        if p.grant.max_depth == 0 or g.grant.max_depth >= p.grant.max_depth:
            raise DelegationError("DelegationDepthExceeded", "declared delegation depth exceeds parent")
        child_effect = g.grant.effect_cap
        child_scope = g.grant.scope
        g = p
        pos += 1


# ---- D4 composition with per-action approval (design §18.3, R-DEL-8) ---------------------------

def authorize_destructive(action, grants, anchors, revoked, now,
                          appr, approver_alg, approver_pubkey, appr_sig, args_content_id, ledger):
    """The D4 two-gate composition: a destructive-effect action requires BOTH a valid delegation
    chain (D3) terminating at a trusted root AND a valid, unconsumed, exact-bytes §7 approval whose
    granted effect covers the action, CONSUMED single-use by the acting agent (accountability binds
    to it). Precedence: the chain is checked first, so a broken chain denies with its D3 error even
    when an approval is present; a valid chain with no valid approval denies ApprovalRequired; a
    valid-but-already-consumed approval denies AlreadyConsumed. The approval is CONSUMED (the single
    state change) only when both gates hold; a rejected action makes no ledger append. Returns None on
    authorization."""
    from . import approval
    # Gate 1 -- the delegation chain (D3). A broken chain denies with its named D3 error.
    verify_chain(action, grants, anchors, revoked, now)
    # Gate 2 -- a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
    try:
        approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, args_content_id, now)
    except approval.ApprovalError:
        raise DelegationError("ApprovalRequired", "no valid approval on a destructive action (held §7.3)")
    if not policy.authorizes(appr.grant, action.effect):
        raise DelegationError("ApprovalRequired", "the approval's granted effect does not cover the action")
    # Consume single-use. The ledger's named error (AlreadyConsumed) is surfaced uniformly as a
    # DelegationError so the composition's whole deny contract is one error type (as the Go reference,
    # where every return is one *cose.Error). Fail-closed: a spent approval is not fresh authority.
    try:
        ledger.consume(appr.id(), action.signer)
    except approval.ApprovalError as e:
        raise DelegationError(e.kind, str(e))
    return None
