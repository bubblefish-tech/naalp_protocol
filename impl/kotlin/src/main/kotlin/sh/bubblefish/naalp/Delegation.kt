// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

//
// C15 multi-hop agent delegation for the Kotlin SDK (design.md §18; R-DEL-1..8), a Phase-3 draft-01
// ADDITIVE tier-1 surface over the frozen spine.
//
// Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
// terminates at a trust anchor. A DelegationGrant is a normal N-AALP envelope object (a tier-1
// Capability surface, kind 4); it introduces NO new envelope, encoding, signature, identity, or audit
// mechanism (R-11.3). Its body carries exactly what agent-delegation adds over a single-hop
// capability: the delegatee `subject`, the `effectCap` ceiling it confers, the `maxDepth`
// onward-delegation bound, and the validity window (plus an optional `scope`). The ISSUER is NOT a
// body field — it is the verified envelope signer (R-DEL-3); the delegation PARENT is named by
// content id in the envelope `causes` (§8.2).
//
// The two graded surfaces: the DelegationGrant wire body (byte-graded == oracle), and the 12-step
// leaf->root chain verifier (verdict-graded == oracle). Every check is fail-closed (§15): an action
// that fails any step is rejected whole, returns its named error, and causes no state change. Ported
// from impl/go/delegation (cross-read against impl/python/naalp/delegation.py); graded against
// vectors/delegation/cases.json. The D4 composition (authorizeDestructive) reuses the Approval
// module's single-use consume ledger for the per-action approval gate — a real wiring, not a stub.
//
object Delegation {

    // Channel binding, the tier-1 kind code, and the tier for agent-delegation (design §18.1).
    const val CHANNEL_CAPABILITY = 0x0002L // Capability channel (reuses the CapDelegate substrate)
    const val KIND_DELEGATION_GRANT = 4L   // tier-1 kind code (next free after CapIssue/Delegate/Revoke/Lookup)
    const val TIER = 1L                    // a named escalation adding multi-hop capability

    // A grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write. This is
    // separate from the body's effectCap, which is the ceiling the grant CONFERS on its subject.
    const val GRANT_EFFECT = Policy.NON_IDEMPOTENT_WRITE

    // ---- the DelegationGrant object body (design §18.1, §18.5) ----

    // The signed body of a DelegationGrant. `subject` is the delegatee agent id (signer-id form, MUST
    // be NFC); `effectCap` the max effect this grant conveys; `maxDepth` the max FURTHER delegation
    // hops below it; `notBefore`/`notAfter` the validity window; `scope` an OPTIONAL NFC resource scope
    // ("" = absent/unconstrained, field 6 omitted).
    class Grant(
        val subject: String,
        val effectCap: Long,
        val maxDepth: Long,
        val notBefore: Long,
        val notAfter: Long,
        val scope: String = "",
    ) {
        // The body map {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}. Encode
        // emits canonical key order, so the append order here is irrelevant to the bytes.
        fun toMap(): Cbor.M {
            val pairs = ArrayList<Cbor.Pair>(6)
            pairs.add(Cbor.Pair(Cbor.U(1), Cbor.T(subject)))
            pairs.add(Cbor.Pair(Cbor.U(2), Cbor.U(effectCap)))
            pairs.add(Cbor.Pair(Cbor.U(3), Cbor.U(maxDepth)))
            pairs.add(Cbor.Pair(Cbor.U(4), Cbor.U(notBefore)))
            pairs.add(Cbor.Pair(Cbor.U(5), Cbor.U(notAfter)))
            if (scope != "") { // "" == absent (field 6 omitted); an empty scope is not a distinct value
                pairs.add(Cbor.Pair(Cbor.U(6), Cbor.T(scope)))
            }
            return Cbor.M(pairs)
        }

        // Deterministic-CBOR encoding of the grant body.
        fun bytes(): ByteArray = Cbor.encode(toMap())

        // The grant body's content id: multihash(0x20, SHA-384(body)). The body's self-address; the
        // ENVELOPE content id (from Envelope.sign) is what a delegation chain wires into `causes`.
        fun contentId(): ByteArray = Cbor.contentId(bytes())

        // Build the (unsigned) N-AALP envelope object carrying this grant: tier 1, Capability channel,
        // kind DelegationGrant, the grant's own effect non_idempotent_write, the grant body as the
        // object body, and `causes` naming the delegation parent by content id (empty for a root
        // grant). The caller signs it; the signer BECOMES the grant's issuer (R-DEL-3). A non-NFC
        // subject/scope or an out-of-range effectCap is rejected fail-closed.
        fun envelopeObject(issuer: ByteArray, created: Long, profile: Long, causes: List<ByteArray>): Envelope.Object {
            Identity.requireNfc(subject) // throws NonNFC
            if (scope != "") Identity.requireNfc(scope)
            if (effectCap > Policy.DESTRUCTIVE) {
                throw NaalpException("GrantMalformed", "effect_cap outside the closed lattice")
            }
            return Envelope.Object(
                kind = KIND_DELEGATION_GRANT,
                channel = CHANNEL_CAPABILITY,
                signer = issuer,
                created = created,
                effect = GRANT_EFFECT,
                body = toMap(),
                tier = TIER,
                profile = profile,
                causes = causes,
            )
        }
    }

    // Parse an envelope object body back into a Grant. A body that is not exactly the {1,2,3,4,5,?6}
    // map with the right value types and an in-range effectCap is an unverifiable/malformed grant link
    // and is rejected ChainBroken (fail-closed). An out-of-range effectCap is NEVER normalized up
    // (that would widen a ceiling — fail-open); it is rejected.
    fun grantFromBody(v: Cbor.Value): Grant {
        if (v !is Cbor.M) throw NaalpException("ChainBroken", "grant body is not a map")
        var subject = ""
        var effectCap = 0L
        var maxDepth = 0L
        var notBefore = 0L
        var notAfter = 0L
        var scope = ""
        val seen = BooleanArray(7)
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U || k.v < 1 || k.v > 6) throw NaalpException("ChainBroken", "grant body has an out-of-range field")
            when (k.v) {
                1L -> { val t = p.v; if (t !is Cbor.T) throw NaalpException("ChainBroken", "subject is not a tstr"); subject = t.v }
                2L -> { val u = p.v; if (u !is Cbor.U || u.v > Policy.DESTRUCTIVE) throw NaalpException("ChainBroken", "effect_cap absent or out of range"); effectCap = u.v }
                3L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("ChainBroken", "max_depth is not a uint"); maxDepth = u.v }
                4L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("ChainBroken", "not_before is not a uint"); notBefore = u.v }
                5L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("ChainBroken", "not_after is not a uint"); notAfter = u.v }
                6L -> { val t = p.v; if (t !is Cbor.T) throw NaalpException("ChainBroken", "scope is not a tstr"); scope = t.v }
            }
            seen[k.v.toInt()] = true
        }
        if (!(seen[1] && seen[2] && seen[3] && seen[4] && seen[5])) { // scope (6) is optional
            throw NaalpException("ChainBroken", "grant body is missing a mandatory field")
        }
        return Grant(subject, effectCap, maxDepth, notBefore, notAfter, scope)
    }

    // ---- kind validation (composes with the frozen baseline) ----

    // Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant).
    fun kindValidator(channel: Long, kind: Long): Boolean = channel == CHANNEL_CAPABILITY && kind == KIND_DELEGATION_GRANT

    private fun baselineKindValidator(channel: Long, kind: Long): Boolean = try {
        Channels.lookup(channel, kind); true
    } catch (e: NaalpException) {
        false
    }

    // Accepts the frozen baseline kinds OR the tier-1 DelegationGrant — the validator a
    // delegation-aware endpoint passes to Envelope.verify. A baseline-only endpoint correctly rejects
    // a DelegationGrant as UnknownKind (fail-closed).
    fun composedKindValidator(channel: Long, kind: Long): Boolean =
        baselineKindValidator(channel, kind) || kindValidator(channel, kind)

    // ---- verified grants + the trust/revocation inputs ----

    // A DelegationGrant that has passed envelope verification and integrity binding: its ENVELOPE
    // content id (what `causes` point to), its verified issuer id (the envelope signer — NOT a body
    // field, R-DEL-3), the parsed grant body, and the grant's own `causes`.
    class Resolved(contentId: ByteArray, val issuer: String, val grant: Grant, causes: List<ByteArray>) {
        val contentId: ByteArray = contentId.copyOf()
        val causes: List<ByteArray> = causes.map { it.copyOf() }
    }

    // Verify a signed DelegationGrant end-to-end with real crypto (Envelope.verify against the
    // composed validator), confirm it is a tier-1 Capability DelegationGrant whose own effect is
    // non_idempotent_write, bind the claimed issuer id to the verifying key (a self-asserted issuer
    // that does not derive from the authenticated key confers nothing, R-DEL-3), and parse the grant
    // body. Any failure is an unverifiable link (ChainBroken / SignerMismatch / the envelope's named
    // error), fail-closed.
    fun verifyGrantObject(profile: Int, alg: Int, pubkey: ByteArray, signedObj: ByteArray): Resolved {
        val o = Envelope.verify(profile.toLong(), alg, pubkey, Envelope.KindValidator { ch, k -> composedKindValidator(ch, k) }, signedObj)
        if (o.channel != CHANNEL_CAPABILITY || o.kind != KIND_DELEGATION_GRANT || o.tier != TIER) {
            throw NaalpException("ChainBroken", "not a tier-1 Capability DelegationGrant")
        }
        if (o.effect != GRANT_EFFECT) {
            throw NaalpException("ChainBroken", "a DelegationGrant's own effect must be non_idempotent_write")
        }
        val issuer = Identity.signerId(alg, pubkey)
        if (String(o.signer, Charsets.UTF_8) != issuer) { // the envelope signer field MUST be the authenticated id
            throw NaalpException("SignerMismatch", "issuer id does not derive from the verifying key")
        }
        val g = grantFromBody(o.body)
        val cid = o.id ?: throw NaalpException("ChainBroken", "verified object has no content id")
        return Resolved(cid, issuer, g, o.causes)
    }

    // Verified grants indexed by their envelope content id (lowercase-hex key), so the chain walk can
    // resolve a parent named in `causes`.
    fun newGrantSet(grants: List<Resolved>): Map<String, Resolved> {
        val s = HashMap<String, Resolved>(grants.size)
        for (g in grants) s[Hex.encode(g.contentId)] = g
        return s
    }

    // Whether the grant named by content id `cid` is revoked as of `now` (a revoke ordered at or
    // before `now`). `revoked` maps a revoked grant's content id (hex) to its revoke position.
    fun revokedAt(revoked: Map<String, Long>, cid: ByteArray, now: Long): Boolean {
        val p = revoked[Hex.encode(cid)]
        return p != null && p <= now
    }

    // The verified action whose delegated authority is being checked. It carries the acting agent (the
    // verified signer of the action object), the action's own effect and resource scope (the running
    // child at the leaf hop), and the action's `causes` (from which the leaf grant is located).
    class Action(val signer: String, val effect: Long, val scope: String, causes: List<ByteArray>) {
        val causes: List<ByteArray> = causes.map { it.copyOf() }
    }

    // ---- D2 scope containment (design §18.1) ----

    // Whether `child` is contained in `parent` under the D2 path-prefix rule: an absent parent scope
    // ("") is unconstrained; otherwise the child must equal the parent or begin with parent + "/". A
    // missing child scope ("") under a scoped parent WIDENS authority and is NOT contained.
    fun scopeContained(child: String, parent: String): Boolean {
        if (parent == "") return true // unconstrained parent
        if (child == "") return false // missing child scope under a scoped parent widens authority
        if (child == parent) return true
        return child.startsWith("$parent/")
    }

    // The distinct verified grants named in `causes` whose subject equals `subject` (the parent/leaf
    // resolution predicate). Duplicate content ids are counted once.
    private fun matchingCauses(causes: List<ByteArray>, subject: String, grants: Map<String, Resolved>): List<Resolved> {
        val seen = HashSet<String>(causes.size)
        val out = ArrayList<Resolved>()
        for (c in causes) {
            val key = Hex.encode(c)
            if (key in seen) continue
            val r = grants[key]
            if (r != null && r.grant.subject == subject) {
                seen.add(key)
                out.add(r)
            }
        }
        return out
    }

    // ---- D3 chain verification (design §18.2) ----

    // The 12-step leaf->root delegation-chain walk, fail-closed with no partial credit. `grants` are
    // the verified grants; `anchors` is the trust-anchor issuer-id set; `revoked` maps a revoked
    // grant's content id (hex) to its revoke position; `now` is the action's authoritative ordering
    // position. Returns normally iff the chain terminates at a trusted root with every hop holding;
    // otherwise throws the specific named error and authorizes nothing.
    fun verifyChain(action: Action, grants: Map<String, Resolved>, anchors: Set<String>, revoked: Map<String, Long>, now: Long) {
        // step 2 — locate the unique leaf grant among the action's causes whose subject == the actor.
        val leaves = matchingCauses(action.causes, action.signer, grants)
        when (leaves.size) {
            0 -> throw NaalpException("EffectNotAuthorized", "no delegation authorizes this action")
            1 -> {} // the unique leaf
            else -> throw NaalpException("ChainBroken", "more than one authorizing grant is ambiguous")
        }
        var g = leaves[0]
        var childEffect = action.effect
        var childScope = action.scope
        var pos = 0L // realized delegation hops beneath the current grant
        val visited = HashSet<String>()

        while (true) {
            val key = Hex.encode(g.contentId)
            if (key in visited) throw NaalpException("ChainBroken", "content-id cycle in the delegation chain")
            visited.add(key)

            // step 4 — validity window at `now`.
            if (now < g.grant.notBefore) throw NaalpException("GrantNotYetValid", "grant is before its not_before at this position")
            if (now > g.grant.notAfter) throw NaalpException("GrantExpired", "grant is past its not_after at this position")
            // step 5 — revocation at `now`.
            if (revokedAt(revoked, g.contentId, now)) throw NaalpException("GrantRevoked", "grant is revoked at or before this position")
            // step 6 — attenuation (CapExceedsParent): effect ceiling AND scope containment.
            if (!Policy.authorizes(g.grant.effectCap, childEffect)) throw NaalpException("CapExceedsParent", "child effect exceeds this grant's effect_cap")
            if (!scopeContained(childScope, g.grant.scope)) throw NaalpException("CapExceedsParent", "child scope is not contained in this grant's scope")
            // step 9 — realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
            if (pos > g.grant.maxDepth) throw NaalpException("DelegationDepthExceeded", "realized delegation depth exceeds max_depth")
            // step 7 — resolve g's delegation parent (the unique cause whose subject == g's issuer).
            val parents = matchingCauses(g.causes, g.issuer, grants)
            if (parents.size > 1) throw NaalpException("ChainBroken", "ambiguous delegation parent")
            if (parents.isEmpty()) {
                // steps 10 / 11 — root test: g has no delegation parent.
                if (anchors.contains(g.issuer)) return // terminated at a trusted root: authorized
                throw NaalpException("UntrustedChainRoot", "the chain root's issuer is not a trust anchor")
            }
            val p = parents[0]
            // step 8 — declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned
            // underflow; a parent with max_depth 0 admits no child grant).
            if (p.grant.maxDepth == 0L || g.grant.maxDepth >= p.grant.maxDepth) {
                throw NaalpException("DelegationDepthExceeded", "declared delegation depth exceeds parent")
            }
            childEffect = g.grant.effectCap
            childScope = g.grant.scope
            g = p
            pos++
        }
    }

    // ---- D4 composition with per-action approval (design §18.3, R-DEL-8) ----

    // The D4 two-gate composition: a destructive-effect action requires BOTH a valid delegation chain
    // (D3) terminating at a trusted root AND a valid, unconsumed, exact-bytes §7 approval whose granted
    // effect covers the action, CONSUMED single-use by the acting agent. Precedence: the chain is
    // checked first, so a broken chain denies with its D3 error even when an approval is present; a
    // valid chain with no valid approval denies ApprovalRequired; a valid-but-already-consumed approval
    // denies AlreadyConsumed. The approval is CONSUMED (the single state change) only when both gates
    // hold; a rejected action makes no ledger append. Returns normally on authorization.
    fun authorizeDestructive(
        action: Action,
        grants: Map<String, Resolved>,
        anchors: Set<String>,
        revoked: Map<String, Long>,
        now: Long,
        appr: Approval.ApprovalRecord,
        approverAlg: Int,
        approverPubkey: ByteArray,
        apprSig: ByteArray,
        argsContentId: ByteArray,
        ledger: Approval.Ledger,
    ) {
        // Gate 1 — the delegation chain (D3). A broken chain denies with its named D3 error.
        verifyChain(action, grants, anchors, revoked, now)
        // Gate 2 — a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
        try {
            Approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, argsContentId, now)
        } catch (e: NaalpException) {
            throw NaalpException("ApprovalRequired", "no valid approval on a destructive action (held §7.3)")
        }
        if (!Policy.authorizes(appr.grant, action.effect)) {
            throw NaalpException("ApprovalRequired", "the approval's granted effect does not cover the action")
        }
        // Consume single-use. Fail-closed: a spent approval is not fresh authority (AlreadyConsumed).
        ledger.consume(appr.id(), action.signer)
    }
}
