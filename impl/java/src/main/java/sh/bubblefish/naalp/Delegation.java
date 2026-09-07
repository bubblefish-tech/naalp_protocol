// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * N-AALP C15 multi-hop AGENT delegation for the Java SDK (design.md §18; R-DEL-1..8), a Phase-3
 * draft-01 ADDITIVE tier-1 surface over the frozen spine.
 *
 * <p>Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
 * terminates at a trust anchor. A DelegationGrant is a normal N-AALP object (a tier-1 Capability
 * surface, kind 4); it introduces NO new envelope, encoding, signature, identity, or audit mechanism
 * (R-11.3) — the mechanism REUSES the -00 CapDelegate substrate (parent-by-content-id in {@code
 * causes} and the {@code CapExceedsParent} attenuation). The only additions over CapDelegate are the
 * body's {@code subject}, {@code max_depth}, and validity window.
 *
 * <p>The two graded surfaces: the DelegationGrant wire body ({@link Grant#bytes}/{@link Grant#contentId},
 * byte-graded == oracle) and the 12-step leaf→root chain verifier ({@link #verifyChain}, verdict-graded
 * == oracle). Every check is fail-closed (§15): an action that fails any step is rejected whole, returns
 * its named error, and causes no state change. An independent transcription of impl/go/delegation
 * (cross-checked against impl/python/naalp/delegation); graded against vectors/delegation/cases.json.
 *
 * <p>ALSO PORTED (STEP-2 ten-port parity wave): the envelope-integration layer performing D3 step 3 —
 * {@link Grant#envelopeObject} builds the (unsigned) N-AALP envelope object carrying a grant;
 * {@link #verifyGrantObject} verifies a signed grant end-to-end with real crypto ({@link Envelope#verify}
 * against the composed validator), confirms it is a tier-1 Capability DelegationGrant, and binds the
 * claimed issuer id to the verifying key (R-DEL-3/R-5.1 — a self-asserted issuer that does not derive
 * from the authenticated key confers nothing, SignerMismatch); {@link #composedKindValidator} accepts
 * the frozen baseline kinds OR the tier-1 DelegationGrant, the validator a delegation-aware endpoint
 * passes to {@link Envelope#verify}. These are NOT graded by vectors/delegation/cases.json, whose
 * scenarios are abstract issuer/subject chains (the D3 verdict logic below IS graded against it); the
 * envelope-integration layer is demonstrated in isolation over real ML-DSA-65 signed objects, using the
 * SAME grant field values the corpus grades (so the round-tripped grant body/content-id still reproduces
 * the oracle). The corpus-graded D3 verdict logic (this file) and the D4 approval composition
 * ({@link #authorizeDestructive}) are fully ported.
 */
public final class Delegation {
    /** Capability channel (reuses the CapDelegate substrate). */
    public static final long CHANNEL_CAPABILITY = 0x0002;
    /** The tier-1 kind code, the next free code after CapIssue/Delegate/Revoke/Lookup (0..3). */
    public static final long KIND_DELEGATION_GRANT = 4;
    /** A named escalation adding multi-hop capability (R-15A.2). */
    public static final long TIER = 1;
    /** A grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write. */
    public static final long GRANT_EFFECT = Policy.NON_IDEMPOTENT_WRITE;

    private Delegation() {}

    // ---- the DelegationGrant object body (design §18.1, §18.5) ------------------------------------

    /** The signed body of a DelegationGrant. {@code subject} is the delegatee agent id (signer-id form,
     * MUST be NFC); {@code effectCap} is the max effect this grant conveys; {@code maxDepth} the max
     * FURTHER delegation hops below it; {@code notBefore}/{@code notAfter} the validity window; {@code
     * scope} an OPTIONAL NFC resource scope ("" = absent/unconstrained, field 6 omitted). */
    public static final class Grant {
        public final String subject;
        public final long effectCap;
        public final long maxDepth;
        public final long notBefore;
        public final long notAfter;
        public final String scope;

        public Grant(String subject, long effectCap, long maxDepth, long notBefore, long notAfter, String scope) {
            this.subject = subject;
            this.effectCap = effectCap;
            this.maxDepth = maxDepth;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.scope = scope;
        }

        private Cbor.M toMap() {
            List<Cbor.Pair> pairs = new ArrayList<>(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(subject)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(effectCap)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(maxDepth)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(notBefore)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(notAfter))));
            if (!scope.isEmpty()) { // "" == absent (field 6 omitted); an empty scope is not a distinct value
                pairs.add(new Cbor.Pair(new Cbor.U(6), new Cbor.T(scope)));
            }
            return new Cbor.M(pairs);
        }

        /** Deterministic-CBOR encoding {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}. */
        public byte[] bytes() {
            return Cbor.encode(toMap());
        }

        /** The grant body's content id: multihash(0x20, SHA-384(body)). */
        public byte[] contentId() {
            return Cbor.contentId(bytes());
        }

        /** Builds the (unsigned) N-AALP envelope object that carries this grant: tier 1, Capability
         * channel, kind DelegationGrant, the grant's own effect non_idempotent_write, the grant body as
         * field 10, and {@code causes} naming the delegation parent by content id (empty for a root
         * grant). The caller signs it with {@link Envelope#sign}; the signer BECOMES the grant's issuer
         * (R-DEL-3). A non-NFC subject/scope is rejected NonNFC ({@link Identity#requireNfc}); an
         * effect_cap outside the closed lattice is rejected GrantMalformed. */
        public Envelope.Object envelopeObject(byte[] issuer, long created, long profile, List<byte[]> causes) {
            Identity.requireNfc(subject);
            if (!scope.isEmpty()) {
                Identity.requireNfc(scope);
            }
            if (effectCap > Policy.DESTRUCTIVE) {
                throw new NaalpException("GrantMalformed",
                        "delegation-grant body has an effect_cap outside the closed lattice");
            }
            return new Envelope.Object(KIND_DELEGATION_GRANT, CHANNEL_CAPABILITY, TIER, issuer, created,
                    GRANT_EFFECT, profile, toMap(), causes, null, null);
        }
    }

    /** Parse an envelope object body back into a Grant. A body that is not exactly the {1,2,3,4,5,?6}
     * map with the right value types and an in-range effect_cap is an unverifiable/malformed grant link
     * and is rejected ChainBroken (fail-closed). An out-of-range effect_cap is NEVER normalized up
     * (that would widen a ceiling — fail-open); it is rejected. */
    public static Grant grantFromBody(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw chainBroken("grant body is not a map");
        }
        String subject = null;
        Long effectCap = null;
        Long maxDepth = null;
        Long notBefore = null;
        Long notAfter = null;
        String scope = "";
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku) || ku.v < 1 || ku.v > 6) {
                throw chainBroken("grant body has an out-of-range field");
            }
            long k = ku.v;
            if (k == 1) {
                if (!(p.val instanceof Cbor.T t)) {
                    throw chainBroken("subject is not a tstr");
                }
                subject = t.v;
            } else if (k == 2) {
                if (!(p.val instanceof Cbor.U u) || u.v > Policy.DESTRUCTIVE || u.v < 0) {
                    throw chainBroken("effect_cap absent or out of range");
                }
                effectCap = u.v;
            } else if (k == 3) {
                if (!(p.val instanceof Cbor.U u)) {
                    throw chainBroken("max_depth is not a uint");
                }
                maxDepth = u.v;
            } else if (k == 4) {
                if (!(p.val instanceof Cbor.U u)) {
                    throw chainBroken("not_before is not a uint");
                }
                notBefore = u.v;
            } else if (k == 5) {
                if (!(p.val instanceof Cbor.U u)) {
                    throw chainBroken("not_after is not a uint");
                }
                notAfter = u.v;
            } else { // k == 6
                if (!(p.val instanceof Cbor.T t)) {
                    throw chainBroken("scope is not a tstr");
                }
                scope = t.v;
            }
        }
        if (subject == null || effectCap == null || maxDepth == null || notBefore == null || notAfter == null) {
            throw chainBroken("grant body is missing a mandatory field");
        }
        return new Grant(subject, effectCap, maxDepth, notBefore, notAfter, scope);
    }

    // ---- kind validation (composes with the frozen baseline) -------------------------------------

    /** Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant). */
    public static boolean kindValidator(long channel, long kind) {
        return channel == CHANNEL_CAPABILITY && kind == KIND_DELEGATION_GRANT;
    }

    private static boolean baselineKindValidator(long channel, long kind) {
        try {
            Channels.lookup(channel, kind);
            return true;
        } catch (NaalpException e) {
            return false;
        }
    }

    /** Accepts the frozen baseline kinds OR the tier-1 DelegationGrant — the validator a
     * delegation-aware endpoint passes to {@link Envelope#verify}. It leaves the frozen registry
     * untouched (R-11.1); a baseline-only endpoint using the baseline validator alone correctly rejects
     * a DelegationGrant as UnknownKind (fail-closed), exactly as the tier model requires. */
    public static boolean composedKindValidator(long channel, long kind) {
        return baselineKindValidator(channel, kind) || kindValidator(channel, kind);
    }

    // ---- verified grants + the trust/revocation inputs -------------------------------------------

    /** A DelegationGrant that has passed envelope verification and integrity binding: its ENVELOPE
     * content id (what {@code causes} point to), its verified issuer id (the envelope signer — NOT a
     * body field, R-DEL-3), the parsed grant body, and the grant's own {@code causes}. */
    public static final class Resolved {
        public final byte[] contentID;
        public final String issuer;
        public final Grant grant;
        public final List<byte[]> causes;

        public Resolved(byte[] contentID, String issuer, Grant grant, List<byte[]> causes) {
            this.contentID = contentID.clone();
            this.issuer = issuer;
            this.grant = grant;
            this.causes = new ArrayList<>();
            for (byte[] c : causes) {
                this.causes.add(c.clone());
            }
        }
    }

    /** Performs D3 step 3 for one grant: verifies the signed object end-to-end with real crypto
     * ({@link Envelope#verify} against the {@link #composedKindValidator}), confirms it is a tier-1
     * Capability DelegationGrant whose own effect is non_idempotent_write, binds the claimed issuer id
     * to the verifying key ({@link Identity#signerId} — a self-asserted issuer that does not derive from
     * the authenticated key confers nothing, R-DEL-3/R-5.1), and parses the grant body. Any failure is an
     * unverifiable link (ChainBroken / SignerMismatch / the envelope's named error), fail-closed. */
    public static Resolved verifyGrantObject(int profile, int alg, byte[] pubkey, byte[] signedObj) {
        Envelope.Object o = Envelope.verify(profile, alg, pubkey, Delegation::composedKindValidator, signedObj, null);
        if (o.channel != CHANNEL_CAPABILITY || o.kind != KIND_DELEGATION_GRANT || o.tier != TIER) {
            throw chainBroken("not a tier-1 Capability DelegationGrant");
        }
        if (o.effect != GRANT_EFFECT) { // a DelegationGrant's own effect is non_idempotent_write
            throw chainBroken("a DelegationGrant's own effect must be non_idempotent_write");
        }
        String issuer = Identity.signerId(alg, pubkey);
        String claimedSigner = new String(o.signer, StandardCharsets.UTF_8);
        if (!claimedSigner.equals(issuer)) { // the envelope signer field MUST be the authenticated id
            throw new NaalpException("SignerMismatch", "the envelope signer field must be the authenticated id");
        }
        Grant g = grantFromBody(o.body);
        return new Resolved(o.id, issuer, g, o.causes);
    }

    /** The verified action whose delegated authority is being checked. It carries the acting agent (the
     * verified signer of the action object), the action's own effect and resource scope (the running
     * child at the leaf hop), and the action's {@code causes} (from which the leaf grant is located). */
    public static final class Action {
        public final String signer;
        public final long effect;
        public final String scope;
        public final List<byte[]> causes;

        public Action(String signer, long effect, String scope, List<byte[]> causes) {
            this.signer = signer;
            this.effect = effect;
            this.scope = scope;
            this.causes = new ArrayList<>();
            for (byte[] c : causes) {
                this.causes.add(c.clone());
            }
        }
    }

    /** Whether the grant named by content id {@code cid} is revoked as of {@code now} (a revoke ordered
     * at or before {@code now}). {@code revoked} maps a grant's content-id hex to its revoke position. */
    public static boolean revokedAt(Map<String, Long> revoked, byte[] cid, long now) {
        Long p = revoked.get(Hex.encode(cid));
        return p != null && p <= now;
    }

    // ---- named, fail-closed errors (design §18.6) ------------------------------------------------

    private static NaalpException chainBroken(String why) {
        return new NaalpException("ChainBroken", why);
    }

    private static NaalpException capExceedsParent(String why) {
        return new NaalpException("CapExceedsParent", why);
    }

    // ---- D2 scope containment (design §18.1) ------------------------------------------------------

    /** Whether {@code child} is contained in {@code parent} under the D2 path-prefix rule: an absent
     * parent scope ("") is unconstrained; otherwise the child must equal the parent or begin with
     * parent + "/". A missing child scope ("") under a scoped parent WIDENS authority and is NOT
     * contained. */
    public static boolean scopeContained(String child, String parent) {
        if (parent.isEmpty()) {
            return true; // unconstrained parent
        }
        if (child.isEmpty()) {
            return false; // missing child scope under a scoped parent widens authority
        }
        if (child.equals(parent)) {
            return true;
        }
        return child.startsWith(parent + "/");
    }

    /** The distinct verified grants named in {@code causes} whose subject equals {@code subject} (the
     * parent/leaf resolution predicate). Duplicate content ids are counted once. */
    private static List<Resolved> matchingCauses(List<byte[]> causes, String subject, Map<String, Resolved> grants) {
        Set<String> seen = new HashSet<>();
        List<Resolved> out = new ArrayList<>();
        for (byte[] c : causes) {
            String key = Hex.encode(c);
            if (seen.contains(key)) {
                continue;
            }
            Resolved r = grants.get(key);
            if (r != null && r.grant.subject.equals(subject)) {
                seen.add(key);
                out.add(r);
            }
        }
        return out;
    }

    // ---- D3 chain verification (design §18.2) -----------------------------------------------------

    /** The 12-step leaf→root delegation-chain walk, fail-closed with no partial credit. {@code grants}
     * are the verified grants keyed by content-id hex; {@code anchors} is the trust-anchor issuer-id
     * set; {@code revoked} maps a revoked grant's content-id hex to its revoke position; {@code now} is
     * the action's authoritative ordering position. Returns normally iff the chain terminates at a
     * trusted root with every hop holding; otherwise throws the specific named error and authorizes
     * nothing. */
    public static void verifyChain(Action action, Map<String, Resolved> grants, Set<String> anchors,
                                   Map<String, Long> revoked, long now) {
        // step 2 — locate the unique leaf grant among the action's causes whose subject == the actor.
        List<Resolved> leaves = matchingCauses(action.causes, action.signer, grants);
        if (leaves.isEmpty()) {
            throw new NaalpException("EffectNotAuthorized", "no delegation authorizes this action");
        }
        if (leaves.size() > 1) {
            throw chainBroken("more than one authorizing grant is ambiguous");
        }
        Resolved g = leaves.get(0);
        long childEffect = action.effect;
        String childScope = action.scope;
        long pos = 0; // realized delegation hops beneath the current grant
        Set<String> visited = new HashSet<>();

        while (true) {
            String key = Hex.encode(g.contentID);
            if (!visited.add(key)) { // a content-id cycle (infeasible for a real hash chain)
                throw chainBroken("content-id cycle in the delegation chain");
            }
            // step 4 — validity window at `now`.
            if (now < g.grant.notBefore) {
                throw new NaalpException("GrantNotYetValid", "grant is before its not_before at this position");
            }
            if (now > g.grant.notAfter) {
                throw new NaalpException("GrantExpired", "grant is past its not_after at this position");
            }
            // step 5 — revocation at `now`.
            if (revokedAt(revoked, g.contentID, now)) {
                throw new NaalpException("GrantRevoked", "grant is revoked at or before this position");
            }
            // step 6 — attenuation (CapExceedsParent): effect ceiling AND scope containment.
            if (!Policy.authorizes(g.grant.effectCap, childEffect)) {
                throw capExceedsParent("child effect exceeds this grant's effect_cap");
            }
            if (!scopeContained(childScope, g.grant.scope)) {
                throw capExceedsParent("child scope is not contained in this grant's scope");
            }
            // step 9 — realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
            if (pos > g.grant.maxDepth) {
                throw new NaalpException("DelegationDepthExceeded", "realized delegation depth exceeds max_depth");
            }
            // step 7 — resolve g's delegation parent (the unique cause whose subject == g's issuer).
            List<Resolved> parents = matchingCauses(g.causes, g.issuer, grants);
            if (parents.size() > 1) {
                throw chainBroken("ambiguous delegation parent");
            }
            if (parents.isEmpty()) {
                // steps 10 / 11 — root test: g has no delegation parent.
                if (anchors.contains(g.issuer)) {
                    return; // terminated at a trusted root: authorized
                }
                throw new NaalpException("UntrustedChainRoot", "the chain root's issuer is not a trust anchor");
            }
            Resolved p = parents.get(0);
            // step 8 — declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned underflow;
            // a parent with max_depth 0 admits no child grant).
            if (p.grant.maxDepth == 0 || g.grant.maxDepth >= p.grant.maxDepth) {
                throw new NaalpException("DelegationDepthExceeded", "declared delegation depth exceeds parent");
            }
            childEffect = g.grant.effectCap;
            childScope = g.grant.scope;
            g = p;
            pos++;
        }
    }

    // ---- D4 composition with per-action approval (design §18.3, R-DEL-8) --------------------------

    /** The D4 two-gate composition: a destructive-effect action requires BOTH a valid delegation chain
     * (D3, {@link #verifyChain}) terminating at a trusted root AND a valid, unconsumed, exact-bytes §7
     * approval whose granted effect covers the action, CONSUMED single-use by the acting agent
     * (accountability binds to it). Precedence: the chain is checked first, so a broken chain denies
     * with its D3 error even when an approval is present; a valid chain with no valid approval denies
     * ApprovalRequired; a valid-but-already-consumed approval denies AlreadyConsumed. The approval is
     * CONSUMED (the single state change) only when both gates hold; a rejected action makes no ledger
     * append. Returns normally on authorization. */
    public static void authorizeDestructive(Action action, Map<String, Resolved> grants, Set<String> anchors,
                                            Map<String, Long> revoked, long now, Approval.ApprovalRecord appr,
                                            int approverAlg, byte[] approverPk, byte[] apprSig, byte[] argsContentID,
                                            Approval.Ledger ledger) {
        // Gate 1 — the delegation chain (D3). A broken chain denies with its named D3 error.
        verifyChain(action, grants, anchors, revoked, now);
        // Gate 2 — a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
        try {
            Approval.verifyApproval(appr, approverAlg, approverPk, apprSig, argsContentID, now);
        } catch (NaalpException e) {
            throw new NaalpException("ApprovalRequired", "no valid approval on a destructive action (held §7.3)");
        }
        if (!Policy.authorizes(appr.grant, action.effect)) {
            throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover the action");
        }
        // Consume single-use — the ledger's named error (AlreadyConsumed) is surfaced fail-closed.
        ledger.consume(appr.id(), action.signer);
    }
}
