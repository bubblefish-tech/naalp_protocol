// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Text;

namespace Naalp
{
    /// <summary>
    /// C15 — multi-hop AGENT delegation (design.md §18; R-DEL-1..8), a Phase-3 draft-01 ADDITIVE
    /// tier-1 surface over the frozen spine — the C# SDK, ported from impl/go/delegation and
    /// cross-checked against impl/python/naalp/delegation and the Java/Kotlin ports.
    ///
    /// <para>Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain
    /// that terminates at a trust anchor. A DelegationGrant is a normal N-AALP object (a tier-1
    /// Capability surface, kind 4); it introduces NO new envelope, encoding, signature, identity, or
    /// audit mechanism (R-11.3) — the mechanism REUSES the -00 CapDelegate substrate (parent-by-content-id
    /// in <c>causes</c> and the <c>CapExceedsParent</c> attenuation). The only additions over CapDelegate
    /// are the body's <c>subject</c>, <c>max_depth</c>, and validity window.</para>
    ///
    /// <para>The two graded surfaces: the DelegationGrant wire body (<see cref="Grant.Bytes"/> /
    /// <see cref="Grant.ContentId"/>, byte-graded == oracle) and the 12-step leaf-&gt;root chain verifier
    /// (<see cref="VerifyChain"/>, verdict-graded == oracle). Every check is fail-closed (§15): an action
    /// that fails any step is rejected whole, returns its named error, and causes no state change.
    /// Graded against vectors/delegation/cases.json.</para>
    ///
    /// <para>The envelope-integration layer — <see cref="Grant.EnvelopeObject"/> /
    /// <see cref="VerifyGrantObject"/> / <see cref="ComposedKindValidator"/> (D3 step 3: verify a signed
    /// grant end-to-end with real crypto and bind its issuer to the authenticated key) — IS ported
    /// (STEP-2 ten-port parity wave), composing the existing envelope/identity spine unchanged
    /// (<see cref="Envelope.Sign"/>/<see cref="Envelope.Verify"/>, <see cref="Identity.SignerId"/>,
    /// <see cref="Identity.RequireNfc"/>). It is NOT graded by vectors/delegation/cases.json, whose
    /// scenarios are abstract issuer/subject chains (the corpus-graded D3 verdict logic, this file's
    /// <see cref="VerifyChain"/>, is exercised over synthetic content ids, as the C# KAT does); its
    /// real-signed-chain behaviour is demonstrated in isolation instead — a self-built, self-signed
    /// two-hop chain round-trips through EnvelopeObject -&gt; envelope.Sign -&gt; VerifyGrantObject and
    /// authorizes, and each of the D3-step-3 failure modes (tampered signature, forged issuer, a
    /// baseline-only verifier, a non-NFC subject) is exercised with real ML-DSA-65 crypto — mirroring the
    /// Go/Rust/Java/Kotlin ports' delegation_test.go coverage of these same functions. The D4 approval
    /// composition (<see cref="AuthorizeDestructive"/>, wired onto the real <see cref="Approval.Ledger"/>)
    /// is fully ported.</para>
    /// </summary>
    public static class Delegation
    {
        /// <summary>Capability channel (reuses the CapDelegate substrate).</summary>
        public const long ChannelCapability = 0x0002;

        /// <summary>The tier-1 kind code, the next free code after CapIssue/Delegate/Revoke/Lookup (0..3).</summary>
        public const long KindDelegationGrant = 4;

        /// <summary>A named escalation adding multi-hop capability (R-15A.2).</summary>
        public const long Tier = 1;

        /// <summary>A grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write.</summary>
        public const long GrantEffect = Policy.NON_IDEMPOTENT_WRITE;

        // ---- the DelegationGrant object body (design §18.1, §18.5) ---------------------------------

        /// <summary>The signed body of a DelegationGrant. <c>Subject</c> is the delegatee agent id
        /// (signer-id form, MUST be NFC); <c>EffectCap</c> is the max effect this grant conveys;
        /// <c>MaxDepth</c> the max FURTHER delegation hops below it; <c>NotBefore</c>/<c>NotAfter</c> the
        /// validity window; <c>Scope</c> an OPTIONAL NFC resource scope ("" = absent/unconstrained, field
        /// 6 omitted).</summary>
        public sealed class Grant
        {
            public readonly string Subject;
            public readonly long EffectCap;
            public readonly long MaxDepth;
            public readonly long NotBefore;
            public readonly long NotAfter;
            public readonly string Scope;

            public Grant(string subject, long effectCap, long maxDepth, long notBefore, long notAfter, string scope)
            {
                Subject = subject;
                EffectCap = effectCap;
                MaxDepth = maxDepth;
                NotBefore = notBefore;
                NotAfter = notAfter;
                Scope = scope;
            }

            private Cbor.M ToMap()
            {
                var pairs = new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Subject)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(EffectCap)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(MaxDepth)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(NotBefore)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(NotAfter)),
                };
                if (Scope.Length != 0) // "" == absent (field 6 omitted); an empty scope is not a distinct value
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(6), new Cbor.T(Scope)));
                }
                return new Cbor.M(pairs);
            }

            /// <summary>The deterministic-CBOR encoding
            /// {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToMap());

            /// <summary>The grant body's content id: multihash(0x20, SHA-384(body)).</summary>
            public byte[] ContentId() => Cbor.ContentId(Bytes());

            /// <summary>
            /// Builds the (unsigned) N-AALP envelope object that carries this grant: tier 1, Capability
            /// channel, kind DelegationGrant, the grant's own effect non_idempotent_write, the grant body
            /// as field 10, and <paramref name="causes"/> naming the delegation parent by content id
            /// (empty/null for a root grant). The caller signs it with <see cref="Envelope.Sign"/>; the
            /// signer BECOMES the grant's issuer (R-DEL-3). A non-NFC subject/scope is rejected NonNFC; an
            /// effect_cap outside the closed lattice is rejected GrantMalformed. Ported from
            /// impl/go/delegation/delegation.go Grant.EnvelopeObject.
            /// </summary>
            public Envelope.Object EnvelopeObject(byte[] issuer, long created, long profile, List<byte[]>? causes)
            {
                Identity.RequireNfc(Subject); // throws NonNFC
                if (Scope.Length != 0)
                {
                    Identity.RequireNfc(Scope); // throws NonNFC
                }
                if (EffectCap > Policy.DESTRUCTIVE)
                {
                    throw new NaalpException("GrantMalformed", "an effect_cap outside the closed lattice is not a valid ceiling");
                }
                return new Envelope.Object(
                    kind: KindDelegationGrant, channel: ChannelCapability, signer: issuer, created: created,
                    effect: GrantEffect, body: ToMap(), tier: Tier, profile: profile, causes: causes);
            }
        }

        /// <summary>Parse an envelope object body back into a Grant. A body that is not exactly the
        /// {1,2,3,4,5,?6} map with the right value types and an in-range effect_cap is an
        /// unverifiable/malformed grant link and is rejected ChainBroken (fail-closed). An out-of-range
        /// effect_cap is NEVER normalized up (that would widen a ceiling — fail-open); it is
        /// rejected.</summary>
        public static Grant GrantFromBody(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                throw ChainBroken("grant body is not a map");
            }
            string? subject = null;
            long? effectCap = null;
            long? maxDepth = null;
            long? notBefore = null;
            long? notAfter = null;
            string scope = "";
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku) || ku.V < 1 || ku.V > 6)
                {
                    throw ChainBroken("grant body has an out-of-range field");
                }
                switch (ku.V)
                {
                    case 1:
                        if (!(p.Val is Cbor.T t1))
                        {
                            throw ChainBroken("subject is not a tstr");
                        }
                        subject = t1.V;
                        break;
                    case 2:
                        if (!(p.Val is Cbor.U u2) || u2.V > Policy.DESTRUCTIVE || u2.V < 0)
                        {
                            throw ChainBroken("effect_cap absent or out of range");
                        }
                        effectCap = u2.V;
                        break;
                    case 3:
                        if (!(p.Val is Cbor.U u3))
                        {
                            throw ChainBroken("max_depth is not a uint");
                        }
                        maxDepth = u3.V;
                        break;
                    case 4:
                        if (!(p.Val is Cbor.U u4))
                        {
                            throw ChainBroken("not_before is not a uint");
                        }
                        notBefore = u4.V;
                        break;
                    case 5:
                        if (!(p.Val is Cbor.U u5))
                        {
                            throw ChainBroken("not_after is not a uint");
                        }
                        notAfter = u5.V;
                        break;
                    case 6:
                        if (!(p.Val is Cbor.T t6))
                        {
                            throw ChainBroken("scope is not a tstr");
                        }
                        scope = t6.V;
                        break;
                }
            }
            if (subject == null || effectCap == null || maxDepth == null || notBefore == null || notAfter == null)
            {
                throw ChainBroken("grant body is missing a mandatory field");
            }
            return new Grant(subject, effectCap.Value, maxDepth.Value, notBefore.Value, notAfter.Value, scope);
        }

        // ---- kind validation (composes with the frozen baseline) -----------------------------------

        /// <summary>Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant).</summary>
        public static bool KindValidator(long channel, long kind) => channel == ChannelCapability && kind == KindDelegationGrant;

        /// <summary>Accepts the frozen baseline kinds OR the tier-1 DelegationGrant — the validator a
        /// delegation-aware endpoint passes to <see cref="Envelope.Verify"/>. It leaves the frozen
        /// registry untouched (R-11.1); a baseline-only endpoint using <see cref="Channels.KindValidator"/>
        /// alone correctly rejects a DelegationGrant as UnknownKind (fail-closed), exactly as the tier
        /// model requires. Ported from impl/go/delegation/delegation.go ComposedKindValidator.</summary>
        public static bool ComposedKindValidator(long channel, long kind) =>
            Channels.KindValidator(channel, kind) || KindValidator(channel, kind);

        // ---- verified grants + the trust/revocation inputs -----------------------------------------

        /// <summary>A DelegationGrant that has passed envelope verification and integrity binding: its
        /// ENVELOPE content id (what <c>causes</c> point to), its verified issuer id (the envelope signer
        /// — NOT a body field, R-DEL-3), the parsed grant body, and the grant's own <c>causes</c>.</summary>
        public sealed class Resolved
        {
            public readonly byte[] ContentId;
            public readonly string Issuer;
            public readonly Grant Grant;
            public readonly List<byte[]> Causes;

            public Resolved(byte[] contentId, string issuer, Grant grant, List<byte[]> causes)
            {
                ContentId = (byte[])contentId.Clone();
                Issuer = issuer;
                Grant = grant;
                Causes = new List<byte[]>(causes.Count);
                foreach (byte[] c in causes)
                {
                    Causes.Add((byte[])c.Clone());
                }
            }
        }

        /// <summary>
        /// Performs D3 step 3 for one grant: it verifies the signed object end-to-end with real crypto
        /// (<see cref="Envelope.Verify"/> against the <see cref="ComposedKindValidator"/>), confirms it is
        /// a tier-1 Capability DelegationGrant whose own effect is non_idempotent_write, binds the claimed
        /// issuer id to the verifying key (<see cref="Identity.SignerId"/> — a self-asserted issuer that
        /// does not derive from the authenticated key confers nothing, R-DEL-3/R-5.1), and parses the
        /// grant body. Any failure is an unverifiable link (ChainBroken / SignerMismatch / the envelope's
        /// named error), fail-closed. Ported from impl/go/delegation/delegation.go VerifyGrantObject.
        /// </summary>
        public static Resolved VerifyGrantObject(int profile, int alg, byte[] pubkey, byte[] signedObj)
        {
            Envelope.Object o = Envelope.Verify(profile, alg, pubkey, ComposedKindValidator, signedObj);
            if (o.Channel != ChannelCapability || o.Kind != KindDelegationGrant || o.Tier != Tier)
            {
                throw ChainBroken("verified object is not a tier-1 Capability DelegationGrant");
            }
            if (o.Effect != GrantEffect) // a DelegationGrant's own effect is non_idempotent_write
            {
                throw ChainBroken("a DelegationGrant's own effect must be non_idempotent_write");
            }
            string issuer = Identity.SignerId(alg, pubkey);
            if (Encoding.UTF8.GetString(o.Signer) != issuer) // the envelope signer field MUST be the authenticated id
            {
                throw new NaalpException("SignerMismatch", "the envelope signer field must be the authenticated id");
            }
            Grant g = GrantFromBody(o.Body);
            return new Resolved(o.Id!, issuer, g, o.Causes);
        }

        /// <summary>The verified action whose delegated authority is being checked. It carries the acting
        /// agent (the verified signer of the action object), the action's own effect and resource scope
        /// (the running child at the leaf hop), and the action's <c>causes</c> (from which the leaf grant
        /// is located).</summary>
        public sealed class Action
        {
            public readonly string Signer;
            public readonly long Effect;
            public readonly string Scope;
            public readonly List<byte[]> Causes;

            public Action(string signer, long effect, string scope, List<byte[]> causes)
            {
                Signer = signer;
                Effect = effect;
                Scope = scope;
                Causes = new List<byte[]>(causes.Count);
                foreach (byte[] c in causes)
                {
                    Causes.Add((byte[])c.Clone());
                }
            }
        }

        /// <summary>Whether the grant named by content id <paramref name="cid"/> is revoked as of
        /// <paramref name="now"/> (a revoke ordered at or before <paramref name="now"/>).
        /// <paramref name="revoked"/> maps a grant's content-id hex to its revoke position.</summary>
        public static bool RevokedAt(IReadOnlyDictionary<string, long> revoked, byte[] cid, long now)
        {
            return revoked.TryGetValue(Hex.Encode(cid), out long p) && p <= now;
        }

        // ---- named, fail-closed errors (design §18.6) ----------------------------------------------

        private static NaalpException ChainBroken(string why) => new NaalpException("ChainBroken", why);

        private static NaalpException CapExceedsParent(string why) => new NaalpException("CapExceedsParent", why);

        // ---- D2 scope containment (design §18.1) ---------------------------------------------------

        /// <summary>Whether <paramref name="child"/> is contained in <paramref name="parent"/> under the
        /// D2 path-prefix rule: an absent parent scope ("") is unconstrained; otherwise the child must
        /// equal the parent or begin with parent + "/". A missing child scope ("") under a scoped parent
        /// WIDENS authority and is NOT contained.</summary>
        public static bool ScopeContained(string child, string parent)
        {
            if (parent.Length == 0)
            {
                return true; // unconstrained parent
            }
            if (child.Length == 0)
            {
                return false; // missing child scope under a scoped parent widens authority
            }
            if (child == parent)
            {
                return true;
            }
            return child.StartsWith(parent + "/", StringComparison.Ordinal);
        }

        /// <summary>The distinct verified grants named in <paramref name="causes"/> whose subject equals
        /// <paramref name="subject"/> (the parent/leaf resolution predicate). Duplicate content ids are
        /// counted once.</summary>
        private static List<Resolved> MatchingCauses(List<byte[]> causes, string subject, IReadOnlyDictionary<string, Resolved> grants)
        {
            var seen = new HashSet<string>();
            var outp = new List<Resolved>();
            foreach (byte[] c in causes)
            {
                string key = Hex.Encode(c);
                if (seen.Contains(key))
                {
                    continue;
                }
                if (grants.TryGetValue(key, out Resolved? r) && r.Grant.Subject == subject)
                {
                    seen.Add(key);
                    outp.Add(r);
                }
            }
            return outp;
        }

        // ---- D3 chain verification (design §18.2) --------------------------------------------------

        /// <summary>The 12-step leaf-&gt;root delegation-chain walk, fail-closed with no partial credit.
        /// <paramref name="grants"/> are the verified grants keyed by content-id hex;
        /// <paramref name="anchors"/> is the trust-anchor issuer-id set; <paramref name="revoked"/> maps a
        /// revoked grant's content-id hex to its revoke position; <paramref name="now"/> is the action's
        /// authoritative ordering position. Returns normally iff the chain terminates at a trusted root
        /// with every hop holding; otherwise throws the specific named error and authorizes nothing.</summary>
        public static void VerifyChain(Action action, IReadOnlyDictionary<string, Resolved> grants,
            IReadOnlySet<string> anchors, IReadOnlyDictionary<string, long> revoked, long now)
        {
            // step 2 — locate the unique leaf grant among the action's causes whose subject == the actor.
            List<Resolved> leaves = MatchingCauses(action.Causes, action.Signer, grants);
            if (leaves.Count == 0)
            {
                throw new NaalpException("EffectNotAuthorized", "no delegation authorizes this action");
            }
            if (leaves.Count > 1)
            {
                throw ChainBroken("more than one authorizing grant is ambiguous");
            }
            Resolved g = leaves[0];
            long childEffect = action.Effect;
            string childScope = action.Scope;
            long pos = 0; // realized delegation hops beneath the current grant
            var visited = new HashSet<string>();

            while (true)
            {
                string key = Hex.Encode(g.ContentId);
                if (!visited.Add(key)) // a content-id cycle (infeasible for a real hash chain)
                {
                    throw ChainBroken("content-id cycle in the delegation chain");
                }
                // step 4 — validity window at `now`.
                if (now < g.Grant.NotBefore)
                {
                    throw new NaalpException("GrantNotYetValid", "grant is before its not_before at this position");
                }
                if (now > g.Grant.NotAfter)
                {
                    throw new NaalpException("GrantExpired", "grant is past its not_after at this position");
                }
                // step 5 — revocation at `now`.
                if (RevokedAt(revoked, g.ContentId, now))
                {
                    throw new NaalpException("GrantRevoked", "grant is revoked at or before this position");
                }
                // step 6 — attenuation (CapExceedsParent): effect ceiling AND scope containment.
                if (!Policy.Authorizes(g.Grant.EffectCap, childEffect))
                {
                    throw CapExceedsParent("child effect exceeds this grant's effect_cap");
                }
                if (!ScopeContained(childScope, g.Grant.Scope))
                {
                    throw CapExceedsParent("child scope is not contained in this grant's scope");
                }
                // step 9 — realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
                if (pos > g.Grant.MaxDepth)
                {
                    throw new NaalpException("DelegationDepthExceeded", "realized delegation depth exceeds max_depth");
                }
                // step 7 — resolve g's delegation parent (the unique cause whose subject == g's issuer).
                List<Resolved> parents = MatchingCauses(g.Causes, g.Issuer, grants);
                if (parents.Count > 1)
                {
                    throw ChainBroken("ambiguous delegation parent");
                }
                if (parents.Count == 0)
                {
                    // steps 10 / 11 — root test: g has no delegation parent.
                    if (anchors.Contains(g.Issuer))
                    {
                        return; // terminated at a trusted root: authorized
                    }
                    throw new NaalpException("UntrustedChainRoot", "the chain root's issuer is not a trust anchor");
                }
                Resolved p = parents[0];
                // step 8 — declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned
                // underflow; a parent with max_depth 0 admits no child grant).
                if (p.Grant.MaxDepth == 0 || g.Grant.MaxDepth >= p.Grant.MaxDepth)
                {
                    throw new NaalpException("DelegationDepthExceeded", "declared delegation depth exceeds parent");
                }
                childEffect = g.Grant.EffectCap;
                childScope = g.Grant.Scope;
                g = p;
                pos++;
            }
        }

        // ---- D4 composition with per-action approval (design §18.3, R-DEL-8) -----------------------

        /// <summary>The D4 two-gate composition: a destructive-effect action requires BOTH a valid
        /// delegation chain (D3, <see cref="VerifyChain"/>) terminating at a trusted root AND a valid,
        /// unconsumed, exact-bytes §7 approval whose granted effect covers the action, CONSUMED single-use
        /// by the acting agent (accountability binds to it). Precedence: the chain is checked first, so a
        /// broken chain denies with its D3 error even when an approval is present; a valid chain with no
        /// valid approval denies ApprovalRequired; a valid-but-already-consumed approval denies
        /// AlreadyConsumed. The approval is CONSUMED (the single state change) only when both gates hold; a
        /// rejected action makes no ledger append. Returns normally on authorization.</summary>
        public static void AuthorizeDestructive(Action action, IReadOnlyDictionary<string, Resolved> grants,
            IReadOnlySet<string> anchors, IReadOnlyDictionary<string, long> revoked, long now,
            Approval.ApprovalRecord appr, int approverAlg, byte[] approverPk, byte[] apprSig, byte[] argsContentId,
            Approval.Ledger ledger)
        {
            // Gate 1 — the delegation chain (D3). A broken chain denies with its named D3 error.
            VerifyChain(action, grants, anchors, revoked, now);
            // Gate 2 — a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
            try
            {
                Approval.VerifyApproval(appr, approverAlg, approverPk, apprSig, argsContentId, now);
            }
            catch (NaalpException)
            {
                throw new NaalpException("ApprovalRequired", "no valid approval on a destructive action (held §7.3)");
            }
            if (!Policy.Authorizes(appr.Grant, action.Effect))
            {
                throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover the action");
            }
            // Consume single-use — the ledger's named error (AlreadyConsumed) is surfaced fail-closed.
            ledger.Consume(appr.Id(), action.Signer);
        }
    }
}
