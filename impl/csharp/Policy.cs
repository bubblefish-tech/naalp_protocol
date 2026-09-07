// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// N-AALP C5 effect vocabulary and authorization for the C# SDK (§6).
    ///
    /// <para>The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
    /// unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
    /// (action &lt;= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.</para>
    /// </summary>
    public static class Policy
    {
        public const long READ_ONLY = 0;
        public const long IDEMPOTENT_WRITE = 1;
        public const long NON_IDEMPOTENT_WRITE = 2;
        public const long DESTRUCTIVE = 3;

        private static readonly string[] Names =
        {
            "read_only", "idempotent_write", "non_idempotent_write", "destructive",
        };

        /// <summary>Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2).</summary>
        public static long NormalizeEffect(long v)
        {
            return (v >= 0 && v <= 3) ? v : DESTRUCTIVE;
        }

        public static string SafetyLabelName(long e)
        {
            return Names[NormalizeEffect(e)];
        }

        /// <summary>The §6.1 lattice: an action of class `action` is permitted under ceiling iff action &lt;= ceiling.</summary>
        public static bool Authorizes(long ceiling, long action)
        {
            return action <= ceiling;
        }

        /// <summary>The signed safety-label body {1: risk, 2: scope} (R-6.4).</summary>
        public static byte[] SafetyLabelBytes(string risk, string scope)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.T(risk)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(scope)),
            }));
        }

        /// <summary>Where a claimed identity came from; only a signature-derived identity is an
        /// authorization principal (R-6.5).</summary>
        public enum PrincipalSource
        {
            Signature = 0,         // the verified COSE signature's signer id
            TransportMetadata = 1, // e.g. a TLS peer name / connection tag
            ForeignHeader = 2,     // e.g. an X-Agent-ID or a carried foreign header
            ClientName = 3,        // e.g. a self-asserted clientInfo.name
        }

        /// <summary>Return the authorization principal id iff it is signature-derived and non-empty
        /// (R-6.5); a transport-metadata, foreign-header, or client-supplied name is refused with
        /// UnauthenticatedPrincipal — it is never treated as an authorization identity.</summary>
        public static string ResolveAuthPrincipal(PrincipalSource src, string id)
        {
            if (src != PrincipalSource.Signature || string.IsNullOrEmpty(id))
            {
                throw new NaalpException("UnauthenticatedPrincipal",
                    "an authorization identity must be signature-derived, not transport/foreign/client-asserted");
            }
            return id;
        }

        /// <summary>The non-critical ext key under which the optional safety label is carried (design §6.4).</summary>
        public const long SafetyLabelExtKey = 1;

        /// <summary>The OPTIONAL signed safety annotation (R-6.4): an accountable, attributable claim,
        /// not a guarantee the content is safe.</summary>
        public sealed class SafetyLabel
        {
            public readonly string Risk;
            public readonly string Scope;
            public SafetyLabel(string risk, string scope) { Risk = risk; Scope = scope; }
        }

        /// <summary>Extract the optional safety label from an object's ext map: (label, true) when a
        /// well-formed label is present, (null, false) when absent, and throws MalformedSafetyLabel when
        /// the ext[1] entry is present but not exactly {1:tstr, 2:tstr} — rejected, never silently
        /// accepted.</summary>
        public static (SafetyLabel Label, bool Present) SafetyLabelFromExt(Cbor.M ext)
        {
            if (ext == null) { return (null, false); }
            foreach (Cbor.Pair p in ext.Pairs)
            {
                if (!(p.K is Cbor.U k) || k.V != SafetyLabelExtKey) { continue; }
                if (!(p.Val is Cbor.M m))
                {
                    throw new NaalpException("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}");
                }
                string risk = null, scope = null;
                foreach (Cbor.Pair q in m.Pairs)
                {
                    if (!(q.K is Cbor.U kk) || !(q.Val is Cbor.T vv))
                    {
                        throw new NaalpException("MalformedSafetyLabel", "safety label entry is not {uint: tstr}");
                    }
                    if (kk.V == 1) { risk = vv.V; }
                    else if (kk.V == 2) { scope = vv.V; }
                }
                if (risk == null || scope == null)
                {
                    throw new NaalpException("MalformedSafetyLabel", "safety label missing risk or scope");
                }
                return (new SafetyLabel(risk, scope), true);
            }
            return (null, false);
        }

        /// <summary>A capability an endpoint issues to an authenticated signer id: the most dangerous
        /// effect that principal is permitted to carry. The zero MaxEffect (ReadOnly) is the
        /// least-privilege default, so a default Grant authorizes only read_only.</summary>
        public sealed class Grant
        {
            public readonly string Principal;
            public readonly long MaxEffect;
            public Grant(string principal, long maxEffect) { Principal = principal; MaxEffect = maxEffect; }

            /// <summary>The endpoint policy check making the effect an authorization input, not a hint
            /// (R-6.3). It resolves the presenter (refusing any non-signature source, R-6.5), requires
            /// that identity to match this grant's principal, and denies an object effect exceeding the
            /// grant's ceiling (normalized fail-closed, R-6.2). No side effect; throws on any failure.</summary>
            public void AuthorizeObject(PrincipalSource src, string presented, long objectEffect)
            {
                string who = ResolveAuthPrincipal(src, presented);
                if (who != Principal)
                {
                    throw new NaalpException("EffectNotAuthorized", "object effect exceeds the granted capability");
                }
                if (!Authorizes(MaxEffect, NormalizeEffect(objectEffect)))
                {
                    throw new NaalpException("EffectNotAuthorized", "object effect exceeds the granted capability");
                }
            }
        }
    }
}
