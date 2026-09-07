// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C21 — the portable gateway-decision object for the C# SDK (design.md §24; requirements
    /// R-GW-1..6), ported from impl/go/gateway.
    ///
    /// <para>A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits
    /// as PORTABLE EVIDENCE that it decided about an action. Its load-bearing property is that
    /// authority lives in the SIGNED BYTES, never in the connection or the host that served them:
    /// VerifyDecision takes NO serving-party/connection identity, so the same signed decision
    /// RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the third-party re-serve
    /// property, R-GW-3). It introduces NO new envelope, encoding, signature, identity, or audit
    /// mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5
    /// effect lattice and the T1 content-id framing (§2.3) unchanged.</para>
    ///
    /// <para>The body is {1: decision, 2: action, 3: policy, 4: effect}. `decision` is a closed set
    /// (allow/deny/hold); `action` is the T1 content id of the action decided about; `policy` is the
    /// opaque identity of the deciding policy (a name, NOT a policy program); `effect` is the C5 effect
    /// class of the action. Every check is fail-closed (§15): a failing object is rejected whole,
    /// throws its named error, and causes no state change.</para>
    /// </summary>
    public static partial class Gateway
    {
        // Decision codes — the closed set a gateway may emit. A code outside the set is rejected
        // (UnknownGatewayDecision).
        public const long DecisionAllow = 0; // the gateway allows the action
        public const long DecisionDeny = 1;  // the gateway denies the action
        public const long DecisionHold = 2;  // the gateway holds the action pending a further step

        private static readonly Dictionary<long, string> DecisionNames = new Dictionary<long, string>
        {
            { DecisionAllow, "allow" },
            { DecisionDeny, "deny" },
            { DecisionHold, "hold" },
        };

        /// <summary>Reports whether code is one of the closed decision codes.</summary>
        public static bool IsKnownDecision(long code) => DecisionNames.ContainsKey(code);

        /// <summary>Returns the decision name, or "unknown".</summary>
        public static string DecisionName(long code)
            => DecisionNames.TryGetValue(code, out string? n) ? n : "unknown";

        // ---- ordering-disclosure embeddable group (design.md §26.3) ------------------------------
        //
        // `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
        // ORDER, and from which observational domain. It is carried as a field inside
        // naalp-decision-record (mandatory, field 5), naalp-egress-attestation (optional, field 6), and
        // naalp-gateway-decision (optional, field 5) — never as a top-level object of its own, so it has
        // no Head()/Id() of its own; it is embedded directly as a nested CBOR map value.

        // Ordering-basis codes — the closed set (design.md §26.3).
        public const long OrderingCorrespondenceOnly = 0; // the record orders only its own two-party construction (the weakest claim)
        public const long OrderingSingleBoundary = 1;     // one boundary observed both terms and is named
        public const long OrderingExternalMechanism = 2;  // an external sequencing mechanism is named

        private static readonly Dictionary<long, string> OrderingBasisNames = new Dictionary<long, string>
        {
            { OrderingCorrespondenceOnly, "correspondence-only" },
            { OrderingSingleBoundary, "single-boundary" },
            { OrderingExternalMechanism, "external-mechanism" },
        };

        /// <summary>Reports whether code is one of the closed ordering-basis codes.</summary>
        public static bool IsKnownOrderingBasis(long code) => OrderingBasisNames.ContainsKey(code);

        /// <summary>Returns the ordering-basis name, or "unknown".</summary>
        public static string OrderingBasisName(long code)
            => OrderingBasisNames.TryGetValue(code, out string? n) ? n : "unknown";

        // Enforcement-disposition codes — the closed set (design.md §26.4).
        public const long EnforcementEnforced = 1; // the producer states it actually enforces this outcome
        public const long EnforcementAdvised = 2;  // the producer's own unverifiable self-account that it only advises

        // Term-disposition kind codes — reused unchanged from the §2.5.4 producing-boundary kind vocabulary.
        public const long TermObserved = 1; // the term was observed first-hand
        public const long TermReported = 2; // the term was reported, relayed from a named source

        /// <summary>
        /// The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md
        /// §26.3). It is never a top-level signed object; it is always a field inside another record.
        /// The zero value (Basis: OrderingCorrespondenceOnly, no boundary/mechanism/relation) is the
        /// weakest claim and is exactly what an ABSENT optional ordering-disclosure field reads as.
        /// </summary>
        public sealed class OrderingDisclosure
        {
            public readonly long Basis;
            public readonly byte[] Boundary;  // present iff Basis == OrderingSingleBoundary
            public readonly byte[] Mechanism; // present iff Basis == OrderingExternalMechanism
            public readonly byte[] Relation;  // present ONLY when Basis == OrderingExternalMechanism (optional even then)

            public OrderingDisclosure(long basis)
                : this(basis, Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>())
            {
            }

            public OrderingDisclosure(long basis, byte[] boundary, byte[] mechanism, byte[] relation)
            {
                Basis = basis;
                Boundary = (byte[])boundary.Clone();
                Mechanism = (byte[])mechanism.Clone();
                Relation = (byte[])relation.Clone();
            }

            /// <summary>Returns self as a nested CBOR map VALUE (never top-level bytes — always
            /// embedded as a field inside its carrying record, so it has no Bytes()/Head()/Id() of its
            /// own).</summary>
            internal Cbor.M ToCbor()
            {
                var pairs = new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.U(Basis)) };
                if (Boundary.Length > 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(2), new Cbor.B(Boundary)));
                }
                if (Mechanism.Length > 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(Mechanism)));
                }
                if (Relation.Length > 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(4), new Cbor.B(Relation)));
                }
                return new Cbor.M(pairs);
            }

            /// <summary>
            /// Checks (a) Basis is in the closed set (UnknownOrderingBasis) and (b) the
            /// basis-conditioned field well-formedness rule (design.md §26.3, native and fail-closed —
            /// any violation rejects the whole carrying record, OrderingDisclosureMalformed).
            /// UnknownOrderingBasis is checked and thrown FIRST: an out-of-set basis is never
            /// additionally reported as malformed.
            /// </summary>
            public void Validate()
            {
                if (!IsKnownOrderingBasis(Basis))
                {
                    throw new NaalpException(
                        "UnknownOrderingBasis",
                        "ordering-disclosure basis is outside the closed set correspondence-only/single-boundary/external-mechanism");
                }
                switch (Basis)
                {
                    case OrderingCorrespondenceOnly:
                        if (Boundary.Length > 0 || Mechanism.Length > 0 || Relation.Length > 0)
                        {
                            throw new NaalpException("OrderingDisclosureMalformed", "correspondence-only requires keys 2/3/4 absent");
                        }
                        break;
                    case OrderingSingleBoundary:
                        if (Boundary.Length == 0 || Mechanism.Length > 0 || Relation.Length > 0)
                        {
                            throw new NaalpException("OrderingDisclosureMalformed", "single-boundary requires key 2 present, keys 3/4 absent");
                        }
                        break;
                    case OrderingExternalMechanism:
                        if (Boundary.Length > 0 || Mechanism.Length == 0)
                        {
                            throw new NaalpException("OrderingDisclosureMalformed", "external-mechanism requires key 2 absent, key 3 present");
                        }
                        break;
                }
            }
        }

        /// <summary>The weakest ordering-disclosure claim, exactly what a verifier reads for an absent
        /// optional ordering-disclosure field.</summary>
        public static OrderingDisclosure CorrespondenceOnly() => new OrderingDisclosure(OrderingCorrespondenceOnly);

        /// <summary>Decodes a nested ordering-disclosure map value. Returns null on any wrong shape,
        /// including an optional key present under the WRONG CBOR type (never silently treated as
        /// absent).</summary>
        private static OrderingDisclosure? OrderingFromCbor(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                return null;
            }
            Dictionary<long, Cbor.Value> f = FieldsOf(m);
            if (!f.TryGetValue(1, out Cbor.Value? basisV) || !(basisV is Cbor.U bu))
            {
                return null;
            }
            byte[] boundary = Array.Empty<byte>();
            byte[] mechanism = Array.Empty<byte>();
            byte[] relation = Array.Empty<byte>();
            if (f.TryGetValue(2, out Cbor.Value? bV))
            {
                if (!(bV is Cbor.B bb)) return null;
                boundary = bb.V;
            }
            if (f.TryGetValue(3, out Cbor.Value? mV))
            {
                if (!(mV is Cbor.B mb)) return null;
                mechanism = mb.V;
            }
            if (f.TryGetValue(4, out Cbor.Value? rV))
            {
                if (!(rV is Cbor.B rb)) return null;
                relation = rb.V;
            }
            return new OrderingDisclosure(bu.V, boundary, mechanism, relation);
        }

        /// <summary>The embeddable group {1: kind, ?2: source} (design.md §26.4). kind is carried as a
        /// plain uint on the wire (the CDDL does not close its value set the way ordering-basis does),
        /// so TermDisposition itself validates no closed set — only naalp-decision-record's own field-6
        /// key set (the record's own field numbers) is fail-closed (TermDispositionMalformed).</summary>
        public sealed class TermDisposition
        {
            public readonly long Kind;
            public readonly byte[] Source; // present iff Kind == TermReported

            public TermDisposition(long kind) : this(kind, Array.Empty<byte>())
            {
            }

            public TermDisposition(long kind, byte[] source)
            {
                Kind = kind;
                Source = (byte[])source.Clone();
            }

            internal Cbor.M ToCbor()
            {
                var pairs = new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.U(Kind)) };
                if (Source.Length > 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(2), new Cbor.B(Source)));
                }
                return new Cbor.M(pairs);
            }
        }

        private static TermDisposition? TermDispositionFromCbor(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                return null;
            }
            Dictionary<long, Cbor.Value> f = FieldsOf(m);
            if (!f.TryGetValue(1, out Cbor.Value? kindV) || !(kindV is Cbor.U ku))
            {
                return null;
            }
            byte[] source = Array.Empty<byte>();
            if (f.TryGetValue(2, out Cbor.Value? sV))
            {
                if (!(sV is Cbor.B sb)) return null;
                source = sb.V;
            }
            return new TermDisposition(ku.V, source);
        }

        // ---- ForeignProfilePin: GatewayDecision field 6, R8 ---------------------------------------
        //
        // The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
        // GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the
        // foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
        // time — binding the reference, not just the class. Both fields are mandatory tstr; the group
        // carries no other keys. It is never a top-level signed object — always embedded as field 6 of
        // its carrying naalp-gateway-decision, so it has no Head()/Id() of its own (mirroring
        // OrderingDisclosure).
        public sealed class ForeignProfilePin
        {
            public readonly string Id;
            public readonly string Revision;
            private readonly bool UnknownField; // an unrecognized key besides 1/2 was present in the decoded CBOR map

            public ForeignProfilePin(string id, string revision) : this(id, revision, false)
            {
            }

            internal ForeignProfilePin(string id, string revision, bool unknownField)
            {
                Id = id;
                Revision = revision;
                UnknownField = unknownField;
            }

            /// <summary>Returns self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}.</summary>
            internal Cbor.M ToCbor()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Id)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(Revision)),
                });
            }

            /// <summary>Checks the foreign-profile-pin's own well-formedness (R8): both Id and Revision
            /// are mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty,
            /// or extra field rejects the WHOLE carrying naalp-gateway-decision
            /// (ForeignProfileMalformed).</summary>
            public void Validate()
            {
                if (Id.Length == 0 || Revision.Length == 0 || UnknownField)
                {
                    throw new NaalpException(
                        "ForeignProfileMalformed",
                        "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)");
                }
            }
        }

        /// <summary>Decodes a nested foreign-profile-pin map value. Decode is STRUCTURAL only,
        /// mirroring OrderingFromCbor: a key present under the WRONG CBOR type fails decode (returns
        /// null, never silently treated as absent); a key that is simply ABSENT decodes to the empty
        /// string, leaving the mandatory-presence check to Validate(). A key besides 1/2 marks the
        /// group unknown, also caught by Validate() — the closed 2-key set is enforced semantically,
        /// not by refusing to decode a map that merely carries an extra key.</summary>
        private static ForeignProfilePin? ForeignProfileFromCbor(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                return null;
            }
            string id = "";
            string revision = "";
            bool unknown = false;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U u1 && u1.V == 1)
                {
                    if (!(p.Val is Cbor.T t1)) return null;
                    id = t1.V;
                }
                else if (p.K is Cbor.U u2 && u2.V == 2)
                {
                    if (!(p.Val is Cbor.T t2)) return null;
                    revision = t2.V;
                }
                else
                {
                    unknown = true;
                }
            }
            return new ForeignProfilePin(id, revision, unknown);
        }

        /// <summary>Builds a key -&gt; value map from a decoded CBOR map's pairs, keyed by the integer
        /// value of any Cbor.U key (mirroring the Go/Python/Java embedded-field accessor field(m, k): a
        /// key that is not a Cbor.U simply does not match — it never causes rejection here). The strict
        /// canonical decoder has already ruled out duplicate keys, so this is a safe 1:1 mapping.
        /// Shared by every evidence-record object's Parse routine (this file and
        /// Gateway.EvidenceRecord.cs).</summary>
        private static Dictionary<long, Cbor.Value> FieldsOf(Cbor.M m)
        {
            var fields = new Dictionary<long, Cbor.Value>();
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U u)
                {
                    fields[u.V] = p.Val;
                }
            }
            return fields;
        }

        /// <summary>
        /// A signed decision an enforcement gateway emits as portable evidence. Decision is the
        /// closed-set outcome; Action is the content id of the action decided about; Policy is the
        /// opaque deciding-policy identity (a name, not a program); Effect is the action's C5 class.
        /// </summary>
        public sealed class GatewayDecision
        {
            public readonly long Decision;
            public readonly byte[] Action;
            public readonly byte[] Policy;
            public readonly long Effect;

            /// <summary>OPTIONAL field 5 (R1); null == absent (reads correspondence-only) — never a
            /// stronger claim inferred from silence.</summary>
            public readonly OrderingDisclosure? Ordering;

            /// <summary>OPTIONAL field 6 (R8); non-null iff decided over foreign-protocol evidence.</summary>
            public readonly ForeignProfilePin? ForeignProfile;

            public GatewayDecision(long decision, byte[] action, byte[] policy, long effect)
                : this(decision, action, policy, effect, null, null)
            {
            }

            public GatewayDecision(
                long decision, byte[] action, byte[] policy, long effect,
                OrderingDisclosure? ordering, ForeignProfilePin? foreignProfile)
            {
                Decision = decision;
                Action = action;
                Policy = policy;
                Effect = effect;
                Ordering = ordering;
                ForeignProfile = foreignProfile;
            }

            /// <summary>The deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect,
            /// ?5: ordering, ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when null (the same
            /// omit-when-absent precedent as naalp-decision-record's optional fields 3/6/7).</summary>
            public byte[] Bytes()
            {
                var pairs = new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(Decision)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Action)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(Policy)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(Effect)),
                };
                if (Ordering != null)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(5), Ordering.ToCbor()));
                }
                if (ForeignProfile != null)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(6), ForeignProfile.ToCbor()));
                }
                return Cbor.Encode(new Cbor.M(pairs));
            }

            /// <summary>The decision's SHA-384 head (48 octets).</summary>
            public byte[] Head()
            {
                using var sha = SHA384.Create();
                return sha.ComputeHash(Bytes());
            }

            /// <summary>The decision's T1 content-id, multihash(0x20, 0x30, SHA-384(body)) (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());

            /// <summary>The decision's C5 effect class, normalized fail-closed (unknown -> destructive).</summary>
            public long EffectClass() => Policy_NormalizeEffect(Effect);
        }

        // Policy.NormalizeEffect proxy (kept local so the name reads at the call site).
        private static long Policy_NormalizeEffect(long v) => Naalp.Policy.NormalizeEffect(v);

        /// <summary>
        /// Reconstructs a GatewayDecision from its body bytes alone. It does NOT validate the decision
        /// code against the closed set — that is VerifyDecision's job — so a decision carrying an
        /// unknown code can be represented (and then rejected). Fail-closed (GwMalformed) on a
        /// malformed shape or a non-canonical encoding.
        /// </summary>
        public static GatewayDecision ParseDecision(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("GwMalformed", "object is not a well-formed N-AALP gateway-decision body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("GwMalformed", "object is not a well-formed N-AALP gateway-decision body");
            }

            Dictionary<long, Cbor.Value> fields = FieldsOf(m);
            if (!fields.TryGetValue(1, out Cbor.Value? decV) || !(decV is Cbor.U du) ||
                !fields.TryGetValue(2, out Cbor.Value? actV) || !(actV is Cbor.B ab) ||
                !fields.TryGetValue(3, out Cbor.Value? polV) || !(polV is Cbor.B pb) ||
                !fields.TryGetValue(4, out Cbor.Value? effV) || !(effV is Cbor.U eu))
            {
                throw new NaalpException("GwMalformed", "object is not a well-formed N-AALP gateway-decision body");
            }

            OrderingDisclosure? ordering = null;
            if (fields.TryGetValue(5, out Cbor.Value? ordV))
            {
                ordering = OrderingFromCbor(ordV);
                if (ordering == null)
                {
                    throw new NaalpException("GwMalformed", "field 5 (ordering) is present but malformed");
                }
            }
            ForeignProfilePin? foreignProfile = null;
            if (fields.TryGetValue(6, out Cbor.Value? fpV))
            {
                foreignProfile = ForeignProfileFromCbor(fpV);
                if (foreignProfile == null)
                {
                    throw new NaalpException("GwMalformed", "field 6 (foreign-profile) is present but malformed");
                }
            }
            return new GatewayDecision(du.V, ab.V, pb.V, eu.V, ordering, foreignProfile);
        }

        // bareProtected encodes the COSE protected header {1: alg} as deterministic CBOR — the exact
        // header impl/go cose.Sign1 produces (a bare {1: alg}, not the enriched envelope header), so
        // the signed gateway-decision object is byte-identical to Go's and Rust's.
        private static byte[] BareProtected(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        // algFromProtected extracts the `alg` (label 1) value from an encoded protected header.
        private static int AlgFromProtected(byte[] prot)
        {
            Cbor.Value pv;
            try
            {
                pv = Cbor.Decode(prot);
            }
            catch (NaalpException)
            {
                throw new NaalpException("Malformed", "malformed COSE object");
            }
            if (pv is Cbor.M m)
            {
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (p.K is Cbor.U ku && ku.V == 1)
                    {
                        if (p.Val is Cbor.N n)
                        {
                            return (int)n.V;
                        }
                        if (p.Val is Cbor.U u)
                        {
                            return (int)u.V;
                        }
                    }
                }
            }
            throw new NaalpException("Malformed", "malformed COSE object");
        }

        /// <summary>
        /// Produces the tagged COSE_Sign1 object over the decision body, signed by the gateway with an
        /// ML-DSA key derived from seed. The protected header is the bare {1: alg} (matching
        /// impl/go/gateway.SignDecision -> cose.Sign1), so the object is byte-identical across ports.
        /// </summary>
        public static byte[] SignDecision(GatewayDecision d, int alg, byte[] seed)
        {
            byte[] prot = BareProtected(alg);
            return Cose.CoseSign1(alg, seed, prot, d.Bytes());
        }

        /// <summary>
        /// A GatewayDecision that has passed signature verification. It carries the verified decision,
        /// action content id, policy identity, and effect class — and NOTHING about WHO served the
        /// bytes, because the authority is the signature (the third-party re-serve property).
        /// </summary>
        public sealed class ResolvedDecision
        {
            public readonly long Decision;
            public readonly byte[] Action;
            public readonly byte[] Policy;
            public readonly long Effect;

            public ResolvedDecision(long decision, byte[] action, byte[] policy, long effect)
            {
                Decision = decision;
                Action = action;
                Policy = policy;
                Effect = effect;
            }
        }

        /// <summary>
        /// Verifies a gateway decision end-to-end and returns the resolved evidence. It (1) verifies the
        /// signed COSE_Sign1 object under the profile with real crypto (registry -> profile floor ->
        /// key/alg match -> signature) against the gateway's verifying key (verifierAlg, verifierPubkey);
        /// (2) reconstructs the decision from the signed bytes; and (3) validates the decision code
        /// against the closed set (UnknownGatewayDecision). It takes NO serving-party or connection
        /// identity: the authority is the signature over the bytes, so the same object yields an
        /// identical ResolvedDecision whether the gateway or an unrelated third party served it. Any
        /// failure throws its named error and resolves nothing (fail-closed).
        /// </summary>
        public static ResolvedDecision VerifyDecision(byte[] obj, int profile, int verifierAlg, byte[] verifierPubkey)
        {
            byte[][] parts;
            try
            {
                parts = Cose.ParseSign1Raw(obj);
            }
            catch (NaalpException)
            {
                throw new NaalpException("Malformed", "malformed COSE object");
            }
            byte[] prot = parts[0];
            byte[] payload = parts[1];
            byte[] sig = parts[2];

            int alg = AlgFromProtected(prot);
            (int level, bool known) = Cose.AlgLevel(alg);
            if (!known)
            {
                throw new NaalpException("UnknownAlg", "algorithm id not in the N-AALP registry");
            }
            if (level < Cose.ProfileMinLevel(profile))
            {
                throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
            }
            if (alg != verifierAlg)
            {
                throw new NaalpException("KeyAlgMismatch", "key algorithm does not match object header");
            }
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            if (!Cose.CoseVerify1Raw(alg, verifierPubkey, tbs, sig))
            {
                throw new NaalpException("BadSignature", "signature verification failed");
            }

            GatewayDecision d = ParseDecision(payload);
            if (!IsKnownDecision(d.Decision))
            {
                throw new NaalpException(
                    "UnknownGatewayDecision",
                    "gateway decision code is outside the closed set allow/deny/hold");
            }
            d.Ordering?.Validate();
            d.ForeignProfile?.Validate();
            return new ResolvedDecision(
                d.Decision,
                (byte[])d.Action.Clone(),
                (byte[])d.Policy.Clone(),
                Naalp.Policy.NormalizeEffect(d.Effect));
        }
    }
}
