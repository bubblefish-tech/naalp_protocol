// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C20 — governed negotiation, advisory risk labels, and trust references for the C# SDK
    /// (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4), ported from impl/go/negotiation and
    /// cross-checked against impl/python/naalp/negotiation.py.
    ///
    /// <para>C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new
    /// envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary
    /// signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (<see cref="Policy"/>),
    /// the T1 content-id framing (§2.3), and the §8.2 causal partial order (the <c>causes</c> field)
    /// UNCHANGED.</para>
    ///
    /// <list type="bullet">
    /// <item>Governed negotiation: a <see cref="Message"/> {1: negotiation, 2: role, 3: profile,
    /// 4: causes[]} is one signed step — an OFFER, a COUNTER, or an ACCEPT — causally linked to its
    /// predecessor(s) by content-id, selecting a profile from a CLOSED pre-registered set. An ACCEPT
    /// MUST DESCEND from its offer by walking the causes DAG (<see cref="VerifyAccept"/>), else it is
    /// rejected (NotDescended). An unknown profile/role is rejected.</item>
    /// <item>Advisory risk labels: a <see cref="RiskLabel"/> {1: code, 2: critical} + a
    /// <see cref="LabeledObject"/> {1: effect, 2: labels[]}. The R-2.5 critical-extension rule applies
    /// (an unknown CRITICAL label is rejected, an unknown non-critical one is ignored). LOAD-BEARING
    /// invariant: carrying a risk label NEVER changes an object's effect class —
    /// <see cref="LabeledObject.EffectClass"/> derives from field 1 (the effect) ALONE.</item>
    /// <item>Trust references: a <see cref="TrustRef"/> {1: registry, 2: reference, 3: subject} carries
    /// a third-party trust statement as a CHECKABLE signed object — <see cref="VerifyTrustRef"/>
    /// recomputes the referenced content-id over the external record. NO wire field weighs it: there is
    /// no score/rank/ordering and no scoring function, by design.</item>
    /// </list>
    ///
    /// <para>Every check is fail-closed (§15): a failing object is rejected whole, throws its named
    /// error, and causes no state change. The signed pins are byte-identical to the Go, Rust and Python
    /// reference implementations (deterministic ML-DSA-65 over identical canonical CBOR).</para>
    /// </summary>
    public static class Negotiation
    {
        /// <summary>The width of a head / content-id digest (SHA-384 = 48 octets).</summary>
        public const int HeadSize = 48;

        // ==== Task 5.1 — governed negotiation ======================================================

        /// <summary>The closed set of negotiation roles. A role outside the set is rejected
        /// (UnknownRole).</summary>
        public const long RoleOffer = 0;   // the initiating offer (root of a negotiation; no causes)
        public const long RoleCounter = 1; // a counter-offer chaining onto the offer or a prior counter
        public const long RoleAccept = 2;  // the accept; it MUST descend from its offer

        private static readonly Dictionary<long, string> RoleNames = new Dictionary<long, string>
        {
            { RoleOffer, "offer" }, { RoleCounter, "counter" }, { RoleAccept, "accept" },
        };

        /// <summary>Reports whether r is one of the three defined negotiation roles.</summary>
        public static bool KnownRole(long r) => RoleNames.ContainsKey(r);

        /// <summary>Returns the role name, or "unknown".</summary>
        public static string RoleName(long r) => RoleNames.TryGetValue(r, out string? n) ? n : "unknown";

        /// <summary>The CLOSED pre-registered negotiation profiles. A negotiation SELECTS a
        /// pre-registered profile; it never carries a free-form capability string or a runtime-generated
        /// handler. A profile outside the set is rejected (UnknownProfile).</summary>
        public const long ProfileBaseline = 0;  // the baseline capability profile
        public const long ProfileStreaming = 1; // the native-streaming capability profile (C9)
        public const long ProfileBatch = 2;     // the batched-delivery capability profile

        private static readonly Dictionary<long, string> ProfileNames = new Dictionary<long, string>
        {
            { ProfileBaseline, "baseline" }, { ProfileStreaming, "streaming" }, { ProfileBatch, "batch" },
        };

        /// <summary>Reports whether p is one of the pre-registered profiles.</summary>
        public static bool IsRegisteredProfile(long p) => ProfileNames.ContainsKey(p);

        /// <summary>Returns the profile name, or "unknown".</summary>
        public static string ProfileName(long p) => ProfileNames.TryGetValue(p, out string? n) ? n : "unknown";

        /// <summary>
        /// One signed step of a governed negotiation: an offer, a counter, or an accept. It is CAUSALLY
        /// LINKED to its predecessor(s) by content-id in <see cref="Causes"/> (empty for an offer) and
        /// SELECTS a pre-registered <see cref="Profile"/>.
        /// </summary>
        public sealed class Message
        {
            public readonly byte[] Negotiation; // opaque negotiation id (ties the exchange together)
            public readonly long Role;          // offer / counter / accept (closed set)
            public readonly long Profile;       // the selected pre-registered profile (closed set)
            public readonly List<byte[]> Causes; // content-ids of predecessors (empty for an offer)

            public Message(byte[] negotiation, long role, long profile, List<byte[]>? causes = null)
            {
                Negotiation = negotiation;
                Role = role;
                Profile = profile;
                Causes = causes ?? new List<byte[]>();
            }

            /// <summary>The deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}.</summary>
            public byte[] Bytes()
            {
                var arr = new List<Cbor.Value>(Causes.Count);
                foreach (byte[] c in Causes) arr.Add(new Cbor.B(c));
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Negotiation)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Role)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Profile)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.A(arr)),
                }));
            }

            /// <summary>The Message's SHA-384 head (48 octets).</summary>
            public byte[] Head() => NegHead(Bytes());

            /// <summary>The Message's T1 content-id (50 octets) — the id a successor names in its causes.</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>Builds an offer (the root of a negotiation): role offer, no causes.</summary>
        public static Message NewOffer(byte[] negotiation, long profile)
            => new Message(negotiation, RoleOffer, profile);

        /// <summary>Builds a counter chaining onto the predecessor named by predecessorId.</summary>
        public static Message NewCounter(byte[] negotiation, long profile, byte[] predecessorId)
            => new Message(negotiation, RoleCounter, profile, new List<byte[]> { predecessorId });

        /// <summary>Builds an accept chaining onto the predecessor named by predecessorId.</summary>
        public static Message NewAccept(byte[] negotiation, long profile, byte[] predecessorId)
            => new Message(negotiation, RoleAccept, profile, new List<byte[]> { predecessorId });

        /// <summary>
        /// Reconstructs a Message from its body bytes alone. It does NOT validate the role or profile
        /// against the closed sets — that is <see cref="VerifyMessage"/>'s job — so a message carrying
        /// an unknown role or profile can be represented (and then rejected). Fail-closed (NegMalformed)
        /// on any malformed shape, a non-canonical body, or a mistyped field.
        /// </summary>
        public static Message ParseMessage(byte[] b)
        {
            Cbor.M? m = DecodeMap(b);
            if (m == null) throw NegMalformed();
            byte[]? neg = BstrField(m, 1);
            long? role = UintField(m, 2);
            long? prof = UintField(m, 3);
            Cbor.Value? causesV = Field(m, 4);
            if (neg == null || role == null || prof == null || !(causesV is Cbor.A arr)) throw NegMalformed();
            var causes = new List<byte[]>(arr.Items.Count);
            foreach (Cbor.Value e in arr.Items)
            {
                if (!(e is Cbor.B bs)) throw NegMalformed();
                causes.Add(bs.V);
            }
            return new Message(neg, role.Value, prof.Value, causes);
        }

        /// <summary>The tagged COSE_Sign1 over the Message body (real deterministic ML-DSA).</summary>
        public static byte[] SignMessage(Message m, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), m.Bytes());

        /// <summary>
        /// Verifies the Message's full signature under the profile, reconstructs it from the signed body
        /// bytes, and validates it against the closed sets: the role MUST be offer/counter/accept
        /// (UnknownRole) and the selected profile MUST be pre-registered (UnknownProfile). Fail-closed.
        /// </summary>
        public static Message VerifyMessage(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifyBody(obj, profile, alg, pubkey);
            Message m = ParseMessage(payload);
            if (!KnownRole(m.Role))
                throw new NaalpException("UnknownRole", "negotiation message role is not offer/counter/accept");
            if (!IsRegisteredProfile(m.Profile))
                throw new NaalpException("UnknownProfile", "negotiation selects a profile outside the closed pre-registered set");
            return m;
        }

        /// <summary>Builds the content-id -> Message index the descent walk resolves predecessors
        /// through. The key is the hex form of the T1 content-id (Message.Id()).</summary>
        public static Dictionary<string, Message> IndexById(IEnumerable<Message> msgs)
        {
            var byId = new Dictionary<string, Message>();
            foreach (Message m in msgs) byId[Convert.ToHexString(m.Id())] = m;
            return byId;
        }

        // descends reports whether `from` reaches targetId by following causes edges resolved through
        // byId: a real reachability walk over the causal DAG. A cause that cannot be resolved through
        // byId cannot extend the chain through it, so a forged causes pointer to an id the verifier
        // never saw does not manufacture descent. Fail-closed.
        private static bool DescendsWalk(Message from, byte[] targetId, Dictionary<string, Message> byId)
        {
            string target = Convert.ToHexString(targetId);
            var seen = new HashSet<string>();
            var stack = new Stack<byte[]>();
            foreach (byte[] c in from.Causes) stack.Push(c);
            while (stack.Count > 0)
            {
                byte[] id = stack.Pop();
                string k = Convert.ToHexString(id);
                if (k == target) return true;
                if (!seen.Add(k)) continue;
                if (!byId.TryGetValue(k, out Message? pred)) continue; // unresolved cause: chain cannot walk through it
                foreach (byte[] c in pred.Causes) stack.Push(c);
            }
            return false;
        }

        /// <summary>Reports whether `accept` descends from `offer` by walking the causes DAG through
        /// byId (a counter or a chain of counters between them is traversed). Performs no signature
        /// check.</summary>
        public static bool Descends(Message accept, Message offer, Dictionary<string, Message> byId)
            => DescendsWalk(accept, offer.Id(), byId);

        /// <summary>
        /// Checks an accept against its offer over a set of verified messages, fail-closed. It requires
        /// `offer` to be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile),
        /// `accept` to be an accept selecting a pre-registered profile (NotAccept / UnknownProfile), and
        /// the accept to DESCEND from the offer (NotDescended otherwise). Returns the AGREED profile. It
        /// authorizes nothing; it accepts or rejects. byId MUST index the negotiation's verified
        /// messages (build it with <see cref="IndexById"/> over <see cref="VerifyMessage"/> results).
        /// </summary>
        public static long VerifyAccept(Message accept, Message offer, Dictionary<string, Message> byId)
        {
            if (offer.Role != RoleOffer)
                throw new NaalpException("NotOffer", "the object presented as the offer is not an offer role");
            if (!IsRegisteredProfile(offer.Profile))
                throw new NaalpException("UnknownProfile", "offer selects a profile outside the closed set");
            if (accept.Role != RoleAccept)
                throw new NaalpException("NotAccept", "the object presented as the accept is not an accept role");
            if (!IsRegisteredProfile(accept.Profile))
                throw new NaalpException("UnknownProfile", "accept selects a profile outside the closed set");
            if (!Descends(accept, offer, byId))
                throw new NaalpException("NotDescended", "accept does not descend from its offer along the causes chain");
            return accept.Profile;
        }

        // ==== Task 5.2 — advisory risk labels ======================================================

        /// <summary>A risk label's advisory class in the vocabulary: informing (purely informational)
        /// or gating (a policy MAY gate on it). This is a REGISTRY attribute of the label code, distinct
        /// from the per-carriage critical flag.</summary>
        public const long ClassInforming = 0;
        public const long ClassGating = 1;

        private static readonly Dictionary<long, string> RiskClassNames = new Dictionary<long, string>
        {
            { ClassInforming, "informing" }, { ClassGating, "gating" },
        };

        /// <summary>Returns the class name ("gating"/"informing"), or "".</summary>
        public static string RiskClassName(long c) => RiskClassNames.TryGetValue(c, out string? n) ? n : "";

        /// <summary>The closed standard risk-label vocabulary codes.</summary>
        public const long RiskSensitive = 1;  // gating: the object touches sensitive material
        public const long RiskEgress = 2;     // gating: the object causes data egress
        public const long RiskReversible = 3; // informing: the object's effect is reversible

        /// <summary>The first code of the private/experimental extensible range. A code at or above it
        /// is unknown to a verifier that lacks it — carried critical it is rejected (R-2.5), carried
        /// non-critical it is ignored.</summary>
        public const long ExtensibleRangeStart = 0x1000;

        private static readonly Dictionary<long, long> RiskVocab = new Dictionary<long, long>
        {
            { RiskSensitive, ClassGating }, { RiskEgress, ClassGating }, { RiskReversible, ClassInforming },
        };

        /// <summary>Returns a code's vocabulary class and whether the code is a registered standard label.</summary>
        public static (long Class, bool Registered) RiskClassOf(long code)
            => RiskVocab.TryGetValue(code, out long c) ? (c, true) : (ClassInforming, false);

        /// <summary>Reports whether code is in the closed standard vocabulary.</summary>
        public static bool IsRegisteredRisk(long code) => RiskVocab.ContainsKey(code);

        /// <summary>Reports whether code lies in the private/experimental extensible range.</summary>
        public static bool InExtensibleRange(long code) => code >= ExtensibleRangeStart;

        /// <summary>One advisory risk label carried on an object. Code is the label code; Critical is the
        /// per-carriage must-understand flag (1 = critical, 0 = advisory) — the uint 1/0, no CBOR
        /// boolean.</summary>
        public sealed class RiskLabel
        {
            public readonly long Code;
            public readonly long Critical;

            public RiskLabel(long code, long critical)
            {
                Code = code;
                Critical = critical;
            }

            /// <summary>Reports whether the label is carried critical (must-understand).</summary>
            public bool IsCritical() => Critical == 1;

            /// <summary>The label's CBOR map {1: code, 2: critical}.</summary>
            internal Cbor.M ToMap() => new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(Code)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(Critical)),
            });

            /// <summary>The deterministic-CBOR encoding of the risk-label body.</summary>
            public byte[] Bytes() => Cbor.Encode(ToMap());
        }

        private static RiskLabel RiskLabelFromValue(Cbor.Value v)
        {
            if (!(v is Cbor.M m)) throw NegMalformed();
            long? code = UintField(m, 1);
            long? crit = UintField(m, 2);
            if (code == null || crit == null) throw NegMalformed();
            if (crit.Value > 1)
                throw new NaalpException("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}");
            return new RiskLabel(code.Value, crit.Value);
        }

        /// <summary>
        /// Applies the critical-extension rule (R-2.5) to a set of carried risk labels: it returns the
        /// RECOGNIZED (standard-vocabulary) labels, DROPS unknown non-critical labels, and REJECTS an
        /// unknown CRITICAL label (UnknownCriticalRisk). A critical flag outside {0,1} is
        /// MalformedCriticalFlag. It NEVER inspects or returns an effect — risk labels are an advisory
        /// dimension, never a fifth effect. Fail-closed.
        /// </summary>
        public static List<RiskLabel> ValidateLabels(List<RiskLabel> labels)
        {
            var recognized = new List<RiskLabel>(labels.Count);
            foreach (RiskLabel l in labels)
            {
                if (l.Critical > 1)
                    throw new NaalpException("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}");
                if (IsRegisteredRisk(l.Code))
                {
                    recognized.Add(l);
                    continue;
                }
                if (l.IsCritical())
                    throw new NaalpException("UnknownCriticalRisk", "an unknown critical risk label is rejected (R-2.5)");
                // unknown non-critical: ignored (dropped from the recognized set)
            }
            return recognized;
        }

        /// <summary>A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk
        /// labels. It exists to demonstrate — provably, in isolation — the load-bearing invariant that
        /// carrying a risk label NEVER changes the object's effect class.</summary>
        public sealed class LabeledObject
        {
            public readonly long Effect;
            public readonly List<RiskLabel> Labels;

            public LabeledObject(long effect, List<RiskLabel>? labels = null)
            {
                Effect = effect;
                Labels = labels ?? new List<RiskLabel>();
            }

            /// <summary>The deterministic-CBOR encoding {1: effect, 2: labels[]}.</summary>
            public byte[] Bytes()
            {
                var arr = new List<Cbor.Value>(Labels.Count);
                foreach (RiskLabel l in Labels) arr.Add(l.ToMap());
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(Effect)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.A(arr)),
                }));
            }

            /// <summary>The LabeledObject's SHA-384 head (48 octets).</summary>
            public byte[] Head() => NegHead(Bytes());

            /// <summary>The LabeledObject's T1 content-id (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());

            /// <summary>
            /// The object's C5 effect class, derived from the effect field (field 1) ALONE and
            /// normalized fail-closed (unknown -> destructive, R-6.2). It DELIBERATELY does not consult
            /// the risk labels: a risk label is an advisory dimension, never a fifth effect, so the
            /// closed C5 lattice is untouched by any label the object carries. This is the load-bearing
            /// C20 invariant.
            /// </summary>
            public long EffectClass() => Policy.NormalizeEffect(Effect);

            /// <summary>Applies the critical-extension rule to the object's carried labels.</summary>
            public List<RiskLabel> ValidateLabels() => Negotiation.ValidateLabels(Labels);
        }

        /// <summary>Reconstructs a LabeledObject from its body bytes alone. Fail-closed (NegMalformed) on
        /// a malformed shape; a critical flag outside {0,1} is MalformedCriticalFlag.</summary>
        public static LabeledObject ParseLabeledObject(byte[] b)
        {
            Cbor.M? m = DecodeMap(b);
            if (m == null) throw NegMalformed();
            long? eff = UintField(m, 1);
            Cbor.Value? labelsV = Field(m, 2);
            if (eff == null || !(labelsV is Cbor.A arr)) throw NegMalformed();
            var labels = new List<RiskLabel>(arr.Items.Count);
            foreach (Cbor.Value e in arr.Items) labels.Add(RiskLabelFromValue(e));
            return new LabeledObject(eff.Value, labels);
        }

        /// <summary>The tagged COSE_Sign1 over the LabeledObject body (real deterministic ML-DSA).</summary>
        public static byte[] SignLabeledObject(LabeledObject o, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), o.Bytes());

        /// <summary>
        /// Verifies the signature under the profile, reconstructs the object, and applies the
        /// critical-extension rule to its labels (an unknown critical label is rejected). Returns the
        /// verified object and its recognized labels. The returned object's EffectClass is unchanged by
        /// any label — labels never participate in the effect. Fail-closed.
        /// </summary>
        public static (LabeledObject Object, List<RiskLabel> Recognized) VerifyLabeledObject(
            byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifyBody(obj, profile, alg, pubkey);
            LabeledObject o = ParseLabeledObject(payload);
            List<RiskLabel> recognized = ValidateLabels(o.Labels);
            return (o, recognized);
        }

        // ==== Task 5.3 — trust references (checkable, never weighed) ================================

        /// <summary>A third-party trust statement carried as a CHECKABLE signed object. Registry is an
        /// opaque external-registry identifier (an ERC-8004-style reputation/identity registry — a name,
        /// not a URL the wire resolves); Reference is the T1 content-id of the referenced external
        /// record; Subject is the opaque id the statement is about. The wire CARRIES the reference; NO
        /// field here weighs it — there is no score, rank, or ordering.</summary>
        public sealed class TrustRef
        {
            public readonly byte[] Registry;
            public readonly byte[] Reference;
            public readonly byte[] Subject;

            public TrustRef(byte[] registry, byte[] reference, byte[] subject)
            {
                Registry = registry;
                Reference = reference;
                Subject = subject;
            }

            /// <summary>The deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}.</summary>
            public byte[] Bytes() => Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(Registry)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(Reference)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(Subject)),
            }));

            /// <summary>The TrustRef's SHA-384 head (48 octets).</summary>
            public byte[] Head() => NegHead(Bytes());

            /// <summary>The TrustRef's own T1 content-id (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());

            /// <summary>The content-id the trust ref binds (the carried external-record reference).</summary>
            public byte[] ReferenceId() => (byte[])Reference.Clone();

            /// <summary>Reports whether the carried Reference is the T1 content-id of `record` — i.e. the
            /// reference recomputes over the presented external bytes. This is the CHECK a relying party
            /// runs to confirm the reference names those exact external bytes; it computes NO score. A
            /// changed record yields a different content-id, so BindsRecord returns false.</summary>
            public bool BindsRecord(byte[] record)
                => Cbor.CompareBytes(Reference, Cbor.ContentId(record)) == 0;
        }

        /// <summary>Reconstructs a TrustRef from its body bytes alone. Fail-closed (NegMalformed).</summary>
        public static TrustRef ParseTrustRef(byte[] b)
        {
            Cbor.M? m = DecodeMap(b);
            if (m == null) throw NegMalformed();
            byte[]? reg = BstrField(m, 1);
            byte[]? reference = BstrField(m, 2);
            byte[]? subj = BstrField(m, 3);
            if (reg == null || reference == null || subj == null) throw NegMalformed();
            return new TrustRef(reg, reference, subj);
        }

        /// <summary>The tagged COSE_Sign1 over the TrustRef body (real deterministic ML-DSA).</summary>
        public static byte[] SignTrustRef(TrustRef r, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), r.Bytes());

        /// <summary>A TrustRef that has passed signature verification and (given the external record) the
        /// content-id recompute. It carries NO score, rank, or trust weight — the protocol does not weigh
        /// trust; which statement to believe is left to the relying party.</summary>
        public sealed class ResolvedTrustRef
        {
            public readonly byte[] Registry;
            public readonly byte[] Reference;
            public readonly byte[] Subject;

            public ResolvedTrustRef(byte[] registry, byte[] reference, byte[] subject)
            {
                Registry = registry;
                Reference = reference;
                Subject = subject;
            }
        }

        /// <summary>
        /// Verifies a trust reference end-to-end: (1) verifies the signed object under the profile with
        /// real crypto (BadSignature); (2) reconstructs it from the signed bytes; and (3) confirms the
        /// reference by RECOMPUTING the external record's content-id and requiring it to equal the
        /// carried Reference (ReferenceMismatch otherwise). Returns the resolved reference — and NOTHING
        /// that scores it: this module has no trust-weighting function, by design. Fail-closed.
        /// </summary>
        public static ResolvedTrustRef VerifyTrustRef(byte[] obj, int profile, int alg, byte[] pubkey, byte[] externalRecord)
        {
            byte[] payload = VerifyBody(obj, profile, alg, pubkey);
            TrustRef r = ParseTrustRef(payload);
            if (!r.BindsRecord(externalRecord))
                throw new NaalpException("ReferenceMismatch", "trust-ref reference content-id does not recompute over the presented external record");
            return new ResolvedTrustRef(r.Registry, r.Reference, r.Subject);
        }

        // ---- full-signature helpers (real ML-DSA COSE_Sign1, bare {1: alg} protected header) --------

        // BareProtected encodes the COSE protected header {1: alg} as deterministic CBOR — the exact
        // header impl/go cose.Sign1 produces (a bare {1: alg}, not the enriched envelope header), so the
        // signed C20 object is byte-identical to Go's, Rust's and Python's.
        private static byte[] BareProtected(int alg)
            => Cbor.Encode(new Cbor.M(new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)) }));

        private static int AlgFromProtected(byte[] prot)
        {
            Cbor.Value pv;
            try { pv = Cbor.Decode(prot); }
            catch (NaalpException) { throw new NaalpException("Malformed", "malformed COSE object"); }
            if (pv is Cbor.M m)
            {
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (p.K is Cbor.U ku && ku.V == 1)
                    {
                        if (p.Val is Cbor.N n) return (int)n.V;
                        if (p.Val is Cbor.U u) return (int)u.V;
                    }
                }
            }
            throw new NaalpException("Malformed", "malformed COSE object");
        }

        // VerifyBody verifies a tagged COSE_Sign1 object's full signature under the profile (registry ->
        // profile floor -> key/alg match -> signature) and returns its signed payload bytes. Fail-closed.
        private static byte[] VerifyBody(byte[] obj, int profile, int verifierAlg, byte[] verifierPubkey)
        {
            byte[][] parts;
            try { parts = Cose.ParseSign1Raw(obj); }
            catch (NaalpException) { throw new NaalpException("Malformed", "malformed COSE object"); }
            byte[] prot = parts[0];
            byte[] payload = parts[1];
            byte[] sig = parts[2];

            int alg = AlgFromProtected(prot);
            (int level, bool known) = Cose.AlgLevel(alg);
            if (!known) throw new NaalpException("UnknownAlg", "algorithm id not in the N-AALP registry");
            if (level < Cose.ProfileMinLevel(profile))
                throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
            if (alg != verifierAlg)
                throw new NaalpException("KeyAlgMismatch", "key algorithm does not match object header");
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            if (!Cose.CoseVerify1Raw(alg, verifierPubkey, tbs, sig))
                throw new NaalpException("BadSignature", "signature verification failed");
            return payload;
        }

        // ---- small deterministic-CBOR helpers -------------------------------------------------------

        // NegHead is SHA-384 over a body — a 48-octet digest (the same construction as audit head).
        private static byte[] NegHead(byte[] b)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(b);
        }

        private static NaalpException NegMalformed()
            => new NaalpException("NegMalformed", "object is not a well-formed N-AALP negotiation/risk-label/labeled-object/trust-ref body");

        // DecodeMap strict-canonical decodes to a CBOR map, or null on any decode error / non-map (a
        // non-canonical body decodes to null -> NegMalformed at the call site).
        private static Cbor.M? DecodeMap(byte[] b)
        {
            Cbor.Value v;
            try { v = Cbor.Decode(b); }
            catch (NaalpException) { return null; }
            return v as Cbor.M;
        }

        private static Cbor.Value? Field(Cbor.M m, long k)
        {
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == k) return p.Val;
            }
            return null;
        }

        private static byte[]? BstrField(Cbor.M m, long k)
            => Field(m, k) is Cbor.B b ? b.V : null;

        private static long? UintField(Cbor.M m, long k)
            => Field(m, k) is Cbor.U u ? u.V : (long?)null;
    }
}
