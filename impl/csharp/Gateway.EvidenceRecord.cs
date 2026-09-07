// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint), ported
    /// from impl/go/gateway/{decision_record,checkpoint,egress_attestation}.go; graded against the
    /// shared vectors/{decision_record,checkpoint,egress_attestation}/cases.json plus
    /// vectors/gateway/cases.json's optional_fields{} block (the ordering-disclosure/term-disposition/
    /// foreign-profile-pin groups in Gateway.cs already carry R1/R8).
    /// </summary>
    public static partial class Gateway
    {
        // The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain
        // (audit.HeadSize) and Go's gateway.HeadSize.
        public const int HeadSize = 48;

        private static byte[] Sha384(byte[] b)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(b);
        }

        // ================================================================================================
        // S1 — naalp-decision-record: the full governed-decision accountability record (design.md §26.4)
        //
        // A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
        // action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
        // triple (§26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids);
        // GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T
        // (established off-record by inclusion under a witnessed naalp-checkpoint-root, below). The
        // record is deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body;
        // both time properties are POSITIONAL, never a self-asserted timestamp.
        // ================================================================================================

        /// <summary>The governed-decision accountability record (design.md §26.4).</summary>
        public sealed class DecisionRecord
        {
            public readonly byte[] Action;
            public readonly List<byte[]> Governing;

            /// <summary>OPTIONAL field 3: content id of the consume-receipt spent at decision time;
            /// Length==0 == absent.</summary>
            public readonly byte[] Consume;

            /// <summary>Field 4: allow/deny/hold (reuses the closed gw-decision set).</summary>
            public readonly long Outcome;

            /// <summary>Field 5, MANDATORY: no silent default — every record states its ordering
            /// basis.</summary>
            public readonly OrderingDisclosure Ordering;

            /// <summary>OPTIONAL field 6: per-term observed/reported, keyed by this record's OWN field
            /// numbers 1..5; null/empty == absent.</summary>
            public readonly Dictionary<long, TermDisposition> Terms;

            /// <summary>OPTIONAL field 7: enforced(1)/advised(2); 0 == absent (0 is not a member of the
            /// closed set).</summary>
            public readonly long Enforcement;

            public DecisionRecord(byte[] action, List<byte[]> governing, long outcome, OrderingDisclosure ordering)
                : this(action, governing, outcome, ordering, Array.Empty<byte>(), new Dictionary<long, TermDisposition>(), 0)
            {
            }

            public DecisionRecord(
                byte[] action, List<byte[]> governing, long outcome, OrderingDisclosure ordering,
                byte[] consume, Dictionary<long, TermDisposition> terms, long enforcement)
            {
                Action = action;
                Governing = governing;
                Consume = consume;
                Outcome = outcome;
                Ordering = ordering;
                Terms = terms;
                Enforcement = enforcement;
            }

            /// <summary>Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome,
            /// 5:ordering, ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (Consume
            /// empty, Terms empty, Enforcement zero) — the omit-when-absent precedent (naalp-approval
            /// ?6:audience).</summary>
            public byte[] Bytes()
            {
                var pairs = new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.B(Action)) };
                var govItems = new List<Cbor.Value>(Governing.Count);
                foreach (byte[] g in Governing)
                {
                    govItems.Add(new Cbor.B(g));
                }
                pairs.Add(new Cbor.Pair(new Cbor.U(2), new Cbor.A(govItems)));
                if (Consume.Length > 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(Consume)));
                }
                pairs.Add(new Cbor.Pair(new Cbor.U(4), new Cbor.U(Outcome)));
                pairs.Add(new Cbor.Pair(new Cbor.U(5), Ordering.ToCbor()));
                if (Terms.Count > 0)
                {
                    var tpairs = new List<Cbor.Pair>();
                    foreach (KeyValuePair<long, TermDisposition> kv in Terms)
                    {
                        tpairs.Add(new Cbor.Pair(new Cbor.U(kv.Key), kv.Value.ToCbor()));
                    }
                    pairs.Add(new Cbor.Pair(new Cbor.U(6), new Cbor.M(tpairs)));
                }
                if (Enforcement != 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(7), new Cbor.U(Enforcement)));
                }
                return Cbor.Encode(new Cbor.M(pairs));
            }

            /// <summary>The record's SHA-384 head (48 octets).</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The record's T1 content-id (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>
        /// Reconstructs a DecisionRecord from its body bytes alone. It performs ONLY structural checks
        /// (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
        /// gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the deny/hold-
        /// with-consume rule, or the terms key set — see ValidateDecisionRecord. Fail-closed on any
        /// malformed shape (DecisionMalformed).
        /// </summary>
        public static DecisionRecord ParseDecisionRecord(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("DecisionMalformed", "object is not a well-formed N-AALP decision-record body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("DecisionMalformed", "object is not a well-formed N-AALP decision-record body");
            }

            Dictionary<long, Cbor.Value> fields = FieldsOf(m);
            if (!fields.TryGetValue(1, out Cbor.Value? actV) || !(actV is Cbor.B ab))
            {
                throw new NaalpException("DecisionMalformed", "missing or wrong-typed field 1 (action)");
            }
            if (!fields.TryGetValue(2, out Cbor.Value? govV) || !(govV is Cbor.A ga))
            {
                throw new NaalpException("DecisionMalformed", "missing or wrong-typed field 2 (governing)");
            }
            var governing = new List<byte[]>(ga.Items.Count);
            foreach (Cbor.Value item in ga.Items)
            {
                if (!(item is Cbor.B gb))
                {
                    throw new NaalpException("DecisionMalformed", "governing array element not a bstr");
                }
                governing.Add(gb.V);
            }
            byte[] consume = Array.Empty<byte>();
            if (fields.TryGetValue(3, out Cbor.Value? cV))
            {
                if (!(cV is Cbor.B cb))
                {
                    throw new NaalpException("DecisionMalformed", "field 3 (consume) wrong type");
                }
                consume = cb.V;
            }
            if (!fields.TryGetValue(4, out Cbor.Value? outV) || !(outV is Cbor.U ou))
            {
                throw new NaalpException("DecisionMalformed", "missing or wrong-typed field 4 (outcome)");
            }
            if (!fields.TryGetValue(5, out Cbor.Value? ordV))
            {
                throw new NaalpException("DecisionMalformed", "missing mandatory field 5 (ordering)");
            }
            OrderingDisclosure? ordering = OrderingFromCbor(ordV);
            if (ordering == null)
            {
                throw new NaalpException("DecisionMalformed", "field 5 (ordering) malformed");
            }
            var terms = new Dictionary<long, TermDisposition>();
            if (fields.TryGetValue(6, out Cbor.Value? tV))
            {
                if (!(tV is Cbor.M tm))
                {
                    throw new NaalpException("DecisionMalformed", "field 6 (terms) wrong type");
                }
                foreach (Cbor.Pair p in tm.Pairs)
                {
                    if (!(p.K is Cbor.U ku))
                    {
                        throw new NaalpException("DecisionMalformed", "terms map key not a uint");
                    }
                    TermDisposition? td = TermDispositionFromCbor(p.Val);
                    if (td == null)
                    {
                        throw new NaalpException("DecisionMalformed", "terms map value malformed");
                    }
                    terms[ku.V] = td;
                }
            }
            long enforcement = 0;
            if (fields.TryGetValue(7, out Cbor.Value? eV))
            {
                if (!(eV is Cbor.U eu))
                {
                    throw new NaalpException("DecisionMalformed", "field 7 (enforcement) wrong type");
                }
                enforcement = eu.V;
            }
            return new DecisionRecord(ab.V, governing, ou.V, ordering, consume, terms, enforcement);
        }

        /// <summary>Reports whether k is one of the record's own field numbers 1..5 — the only valid
        /// keys for the field-6 terms map (design.md §26.4; TermDispositionMalformed otherwise).</summary>
        private static bool ValidDecisionRecordTermKey(long k) => k >= 1 && k <= 5;

        /// <summary>
        /// Performs the semantic, closed-set, and native well-formedness checks ParseDecisionRecord
        /// deliberately does not (mirroring VerifyDecision's Parse/Verify split):
        ///
        ///  1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
        ///  2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
        ///     OrderingDisclosureMalformed) — checked BEFORE the deny/hold-consume rule so a record
        ///     whose ordering is itself malformed is never additionally reported as a consume violation.
        ///  3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
        ///     (DecisionMalformed) — nothing was consumed, so a value here would assert authority spent
        ///     for an action the record's own outcome says was not taken.
        ///  4. Every terms map key must be one of the record's own field numbers 1..5
        ///     (TermDispositionMalformed).
        /// </summary>
        public static void ValidateDecisionRecord(DecisionRecord d)
        {
            if (!IsKnownDecision(d.Outcome))
            {
                throw new NaalpException("UnknownGatewayDecision", "decision-record outcome is outside the closed set allow/deny/hold");
            }
            d.Ordering.Validate();
            if (d.Outcome != DecisionAllow && d.Consume.Length > 0)
            {
                throw new NaalpException("DecisionMalformed", "a deny/hold outcome must not carry a field-3 consume reference");
            }
            foreach (long k in d.Terms.Keys)
            {
                if (!ValidDecisionRecordTermKey(k))
                {
                    throw new NaalpException("TermDispositionMalformed", "a terms map key is outside the record's own field set 1..5");
                }
            }
        }

        /// <summary>Produces the tagged COSE_Sign1 object over the record body, signed by the governed
        /// decision point.</summary>
        public static byte[] SignDecisionRecord(DecisionRecord d, int alg, byte[] seed)
        {
            return Cose.CoseSign1(alg, seed, BareProtected(alg), d.Bytes());
        }

        /// <summary>A DecisionRecord that has passed signature verification and full semantic
        /// validation.</summary>
        public sealed class ResolvedDecisionRecord
        {
            public readonly byte[] Action;
            public readonly List<byte[]> Governing;
            public readonly byte[] Consume;
            public readonly long Outcome;
            public readonly OrderingDisclosure Ordering;
            public readonly Dictionary<long, TermDisposition> Terms;
            public readonly long Enforcement;

            public ResolvedDecisionRecord(
                byte[] action, List<byte[]> governing, byte[] consume, long outcome,
                OrderingDisclosure ordering, Dictionary<long, TermDisposition> terms, long enforcement)
            {
                Action = action;
                Governing = governing;
                Consume = consume;
                Outcome = outcome;
                Ordering = ordering;
                Terms = terms;
                Enforcement = enforcement;
            }
        }

        /// <summary>
        /// Verifies a decision record end-to-end: (1) the signed object under the profile with real
        /// crypto; (2) structural reconstruction (ParseDecisionRecord); and (3) full semantic validation
        /// (ValidateDecisionRecord). It takes no serving-party or connection identity — the authority is
        /// the signature over the bytes, mirroring VerifyDecision. Any failure throws its named error and
        /// resolves nothing (fail-closed).
        /// </summary>
        public static ResolvedDecisionRecord VerifyDecisionRecord(byte[] obj, int profile, int verifierAlg, byte[] verifierPubkey)
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

            DecisionRecord d = ParseDecisionRecord(payload);
            ValidateDecisionRecord(d);
            return new ResolvedDecisionRecord(
                (byte[])d.Action.Clone(),
                new List<byte[]>(d.Governing),
                (byte[])d.Consume.Clone(),
                d.Outcome,
                d.Ordering,
                d.Terms,
                d.Enforcement);
        }

        // ================================================================================================
        // S3 — naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: the neither-party
        // anchor for the BINDING-FIXED-BY-T leg of the accountability triple (design.md §26.5).
        //
        // Tree construction follows RFC 9162 (https://www.rfc-editor.org/rfc/rfc9162.html) §2.1 EXACTLY,
        // SHA-384-profiled: leaf hash = HASH(0x00 || leaf); interior node hash = HASH(0x01 || left ||
        // right); MTH({}) = HASH() (the empty hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) =
        // NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest power of two k < n. §2.1.2's PATH(m, D[n])
        // recursion (leaf-to-root sibling order) generates the audit path; §2.1.3.1's inverse recursion
        // recomputes the root from (leaf, index, size, path) and compares against the named root
        // (InclusionProofInvalid on mismatch, fail-closed).
        // ================================================================================================

        /// <summary>The HeadSize all-zero prev value a log's first checkpoint chains from.</summary>
        public static byte[] GenesisPrev() => new byte[HeadSize];

        /// <summary>A log operator's signed Merkle tree head over a leaf set of record content ids
        /// (design.md §26.5).</summary>
        public sealed class CheckpointRoot
        {
            public readonly byte[] Log;
            public readonly long Size;
            public readonly byte[] Root;
            public readonly byte[] Prev;
            public readonly long At;

            public CheckpointRoot(byte[] log, long size, byte[] root, byte[] prev, long at)
            {
                Log = log;
                Size = size;
                Root = root;
                Prev = prev;
                At = at;
            }

            /// <summary>Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Log)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Size)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(Root)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Prev)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(At)),
                }));
            }

            /// <summary>The checkpoint's SHA-384 head (48 octets) — the prev the NEXT checkpoint chains
            /// from.</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The checkpoint's T1 content-id (50 octets) — what an inclusion proof's Root
            /// field and a witness-cosign's Root field both name.</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>Reconstructs a CheckpointRoot from its body bytes alone. Fail-closed on any
        /// malformed shape (CheckpointMalformed): every one of the five fields is mandatory.</summary>
        public static CheckpointRoot ParseCheckpointRoot(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("CheckpointMalformed", "object is not a well-formed N-AALP checkpoint-root body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("CheckpointMalformed", "object is not a well-formed N-AALP checkpoint-root body");
            }
            Dictionary<long, Cbor.Value> f = FieldsOf(m);
            if (!f.TryGetValue(1, out Cbor.Value? logV) || !(logV is Cbor.B lb) ||
                !f.TryGetValue(2, out Cbor.Value? sizeV) || !(sizeV is Cbor.U su) ||
                !f.TryGetValue(3, out Cbor.Value? rootV) || !(rootV is Cbor.B rb) ||
                !f.TryGetValue(4, out Cbor.Value? prevV) || !(prevV is Cbor.B pb) ||
                !f.TryGetValue(5, out Cbor.Value? atV) || !(atV is Cbor.U au))
            {
                throw new NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-5");
            }
            return new CheckpointRoot(lb.V, su.V, rb.V, pb.V, au.V);
        }

        /// <summary>Produces the tagged COSE_Sign1 object over the checkpoint body, signed by the log
        /// operator.</summary>
        public static byte[] SignCheckpointRoot(CheckpointRoot c, int alg, byte[] seed)
        {
            return Cose.CoseSign1(alg, seed, BareProtected(alg), c.Bytes());
        }

        /// <summary>A witness's countersignature over one exact checkpoint by content id (design.md
        /// §26.5). Whether the witness's observational domain is genuinely distinct from both parties to
        /// the decisions the checkpoint covers is a structural deployment fact checkable in substance at
        /// T+n — the wire supplies the hook; it does not manufacture the independence itself.</summary>
        public sealed class WitnessCosign
        {
            public readonly byte[] Witness;
            public readonly byte[] Root;
            public readonly long At;

            public WitnessCosign(byte[] witness, byte[] root, long at)
            {
                Witness = witness;
                Root = root;
                At = at;
            }

            /// <summary>Deterministic-CBOR encoding {1:witness, 2:root, 3:at}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Witness)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Root)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(At)),
                }));
            }

            /// <summary>The cosign's SHA-384 head (48 octets).</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The cosign's T1 content-id (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>Reconstructs a WitnessCosign from its body bytes alone. Fail-closed on any malformed
        /// shape: every one of the three fields is mandatory.</summary>
        public static WitnessCosign ParseWitnessCosign(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("CheckpointMalformed", "object is not a well-formed N-AALP witness-cosign body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("CheckpointMalformed", "object is not a well-formed N-AALP witness-cosign body");
            }
            Dictionary<long, Cbor.Value> f = FieldsOf(m);
            if (!f.TryGetValue(1, out Cbor.Value? wV) || !(wV is Cbor.B wb) ||
                !f.TryGetValue(2, out Cbor.Value? rV) || !(rV is Cbor.B rb) ||
                !f.TryGetValue(3, out Cbor.Value? aV) || !(aV is Cbor.U au))
            {
                throw new NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-3");
            }
            return new WitnessCosign(wb.V, rb.V, au.V);
        }

        /// <summary>Produces the tagged COSE_Sign1 object over the cosign body, signed by the
        /// witness.</summary>
        public static byte[] SignWitnessCosign(WitnessCosign w, int alg, byte[] seed)
        {
            return Cose.CoseSign1(alg, seed, BareProtected(alg), w.Bytes());
        }

        /// <summary>Checks that w names the EXACT checkpoint it accompanies (WitnessRootMismatch,
        /// design.md §26.5): w.Root must equal accompaniedCheckpointId, the content id of the
        /// naalp-checkpoint-root object w claims to cosign. Fail-closed.</summary>
        public static void ValidateWitnessCosign(WitnessCosign w, byte[] accompaniedCheckpointId)
        {
            if (!((ReadOnlySpan<byte>)w.Root).SequenceEqual(accompaniedCheckpointId))
            {
                throw new NaalpException(
                    "WitnessRootMismatch",
                    "witness-cosign names a root content id that does not match the checkpoint it accompanies");
            }
        }

        /// <summary>Proves one record's content id existed as a leaf under a named checkpoint
        /// (design.md §26.5, RFC 9162 §2.1.3.1).</summary>
        public sealed class InclusionProof
        {
            public readonly byte[] Root;
            public readonly byte[] Leaf;
            public readonly long Index;
            public readonly List<byte[]> Path;

            public InclusionProof(byte[] root, byte[] leaf, long index, List<byte[]> path)
            {
                Root = root;
                Leaf = leaf;
                Index = index;
                Path = path;
            }

            /// <summary>Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}.</summary>
            public byte[] Bytes()
            {
                var arr = new List<Cbor.Value>(Path.Count);
                foreach (byte[] s in Path)
                {
                    arr.Add(new Cbor.B(s));
                }
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Root)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Leaf)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Index)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.A(arr)),
                }));
            }

            /// <summary>The proof's SHA-384 head (48 octets).</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The proof's T1 content-id (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>Reconstructs an InclusionProof from its body bytes alone. Fail-closed on any
        /// malformed shape: every one of the four fields is mandatory.</summary>
        public static InclusionProof ParseInclusionProof(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("CheckpointMalformed", "object is not a well-formed N-AALP inclusion-proof body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("CheckpointMalformed", "object is not a well-formed N-AALP inclusion-proof body");
            }
            Dictionary<long, Cbor.Value> f = FieldsOf(m);
            if (!f.TryGetValue(1, out Cbor.Value? rootV) || !(rootV is Cbor.B rb) ||
                !f.TryGetValue(2, out Cbor.Value? leafV) || !(leafV is Cbor.B lb) ||
                !f.TryGetValue(3, out Cbor.Value? idxV) || !(idxV is Cbor.U iu) ||
                !f.TryGetValue(4, out Cbor.Value? pathV) || !(pathV is Cbor.A pa))
            {
                throw new NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-4");
            }
            var path = new List<byte[]>(pa.Items.Count);
            foreach (Cbor.Value item in pa.Items)
            {
                if (!(item is Cbor.B pb))
                {
                    throw new NaalpException("CheckpointMalformed", "path array element not a bstr");
                }
                path.Add(pb.V);
            }
            return new InclusionProof(rb.V, lb.V, iu.V, path);
        }

        // ---- RFC 9162 §2.1 Merkle tree math (SHA-384-profiled) ---------------------------------------

        /// <summary>leaf_hash = HASH(0x00 || leaf) (RFC 9162 §2.1's LEAF_HASH, leaf/interior domain
        /// separation).</summary>
        private static byte[] LeafHash(byte[] leaf)
        {
            byte[] b = new byte[1 + leaf.Length];
            b[0] = 0x00;
            Array.Copy(leaf, 0, b, 1, leaf.Length);
            return Sha384(b);
        }

        /// <summary>node_hash = HASH(0x01 || left || right) (RFC 9162 §2.1's NODE_HASH).</summary>
        private static byte[] NodeHash(byte[] l, byte[] r)
        {
            byte[] b = new byte[1 + l.Length + r.Length];
            b[0] = 0x01;
            Array.Copy(l, 0, b, 1, l.Length);
            Array.Copy(r, 0, b, 1 + l.Length, r.Length);
            return Sha384(b);
        }

        /// <summary>The largest power of two strictly less than n (n &gt; 1), per RFC 9162 §2.1's k =
        /// "the largest power of two smaller than n".</summary>
        private static int LargestPowerOfTwoLessThan(int n)
        {
            int k = 1;
            while (2 * k < n)
            {
                k *= 2;
            }
            return k;
        }

        /// <summary>Computes MTH(leaves) per RFC 9162 §2.1: MTH({}) = HASH() (SHA-384 of the empty
        /// string); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the
        /// largest power of two k &lt; n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is
        /// applied internally — callers never hash a leaf before calling MerkleRoot. leaves == null is
        /// accepted as the empty list.</summary>
        public static byte[] MerkleRoot(List<byte[]>? leaves)
        {
            int n = leaves?.Count ?? 0;
            if (n == 0)
            {
                return Sha384(Array.Empty<byte>()); // MTH({}) = HASH(""), the empty-list base case
            }
            if (n == 1)
            {
                return LeafHash(leaves![0]);
            }
            int k = LargestPowerOfTwoLessThan(n);
            return NodeHash(MerkleRoot(leaves!.GetRange(0, k)), MerkleRoot(leaves.GetRange(k, n - k)));
        }

        /// <summary>Computes the RFC 9162 §2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling
        /// order — the list's FIRST entry is the leaf's immediate sibling, the LAST is closest to the
        /// root, exactly the order naalp-inclusion-proof's Path field carries).</summary>
        public static List<byte[]> GenerateInclusionProofPath(List<byte[]> leaves, int index)
        {
            if (index < 0 || index >= leaves.Count)
            {
                throw new NaalpException("InclusionProofInvalid", "leaf index out of range");
            }
            return GenPath(leaves, index);
        }

        private static List<byte[]> GenPath(List<byte[]> leaves, int index)
        {
            int n = leaves.Count;
            if (n <= 1)
            {
                return new List<byte[]>(); // PATH(0, {d0}) = {} — the single-leaf base case
            }
            int k = LargestPowerOfTwoLessThan(n);
            List<byte[]> outp;
            if (index < k)
            {
                outp = GenPath(leaves.GetRange(0, k), index);
                outp.Add(MerkleRoot(leaves.GetRange(k, n - k)));
            }
            else
            {
                outp = GenPath(leaves.GetRange(k, n - k), index - k);
                outp.Add(MerkleRoot(leaves.GetRange(0, k)));
            }
            return outp;
        }

        // Internal sentinel: the recursive root recomputation ran out of path entries (or had entries
        // left over) before reaching the single-leaf base case. Always surfaced to callers as
        // InclusionProofInvalid — never exported.
        private sealed class PathLengthMismatchException : Exception
        {
        }

        /// <summary>The exact structural inverse of GenPath: at each level it consumes the LAST
        /// remaining path entry (closest to the root) as this level's sibling and recurses into the
        /// appropriate half with the entries that remain.</summary>
        private static byte[] RecomputeRoot(byte[] leafH, int index, int size, List<byte[]> path)
        {
            if (size == 1)
            {
                if (path.Count != 0)
                {
                    throw new PathLengthMismatchException();
                }
                return leafH;
            }
            if (path.Count == 0)
            {
                throw new PathLengthMismatchException();
            }
            int k = LargestPowerOfTwoLessThan(size);
            byte[] last = path[path.Count - 1];
            List<byte[]> rest = path.GetRange(0, path.Count - 1);
            if (index < k)
            {
                byte[] left = RecomputeRoot(leafH, index, k, rest);
                return NodeHash(left, last);
            }
            byte[] right = RecomputeRoot(leafH, index - k, size - k, rest);
            return NodeHash(last, right);
        }

        /// <summary>
        /// Recomputes the audit path bottom-up (RFC 9162 §2.1.3.1, the inverse of PATH()) from (leaf,
        /// index, size, path) and compares the result against root. size is the tree size the proof is
        /// checked against — the resolved naalp-checkpoint-root's own Size field, NOT carried inside
        /// naalp-inclusion-proof itself. Fail-closed: any mismatch, out-of-range index, or path-length
        /// mismatch is InclusionProofInvalid.
        /// </summary>
        public static void VerifyInclusionProof(byte[] leaf, long index, long size, List<byte[]> path, byte[] root)
        {
            if (size == 0 || index >= size)
            {
                throw new NaalpException("InclusionProofInvalid", "index out of range for the claimed tree size");
            }
            byte[] got;
            try
            {
                got = RecomputeRoot(LeafHash(leaf), (int)index, (int)size, new List<byte[]>(path));
            }
            catch (PathLengthMismatchException)
            {
                throw new NaalpException("InclusionProofInvalid", "inclusion path length does not match the claimed tree size");
            }
            if (!((ReadOnlySpan<byte>)got).SequenceEqual(root))
            {
                throw new NaalpException("InclusionProofInvalid", "inclusion audit path does not recompute to the named root");
            }
        }

        // ================================================================================================
        // E6.3 — naalp-egress-attestation: a SIGNED attestation a gateway/sidecar emits that an object of
        // a given effect class, bound to a given audience, crossed an egress boundary at a given time —
        // third-party verifiable WITHOUT the payload. A near-clone of GatewayDecision: the gateway is the
        // SIGNER, and VerifyEgressAttestation takes NO serving-party or connection identity — the
        // authority is the signature over the bytes, so the identical attested evidence re-verifies
        // whether the gateway or an unrelated third party serves it.
        // ================================================================================================

        public const long BindingContentBound = 0; // digest is the crossed object's T1 content-id
        public const long BindingContentFree = 1;  // digest is a hiding commitment SHA-384(content_id||salt)

        private static readonly Dictionary<long, string> BindingNames = new Dictionary<long, string>
        {
            { BindingContentBound, "content_bound" },
            { BindingContentFree, "content_free" },
        };

        /// <summary>Reports whether code is one of the closed binding codes.</summary>
        public static bool IsKnownBinding(long code) => BindingNames.ContainsKey(code);

        /// <summary>Returns the binding name, or "unknown".</summary>
        public static string BindingName(long code)
            => BindingNames.TryGetValue(code, out string? n) ? n : "unknown";

        /// <summary>A signed attestation a gateway/sidecar emits that an object crossed an egress
        /// boundary. Binding selects how Digest is interpreted (content_bound: the crossed object's T1
        /// content-id; content_free: a hiding commitment). Effect is the crossed object's C5 effect
        /// class. Audience is the bound destination (empty-permitted). At is the crossing time, epoch
        /// ms.</summary>
        public sealed class EgressAttestation
        {
            public readonly long Binding;
            public readonly byte[] Digest;
            public readonly long Effect;
            public readonly byte[] Audience;
            public readonly long At;

            /// <summary>OPTIONAL field 6 (design.md §26.3/§26.6). null == ABSENT (reads
            /// correspondence-only); a non-null pointer to the zero value is a DISTINCT wire encoding
            /// (field 6 present, {1:0}) from the field being omitted entirely.</summary>
            public readonly OrderingDisclosure? Ordering;

            public EgressAttestation(long binding, byte[] digest, long effect, byte[] audience, long at)
                : this(binding, digest, effect, audience, at, null)
            {
            }

            public EgressAttestation(
                long binding, byte[] digest, long effect, byte[] audience, long at, OrderingDisclosure? ordering)
            {
                Binding = binding;
                Digest = digest;
                Effect = effect;
                Audience = audience;
                At = at;
                Ordering = ordering;
            }

            /// <summary>Deterministic-CBOR encoding {1: binding, 2: digest, 3: effect, 4: audience,
            /// 5: at, ?6: ordering}. Field 6 is OMITTED when Ordering is null.</summary>
            public byte[] Bytes()
            {
                var pairs = new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(Binding)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Digest)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Effect)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Audience)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(At)),
                };
                if (Ordering != null)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(6), Ordering.ToCbor()));
                }
                return Cbor.Encode(new Cbor.M(pairs));
            }

            /// <summary>The attestation's SHA-384 head (48 octets).</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The attestation's T1 content-id (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());

            /// <summary>The attestation's C5 effect class, normalized fail-closed: a value the
            /// evaluator does not recognize is treated as destructive, never as a weaker
            /// class.</summary>
            public long EffectClass() => Naalp.Policy.NormalizeEffect(Effect);
        }

        /// <summary>
        /// Reconstructs an EgressAttestation from its body bytes alone. It does NOT validate the binding
        /// code against the closed set — that is VerifyEgressAttestation's job — so an attestation
        /// carrying an unknown binding can be represented (and then rejected). Fail-closed on a
        /// malformed shape: every one of the five mandatory fields is required, and a present-but-wrong-
        /// typed field 6 fails here too.
        /// </summary>
        public static EgressAttestation ParseEgressAttestation(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("EgMalformed", "object is not a well-formed N-AALP egress-attestation body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("EgMalformed", "object is not a well-formed N-AALP egress-attestation body");
            }
            Dictionary<long, Cbor.Value> f = FieldsOf(m);
            if (!f.TryGetValue(1, out Cbor.Value? bV) || !(bV is Cbor.U bu) ||
                !f.TryGetValue(2, out Cbor.Value? dV) || !(dV is Cbor.B db) ||
                !f.TryGetValue(3, out Cbor.Value? eV) || !(eV is Cbor.U eu) ||
                !f.TryGetValue(4, out Cbor.Value? aV) || !(aV is Cbor.B aub) ||
                !f.TryGetValue(5, out Cbor.Value? atV) || !(atV is Cbor.U atu))
            {
                throw new NaalpException("EgMalformed", "missing or wrong-typed field 1-5");
            }
            OrderingDisclosure? ordering = null;
            if (f.TryGetValue(6, out Cbor.Value? ordV))
            {
                ordering = OrderingFromCbor(ordV);
                if (ordering == null)
                {
                    throw new NaalpException("EgMalformed", "field 6 (ordering) is present but malformed");
                }
            }
            return new EgressAttestation(bu.V, db.V, eu.V, aub.V, atu.V, ordering);
        }

        /// <summary>Produces the tagged COSE_Sign1 object over the attestation body, signed by the
        /// gateway.</summary>
        public static byte[] SignEgressAttestation(EgressAttestation a, int alg, byte[] seed)
        {
            return Cose.CoseSign1(alg, seed, BareProtected(alg), a.Bytes());
        }

        /// <summary>An EgressAttestation that has passed signature verification. It carries NOTHING
        /// about WHO served the bytes — the authority is the signature, so the resolved evidence is
        /// identical regardless of the serving party (the third-party re-serve property).</summary>
        public sealed class ResolvedEgressAttestation
        {
            public readonly long Binding;
            public readonly byte[] Digest;
            public readonly long Effect;
            public readonly byte[] Audience;
            public readonly long At;
            public readonly OrderingDisclosure? Ordering;

            public ResolvedEgressAttestation(
                long binding, byte[] digest, long effect, byte[] audience, long at, OrderingDisclosure? ordering)
            {
                Binding = binding;
                Digest = digest;
                Effect = effect;
                Audience = audience;
                At = at;
                Ordering = ordering;
            }
        }

        /// <summary>Performs the semantic, closed-set checks ParseEgressAttestation deliberately does
        /// not (mirroring VerifyDecision's Parse/Verify split): the binding must be in the closed set
        /// (UnknownEgressBinding), and — if present — the field-6 ordering disclosure must satisfy its
        /// basis-conditioned well-formedness rule (UnknownOrderingBasis /
        /// OrderingDisclosureMalformed).</summary>
        public static void ValidateEgressAttestation(EgressAttestation a)
        {
            if (!IsKnownBinding(a.Binding))
            {
                throw new NaalpException(
                    "UnknownEgressBinding",
                    "egress attestation binding code is outside the closed set content_bound/content_free");
            }
            a.Ordering?.Validate();
        }

        /// <summary>
        /// Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
        /// the signed object under the profile with real crypto against the GATEWAY's verifier
        /// (verifierAlg, verifierPubkey); (2) reconstructs it from the signed bytes; and (3) validates
        /// the binding code against the closed set (UnknownEgressBinding), and the ordering disclosure
        /// if present. It takes NO serving-party or connection identity: the authority is the signature
        /// over the bytes, so the same obj yields an identical ResolvedEgressAttestation whether the
        /// gateway or an unrelated third party served it (the third-party re-serve property). Any
        /// failure throws its named error and resolves nothing (fail-closed).
        /// </summary>
        public static ResolvedEgressAttestation VerifyEgressAttestation(byte[] obj, int profile, int verifierAlg, byte[] verifierPubkey)
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

            EgressAttestation a = ParseEgressAttestation(payload);
            ValidateEgressAttestation(a);
            return new ResolvedEgressAttestation(
                a.Binding,
                (byte[])a.Digest.Clone(),
                Naalp.Policy.NormalizeEffect(a.Effect),
                (byte[])a.Audience.Clone(),
                a.At,
                a.Ordering);
        }

        // ---- content_free commitment open/verify pair ------------------------------------------------

        /// <summary>The content_free hiding commitment over an object's T1 content-id and a salt:
        /// SHA-384(objectCid || salt) (48 octets). The commitment reveals nothing about objectCid
        /// without the salt; a gateway builds it once to populate a content_free attestation's Digest
        /// field, and retains objectCid+salt to later prove which object crossed via
        /// OpenEgressCommitment.</summary>
        public static byte[] EgressCommit(byte[] objectCid, byte[] salt)
        {
            byte[] b = new byte[objectCid.Length + salt.Length];
            Array.Copy(objectCid, 0, b, 0, objectCid.Length);
            Array.Copy(salt, 0, b, objectCid.Length, salt.Length);
            return Sha384(b);
        }

        /// <summary>Proves which object crossed under a content_free attestation. It recomputes
        /// EgressCommit(objectCid, salt) and compares it, in constant time, against a.Digest. Returns
        /// true iff a is a content_free attestation AND the recomputed commitment matches: a wrong salt
        /// or a wrong objectCid both fail to open (return false), and a content_bound attestation never
        /// opens (its Digest is not a commitment).</summary>
        public static bool OpenEgressCommitment(EgressAttestation a, byte[] objectCid, byte[] salt)
        {
            if (a.Binding != BindingContentFree)
            {
                return false;
            }
            byte[] want = EgressCommit(objectCid, salt);
            if (want.Length != a.Digest.Length)
            {
                return false;
            }
            return CryptographicOperations.FixedTimeEquals(want, a.Digest);
        }
    }
}
