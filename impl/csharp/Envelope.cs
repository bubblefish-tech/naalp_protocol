// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// N-AALP C3 object envelope for the C# SDK — the full signed object and its offline verify
    /// (design.md §2). This is the ergonomic surface a developer uses: build an <see cref="Object"/>
    /// (its channel/kind/effect/body and the rest), sign it with an ML-DSA key seed, and get a single
    /// self-describing, offline-verifiable byte string; verify one from the object + key + spec alone.
    ///
    /// <para>The object body is a deterministic-CBOR map (fields 1..12) carried as the COSE_Sign1
    /// payload; field 1 is the content id, multihash(0x20, SHA-384(canonical-body-without-field-1))
    /// (§2.3). The COSE protected header carries the signature algorithm plus a routing copy of the
    /// signer, profile, and naalp-version (§2.1, §2.5); a verifier that finds the header copies
    /// disagreeing with the body rejects the object (HeaderBodyMismatch), and every failure is
    /// fail-closed with a named error and no partial application (§2.6). The bytes are byte-identical
    /// to the Go, Rust and Python reference implementations (vectors/worked/example.json is the
    /// byte-level known-answer for this module).</para>
    /// </summary>
    public static partial class Envelope
    {
        // Wire constants (field numbers §2.1, naalp-version §2.5, header label) are generated from
        // spec/wire-constants.csv into the Envelope.WireConstants.cs partial-class fragment, so they
        // are authored once and cannot be re-typed and drift (scripts/gen_wire_constants.py).

        /// <summary>The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519
        /// composite signature (§4.2); present (value 1) iff a composite alg signs the object, so a
        /// pure object stays byte-identical to a draft-00 object.</summary>
        public const long SUITE_MLDSA65_ED25519 = 1;

        /// <summary>Reports whether (channel, kind) is a recognized surface kind. A null validator
        /// rejects every kind (fail-closed dispatch, §2.6).</summary>
        public delegate bool KindValidator(long channel, long kind);

        /// <summary>A decoded N-AALP object body. <see cref="Id"/> is set by <see cref="Sign"/>
        /// (content id §2.3).</summary>
        public sealed class Object
        {
            public byte[]? Id;
            public long Kind;
            public long Channel;
            public long Tier;
            public byte[] Signer;
            public long Created;
            public long Effect;
            public List<byte[]> Causes;
            public long Profile;
            public Cbor.Value Body;
            public Cbor.M? Ext;   // optional non-critical extensions (field 11); null = absent
            public Cbor.M? Cext;  // optional critical extensions (field 12); null = absent
            // field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience
            // object encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
            public string Audience;
            // field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg
            // signs this object; 0 = absent, so a pure object stays byte-identical to draft-00.
            public long Suite;

            public Object(long kind, long channel, byte[] signer, long created, long effect,
                Cbor.Value body, long tier = 0, long profile = Cose.PROFILE_PUBLIC,
                List<byte[]>? causes = null, Cbor.M? ext = null, Cbor.M? cext = null,
                string audience = "", long suite = 0)
            {
                Id = null;
                Kind = kind;
                Channel = channel;
                Tier = tier;
                Signer = (byte[])signer.Clone();
                Created = created;
                Effect = effect;
                Causes = causes ?? new List<byte[]>();
                Profile = profile;
                Body = body;
                Ext = ext;
                Cext = cext;
                Audience = audience;
                Suite = suite;
            }

            // bodyMap builds the object body as a CBOR map. Encode emits canonical key order, so the
            // append order here is irrelevant to the bytes.
            internal Cbor.M BodyMap(bool includeId)
            {
                var pairs = new List<Cbor.Pair>(12);
                if (includeId)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(FieldId), new Cbor.B(Id!)));
                }
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldKind), new Cbor.U(Kind)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldChannel), new Cbor.U(Channel)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldTier), new Cbor.U(Tier)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldSigner), new Cbor.B(Signer)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldCreated), new Cbor.U(Created)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldEffect), new Cbor.U(Effect)));
                var causeItems = new List<Cbor.Value>(Causes.Count);
                foreach (byte[] c in Causes)
                {
                    causeItems.Add(new Cbor.B(c));
                }
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldCauses), new Cbor.A(causeItems)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldProfile), new Cbor.U(Profile)));
                pairs.Add(new Cbor.Pair(new Cbor.U(FieldBody), Body));
                if (Ext != null)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(FieldExt), Ext));
                }
                if (Cext != null)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(FieldCext), Cext));
                }
                if (Audience.Length != 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(FieldAudience), new Cbor.T(Audience)));
                }
                if (Suite != 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(FieldSuite), new Cbor.U(Suite)));
                }
                return new Cbor.M(pairs);
            }

            /// <summary>The object content id over the body without field 1 (§2.3).</summary>
            public byte[] ContentId()
            {
                return Cbor.ContentId(BodyMap(false));
            }
        }

        private static byte[] ProtectedHeader(int alg, byte[] signer, long profile)
        {
            var naalp = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(signer)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(profile)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(NaalpVersion)),
            });
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
                new Cbor.Pair(new Cbor.T(HeaderLabel), naalp),
            }));
        }

        /// <summary>
        /// Assemble, content-id-bind, and deterministically sign a full N-AALP object with an ML-DSA
        /// key derived from <paramref name="seed"/>. The object's Signer/Profile fields and the alg
        /// populate the protected-header routing copies. Returns the tagged COSE_Sign1 object bytes.
        /// </summary>
        public static byte[] Sign(Object obj, int alg, byte[] seed)
        {
            obj.Id = obj.ContentId();
            byte[] payload = Cbor.Encode(obj.BodyMap(true));
            byte[] prot = ProtectedHeader(alg, obj.Signer, obj.Profile);
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            byte[] sig = Cose.MldsaSign(alg, seed, tbs);
            return Cose.AssembleSign1Raw(prot, payload, sig);
        }

        /// <summary>
        /// Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
        /// signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
        /// content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
        /// with ctx = the suite Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes,
        /// byte-identical to the Go/Rust/Python/TS/Java/Kotlin/Ruby/PHP composite object.
        /// </summary>
        public static byte[] SignComposite(Object obj, byte[] mldsaSeed, byte[] edSeed)
        {
            obj.Suite = SUITE_MLDSA65_ED25519;
            obj.Id = obj.ContentId(); // covers field 14 (suite is now set)
            byte[] payload = Cbor.Encode(obj.BodyMap(true));
            byte[] prot = ProtectedHeader(Cose.ALG_COMPOSITE_65_ED25519, obj.Signer, obj.Profile);
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            byte[] sig = Cose.CompositeSign(mldsaSeed, edSeed, tbs);
            return Cose.AssembleSign1Raw(prot, payload, sig);
        }

        private static void ParseProtected(byte[] prot, out int alg, out byte[] signer,
            out long profile, out long version)
        {
            // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping
            // an empty CBOR map (the 0x41A0 form — its unwrapped content is the single byte 0xA0)
            // is the one redundant encoding RFC 9052 §3 otherwise permits, and MUST be rejected as
            // NonCanonical before the header is interpreted (otherwise it dies downstream as a
            // generic Malformed / no-alg, losing the determinism verdict).
            if (prot.Length == 1 && prot[0] == 0xA0)
            {
                throw new NaalpException("NonCanonical",
                    "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)");
            }
            Cbor.Value pv = Cbor.Decode(prot);
            if (!(pv is Cbor.M m))
            {
                throw new NaalpException("Malformed", "protected header not a map");
            }
            int? algOpt = null;
            byte[]? signerOpt = null;
            long? profileOpt = null;
            long? versionOpt = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == 1 && p.Val is Cbor.N nAlg)
                {
                    algOpt = (int)nAlg.V;
                }
                else if (p.K is Cbor.T kt && kt.V == HeaderLabel && p.Val is Cbor.M nm)
                {
                    foreach (Cbor.Pair np in nm.Pairs)
                    {
                        if (!(np.K is Cbor.U nk))
                        {
                            continue;
                        }
                        if (nk.V == 1 && np.Val is Cbor.B bs)
                        {
                            signerOpt = bs.V;
                        }
                        else if (nk.V == 2 && np.Val is Cbor.U pu)
                        {
                            profileOpt = pu.V;
                        }
                        else if (nk.V == 3 && np.Val is Cbor.U vu)
                        {
                            versionOpt = vu.V;
                        }
                    }
                }
            }
            if (algOpt == null || signerOpt == null || profileOpt == null || versionOpt == null)
            {
                throw new NaalpException("Malformed", "protected header missing routing fields");
            }
            alg = algOpt.Value;
            signer = signerOpt;
            profile = profileOpt.Value;
            version = versionOpt.Value;
        }

        private static Object ObjectFromMap(Cbor.M m)
        {
            var fields = new Dictionary<long, Cbor.Value>();
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("Malformed", "non-uint body key");
                }
                fields[ku.V] = p.Val;
            }

            Cbor.B NeedB(int fnum)
            {
                if (!fields.TryGetValue(fnum, out Cbor.Value? v) || !(v is Cbor.B b))
                {
                    throw new NaalpException("Malformed", "field " + fnum + " wrong type/absent");
                }
                return b;
            }

            Cbor.U NeedU(int fnum)
            {
                if (!fields.TryGetValue(fnum, out Cbor.Value? v) || !(v is Cbor.U u))
                {
                    throw new NaalpException("Malformed", "field " + fnum + " wrong type/absent");
                }
                return u;
            }

            Cbor.A NeedA(int fnum)
            {
                if (!fields.TryGetValue(fnum, out Cbor.Value? v) || !(v is Cbor.A a))
                {
                    throw new NaalpException("Malformed", "field " + fnum + " wrong type/absent");
                }
                return a;
            }

            byte[] signer = NeedB(FieldSigner).V;
            Cbor.A causesArr = NeedA(FieldCauses);
            if (causesArr.Items.Count > MaxCauses) // causal fan-in bound (§3.4, R7)
            {
                throw new NaalpException("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)");
            }
            var causes = new List<byte[]>();
            foreach (Cbor.Value c in causesArr.Items)
            {
                if (!(c is Cbor.B cb))
                {
                    throw new NaalpException("Malformed", "cause not a bstr");
                }
                causes.Add(cb.V);
            }

            Cbor.M? ext = null;
            Cbor.M? cext = null;
            if (fields.TryGetValue(FieldExt, out Cbor.Value? extV))
            {
                if (!(extV is Cbor.M em))
                {
                    throw new NaalpException("Malformed", "ext not a map");
                }
                if (em.Pairs.Count > MaxExt) // ext cardinality bound (§3.4, R7)
                {
                    throw new NaalpException("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)");
                }
                ext = em;
            }
            if (fields.TryGetValue(FieldCext, out Cbor.Value? cextV))
            {
                if (!(cextV is Cbor.M cm))
                {
                    throw new NaalpException("Malformed", "cext not a map");
                }
                if (cm.Pairs.Count > MaxCext) // cext cardinality bound (§3.4, R7)
                {
                    throw new NaalpException("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)");
                }
                cext = cm;
            }
            string audience = "";
            if (fields.TryGetValue(FieldAudience, out Cbor.Value? audV))
            {
                if (!(audV is Cbor.T at))
                {
                    throw new NaalpException("Malformed", "audience not a tstr");
                }
                audience = at.V;
            }
            long suite = 0;
            if (fields.TryGetValue(FieldSuite, out Cbor.Value? suiteV))
            {
                if (!(suiteV is Cbor.U su))
                {
                    throw new NaalpException("Malformed", "suite not a uint");
                }
                suite = su.V;
            }

            if (!fields.TryGetValue(FieldBody, out Cbor.Value? body))
            {
                throw new NaalpException("Malformed", "field 10 wrong type/absent");
            }

            var o = new Object(
                kind: NeedU(FieldKind).V,
                channel: NeedU(FieldChannel).V,
                signer: signer,
                created: NeedU(FieldCreated).V,
                effect: NeedU(FieldEffect).V,
                body: body,
                tier: NeedU(FieldTier).V,
                profile: NeedU(FieldProfile).V,
                causes: causes,
                ext: ext,
                cext: cext,
                audience: audience,
                suite: suite);
            o.Id = (fields.TryGetValue(FieldId, out Cbor.Value? idV) && idV is Cbor.B idB) ? idB.V : null;
            return o;
        }

        /// <summary>The single-use consume binding gate (§2.5.3), checked at the point of use --
        /// before the consume logic (the CAS append) -- NEVER inside Verify. An in-transit relay,
        /// ordering authority, or auditor legitimately verifies objects addressed to some OTHER
        /// authority; only the authority about to CONSUME an object enforces that the object is
        /// addressed to it. Three branches: (a) absent audience on a consume-once object ->
        /// WrongAudience; (b) an audience present but not this authority -> WrongAudience; (c) a
        /// non-consume-once object with no audience -> pass. Throws NaalpException("WrongAudience").
        /// </summary>
        public static void CheckAudience(Object o, string selfAuthority, bool consumeOnce)
        {
            if (o.Audience.Length == 0)
            {
                if (consumeOnce)
                {
                    throw new NaalpException("WrongAudience", "consume-once object has no audience");
                }
                return;
            }
            if (o.Audience != selfAuthority)
            {
                throw new NaalpException("WrongAudience", "object audience is not this consuming authority");
            }
        }

        // CheckCext runs the shared critical-extension rule (§2.5, R-2.5) for BOTH the tag-18 Verify
        // and the tag-98 rotation path (VerifyRotationObject), so the two never drift on it -- mirroring
        // impl/go's decodeAndCheck, which both Go verify paths call. Any unrecognized critical key
        // rejects; RecheckKey (13) is envelope-recognized rather than caller-supplied: a critical
        // recheck naming an unknown procedure id rejects (UnknownCriticalExt), a known id is accepted.
        private static void CheckCext(Cbor.M? cext, HashSet<long> knownCext)
        {
            if (cext == null)
            {
                return;
            }
            foreach (Cbor.Pair p in cext.Pairs)
            {
                if (!(p.K is Cbor.U ck))
                {
                    throw new NaalpException("UnknownCriticalExt", "unrecognized critical extension");
                }
                if (ck.V == RECHECK_KEY)
                {
                    if (!(p.Val is Cbor.U rid))
                    {
                        throw new NaalpException("Malformed", "recheck procedure id not a uint");
                    }
                    if (!IsKnownRecheckProcedure(rid.V))
                    {
                        throw new NaalpException("UnknownCriticalExt", "unrecognized critical extension");
                    }
                    continue;
                }
                if (!knownCext.Contains(ck.V))
                {
                    throw new NaalpException("UnknownCriticalExt", "unrecognized critical extension");
                }
            }
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Verify a signed N-AALP object end-to-end, offline, from the object + key + spec alone
        /// (R-2.4). Returns the decoded <see cref="Object"/> on success; throws a
        /// <see cref="NaalpException"/> (or a cbor NonCanonical error) carrying a stable Kind on the
        /// first named failure. Check order (fail-closed throughout): decode -> content-id -> field
        /// ranges -> header/body copies + version -> critical extensions -> kind/channel dispatch ->
        /// profile floor -> signature.
        /// </summary>
        public static Object Verify(int profile, int alg, byte[] pubkey, KindValidator? kindValidator,
            byte[] objBytes, HashSet<long>? knownCext = null)
        {
            // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw
            // bytes, before any parse (RFC 8949 §10 decoder-memory guard).
            if (objBytes.Length > MaxObjectSize)
            {
                throw new NaalpException("TooLarge", "object exceeds the maximum octet size (§3.4, R7)");
            }
            knownCext ??= new HashSet<long>();
            byte[][] parts;
            try
            {
                parts = Cose.ParseSign1Raw(objBytes);
            }
            catch (NaalpException)
            {
                throw new NaalpException("Malformed", "not a COSE_Sign1 object");
            }
            byte[] prot = parts[0];
            byte[] payload = parts[1];
            byte[] sig = parts[2];

            // non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7)
            Cbor.Value bv = Cbor.DecodeBounded(payload, (int)MaxNestingDepth);
            if (!(bv is Cbor.M bodyMap))
            {
                throw new NaalpException("Malformed", "body not a map");
            }

            // content-id: recompute over the body without field 1 and compare to the claimed id.
            byte[]? claimed = null;
            var without = new List<Cbor.Pair>(bodyMap.Pairs.Count);
            foreach (Cbor.Pair p in bodyMap.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == FieldId)
                {
                    if (!(p.Val is Cbor.B idb))
                    {
                        throw new NaalpException("Malformed", "id not a bstr");
                    }
                    claimed = idb.V;
                    continue;
                }
                without.Add(p);
            }
            if (claimed == null)
            {
                throw new NaalpException("Malformed", "no content id");
            }
            byte[] recomputed = Cbor.ContentId(new Cbor.M(without));
            if (!BytesEqual(recomputed, claimed))
            {
                throw new NaalpException("ContentIdMismatch", "recomputed id differs");
            }

            Object o = ObjectFromMap(bodyMap);

            // A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND
            // new key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature
            // and is rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
            if (IsRotationObject(o.Channel, o.Kind))
            {
                throw new NaalpException("RotationUnauthorized", "single-signature rotation missing the old-key co-signature");
            }

            // field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3.
            if (o.Channel > 19 || o.Effect > 3 || o.Profile < 1 || o.Profile > 3)
            {
                throw new NaalpException("RangeError", "field out of range");
            }

            // protected-header copies vs body (HeaderBodyMismatch, §2.1) + version.
            ParseProtected(prot, out int halg, out byte[] hsigner, out long hprofile, out long hversion);
            if (hversion != NaalpVersion)
            {
                throw new NaalpException("UnsupportedVersion", "bad naalp-version");
            }
            if (!BytesEqual(hsigner, o.Signer) || hprofile != o.Profile)
            {
                throw new NaalpException("HeaderBodyMismatch", "protected header disagrees with body");
            }

            // critical extensions: any unrecognized key rejects (§2.5, R-2.5). RecheckKey (13) is an
            // envelope-recognized critical key: a critical recheck naming an UNKNOWN procedure id is
            // rejected fail-closed (the critical-extension rule reaching the procedure it names, T1.3);
            // a known procedure id is recognized. A NON-critical recheck (ext, field 11) is never
            // rejected here -- an unknown non-critical procedure is ignored per the may-ignore rule.
            CheckCext(o.Cext, knownCext);

            // kind/channel surface dispatch (UnknownKind, §2.6).
            if (kindValidator == null || !kindValidator(o.Channel, o.Kind))
            {
                throw new NaalpException("UnknownKind", "kind/channel not a registered surface");
            }

            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);

            // Opt-in composite path (§4.2/§4.4/§4.5), handled BEFORE the pure algLevel gate because the
            // composite alg (-65537) is not a registered pure alg. CompositeRefused (Sovereign floors
            // at level 5, the composite ML-DSA-65 leg is level 3) -> SuiteMismatch (field 14 must
            // declare the matching suite) -> both-legs signature. Verifying key = mldsaPub ||
            // ed25519Pub; cryptographically checked in full (both legs).
            if (halg == Cose.ALG_COMPOSITE_65_ED25519)
            {
                if (profile == Cose.PROFILE_SOVEREIGN)
                {
                    throw new NaalpException("CompositeRefused", "composite refused on the Sovereign profile");
                }
                if (o.Suite != SUITE_MLDSA65_ED25519)
                {
                    throw new NaalpException("SuiteMismatch", "field 14 does not declare the composite suite");
                }
                if (pubkey.Length < Cose.MLDSA65_PUB_SIZE + 32)
                {
                    throw new NaalpException("BadSignature", "composite public key too short");
                }
                byte[] mldsaPub = new byte[Cose.MLDSA65_PUB_SIZE];
                Array.Copy(pubkey, 0, mldsaPub, 0, Cose.MLDSA65_PUB_SIZE);
                byte[] edPub = new byte[pubkey.Length - Cose.MLDSA65_PUB_SIZE];
                Array.Copy(pubkey, Cose.MLDSA65_PUB_SIZE, edPub, 0, edPub.Length);
                if (edPub.Length != 32 || !Cose.CompositeVerify(mldsaPub, edPub, tbs, sig))
                {
                    throw new NaalpException("BadSignature", "composite signature does not verify");
                }
                return o;
            }

            // pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
            if (o.Suite != 0)
            {
                throw new NaalpException("SuiteMismatch", "pure object carries a composite suite field");
            }

            // profile floor + COSE signature (reuse the C2 registry + verifier).
            (int level, bool known) = Cose.AlgLevel(halg);
            if (!known)
            {
                throw new NaalpException("UnknownAlg", "unregistered alg");
            }
            if (level < Cose.ProfileMinLevel(profile))
            {
                throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
            }
            if (!Cose.CoseVerify1Raw(halg, pubkey, tbs, sig))
            {
                throw new NaalpException("BadSignature", "signature does not verify");
            }
            return o;
        }

        // --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) ---

        // The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a
        // Sovereign/High verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT,
        // fail-closed) rather than only the NEW leg. Ratified default = true (matches impl/go).
        public const bool ROTATION_OLD_LEG_FLOOR_APPLIES = true;

        private static bool IsRotationObject(long channel, long kind)
        {
            return channel == 3 && kind == 0;
        }

        private static bool IsCompositeAlg(int alg)
        {
            return alg == Cose.ALG_COMPOSITE_65_ED25519 || alg == Cose.ALG_COMPOSITE_44_ED25519;
        }

        /// <summary>
        /// Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
        /// fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
        /// Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes
        /// are byte-identical to the Go/Rust/Python/TypeScript/Ruby/PHP reference implementations.
        /// </summary>
        public static byte[] SignRotationObject(Object o, int oldAlg, byte[] oldSeed, int newAlg, byte[] newSeed)
        {
            if (!IsRotationObject(o.Channel, o.Kind))
            {
                throw new NaalpException("UnknownKind", "tag-98 permitted only for the Identity Rotation object");
            }
            if (IsCompositeAlg(oldAlg) || IsCompositeAlg(newAlg))
            {
                throw new NaalpException("Malformed", "composite-inside-rotation is undecided");
            }
            o.Suite = 0; // a rotation object is never composite
            o.Id = o.ContentId();
            byte[] payload = Cbor.Encode(o.BodyMap(true));
            byte[] bodyProt = ProtectedHeader(newAlg, o.Signer, o.Profile);
            byte[][] oldLeg = Cose.SignatureLeg(bodyProt, oldAlg, oldSeed, payload);
            byte[][] newLeg = Cose.SignatureLeg(bodyProt, newAlg, newSeed, payload);
            return Cose.AssembleSignRaw(bodyProt, payload, new List<byte[][]> { oldLeg, newLeg });
        }

        /// <summary>
        /// Verify a tag-98 Rotation object (§5.2): the same object-body checks as Verify(), then EXACTLY
        /// two legs in fixed order (old-key then new-key) BOTH verifying. Any missing/wrong/bad old leg
        /// is RotationUnauthorized. Permitted ONLY for (channel 3, kind 0).
        /// </summary>
        public static Object VerifyRotationObject(int profile, int oldAlg, byte[] oldPk, int newAlg, byte[] newPk,
            KindValidator? kindValidator, byte[] objBytes, HashSet<long>? knownCext = null)
        {
            // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
            // object too, so it is size-checked on raw bytes before any parse.
            if (objBytes.Length > MaxObjectSize)
            {
                throw new NaalpException("TooLarge", "object exceeds the maximum octet size (§3.4, R7)");
            }
            knownCext ??= new HashSet<long>();
            byte[] bodyProt;
            byte[] payload;
            List<byte[][]> legs;
            try
            {
                (bodyProt, payload, legs) = Cose.ParseSignRaw(objBytes);
            }
            catch (NaalpException)
            {
                throw new NaalpException("Malformed", "not a COSE_Sign object");
            }

            Cbor.Value bv = Cbor.DecodeBounded(payload, (int)MaxNestingDepth);
            if (!(bv is Cbor.M bodyMap))
            {
                throw new NaalpException("Malformed", "body not a map");
            }

            byte[]? claimed = null;
            var without = new List<Cbor.Pair>(bodyMap.Pairs.Count);
            foreach (Cbor.Pair p in bodyMap.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == FieldId)
                {
                    if (!(p.Val is Cbor.B idb))
                    {
                        throw new NaalpException("Malformed", "id not a bstr");
                    }
                    claimed = idb.V;
                    continue;
                }
                without.Add(p);
            }
            if (claimed == null)
            {
                throw new NaalpException("Malformed", "no content id");
            }
            if (!BytesEqual(Cbor.ContentId(new Cbor.M(without)), claimed))
            {
                throw new NaalpException("ContentIdMismatch", "recomputed id differs");
            }

            Object o = ObjectFromMap(bodyMap);
            if (o.Channel > 19 || o.Effect > 3 || o.Profile < 1 || o.Profile > 3)
            {
                throw new NaalpException("RangeError", "field out of range");
            }

            ParseProtected(bodyProt, out int halg, out byte[] hsigner, out long hprofile, out long hversion);
            if (hversion != NaalpVersion)
            {
                throw new NaalpException("UnsupportedVersion", "bad naalp-version");
            }
            if (!BytesEqual(hsigner, o.Signer) || hprofile != o.Profile)
            {
                throw new NaalpException("HeaderBodyMismatch", "protected header disagrees with body");
            }
            CheckCext(o.Cext, knownCext);

            // tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
            if (!IsRotationObject(o.Channel, o.Kind))
            {
                throw new NaalpException("UnknownKind", "tag-98 permitted only for the Identity Rotation object");
            }
            if (kindValidator == null || !kindValidator(o.Channel, o.Kind))
            {
                throw new NaalpException("UnknownKind", "kind/channel not a registered surface");
            }
            if (IsCompositeAlg(halg))
            {
                throw new NaalpException("Malformed", "composite-inside-rotation is undecided");
            }
            if (halg != newAlg)
            {
                throw new NaalpException("KeyAlgMismatch", "body header alg is not the new key alg");
            }

            // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
            if (legs.Count != 2)
            {
                throw new NaalpException("RotationUnauthorized", "rotation must carry exactly two legs");
            }
            int oldLegAlg = Cose.AlgFromProtected(legs[0][0]);
            int newLegAlg = Cose.AlgFromProtected(legs[1][0]);
            if (IsCompositeAlg(oldLegAlg) || IsCompositeAlg(newLegAlg))
            {
                throw new NaalpException("Malformed", "composite leg in a rotation");
            }
            if (oldLegAlg != oldAlg || newLegAlg != newAlg)
            {
                throw new NaalpException("RotationUnauthorized", "legs not in (old, new) order");
            }

            // profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
            (int newLevel, bool nknown) = Cose.AlgLevel(newLegAlg);
            if (!nknown)
            {
                throw new NaalpException("UnknownAlg", "unregistered alg");
            }
            if (newLevel < Cose.ProfileMinLevel(profile))
            {
                throw new NaalpException("ProfileDowngrade", "new-leg level below the profile minimum");
            }
            if (ROTATION_OLD_LEG_FLOOR_APPLIES)
            {
                (int oldLevel, bool oknown) = Cose.AlgLevel(oldLegAlg);
                if (!oknown)
                {
                    throw new NaalpException("UnknownAlg", "unregistered alg");
                }
                if (oldLevel < Cose.ProfileMinLevel(profile))
                {
                    throw new NaalpException("ProfileDowngrade", "old-leg level below the profile minimum");
                }
            }

            // both legs MUST verify over their per-signer ToBeSigned.
            byte[] oldTbs = Cose.SignatureToBeSigned(bodyProt, oldLegAlg, payload);
            if (!Cose.CoseVerify1Raw(oldLegAlg, oldPk, oldTbs, legs[0][1]))
            {
                throw new NaalpException("RotationUnauthorized", "old leg does not verify");
            }
            byte[] newTbs = Cose.SignatureToBeSigned(bodyProt, newLegAlg, payload);
            if (!Cose.CoseVerify1Raw(newLegAlg, newPk, newTbs, legs[1][1]))
            {
                throw new NaalpException("RotationUnauthorized", "new leg does not verify");
            }
            return o;
        }
    }
}
