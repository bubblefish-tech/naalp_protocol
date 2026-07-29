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
    public static class Envelope
    {
        // object body field numbers (§2.1)
        public const int FieldId = 1;
        public const int FieldKind = 2;
        public const int FieldChannel = 3;
        public const int FieldTier = 4;
        public const int FieldSigner = 5;
        public const int FieldCreated = 6;
        public const int FieldEffect = 7;
        public const int FieldCauses = 8;
        public const int FieldProfile = 9;
        public const int FieldBody = 10;
        public const int FieldExt = 11;
        public const int FieldCext = 12;

        public const int NaalpVersion = 1;
        private const string HeaderLabel = "naalp";

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

            public Object(long kind, long channel, byte[] signer, long created, long effect,
                Cbor.Value body, long tier = 0, long profile = Cose.PROFILE_PUBLIC,
                List<byte[]>? causes = null, Cbor.M? ext = null, Cbor.M? cext = null)
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

        private static void ParseProtected(byte[] prot, out int alg, out byte[] signer,
            out long profile, out long version)
        {
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
            var causes = new List<byte[]>();
            foreach (Cbor.Value c in NeedA(FieldCauses).Items)
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
                ext = em;
            }
            if (fields.TryGetValue(FieldCext, out Cbor.Value? cextV))
            {
                if (!(cextV is Cbor.M cm))
                {
                    throw new NaalpException("Malformed", "cext not a map");
                }
                cext = cm;
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
                cext: cext);
            o.Id = (fields.TryGetValue(FieldId, out Cbor.Value? idV) && idV is Cbor.B idB) ? idB.V : null;
            return o;
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

            Cbor.Value bv = Cbor.Decode(payload); // throws NonCanonical on a non-canonical body
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

            // critical extensions: any unrecognized key rejects (§2.5, R-2.5).
            if (o.Cext != null)
            {
                foreach (Cbor.Pair p in o.Cext.Pairs)
                {
                    if (!(p.K is Cbor.U ck) || !knownCext.Contains(ck.V))
                    {
                        throw new NaalpException("UnknownCriticalExt", "unrecognized critical extension");
                    }
                }
            }

            // kind/channel surface dispatch (UnknownKind, §2.6).
            if (kindValidator == null || !kindValidator(o.Channel, o.Kind))
            {
                throw new NaalpException("UnknownKind", "kind/channel not a registered surface");
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
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            if (!Cose.CoseVerify1Raw(halg, pubkey, tbs, sig))
            {
                throw new NaalpException("BadSignature", "signature does not verify");
            }
            return o;
        }
    }
}
