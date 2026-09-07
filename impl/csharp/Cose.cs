// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Naalp
{
    /// <summary>
    /// N-AALP C2 signing layer for the C# SDK: the COSE_Sign1 (RFC 9052) signing-input and object
    /// assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).
    ///
    /// <para>The deterministic ML-DSA path uses BouncyCastle's <c>MLDsaSigner(params, deterministic:
    /// true)</c>, so the FIPS 204 <c>rnd</c> stays 32 zero bytes — byte-identical to the Go (CIRCL),
    /// Rust (fips204), Python (dilithium-py) and Java (Bouncy Castle) reference implementations. Key
    /// material is derived from the 32-byte NIST seed (xi) via
    /// <c>MLDsaPrivateKeyParameters.FromSeed</c>, so the public key equals the NIST ACVP keyGen
    /// vector.</para>
    /// </summary>
    public static class Cose
    {
        public const int ALG_MLDSA65 = -49;
        public const int ALG_MLDSA87 = -50;
        public const int ALG_ED25519 = -19;

        public const int PROFILE_PUBLIC = 1;
        public const int PROFILE_ENTERPRISE = 2;
        public const int PROFILE_SOVEREIGN = 3;

        public const long TAG_SIGN1 = 18;

        /// <summary>
        /// The NIST security level of a registered signature algorithm, and whether it is registered
        /// (§2.2). ML-DSA-87 is level 5, ML-DSA-65 is level 3; Ed25519 is classical (level 0), valid
        /// only as a hybrid leg. The boolean is false for any unregistered alg (level then reads 0).
        /// </summary>
        public static (int Level, bool Known) AlgLevel(int alg)
        {
            switch (alg)
            {
                case ALG_MLDSA87:
                    return (5, true);
                case ALG_MLDSA65:
                    return (3, true);
                case ALG_ED25519:
                    return (0, true);
                default:
                    return (0, false);
            }
        }

        /// <summary>
        /// The minimum signature level a profile accepts (§2.2): Sovereign floors at level 5, every
        /// other profile at level 3. A signature below the floor is a ProfileDowngrade.
        /// </summary>
        public static int ProfileMinLevel(int profile)
        {
            return profile == PROFILE_SOVEREIGN ? 5 : 3;
        }

        /// <summary>The RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header.</summary>
        public static byte[] ToBeSignedRaw(byte[] protectedHeader, byte[] payload)
        {
            return Cbor.Encode(new Cbor.A(new List<Cbor.Value>
            {
                new Cbor.T("Signature1"),
                new Cbor.B(protectedHeader),
                new Cbor.B(Array.Empty<byte>()),
                new Cbor.B(payload),
            }));
        }

        /// <summary>The tagged COSE_Sign1 object: 18([protected, {}, payload, signature]).</summary>
        public static byte[] AssembleSign1Raw(byte[] protectedHeader, byte[] payload, byte[] sig)
        {
            return Cbor.Encode(new Cbor.Tag(TAG_SIGN1, new Cbor.A(new List<Cbor.Value>
            {
                new Cbor.B(protectedHeader),
                new Cbor.M(new List<Cbor.Pair>()),
                new Cbor.B(payload),
                new Cbor.B(sig),
            })));
        }

        /// <summary>Recover [protected, payload, sig] from a tagged COSE_Sign1 object.</summary>
        public static byte[][] ParseSign1Raw(byte[] obj)
        {
            Cbor.Value v = Cbor.Decode(obj);
            if (!(v is Cbor.Tag tag) || tag.N != TAG_SIGN1 || !(tag.Content is Cbor.A arr))
            {
                throw new NaalpException("Malformed", "not a tagged COSE_Sign1");
            }
            List<Cbor.Value> items = arr.Items;
            if (items.Count != 4
                || !(items[0] is Cbor.B p)
                || !(items[2] is Cbor.B pl)
                || !(items[3] is Cbor.B s))
            {
                throw new NaalpException("Malformed", "malformed COSE_Sign1 array");
            }
            return new byte[][] { p.V, pl.V, s.V };
        }

        // --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

        public const long TAG_SIGN = 98;

        /// <summary>One COSE_Signature protected header: {1: alg} (RFC 9052 §4).</summary>
        public static byte[] LegProtected(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        /// <summary>
        /// The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
        /// det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note
        /// the five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
        /// "Signature1" of a COSE_Sign1.
        /// </summary>
        public static byte[] SignatureToBeSigned(byte[] bodyProt, int signerAlg, byte[] payload)
        {
            return Cbor.Encode(new Cbor.A(new List<Cbor.Value>
            {
                new Cbor.T("Signature"),
                new Cbor.B(bodyProt),
                new Cbor.B(LegProtected(signerAlg)),
                new Cbor.B(Array.Empty<byte>()),
                new Cbor.B(payload),
            }));
        }

        /// <summary>Build one COSE_Signature leg: [leg_protected_bytes, signature_bytes].</summary>
        public static byte[][] SignatureLeg(byte[] bodyProt, int alg, byte[] seed, byte[] payload)
        {
            byte[] sprot = LegProtected(alg);
            byte[] sig = MldsaSign(alg, seed, SignatureToBeSigned(bodyProt, alg, payload));
            return new byte[][] { sprot, sig };
        }

        /// <summary>The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]).</summary>
        public static byte[] AssembleSignRaw(byte[] bodyProt, byte[] payload, List<byte[][]> legs)
        {
            var sigArr = new List<Cbor.Value>();
            foreach (byte[][] leg in legs)
            {
                sigArr.Add(new Cbor.A(new List<Cbor.Value>
                {
                    new Cbor.B(leg[0]),
                    new Cbor.M(new List<Cbor.Pair>()),
                    new Cbor.B(leg[1]),
                }));
            }
            return Cbor.Encode(new Cbor.Tag(TAG_SIGN, new Cbor.A(new List<Cbor.Value>
            {
                new Cbor.B(bodyProt),
                new Cbor.M(new List<Cbor.Pair>()),
                new Cbor.B(payload),
                new Cbor.A(sigArr),
            })));
        }

        /// <summary>Recover (body_prot, payload, legs[(sprot, sig)]) from a tagged COSE_Sign object.</summary>
        public static (byte[] BodyProt, byte[] Payload, List<byte[][]> Legs) ParseSignRaw(byte[] obj)
        {
            Cbor.Value v = Cbor.Decode(obj);
            if (!(v is Cbor.Tag tag) || tag.N != TAG_SIGN || !(tag.Content is Cbor.A arr))
            {
                throw new NaalpException("Malformed", "not a tagged COSE_Sign");
            }
            List<Cbor.Value> items = arr.Items;
            if (items.Count != 4 || !(items[0] is Cbor.B bp) || !(items[2] is Cbor.B pl) || !(items[3] is Cbor.A sigs))
            {
                throw new NaalpException("Malformed", "malformed COSE_Sign array");
            }
            var legs = new List<byte[][]>();
            foreach (Cbor.Value sv in sigs.Items)
            {
                if (!(sv is Cbor.A e) || e.Items.Count != 3 || !(e.Items[0] is Cbor.B sprot) || !(e.Items[2] is Cbor.B lsig))
                {
                    throw new NaalpException("Malformed", "malformed COSE_Signature leg");
                }
                legs.Add(new byte[][] { sprot.V, lsig.V });
            }
            return (bp.V, pl.V, legs);
        }

        /// <summary>Extract the alg (label 1) value from a serialized leg protected header {1: alg}.</summary>
        public static int AlgFromProtected(byte[] prot)
        {
            // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a
            // bstr wrapping an empty map; its unwrapped content is the single byte 0xA0) as
            // NonCanonical, before interpreting the header — the empty protected header is pinned
            // to 0x40.
            if (prot.Length == 1 && prot[0] == 0xA0)
            {
                throw new NaalpException("NonCanonical",
                    "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)");
            }
            Cbor.Value v = Cbor.Decode(prot);
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("Malformed", "protected header not a map");
            }
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == 1 && p.Val is Cbor.N nv)
                {
                    return (int)nv.V;
                }
            }
            throw new NaalpException("Malformed", "no alg in protected header");
        }

        // --- ML-DSA (FIPS 204) via BouncyCastle ---

        private static MLDsaParameters MldsaParams(int alg)
        {
            if (alg == ALG_MLDSA65)
            {
                return MLDsaParameters.ml_dsa_65;
            }
            if (alg == ALG_MLDSA87)
            {
                return MLDsaParameters.ml_dsa_87;
            }
            throw new NaalpException("UnknownAlg", "alg " + alg + " is not an ML-DSA algorithm");
        }

        /// <summary>Derive the public key from a 32-byte seed (NIST ACVP keyGen); returns pk bytes.</summary>
        public static byte[] MldsaKeygen(string param, byte[] seed)
        {
            MLDsaParameters p = param == "ML-DSA-87" ? MLDsaParameters.ml_dsa_87 : MLDsaParameters.ml_dsa_65;
            if (seed.Length != 32)
            {
                throw new NaalpException("Malformed", "ML-DSA seed must be 32 bytes");
            }
            MLDsaPrivateKeyParameters sk = MLDsaPrivateKeyParameters.FromSeed(p, seed);
            return sk.GetPublicKeyEncoded();
        }

        /// <summary>Deterministic (rnd=0) ML-DSA signature over tbs with the key derived from seed.</summary>
        public static byte[] MldsaSign(int alg, byte[] seed, byte[] tbs)
        {
            MLDsaParameters p = MldsaParams(alg);
            if (seed.Length != 32)
            {
                throw new NaalpException("Malformed", "ML-DSA seed must be 32 bytes");
            }
            MLDsaPrivateKeyParameters sk = MLDsaPrivateKeyParameters.FromSeed(p, seed);
            var signer = new MLDsaSigner(p, deterministic: true); // rnd = 32 zero bytes
            signer.Init(true, sk);
            signer.BlockUpdate(tbs, 0, tbs.Length);
            return signer.GenerateSignature();
        }

        public static bool MldsaVerify(int alg, byte[] pk, byte[] tbs, byte[] sig)
        {
            MLDsaParameters p = MldsaParams(alg);
            MLDsaPublicKeyParameters pub = MLDsaPublicKeyParameters.FromEncoding(p, pk);
            var signer = new MLDsaSigner(p, deterministic: true);
            signer.Init(false, pub);
            signer.BlockUpdate(tbs, 0, tbs.Length);
            return signer.VerifySignature(sig);
        }

        // --- Ed25519 (RFC 8032) via BouncyCastle ---

        public static byte[] Ed25519Sign(byte[] seed, byte[] msg)
        {
            if (seed.Length != 32)
            {
                throw new NaalpException("Malformed", "ed25519 secret key must be a 32-byte seed");
            }
            var priv = new Ed25519PrivateKeyParameters(seed, 0);
            var signer = new Ed25519Signer();
            signer.Init(true, priv);
            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.GenerateSignature();
        }

        public static bool Ed25519Verify(byte[] pk, byte[] msg, byte[] sig)
        {
            if (pk.Length != 32)
            {
                return false;
            }
            var pub = new Ed25519PublicKeyParameters(pk, 0);
            var signer = new Ed25519Signer();
            signer.Init(false, pub);
            signer.BlockUpdate(msg, 0, msg.Length);
            return signer.VerifySignature(sig);
        }

        /// <summary>Derive the 32-byte Ed25519 public key from a 32-byte seed (RFC 8032 secret key
        /// clamping + scalar-basepoint multiplication, via BouncyCastle's key-pair derivation).</summary>
        public static byte[] Ed25519PublicKeyFromSeed(byte[] seed)
        {
            if (seed.Length != 32)
            {
                throw new NaalpException("Malformed", "ed25519 secret key must be a 32-byte seed");
            }
            var priv = new Ed25519PrivateKeyParameters(seed, 0);
            return priv.GeneratePublicKey().GetEncoded();
        }

        // --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

        public const int ALG_COMPOSITE_65_ED25519 = -65537; // COMPSIG-MLDSA65-Ed25519-SHA512
        public const int ALG_COMPOSITE_44_ED25519 = -65538; // edge; RESERVED, not implemented
        private static readonly byte[] COMPOSITE_PREFIX =
            System.Text.Encoding.ASCII.GetBytes("CompositeAlgorithmSignatures2025");
        private static readonly byte[] COMPOSITE_LABEL_MLDSA65_ED25519 =
            System.Text.Encoding.ASCII.GetBytes("COMPSIG-MLDSA65-Ed25519-SHA512");
        private const int MLDSA65_SIG_SIZE = 3309;   // FIPS 204 ML-DSA-65 signature size
        public const int MLDSA65_PUB_SIZE = 1952;    // FIPS 204 ML-DSA-65 pubkey size (split point)

        /// <summary>
        /// The LAMPS composite message representative M' = Prefix || Label || len(ctx) || ctx ||
        /// SHA-512(M) (§4.2). len(ctx) is a single length octet; the N-AALP composite context is
        /// empty, so the octet is 0x00. Both legs sign this same M'.
        /// </summary>
        public static byte[] ComputeMprime(byte[] label, byte[] ctx, byte[] m)
        {
            if (ctx.Length > 255)
            {
                throw new NaalpException("Malformed", "composite context exceeds one length octet");
            }
            byte[] h;
            using (var sha = System.Security.Cryptography.SHA512.Create())
            {
                h = sha.ComputeHash(m);
            }
            byte[] outp = new byte[COMPOSITE_PREFIX.Length + label.Length + 1 + ctx.Length + h.Length];
            int o = 0;
            Array.Copy(COMPOSITE_PREFIX, 0, outp, o, COMPOSITE_PREFIX.Length);
            o += COMPOSITE_PREFIX.Length;
            Array.Copy(label, 0, outp, o, label.Length);
            o += label.Length;
            outp[o++] = (byte)ctx.Length;               // len(ctx) as a single length octet
            Array.Copy(ctx, 0, outp, o, ctx.Length);
            o += ctx.Length;
            Array.Copy(h, 0, outp, o, h.Length);
            return outp;
        }

        /// <summary>
        /// The LAMPS composite signature value over the COSE ToBeSigned <paramref name="tbs"/>:
        /// mldsaSig || tradSig (ML-DSA-65 first, raw concatenation; §4.2). The ML-DSA leg is
        /// deterministic (rnd=0) with context = the suite Label octets (ParametersWithContext); the
        /// Ed25519 leg signs M' with no context.
        /// </summary>
        public static byte[] CompositeSign(byte[] mldsaSeed, byte[] edSeed, byte[] tbs)
        {
            if (mldsaSeed.Length != 32)
            {
                throw new NaalpException("Malformed", "ML-DSA seed must be 32 bytes");
            }
            byte[] mprime = ComputeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, Array.Empty<byte>(), tbs);
            MLDsaPrivateKeyParameters sk = MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, mldsaSeed);
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
            signer.Init(true, new ParametersWithContext(sk, COMPOSITE_LABEL_MLDSA65_ED25519));
            signer.BlockUpdate(mprime, 0, mprime.Length);
            byte[] mldsaSig = signer.GenerateSignature();
            byte[] tradSig = Ed25519Sign(edSeed, mprime);
            byte[] outp = new byte[mldsaSig.Length + tradSig.Length];
            Array.Copy(mldsaSig, 0, outp, 0, mldsaSig.Length);   // ML-DSA first (LAMPS order)
            Array.Copy(tradSig, 0, outp, mldsaSig.Length, tradSig.Length);
            return outp;
        }

        /// <summary>
        /// Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context)
        /// validate over M'. A value of the wrong length is malformed and rejected. A stripped or
        /// re-interpreted lone leg has no valid composite because M' binds both components
        /// (RFC 9955; §4.2/§4.5).
        /// </summary>
        public static bool CompositeVerify(byte[] mldsaPk, byte[] edPk, byte[] m, byte[] sig)
        {
            if (sig.Length != MLDSA65_SIG_SIZE + 64)
            {
                return false;
            }
            byte[] mprime = ComputeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, Array.Empty<byte>(), m);
            MLDsaPublicKeyParameters pub = MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, mldsaPk);
            var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
            signer.Init(false, new ParametersWithContext(pub, COMPOSITE_LABEL_MLDSA65_ED25519));
            signer.BlockUpdate(mprime, 0, mprime.Length);
            byte[] mldsaSigPart = new byte[MLDSA65_SIG_SIZE];
            Array.Copy(sig, 0, mldsaSigPart, 0, MLDSA65_SIG_SIZE);
            bool mldsaOk = signer.VerifySignature(mldsaSigPart);
            byte[] edSigPart = new byte[sig.Length - MLDSA65_SIG_SIZE];
            Array.Copy(sig, MLDSA65_SIG_SIZE, edSigPart, 0, edSigPart.Length);
            bool edOk = Ed25519Verify(edPk, mprime, edSigPart);
            return mldsaOk && edOk;
        }

        /// <summary>Produce a deterministic tagged COSE_Sign1 object over (protected, payload).</summary>
        public static byte[] CoseSign1(int alg, byte[] seed, byte[] protectedHeader, byte[] payload)
        {
            byte[] tbs = ToBeSignedRaw(protectedHeader, payload);
            byte[] sig = MldsaSign(alg, seed, tbs);
            return AssembleSign1Raw(protectedHeader, payload, sig);
        }

        /// <summary>
        /// Verify a raw signature over already-assembled ToBeSigned bytes, dispatching by alg. This is
        /// the surface the C3 envelope verifier calls once it has recomputed the Sig_structure.
        /// </summary>
        public static bool CoseVerify1Raw(int alg, byte[] pk, byte[] tbs, byte[] sig)
        {
            if (alg == ALG_MLDSA65 || alg == ALG_MLDSA87)
            {
                return MldsaVerify(alg, pk, tbs, sig);
            }
            if (alg == ALG_ED25519)
            {
                return Ed25519Verify(pk, tbs, sig);
            }
            throw new NaalpException("UnknownAlg", "unknown alg " + alg);
        }

        public static bool CoseVerify1(int alg, byte[] pk, byte[] obj)
        {
            byte[][] parts = ParseSign1Raw(obj);
            byte[] tbs = ToBeSignedRaw(parts[0], parts[1]);
            return CoseVerify1Raw(alg, pk, tbs, parts[2]);
        }
    }
}
