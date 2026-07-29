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
