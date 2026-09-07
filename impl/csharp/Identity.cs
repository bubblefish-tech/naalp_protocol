// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Naalp
{
    /// <summary>
    /// N-AALP C4 identity for the C# SDK: the self-certifying signer id (§5.1) and the NFC rule.
    ///
    /// <para>signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
    /// identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats registry:
    /// ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12. The
    /// multibase prefix is 'b' (base32 lowercase, no padding).</para>
    /// </summary>
    public static class Identity
    {
        private const int MH_SHA256 = 0x12;
        private static readonly char[] B32 = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();

        private static int Multicodec(int alg)
        {
            switch (alg)
            {
                case Cose.ALG_ED25519:
                    return 0xED;
                case Cose.ALG_MLDSA65:
                    return 0x1211;
                case Cose.ALG_MLDSA87:
                    return 0x1212;
                default:
                    throw new NaalpException("UnknownAlg", "no multicodec for alg " + alg);
            }
        }

        /// <summary>LEB128 unsigned varint.</summary>
        internal static byte[] Uvarint(int n)
        {
            var outp = new MemoryStream();
            ulong v = (uint)n;
            while (true)
            {
                int b = (int)(v & 0x7F);
                v >>= 7;
                if (v != 0)
                {
                    outp.WriteByte((byte)(b | 0x80));
                }
                else
                {
                    outp.WriteByte((byte)b);
                    break;
                }
            }
            return outp.ToArray();
        }

        /// <summary>Base32 (RFC 4648) lowercase, no padding.</summary>
        internal static string Base32NoPad(byte[] data)
        {
            var sb = new StringBuilder();
            uint buffer = 0;
            int bits = 0;
            foreach (byte bb in data)
            {
                buffer = (buffer << 8) | (uint)(bb & 0xFF);
                bits += 8;
                while (bits >= 5)
                {
                    bits -= 5;
                    sb.Append(B32[(int)((buffer >> bits) & 0x1F)]);
                }
            }
            if (bits > 0)
            {
                sb.Append(B32[(int)((buffer << (5 - bits)) & 0x1F)]);
            }
            return sb.ToString();
        }

        /// <summary>The self-certifying signer id for (alg, pubkey).</summary>
        public static string SignerId(int alg, byte[] pubkey)
        {
            int mc = Multicodec(alg);
            byte[] mcv = Uvarint(mc);
            byte[] tagged = new byte[mcv.Length + pubkey.Length];
            Array.Copy(mcv, 0, tagged, 0, mcv.Length);
            Array.Copy(pubkey, 0, tagged, mcv.Length, pubkey.Length);
            byte[] digest;
            using (var sha = SHA256.Create())
            {
                digest = sha.ComputeHash(tagged);
            }
            byte[] mhCode = Uvarint(MH_SHA256);
            byte[] mhLen = Uvarint(digest.Length);
            byte[] mh = new byte[mhCode.Length + mhLen.Length + digest.Length];
            Array.Copy(mhCode, 0, mh, 0, mhCode.Length);
            Array.Copy(mhLen, 0, mh, mhCode.Length, mhLen.Length);
            Array.Copy(digest, 0, mh, mhCode.Length + mhLen.Length, digest.Length);
            return "b" + Base32NoPad(mh);
        }

        public static void CheckSigner(string claimed, int alg, byte[] pubkey)
        {
            if (SignerId(alg, pubkey) != claimed)
            {
                throw new NaalpException("SignerMismatch", "signer id does not recompute from the key");
            }
        }

        /// <summary>
        /// The self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
        /// multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public
        /// key — using only existing official multicodecs (no minted code) — so stripping or
        /// substituting either leg changes the id (=> SignerMismatch before verify).
        /// Downgrade-resistant, byte-identical to the Java/Go/Python/Ruby/PHP ports.
        /// </summary>
        public static string CompositeSignerId(int mldsaAlg, byte[] mldsaPub, byte[] edPub)
        {
            if (mldsaAlg != Cose.ALG_MLDSA65 && mldsaAlg != Cose.ALG_MLDSA87)
            {
                throw new NaalpException("UnknownAlg", "composite signer id requires an ML-DSA alg, got " + mldsaAlg);
            }
            byte[] mcMl = Uvarint(Multicodec(mldsaAlg));
            byte[] mcEd = Uvarint(Multicodec(Cose.ALG_ED25519));
            byte[] preimage = new byte[mcMl.Length + mldsaPub.Length + mcEd.Length + edPub.Length];
            int o = 0;
            Array.Copy(mcMl, 0, preimage, o, mcMl.Length); o += mcMl.Length;
            Array.Copy(mldsaPub, 0, preimage, o, mldsaPub.Length); o += mldsaPub.Length;
            Array.Copy(mcEd, 0, preimage, o, mcEd.Length); o += mcEd.Length;
            Array.Copy(edPub, 0, preimage, o, edPub.Length);
            byte[] digest;
            using (var sha = SHA256.Create())
            {
                digest = sha.ComputeHash(preimage);
            }
            byte[] mhCode = Uvarint(MH_SHA256);
            byte[] mhLen = Uvarint(digest.Length);
            byte[] mh = new byte[mhCode.Length + mhLen.Length + digest.Length];
            Array.Copy(mhCode, 0, mh, 0, mhCode.Length);
            Array.Copy(mhLen, 0, mh, mhCode.Length, mhLen.Length);
            Array.Copy(digest, 0, mh, mhCode.Length + mhLen.Length, digest.Length);
            return "b" + Base32NoPad(mh);
        }

        /// <summary>Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3).</summary>
        /// <remarks>
        /// Fails closed if the runtime cannot perform Unicode normalization. Under .NET
        /// globalization-invariant mode ICU is disabled and <see cref="string.IsNormalized(NormalizationForm)"/>
        /// degrades to a no-op that returns <c>true</c> for every input — which would silently accept
        /// a non-NFC string (a fail-open on a security-relevant check). We first confirm real
        /// normalization is available via a known decomposition (U+00C5 &lt;-&gt; "A" + U+030A); if that
        /// round-trip is inert or throws, the runtime cannot enforce NFC and we reject.
        /// </remarks>
        public static void RequireNfc(string s)
        {
            bool normalizationWorks;
            try
            {
                normalizationWorks = ("A" + (char)0x030A).Normalize(NormalizationForm.FormC) == ((char)0x00C5).ToString();
            }
            catch
            {
                normalizationWorks = false;
            }
            if (!normalizationWorks)
            {
                throw new NaalpException(
                    "NonNFC",
                    "Unicode normalization is unavailable (globalization-invariant runtime); cannot verify NFC");
            }
            if (!s.IsNormalized(NormalizationForm.FormC))
            {
                throw new NaalpException("NonNFC", "string is not Unicode NFC");
            }
        }

        /// <summary>Decode a UTF-8 byte payload to a string (matches the adapter's utf8_hex handling).</summary>
        public static string Utf8(byte[] b)
        {
            return new UTF8Encoding(false, false).GetString(b);
        }

        // ---- key rotation (design §5.2): the ADDITIVE C4 co-signed old->new primitive ---------
        //
        // The self-certifying signer id survives a key rotation: a RotationRecord binds the old id to
        // the new id from a not_before position, co-signed by BOTH keys, so attribution to the durable
        // identity is preserved across rotation (R-1.4). This is the C4 primitive the Delivery-Model-B
        // principal registry (Rooms.PrincipalRegistry) composes on for a rotation-authorised rebind.
        // Purely additive: it introduces no new envelope, encoding, or signature mechanism — the
        // rotation body is deterministic CBOR and each leg is a raw deterministic ML-DSA signature over
        // that body, byte-identical to the Go (impl/go/identity) and Python (impl/python/naalp/identity)
        // reference implementations.

        /// <summary>Links an old signer id to a new one from <c>NotBefore</c> (§5.2). Its signed bytes
        /// are the deterministic-CBOR map {1: old, 2: new, 3: not_before}, byte-identical to the Go and
        /// Python references.</summary>
        public sealed class RotationRecord
        {
            public readonly string Old;
            public readonly string New;
            public readonly long NotBefore;

            public RotationRecord(string old, string @new, long notBefore)
            {
                Old = old;
                New = @new;
                NotBefore = notBefore;
            }

            /// <summary>The deterministic-CBOR rotation body {1: old, 2: new, 3: not_before}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new System.Collections.Generic.List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Old)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(New)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(NotBefore)),
                }));
            }
        }

        /// <summary>Co-sign a rotation with BOTH the old and new keys (§5.2): each leg is a raw
        /// deterministic ML-DSA signature over the rotation body. Returns (oldSig, newSig).</summary>
        public static (byte[] OldSig, byte[] NewSig) SignRotation(RotationRecord r, int alg, byte[] oldSeed, byte[] newSeed)
        {
            byte[] m = r.Bytes();
            return (Cose.MldsaSign(alg, oldSeed, m), Cose.MldsaSign(alg, newSeed, m));
        }

        /// <summary>Confirm a rotation is authorized (§5.2, §5.5): the old and new keys derive the ids
        /// in the record AND both signatures verify. Any failure — an id that does not recompute from
        /// its key, an unregistered algorithm, or a signature that does not verify — collapses to a
        /// single RotationUnauthorized error (fail-closed), exactly as the Go and Python references do.
        /// A substitution not co-signed by the old key cannot pass, so the durable id cannot be
        /// hijacked to an unrelated key.</summary>
        public static void VerifyRotation(RotationRecord r, int oldAlg, byte[] oldPub, int newAlg, byte[] newPub, byte[] oldSig, byte[] newSig)
        {
            try
            {
                if (SignerId(oldAlg, oldPub) != r.Old)
                {
                    throw new NaalpException("RotationUnauthorized", "old key does not derive the record's old id");
                }
                if (SignerId(newAlg, newPub) != r.New)
                {
                    throw new NaalpException("RotationUnauthorized", "new key does not derive the record's new id");
                }
            }
            catch (NaalpException e) when (e.Kind != "RotationUnauthorized")
            {
                // an unregistered-algorithm rejection (UnknownAlg from SignerId) collapses to
                // RotationUnauthorized — no foreign kind leaks out of this authorization gate.
                throw new NaalpException("RotationUnauthorized", "rotation names an unregistered algorithm");
            }
            byte[] m = r.Bytes();
            if (!Cose.CoseVerify1Raw(oldAlg, oldPub, m, oldSig) || !Cose.CoseVerify1Raw(newAlg, newPub, m, newSig))
            {
                throw new NaalpException("RotationUnauthorized", "a rotation signature does not verify under its key");
            }
        }

        // ---- revocation (design §5.3) -----------------------------------------------------

        /// <summary>Marks a key dead from <c>NotAfter</c> (§5.3). Its signed bytes are the
        /// deterministic-CBOR map {1: key, 2: not_after}, byte-identical to the Go and Rust
        /// references.</summary>
        public sealed class RevocationRecord
        {
            public readonly string Key;
            public readonly long NotAfter;

            public RevocationRecord(string key, long notAfter)
            {
                Key = key;
                NotAfter = notAfter;
            }

            /// <summary>The deterministic-CBOR revocation body {1: key, 2: not_after}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new System.Collections.Generic.List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Key)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(NotAfter)),
                }));
            }
        }

        /// <summary>Confirms a revocation is validly signed (§5.3): by the key it revokes, or by a
        /// deployer-configured recovery key. <paramref name="recoveryIds"/> is the deployer's set of
        /// authorized recovery-key signer ids; a revocation whose signer is neither
        /// <c>r.Key</c> nor a member of <paramref name="recoveryIds"/> is rejected SignerMismatch
        /// (§5.5), fail-closed -- an empty <paramref name="recoveryIds"/> admits only the revoked key
        /// itself. The signer id is recomputed from the presented key and checked BEFORE the
        /// signature (membership before signature, fail-closed), exactly as the Go and Rust
        /// references do.</summary>
        public static void VerifyRevocation(RevocationRecord r, int alg, byte[] pub, byte[] sig, System.Collections.Generic.IReadOnlyList<string> recoveryIds)
        {
            string id = SignerId(alg, pub); // UnknownAlg propagates unchanged (fail-closed)
            bool authorized = id == r.Key;
            if (!authorized && recoveryIds != null)
            {
                foreach (string rid in recoveryIds)
                {
                    if (rid == id)
                    {
                        authorized = true;
                        break;
                    }
                }
            }
            if (!authorized)
            {
                throw new NaalpException("SignerMismatch", "signer id is neither the revoked key nor an authorized recovery key");
            }
            if (!Cose.CoseVerify1Raw(alg, pub, r.Bytes(), sig))
            {
                throw new NaalpException("BadSignature", "signature verification failed");
            }
        }

        /// <summary>Reports whether an object fixed at authoritative position <paramref
        /// name="posTime"/> is after the revocation (KeyRevoked); objects fixed at or before
        /// NotAfter stay valid (§5.3).</summary>
        public static bool RevokedAt(RevocationRecord r, long posTime)
        {
            return posTime > r.NotAfter;
        }

        // ---- foreign-identity linkage (design §5.4) ----------------------------------------

        /// <summary>Cross-signs a foreign identity to a signer id (§5.4). Its signed bytes are the
        /// deterministic-CBOR map {1: controls, 2: foreign_id, 3: not_after}, byte-identical to the
        /// Go and Rust references. It is signed by the FOREIGN identity's key.</summary>
        public sealed class ForeignLinkRecord
        {
            public readonly string Controls;
            public readonly string ForeignId;
            public readonly long NotAfter;

            public ForeignLinkRecord(string controls, string foreignId, long notAfter)
            {
                Controls = controls;
                ForeignId = foreignId;
                NotAfter = notAfter;
            }

            /// <summary>The deterministic-CBOR foreign-link body {1: controls, 2: foreign_id,
            /// 3: not_after}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new System.Collections.Generic.List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Controls)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(ForeignId)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(NotAfter)),
                }));
            }
        }

        /// <summary>Reports whether a foreign-identity link confers linkage at time
        /// <paramref name="now"/>. A non-NFC <c>foreign_id</c> is rejected (NonNFC). An expired link
        /// or a bad cross-signature confers NO linkage but is not itself an error -- it simply does
        /// not link (the object remains valid on its own signature, §5.4/§5.5). It NEVER overrides
        /// the key-derived id.</summary>
        public static bool VerifyForeignLink(ForeignLinkRecord r, int foreignAlg, byte[] foreignPub, byte[] sig, long now)
        {
            RequireNfc(r.ForeignId); // throws NonNFC, checked first
            if (now > r.NotAfter)
            {
                return false; // expired: confers no authority (ignored)
            }
            if (!Cose.CoseVerify1Raw(foreignAlg, foreignPub, r.Bytes(), sig))
            {
                return false; // bad/absent cross-signature: no linkage
            }
            return true;
        }

        // ---- durable identity thread (rotation-surviving attribution, R-1.4) ---------------

        /// <summary>One verified rotation step: the record plus the two keys and their
        /// co-signatures.</summary>
        public sealed class RotationEvidence
        {
            public readonly RotationRecord Record;
            public readonly int OldAlg;
            public readonly byte[] OldPub;
            public readonly int NewAlg;
            public readonly byte[] NewPub;
            public readonly byte[] OldSig;
            public readonly byte[] NewSig;

            public RotationEvidence(RotationRecord record, int oldAlg, byte[] oldPub, int newAlg, byte[] newPub, byte[] oldSig, byte[] newSig)
            {
                Record = record;
                OldAlg = oldAlg;
                OldPub = oldPub;
                NewAlg = newAlg;
                NewPub = newPub;
                OldSig = oldSig;
                NewSig = newSig;
            }
        }

        /// <summary>A durable identity: a root signer id continued by a chain of rotations.</summary>
        public sealed class Thread
        {
            public readonly string Root;    // the id the thread is named by (the first key)
            public readonly string Current; // the id after the latest rotation
            public readonly System.Collections.Generic.List<string> Chain; // root, then each rotated-to id in order

            public Thread(string root, string current, System.Collections.Generic.List<string> chain)
            {
                Root = root;
                Current = current;
                Chain = chain;
            }

            /// <summary>Reports whether an object whose body signer id is <paramref name="signer"/>
            /// belongs to this durable thread (any id in the chain, including a pre-rotation key,
            /// R-1.4).</summary>
            public bool Attributable(string signer)
            {
                foreach (string id in Chain)
                {
                    if (id == signer)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>Verifies an ordered rotation chain and returns the durable identity thread.
        /// Each rotation must be authorized (co-signed) and link the previous <c>new</c> to the
        /// next <c>old</c>; a break yields RotationUnauthorized. A receipt signed under any id in
        /// Chain is attributable to Root, so it stays attributable after rotation
        /// (R-1.4).</summary>
        public static Thread ResolveThread(System.Collections.Generic.IReadOnlyList<RotationEvidence> evs)
        {
            if (evs == null || evs.Count == 0)
            {
                throw new NaalpException("RotationUnauthorized", "empty rotation-evidence chain");
            }
            string root = evs[0].Record.Old;
            var chain = new System.Collections.Generic.List<string> { root };
            string prevNew = root;
            foreach (RotationEvidence e in evs)
            {
                if (e.Record.Old != prevNew)
                {
                    throw new NaalpException("RotationUnauthorized", "rotation chain is not contiguous");
                }
                VerifyRotation(e.Record, e.OldAlg, e.OldPub, e.NewAlg, e.NewPub, e.OldSig, e.NewSig);
                chain.Add(e.Record.New);
                prevNew = e.Record.New;
            }
            return new Thread(root, prevNew, chain);
        }
    }
}
