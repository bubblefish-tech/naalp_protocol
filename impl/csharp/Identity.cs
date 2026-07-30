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
    }
}
