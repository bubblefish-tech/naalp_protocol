// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Text;

namespace Naalp
{
    /// <summary>Lowercase, no-separator hex encode/decode (the wire byte-field encoding).</summary>
    public static class Hex
    {
        private const string Digits = "0123456789abcdef";

        /// <summary>Encode bytes to lowercase hex.</summary>
        public static string Encode(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                sb.Append(Digits[(b >> 4) & 0xF]);
                sb.Append(Digits[b & 0xF]);
            }
            return sb.ToString();
        }

        /// <summary>Decode a hex string (any case) to bytes.</summary>
        public static byte[] Decode(string s)
        {
            if (s == null)
            {
                throw new NaalpException("Malformed", "hex string is null");
            }
            if ((s.Length & 1) != 0)
            {
                throw new NaalpException("Malformed", "hex string has odd length");
            }
            byte[] outp = new byte[s.Length / 2];
            for (int i = 0; i < outp.Length; i++)
            {
                outp[i] = (byte)((Nibble(s[2 * i]) << 4) | Nibble(s[2 * i + 1]));
            }
            return outp;
        }

        private static int Nibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new NaalpException("Malformed", "invalid hex character '" + c + "'");
        }
    }
}
