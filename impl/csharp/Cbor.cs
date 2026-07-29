// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Naalp
{
    /// <summary>
    /// Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
    ///
    /// <para>An independent C# implementation of the same deterministic profile the Go, Rust, Python
    /// and Java reference implementations produce: shortest-form integer heads, no indefinite lengths,
    /// canonical (bytewise-ascending, by encoded key) map ordering, and no duplicate keys. The strict
    /// decoder rejects every non-canonical encoding — out-of-order or duplicate map keys, non-shortest
    /// integers, indefinite lengths, trailing bytes — with a NaalpException of kind NonCanonical. The
    /// content id is multihash(0x20, 0x30, SHA-384(body)) over the deterministic body bytes (§2.3).</para>
    /// </summary>
    public static class Cbor
    {
        // Strict UTF-8: matches Python's str.decode("utf-8") / encode("utf-8") — reject invalid bytes,
        // never emit a BOM.
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);

        // --- value model (mirrors the Go/Rust/Python/Java cbor.Value variants) ---

        /// <summary>Base of the CBOR value hierarchy.</summary>
        public abstract class Value { }

        /// <summary>CBOR unsigned integer (major 0).</summary>
        public sealed class U : Value
        {
            public readonly long V;
            public U(long v) { V = v; }
        }

        /// <summary>CBOR negative integer (major 1); V is the negative value itself.</summary>
        public sealed class N : Value
        {
            public readonly long V;
            public N(long v) { V = v; }
        }

        /// <summary>CBOR byte string (major 2).</summary>
        public sealed class B : Value
        {
            public readonly byte[] V;
            public B(byte[] v) { V = v; }
        }

        /// <summary>CBOR text string (major 3).</summary>
        public sealed class T : Value
        {
            public readonly string V;
            public T(string v) { V = v; }
        }

        /// <summary>CBOR array (major 4).</summary>
        public sealed class A : Value
        {
            public readonly List<Value> Items;
            public A(List<Value> items) { Items = items; }
        }

        /// <summary>A single map entry.</summary>
        public sealed class Pair
        {
            public readonly Value K;
            public readonly Value Val;
            public Pair(Value k, Value val) { K = k; Val = val; }
        }

        /// <summary>CBOR map (major 5); Pairs is a list of (key, value).</summary>
        public sealed class M : Value
        {
            public readonly List<Pair> Pairs;
            public M(List<Pair> pairs) { Pairs = pairs; }
        }

        /// <summary>CBOR tag (major 6).</summary>
        public sealed class Tag : Value
        {
            public readonly long N;
            public readonly Value Content;
            public Tag(long n, Value content) { N = n; Content = content; }
        }

        // --- encoder ---

        private static byte[] Head(int major, long n)
        {
            // All call sites pass a non-negative n; use unsigned arithmetic for the head so shifts and
            // the shortest-form thresholds are exact even for large 64-bit values.
            ulong u = (ulong)n;
            int m = major << 5;
            if (u < 24)
            {
                return new byte[] { (byte)(m | (int)u) };
            }
            if (u < 256)
            {
                return new byte[] { (byte)(m | 24), (byte)u };
            }
            if (u < 65536UL)
            {
                return new byte[] { (byte)(m | 25), (byte)(u >> 8), (byte)u };
            }
            if (u < 4294967296UL)
            {
                return new byte[]
                {
                    (byte)(m | 26),
                    (byte)(u >> 24), (byte)(u >> 16), (byte)(u >> 8), (byte)u,
                };
            }
            return new byte[]
            {
                (byte)(m | 27),
                (byte)(u >> 56), (byte)(u >> 48), (byte)(u >> 40), (byte)(u >> 32),
                (byte)(u >> 24), (byte)(u >> 16), (byte)(u >> 8), (byte)u,
            };
        }

        /// <summary>Deterministic-CBOR encode a value; map keys are emitted in canonical order.</summary>
        public static byte[] Encode(Value v)
        {
            var outp = new MemoryStream();
            EncodeInto(v, outp);
            return outp.ToArray();
        }

        private static void Write(MemoryStream outp, byte[] b)
        {
            outp.Write(b, 0, b.Length);
        }

        private static void EncodeInto(Value v, MemoryStream outp)
        {
            switch (v)
            {
                case U u:
                    if (u.V < 0)
                    {
                        throw new NaalpException("NonCanonical", "uint is negative");
                    }
                    Write(outp, Head(0, u.V));
                    break;
                case N n:
                    Write(outp, Head(1, -1 - n.V));
                    break;
                case B b:
                    Write(outp, Head(2, b.V.Length));
                    Write(outp, b.V);
                    break;
                case T t:
                    byte[] s = Utf8.GetBytes(t.V);
                    Write(outp, Head(3, s.Length));
                    Write(outp, s);
                    break;
                case A a:
                    Write(outp, Head(4, a.Items.Count));
                    foreach (Value item in a.Items)
                    {
                        EncodeInto(item, outp);
                    }
                    break;
                case M m:
                {
                    int count = m.Pairs.Count;
                    var keys = new byte[count][];
                    var vals = new byte[count][];
                    for (int i = 0; i < count; i++)
                    {
                        keys[i] = Encode(m.Pairs[i].K);
                        vals[i] = Encode(m.Pairs[i].Val);
                    }
                    var order = new int[count];
                    for (int i = 0; i < count; i++)
                    {
                        order[i] = i;
                    }
                    Array.Sort(order, (x, y) => CompareBytes(keys[x], keys[y]));
                    Write(outp, Head(5, count));
                    byte[]? prev = null;
                    foreach (int idx in order)
                    {
                        byte[] k = keys[idx];
                        if (prev != null && CompareBytes(prev, k) == 0)
                        {
                            throw new NaalpException("NonCanonical", "duplicate map key");
                        }
                        prev = k;
                        Write(outp, k);
                        Write(outp, vals[idx]);
                    }
                    break;
                }
                case Tag tg:
                    Write(outp, Head(6, tg.N));
                    EncodeInto(tg.Content, outp);
                    break;
                default:
                    throw new NaalpException("NonCanonical", "not a cbor value");
            }
        }

        /// <summary>Unsigned bytewise lexicographic comparison.</summary>
        internal static int CompareBytes(byte[] a, byte[] b)
        {
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++)
            {
                int x = a[i] & 0xFF;
                int y = b[i] & 0xFF;
                if (x != y)
                {
                    return x - y;
                }
            }
            return a.Length - b.Length;
        }

        // --- decoder (strict canonical) ---

        private sealed class Cursor
        {
            public readonly byte[] Data;
            public int Pos;
            public Cursor(byte[] data) { Data = data; }
            public int Remaining => Data.Length - Pos;
        }

        private static Value Dec(Cursor c)
        {
            if (c.Remaining < 1)
            {
                throw new NaalpException("NonCanonical", "truncated");
            }
            int ib = c.Data[c.Pos++] & 0xFF;
            int major = ib >> 5;
            int ai = ib & 0x1F;
            if (ai == 31)
            {
                throw new NaalpException("NonCanonical", "indefinite length");
            }
            ulong arg;
            if (ai < 24)
            {
                arg = (ulong)ai;
            }
            else if (ai == 24)
            {
                if (c.Remaining < 1)
                {
                    throw new NaalpException("NonCanonical", "truncated head");
                }
                arg = c.Data[c.Pos++] & 0xFFUL;
                if (arg < 24)
                {
                    throw new NaalpException("NonCanonical", "non-shortest integer");
                }
            }
            else if (ai == 25)
            {
                if (c.Remaining < 2)
                {
                    throw new NaalpException("NonCanonical", "truncated head");
                }
                arg = ReadBE(c, 2);
                if (arg < 256)
                {
                    throw new NaalpException("NonCanonical", "non-shortest integer");
                }
            }
            else if (ai == 26)
            {
                if (c.Remaining < 4)
                {
                    throw new NaalpException("NonCanonical", "truncated head");
                }
                arg = ReadBE(c, 4);
                if (arg < 65536UL)
                {
                    throw new NaalpException("NonCanonical", "non-shortest integer");
                }
            }
            else if (ai == 27)
            {
                if (c.Remaining < 8)
                {
                    throw new NaalpException("NonCanonical", "truncated head");
                }
                arg = ReadBE(c, 8);
                if (arg < 4294967296UL)
                {
                    throw new NaalpException("NonCanonical", "non-shortest integer");
                }
            }
            else
            {
                throw new NaalpException("NonCanonical", "reserved additional-info");
            }

            switch (major)
            {
                case 0:
                    return new U((long)arg);
                case 1:
                    return new N(-1L - (long)arg);
                case 2:
                {
                    int len = LenOf(arg);
                    if (c.Remaining < len)
                    {
                        throw new NaalpException("NonCanonical", "truncated byte string");
                    }
                    byte[] b = new byte[len];
                    Array.Copy(c.Data, c.Pos, b, 0, len);
                    c.Pos += len;
                    return new B(b);
                }
                case 3:
                {
                    int len = LenOf(arg);
                    if (c.Remaining < len)
                    {
                        throw new NaalpException("NonCanonical", "truncated text string");
                    }
                    string s;
                    try
                    {
                        s = Utf8.GetString(c.Data, c.Pos, len);
                    }
                    catch (Exception)
                    {
                        throw new NaalpException("NonCanonical", "text string is not valid UTF-8");
                    }
                    c.Pos += len;
                    return new T(s);
                }
                case 4:
                {
                    int len = LenOf(arg);
                    var items = new List<Value>(len);
                    for (int i = 0; i < len; i++)
                    {
                        items.Add(Dec(c));
                    }
                    return new A(items);
                }
                case 5:
                {
                    int len = LenOf(arg);
                    var pairs = new List<Pair>(len);
                    byte[]? prev = null;
                    for (int i = 0; i < len; i++)
                    {
                        int before = c.Pos;
                        Value k = Dec(c);
                        byte[] kbytes = new byte[c.Pos - before];
                        Array.Copy(c.Data, before, kbytes, 0, kbytes.Length);
                        Value val = Dec(c);
                        if (prev != null && CompareBytes(kbytes, prev) <= 0)
                        {
                            throw new NaalpException("NonCanonical", "map keys out of order or duplicate");
                        }
                        prev = kbytes;
                        pairs.Add(new Pair(k, val));
                    }
                    return new M(pairs);
                }
                case 6:
                {
                    Value content = Dec(c);
                    return new Tag((long)arg, content);
                }
                default:
                    throw new NaalpException("NonCanonical", "unsupported major type " + major);
            }
        }

        private static ulong ReadBE(Cursor c, int n)
        {
            ulong v = 0;
            for (int i = 0; i < n; i++)
            {
                v = (v << 8) | (c.Data[c.Pos++] & 0xFFUL);
            }
            return v;
        }

        private static int LenOf(ulong arg)
        {
            if (arg > int.MaxValue)
            {
                throw new NaalpException("NonCanonical", "length out of range");
            }
            return (int)arg;
        }

        /// <summary>Strict canonical decode: rejects any non-canonical encoding with a NonCanonical error.</summary>
        public static Value Decode(byte[] data)
        {
            var c = new Cursor(data);
            Value v = Dec(c);
            if (c.Remaining != 0)
            {
                throw new NaalpException("NonCanonical", "trailing bytes after top-level item");
            }
            return v;
        }

        // --- content id ---

        /// <summary>Content id = multihash(0x20 [sha2-384], 0x30 [48], SHA-384(body-bytes)) (§2.3).</summary>
        public static byte[] ContentId(byte[] body)
        {
            byte[] digest;
            using (var sha = SHA384.Create())
            {
                digest = sha.ComputeHash(body);
            }
            byte[] outp = new byte[2 + digest.Length];
            outp[0] = 0x20;
            outp[1] = 0x30;
            Array.Copy(digest, 0, outp, 2, digest.Length);
            return outp;
        }

        /// <summary>Content id over a value (encode then hash).</summary>
        public static byte[] ContentId(Value v)
        {
            return ContentId(Encode(v));
        }
    }
}
