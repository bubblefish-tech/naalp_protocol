// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// N-AALP body builders for the C# SDK — the deterministic-CBOR bodies of the spine records:
    /// approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
    /// open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
    /// transport confidentiality boundary (C11, §12). Each body is exactly what the Go, Rust, Python
    /// and Java reference implementations encode, so the bytes are byte-identical.
    /// </summary>
    public static class Records
    {
        private static byte[] Sha384(byte[] b)
        {
            using (var sha = SHA384.Create())
            {
                return sha.ComputeHash(b);
            }
        }

        // --- C6 approval + consume ledger (§7) ---

        public static byte[] ApprovalBody(byte[] approves, string approver, long grant, byte[] nonce, long notAfter)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(approves)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(approver)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(grant)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(nonce)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(notAfter)),
            }));
        }

        public static byte[] ApprovalId(byte[] approves, string approver, long grant, byte[] nonce, long notAfter)
        {
            return Cbor.ContentId(ApprovalBody(approves, approver, grant, nonce, notAfter));
        }

        public static byte[] LedgerEntry(long seq, byte[] prev, byte[] approvalId, string by)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(seq)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(prev)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(approvalId)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.T(by)),
            }));
        }

        // --- C7 audit receipt (§8) ---

        public static byte[] ReceiptBody(byte[] prev, byte[] obj, long seq, long at)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(prev)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(obj)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(seq)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(at)),
            }));
        }

        public static byte[] ReceiptHead(byte[] body)
        {
            return Sha384(body);
        }

        // --- C8 delivery (§9) ---

        public static byte[] DeliveryUpdate(byte[] obj, long stage, long at)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(obj)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(stage)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(at)),
            }));
        }

        // --- C9 streaming (§10) ---

        /// <summary>A stream chunk: an absolute offset and its data bytes.</summary>
        public sealed class Chunk
        {
            public readonly long Offset;
            public readonly byte[] Data;
            public Chunk(long offset, byte[] data) { Offset = offset; Data = data; }
        }

        /// <summary>Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2).</summary>
        public static byte[] StreamDigest(List<Chunk> chunks)
        {
            var sorted = new List<Chunk>(chunks);
            // Stable sort by offset so equal-offset chunks keep input order (matches Python's
            // list.sort / Java's stable Collections.sort).
            StableSortByOffset(sorted);
            using (var sha = SHA384.Create())
            {
                foreach (Chunk c in sorted)
                {
                    sha.TransformBlock(c.Data, 0, c.Data.Length, null, 0);
                }
                sha.TransformFinalBlock(System.Array.Empty<byte>(), 0, 0);
                return sha.Hash!;
            }
        }

        private static void StableSortByOffset(List<Chunk> list)
        {
            // Decorate-sort-undecorate for a guaranteed-stable ordering by offset.
            var indexed = new List<KeyValuePair<int, Chunk>>(list.Count);
            for (int i = 0; i < list.Count; i++)
            {
                indexed.Add(new KeyValuePair<int, Chunk>(i, list[i]));
            }
            indexed.Sort((a, b) =>
            {
                int c = a.Value.Offset.CompareTo(b.Value.Offset);
                return c != 0 ? c : a.Key.CompareTo(b.Key);
            });
            for (int i = 0; i < list.Count; i++)
            {
                list[i] = indexed[i].Value;
            }
        }

        public static byte[] StreamOpenBody(byte[] streamId, long effect, byte[]? approval, long substream)
        {
            var pairs = new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(effect)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(substream)),
            };
            if (approval != null && approval.Length > 0) // field 3 present only with an approval binding
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(3), new Cbor.B(approval)));
            }
            return Cbor.Encode(new Cbor.M(pairs));
        }

        public static byte[] StreamCommitBody(byte[] streamId, byte[] digest)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(digest)),
            }));
        }

        public static byte[] StreamCheckpointBody(byte[] streamId, long throughOffset, byte[] digestSoFar)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(streamId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(throughOffset)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(digestSoFar)),
            }));
        }

        // --- C12 foreign carriage (§13) ---

        public const long CLASS_OPAQUE = 5;

        public static byte[] CarriageBody(long protocolId, long cls, long contentType,
                                          byte[] correlation, string method, byte[] foreign)
        {
            if (cls > CLASS_OPAQUE)
            {
                throw new NaalpException("MappingError", "carriage class " + cls + " is not defined");
            }
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(protocolId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(cls)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(contentType)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(correlation)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.T(method)),
                new Cbor.Pair(new Cbor.U(6), new Cbor.B(foreign)),
            }));
        }

        // --- C11 transport confidentiality boundary (§12) ---

        private static bool[]? Transport(string name)
        {
            switch (name)
            {
                case "npamp": return new[] { true, true };
                case "quic": return new[] { true, true };
                case "websocket+wss": return new[] { true, false };
                case "websocket+ws": return new[] { false, false };
                case "https": return new[] { true, false };
                case "http": return new[] { false, false };
                default: return null;
            }
        }

        /// <summary>Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label.</summary>
        public static string TransportEmit(string name, bool sensitive, bool requirePeerAuth)
        {
            bool[]? t = Transport(name);
            if (t == null)
            {
                throw new NaalpException("UnknownTransport", "unknown transport " + name);
            }
            bool confidential = t[0];
            bool peerAuthenticated = t[1];
            if (sensitive && !confidential)
            {
                return "ConfidentialTransportRequired";
            }
            if (requirePeerAuth && !peerAuthenticated)
            {
                return "PeerUnauthenticated";
            }
            return "ok";
        }
    }
}
