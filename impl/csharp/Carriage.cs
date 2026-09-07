// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// C12 — foreign carriage by class for the C# SDK (design.md §13; R-14.1..14.8, R-18.6), ported
    /// from impl/go/carriage and cross-checked against impl/python/naalp/carriage.py.
    ///
    /// <para>N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a
    /// signed N-AALP carriage object whose effect, safety, identity, and audit apply, and whose foreign
    /// body is interpreted by a carriage CLASS — not a bespoke per-protocol mapping (R-14.1). There are
    /// five structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that
    /// makes any protocol — including one nobody has defined — carriable immediately on an experimental
    /// protocol id with no registration (R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST
    /// NOT be re-serialized, canonicalized, summarized, or rewritten (R-14.4); N-AALP metadata is carried
    /// around it, never inside it. The carriage object's signer remains the authority — a foreign
    /// identity never becomes an N-AALP authorization identity (R-14.6).</para>
    ///
    /// <para>Each carriage class is graded against its own per-class oracle
    /// <c>vectors/carriage/&lt;class&gt;/cases.json</c>. Carriage bodies are UNSIGNED; the R-14.6
    /// containment property is demonstrated over a real signed <see cref="Envelope.Object"/>.</para>
    /// </summary>
    public static class Carriage
    {
        // Carriage classes (design.md §13.2).
        public const long ClassJSONRPC = 0;
        public const long ClassHTTP = 1;
        public const long ClassMSG = 2;
        public const long ClassSTREAM = 3;
        public const long ClassDOC = 4;
        public const long ClassOPAQUE = 5;

        private static readonly string[] ClassNames = { "JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE" };

        /// <summary>Returns the name of a class code (0..5), or "unknown".</summary>
        public static string ClassName(long c)
            => (c >= 0 && c < ClassNames.Length) ? ClassNames[c] : "unknown";

        /// <summary>The body of a carriage object (design.md §13.2). <see cref="Foreign"/> is the foreign
        /// message carried octet-for-octet (R-14.4).</summary>
        public sealed class CarriageBody
        {
            public readonly long ProtocolID;
            public readonly long Class;
            public readonly long ContentType;
            public readonly byte[] Correlation;
            public readonly string Method;
            public readonly byte[] Foreign;

            public CarriageBody(long protocolId, long klass, long contentType, byte[] correlation, string method, byte[] foreign)
            {
                ProtocolID = protocolId;
                Class = klass;
                ContentType = contentType;
                Correlation = correlation;
                Method = method;
                Foreign = foreign;
            }

            /// <summary>The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type,
            /// 4: correlation, 5: method, 6: foreign}.</summary>
            public Cbor.Value ToValue() => new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(ProtocolID)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(Class)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(ContentType)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(Correlation)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.T(Method)),
                new Cbor.Pair(new Cbor.U(6), new Cbor.B(Foreign)),
            });

            /// <summary>The deterministic-CBOR encoding of the carriage body.</summary>
            public byte[] Bytes() => Cbor.Encode(ToValue());
        }

        /// <summary>Rejects a class code outside the defined set with a typed mapping error, never a
        /// silent drop (R-14.8). Returns when the class is representable.</summary>
        public static void ValidateClass(long klass)
        {
            if (klass > ClassOPAQUE || klass < 0)
            {
                throw new NaalpException("MappingError", "an N-AALP semantic cannot be represented by this carriage class");
            }
        }

        /// <summary>
        /// Wraps a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not
        /// parse, canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE
        /// with an experimental protocol id and zero new specification (R-18.6).
        /// </summary>
        public static CarriageBody Carry(long protocolId, long klass, long contentType, byte[] correlation, string method, byte[] foreign)
        {
            ValidateClass(klass);
            return new CarriageBody(protocolId, klass, contentType, correlation, method, foreign);
        }

        /// <summary>
        /// Parses a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A
        /// structurally invalid body is Malformed; an unknown class is a MappingError. The mandatory
        /// foreign field (key 6) must be present.
        /// </summary>
        public static CarriageBody CarriageFromValue(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("Malformed", "carriage body is not a map");
            }
            long protocolId = 0, klass = 0, contentType = 0;
            byte[] correlation = Array.Empty<byte>();
            byte[] foreign = Array.Empty<byte>();
            string method = "";
            bool haveForeign = false;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("Malformed", "non-uint carriage key");
                }
                switch (ku.V)
                {
                    case 1:
                        if (!(p.Val is Cbor.U u1)) throw new NaalpException("Malformed", "protocol_id not a uint");
                        protocolId = u1.V;
                        break;
                    case 2:
                        if (!(p.Val is Cbor.U u2)) throw new NaalpException("Malformed", "class not a uint");
                        klass = u2.V;
                        break;
                    case 3:
                        if (!(p.Val is Cbor.U u3)) throw new NaalpException("Malformed", "content_type not a uint");
                        contentType = u3.V;
                        break;
                    case 4:
                        if (!(p.Val is Cbor.B b4)) throw new NaalpException("Malformed", "correlation not a bstr");
                        correlation = b4.V;
                        break;
                    case 5:
                        if (!(p.Val is Cbor.T t5)) throw new NaalpException("Malformed", "method not a tstr");
                        method = t5.V;
                        break;
                    case 6:
                        if (!(p.Val is Cbor.B b6)) throw new NaalpException("Malformed", "foreign not a bstr");
                        foreign = b6.V;
                        haveForeign = true;
                        break;
                    default:
                        throw new NaalpException("Malformed", "unknown carriage field");
                }
            }
            if (!haveForeign)
            {
                throw new NaalpException("Malformed", "carriage body missing the mandatory foreign field");
            }
            ValidateClass(klass);
            return new CarriageBody(protocolId, klass, contentType, correlation, method, foreign);
        }

        /// <summary>
        /// The protocol-id range (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
        /// experimental 0x10-0x7F (no registration), private 0x80-0xFF. protocol_id is one
        /// octet; anything wider is invalid.
        /// </summary>
        public static string ProtocolRange(long id)
        {
            if (id == 0x00) return "reserved";
            if (id <= 0x0F) return "standards";
            if (id <= 0x7F) return "experimental";
            if (id <= 0xFF) return "private";
            return "invalid";
        }

        /// <summary>Records whether a carried message was actually delivered. A report never claims
        /// delivery it did not achieve (R-14.8).</summary>
        public sealed class DeliveryReport
        {
            public readonly bool Delivered;

            public DeliveryReport(bool delivered)
            {
                Delivered = delivered;
            }
        }

        /// <summary>
        /// Produces a delivery report from the below-foreign outcome: a failed delivery throws
        /// NotDelivered (never a false "delivered"); a success returns DeliveryReport(Delivered=true)
        /// (R-14.8).
        /// </summary>
        public static DeliveryReport Report(bool deliveredBelow)
        {
            if (!deliveredBelow)
            {
                throw new NaalpException("NotDelivered", "a below-foreign failure; the message was not delivered");
            }
            return new DeliveryReport(true);
        }

        /// <summary>
        /// The authorizing principal of a carriage object: the N-AALP signer of the object (envelope
        /// field 5), never any foreign principal named inside the foreign bytes (R-14.6). It reads only
        /// the signed envelope, never the carried foreign message.
        /// </summary>
        public static byte[] CarriageAuthority(Envelope.Object o) => o.Signer;
    }
}
