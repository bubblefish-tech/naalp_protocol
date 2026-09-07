// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

namespace Naalp
{
    public static partial class Envelope
    {
        /// <summary>
        /// The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
        /// disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and
        /// whether that boundary OBSERVED the event it describes first-hand or is RELAYING a report of
        /// it. It lives in the NON-CRITICAL ext map (field 11): a verifier that does not understand it,
        /// or that reads a malformed value, ignores the entry and the object still verifies (may-ignore).
        /// Because ext (field 11) is part of the signed body/payload, the disclosure is covered by the
        /// SIGNER's own COSE_Sign1 signature — it is a SELF-ASSERTED claim. 15 collides with neither the
        /// safety-label ext key 1 (§6.4), the recheck ext/cext key 13 (§2.5.1), nor the signer-counter
        /// ext key 14 (§2.5.2). Byte-identical to impl/go, impl/rust and impl/python.
        /// </summary>
        public const int PRODUCING_BOUNDARY_KEY = 15;

        /// <summary>This boundary witnessed the event directly (first-hand).</summary>
        public const long PRODUCING_BOUNDARY_OBSERVED = 1;

        /// <summary>This boundary is relaying a report it did not witness.</summary>
        public const long PRODUCING_BOUNDARY_REPORTED = 2;

        /// <summary>
        /// A decoded producing-boundary disclosure (<see cref="PRODUCING_BOUNDARY_KEY"/>, §2.5.4).
        /// <see cref="Boundary"/> is the emitting trust boundary (the same bstr party-id form as
        /// <see cref="Object.Signer"/>). <see cref="Kind"/> is <see cref="PRODUCING_BOUNDARY_OBSERVED"/>
        /// or <see cref="PRODUCING_BOUNDARY_REPORTED"/>. <see cref="Reporting"/> names the report origin
        /// and is non-null ONLY when Kind is PRODUCING_BOUNDARY_REPORTED (an observer relays from no
        /// one).
        /// </summary>
        public sealed class ProducingBoundary
        {
            public readonly byte[] Boundary;
            public readonly long Kind;
            public readonly byte[]? Reporting;

            public ProducingBoundary(byte[] boundary, long kind, byte[]? reporting = null)
            {
                Boundary = (byte[])boundary.Clone();
                Kind = kind;
                Reporting = reporting == null ? null : (byte[])reporting.Clone();
            }
        }
    }

    /// <summary>
    /// Accessor/setter for the NA-IETF-1 producing-boundary disclosure
    /// (<see cref="Envelope.ProducingBoundary"/>, §2.5.4).
    ///
    /// <para>Kept as EXTENSION methods on <see cref="Envelope.Object"/> — rather than instance members
    /// of <see cref="Envelope.Object"/> or static members of <see cref="Envelope"/> — for two reasons:
    /// (1) this optional surface can then be added purely additively, with no edit to the existing
    /// Envelope.cs; and (2) a static method and a nested type cannot share one identifier inside the
    /// SAME declaring type in C#, so an accessor named <c>ProducingBoundary</c> living on
    /// <see cref="Envelope"/> itself would collide with the nested <see cref="Envelope.ProducingBoundary"/>
    /// type. Living in a separate class sidesteps that while keeping the call site
    /// <c>o.ProducingBoundary()</c> — the same ergonomics as impl/go's <c>(o *Object) ProducingBoundary()</c>
    /// method.</para>
    /// </summary>
    public static class EnvelopeProducingBoundaryExtensions
    {
        // The producing-boundary value sub-map wire keys (§2.5.4) — local to this accessor/setter pair,
        // exactly as every other N-AALP port keeps them private to its producing-boundary module.
        private const int PbFieldBoundary = 1;  // bstr — the emitting trust boundary (party id)
        private const int PbFieldKind = 2;      // 1 observed / 2 reported
        private const int PbFieldReporting = 3; // bstr — report origin; present iff kind = reported

        private static bool ExtGetValue(Cbor.M m, int key, out Cbor.Value value)
        {
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == key)
                {
                    value = p.Val;
                    return true;
                }
            }
            value = null!;
            return false;
        }

        /// <summary>
        /// Return (ProducingBoundary, true) iff <paramref name="o"/> carries a WELL-FORMED
        /// producing-boundary disclosure in the non-critical ext map (field 11,
        /// <see cref="Envelope.PRODUCING_BOUNDARY_KEY"/>): a non-empty boundary (key 1), a kind (key 2)
        /// in {observed, reported}, and a reporting-boundary (key 3) absent unless the kind is reported.
        /// A malformed value is IGNORED — returns (null, false), NEVER throwing (may-ignore). An absent
        /// disclosure returns (null, false). An unrecognized sub-key is ignored and does not by itself
        /// make an otherwise well-formed value malformed.
        /// </summary>
        public static (Envelope.ProducingBoundary? Pb, bool Present) ProducingBoundary(this Envelope.Object o)
        {
            if (o.Ext == null)
            {
                return (null, false);
            }
            if (!ExtGetValue(o.Ext, Envelope.PRODUCING_BOUNDARY_KEY, out Cbor.Value v) || !(v is Cbor.M m))
            {
                return (null, false);
            }

            byte[]? boundary = null;
            byte[]? reporting = null;
            long kind = 0;
            bool haveBoundary = false;
            bool haveKind = false;
            bool haveReporting = false;

            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    return (null, false);
                }
                if (ku.V == PbFieldBoundary)
                {
                    if (!(p.Val is Cbor.B b))
                    {
                        return (null, false);
                    }
                    boundary = b.V;
                    haveBoundary = true;
                }
                else if (ku.V == PbFieldKind)
                {
                    if (!(p.Val is Cbor.U u))
                    {
                        return (null, false);
                    }
                    kind = u.V;
                    haveKind = true;
                }
                else if (ku.V == PbFieldReporting)
                {
                    if (!(p.Val is Cbor.B rb))
                    {
                        return (null, false);
                    }
                    reporting = rb.V;
                    haveReporting = true;
                }
                // else: an unrecognized sub-key — may-ignore. It does not surface a disclosure of its
                // own and does not invalidate an otherwise well-formed {boundary, kind, reporting?} core.
            }

            // well-formedness (§2.5.4). Any failure returns (null, false) (may-ignore), never an error.
            if (!haveBoundary || boundary!.Length == 0)
            {
                return (null, false); // no boundary named
            }
            if (!haveKind || (kind != Envelope.PRODUCING_BOUNDARY_OBSERVED && kind != Envelope.PRODUCING_BOUNDARY_REPORTED))
            {
                return (null, false); // absent or out-of-enum kind
            }
            if (haveReporting && kind != Envelope.PRODUCING_BOUNDARY_REPORTED)
            {
                return (null, false); // a reporting-boundary under observed: an observer relays from no one
            }
            var pb = new Envelope.ProducingBoundary(boundary!, kind, haveReporting ? reporting : null);
            return (pb, true);
        }

        /// <summary>
        /// Name <paramref name="pb"/> as <paramref name="o"/>'s producing-boundary disclosure in the
        /// NON-CRITICAL ext map (field 11), covered by the signer's COSE_Sign1 signature. Creates the
        /// ext carrier if absent and leaves any other extension entries intact. The reporting-boundary is
        /// emitted ONLY when non-null AND the kind is reported, so a caller cannot accidentally emit a
        /// malformed observed-with-reporting disclosure (an observer relays from no one). Sub-map keys
        /// are appended in ascending order; Encode emits canonical CBOR regardless, so the object stays
        /// deterministic.
        /// </summary>
        public static void SetProducingBoundary(this Envelope.Object o, Envelope.ProducingBoundary pb)
        {
            var sub = new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(PbFieldBoundary), new Cbor.B(pb.Boundary)),
                new Cbor.Pair(new Cbor.U(PbFieldKind), new Cbor.U(pb.Kind)),
            };
            if (pb.Reporting != null && pb.Kind == Envelope.PRODUCING_BOUNDARY_REPORTED)
            {
                sub.Add(new Cbor.Pair(new Cbor.U(PbFieldReporting), new Cbor.B(pb.Reporting)));
            }
            var entry = new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(sub));
            if (o.Ext == null)
            {
                o.Ext = new Cbor.M(new List<Cbor.Pair> { entry });
                return;
            }
            var newPairs = new List<Cbor.Pair>(o.Ext.Pairs.Count + 1);
            bool replaced = false;
            foreach (Cbor.Pair p in o.Ext.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == Envelope.PRODUCING_BOUNDARY_KEY)
                {
                    newPairs.Add(entry);
                    replaced = true;
                }
                else
                {
                    newPairs.Add(p);
                }
            }
            if (!replaced)
            {
                newPairs.Add(entry);
            }
            o.Ext = new Cbor.M(newPairs);
        }
    }
}
