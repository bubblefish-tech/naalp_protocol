// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// Manufacturing Add-ons Component F, the physical-hazard authorization extension
    /// (design.md addendum; requirements F1-F5; wire authority
    /// `spec/naalp-draft-01.cddl`), C# port of
    /// impl/rust/naalp-hazard/src/lib.rs.
    ///
    /// <para><c>effect</c> (Envelope field 7, <see cref="Policy"/>) describes DATA reversibility.
    /// <c>hazard</c> is a new, ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible
    /// action may still be a high physical hazard. The two dimensions are never merged and
    /// neither derives the other.</para>
    ///
    /// <para>This module adds no new cryptography and no new CBOR codec of its own: every encode
    /// call delegates to <see cref="Cbor.Encode"/> / <see cref="Cbor.ContentId(Cbor.Value)"/>,
    /// exactly as the Rust reference crate adds no crypto/encoding of its own over the graded
    /// <c>naalp</c> core.</para>
    ///
    /// <para>The fail-closed rules (F2, F3):</para>
    /// <list type="bullet">
    /// <item><see cref="HazardClassOps.FromCode"/> is the ONE fail-closed decode entry point: any
    /// missing or out-of-range raw value normalizes to <see cref="HazardClass.MotionInSharedSpace"/>
    /// -- the highest class -- never to "absent" or any weaker class.</item>
    /// <item><see cref="HazardAuthorized"/> requires an EXACT class match (not a &lt;= ceiling the
    /// way the effect lattice's <see cref="Policy.Authorizes"/> works) AND full containment of the
    /// claim's envelope inside the grant's on every axis, the speed bound, and the time window. Any
    /// single failing dimension denies the WHOLE claim -- there is no partial authorization.</item>
    /// <item><see cref="HazardAuthorizedOptional"/> additionally covers the case where an action
    /// carries NO hazard claim at all: there is no envelope to check containment against, so it
    /// denies immediately with a distinct error (<c>HazardUnknown</c>) rather than fabricating a
    /// sentinel envelope and running the ordinary coverage check.</item>
    /// </list>
    /// </summary>
    public static class Hazard
    {
        // ---- hazard-class (F2: closed, fail-closed to the highest class) ----------------------

        /// <summary>The closed five-value hazard-class vocabulary (`spec/naalp-draft-01.cddl`).
        /// <see cref="MotionInSharedSpace"/> is BOTH a named class (4) and the fail-closed default
        /// for an unrecognized or absent raw value (F2) -- the assumption that "the producer did
        /// not tell us" is at least as dangerous as the worst named class.</summary>
        public enum HazardClass
        {
            None = 0,
            ToolActuation = 1,
            Thermal = 2,
            EnergyRelease = 3,
            MotionInSharedSpace = 4,
        }

        public static class HazardClassOps
        {
            /// <summary>The CDDL wire code (0..4).</summary>
            public static long Code(HazardClass c) => (long)c;

            /// <summary>Fail-closed decode (F2). <c>null</c> (the raw value was absent) or any
            /// value outside 0..=4 (unrecognized) normalizes to
            /// <see cref="HazardClass.MotionInSharedSpace"/> -- never to a weaker class, and never a
            /// decode failure (there is no "invalid hazard" outcome; there is only "the worst case
            /// we must assume"). This takes a nullable arbitrary-magnitude unsigned code (via
            /// <see cref="ulong"/>) so a malformed wire value outside even a byte range still
            /// normalizes correctly rather than throwing.</summary>
            public static HazardClass FromCode(ulong? code)
            {
                if (code.HasValue)
                {
                    switch (code.Value)
                    {
                        case 0: return HazardClass.None;
                        case 1: return HazardClass.ToolActuation;
                        case 2: return HazardClass.Thermal;
                        case 3: return HazardClass.EnergyRelease;
                        case 4: return HazardClass.MotionInSharedSpace;
                    }
                }
                return HazardClass.MotionInSharedSpace; // F2: unknown/absent -> highest class
            }

            public static Cbor.Value ToValue(HazardClass c) => new Cbor.U(Code(c));
        }

        // ---- spatial-bounds ---------------------------------------------------------------------

        /// <summary>A named coordinate frame plus a signed axis-aligned bounding region in that
        /// frame, integer millimeters (`spec/naalp-draft-01.cddl` `spatial-bounds`).</summary>
        public sealed class SpatialBounds
        {
            public readonly string Frame;
            /// <summary>Per-axis (min, max), millimeters, signed. MUST be non-empty; every entry
            /// MUST satisfy min &lt;= max.</summary>
            public readonly List<(long Min, long Max)> Axes;

            public SpatialBounds(string frame, List<(long Min, long Max)> axes)
            {
                Frame = frame;
                Axes = axes;
            }

            /// <summary>Structural validity (`spec/naalp-draft-01.cddl`): non-empty axes, every
            /// min &lt;= max, frame non-empty and Unicode NFC.</summary>
            public bool IsWellFormed()
            {
                if (Axes == null || Axes.Count == 0) { return false; }
                foreach ((long min, long max) in Axes)
                {
                    if (min > max) { return false; }
                }
                if (string.IsNullOrEmpty(Frame)) { return false; }
                try
                {
                    Identity.RequireNfc(Frame);
                }
                catch (NaalpException)
                {
                    return false;
                }
                return true;
            }

            public Cbor.Value ToValue()
            {
                var axes = new List<Cbor.Value>(Axes.Count);
                foreach ((long min, long max) in Axes)
                {
                    axes.Add(new Cbor.A(new List<Cbor.Value> { IntValue(min), IntValue(max) }));
                }
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Frame)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.A(axes)),
                });
            }

            /// <summary>Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still
            /// encodes (encoding is not the validity gate); callers MUST check
            /// <see cref="IsWellFormed"/> before treating a <see cref="SpatialBounds"/> as
            /// authoritative, exactly as <see cref="FromValue"/> does on decode.</summary>
            public byte[] Bytes() => Cbor.Encode(ToValue());

            /// <summary>Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed
            /// key or value, a missing key, empty axes, an axis with min &gt; max, or a
            /// non-NFC/empty frame -- fail-closed (HazardMalformed), never a partially-valid
            /// result.</summary>
            public static SpatialBounds FromValue(Cbor.Value v)
            {
                if (!(v is Cbor.M m)) { throw MalformedError(); }
                string frame = null;
                bool haveFrame = false;
                List<(long, long)> axes = null;
                bool haveAxes = false;
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (!(p.K is Cbor.U ku)) { throw MalformedError(); }
                    switch (ku.V)
                    {
                        case 1:
                            if (!(p.Val is Cbor.T t)) { throw MalformedError(); }
                            frame = t.V;
                            haveFrame = true;
                            break;
                        case 2:
                            if (!(p.Val is Cbor.A a) || a.Items.Count == 0) { throw MalformedError(); }
                            var outAxes = new List<(long, long)>(a.Items.Count);
                            foreach (Cbor.Value it in a.Items)
                            {
                                if (!(it is Cbor.A pair) || pair.Items.Count != 2) { throw MalformedError(); }
                                long min = IntFromValue(pair.Items[0]);
                                long max = IntFromValue(pair.Items[1]);
                                if (min > max) { throw MalformedError(); }
                                outAxes.Add((min, max));
                            }
                            axes = outAxes;
                            haveAxes = true;
                            break;
                        default:
                            throw MalformedError();
                    }
                }
                if (!haveFrame || !haveAxes) { throw MalformedError(); }
                var sb = new SpatialBounds(frame, axes);
                if (!sb.IsWellFormed()) { throw MalformedError(); }
                return sb;
            }
        }

        private static Cbor.Value IntValue(long v)
        {
            return v >= 0 ? (Cbor.Value)new Cbor.U(v) : new Cbor.N(v);
        }

        private static long IntFromValue(Cbor.Value v)
        {
            switch (v)
            {
                case Cbor.U u: return u.V;
                case Cbor.N n: return n.V;
                default: throw MalformedError();
            }
        }

        /// <summary>Full containment (F3): same frame id (a bound in one frame says nothing about a
        /// bound in a different, unrelated frame), the SAME axis count in the SAME order, and every
        /// claim axis's [min,max] a subset of the matching grant axis's [min,max].</summary>
        public static bool SpatialContained(SpatialBounds claim, SpatialBounds grant)
        {
            if (claim.Frame != grant.Frame) { return false; }
            if (claim.Axes.Count != grant.Axes.Count) { return false; }
            for (int i = 0; i < claim.Axes.Count; i++)
            {
                (long cmin, long cmax) = claim.Axes[i];
                (long gmin, long gmax) = grant.Axes[i];
                if (!(cmin >= gmin && cmax <= gmax)) { return false; }
            }
            return true;
        }

        // ---- hazard-window ------------------------------------------------------------------------

        /// <summary>A validity window, epoch ms, the same convention as `naalp-object` field 6
        /// (created) and `naalp-delegation-grant` fields 4/5.</summary>
        public readonly struct HazardWindow
        {
            public readonly ulong NotBefore;
            public readonly ulong NotAfter;

            public HazardWindow(ulong notBefore, ulong notAfter)
            {
                NotBefore = notBefore;
                NotAfter = notAfter;
            }

            public Cbor.Value ToValue()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(unchecked((long)NotBefore))),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(unchecked((long)NotAfter))),
                });
            }

            internal static HazardWindow FromValue(Cbor.Value v)
            {
                if (!(v is Cbor.M m)) { throw MalformedError(); }
                ulong? notBefore = null, notAfter = null;
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (!(p.K is Cbor.U ku) || !(p.Val is Cbor.U vu)) { throw MalformedError(); }
                    switch (ku.V)
                    {
                        case 1: notBefore = unchecked((ulong)vu.V); break;
                        case 2: notAfter = unchecked((ulong)vu.V); break;
                        default: throw MalformedError();
                    }
                }
                if (!notBefore.HasValue || !notAfter.HasValue) { throw MalformedError(); }
                return new HazardWindow(notBefore.Value, notAfter.Value);
            }
        }

        // ---- hazard-envelope -----------------------------------------------------------------------

        /// <summary>The full physical envelope a claim or an authorization bounds itself by. All
        /// three fields are MANDATORY on the wire (`spec/naalp-draft-01.cddl`) -- a silently-absent
        /// axis would be fail-OPEN in a physical-safety context, so an issuer that means "unbounded"
        /// states so explicitly with wide numeric bounds; the wire never infers permissiveness from
        /// silence here (deliberate contrast with `naalp-delegation-grant`'s optional scope).</summary>
        public sealed class HazardEnvelope
        {
            public readonly SpatialBounds Spatial;
            /// <summary>Max instantaneous speed, millimeters per second.</summary>
            public readonly ulong SpeedBoundMmS;
            public readonly HazardWindow Window;

            public HazardEnvelope(SpatialBounds spatial, ulong speedBoundMmS, HazardWindow window)
            {
                Spatial = spatial;
                SpeedBoundMmS = speedBoundMmS;
                Window = window;
            }

            public Cbor.Value ToValue()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), Spatial.ToValue()),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(unchecked((long)SpeedBoundMmS))),
                    new Cbor.Pair(new Cbor.U(3), Window.ToValue()),
                });
            }

            /// <summary>Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToValue());

            /// <summary>The envelope's content id (T1 framing): a pure function of the bytes
            /// above.</summary>
            public byte[] ContentId() => Cbor.ContentId(ToValue());

            /// <summary>Parse a `hazard-envelope` map; fail-closed on any missing/malformed
            /// field.</summary>
            public static HazardEnvelope FromValue(Cbor.Value v)
            {
                if (!(v is Cbor.M m)) { throw MalformedError(); }
                SpatialBounds spatial = null;
                ulong? speed = null;
                HazardWindow? window = null;
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (!(p.K is Cbor.U ku)) { throw MalformedError(); }
                    switch (ku.V)
                    {
                        case 1:
                            spatial = SpatialBounds.FromValue(p.Val);
                            break;
                        case 2:
                            if (!(p.Val is Cbor.U su)) { throw MalformedError(); }
                            speed = unchecked((ulong)su.V);
                            break;
                        case 3:
                            window = HazardWindow.FromValue(p.Val);
                            break;
                        default:
                            throw MalformedError();
                    }
                }
                if (spatial == null || !speed.HasValue || !window.HasValue) { throw MalformedError(); }
                return new HazardEnvelope(spatial, speed.Value, window.Value);
            }
        }

        /// <summary>Full containment (F3): <see cref="SpatialContained"/> AND
        /// claim.SpeedBoundMmS &lt;= grant.SpeedBoundMmS AND the claim's window is a sub-interval of
        /// the grant's (grant.NotBefore &lt;= claim.NotBefore and claim.NotAfter &lt;=
        /// grant.NotAfter).</summary>
        public static bool EnvelopeContained(HazardEnvelope claim, HazardEnvelope grant)
        {
            return SpatialContained(claim.Spatial, grant.Spatial)
                && claim.SpeedBoundMmS <= grant.SpeedBoundMmS
                && grant.Window.NotBefore <= claim.Window.NotBefore
                && claim.Window.NotAfter <= grant.Window.NotAfter;
        }

        // ---- naalp-hazard-claim / naalp-hazard-authorization -----------------------------------------

        /// <summary>A signed physical-hazard claim (`spec/naalp-draft-01.cddl` `naalp-hazard-claim`).
        /// Carriage (the object it accompanies and how) is a wire-impact decision, not this module's
        /// concern.</summary>
        public sealed class HazardClaim
        {
            public readonly HazardClass Class;
            public readonly HazardEnvelope Envelope;

            public HazardClaim(HazardClass cls, HazardEnvelope envelope)
            {
                Class = cls;
                Envelope = envelope;
            }

            public Cbor.Value ToValue() => HazardBodyToValue(Class, Envelope);

            /// <summary>Deterministic-CBOR encoding of {1:class,2:envelope}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToValue());

            /// <summary>The claim's content id (T1 framing).</summary>
            public byte[] ContentId() => Cbor.ContentId(ToValue());

            /// <summary>Parse a `naalp-hazard-claim` body. Both class and envelope are mandatory --
            /// a claim declaring one and omitting the other is HazardMalformed, not partially
            /// valid.</summary>
            public static HazardClaim FromValue(Cbor.Value v)
            {
                (HazardClass cls, HazardEnvelope env) = HazardBodyFromValue(v);
                return new HazardClaim(cls, env);
            }
        }

        /// <summary>A signed physical-hazard authorization ("a grant" in requirements F3's
        /// language; `spec/naalp-draft-01.cddl` `naalp-hazard-authorization`). Same shape as
        /// <see cref="HazardClaim"/> deliberately: one envelope shape for both sides keeps the
        /// containment check symmetric.</summary>
        public sealed class HazardAuthorization
        {
            public readonly HazardClass Class;
            public readonly HazardEnvelope Envelope;

            public HazardAuthorization(HazardClass cls, HazardEnvelope envelope)
            {
                Class = cls;
                Envelope = envelope;
            }

            public Cbor.Value ToValue() => HazardBodyToValue(Class, Envelope);

            /// <summary>Deterministic-CBOR encoding of {1:class,2:envelope}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToValue());

            /// <summary>The authorization's content id (T1 framing).</summary>
            public byte[] ContentId() => Cbor.ContentId(ToValue());

            /// <summary>Parse a `naalp-hazard-authorization` body.</summary>
            public static HazardAuthorization FromValue(Cbor.Value v)
            {
                (HazardClass cls, HazardEnvelope env) = HazardBodyFromValue(v);
                return new HazardAuthorization(cls, env);
            }
        }

        private static Cbor.Value HazardBodyToValue(HazardClass cls, HazardEnvelope envelope)
        {
            return new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), HazardClassOps.ToValue(cls)),
                new Cbor.Pair(new Cbor.U(2), envelope.ToValue()),
            });
        }

        private static (HazardClass, HazardEnvelope) HazardBodyFromValue(Cbor.Value v)
        {
            if (!(v is Cbor.M m)) { throw MalformedError(); }
            ulong? classCode = null;
            HazardEnvelope envelope = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku)) { throw MalformedError(); }
                switch (ku.V)
                {
                    case 1:
                        // An out-of-range class ON THE WIRE (not merely "absent") is a malformed
                        // body, not a normalize-to-4 input: F2's fail-closed normalization is for
                        // the DECODE step that produces a class from a less-structured source (see
                        // HazardClassOps.FromCode), not for a CDDL-invalid hazard-class value
                        // already claiming to be well-formed.
                        if (!(p.Val is Cbor.U cu) || cu.V < 0 || cu.V > 4) { throw MalformedError(); }
                        classCode = unchecked((ulong)cu.V);
                        break;
                    case 2:
                        envelope = HazardEnvelope.FromValue(p.Val);
                        break;
                    default:
                        throw MalformedError();
                }
            }
            if (!classCode.HasValue || envelope == null) { throw MalformedError(); }
            return (HazardClassOps.FromCode(classCode), envelope);
        }

        // ---- F3: grant-coverage authorization -----------------------------------------------------

        /// <summary>Authorize a well-formed, present claim against an authorization (F3): EXACT
        /// class match (not a &lt;= ceiling -- see the module doc) AND <see cref="EnvelopeContained"/>.
        /// Any single failing dimension denies the WHOLE claim (HazardNotCovered) -- there is no
        /// partial authorization and no fail-open branch.</summary>
        public static void HazardAuthorized(HazardClaim claim, HazardAuthorization grant)
        {
            if (claim.Class != grant.Class)
            {
                throw NotCoveredError();
            }
            if (!EnvelopeContained(claim.Envelope, grant.Envelope))
            {
                throw NotCoveredError();
            }
        }

        /// <summary>Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct
        /// from a present-but-unrecognized class byte inside a claim). <c>null</c> -- no
        /// hazard-claim object exists at all for an action that requires one -- denies immediately
        /// (HazardUnknown) rather than fabricating a sentinel envelope and running the ordinary
        /// coverage check: there is no envelope to check containment against, so the honest outcome
        /// is a distinct error, not a coverage denial that implies an envelope was
        /// compared.</summary>
        public static void HazardAuthorizedOptional(HazardClaim claim, HazardAuthorization grant)
        {
            if (claim == null)
            {
                throw UnknownError();
            }
            HazardAuthorized(claim, grant);
        }

        // ---- errors ---------------------------------------------------------------------------

        /// <summary>(HazardMalformed) a hazard-claim/hazard-authorization/envelope body is not the
        /// CDDL shape (`spec/naalp-draft-01.cddl`), a spatial-bounds axis has min &gt; max, axes is
        /// empty, or frame is not Unicode NFC.</summary>
        public static NaalpException MalformedError()
        {
            return new NaalpException("HazardMalformed",
                "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid");
        }

        /// <summary>(HazardNotCovered) a well-formed claim's class or envelope is not fully covered
        /// by the presented authorization.</summary>
        public static NaalpException NotCoveredError()
        {
            return new NaalpException("HazardNotCovered",
                "declared hazard class or envelope is not fully covered by the authorization");
        }

        /// <summary>(HazardUnknown) the hazard value for an action requiring one is unrecognized or
        /// absent, and -- for the fully-absent case -- no envelope exists to check coverage against
        /// at all.</summary>
        public static NaalpException UnknownError()
        {
            return new NaalpException("HazardUnknown",
                "hazard value unrecognized or absent; no claim to check coverage against");
        }
    }
}
