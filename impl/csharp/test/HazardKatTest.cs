// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// Manufacturing Add-ons Component F (naalp-hazard) known-answer test for the C# SDK,
    /// graded against the independent, non-circular oracle
    /// <c>vectors/hazard/cases.json</c> (tools/hazard_oracle.py) -- mirroring
    /// impl/rust/naalp-hazard/src/lib.rs's test module, i.e. C# == Rust == oracle.
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~HazardKatTest</c></para>
    /// </summary>
    public sealed class HazardKatTest
    {
        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static string? FindVector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "hazard", "cases.json");
                if (File.Exists(p))
                {
                    return p;
                }
                d = d.Parent;
            }
            return null;
        }

        private static JsonElement Vector()
        {
            string? p = FindVector();
            Assert.True(p != null, "committed hazard vector not found from " + AppContext.BaseDirectory);
            var doc = JsonDocument.Parse(File.ReadAllText(p!));
            return doc.RootElement.Clone();
        }

        // A code cell in the oracle is null, a JSON number, or (for the >2^63-1 case) a decimal
        // string -- never a float64 decoder anywhere, so the exact code survives.
        private static ulong? GetNullableULong(JsonElement el, string prop)
        {
            if (!el.TryGetProperty(prop, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            if (v.ValueKind == JsonValueKind.String)
            {
                return ulong.Parse(v.GetString()!);
            }
            return v.GetUInt64();
        }

        private static List<(long Min, long Max)> AxesFrom(JsonElement axesEl)
        {
            var outp = new List<(long, long)>();
            foreach (JsonElement pair in axesEl.EnumerateArray())
            {
                outp.Add((pair[0].GetInt64(), pair[1].GetInt64()));
            }
            return outp;
        }

        private static Hazard.HazardEnvelope EnvFrom(JsonElement o)
        {
            return new Hazard.HazardEnvelope(
                new Hazard.SpatialBounds(o.GetProperty("frame").GetString()!, AxesFrom(o.GetProperty("axes"))),
                o.GetProperty("speed_bound_mm_s").GetUInt64(),
                new Hazard.HazardWindow(o.GetProperty("not_before").GetUInt64(), o.GetProperty("not_after").GetUInt64()));
        }

        private static string ErrKind(Action a)
        {
            try
            {
                a();
                return "no-error";
            }
            catch (NaalpException e)
            {
                return e.Kind;
            }
        }

        // ---- F2: fail-closed class decode (mutation anchor: a constant HazardClass.None return
        // would pass none of the non-zero cases; a constant MotionInSharedSpace would fail the
        // exact 0..3 cases). --------------------------------------------------------------------
        [Fact]
        public void FromCodeFailClosedMatchesOracle()
        {
            JsonElement c = Vector();
            foreach (JsonElement row in c.GetProperty("from_code").EnumerateArray())
            {
                ulong? input = GetNullableULong(row, "code");
                long want = row.GetProperty("class").GetInt64();
                Assert.True((long)Hazard.HazardClassOps.Code(Hazard.HazardClassOps.FromCode(input)) == want,
                    "from_code(" + (input?.ToString() ?? "null") + ")");
            }

            // Explicit oracle-independent assertions of the two named fail-closed cases (F2).
            Assert.Equal(Hazard.HazardClass.MotionInSharedSpace, Hazard.HazardClassOps.FromCode(null));
            Assert.Equal(Hazard.HazardClass.MotionInSharedSpace, Hazard.HazardClassOps.FromCode(9));
            Assert.Equal(Hazard.HazardClass.MotionInSharedSpace, Hazard.HazardClassOps.FromCode(ulong.MaxValue));

            // The five in-range codes decode to themselves, never collapsing to the default.
            for (ulong code = 0; code <= 4; code++)
            {
                Assert.Equal((long)code, Hazard.HazardClassOps.Code(Hazard.HazardClassOps.FromCode(code)));
            }
        }

        // ---- byte-level: encode matches the independent oracle (=> C# == Rust once graded). ----
        [Fact]
        public void ClaimAndAuthorizationBytesMatchOracle()
        {
            JsonElement c = Vector();
            foreach (JsonElement row in c.GetProperty("bodies").EnumerateArray())
            {
                Hazard.HazardClass cls = Hazard.HazardClassOps.FromCode(row.GetProperty("class").GetUInt64());
                Hazard.HazardEnvelope e = EnvFrom(row);
                var claim = new Hazard.HazardClaim(cls, e);
                var auth = new Hazard.HazardAuthorization(cls, e);
                string name = row.GetProperty("name").GetString()!;
                string want = row.GetProperty("body_hex").GetString()!;
                Assert.Equal(want, Hex(claim.Bytes()));
                Assert.Equal(want, Hex(auth.Bytes()));
                Assert.Equal(row.GetProperty("content_id_hex").GetString(), Hex(claim.ContentId()));
            }
        }

        // Round-trip: FromValue(ToValue(x)) == x for every oracle body.
        [Fact]
        public void RoundTripMatchesOracle()
        {
            JsonElement c = Vector();
            foreach (JsonElement row in c.GetProperty("bodies").EnumerateArray())
            {
                Hazard.HazardClass cls = Hazard.HazardClassOps.FromCode(row.GetProperty("class").GetUInt64());
                Hazard.HazardEnvelope e = EnvFrom(row);
                var claim = new Hazard.HazardClaim(cls, e);
                Hazard.HazardClaim got = Hazard.HazardClaim.FromValue(claim.ToValue());
                Assert.Equal(claim.Class, got.Class);
                Assert.Equal(Hex(claim.Bytes()), Hex(got.Bytes()));
            }
        }

        // ---- F3: coverage matrix (mutation anchor: a constant "always authorized" fails the deny
        // rows; a constant "always denied" fails the allow rows). ---------------------------------
        [Fact]
        public void CoverageMatchesOracle()
        {
            JsonElement c = Vector();
            JsonElement rows = c.GetProperty("coverage");
            Assert.True(rows.GetArrayLength() > 0);
            int allows = 0, denies = 0;
            foreach (JsonElement row in rows.EnumerateArray())
            {
                var claim = new Hazard.HazardClaim(
                    Hazard.HazardClassOps.FromCode(GetNullableULong(row, "claim_class_code")),
                    EnvFrom(row.GetProperty("claim_envelope")));
                var grant = new Hazard.HazardAuthorization(
                    Hazard.HazardClassOps.FromCode(GetNullableULong(row, "grant_class_code")),
                    EnvFrom(row.GetProperty("grant_envelope")));
                bool wantOk = row.GetProperty("authorized").GetBoolean();
                string name = row.GetProperty("name").GetString()!;
                if (wantOk)
                {
                    allows++;
                    Hazard.HazardAuthorized(claim, grant); // must NOT throw
                }
                else
                {
                    denies++;
                    NaalpException ex = Assert.Throws<NaalpException>(() => Hazard.HazardAuthorized(claim, grant));
                    Assert.Equal("HazardNotCovered", ex.Kind);
                }
            }
            Assert.True(allows > 0 && denies > 0, "matrix needs both allows and denies");
        }

        // F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all):
        // distinct from an in-range-but-mismatched class, and distinct from an unrecognized class
        // byte inside a present claim (covered by CoverageMatchesOracle's normalized rows).
        [Fact]
        public void AbsentClaimDeniesWithDistinctError()
        {
            var grant = new Hazard.HazardAuthorization(
                Hazard.HazardClass.ToolActuation,
                new Hazard.HazardEnvelope(
                    new Hazard.SpatialBounds("cell-7/world", new List<(long, long)> { (0, 1000), (0, 1000), (0, 500) }),
                    500, new Hazard.HazardWindow(0, 1000)));

            NaalpException ex = Assert.Throws<NaalpException>(() => Hazard.HazardAuthorizedOptional(null, grant));
            Assert.Equal("HazardUnknown", ex.Kind);

            // A present, well-covered claim still authorizes through the same entry point.
            var claim = new Hazard.HazardClaim(
                Hazard.HazardClass.ToolActuation,
                new Hazard.HazardEnvelope(
                    new Hazard.SpatialBounds("cell-7/world", new List<(long, long)> { (100, 200), (100, 200), (0, 100) }),
                    100, new Hazard.HazardWindow(10, 900)));
            Hazard.HazardAuthorizedOptional(claim, grant); // must NOT throw
        }

        // ---- structural malformation (fail-closed, never partially valid) -----------------------
        [Fact]
        public void MalformedBodiesRejected()
        {
            // empty axes
            var bad = new Hazard.SpatialBounds("f", new List<(long, long)>());
            Assert.False(bad.IsWellFormed());
            Assert.Equal("HazardMalformed", ErrKind(() => Hazard.SpatialBounds.FromValue(bad.ToValue())));

            // min > max
            var bad2 = new Hazard.SpatialBounds("f", new List<(long, long)> { (10, -10) });
            Assert.False(bad2.IsWellFormed());

            // non-NFC frame ('e' + combining acute, NFD not NFC)
            var bad3 = new Hazard.SpatialBounds("é", new List<(long, long)> { (0, 1) });
            Assert.False(bad3.IsWellFormed());

            // wrong shape entirely (not a map)
            Assert.Equal("HazardMalformed", ErrKind(() => Hazard.HazardClaim.FromValue(new Cbor.U(0))));

            // class present, envelope missing
            var partial = new Cbor.M(new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.U(1)) });
            Assert.Equal("HazardMalformed", ErrKind(() => Hazard.HazardClaim.FromValue(partial)));

            // an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
            // normalized -- see Hazard.HazardBodyFromValue's doc comment.
            var goodEnv = new Hazard.HazardEnvelope(
                new Hazard.SpatialBounds("f", new List<(long, long)> { (0, 1) }), 1, new Hazard.HazardWindow(0, 1));
            var outOfRange = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(99)),
                new Cbor.Pair(new Cbor.U(2), goodEnv.ToValue()),
            });
            Assert.Equal("HazardMalformed", ErrKind(() => Hazard.HazardClaim.FromValue(outOfRange)));
        }

        // ---- containment truth table (independent of the oracle file, direct assertions) --------
        [Fact]
        public void SpatialContainedTruthTable()
        {
            var grant = new Hazard.SpatialBounds("f", new List<(long, long)> { (0, 100), (0, 100) });
            // fully inside -> contained
            var inside = new Hazard.SpatialBounds("f", new List<(long, long)> { (10, 90), (10, 90) });
            Assert.True(Hazard.SpatialContained(inside, grant));
            // equal bounds -> contained (closed interval)
            var equal = new Hazard.SpatialBounds("f", new List<(long, long)> { (0, 100), (0, 100) });
            Assert.True(Hazard.SpatialContained(equal, grant));
            // one axis pokes outside -> not contained
            var outside = new Hazard.SpatialBounds("f", new List<(long, long)> { (10, 90), (10, 101) });
            Assert.False(Hazard.SpatialContained(outside, grant));
            // different frame -> never contained regardless of numeric bounds
            var wrongFrame = new Hazard.SpatialBounds("g", new List<(long, long)> { (10, 90), (10, 90) });
            Assert.False(Hazard.SpatialContained(wrongFrame, grant));
            // fewer axes -> never contained
            var fewer = new Hazard.SpatialBounds("f", new List<(long, long)> { (10, 90) });
            Assert.False(Hazard.SpatialContained(fewer, grant));
        }

        [Fact]
        public void EnvelopeContainedWindowAndSpeed()
        {
            Hazard.HazardEnvelope MkEnv(long lo, long hi, ulong speed, ulong nb, ulong na) =>
                new Hazard.HazardEnvelope(new Hazard.SpatialBounds("f", new List<(long, long)> { (lo, hi) }), speed, new Hazard.HazardWindow(nb, na));

            Hazard.HazardEnvelope grant = MkEnv(0, 100, 500, 100, 900);
            Hazard.HazardEnvelope ok = MkEnv(0, 100, 500, 100, 900); // exact edges, closed interval
            Assert.True(Hazard.EnvelopeContained(ok, grant));
            Hazard.HazardEnvelope speedOver = MkEnv(0, 100, 501, 100, 900);
            Assert.False(Hazard.EnvelopeContained(speedOver, grant));
            Hazard.HazardEnvelope startsEarly = MkEnv(0, 100, 500, 99, 900);
            Assert.False(Hazard.EnvelopeContained(startsEarly, grant));
            Hazard.HazardEnvelope endsLate = MkEnv(0, 100, 500, 100, 901);
            Assert.False(Hazard.EnvelopeContained(endsLate, grant));
        }
    }
}
