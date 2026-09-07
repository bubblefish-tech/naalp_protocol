// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// The T1.5 (NAALP-REQ-121) ledger-signed consume-receipt / fork-evidence surface and the R-TDCS
    /// trust-decision-closure-sovereignty additions (design.md §7.5, §25, C22) for the C# SDK, graded
    /// against the independent, non-circular corpora <c>vectors/consume_receipt/cases.json</c> and
    /// <c>vectors/trust_decision/cases.json</c> (NOT produced by this code): the ledger-signed consume
    /// receipt body + sign/verify, fork detection (same-ledger and cross-ledger), the
    /// first-append-wins compare-and-set anchor, wire edge cases (non-canonical, oversized position,
    /// empty-vs-absent ledger), the R-TDCS-5 audience binding, the R-TDCS-3 party-visible refusal
    /// (closed outcome set, no detail leak), and R-TDCS-4 freshness independence.
    ///
    /// <para>Mirrors impl/go/approval/{approval_test.go (T1.5 section), tdcs_test.go, wire_tdcs_test.go,
    /// audience_consume_test.go} and impl/rust/src/approval.rs's T1.5 test module.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj --filter FullyQualifiedName~ApprovalKatTest</c></para>
    /// </summary>
    public sealed class ApprovalKatTest
    {
        private static JsonElement LoadVector(string relPath)
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, relPath);
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException(relPath + " not found from " + AppContext.BaseDirectory);
        }

        private static JsonElement CrVector() => LoadVector(Path.Combine("vectors", "consume_receipt", "cases.json"));
        private static JsonElement TdcsVector() => LoadVector(Path.Combine("vectors", "trust_decision", "cases.json"));

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        // Subsequence search over raw bytes (Assert.Contains/DoesNotContain on byte[] means ELEMENT
        // membership, not subsequence -- this checks whether `needle` occurs anywhere inside `haystack`).
        private static bool ContainsBytes(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0)
            {
                return true;
            }
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    return true;
                }
            }
            return false;
        }

        // GetU64 reads a JSON integer that may exceed long.MaxValue and returns it as the SAME BIT
        // PATTERN in a signed long -- the wire convention this port uses for Cbor.U.V / LedgerEntry.Seq
        // / ConsumeReceipt.Position (mirrors IdentityRecordsKatTest.GetU64).
        private static long GetU64(JsonElement el, string prop)
        {
            JsonElement v = el.GetProperty(prop);
            // R12 (NAALP-01-03): a 64-bit position/counter above 2^53 is carried as a decimal string
            // so a float64 decoder cannot round it; parse the string exactly (same bit pattern).
            if (v.ValueKind == JsonValueKind.String)
            {
                return unchecked((long)ulong.Parse(v.GetString()!));
            }
            if (v.TryGetInt64(out long l))
            {
                return l;
            }
            return unchecked((long)v.GetUInt64());
        }

        private static string TempWal(string tag) => Path.Combine(Path.GetTempPath(), "naalp-consume-receipt-" + tag + "-" + Guid.NewGuid().ToString("N") + ".wal");

        /// <summary>A real deterministic ML-DSA-65 ledger key for the given seed byte (mirrors Go's
        /// ledgerKey helper).</summary>
        private static (int Alg, byte[] Pk, byte[] Seed) LedgerKey(byte seedByte)
        {
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                seed[i] = seedByte;
            }
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            return (Cose.ALG_MLDSA65, pk, seed);
        }

        /// <summary>Builds a ledger-id -> (alg, pubkey) resolver over named pairs (mirrors Go's resolverFor).</summary>
        private static Func<byte[], (int Alg, byte[] Pk, bool Ok)> ResolverFor(Dictionary<string, (int Alg, byte[] Pk)> pairs)
        {
            return (id) =>
            {
                string k = Hex(id);
                if (pairs.TryGetValue(k, out (int Alg, byte[] Pk) v))
                {
                    return (v.Alg, v.Pk, true);
                }
                return (0, Array.Empty<byte>(), false);
            };
        }

        private static Approval.ConsumeReceipt ReceiptOf(JsonElement j)
        {
            return new Approval.ConsumeReceipt(
                Hb(j.GetProperty("ledger_hex").GetString()!),
                Hb(j.GetProperty("approval_id_hex").GetString()!),
                GetU64(j, "position"));
        }

        // ==== T1.5 (NAALP-REQ-121): ledger-signed consume receipt ================================

        // ---- receipt body byte-parity: base + sequence + every fork leg -------------------------

        [Fact]
        public void ConsumeReceiptBytesMatchOracle()
        {
            JsonElement c = CrVector();
            var all = new List<JsonElement> { c.GetProperty("base") };
            foreach (JsonElement s in c.GetProperty("sequence").EnumerateArray())
            {
                all.Add(s);
            }
            foreach (JsonElement f in c.GetProperty("forks").EnumerateArray())
            {
                all.Add(f.GetProperty("a"));
                all.Add(f.GetProperty("b"));
            }
            Assert.True(all.Count > 0, "no consume-receipt cases");
            foreach (JsonElement rj in all)
            {
                string got = Hex(ReceiptOf(rj).Bytes());
                Assert.True(got == rj.GetProperty("body_hex").GetString(), "receipt body mismatch");
            }
        }

        // ---- sign/verify: valid, unnamed ledger, tampered signature, wrong ledger key -----------

        [Fact]
        public void ConsumeReceiptSignVerify()
        {
            JsonElement c = CrVector();
            (int Alg, byte[] Pk, byte[] Seed) k = LedgerKey(0x51);
            Approval.ConsumeReceipt r = ReceiptOf(c.GetProperty("base"));
            byte[] sig = Approval.SignConsumeReceipt(r, k.Alg, k.Seed);
            Approval.VerifyConsumeReceipt(r, k.Alg, k.Pk, sig); // must not throw

            var unnamed = new Approval.ConsumeReceipt(Array.Empty<byte>(), r.ApprovalId, r.Position);
            NaalpException ex1 = Assert.Throws<NaalpException>(() => Approval.VerifyConsumeReceipt(unnamed, k.Alg, k.Pk, sig));
            Assert.Equal("ConsumeReceiptUnsigned", ex1.Kind);

            byte[] bad = (byte[])sig.Clone();
            bad[bad.Length - 1] ^= 1;
            NaalpException ex2 = Assert.Throws<NaalpException>(() => Approval.VerifyConsumeReceipt(r, k.Alg, k.Pk, bad));
            Assert.Equal("ConsumeReceiptUnsigned", ex2.Kind);

            (int Alg, byte[] Pk, byte[] Seed) other = LedgerKey(0x52);
            NaalpException ex3 = Assert.Throws<NaalpException>(() => Approval.VerifyConsumeReceipt(r, other.Alg, other.Pk, sig));
            Assert.Equal("ConsumeReceiptUnsigned", ex3.Kind);
        }

        // ---- fork detection, same ledger, two positions ------------------------------------------

        [Fact]
        public void ConsumeForkSameLedgerDetected()
        {
            JsonElement c = CrVector();
            JsonElement fk = default;
            bool found = false;
            foreach (JsonElement f in c.GetProperty("forks").EnumerateArray())
            {
                if (f.GetProperty("name").GetString() == "same_ledger_diff_position")
                {
                    fk = f;
                    found = true;
                    break;
                }
            }
            Assert.True(found, "same_ledger_diff_position case missing from oracle");
            Assert.Equal("fork", fk.GetProperty("expect").GetString());

            (int Alg, byte[] Pk, byte[] Seed) k = LedgerKey(0x41); // one ledger signs both conflicting positions
            Approval.ConsumeReceipt ra = ReceiptOf(fk.GetProperty("a"));
            Approval.ConsumeReceipt rb = ReceiptOf(fk.GetProperty("b"));
            byte[] sigA = Approval.SignConsumeReceipt(ra, k.Alg, k.Seed);
            byte[] sigB = Approval.SignConsumeReceipt(rb, k.Alg, k.Seed);

            var resolve = ResolverFor(new Dictionary<string, (int Alg, byte[] Pk)> { { Hex(ra.Ledger), (k.Alg, k.Pk) } });
            Approval.ReceiptSet rs = Approval.NewReceiptSet(resolve);
            Assert.Null(rs.Observe(ra, sigA));
            Approval.ConsumeForkEvidence? fe = rs.Observe(rb, sigB);
            Assert.NotNull(fe);
            Assert.NotEqual(fe!.A.Position, fe.B.Position); // the contradiction is legible
            fe.Verify(resolve); // must not throw: non-repudiable

            // a byte-identical re-emission is a benign duplicate, never flagged.
            Approval.ReceiptSet rs2 = Approval.NewReceiptSet(resolve);
            rs2.Observe(ra, sigA);
            Assert.Null(rs2.Observe(ra, sigA));
        }

        // ---- fork detection, cross ledger, live via ConsumeWithReceipt --------------------------

        [Fact]
        public void ConsumeForkCrossLedgerDetected()
        {
            JsonElement c = CrVector();
            byte[] ledgerAId = Hb(c.GetProperty("ledgers").GetProperty("a_hex").GetString()!);
            byte[] ledgerBId = Hb(c.GetProperty("ledgers").GetProperty("b_hex").GetString()!);
            byte[] approvalX = Hb(c.GetProperty("approvals").GetProperty("x_hex").GetString()!);
            string ledgerAName = System.Text.Encoding.UTF8.GetString(ledgerAId);
            string ledgerBName = System.Text.Encoding.UTF8.GetString(ledgerBId);
            (int Alg, byte[] Pk, byte[] Seed) ka = LedgerKey(0x41);
            (int Alg, byte[] Pk, byte[] Seed) kb = LedgerKey(0x42);

            string pathA = TempWal("cross_a");
            string pathB = TempWal("cross_b");
            try
            {
                Approval.Ledger lA = Approval.OpenLedgerSigned(pathA, ledgerAName, ka.Alg, ka.Seed);
                Approval.Ledger lB = Approval.OpenLedgerSigned(pathB, ledgerBName, kb.Alg, kb.Seed);
                try
                {
                    // two independent ordering authorities, run concurrently; each consumes approval X
                    // locally (the double spend is not prevented, only made provable on comparison).
                    Task<(Approval.LedgerEntry, Approval.ConsumeReceipt, byte[])> tA = Task.Run(() => lA.ConsumeWithReceipt(approvalX, "requester"));
                    Task<(Approval.LedgerEntry, Approval.ConsumeReceipt, byte[])> tB = Task.Run(() => lB.ConsumeWithReceipt(approvalX, "requester"));
                    Task.WaitAll(tA, tB);
                    var results = new List<(Approval.ConsumeReceipt R, byte[] Sig)>
                    {
                        (tA.Result.Item2, tA.Result.Item3),
                        (tB.Result.Item2, tB.Result.Item3),
                    };

                    var resolve = ResolverFor(new Dictionary<string, (int Alg, byte[] Pk)>
                    {
                        { Hex(ledgerAId), (ka.Alg, ka.Pk) },
                        { Hex(ledgerBId), (kb.Alg, kb.Pk) },
                    });
                    Approval.ReceiptSet rs = Approval.NewReceiptSet(resolve);
                    Approval.ConsumeForkEvidence? fork = null;
                    foreach ((Approval.ConsumeReceipt r, byte[] sig) in results)
                    {
                        Approval.ConsumeForkEvidence? fe = rs.Observe(r, sig);
                        if (fe != null)
                        {
                            fork = fe;
                        }
                    }
                    Assert.NotNull(fork);
                    Assert.NotEqual(Hex(fork!.A.Ledger), Hex(fork.B.Ledger)); // names both ledgers, not one twice
                    fork.Verify(resolve); // must not throw
                }
                finally
                {
                    lA.Close();
                    lB.Close();
                }
            }
            finally
            {
                if (File.Exists(pathA)) File.Delete(pathA);
                if (File.Exists(pathB)) File.Delete(pathB);
            }
        }

        // ---- ConsumeWithReceipt first-append-wins CAS --------------------------------------------

        [Fact]
        public void ConsumeFirstAppendWinsCas()
        {
            JsonElement c = CrVector();
            byte[] ledgerAId = Hb(c.GetProperty("ledgers").GetProperty("a_hex").GetString()!);
            byte[] approvalX = Hb(c.GetProperty("approvals").GetProperty("x_hex").GetString()!);
            string ledgerAName = System.Text.Encoding.UTF8.GetString(ledgerAId);
            (int Alg, byte[] Pk, byte[] Seed) k = LedgerKey(0x41);
            string path = TempWal("cas");
            try
            {
                Approval.Ledger l = Approval.OpenLedgerSigned(path, ledgerAName, k.Alg, k.Seed);
                try
                {
                    (Approval.LedgerEntry e, Approval.ConsumeReceipt r1, byte[] sig1) = l.ConsumeWithReceipt(approvalX, "requester");
                    Assert.Equal(0L, e.Seq);
                    Assert.Equal(0L, r1.Position);

                    NaalpException ex = Assert.Throws<NaalpException>(() => l.ConsumeWithReceipt(approvalX, "requester"));
                    Assert.Equal("AlreadyConsumed", ex.Kind); // second consume must be first-append-wins
                    Assert.Equal(1, l.Len());
                }
                finally
                {
                    l.Close();
                }
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }

        // ---- exactly-once under a concurrent race (ConsumeWithReceipt) --------------------------

        [Fact]
        public void ConsumeReceiptExactlyOnceUnderRace()
        {
            JsonElement c = CrVector();
            byte[] ledgerAId = Hb(c.GetProperty("ledgers").GetProperty("a_hex").GetString()!);
            byte[] approvalX = Hb(c.GetProperty("approvals").GetProperty("x_hex").GetString()!);
            string ledgerAName = System.Text.Encoding.UTF8.GetString(ledgerAId);
            (int Alg, byte[] Pk, byte[] Seed) k = LedgerKey(0x41);
            string path = TempWal("race");
            try
            {
                Approval.Ledger l = Approval.OpenLedgerSigned(path, ledgerAName, k.Alg, k.Seed);
                try
                {
                    const int N = 64;
                    long wins = 0;
                    long alreadys = 0;
                    long unexpected = 0;
                    (Approval.ConsumeReceipt R, byte[] Sig)? winner = null;
                    var winLock = new object();
                    using var start = new ManualResetEventSlim(false);
                    var tasks = new Task[N];
                    for (int i = 0; i < N; i++)
                    {
                        tasks[i] = Task.Run(() =>
                        {
                            start.Wait();
                            try
                            {
                                (Approval.LedgerEntry _, Approval.ConsumeReceipt r, byte[] sig) = l.ConsumeWithReceipt(approvalX, "requester");
                                Interlocked.Increment(ref wins);
                                lock (winLock) { winner = (r, sig); }
                            }
                            catch (NaalpException ex) when (ex.Kind == "AlreadyConsumed")
                            {
                                Interlocked.Increment(ref alreadys);
                            }
                            catch
                            {
                                Interlocked.Increment(ref unexpected);
                            }
                        });
                    }
                    start.Set();
                    Task.WaitAll(tasks);
                    Assert.Equal(0L, Interlocked.Read(ref unexpected));
                    Assert.Equal(1L, Interlocked.Read(ref wins));
                    Assert.Equal((long)(N - 1), Interlocked.Read(ref alreadys));
                    Assert.Equal(1, l.Len());

                    // the single minted receipt is not a fork with itself.
                    var resolve = ResolverFor(new Dictionary<string, (int Alg, byte[] Pk)> { { Hex(ledgerAId), (k.Alg, k.Pk) } });
                    Approval.ReceiptSet rs = Approval.NewReceiptSet(resolve);
                    Assert.NotNull(winner);
                    Assert.Null(rs.Observe(winner!.Value.R, winner.Value.Sig));
                }
                finally
                {
                    l.Close();
                }
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }

        // ---- wire edge cases: non-canonical, oversized position, empty-vs-absent ledger ---------

        [Fact]
        public void ConsumeReceiptWireCases()
        {
            JsonElement c = CrVector();
            JsonElement wire = c.GetProperty("wire");

            // keys out of order -> the strict decoder rejects NonCanonical, before any receipt rule.
            byte[] noncanon = Hb(wire.GetProperty("keys_out_of_order").GetProperty("payload_hex").GetString()!);
            NaalpException nc = Assert.Throws<NaalpException>(() => Cbor.Decode(noncanon));
            Assert.Equal("NonCanonical", nc.Kind);
            // the canonical variant of the same logical receipt decodes cleanly.
            byte[] canon = Hb(wire.GetProperty("keys_out_of_order").GetProperty("canonical_payload_hex").GetString()!);
            Cbor.Decode(canon); // must not throw

            // position too large for a normal machine int: 64-bit uint round-trips.
            byte[] ledgerX = Hb(c.GetProperty("base").GetProperty("ledger_hex").GetString()!);
            byte[] approvalXb = Hb(c.GetProperty("base").GetProperty("approval_id_hex").GetString()!);
            foreach (JsonElement big in wire.GetProperty("position_too_large").EnumerateArray())
            {
                long pos = GetU64(big, "position");
                var r = new Approval.ConsumeReceipt(ledgerX, approvalXb, pos);
                Assert.True(Hex(r.Bytes()) == big.GetProperty("body_hex").GetString(), big.GetProperty("name").GetString());
                var m = (Cbor.M)Cbor.Decode(Hb(big.GetProperty("body_hex").GetString()!));
                bool found = false;
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (p.K is Cbor.U ku && ku.V == 3 && p.Val is Cbor.U pv)
                    {
                        Assert.Equal(pos, pv.V);
                        found = true;
                    }
                }
                Assert.True(found, "position field not found in decoded map");
            }

            // empty-ledger receipt: matches the oracle bytes, is verify-rejected fail-closed, and its
            // bytes differ from the absent-ledger variant (empty != absent).
            JsonElement el = wire.GetProperty("empty_ledger");
            var empty = new Approval.ConsumeReceipt(Array.Empty<byte>(), Hb(el.GetProperty("approval_id_hex").GetString()!), GetU64(el, "position"));
            Assert.Equal(el.GetProperty("body_hex").GetString(), Hex(empty.Bytes()));
            (int Alg, byte[] Pk, byte[] Seed) k = LedgerKey(0x41);
            NaalpException exEmpty = Assert.Throws<NaalpException>(() => Approval.VerifyConsumeReceipt(empty, k.Alg, k.Pk, Array.Empty<byte>()));
            Assert.Equal("ConsumeReceiptUnsigned", exEmpty.Kind);
            Assert.NotEqual(el.GetProperty("body_hex").GetString(), wire.GetProperty("absent_ledger").GetProperty("body_hex").GetString());
        }

        // ==== R-TDCS-5 (design.md §25, C22): approval audience binding ============================

        [Fact]
        public void AudienceByteParityAndCheck()
        {
            JsonElement c = TdcsVector();
            JsonElement a = c.GetProperty("audience");
            byte[] approves = Hb(a.GetProperty("approves_hex").GetString()!);
            string approver = a.GetProperty("approver").GetString()!;
            long grant = a.GetProperty("grant").GetInt64();
            byte[] nonce = Hb(a.GetProperty("nonce_hex").GetString()!);
            long notAfter = GetU64(a, "not_after");
            string useMatch = a.GetProperty("use_context_match").GetString()!;
            string useMismatch = a.GetProperty("use_context_mismatch").GetString()!;

            int n = 0;
            foreach (JsonElement tc in a.GetProperty("cases").EnumerateArray())
            {
                n++;
                string name = tc.GetProperty("name").GetString()!;
                string audience = tc.GetProperty("audience").GetString()!; // "" for audience_absent
                var rec = new Approval.ApprovalRecord(approves, approver, grant, nonce, notAfter, audience);
                Assert.True(Hex(rec.Bytes()) == tc.GetProperty("record_hex").GetString(), name + ": bytes");
                Assert.True(Hex(rec.Id()) == tc.GetProperty("approval_id_hex").GetString(), name + ": id");
            }
            Assert.True(n > 0, "no audience.cases loaded");

            // naming a context must change the signed bytes (a verdict cannot silently move contexts).
            var present = new Approval.ApprovalRecord(approves, approver, grant, nonce, notAfter, useMatch);
            var absent = new Approval.ApprovalRecord(approves, approver, grant, nonce, notAfter);
            Assert.NotEqual(Hex(present.Bytes()), Hex(absent.Bytes()));

            Approval.VerifyAudience(present, useMatch); // must not throw
            NaalpException ex = Assert.Throws<NaalpException>(() => Approval.VerifyAudience(present, useMismatch));
            Assert.Equal("AudienceMismatch", ex.Kind);
            Approval.VerifyAudience(absent, useMismatch); // absent audience passes any context
        }

        // ==== R-TDCS-3 (design.md §25, C22): party-visible coarse refusal =========================
        //
        // MUTATION ANCHOR: Approval.IsKnownRefusalOutcome gates ParseRefusal's UnknownRefusalOutcome
        // rejection (see RefusalUnknownOutcomeRejectedFailClosed below). Neutering it to `return true;`
        // (always) would let the unknown-outcome (3) refusal body parse as valid, flipping that
        // assertion from pass to fail.

        [Fact]
        public void RefusalCoarseAndNoLeak()
        {
            JsonElement c = TdcsVector();
            JsonElement r = c.GetProperty("refusal");
            byte[] fullRecord = Hb(r.GetProperty("full_record_hex").GetString()!);
            byte[] recordId = Hb(r.GetProperty("full_record_id_hex").GetString()!);
            byte[] reason = System.Text.Encoding.UTF8.GetBytes(r.GetProperty("leaked_reason").GetString()!);

            int n = 0;
            foreach (JsonElement tc in r.GetProperty("cases").EnumerateArray())
            {
                n++;
                string name = tc.GetProperty("name").GetString()!;
                long outcome = tc.GetProperty("outcome").GetInt64();
                Approval.Refusal ref_ = Approval.RefusalFromRecord(outcome, fullRecord);
                byte[] b = ref_.Bytes();
                Assert.True(Hex(b) == tc.GetProperty("record_hex").GetString(), name + ": bytes");
                Assert.False(ContainsBytes(b, reason), name + ": the record's reason LEAKED into the party-visible refusal");
                Assert.True(ContainsBytes(b, recordId), name + ": refusal does not carry the full-record content id");

                Approval.Refusal got = Approval.ParseRefusal(b);
                Assert.True(got.Outcome == outcome, name + ": round-trip outcome");
                Assert.True(Hex(got.Record) == Hex(recordId), name + ": round-trip record id");
            }
            Assert.True(n > 0, "no refusal.cases loaded");

            JsonElement reject = r.GetProperty("reject");
            NaalpException unk = Assert.Throws<NaalpException>(() => Approval.ParseRefusal(Hb(reject.GetProperty("unknown_outcome_hex").GetString()!)));
            Assert.Equal("UnknownRefusalOutcome", unk.Kind);

            var rejectCases = new (string Name, string Hex)[]
            {
                ("extra field (leaked detail)", reject.GetProperty("detail_leak_extra_field_hex").GetString()!),
                ("missing record id", reject.GetProperty("missing_record_hex").GetString()!),
                ("empty record id", reject.GetProperty("empty_record_hex").GetString()!),
            };
            foreach ((string name, string hex) in rejectCases)
            {
                NaalpException ex = Assert.Throws<NaalpException>(() => Approval.ParseRefusal(Hb(hex)));
                Assert.True(ex.Kind == "RefusalDetailLeak", name + ": want RefusalDetailLeak, got " + ex.Kind);
            }
        }

        /// <summary>
        /// The FAIL-CLOSED anchor, isolated: an outcome OUTSIDE the closed set {denied, held,
        /// unverifiable} MUST be rejected by <see cref="Approval.IsKnownRefusalOutcome"/> AND by
        /// <see cref="Approval.ParseRefusal"/> (UnknownRefusalOutcome) -- never accepted. This is the
        /// recorded mutation target: neutering IsKnownRefusalOutcome to always return true flips this
        /// test red.
        /// </summary>
        [Fact]
        public void RefusalUnknownOutcomeRejectedFailClosed()
        {
            Assert.False(Approval.IsKnownRefusalOutcome(3));
            Assert.False(Approval.IsKnownRefusalOutcome(-1));
            Assert.False(Approval.IsKnownRefusalOutcome(999));
            Assert.True(Approval.IsKnownRefusalOutcome(Approval.RefusalDenied));
            Assert.True(Approval.IsKnownRefusalOutcome(Approval.RefusalHeld));
            Assert.True(Approval.IsKnownRefusalOutcome(Approval.RefusalUnverifiable));

            JsonElement c = TdcsVector();
            byte[] unknownBody = Hb(c.GetProperty("refusal").GetProperty("reject").GetProperty("unknown_outcome_hex").GetString()!);
            NaalpException ex = Assert.Throws<NaalpException>(() => Approval.ParseRefusal(unknownBody));
            Assert.Equal("UnknownRefusalOutcome", ex.Kind);
        }

        // ==== R-TDCS-4 (design.md §25, C22): freshness independence ===============================

        [Fact]
        public void FreshnessIndependence()
        {
            (int Alg, byte[] Pk, byte[] Seed) approver = LedgerKey(0x11); // the authenticated party
            (int Alg, byte[] Pk, byte[] Seed) ledger = LedgerKey(0x22);   // the ordering authority -- a DISTINCT key
            byte[] argsId = System.Text.Encoding.UTF8.GetBytes("the-exact-canonical-args-content-id");
            byte[] approverId = System.Text.Encoding.UTF8.GetBytes("approver-authenticated-party-id");
            byte[] ledgerId = System.Text.Encoding.UTF8.GetBytes("ordering-authority-ledger-id");

            var a = new Approval.ApprovalRecord(argsId, "approver-authenticated-party-id", 1, System.Text.Encoding.UTF8.GetBytes("anti-replay-nonce"), 1000);
            byte[] aSig = Approval.SignApproval(a, approver.Alg, approver.Seed);
            var r = new Approval.ConsumeReceipt(ledgerId, a.Id(), 7);
            byte[] rSig = Approval.SignConsumeReceipt(r, ledger.Alg, ledger.Seed);

            // Distinct ordering authority (party != ledger): verifies.
            Approval.VerifyFreshIndependent(a, approver.Alg, approver.Pk, aSig, argsId, 1000, r, ledger.Alg, ledger.Pk, rSig, approverId);

            // Self-asserted freshness (party == ledger): rejected -- the load-bearing distinctness.
            NaalpException selfEx = Assert.Throws<NaalpException>(() =>
                Approval.VerifyFreshIndependent(a, approver.Alg, approver.Pk, aSig, argsId, 1000, r, ledger.Alg, ledger.Pk, rSig, ledgerId));
            Assert.Equal("FreshnessSelfAsserted", selfEx.Kind);

            // The distinctness check does not weaken the underlying checks: expired still fails closed.
            NaalpException expEx = Assert.Throws<NaalpException>(() =>
                Approval.VerifyFreshIndependent(a, approver.Alg, approver.Pk, aSig, argsId, a.NotAfter + 1, r, ledger.Alg, ledger.Pk, rSig, approverId));
            Assert.Equal("ApprovalExpired", expEx.Kind);

            // A receipt with no named ordering authority is not evidence, even with a distinct party id.
            var empty = new Approval.ConsumeReceipt(Array.Empty<byte>(), a.Id(), 7);
            (int Alg, byte[] Pk, byte[] Seed) throwaway = LedgerKey(0x33);
            byte[] emptySig = Approval.SignConsumeReceipt(empty, throwaway.Alg, throwaway.Seed);
            NaalpException unnamedEx = Assert.Throws<NaalpException>(() =>
                Approval.VerifyFreshIndependent(a, approver.Alg, approver.Pk, aSig, argsId, 1000, empty, ledger.Alg, ledger.Pk, emptySig, approverId));
            Assert.Equal("ConsumeReceiptUnsigned", unnamedEx.Kind);
        }

        // ==== design.md §2.5.3 audience-checked consume choke point, via a signed ledger ==========

        [Fact]
        public void ConsumeObjectAudienceViaSignedLedger()
        {
            (int Alg, byte[] Pk, byte[] Seed) k = LedgerKey(0x07);
            byte[] appId = System.Text.Encoding.UTF8.GetBytes("approval-content-id-0001");
            string path = TempWal("consume-object");
            try
            {
                Approval.Ledger l = Approval.OpenLedgerSigned(path, "authority-A", k.Alg, k.Seed);
                try
                {
                    var wrongAud = new Envelope.Object(0, 0, Array.Empty<byte>(), 0, 0, new Cbor.M(new List<Cbor.Pair>()), audience: "authority-B");
                    NaalpException wrongEx = Assert.Throws<NaalpException>(() => l.ConsumeObject(wrongAud, appId, "by-x"));
                    Assert.Equal("WrongAudience", wrongEx.Kind);
                    Assert.Equal(0, l.Len());

                    var correctAud = new Envelope.Object(0, 0, Array.Empty<byte>(), 0, 0, new Cbor.M(new List<Cbor.Pair>()), audience: "authority-A");
                    Approval.LedgerEntry entry = l.ConsumeObject(correctAud, appId, "by-x");
                    Assert.NotNull(entry);
                    Assert.Equal(1, l.Len());
                    Assert.True(l.IsConsumed(appId));
                }
                finally
                {
                    l.Close();
                }
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }
    }
}
