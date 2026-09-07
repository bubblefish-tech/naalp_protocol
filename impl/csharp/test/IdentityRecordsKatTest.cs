// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// The ENVELOPE-adjacent identity RECORD + THREAD surfaces (design.md §5.3/§5.4/§5.2, R-1.4):
    /// <see cref="Identity.RevocationRecord"/>, <see cref="Identity.RevokedAt"/>,
    /// <see cref="Identity.VerifyRevocation"/>, <see cref="Identity.ForeignLinkRecord"/>,
    /// <see cref="Identity.VerifyForeignLink"/>, <see cref="Identity.RotationEvidence"/>,
    /// <see cref="Identity.Thread"/>, <see cref="Identity.Thread.Attributable"/>,
    /// <see cref="Identity.ResolveThread"/> -- graded against the independent, non-circular oracle
    /// (tools/identity_records_oracle.py -&gt; vectors/identity_records/cases.json), i.e.
    /// C# == Go == Rust == oracle. Mirrors impl/go/identity/identity_records_oracle_test.go and
    /// impl/rust/src/identity.rs's identity_records_oracle.py section.
    ///
    /// <para>SECURITY-CRITICAL fail-closed anchor: <see cref="Identity.VerifyRevocation"/> checks
    /// signer-id MEMBERSHIP (record.key OR a deployer-configured recovery id) BEFORE the signature.
    /// "recovery_key_not_configured_reject" is the mutation anchor -- a valid recovery-key signature
    /// presented against an EMPTY authorized-recovery-id set MUST be rejected SignerMismatch; dropping
    /// the membership guard (authorized := true unconditionally) flips it to accept.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~IdentityRecordsKatTest</c></para>
    /// </summary>
    public sealed class IdentityRecordsKatTest
    {
        private static string? FindVector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 10 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "identity_records", "cases.json");
                if (File.Exists(p))
                {
                    return p;
                }
                d = d.Parent;
            }
            return null;
        }

        private static JsonElement LoadCorpus(out JsonDocument doc)
        {
            string? p = FindVector();
            Assert.True(p != null, "committed identity_records vector not found from " + AppContext.BaseDirectory);
            doc = JsonDocument.Parse(File.ReadAllText(p!, Encoding.UTF8));
            return doc.RootElement;
        }

        private static byte[] Hex(string s) => Convert.FromHexString(s);
        private static string HexLower(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        // GetU64 reads a JSON integer that may exceed long.MaxValue and returns it as the SAME BIT
        // PATTERN in a signed long -- the wire convention this port already uses for Cbor.U.V.
        private static long GetU64(JsonElement el, string prop)
        {
            JsonElement v = el.GetProperty(prop);
            if (v.TryGetInt64(out long l))
            {
                return l;
            }
            return unchecked((long)v.GetUInt64());
        }

        private static long? GetNullableU64(JsonElement el, string prop)
        {
            if (!el.TryGetProperty(prop, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            if (v.TryGetInt64(out long l))
            {
                return l;
            }
            return unchecked((long)v.GetUInt64());
        }

        private static List<string> StringList(JsonElement arr)
        {
            var outp = new List<string>();
            foreach (JsonElement e in arr.EnumerateArray())
            {
                outp.Add(e.GetString()!);
            }
            return outp;
        }

        // ---- RevocationRecord.Bytes (§5.3) -----------------------------------------------------

        [Fact]
        public void RevocationRecordBytesMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("revocation").GetProperty("record_bytes");
                int n = 0;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    n++;
                    string name = tc.GetProperty("name").GetString()!;
                    var r = new Identity.RevocationRecord(tc.GetProperty("key").GetString()!, GetU64(tc, "not_after"));
                    string want = tc.GetProperty("bytes_hex").GetString()!;
                    Assert.True(want == HexLower(r.Bytes()), name);
                }
                Assert.True(n > 0, "no revocation.record_bytes cases loaded");
            }
        }

        // ---- RevokedAt (§5.3) -- MUTATION ANCHOR: "at_boundary_still_valid" pins `>` vs `>=`. -------

        [Fact]
        public void RevokedAtMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement scenarios = root.GetProperty("revocation").GetProperty("revoked_at");
                int n = 0;
                foreach (JsonElement sc in scenarios.EnumerateArray())
                {
                    n++;
                    string name = sc.GetProperty("name").GetString()!;
                    string queryKey = sc.GetProperty("query_key").GetString()!;
                    long queryPosition = GetU64(sc, "query_position");
                    bool expectRevoked = sc.GetProperty("expect_revoked").GetBoolean();
                    long? expectNotAfter = GetNullableU64(sc, "expect_not_after");

                    bool revoked = false;
                    long notAfter = 0;
                    foreach (JsonElement rv in sc.GetProperty("revocations").EnumerateArray())
                    {
                        string key = rv.GetProperty("key").GetString()!;
                        if (key != queryKey)
                        {
                            continue;
                        }
                        long na = GetU64(rv, "not_after");
                        var rec = new Identity.RevocationRecord(key, na);
                        if (Identity.RevokedAt(rec, queryPosition))
                        {
                            revoked = true;
                            notAfter = na;
                        }
                    }
                    Assert.True(revoked == expectRevoked, name);
                    if (expectRevoked)
                    {
                        Assert.True(expectNotAfter.HasValue && notAfter == expectNotAfter.Value, name);
                    }
                }
                Assert.True(n > 0, "no revocation.revoked_at scenarios loaded");
            }
        }

        // ---- VerifyRevocation (§5.3, §5.5) -- SECURITY-CRITICAL fail-closed authorization ---------
        // §5.3 permits a Revocation to be signed by the key it revokes OR by a deployer-configured
        // recovery key. VerifyRevocation takes the deployer's authorized recovery-id set and accepts a
        // signer iff its recomputed id equals record.Key or is a member of that set, THEN verifies the
        // signature (membership BEFORE signature, fail-closed). MUTATION ANCHORS:
        // "recovery_key_not_configured_reject" (a valid recovery-key signature with an EMPTY
        // authorized set -> SignerMismatch) and "wrong_key_reject" -- dropping the membership guard
        // flips both to accept.

        [Fact]
        public void VerifyRevocationMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("revocation").GetProperty("verify");
                int n = 0;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    n++;
                    string name = tc.GetProperty("name").GetString()!;
                    JsonElement recEl = tc.GetProperty("record");
                    var rec = new Identity.RevocationRecord(recEl.GetProperty("key").GetString()!, GetU64(recEl, "not_after"));
                    int alg = (int)tc.GetProperty("candidate_alg").GetInt64();
                    byte[] pub = Hex(tc.GetProperty("candidate_pubkey_hex").GetString()!);
                    byte[] sig = Hex(tc.GetProperty("sig_hex").GetString()!);
                    List<string> recoveryIds = StringList(tc.GetProperty("authorized_recovery_ids"));
                    bool expectValid = tc.GetProperty("expect_valid").GetBoolean();
                    string expectKind = tc.TryGetProperty("expect_error_kind", out JsonElement ek) ? ek.GetString() ?? "" : "";

                    if (expectValid)
                    {
                        Identity.VerifyRevocation(rec, alg, pub, sig, recoveryIds); // must not throw
                    }
                    else
                    {
                        NaalpException ex = Assert.Throws<NaalpException>(() =>
                            Identity.VerifyRevocation(rec, alg, pub, sig, recoveryIds));
                        if (expectKind.Length > 0)
                        {
                            Assert.True(expectKind == ex.Kind, name + ": got " + ex.Kind);
                        }
                    }
                }
                Assert.True(n >= 7, "expected at least 7 revocation.verify cases, got " + n);
            }
        }

        /// <summary>
        /// The fail-closed anchor, isolated: a VALID recovery-key signature presented against an
        /// EMPTY authorized-recovery-id set MUST be rejected SignerMismatch (§5.5) -- the membership
        /// check runs before the signature check and an unconfigured recovery key confers no
        /// authority. This is the assertion the required mutation witness targets.
        /// </summary>
        [Fact]
        public void RecoveryKeyNotConfiguredIsRejectedFailClosed()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("revocation").GetProperty("verify");
                bool found = false;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    if (tc.GetProperty("name").GetString() != "recovery_key_not_configured_reject")
                    {
                        continue;
                    }
                    found = true;
                    JsonElement recEl = tc.GetProperty("record");
                    var rec = new Identity.RevocationRecord(recEl.GetProperty("key").GetString()!, GetU64(recEl, "not_after"));
                    int alg = (int)tc.GetProperty("candidate_alg").GetInt64();
                    byte[] pub = Hex(tc.GetProperty("candidate_pubkey_hex").GetString()!);
                    byte[] sig = Hex(tc.GetProperty("sig_hex").GetString()!);
                    List<string> recoveryIds = StringList(tc.GetProperty("authorized_recovery_ids"));
                    Assert.Empty(recoveryIds); // the anchor requires an EMPTY authorized set
                    NaalpException ex = Assert.Throws<NaalpException>(() =>
                        Identity.VerifyRevocation(rec, alg, pub, sig, recoveryIds));
                    Assert.Equal("SignerMismatch", ex.Kind);
                }
                Assert.True(found, "recovery_key_not_configured_reject case not found in the corpus");
            }
        }

        // ---- ForeignLinkRecord.Bytes (§5.4) -- MUTATION ANCHOR: collapsing NFC/NFD to the same bytes
        //      would flip the not-equal assertion below. ------------------------------------------

        [Fact]
        public void ForeignLinkRecordBytesMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("foreign_link").GetProperty("record_bytes");
                var seen = new Dictionary<string, string>();
                int n = 0;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    n++;
                    string name = tc.GetProperty("name").GetString()!;
                    var r = new Identity.ForeignLinkRecord(
                        tc.GetProperty("controls").GetString()!,
                        tc.GetProperty("foreign_id").GetString()!,
                        GetU64(tc, "not_after"));
                    string want = tc.GetProperty("bytes_hex").GetString()!;
                    string got = HexLower(r.Bytes());
                    Assert.True(want == got, name);
                    seen[name] = got;
                }
                Assert.True(n >= 2, "expected at least 2 foreign_link.record_bytes cases, got " + n);
                Assert.NotEqual(seen["nfc_form"], seen["nfd_form_different_bytes"]);
            }
        }

        // ---- VerifyForeignLink (§5.4, §5.5) -----------------------------------------------------
        // Valid+unexpired, the not_after boundary (MUTATION ANCHOR for `now > NotAfter`), expiry
        // (ignored, no error), wrong-key (ignored, no error -- the SAME bucket as expiry per §5.5),
        // and non-NFC foreign_id (NonNFC, checked before expiry/signature).

        [Fact]
        public void VerifyForeignLinkMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("foreign_link").GetProperty("verify");
                int n = 0;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    n++;
                    string name = tc.GetProperty("name").GetString()!;
                    JsonElement recEl = tc.GetProperty("record");
                    var rec = new Identity.ForeignLinkRecord(
                        recEl.GetProperty("controls").GetString()!,
                        recEl.GetProperty("foreign_id").GetString()!,
                        GetU64(recEl, "not_after"));
                    int alg = (int)tc.GetProperty("candidate_alg").GetInt64();
                    byte[] pub = Hex(tc.GetProperty("candidate_pubkey_hex").GetString()!);
                    byte[] sig = Hex(tc.GetProperty("sig_hex").GetString()!);
                    long now = GetU64(tc, "now");
                    string expectKind = tc.TryGetProperty("expect_error_kind", out JsonElement ek) ? ek.GetString() ?? "" : "";

                    if (expectKind.Length > 0)
                    {
                        NaalpException ex = Assert.Throws<NaalpException>(() =>
                            Identity.VerifyForeignLink(rec, alg, pub, sig, now));
                        Assert.True(expectKind == ex.Kind, name + ": got " + ex.Kind);
                        continue;
                    }

                    bool linked = Identity.VerifyForeignLink(rec, alg, pub, sig, now);
                    bool expectLinked = tc.GetProperty("expect_linked").GetBoolean();
                    Assert.True(linked == expectLinked, name);
                    if (expectLinked)
                    {
                        Assert.True(rec.Controls == tc.GetProperty("expect_controls").GetString(), name);
                        Assert.True(rec.ForeignId == tc.GetProperty("expect_foreign_id").GetString(), name);
                    }
                }
                Assert.True(n > 0, "no foreign_link.verify cases loaded");
            }
        }

        // ---- RotationEvidence / Thread / ResolveThread (§5.2, R-1.4) ---------------------------

        private static List<Identity.RotationEvidence> BuildEvidence(JsonElement evsJson)
        {
            var outp = new List<Identity.RotationEvidence>();
            foreach (JsonElement e in evsJson.EnumerateArray())
            {
                var rec = new Identity.RotationRecord(
                    e.GetProperty("old").GetString()!,
                    e.GetProperty("new").GetString()!,
                    GetU64(e, "not_before"));
                string wantBytes = e.GetProperty("record_bytes_hex").GetString()!;
                Assert.True(wantBytes == HexLower(rec.Bytes()), "RotationRecord.Bytes() (RotationEvidence input)");
                int oldAlg = (int)e.GetProperty("old_alg").GetInt64();
                int newAlg = (int)e.GetProperty("new_alg").GetInt64();
                byte[] oldPub = Hex(e.GetProperty("old_pubkey_hex").GetString()!);
                byte[] newPub = Hex(e.GetProperty("new_pubkey_hex").GetString()!);
                byte[] oldSig = Hex(e.GetProperty("old_sig_hex").GetString()!);
                byte[] newSig = Hex(e.GetProperty("new_sig_hex").GetString()!);
                outp.Add(new Identity.RotationEvidence(rec, oldAlg, oldPub, newAlg, newPub, oldSig, newSig));
            }
            return outp;
        }

        // ResolveThread: empty chain, single link, a 3-link contiguous chain, and TWO distinct
        // broken-chain shapes -- "broken_link_old_mismatch" pins the CONTIGUITY guard, and
        // "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE guard (VerifyRotation),
        // isolating one guard from the other. MUTATION ANCHORS.

        [Fact]
        public void ResolveThreadMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("thread").GetProperty("resolve");
                int n = 0;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    n++;
                    string name = tc.GetProperty("name").GetString()!;
                    List<Identity.RotationEvidence> evs = BuildEvidence(tc.GetProperty("evidence"));
                    string expectError = tc.TryGetProperty("expect_error", out JsonElement ee) ? ee.GetString() ?? "" : "";

                    if (expectError.Length > 0)
                    {
                        NaalpException ex = Assert.Throws<NaalpException>(() => Identity.ResolveThread(evs));
                        Assert.True(expectError == ex.Kind, name + ": got " + ex.Kind);
                        continue;
                    }

                    Identity.Thread th = Identity.ResolveThread(evs);
                    JsonElement want = tc.GetProperty("expect_thread");
                    Assert.True(th.Root == want.GetProperty("root").GetString(), name);
                    Assert.True(th.Current == want.GetProperty("current").GetString(), name);
                    List<string> wantChain = StringList(want.GetProperty("chain"));
                    Assert.True(wantChain.Count == th.Chain.Count, name + ": chain length");
                    for (int i = 0; i < wantChain.Count; i++)
                    {
                        Assert.True(wantChain[i] == th.Chain[i], name + ": chain[" + i + "]");
                    }
                }
                Assert.True(n > 0, "no thread.resolve cases loaded");
            }
        }

        // Thread.Attributable: root/intermediate/current keys are attributable; an unrelated key is
        // not. "unrelated_key_not_attributable" is the MUTATION ANCHOR (an always-true stub flips it).

        [Fact]
        public void ThreadAttributableMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement cases = root.GetProperty("thread").GetProperty("attributable");
                int n = 0;
                foreach (JsonElement tc in cases.EnumerateArray())
                {
                    n++;
                    JsonElement thJson = tc.GetProperty("thread");
                    var th = new Identity.Thread(
                        thJson.GetProperty("root").GetString()!,
                        thJson.GetProperty("current").GetString()!,
                        StringList(thJson.GetProperty("chain")));
                    string query = tc.GetProperty("query").GetString()!;
                    bool expect = tc.GetProperty("expect").GetBoolean();
                    Assert.True(th.Attributable(query) == expect, tc.GetProperty("name").GetString());
                }
                Assert.True(n > 0, "no thread.attributable cases loaded");
            }
        }
    }
}
