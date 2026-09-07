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
    /// C15 multi-hop agent-delegation conformance for the C# SDK, graded against the shared independent
    /// corpus <c>vectors/delegation/cases.json</c> (NOT produced by this code): the DelegationGrant wire
    /// body + content id (and its GrantFromBody decode round-trip), the D2 scope-containment path-prefix
    /// rule, and the 12-step leaf-&gt;root chain verifier's verdict for every scenario (authorized /
    /// GrantExpired / GrantNotYetValid / GrantRevoked / CapExceedsParent / DelegationDepthExceeded /
    /// UntrustedChainRoot / ChainBroken / EffectNotAuthorized).
    ///
    /// <para>CORPUS-GRADED (pure bytes / verdicts): every grant body and id, every scope-containment
    /// verdict, and every chain-verification verdict — reproduced byte-for-byte or verdict-for-verdict
    /// from the corpus. The chain scenarios are abstract (issuer/subject with index-referenced causes),
    /// exactly as the reference verdict tests build them; each scenario grant is assigned a distinct
    /// synthetic content id and the verdict is invariant to the specific id bytes. WIRING DEMONSTRATED IN
    /// ISOLATION: the D4 two-gate composition (<see cref="Delegation.AuthorizeDestructive"/>) wires a
    /// valid delegation chain onto a real §7 approval consumed single-use through the
    /// <see cref="Approval.Ledger"/> from this wave — a destructive action authorizes once and denies
    /// AlreadyConsumed on replay. Ported from impl/go/delegation; mirrors the Java/Kotlin ports.</para>
    ///
    /// <para>The envelope-integration layer (EnvelopeObject / VerifyGrantObject / ComposedKindValidator,
    /// D3 step 3) is NOT graded by this corpus, whose scenarios are abstract (the reference verdict tests
    /// build Resolved grants directly, as ChainScenariosMatchOracle above does); it IS demonstrated in
    /// isolation with real ML-DSA-65 crypto below — a self-built, self-signed two-hop chain authorizes,
    /// and each D3-step-3 failure mode (tampered signature, forged issuer, a baseline-only verifier, a
    /// non-NFC subject) is exercised — mirroring impl/go/delegation/delegation_test.go's dedicated
    /// behavioural tests (TestValid2HopAuthorized, TestTamperedGrantSignatureRejected,
    /// TestForgedIssuerRejected, TestBaselineVerifierRejectsGrantKind, TestNonNFCSubjectRejected).</para>
    /// </summary>
    public sealed class DelegationTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "delegation", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/delegation/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        /// <summary>A distinct synthetic content id per scenario grant index (the verdict is invariant to
        /// the specific bytes; only per-index distinctness and consistent cross-reference matter).</summary>
        private static byte[] ScenarioCid(int i) => Cbor.ContentId(Encoding.UTF8.GetBytes("naalp-deleg-grant-" + i));

        private static Delegation.Grant GrantOf(JsonElement g)
        {
            return new Delegation.Grant(
                g.GetProperty("subject").GetString()!,
                g.GetProperty("effect_cap").GetInt64(),
                g.GetProperty("max_depth").GetInt64(),
                g.GetProperty("not_before").GetInt64(),
                g.GetProperty("not_after").GetInt64(),
                g.GetProperty("scope").GetString()!);
        }

        // ---- the DelegationGrant wire body + content id (byte-graded) -------------------------

        [Fact]
        public void GrantBytesMatchOracle()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement g in v.GetProperty("grants").EnumerateArray())
            {
                Delegation.Grant grant = GrantOf(g);
                Assert.Equal(g.GetProperty("body_hex").GetString(), Hex(grant.Bytes()));
                Assert.Equal(g.GetProperty("content_id_hex").GetString(), Hex(grant.ContentId()));
                // GrantFromBody round-trips the decoded body back to the same bytes (the decode direction).
                Delegation.Grant back = Delegation.GrantFromBody(Cbor.Decode(grant.Bytes()));
                Assert.Equal(g.GetProperty("body_hex").GetString(), Hex(back.Bytes()));
                count++;
            }
            Assert.True(count > 0, "corpus carried no grants");

            // a malformed grant body (effect_cap out of the closed lattice) is rejected ChainBroken.
            byte[] bad = Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.T("x")),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(4)), // effect_cap 4 > destructive
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(0)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(0)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(0)),
            }));
            var ex = Assert.Throws<NaalpException>(() => Delegation.GrantFromBody(Cbor.Decode(bad)));
            Assert.Equal("ChainBroken", ex.Kind);
        }

        // ---- the D2 scope-containment path-prefix rule (both allows and denies) ---------------

        [Fact]
        public void ScopeContainmentMatchesOracle()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement r in v.GetProperty("scope_containment").EnumerateArray())
            {
                string child = r.GetProperty("child").GetString()!;
                string parent = r.GetProperty("parent").GetString()!;
                Assert.Equal(r.GetProperty("contained").GetBoolean(), Delegation.ScopeContained(child, parent));
                count++;
            }
            Assert.True(count > 0, "corpus carried no scope-containment rows");
        }

        // ---- the 12-step chain verifier verdict for every scenario (the mutation anchor) ------

        [Fact]
        public void ChainScenariosMatchOracle()
        {
            // Every scenario's verdict must equal the oracle's independently computed verdict — the set
            // contains authorized outcomes AND every named deny, so a constant verifier fails somewhere.
            // THIS is the mutation-target assertion: dropping the step-6 effect-attenuation check in
            // VerifyChain flips the "effect_exceeds_leaf" scenario (a leaf could act above its granted
            // effect_cap — a privilege escalation) from CapExceedsParent to authorized.
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement sc in v.GetProperty("scenarios").EnumerateArray())
            {
                string name = sc.GetProperty("name").GetString()!;
                var gblocks = new List<JsonElement>();
                foreach (JsonElement g in sc.GetProperty("grants").EnumerateArray())
                {
                    gblocks.Add(g);
                }
                var cids = new List<byte[]>();
                for (int i = 0; i < gblocks.Count; i++)
                {
                    cids.Add(ScenarioCid(i));
                }
                var gs = new Dictionary<string, Delegation.Resolved>();
                for (int i = 0; i < gblocks.Count; i++)
                {
                    JsonElement g = gblocks[i];
                    var causes = new List<byte[]>();
                    foreach (JsonElement ci in g.GetProperty("causes").EnumerateArray())
                    {
                        causes.Add(cids[ci.GetInt32()]);
                    }
                    var r = new Delegation.Resolved(cids[i], g.GetProperty("issuer").GetString()!, GrantOf(g), causes);
                    gs[Hex(cids[i])] = r;
                }

                JsonElement ab = sc.GetProperty("action");
                var acauses = new List<byte[]>();
                foreach (JsonElement ci in ab.GetProperty("causes").EnumerateArray())
                {
                    acauses.Add(cids[ci.GetInt32()]);
                }
                var action = new Delegation.Action(ab.GetProperty("signer").GetString()!, ab.GetProperty("effect").GetInt64(),
                    ab.GetProperty("scope").GetString()!, acauses);

                var anchors = new HashSet<string>();
                foreach (JsonElement a in sc.GetProperty("anchors").EnumerateArray())
                {
                    anchors.Add(a.GetString()!);
                }
                var revoked = new Dictionary<string, long>();
                foreach (JsonElement rv in sc.GetProperty("revoked").EnumerateArray())
                {
                    revoked[Hex(cids[rv.GetProperty("grant").GetInt32()])] = rv.GetProperty("pos").GetInt64();
                }
                long now = sc.GetProperty("now").GetInt64();
                string expect = sc.GetProperty("expect").GetString()!;

                string got;
                try
                {
                    Delegation.VerifyChain(action, gs, anchors, revoked, now);
                    got = "authorized";
                }
                catch (NaalpException e)
                {
                    got = e.Kind;
                }
                Assert.Equal(expect, got); // scenario `name` -> `expect`
                Assert.True(expect == got, name); // name surfaced on failure
                count++;
            }
            Assert.True(count > 0, "corpus carried no scenarios");
        }

        // ---- D4 two-gate composition wired onto the real §7 approval ledger --------------------

        [Fact]
        public void D4CompositionAuthorizeConsumeAndDeny()
        {
            byte[] argsId = Cbor.ContentId(Encoding.UTF8.GetBytes("destructive-op-args"));
            byte[] approverSeed = new byte[32];
            for (int i = 0; i < 32; i++) approverSeed[i] = 7;
            byte[] approverPk = Cose.MldsaKeygen("ML-DSA-65", approverSeed);
            byte[] nonce = new byte[16];
            var appr = new Approval.ApprovalRecord(argsId, "A", Policy.DESTRUCTIVE, nonce, 100000);
            byte[] apprSig = Approval.SignApproval(appr, Alg, approverSeed);

            byte[] rootCid = ScenarioCid(0);
            var chainGrant = new Delegation.Grant("B", Policy.DESTRUCTIVE, 0, 100, 900, "");
            var rootGrant = new Delegation.Resolved(rootCid, "A", chainGrant, new List<byte[]>());
            var d4grants = new Dictionary<string, Delegation.Resolved> { [Hex(rootCid)] = rootGrant };
            var d4action = new Delegation.Action("B", Policy.DESTRUCTIVE, "", new List<byte[]> { rootCid });
            var d4anchors = new HashSet<string> { "A" };
            var noRevoked = new Dictionary<string, long>();

            string wal = Path.Combine(Path.GetTempPath(), "naalp-deleg-waveB-" + Guid.NewGuid().ToString("N") + ".wal");
            try
            {
                Approval.Ledger ledger = Approval.OpenLedger(wal);
                // both gates valid: a destructive action authorizes once and consumes the approval.
                Delegation.AuthorizeDestructive(d4action, d4grants, d4anchors, noRevoked, 500, appr, Alg, approverPk, apprSig, argsId, ledger);
                Assert.True(ledger.IsConsumed(appr.Id()));
                // replay: the single-use approval is spent -> AlreadyConsumed.
                var replay = Assert.Throws<NaalpException>(() => Delegation.AuthorizeDestructive(
                    d4action, d4grants, d4anchors, noRevoked, 500, appr, Alg, approverPk, apprSig, argsId, ledger));
                Assert.Equal("AlreadyConsumed", replay.Kind);
                ledger.Close();
            }
            finally
            {
                if (File.Exists(wal)) File.Delete(wal);
            }

            // Gate 2 absent: a valid chain but a mismatched approval denies ApprovalRequired, no append.
            string wal2 = Path.Combine(Path.GetTempPath(), "naalp-deleg-waveB2-" + Guid.NewGuid().ToString("N") + ".wal");
            try
            {
                Approval.Ledger ledger2 = Approval.OpenLedger(wal2);
                byte[] otherArgs = Cbor.ContentId(Encoding.UTF8.GetBytes("some other args"));
                var req = Assert.Throws<NaalpException>(() => Delegation.AuthorizeDestructive(
                    d4action, d4grants, d4anchors, noRevoked, 500, appr, Alg, approverPk, apprSig, otherArgs, ledger2));
                Assert.Equal("ApprovalRequired", req.Kind);
                Assert.Equal(0, ledger2.Len()); // no ledger append on a rejected action
                ledger2.Close();
            }
            finally
            {
                if (File.Exists(wal2)) File.Delete(wal2);
            }

            // Precedence: a broken chain (untrusted root) denies with the D3 error even with a valid
            // approval present, and consumes nothing (the chain is checked first).
            string wal3 = Path.Combine(Path.GetTempPath(), "naalp-deleg-waveB3-" + Guid.NewGuid().ToString("N") + ".wal");
            try
            {
                Approval.Ledger ledger3 = Approval.OpenLedger(wal3);
                var untrustedAnchors = new HashSet<string> { "Z" };
                var d3 = Assert.Throws<NaalpException>(() => Delegation.AuthorizeDestructive(
                    d4action, d4grants, untrustedAnchors, noRevoked, 500, appr, Alg, approverPk, apprSig, argsId, ledger3));
                Assert.Equal("UntrustedChainRoot", d3.Kind);
                Assert.Equal(0, ledger3.Len());
                ledger3.Close();
            }
            finally
            {
                if (File.Exists(wal3)) File.Delete(wal3);
            }
        }

        // ---- envelope-integration layer: EnvelopeObject / VerifyGrantObject / ComposedKindValidator ----
        //
        // Demonstrated in isolation with real ML-DSA-65 crypto (NOT corpus-graded, whose scenarios are
        // abstract issuer/subject chains) — mirrors impl/go/delegation/delegation_test.go's dedicated
        // behavioural tests over these same three functions.

        /// <summary>A key pair plus its self-certifying signer id, for building real signed grants.</summary>
        private readonly struct Key
        {
            public readonly string Id;
            public readonly byte[] Seed;
            public readonly byte[] Pub;
            public Key(string id, byte[] seed, byte[] pub) { Id = id; Seed = seed; Pub = pub; }
        }

        private static Key MkKey(byte seedByte)
        {
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) { seed[i] = seedByte; }
            byte[] pub = Cose.MldsaKeygen("ML-DSA-65", seed);
            string id = Identity.SignerId(Alg, pub);
            return new Key(id, seed, pub);
        }

        /// <summary>ComposedKindValidator accepts a frozen-baseline (channel,kind) OR the tier-1
        /// DelegationGrant, and leaves the frozen registry untouched (a baseline-only validator still
        /// rejects the tier-1 kind).</summary>
        [Fact]
        public void ComposedKindValidatorAcceptsBaselineAndTier1()
        {
            Assert.True(Delegation.ComposedKindValidator(0x0001, 2)); // baseline Memory/MemoryWrite
            Assert.True(Delegation.ComposedKindValidator(Delegation.ChannelCapability, Delegation.KindDelegationGrant));
            Assert.False(Delegation.ComposedKindValidator(0x0001, 999)); // unregistered kind
            Assert.False(Channels.KindValidator(Delegation.ChannelCapability, Delegation.KindDelegationGrant)); // baseline alone
        }

        /// <summary>The happy path with real crypto: build+sign an A-&gt;M-&gt;B two-hop DelegationGrant
        /// chain via <see cref="Delegation.Grant.EnvelopeObject"/> + <see cref="Envelope.Sign"/>, verify
        /// each grant end-to-end via <see cref="Delegation.VerifyGrantObject"/>, build+sign+verify the
        /// action object as B through <see cref="Delegation.ComposedKindValidator"/>, and confirm
        /// <see cref="Delegation.VerifyChain"/> authorizes it. THIS is the mutation-target assertion for
        /// the envelope-integration family: neutering the SignerMismatch issuer-key binding in
        /// VerifyGrantObject does not affect this happy path, but flips ForgedIssuerRejected below.</summary>
        [Fact]
        public void EnvelopeIntegrationTwoHopChainAuthorized()
        {
            Key a = MkKey(50); // trust anchor / root issuer
            Key m = MkKey(51); // middle
            Key b = MkKey(52); // actor

            var rootGrant = new Delegation.Grant(m.Id, Policy.DESTRUCTIVE, 2, 0, 1_000_000, "");
            Envelope.Object rootObj = rootGrant.EnvelopeObject(Encoding.UTF8.GetBytes(a.Id), 1, Cose.PROFILE_PUBLIC, null);
            byte[] rootSigned = Envelope.Sign(rootObj, Alg, a.Seed);
            Delegation.Resolved rootRes = Delegation.VerifyGrantObject(Cose.PROFILE_PUBLIC, Alg, a.Pub, rootSigned);
            Assert.Equal(a.Id, rootRes.Issuer);

            var leafGrant = new Delegation.Grant(b.Id, Policy.DESTRUCTIVE, 1, 0, 1_000_000, "");
            Envelope.Object leafObj = leafGrant.EnvelopeObject(Encoding.UTF8.GetBytes(m.Id), 1, Cose.PROFILE_PUBLIC, new List<byte[]> { rootRes.ContentId });
            byte[] leafSigned = Envelope.Sign(leafObj, Alg, m.Seed);
            Delegation.Resolved leafRes = Delegation.VerifyGrantObject(Cose.PROFILE_PUBLIC, Alg, m.Pub, leafSigned);
            Assert.Equal(m.Id, leafRes.Issuer);

            var grants = new Dictionary<string, Delegation.Resolved>
            {
                [Hex(rootRes.ContentId)] = rootRes,
                [Hex(leafRes.ContentId)] = leafRes,
            };

            // build, sign, and verify the action object as B (grading R-DEL-2 / D3 step 1 with real crypto).
            var actionObj = new Envelope.Object(
                kind: 2, channel: 0x0001, signer: Encoding.UTF8.GetBytes(b.Id), created: 1,
                effect: Policy.NON_IDEMPOTENT_WRITE, body: new Cbor.T("action"),
                causes: new List<byte[]> { leafRes.ContentId });
            byte[] actionSigned = Envelope.Sign(actionObj, Alg, b.Seed);
            Envelope.Object verifiedAction = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, b.Pub, Delegation.ComposedKindValidator, actionSigned);
            Assert.Equal(b.Id, Encoding.UTF8.GetString(verifiedAction.Signer));

            var action = new Delegation.Action(Encoding.UTF8.GetString(verifiedAction.Signer), verifiedAction.Effect, "", verifiedAction.Causes);
            var anchors = new HashSet<string> { a.Id };

            // authorized: VerifyChain returns normally (no exception).
            Delegation.VerifyChain(action, grants, anchors, new Dictionary<string, long>(), 500);
        }

        /// <summary>Flipping a byte of a grant's signature makes it an unverifiable link (D3 step 3) —
        /// VerifyGrantObject rejects it BadSignature.</summary>
        [Fact]
        public void TamperedGrantSignatureRejected()
        {
            Key m = MkKey(53);
            Key b = MkKey(54);
            var leafGrant = new Delegation.Grant(b.Id, Policy.DESTRUCTIVE, 1, 0, 1_000_000, "");
            Envelope.Object leafObj = leafGrant.EnvelopeObject(Encoding.UTF8.GetBytes(m.Id), 1, Cose.PROFILE_PUBLIC, null);
            byte[] leafSigned = Envelope.Sign(leafObj, Alg, m.Seed);
            byte[] tampered = (byte[])leafSigned.Clone();
            tampered[tampered.Length - 1] ^= 0x01;
            var ex = Assert.Throws<NaalpException>(() => Delegation.VerifyGrantObject(Cose.PROFILE_PUBLIC, Alg, m.Pub, tampered));
            Assert.Equal("BadSignature", ex.Kind);
        }

        /// <summary>A grant whose envelope signer field claims an issuer id NOT derived from the signing
        /// key is rejected SignerMismatch (R-DEL-3: the issuer is the verified signer, not a claimed
        /// field). The header/body signer copies agree (both name the victim), so envelope.Verify passes;
        /// the issuer-to-key binding in VerifyGrantObject must still reject. THIS IS THE RED-EVIDENCE
        /// MUTATION ANCHOR for the envelope-integration family: dropping the
        /// <c>Encoding.UTF8.GetString(o.Signer) != issuer</c> check in VerifyGrantObject makes this forged
        /// grant verify successfully.</summary>
        [Fact]
        public void ForgedIssuerRejected()
        {
            Key realKey = MkKey(55);
            Key victim = MkKey(56); // the id the forger tries to impersonate
            Key subject = MkKey(57);
            var g = new Delegation.Grant(subject.Id, Policy.NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "");
            // claim the VICTIM as issuer but sign with realKey.
            Envelope.Object obj = g.EnvelopeObject(Encoding.UTF8.GetBytes(victim.Id), 1, Cose.PROFILE_PUBLIC, null);
            byte[] signed = Envelope.Sign(obj, Alg, realKey.Seed);
            var ex = Assert.Throws<NaalpException>(() => Delegation.VerifyGrantObject(Cose.PROFILE_PUBLIC, Alg, realKey.Pub, signed));
            Assert.Equal("SignerMismatch", ex.Kind);
        }

        /// <summary>A frozen baseline verifier (no tier licensed) rejects the tier-1 DelegationGrant kind
        /// as UnknownKind (fail-closed), exactly as the tier model requires.</summary>
        [Fact]
        public void BaselineVerifierRejectsGrantKind()
        {
            Key issuer = MkKey(58);
            Key subject = MkKey(59);
            var g = new Delegation.Grant(subject.Id, Policy.NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "");
            Envelope.Object obj = g.EnvelopeObject(Encoding.UTF8.GetBytes(issuer.Id), 1, Cose.PROFILE_PUBLIC, null);
            byte[] signed = Envelope.Sign(obj, Alg, issuer.Seed);
            var ex = Assert.Throws<NaalpException>(() => Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, issuer.Pub, Channels.KindValidator, signed));
            Assert.Equal("UnknownKind", ex.Kind);
        }

        /// <summary>A non-NFC subject is rejected at build (fail-closed), before any signing.</summary>
        [Fact]
        public void NonNFCSubjectRejected()
        {
            Key issuer = MkKey(61);
            string nonNfc = "e" + (char)0x0301; // "e" + combining acute (NFD, not NFC)
            var g = new Delegation.Grant(nonNfc, Policy.READ_ONLY, 0, 0, 1, "");
            var ex = Assert.Throws<NaalpException>(() => g.EnvelopeObject(Encoding.UTF8.GetBytes(issuer.Id), 1, Cose.PROFILE_PUBLIC, null));
            Assert.Equal("NonNFC", ex.Kind);
        }
    }
}
