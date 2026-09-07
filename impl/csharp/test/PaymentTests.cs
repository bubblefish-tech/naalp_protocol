// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C21 (5B.1) NAALP-PAY payment-import conformance for the C# SDK, graded against the shared
    /// independent corpus <c>vectors/payment/cases.json</c> (NOT produced by this code): the closed
    /// payment-format registry, the byte-exact PaymentImport body/head/content-id (incl. the oversized
    /// &gt;2^53 amount and the minimal import), the foreign-payload content id (carriage binding), the
    /// byte-exact ChargeBinding body/head/content-id, the parse round-trip, the fail-closed edge cases
    /// (non-canonical -&gt; NonCanonical / PayMalformed, absent mandatory field -&gt; PayMalformed, a
    /// bstr-currency look-alike -&gt; PayMalformed, empty vs populated foreign distinct by content-id),
    /// and the mismatch content-ids (a wrong amount, wrong payee, or substituted foreign payload yields
    /// a DIFFERENT charge content-id, so a §7 approval bound to the original no longer matches).
    ///
    /// <para>The PaymentImport SIGNATURE is real deterministic ML-DSA-65 via a bare-{1:alg} COSE_Sign1
    /// (as the reference's cose.Sign1); the corpus carries no signed vector for this channel, so
    /// sign/verify is demonstrated in isolation only — stated honestly, not corpus-graded.</para>
    ///
    /// <para><see cref="Payment.AuthorizeCharge"/> IS ported and demonstrated in isolation below
    /// (STEP-2 ten-port parity wave; the corpus grades no approval/consume flow — abstract binding
    /// content ids only): all four fail-closed deny paths (UnknownPaymentFormat, ApprovalMismatch /
    /// ApprovalExpired / BadSignature from <see cref="Approval.VerifyApproval"/>, ApprovalRequired from
    /// the effect-coverage check) plus the success-consumes-exactly-once / replay-denies-AlreadyConsumed
    /// single-use guarantee, wired onto the real <see cref="Approval.Ledger"/> — mirroring
    /// impl/go/payment/payment_test.go's TestChargeSingleUseAndBinding and
    /// TestPaymentImportMultiUseMutation.</para>
    /// </summary>
    public sealed class PaymentTests
    {
        private const int Alg = Cose.ALG_MLDSA65;
        private static readonly byte[] Seed = new byte[32];
        private static readonly byte[] Pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "payment", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/payment/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static Payment.PaymentImport ImportFrom(JsonElement iv)
        {
            return new Payment.PaymentImport(
                iv.GetProperty("format").GetInt64(),
                iv.GetProperty("amount").GetInt64(),
                iv.GetProperty("currency").GetString()!,
                Hb(iv.GetProperty("payee_hex").GetString()!),
                iv.GetProperty("not_after").GetInt64(),
                Hb(iv.GetProperty("foreign_hex").GetString()!));
        }

        // ---- closed payment-format registry (design §24) --------------------------------------

        [Fact]
        public void FormatVocabulary()
        {
            JsonElement v = Vector();
            foreach (JsonElement fv in v.GetProperty("format_vocabulary").EnumerateArray())
            {
                Assert.True(Payment.IsRegisteredFormat(fv.GetProperty("code").GetInt64()), fv.GetProperty("name").GetString());
                Assert.Equal(fv.GetProperty("name").GetString(), Payment.FormatName(fv.GetProperty("code").GetInt64()));
            }
            Assert.False(Payment.IsRegisteredFormat(v.GetProperty("unknown_format").GetInt64()));
            Assert.Equal("unknown", Payment.FormatName(v.GetProperty("unknown_format").GetInt64()));
        }

        [Fact]
        public void ChargeEffectMatchesOracle()
        {
            JsonElement v = Vector();
            Assert.Equal(v.GetProperty("charge_effect").GetInt64(), Payment.ChargeEffect);
            Assert.Equal(Policy.NON_IDEMPOTENT_WRITE, Payment.ChargeEffect);
        }

        // ---- PaymentImport byte parity (design §24) -------------------------------------------

        [Fact]
        public void ImportBodiesMatchOracle()
        {
            JsonElement imports = Vector().GetProperty("imports");
            foreach (string name in new[] { "ap2", "acp", "x402" })
            {
                JsonElement iv = imports.GetProperty(name);
                Payment.PaymentImport p = ImportFrom(iv);
                Assert.Equal(iv.GetProperty("body_hex").GetString(), Hex(p.Bytes()));
                Assert.Equal(iv.GetProperty("head_hex").GetString(), Hex(p.Head()));
                Assert.Equal(iv.GetProperty("id_hex").GetString(), Hex(p.Id()));
                Assert.Equal(iv.GetProperty("foreign_id_hex").GetString(), Hex(p.ForeignId()));
            }
        }

        [Fact]
        public void ChargeBindingIdsMatchOracle()
        {
            // THIS is the mutation-target assertion: the exact charge value a §7 approval binds.
            JsonElement imports = Vector().GetProperty("imports");
            foreach (string name in new[] { "ap2", "acp", "x402" })
            {
                JsonElement iv = imports.GetProperty(name);
                Payment.ChargeBinding cb = ImportFrom(iv).ChargeBinding();
                JsonElement cbv = iv.GetProperty("charge_binding");
                Assert.Equal(cbv.GetProperty("body_hex").GetString(), Hex(cb.Bytes()));
                Assert.Equal(cbv.GetProperty("head_hex").GetString(), Hex(cb.Head()));
                Assert.Equal(cbv.GetProperty("id_hex").GetString(), Hex(cb.ContentId()));
            }
        }

        [Fact]
        public void BigAmountOver253RoundTrips()
        {
            JsonElement bv = Vector().GetProperty("big_amount");
            long amount = long.Parse(bv.GetProperty("amount_str").GetString()!);
            Assert.True(amount > (1L << 53), "oracle big amount must be > 2^53");
            var p = new Payment.PaymentImport(
                bv.GetProperty("format").GetInt64(), amount, bv.GetProperty("currency").GetString()!,
                Hb(bv.GetProperty("payee_hex").GetString()!), bv.GetProperty("not_after").GetInt64(),
                Hb(bv.GetProperty("foreign_hex").GetString()!));
            Assert.Equal(bv.GetProperty("body_hex").GetString(), Hex(p.Bytes()));
            Assert.Equal(bv.GetProperty("head_hex").GetString(), Hex(p.Head()));
            Assert.Equal(bv.GetProperty("id_hex").GetString(), Hex(p.Id()));
            Assert.Equal(bv.GetProperty("charge_binding").GetProperty("id_hex").GetString(), Hex(p.ChargeBinding().ContentId()));
            // and the parsed amount round-trips byte-exact through the strict decoder
            Payment.PaymentImport rp = Payment.ParsePaymentImport(Hb(bv.GetProperty("body_hex").GetString()!));
            Assert.Equal(amount, rp.Amount);
        }

        [Fact]
        public void MinimalImport()
        {
            JsonElement m = Vector().GetProperty("minimal");
            Payment.PaymentImport p = ImportFrom(m);
            Assert.Equal(m.GetProperty("body_hex").GetString(), Hex(p.Bytes()));
            Assert.Equal(m.GetProperty("head_hex").GetString(), Hex(p.Head()));
            Assert.Equal(m.GetProperty("id_hex").GetString(), Hex(p.Id()));
        }

        // ---- parse round-trip + fail-closed edges (design §24, §15) ---------------------------

        [Fact]
        public void ParseRoundtrips()
        {
            JsonElement imports = Vector().GetProperty("imports");
            foreach (string name in new[] { "ap2", "acp", "x402" })
            {
                JsonElement iv = imports.GetProperty(name);
                Payment.PaymentImport p = Payment.ParsePaymentImport(Hb(iv.GetProperty("body_hex").GetString()!));
                Assert.Equal(iv.GetProperty("format").GetInt64(), p.Format);
                Assert.Equal(iv.GetProperty("amount").GetInt64(), p.Amount);
                Assert.Equal(iv.GetProperty("currency").GetString(), p.Currency);
                Assert.Equal(Hex(Hb(iv.GetProperty("payee_hex").GetString()!)), Hex(p.Payee));
                Assert.Equal(iv.GetProperty("not_after").GetInt64(), p.NotAfter);
                Assert.Equal(Hex(Hb(iv.GetProperty("foreign_hex").GetString()!)), Hex(p.Foreign));
            }
        }

        [Fact]
        public void NoncanonicalBodyRejected()
        {
            JsonElement ec = Vector().GetProperty("edge_cases").GetProperty("keys_out_of_order");
            byte[] noncanon = Hb(ec.GetProperty("noncanonical_body_hex").GetString()!);
            var ce = Assert.Throws<NaalpException>(() => Cbor.Decode(noncanon));
            Assert.Equal("NonCanonical", ce.Kind);
            var pe = Assert.Throws<NaalpException>(() => Payment.ParsePaymentImport(noncanon));
            Assert.Equal("PayMalformed", pe.Kind); // the corpus 'reject' family
            // the canonical form of the same content parses
            Payment.PaymentImport p = Payment.ParsePaymentImport(Hb(ec.GetProperty("canonical_body_hex").GetString()!));
            Assert.Equal(ec.GetProperty("format").GetInt64(), p.Format);
        }

        [Fact]
        public void EmptyVsAbsentForeign()
        {
            JsonElement ev = Vector().GetProperty("edge_cases").GetProperty("empty_vs_absent");
            JsonElement emptyV = ev.GetProperty("empty_foreign");
            JsonElement popV = ev.GetProperty("populated_foreign");

            Payment.PaymentImport empty = Payment.ParsePaymentImport(Hb(emptyV.GetProperty("body_hex").GetString()!));
            Assert.Equal(Array.Empty<byte>(), empty.Foreign);
            Assert.Equal(emptyV.GetProperty("id_hex").GetString(), Hex(empty.Id()));
            Assert.Equal(emptyV.GetProperty("foreign_id_hex").GetString(), Hex(empty.ForeignId()));

            Payment.PaymentImport populated = Payment.ParsePaymentImport(Hb(popV.GetProperty("body_hex").GetString()!));
            Assert.Equal(popV.GetProperty("id_hex").GetString(), Hex(populated.Id()));
            Assert.Equal(popV.GetProperty("foreign_id_hex").GetString(), Hex(populated.ForeignId()));

            // an empty foreign payload is present and valid, distinct by content-id from a populated one
            Assert.NotEqual(Hex(empty.Id()), Hex(populated.Id()));
            Assert.NotEqual(Hex(empty.ForeignId()), Hex(populated.ForeignId()));

            // field 6 (foreign) is mandatory: a body missing it is rejected fail-closed
            JsonElement af = ev.GetProperty("absent_field");
            var pe = Assert.Throws<NaalpException>(() => Payment.ParsePaymentImport(Hb(af.GetProperty("body_hex").GetString()!)));
            Assert.Equal(af.GetProperty("reject").GetString(), pe.Kind); // PayMalformed
        }

        [Fact]
        public void LookAlikeRejected()
        {
            JsonElement la = Vector().GetProperty("edge_cases").GetProperty("look_alike");
            var pe = Assert.Throws<NaalpException>(() => Payment.ParsePaymentImport(Hb(la.GetProperty("body_hex").GetString()!)));
            Assert.Equal(la.GetProperty("reject").GetString(), pe.Kind); // PayMalformed (currency as bstr)
        }

        // ---- the binding property: a changed charge is a different content-id -----------------

        [Fact]
        public void ChargeBindingMismatchIds()
        {
            // An approval binds the base ap2 charge-binding content-id; a wrong amount, wrong payee, or
            // substituted foreign payload yields a DIFFERENT charge content-id (ApprovalMismatch at the
            // §7 layer). All three are reproduced byte-exact from the corpus base.
            JsonElement v = Vector();
            JsonElement baseIv = v.GetProperty("imports").GetProperty("ap2");
            Payment.PaymentImport bs = ImportFrom(baseIv);
            byte[] baseId = bs.ChargeBinding().ContentId();
            Assert.Equal(baseIv.GetProperty("charge_binding").GetProperty("id_hex").GetString(), Hex(baseId));
            JsonElement mm = v.GetProperty("mismatch");

            var wrongAmount = new Payment.PaymentImport(bs.Format, bs.Amount + 8000, bs.Currency, bs.Payee, bs.NotAfter, bs.Foreign);
            Assert.Equal(mm.GetProperty("wrong_amount_charge_id_hex").GetString(), Hex(wrongAmount.ChargeBinding().ContentId()));

            var wrongPayee = new Payment.PaymentImport(bs.Format, bs.Amount, bs.Currency, Encoding.UTF8.GetBytes("merchant:evil-store"), bs.NotAfter, bs.Foreign);
            Assert.Equal(mm.GetProperty("wrong_payee_charge_id_hex").GetString(), Hex(wrongPayee.ChargeBinding().ContentId()));

            var substituted = new Payment.PaymentImport(bs.Format, bs.Amount, bs.Currency, bs.Payee, bs.NotAfter, Hb(mm.GetProperty("substituted_foreign_hex").GetString()!));
            Assert.Equal(mm.GetProperty("substituted_foreign_id_hex").GetString(), Hex(substituted.ForeignId()));
            Assert.Equal(mm.GetProperty("substituted_charge_id_hex").GetString(), Hex(substituted.ChargeBinding().ContentId()));

            foreach (string other in new[]
            {
                mm.GetProperty("wrong_amount_charge_id_hex").GetString()!,
                mm.GetProperty("wrong_payee_charge_id_hex").GetString()!,
                mm.GetProperty("substituted_charge_id_hex").GetString()!,
            })
            {
                Assert.NotEqual(Hex(baseId), other); // a changed charge must not match the bound one
            }
        }

        // ---- signed import round-trip in isolation (design §24) -------------------------------

        [Fact]
        public void SignVerifyImportInIsolation()
        {
            // NOT corpus-graded (no signed vector). Real deterministic ML-DSA-65 via a bare COSE_Sign1.
            JsonElement iv = Vector().GetProperty("imports").GetProperty("ap2");
            Payment.PaymentImport p = ImportFrom(iv);
            byte[] obj = Payment.SignPaymentImport(p, Alg, Seed);
            Payment.PaymentImport got = Payment.VerifyPaymentImport(obj, Cose.PROFILE_PUBLIC, Alg, Pk);
            Assert.Equal(p.Format, got.Format);
            Assert.Equal(p.Amount, got.Amount);
            Assert.Equal(p.Currency, got.Currency);
            Assert.Equal(Hex(p.Payee), Hex(got.Payee));
            Assert.Equal(p.NotAfter, got.NotAfter);
            Assert.Equal(Hex(p.Foreign), Hex(got.Foreign));

            // tampered signature -> BadSignature
            byte[] bad = (byte[])obj.Clone();
            bad[bad.Length - 1] ^= 1;
            var be = Assert.Throws<NaalpException>(() => Payment.VerifyPaymentImport(bad, Cose.PROFILE_PUBLIC, Alg, Pk));
            Assert.Equal("BadSignature", be.Kind);

            // an unknown imported format is not chargeable -> UnknownPaymentFormat
            var badFmt = new Payment.PaymentImport(Vector().GetProperty("unknown_format").GetInt64(), 1, "USD", Encoding.UTF8.GetBytes("x"), 1, Array.Empty<byte>());
            byte[] badObj = Payment.SignPaymentImport(badFmt, Alg, Seed);
            var ue = Assert.Throws<NaalpException>(() => Payment.VerifyPaymentImport(badObj, Cose.PROFILE_PUBLIC, Alg, Pk));
            Assert.Equal("UnknownPaymentFormat", ue.Kind);
        }

        // ---- AuthorizeCharge: the per-charge approval gate wired onto the real §7 ledger --------

        private static Approval.ApprovalRecord MkApproval(byte[] chargeCid, string approver, long grant, byte nonceByte, long notAfter, byte[] seed, out byte[] sig)
        {
            byte[] nonce = new byte[16];
            for (int i = 0; i < nonce.Length; i++) { nonce[i] = nonceByte; }
            var a = new Approval.ApprovalRecord(chargeCid, approver, grant, nonce, notAfter);
            sig = Approval.SignApproval(a, Alg, seed);
            return a;
        }

        private static Approval.Ledger FreshLedger()
        {
            string path = Path.Combine(Path.GetTempPath(), "naalp-payment-authcharge-" + Guid.NewGuid().ToString("N") + ".wal");
            return Approval.OpenLedger(path);
        }

        /// <summary>
        /// The C21 payment checkpoint: an imported payment is spent SINGLE-USE through the §7 ledger (a
        /// replay is AlreadyConsumed) and is bound to the exact charge (a wrong amount, wrong payee, or
        /// substituted foreign payload fails its approval binding). Grades all four fail-closed deny paths
        /// plus success-consumes-once vs vectors/payment/cases.json's mismatch content ids. Mirrors
        /// impl/go/payment/payment_test.go TestChargeSingleUseAndBinding.
        /// </summary>
        [Fact]
        public void ChargeSingleUseAndBinding()
        {
            JsonElement v = Vector();
            byte[] approverSeed = new byte[32];
            for (int i = 0; i < approverSeed.Length; i++) { approverSeed[i] = 0x11; }
            byte[] approverPk = Cose.MldsaKeygen("ML-DSA-65", approverSeed);
            byte[] foreignSeed = new byte[32];
            for (int i = 0; i < foreignSeed.Length; i++) { foreignSeed[i] = 0x22; }
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", foreignSeed);

            Payment.PaymentImport pi = ImportFrom(v.GetProperty("imports").GetProperty("ap2"));
            byte[] chargeCid = pi.ChargeBinding().ContentId();
            Approval.ApprovalRecord appr = MkApproval(chargeCid, "approver-A", Payment.ChargeEffect, 0x01, pi.NotAfter, approverSeed, out byte[] apprSig);

            string walPath = Path.Combine(Path.GetTempPath(), "naalp-payment-authcharge-main-" + Guid.NewGuid().ToString("N") + ".wal");
            Approval.Ledger ledger = Approval.OpenLedger(walPath);
            try
            {
                // First charge: authorized and consumed exactly once.
                Approval.LedgerEntry entry = Payment.AuthorizeCharge(pi, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, ledger);
                Assert.Equal(0L, entry.Seq);

                // Replay: the same approval is rejected by the ledger, no second spend, no state change.
                var replay = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(pi, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, ledger));
                Assert.Equal("AlreadyConsumed", replay.Kind);
                Assert.Equal(1, ledger.Len());

                // A wrong-amount charge yields a different charge content-id, so the approval no longer matches.
                var wrongAmount = new Payment.PaymentImport(pi.Format, pi.Amount + 8000, pi.Currency, pi.Payee, pi.NotAfter, pi.Foreign);
                Assert.Equal(v.GetProperty("mismatch").GetProperty("wrong_amount_charge_id_hex").GetString(), Hex(wrongAmount.ChargeBinding().ContentId()));
                var mismatch1 = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(wrongAmount, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, FreshLedger()));
                Assert.Equal("ApprovalMismatch", mismatch1.Kind);

                // A wrong-payee charge likewise fails the binding.
                var wrongPayee = new Payment.PaymentImport(pi.Format, pi.Amount, pi.Currency, Encoding.UTF8.GetBytes("merchant:evil-store"), pi.NotAfter, pi.Foreign);
                Assert.Equal(v.GetProperty("mismatch").GetProperty("wrong_payee_charge_id_hex").GetString(), Hex(wrongPayee.ChargeBinding().ContentId()));
                var mismatch2 = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(wrongPayee, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, FreshLedger()));
                Assert.Equal("ApprovalMismatch", mismatch2.Kind);

                // A substituted foreign payload changes the foreign content-id, hence the charge binding.
                JsonElement mm = v.GetProperty("mismatch");
                var substituted = new Payment.PaymentImport(pi.Format, pi.Amount, pi.Currency, pi.Payee, pi.NotAfter, Hb(mm.GetProperty("substituted_foreign_hex").GetString()!));
                Assert.Equal(mm.GetProperty("substituted_foreign_id_hex").GetString(), Hex(substituted.ForeignId()));
                Assert.Equal(mm.GetProperty("substituted_charge_id_hex").GetString(), Hex(substituted.ChargeBinding().ContentId()));
                var mismatch3 = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(substituted, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, FreshLedger()));
                Assert.Equal("ApprovalMismatch", mismatch3.Kind);

                // A foreign key never authenticates the approval.
                var badSig = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(pi, appr, Alg, foreignPk, apprSig, "payer-1", pi.NotAfter, FreshLedger()));
                Assert.Equal("BadSignature", badSig.Kind);

                // An expired charge is rejected.
                var expired = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(pi, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter + 1, FreshLedger()));
                Assert.Equal("ApprovalExpired", expired.Kind);

                // An under-granting approval (read_only cannot authorize a non_idempotent_write charge) is denied.
                // THIS is the red-evidence mutation anchor: dropping the Policy.Authorizes effect-coverage
                // check in AuthorizeCharge flips this deny to a wrongly-authorized charge.
                byte[] underCid = pi.ChargeBinding().ContentId();
                Approval.ApprovalRecord underAppr = MkApproval(underCid, "approver-A", Policy.READ_ONLY, 0x03, pi.NotAfter, approverSeed, out byte[] underSig);
                var underGrant = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(pi, underAppr, Alg, approverPk, underSig, "payer-1", pi.NotAfter, FreshLedger()));
                Assert.Equal("ApprovalRequired", underGrant.Kind);

                // An unknown imported format is not chargeable.
                var unk = new Payment.PaymentImport(v.GetProperty("unknown_format").GetInt64(), pi.Amount, pi.Currency, pi.Payee, pi.NotAfter, pi.Foreign);
                var unkFmt = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(unk, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, FreshLedger()));
                Assert.Equal("UnknownPaymentFormat", unkFmt.Kind);
            }
            finally
            {
                ledger.Close();
                if (File.Exists(walPath)) { File.Delete(walPath); }
            }
        }

        /// <summary>
        /// REQUIRED checkpoint mutation (a): an importer that treats a payment token as MULTI-USE fails
        /// the replay case. The honest AuthorizeCharge consumes single-use through the §7 ledger, so a
        /// replay is AlreadyConsumed; a MUTANT importer that skips the ledger consume (treating the token
        /// as multi-use) authorizes the replay a second time — the exact double-spend the ledger prevents.
        /// Proves ledger.Consume is the load-bearing single-use guarantee. Mirrors
        /// impl/go/payment/payment_test.go TestPaymentImportMultiUseMutation.
        /// </summary>
        [Fact]
        public void PaymentImportMultiUseMutation()
        {
            JsonElement v = Vector();
            byte[] approverSeed = new byte[32];
            for (int i = 0; i < approverSeed.Length; i++) { approverSeed[i] = 0x11; }
            byte[] approverPk = Cose.MldsaKeygen("ML-DSA-65", approverSeed);
            Payment.PaymentImport pi = ImportFrom(v.GetProperty("imports").GetProperty("ap2"));
            byte[] chargeCid = pi.ChargeBinding().ContentId();
            Approval.ApprovalRecord appr = MkApproval(chargeCid, "approver-A", Payment.ChargeEffect, 0x01, pi.NotAfter, approverSeed, out byte[] apprSig);

            // HONEST path: single-use through the ledger — the replay is rejected.
            Approval.Ledger ledger = FreshLedger();
            try
            {
                Payment.AuthorizeCharge(pi, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, ledger);
                var replay = Assert.Throws<NaalpException>(() => Payment.AuthorizeCharge(pi, appr, Alg, approverPk, apprSig, "payer-1", pi.NotAfter, ledger));
                Assert.Equal("AlreadyConsumed", replay.Kind);
            }
            finally
            {
                ledger.Close();
            }

            // MUTANT importer: verifies the binding but treats the token as MULTI-USE (no ledger consume).
            // This is the bug the ledger prevents; the mutant wrongly authorizes the replay a second time.
            void MutantAuthorize(Payment.PaymentImport p)
            {
                byte[] cid = p.ChargeBinding().ContentId();
                Approval.VerifyApproval(appr, Alg, approverPk, apprSig, cid, p.NotAfter); // no Consume => multi-use
            }
            MutantAuthorize(pi); // does not throw
            MutantAuthorize(pi); // does NOT reject the replay -- proving ledger.Consume is the single-use guarantee.
        }
    }
}
