// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C21 (task 5B.1) — NAALP-PAY payment import for the C# SDK (design.md §24; requirements
    /// R-PAY-1..6), ported from impl/go/payment.
    ///
    /// <para>NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol
    /// delegated token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not
    /// adoption): the foreign bytes are never re-serialized, canonicalized, or rewritten (R-14.4), and a
    /// foreign identity inside them never becomes an N-AALP authorization identity (R-14.6). It
    /// introduces NO new envelope, encoding, signature, identity, effect, or ledger mechanism (R-11.3):
    /// the imported payload becomes a value-bearing charge that N-AALP governs with its OWN added
    /// guarantees, reusing the closed C5 effect lattice (<see cref="Policy"/>). There is NO fifth effect
    /// and NO payment-specific ledger.</para>
    ///
    /// <list type="bullet">
    /// <item>PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is
    /// the wrapper body. <c>format</c> selects the imported FORMAT from the closed payment-format
    /// registry; <c>foreign</c> carries the imported payload octet-for-octet. An unknown format is
    /// rejected (UnknownPaymentFormat).</item>
    /// <item>THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee,
    /// 5: not_after, 6: foreign_id} names the exact value a §7 approval binds by content id — including
    /// the foreign payload's content id (the carriage binding). A wrong-amount, wrong-payee,
    /// wrong-currency, or substituted-payload charge yields a different content id and no longer matches
    /// the approval.</item>
    /// </list>
    ///
    /// <para>Every check is fail-closed (§15): a failing charge is rejected whole, throws its named
    /// error, and causes no state change. The PaymentImport SIGNATURE is a bare-{1:alg} COSE_Sign1 (as
    /// the reference's cose.Sign1) with real deterministic ML-DSA via <see cref="Cose.CoseSign1"/>.</para>
    ///
    /// <para><see cref="AuthorizeCharge"/> IS ported (STEP-2 ten-port parity wave), composing EXISTING
    /// C# SDK primitives unchanged: <see cref="Approval.VerifyApproval"/> (binds the exact charge
    /// content id), <see cref="Policy.Authorizes"/> (the granted effect covers the charge's
    /// non_idempotent_write), and <see cref="Approval.Ledger.Consume"/> (the single-use §7 ledger — a
    /// replay throws AlreadyConsumed, no double-spend). There is no payment-specific ledger or effect.
    /// Graded against vectors/payment/cases.json for the binding content ids, and demonstrated in
    /// isolation (mutation-witnessed) for the deny paths and the single-use guarantee, mirroring
    /// impl/go/payment/payment.go AuthorizeCharge byte-for-byte on the accept/reject verdict.</para>
    /// </summary>
    public static class Payment
    {
        /// <summary>The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit
        /// chain (<see cref="Audit.HeadSize"/>).</summary>
        public const int HeadSize = 48;

        /// <summary>The C5 effect a payment spend carries: a non_idempotent_write. A charge is
        /// value-bearing and not safely repeatable, which is why it is spent single-use through the §7
        /// ledger; the approval's grant must cover this effect (the value-bearing rule).</summary>
        public const long ChargeEffect = Policy.NON_IDEMPOTENT_WRITE;

        // Payment format codes (design.md §24; the closed payment-format registry). These name the
        // imported FORMAT carried octet-for-octet — not an adopted schema. A code outside the closed set
        // is rejected (UnknownPaymentFormat).
        public const long FormatAP2Mandate = 1; // AP2 mandate
        public const long FormatACPToken = 2;   // Agentic Commerce Protocol delegated token
        public const long FormatX402 = 3;       // x402 payload

        private static readonly Dictionary<long, string> FormatNames = new Dictionary<long, string>
        {
            { FormatAP2Mandate, "ap2-mandate" },
            { FormatACPToken, "acp-delegated-token" },
            { FormatX402, "x402-payload" },
        };

        /// <summary>Reports whether code is one of the closed payment formats.</summary>
        public static bool IsRegisteredFormat(long code) => FormatNames.ContainsKey(code);

        /// <summary>Returns the registry name of a format code, or "unknown".</summary>
        public static string FormatName(long code) => FormatNames.TryGetValue(code, out string? n) ? n : "unknown";

        private static byte[] Sha384(byte[] b)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(b);
        }

        /// <summary>
        /// Wraps a foreign payment payload as a value-bearing charge. Format selects the imported format
        /// (closed registry); Amount/Currency/Payee/NotAfter are the bound charge terms; Foreign is the
        /// imported payload carried octet-for-octet (carriage, not adoption).
        /// </summary>
        public sealed class PaymentImport
        {
            public readonly long Format;
            public readonly long Amount;
            public readonly string Currency;
            public readonly byte[] Payee;
            public readonly long NotAfter;
            public readonly byte[] Foreign;

            public PaymentImport(long format, long amount, string currency, byte[] payee, long notAfter, byte[] foreign)
            {
                Format = format;
                Amount = amount;
                Currency = currency;
                Payee = payee;
                NotAfter = notAfter;
                Foreign = foreign;
            }

            /// <summary>The deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee,
            /// 5: not_after, 6: foreign}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(Format)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Amount)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.T(Currency)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Payee)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(NotAfter)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(Foreign)),
                }));
            }

            /// <summary>The SHA-384 head (48 octets).</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The T1 content-id (50 octets): multihash(0x20, SHA-384(body)).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());

            /// <summary>The T1 content-id of the carried foreign payload — the hash the charge binding
            /// binds (the carriage binding). A substituted payload yields a different ForeignId.</summary>
            public byte[] ForeignId() => Cbor.ContentId(Foreign);

            /// <summary>The exact charge value an approval binds for this import (amount + currency +
            /// payee + expiry + the foreign payload's content id). A change to any bound term — including
            /// the foreign payload — changes the binding's content id.</summary>
            public ChargeBinding ChargeBinding()
            {
                return new ChargeBinding(Format, Amount, Currency, Payee, NotAfter, ForeignId());
            }
        }

        /// <summary>
        /// Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign
        /// payload's content id. A §7 approval binds THIS binding's content id, so a change to any bound
        /// term invalidates a prior approval (ApprovalMismatch).
        /// </summary>
        public sealed class ChargeBinding
        {
            public readonly long Format;
            public readonly long Amount;
            public readonly string Currency;
            public readonly byte[] Payee;
            public readonly long NotAfter;
            public readonly byte[] ForeignId; // content-id of the foreign payload: multihash(0x20, SHA-384(foreign))

            public ChargeBinding(long format, long amount, string currency, byte[] payee, long notAfter, byte[] foreignId)
            {
                Format = format;
                Amount = amount;
                Currency = currency;
                Payee = payee;
                NotAfter = notAfter;
                ForeignId = foreignId;
            }

            /// <summary>The deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee,
            /// 5: not_after, 6: foreign_id}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(Format)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(Amount)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.T(Currency)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Payee)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(NotAfter)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(ForeignId)),
                }));
            }

            /// <summary>The SHA-384 head (48 octets).</summary>
            public byte[] Head() => Sha384(Bytes());

            /// <summary>The charge content id an approval binds: multihash(0x20, SHA-384(binding)).</summary>
            public byte[] ContentId() => Cbor.ContentId(Bytes());
        }

        /// <summary>
        /// Reconstructs a PaymentImport from its body bytes alone. It does NOT validate the format
        /// against the closed set — that is <see cref="VerifyPaymentImport"/>'s job — so an import
        /// carrying an unknown format can be represented (and then rejected). Fail-closed (PayMalformed)
        /// on a malformed shape or a non-canonical encoding.
        /// </summary>
        public static PaymentImport ParsePaymentImport(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b); // the strict decoder rejects a non-canonical body (NonCanonical)
            }
            catch (NaalpException)
            {
                throw new NaalpException("PayMalformed", "object is not a well-formed N-AALP payment-import body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("PayMalformed", "payment import is not a map");
            }

            long? format = null, amount = null, notAfter = null;
            string? currency = null;
            byte[]? payee = null, foreign = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    continue;
                }
                switch (ku.V)
                {
                    case 1 when p.Val is Cbor.U fu:
                        format = fu.V;
                        break;
                    case 2 when p.Val is Cbor.U au:
                        amount = au.V;
                        break;
                    case 3 when p.Val is Cbor.T ct:
                        currency = ct.V;
                        break;
                    case 4 when p.Val is Cbor.B pb:
                        payee = pb.V;
                        break;
                    case 5 when p.Val is Cbor.U nu:
                        notAfter = nu.V;
                        break;
                    case 6 when p.Val is Cbor.B fb:
                        foreign = fb.V;
                        break;
                }
            }
            if (format == null || amount == null || currency == null || payee == null || notAfter == null || foreign == null)
            {
                throw new NaalpException("PayMalformed", "object is not a well-formed N-AALP payment-import body");
            }
            return new PaymentImport(format.Value, amount.Value, currency, payee, notAfter.Value, foreign);
        }

        // bareProtected encodes the COSE protected header {1: alg} as deterministic CBOR — the exact
        // bare header the reference's cose.Sign1 produces (alg is the negative registered id), so the
        // signed payment-import object is byte-identical across ports.
        private static byte[] BareProtected(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        private static int AlgFromProtected(byte[] prot)
        {
            Cbor.Value pv;
            try
            {
                pv = Cbor.Decode(prot);
            }
            catch (NaalpException)
            {
                throw new NaalpException("PayMalformed", "malformed protected header");
            }
            if (pv is Cbor.M m)
            {
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (p.K is Cbor.U ku && ku.V == 1)
                    {
                        if (p.Val is Cbor.N n)
                        {
                            return (int)n.V;
                        }
                        if (p.Val is Cbor.U u)
                        {
                            return (int)u.V;
                        }
                    }
                }
            }
            throw new NaalpException("PayMalformed", "protected header has no alg");
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the PaymentImport body with a real
        /// deterministic ML-DSA key derived from seed (bare {1: alg} header).</summary>
        public static byte[] SignPaymentImport(PaymentImport p, int alg, byte[] seed)
        {
            return Cose.CoseSign1(alg, seed, BareProtected(alg), p.Bytes());
        }

        /// <summary>
        /// Verifies the import's full signature under the profile, reconstructs it from the signed body
        /// bytes, and validates the format against the closed registry. Check order (fail-closed):
        /// PayMalformed -> UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse ->
        /// UnknownPaymentFormat. Returns the PaymentImport on success.
        /// </summary>
        public static PaymentImport VerifyPaymentImport(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[][] parts;
            try
            {
                parts = Cose.ParseSign1Raw(obj);
            }
            catch (NaalpException)
            {
                throw new NaalpException("PayMalformed", "not a tagged COSE_Sign1");
            }
            byte[] prot = parts[0];
            byte[] payload = parts[1];
            byte[] sig = parts[2];

            int halg = AlgFromProtected(prot);
            (int level, bool known) = Cose.AlgLevel(halg);
            if (!known)
            {
                throw new NaalpException("UnknownAlg", "algorithm id not in the N-AALP registry");
            }
            if (level < Cose.ProfileMinLevel(profile))
            {
                throw new NaalpException("ProfileDowngrade", "signature level below the profile minimum");
            }
            if (halg != alg)
            {
                throw new NaalpException("KeyAlgMismatch", "key algorithm does not match object header");
            }
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            if (!Cose.CoseVerify1Raw(halg, pubkey, tbs, sig))
            {
                throw new NaalpException("BadSignature", "signature verification failed");
            }
            PaymentImport p = ParsePaymentImport(payload);
            if (!IsRegisteredFormat(p.Format))
            {
                throw new NaalpException("UnknownPaymentFormat",
                    "payment import selects a format outside the closed payment-format registry");
            }
            return p;
        }

        // ---- the per-charge approval gate (reuses §7 approval + consume ledger) -----------------

        /// <summary>
        /// Enforces the value-bearing rule for an imported payment, reusing the §7 approval and
        /// single-use consume ledger UNCHANGED (ported from impl/go/payment/payment.go AuthorizeCharge).
        /// The approval MUST bind the EXACT charge binding content id (format + amount + currency + payee
        /// + expiry + foreign_id) — so it satisfies neither a different amount/payee/currency nor a
        /// substituted foreign payload (ApprovalMismatch, from <see cref="Approval.VerifyApproval"/>) —
        /// its granted effect must cover the charge's <see cref="ChargeEffect"/> (a non_idempotent_write,
        /// ApprovalRequired otherwise), it must be unexpired at <paramref name="now"/>
        /// (ApprovalExpired), it must verify under the approver's key (BadSignature), and it is consumed
        /// single-use by <paramref name="by"/> through the §7 ledger (AlreadyConsumed on replay — no
        /// double-spend). Precedence and fail-closed behaviour mirror the spine: a non-matching or
        /// under-granting approval denies with no ledger append; an already-spent approval denies
        /// AlreadyConsumed; the consume (the single state change) happens only when every check holds.
        /// An unknown/unregistered imported format is rejected first (UnknownPaymentFormat), before any
        /// ledger interaction. Returns the ledger entry on success.
        /// </summary>
        public static Approval.LedgerEntry AuthorizeCharge(
            PaymentImport p, Approval.ApprovalRecord appr, int approverAlg, byte[] approverPk, byte[] apprSig,
            string by, long now, Approval.Ledger ledger)
        {
            if (!IsRegisteredFormat(p.Format))
            {
                throw new NaalpException("UnknownPaymentFormat",
                    "payment import selects a format outside the closed payment-format registry");
            }
            byte[] chargeCid = p.ChargeBinding().ContentId();
            // ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature:
            Approval.VerifyApproval(appr, approverAlg, approverPk, apprSig, chargeCid, now);
            if (!Policy.Authorizes(appr.Grant, ChargeEffect))
            {
                throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover the charge");
            }
            // AlreadyConsumed on replay — single-use, no double-spend. The single state change.
            return ledger.Consume(appr.Id(), by);
        }
    }
}
