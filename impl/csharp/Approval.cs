// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C6 — the approval object that binds exact canonical arguments by content id, and the durable,
    /// hash-chained, single-use consume ledger (design.md §7; requirements R-7.1..7.4) — the C# SDK,
    /// ported from impl/go/approval and cross-checked against impl/python/naalp/approval and the
    /// Java/Kotlin ports.
    ///
    /// <para>An <see cref="ApprovalRecord"/> binds, under signature, the content id of the exact
    /// canonical argument object it approves (§7.1); because the args are named by content id, mutating
    /// any argument changes the id and the approval no longer matches (ApprovalMismatch). The consume
    /// ledger is a durable compare-and-set set keyed by approval content id: the FIRST consumer of an id
    /// wins and every later consume of the same id is rejected AlreadyConsumed (§7.2). Atomicity is
    /// honest, not decorative — the membership check AND the append run inside ONE lock-held critical
    /// section (the single-writer discipline, mirroring the Go reference's single mutex), so there is no
    /// read-then-write TOCTOU window and a race spends an approval exactly once. Each winning consume is
    /// written and fsynced to the write-ahead log before it returns (persist-before-ack, R-7.2). A held
    /// outcome is a distinct signed non-success result (<see cref="HeldResult"/>, §7.4). Every rejection
    /// is fail-closed and causes no ledger append.</para>
    ///
    /// <para>The wire bodies (approval body, ledger entry) are byte-identical to Go/Rust/Python/Java.
    /// Byte surfaces are graded against vectors/approval/cases.json; the approval SIGNATURE is a RAW
    /// deterministic ML-DSA-65 signature over the body bytes (<see cref="Cose.MldsaVerify"/>),
    /// demonstrated in isolation (the corpus carries no signature vector).</para>
    ///
    /// <para>The T1.5 (NAALP-REQ-121) ledger-signed <see cref="ConsumeReceipt"/> /
    /// <see cref="ConsumeForkEvidence"/> / <see cref="ReceiptSet"/> double-spend-evidence surface
    /// (approval.go §7.5) IS ported, graded against the independent, non-circular
    /// vectors/consume_receipt/cases.json corpus (distinct from vectors/approval/cases.json). Also
    /// ported: the R-TDCS-3 party-visible <see cref="Refusal"/> object (a closed outcome vocabulary +
    /// the full record's content id, never the discriminating detail), R-TDCS-4
    /// <see cref="VerifyFreshIndependent"/> (freshness judged from an ordering authority structurally
    /// distinct from the authenticated party), and R-TDCS-5 <see cref="VerifyAudience"/> (an approval's
    /// OPTIONAL valid-context binding) — all three graded against vectors/trust_decision/cases.json. The
    /// single-use replay guarantee (AlreadyConsumed, the core §7.2 property) remains the
    /// security-critical anchor; ConsumeWithReceipt's first-append-wins CAS is the T1.5 anchor.</para>
    /// </summary>
    public static class Approval
    {
        /// <summary>The width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.</summary>
        public const int HeadSize = 48;

        private static byte[] Sha384(byte[] b) => SHA384.HashData(b);

        // ---- §7.1 the approval object body ---------------------------------------------------------

        /// <summary>The body of an Approval object (§7.1). Signed over its deterministic-CBOR bytes.
        /// <c>Approves</c> is the content id of the exact canonical args object; a changed argument
        /// changes the id and the approval no longer matches (ApprovalMismatch).</summary>
        public sealed class ApprovalRecord
        {
            public readonly byte[] Approves; // content id of the exact canonical args object (§7.1)
            public readonly string Approver; // approver signer id
            public readonly long Grant;      // granted effect class (0..3), the C5 effect
            public readonly byte[] Nonce;    // anti-replay nonce (§7.3)
            public readonly long NotAfter;   // expiry, epoch ms (§7.3)
            public readonly string Audience; // OPTIONAL valid-context (R-TDCS-5); "" == absent (field 6 omitted)

            public ApprovalRecord(byte[] approves, string approver, long grant, byte[] nonce, long notAfter, string audience = "")
            {
                Approves = (byte[])approves.Clone();
                Approver = approver;
                Grant = grant;
                Nonce = (byte[])nonce.Clone();
                NotAfter = notAfter;
                Audience = audience;
            }

            /// <summary>The deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6
            /// is OMITTED when <see cref="Audience"/> is "" -- an empty string is not a distinct value, so
            /// an approval that names no audience encodes byte-identically to a 5-field approval
            /// (R-TDCS-5, additive by design; mirrors impl/go &amp; impl/rust ApprovalRecord.Bytes()
            /// byte-for-byte).</summary>
            public byte[] Bytes()
            {
                var pairs = new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Approves)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(Approver)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Grant)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Nonce)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(NotAfter)),
                };
                if (Audience.Length > 0)
                {
                    pairs.Add(new Cbor.Pair(new Cbor.U(6), new Cbor.T(Audience)));
                }
                return Cbor.Encode(new Cbor.M(pairs));
            }

            /// <summary>The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets).</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>Sign the approval body with a real deterministic ML-DSA key derived from
        /// <paramref name="seed"/>. The signed input is the approval body bytes DIRECTLY (the reference
        /// cose.Signer: raw message, rnd=0 — NO COSE Sig_structure wrapping).</summary>
        public static byte[] SignApproval(ApprovalRecord a, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, a.Bytes());

        /// <summary>
        /// Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact
        /// args by content id, (3) not expired at <paramref name="posTime"/>. Returns normally only if
        /// all three hold; otherwise throws the specific named error and authorizes nothing. Check order
        /// is fail-closed: BadSignature -> ApprovalMismatch -> ApprovalExpired. It does NOT consume —
        /// consumption is the separate atomic ledger step (§7.2).
        /// </summary>
        public static void VerifyApproval(ApprovalRecord a, int alg, byte[] pk, byte[] sig, byte[] argsContentId, long posTime)
        {
            if (!Cose.CoseVerify1Raw(alg, pk, a.Bytes(), sig))
            {
                throw new NaalpException("BadSignature", "approval signature does not verify");
            }
            if (!BytesEqual(a.Approves, argsContentId))
            {
                throw new NaalpException("ApprovalMismatch", "approval does not bind these arguments' content id");
            }
            if (posTime > a.NotAfter)
            {
                throw new NaalpException("ApprovalExpired", "approval is past its not_after");
            }
        }

        /// <summary>
        /// (R-TDCS-5) Enforce the OPTIONAL audience binding. An approval that NAMES an audience
        /// (<c>a.Audience != ""</c>) is valid only in that context: a relying party checks it at use and
        /// rejects AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted by
        /// the issuer's explicit choice and passes for any use context -- a deployment MAY require an
        /// audience by local policy above this check. The check is mandatory WHEN a context is present,
        /// never mandatory-presence (the JWT `aud` present-optional / check-mandatory shape). Mirrors
        /// impl/go &amp; impl/rust VerifyAudience byte-for-byte on the accept/reject verdict.
        /// </summary>
        public static void VerifyAudience(ApprovalRecord a, string useContext)
        {
            if (a.Audience.Length > 0 && a.Audience != useContext)
            {
                throw new NaalpException("AudienceMismatch", "approval names an audience other than the use context");
            }
        }

        /// <summary>
        /// The composed, single-call consume choke point for the approval state machine (draft "##
        /// Approval state machine"). Runs the table's precedence in ONE impl-owned place -- the exact
        /// sequence that Payment.AuthorizeCharge, Mcp, Agui and Delegation each hand-assemble -- so a
        /// caller (and the conformance suite) drives one realization of the reactions rather than
        /// re-deriving the ordering at each call site:
        ///
        /// <para>1. <see cref="VerifyApproval"/> checks the signature, then the args-content-id binding
        /// (ApprovalMismatch, which the draft says "takes precedence over every cell"), then expiry
        /// (ApprovalExpired) -- all BEFORE the ledger is consulted. So a request both past not_after AND
        /// already in the ledger throws ApprovalExpired, never AlreadyConsumed (the draft's
        /// expiry-over-consume rule), and the ledger is left untouched by the rejected request.</para>
        ///
        /// <para>2. The granted effect must be a valid class (0..3) and must cover the action's required
        /// effect; a grant outside the closed vocabulary, or one below the required effect, authorizes
        /// nothing and throws ApprovalRequired (fail-closed; the grant-range guard is stricter than the
        /// raw callers).</para>
        ///
        /// <para>3. The atomic single-use consume through the §7 ledger: the first consumer of the id
        /// wins, a second throws AlreadyConsumed, and neither a rejected earlier step nor a losing race
        /// appends.</para>
        ///
        /// <para>Every rejection is fail-closed and appends nothing; it consumes only when every check
        /// holds, returning the ledger entry. It does NOT enforce object audience -- that is
        /// <see cref="Ledger.ConsumeObject"/>'s binding (design.md §2.5.3); ConsumeApproval is the
        /// args-content-id/effect/single-use choke point. Mirrors impl/go/approval/approval.go
        /// ConsumeApproval and impl/rust/src/approval.rs consume_approval byte-for-byte on the
        /// accept/reject verdict.</para>
        /// </summary>
        public static LedgerEntry ConsumeApproval(
            ApprovalRecord a, int approverAlg, byte[] approverPk, byte[] aSig, byte[] argsContentId,
            long posTime, long requiredEffect, Ledger ledger, string by)
        {
            VerifyApproval(a, approverAlg, approverPk, aSig, argsContentId, posTime); // BadSignature/ApprovalMismatch/ApprovalExpired, all before the ledger
            if (a.Grant > Policy.DESTRUCTIVE)
            {
                throw new NaalpException("ApprovalRequired", "action requires an approval that is not present"); // a grant outside the closed 0..3 effect vocabulary authorizes nothing
            }
            if (!Policy.Authorizes(a.Grant, requiredEffect))
            {
                throw new NaalpException("ApprovalRequired", "action requires an approval that is not present"); // the approval's granted effect does not cover this action
            }
            return ledger.Consume(a.Id(), by);
        }

        // ---- §7.4 the held (not-yet-granted) outcome -----------------------------------------------

        /// <summary>The distinct, signed, non-success result returned when an action requires an approval
        /// that has not been granted (§7.4). It is never a silent success or a silent denial.</summary>
        public sealed class HeldResult
        {
            public readonly byte[] Approves; // content id of the args whose approval is pending
            public readonly string Reason;

            public HeldResult(byte[] approves, string reason)
            {
                Approves = (byte[])approves.Clone();
                Reason = reason;
            }

            /// <summary>The deterministic-CBOR encoding {1: approves, 2: reason}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Approves)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(Reason)),
                }));
            }
        }

        /// <summary>Sign a held result so the "not yet granted" outcome is itself attributable (real ML-DSA).</summary>
        public static byte[] SignHeld(HeldResult h, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, h.Bytes());

        // ---- R-TDCS-3 (design.md §25, C22) the party-visible coarse refusal object -----------------
        //
        // A refusal returned to the authenticated party carries ONLY a single value from a CLOSED
        // vocabulary and the content id of the full signed record that carries the discriminating
        // detail -- a reference, not the reason. The detail exists, is signed, and is auditor-resolvable
        // through the record channel, but never reaches the adversary-facing surface, so repeated
        // refusals cannot serve an adaptive party as an oracle. Mirrors impl/go/approval/refusal.go and
        // impl/rust's refusal section byte-for-byte on both the wire bytes and the accept/reject verdict.

        public const long RefusalDenied = 0;       // the action is refused
        public const long RefusalHeld = 1;         // the action requires a further step not yet taken
        public const long RefusalUnverifiable = 2; // required evidence did not verify

        private static readonly Dictionary<long, string> RefusalOutcomeName = new Dictionary<long, string>
        {
            { RefusalDenied, "denied" },
            { RefusalHeld, "held" },
            { RefusalUnverifiable, "unverifiable" },
        };

        /// <summary>Whether <paramref name="code"/> is in the CLOSED refusal-outcome set. FAIL-CLOSED
        /// anchor: a code outside {denied, held, unverifiable} MUST return false, never true.</summary>
        public static bool IsKnownRefusalOutcome(long code) => RefusalOutcomeName.ContainsKey(code);

        /// <summary>The party-visible coarse refusal body {1: outcome, 2: record}. Outcome is the
        /// closed-set coarse outcome; Record is the T1 content id of the full signed record carrying the
        /// discriminating detail.</summary>
        public sealed class Refusal
        {
            public readonly long Outcome;
            public readonly byte[] Record;

            public Refusal(long outcome, byte[] record)
            {
                Outcome = outcome;
                Record = (byte[])record.Clone();
            }

            /// <summary>The deterministic-CBOR encoding {1: outcome, 2: record}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(Outcome)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Record)),
                }));
            }
        }

        /// <summary>Build the party-visible refusal for a full signed record: it carries the coarse
        /// outcome and the content id of <paramref name="fullRecord"/>, and NOTHING drawn from inside
        /// <paramref name="fullRecord"/> -- the discriminating detail stays in the record, referenced
        /// only by its id. This is the coarse-to-party split the closure property requires (R-TDCS-3).</summary>
        public static Refusal RefusalFromRecord(long outcome, byte[] fullRecord)
        {
            return new Refusal(outcome, Cbor.ContentId(fullRecord));
        }

        /// <summary>Reconstruct a Refusal from its body bytes, enforcing that a party-visible refusal
        /// carries ONLY {outcome, record} and nothing more (R-TDCS-3). Rejects, fail-closed: a malformed
        /// body, any key other than 1 and 2, a missing or empty record id (RefusalDetailLeak --
        /// discriminating detail leaked, or the auditor reference dropped), and an outcome outside the
        /// closed set (UnknownRefusalOutcome). Authorizes nothing.</summary>
        public static Refusal ParseRefusal(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw new NaalpException("RefusalDetailLeak", "malformed refusal body");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("RefusalDetailLeak", "refusal is not a map");
            }
            long? outcome = null;
            byte[]? record = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("RefusalDetailLeak", "non-uint refusal key");
                }
                switch (ku.V)
                {
                    case 1 when p.Val is Cbor.U u:
                        outcome = u.V;
                        break;
                    case 2 when p.Val is Cbor.B b2:
                        record = b2.V;
                        break;
                    default:
                        throw new NaalpException("RefusalDetailLeak", "any field beyond {1,2} is leaked detail");
                }
            }
            if (outcome == null || record == null || record.Length == 0)
            {
                throw new NaalpException("RefusalDetailLeak", "refusal must carry the full-record content id");
            }
            if (!IsKnownRefusalOutcome(outcome.Value))
            {
                throw new NaalpException("UnknownRefusalOutcome", "refusal outcome is outside the closed set denied/held/unverifiable");
            }
            return new Refusal(outcome.Value, record);
        }

        // ---- §7.2 the consume ledger entry ---------------------------------------------------------

        /// <summary>One append to the consume ledger (§7.2).</summary>
        public sealed class LedgerEntry
        {
            public readonly long Seq;         // ledger sequence position
            public readonly byte[] Prev;      // prior chain head (HeadSize bytes; genesis is all-zero)
            public readonly byte[] ApprovalId; // the approval content id being consumed
            public readonly string By;        // consumer signer id

            public LedgerEntry(long seq, byte[] prev, byte[] approvalId, string by)
            {
                Seq = seq;
                Prev = (byte[])prev.Clone();
                ApprovalId = (byte[])approvalId.Clone();
                By = by;
            }

            /// <summary>The deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by} (shared
            /// spine). The head after this entry is SHA-384(Bytes()); because Bytes() carries Prev,
            /// editing any entry breaks the next entry's linkage.</summary>
            public byte[] Bytes() => Records.LedgerEntry(Seq, Prev, ApprovalId, By);

            /// <summary>This entry's chain head — the prev of the next entry.</summary>
            public byte[] Head() => Sha384(Bytes());
        }

        private static LedgerEntry ParseEntry(byte[] rec)
        {
            if (!(Cbor.Decode(rec) is Cbor.M m)) // strict decoder: throws NonCanonical on a non-canonical body
            {
                throw new NaalpException("LedgerCorrupt", "ledger entry is not a map");
            }
            long? seq = null;
            byte[]? prev = null;
            byte[]? aid = null;
            string? by = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("LedgerCorrupt", "non-uint ledger entry key");
                }
                switch (ku.V)
                {
                    case 1 when p.Val is Cbor.U s:
                        seq = s.V;
                        break;
                    case 2 when p.Val is Cbor.B b:
                        prev = b.V;
                        break;
                    case 3 when p.Val is Cbor.B b:
                        aid = b.V;
                        break;
                    case 4 when p.Val is Cbor.T t:
                        by = t.V;
                        break;
                    default:
                        throw new NaalpException("LedgerCorrupt", "unknown or mistyped ledger entry field");
                }
            }
            if (seq == null || prev == null || aid == null || by == null)
            {
                throw new NaalpException("LedgerCorrupt", "ledger entry missing a mandatory field");
            }
            return new LedgerEntry(seq.Value, prev, aid, by);
        }

        /// <summary>Open (creating if needed) a WAL-backed consume ledger at <paramref name="path"/> and
        /// replay any existing log to rebuild the consumed set and chain head. A log that does not
        /// hash-chain cleanly is refused (LedgerCorrupt) rather than trusted.</summary>
        public static Ledger OpenLedger(string path, string authority = "") => new Ledger(path, authority);

        /// <summary>
        /// Open a WAL-backed ledger (as <see cref="OpenLedger"/>) bound to its own ordering-authority
        /// identity <paramref name="ledgerId"/> (the signer-id form of the ledger key, UTF-8 encoded for
        /// the ConsumeReceipt wire field) and a real deterministic ML-DSA signing key
        /// (<paramref name="alg"/>/<paramref name="seed"/>), so it can mint ledger-signed consume
        /// receipts (design.md §7.5; T1.5, NAALP-REQ-121). A zero-length <paramref name="ledgerId"/> is
        /// refused fail-closed: an unnamed ordering authority cannot sign the anti-double-spend position,
        /// so <see cref="Ledger.ConsumeWithReceipt"/> would have nothing accountable to emit. Mirrors
        /// impl/go &amp; impl/rust OpenLedgerSigned.
        /// </summary>
        public static Ledger OpenLedgerSigned(string path, string ledgerId, int alg, byte[] seed)
        {
            if (ledgerId.Length == 0)
            {
                throw new NaalpException("LedgerUnsigned", "ledger was not opened with a signing key");
            }
            return new Ledger(path, ledgerId, alg, seed);
        }

        /// <summary>
        /// The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through
        /// <see cref="Consume"/> under a single lock (the single-writer discipline), and each winning
        /// consume is written and fsynced to the WAL before it returns.
        /// </summary>
        public sealed class Ledger : IDisposable
        {
            private readonly object _mu = new object();
            private readonly FileStream _f;
            private readonly Dictionary<string, long> _consumed = new Dictionary<string, long>(); // approval-id hex -> seq
            private byte[] _head = new byte[HeadSize]; // current chain head (genesis is all-zero)
            private long _seq;                          // next sequence number
            private readonly string _ledgerId;          // consuming-authority NAME (§2.5.3 audience target); identity only, unless opened signed
            // T1.5 (NAALP-REQ-121): set only by OpenLedgerSigned; null for a plain OpenLedger (which
            // offers Consume/ConsumeObject, not the ledger-signed receipt).
            private readonly int? _signAlg;
            private readonly byte[]? _signSeed;

            internal Ledger(string path, string authority = "", int? signAlg = null, byte[]? signSeed = null)
            {
                _ledgerId = authority;
                _signAlg = signAlg;
                _signSeed = signSeed;
                _f = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                try
                {
                    Replay();
                }
                catch
                {
                    // A failed open (e.g. LedgerCorrupt on a broken WAL chain) must not leak the
                    // exclusive FileShare.None handle: the constructor throws before the object is
                    // returned, so nothing can Dispose it, and on Windows the leaked handle blocks
                    // any later delete or replace of the WAL until GC finalizes the stream.
                    _f.Dispose();
                    throw;
                }
            }

            private void Replay()
            {
                _f.Seek(0, SeekOrigin.Begin);
                byte[] head = new byte[HeadSize];
                long seq = 0;
                var lenBuf = new byte[4];
                while (true)
                {
                    if (!ReadFull(lenBuf))
                    {
                        break; // clean EOF at a record boundary
                    }
                    int n = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                    var rec = new byte[n];
                    if (!ReadFull(rec))
                    {
                        throw new NaalpException("LedgerCorrupt", "truncated ledger WAL record");
                    }
                    LedgerEntry e = ParseEntry(rec);
                    if (e.Seq != seq || !BytesEqual(e.Prev, head))
                    {
                        throw new NaalpException("LedgerCorrupt", "out-of-order seq or broken chain linkage");
                    }
                    _consumed[Hex.Encode(e.ApprovalId)] = e.Seq;
                    head = Sha384(rec);
                    seq++;
                }
                _head = head;
                _seq = seq;
                _f.Seek(0, SeekOrigin.End);
            }

            private bool ReadFull(byte[] buf)
            {
                int off = 0;
                while (off < buf.Length)
                {
                    int r = _f.Read(buf, off, buf.Length - off);
                    if (r == 0)
                    {
                        return off == 0 ? false : throw new NaalpException("LedgerCorrupt", "truncated ledger WAL record");
                    }
                    off += r;
                }
                return true;
            }

            /// <summary>
            /// Atomically consume an approval id exactly once (§7.2). The first caller for a given id
            /// appends a ledger entry (written and fsynced to the WAL before returning) and returns it;
            /// every later caller for the same id throws AlreadyConsumed with no append. The single lock
            /// serialises the compare-and-set, so under a race exactly one caller wins.
            /// </summary>
            public LedgerEntry Consume(byte[] approvalId, string by)
            {
                lock (_mu)
                {
                    string k = Hex.Encode(approvalId);
                    if (_consumed.ContainsKey(k))
                    {
                        throw new NaalpException("AlreadyConsumed", "approval already consumed");
                    }
                    var e = new LedgerEntry(_seq, _head, approvalId, by);
                    byte[] rec = e.Bytes();
                    var lenBuf = new byte[4];
                    lenBuf[0] = (byte)(rec.Length >> 24);
                    lenBuf[1] = (byte)(rec.Length >> 16);
                    lenBuf[2] = (byte)(rec.Length >> 8);
                    lenBuf[3] = (byte)rec.Length;
                    _f.Write(lenBuf, 0, 4);
                    _f.Write(rec, 0, rec.Length);
                    _f.Flush(flushToDisk: true); // persist-before-ack (R-7.2 durability)
                    _consumed[k] = e.Seq;
                    _head = e.Head();
                    _seq++;
                    return e;
                }
            }

            /// <summary>
            /// Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at
            /// the choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's
            /// consuming authority, or the object is rejected WrongAudience with no ledger append. An
            /// unnamed ledger (no authority) refuses LedgerUnsigned -- it cannot be the audience of any
            /// object. The audience check is NEVER inside Envelope.Verify (a relay/auditor legitimately
            /// verifies objects addressed to others). Mirrors Go/Rust Ledger.ConsumeObject -- the
            /// authority is this port's ledger NAME.
            /// </summary>
            public LedgerEntry ConsumeObject(Envelope.Object o, byte[] approvalId, string by)
            {
                if (_ledgerId.Length == 0)
                {
                    throw new NaalpException("LedgerUnsigned", "ledger has no consuming authority");
                }
                // fail-closed, before the CAS: throws NaalpException("WrongAudience") and appends nothing
                Envelope.CheckAudience(o, _ledgerId, true);
                return Consume(approvalId, by);
            }

            /// <summary>
            /// Perform the first-append-wins compare-and-set (exactly as <see cref="Consume"/>) AND, on
            /// the winning append, return a ledger-signed <see cref="ConsumeReceipt"/> binding the
            /// approval id to the entry's forward-only position (its ledger seq) (design.md §7.5; T1.5,
            /// NAALP-REQ-121). The ledger MUST have been opened with <see cref="OpenLedgerSigned"/>; a
            /// plain ledger throws LedgerUnsigned (fail-closed). A second consume of the same approval id
            /// throws AlreadyConsumed and signs nothing -- the first receipt stands (first-append-wins).
            /// The receipt is signed before the WAL write, so a signing failure records nothing. The
            /// single lock serialises concurrent callers, so under a race exactly one wins and exactly one
            /// receipt is minted. THIS IS THE COMPARE-AND-SET MUTATION ANCHOR (mirrors impl/go &amp;
            /// impl/rust): dropping the consumed-set membership check below would let a second call mint
            /// a SECOND receipt for the same approval id -- a double-spend of a single-use approval.
            /// </summary>
            public (LedgerEntry Entry, ConsumeReceipt Receipt, byte[] Signature) ConsumeWithReceipt(byte[] approvalId, string by)
            {
                lock (_mu)
                {
                    if (_signAlg == null || _signSeed == null || _ledgerId.Length == 0)
                    {
                        throw new NaalpException("LedgerUnsigned", "ledger was not opened with a signing key");
                    }
                    string k = Hex.Encode(approvalId);
                    if (_consumed.ContainsKey(k))
                    {
                        throw new NaalpException("AlreadyConsumed", "approval already consumed"); // first-append-wins: no second receipt
                    }
                    var e = new LedgerEntry(_seq, _head, approvalId, by);
                    // The receipt binds the approval id to THIS consume's forward-only position (the
                    // entry seq), signed by the ledger key. Sign BEFORE touching the WAL so a signing
                    // failure records nothing.
                    byte[] ledgerIdBytes = System.Text.Encoding.UTF8.GetBytes(_ledgerId);
                    var receipt = new ConsumeReceipt(ledgerIdBytes, approvalId, e.Seq);
                    byte[] sig = Cose.MldsaSign(_signAlg.Value, _signSeed, receipt.Bytes());
                    byte[] rec = e.Bytes();
                    var lenBuf = new byte[4];
                    lenBuf[0] = (byte)(rec.Length >> 24);
                    lenBuf[1] = (byte)(rec.Length >> 16);
                    lenBuf[2] = (byte)(rec.Length >> 8);
                    lenBuf[3] = (byte)rec.Length;
                    _f.Write(lenBuf, 0, 4);
                    _f.Write(rec, 0, rec.Length);
                    _f.Flush(flushToDisk: true); // persist-before-ack (R-7.2 durability)
                    _consumed[k] = e.Seq;
                    _head = e.Head();
                    _seq++;
                    return (e, receipt, sig);
                }
            }

            /// <summary>Whether an approval id has been consumed.</summary>
            public bool IsConsumed(byte[] approvalId)
            {
                lock (_mu)
                {
                    return _consumed.ContainsKey(Hex.Encode(approvalId));
                }
            }

            /// <summary>The current chain head (a copy).</summary>
            public byte[] Head()
            {
                lock (_mu)
                {
                    return (byte[])_head.Clone();
                }
            }

            /// <summary>The number of consumed approvals.</summary>
            public int Len()
            {
                lock (_mu)
                {
                    return _consumed.Count;
                }
            }

            /// <summary>Flush and close the WAL file.</summary>
            public void Close()
            {
                lock (_mu)
                {
                    _f.Dispose();
                }
            }

            public void Dispose() => Close();
        }

        // ---- §7.5 (T1.5, NAALP-REQ-121) ledger-signed consume receipt + fork evidence --------------
        //
        // The ledger-signed evidence that a consuming ledger -- the ORDERING AUTHORITY -- bound an
        // approval content id to its own forward-only position. The anti-double-spend counter
        // (Position) rides under the LEDGER's signature, never the requester's: the requester cannot
        // forge the ledger's position or its signature. A partition that spends one approval twice
        // therefore leaves two ledger-signed receipts against one approval id, each carrying a position
        // drawn from forked state -- a contradiction authored by neither the requester nor a thief,
        // provable the instant the two receipts are compared (see ConsumeForkEvidence). It does not
        // PREVENT the second spend; it makes the double-spend detectable in bytes neither party could
        // repudiate. Mirrors impl/go/approval/approval.go and impl/rust/src/approval.rs byte-for-byte.

        /// <summary>One ledger-signed consume receipt {1: ledger, 2: approval_id, 3: position}.</summary>
        public sealed class ConsumeReceipt
        {
            public readonly byte[] Ledger;     // the consuming ledger's signer id (the ordering authority; REQ-121)
            public readonly byte[] ApprovalId; // the approval content id consumed (the compare-and-set key)
            public readonly long Position;     // the ledger's forward-only position bound to this consume (u64 bit pattern)

            public ConsumeReceipt(byte[] ledger, byte[] approvalId, long position)
            {
                Ledger = (byte[])ledger.Clone();
                ApprovalId = (byte[])approvalId.Clone();
                Position = position;
            }

            /// <summary>The deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id,
            /// 3: position} -- the exact bytes the ledger signs (T1.5).</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Ledger)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(ApprovalId)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Position)),
                }));
            }
        }

        /// <summary>Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter
        /// is under the ordering authority's signature). The signed input is the receipt Bytes().</summary>
        public static byte[] SignConsumeReceipt(ConsumeReceipt r, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, r.Bytes());

        /// <summary>Check that a consume receipt is a valid ledger-signed statement: the ledger id is
        /// present (an unnamed ordering authority is not evidence) and the signature verifies under the
        /// ledger's key. FAIL-CLOSED: either fault throws ConsumeReceiptUnsigned. <paramref name="pk"/>
        /// MUST be the key resolved for <c>r.Ledger</c>.</summary>
        public static void VerifyConsumeReceipt(ConsumeReceipt r, int alg, byte[] pk, byte[] sig)
        {
            if (r.Ledger.Length == 0)
            {
                throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify");
            }
            if (!Cose.CoseVerify1Raw(alg, pk, r.Bytes(), sig))
            {
                throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify");
            }
        }

        /// <summary>
        /// (R-TDCS-4, design.md §25) Judge an approval's present-moment validity using time drawn from an
        /// ordering authority STRUCTURALLY DISTINCT from the party being authenticated. It is the named
        /// realization of the §18.2 seam -- "validity judged on the ordering position, never the signer's
        /// clock" -- composing the existing verifiers and adding the distinctness check a relying party
        /// runs so a party can never be the source of the time against which its own credential's expiry
        /// is judged. It (1) verifies the approval binds <paramref name="argsContentId"/>, is signed by
        /// the approver, and is unexpired at <paramref name="posTime"/> (the ORDERING AUTHORITY's
        /// forward-only position, never a clock the approver supplies); (2) verifies the consume receipt
        /// is ledger-signed (the position rides under the ordering authority's key, never the
        /// requester's); and (3) rejects FreshnessSelfAsserted when the ordering authority
        /// <c>r.Ledger</c> IS the authenticated party <paramref name="partyId"/>. FAIL-CLOSED: any fault
        /// throws its named error and authorizes nothing.
        /// </summary>
        public static void VerifyFreshIndependent(
            ApprovalRecord a, int approverAlg, byte[] approverPk, byte[] aSig, byte[] argsContentId, long posTime,
            ConsumeReceipt r, int ledgerAlg, byte[] ledgerPk, byte[] rSig, byte[] partyId)
        {
            VerifyApproval(a, approverAlg, approverPk, aSig, argsContentId, posTime);
            VerifyConsumeReceipt(r, ledgerAlg, ledgerPk, rSig);
            if (BytesEqual(r.Ledger, partyId))
            {
                throw new NaalpException("FreshnessSelfAsserted", "the ordering authority that stamps freshness is the authenticated party itself");
            }
        }

        /// <summary>
        /// The non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content id received TWO
        /// conflicting ledger-signed consume receipts -- a double spend made provable on comparison. It
        /// carries both receipts and both ledger signatures; because a verifier checks each signature
        /// under the key its receipt names, the contradiction is authored by neither the requester nor a
        /// thief. Both positions (and, cross-ledger, both ledger ids) are surfaced so the contradiction
        /// is legible to a human and to tooling.
        /// </summary>
        public sealed class ConsumeForkEvidence
        {
            public readonly byte[] ApprovalId; // the one approval content id spent twice
            public readonly ConsumeReceipt A;  // first receipt
            public readonly byte[] SigA;       // ledger A's signature over A.Bytes()
            public readonly ConsumeReceipt B;  // second receipt (same approval id; different position and/or ledger)
            public readonly byte[] SigB;       // ledger B's signature over B.Bytes()

            public ConsumeForkEvidence(byte[] approvalId, ConsumeReceipt a, byte[] sigA, ConsumeReceipt b, byte[] sigB)
            {
                ApprovalId = (byte[])approvalId.Clone();
                A = a;
                SigA = (byte[])sigA.Clone();
                B = b;
                SigB = (byte[])sigB.Clone();
            }

            /// <summary>
            /// Check that this is a genuine fork: (1) the disputed approval id is present and BOTH
            /// receipts name it; (2) the two receipts actually conflict -- they are NOT byte-identical (a
            /// byte-identical re-emission is a benign duplicate, not a fork); and (3) BOTH ledger
            /// signatures verify under the keys their receipts name, resolved through
            /// <paramref name="resolve"/>. Any failure throws (fail-closed): a mismatched/absent approval
            /// id or a byte-identical pair is ConsumeForkInvalid, and an unnamed/unresolvable ledger or a
            /// signature that does not verify is ConsumeReceiptUnsigned. On a clean pass the double spend
            /// is proven and non-repudiable.
            /// </summary>
            public void Verify(Func<byte[], (int Alg, byte[] Pk, bool Ok)> resolve)
            {
                if (ApprovalId.Length == 0)
                {
                    throw new NaalpException("ConsumeForkInvalid", "fork evidence does not prove a double spend");
                }
                if (!BytesEqual(A.ApprovalId, ApprovalId) || !BytesEqual(B.ApprovalId, ApprovalId))
                {
                    throw new NaalpException("ConsumeForkInvalid", "fork evidence does not prove a double spend"); // both receipts must name the disputed approval id
                }
                if (BytesEqual(A.Bytes(), B.Bytes()))
                {
                    throw new NaalpException("ConsumeForkInvalid", "fork evidence does not prove a double spend"); // byte-identical receipts are a benign duplicate
                }
                (int Alg, byte[] Pk, bool Ok) ra = resolve(A.Ledger);
                if (!ra.Ok || A.Ledger.Length == 0)
                {
                    throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify");
                }
                (int Alg, byte[] Pk, bool Ok) rb = resolve(B.Ledger);
                if (!rb.Ok || B.Ledger.Length == 0)
                {
                    throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify");
                }
                if (!Cose.CoseVerify1Raw(ra.Alg, ra.Pk, A.Bytes(), SigA) || !Cose.CoseVerify1Raw(rb.Alg, rb.Pk, B.Bytes(), SigB))
                {
                    throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify");
                }
            }
        }

        /// <summary>
        /// Observes ledger-signed consume receipts, keyed by approval content id, and detects a fork (a
        /// double spend) from the signed receipts alone (T1.5, NAALP-REQ-121) -- the consume-layer
        /// analogue of the audit auditor's equivocation detection. It resolves each receipt's ledger key
        /// through the constructor-supplied resolver, throws ConsumeReceiptUnsigned for any receipt
        /// whose ledger signature does not verify, and on a conflicting second receipt for one approval
        /// id returns a non-repudiable <see cref="ConsumeForkEvidence"/> (a benign byte-identical
        /// duplicate returns null, same as a first sighting).
        /// </summary>
        public sealed class ReceiptSet
        {
            private readonly object _mu = new object();
            private readonly Func<byte[], (int Alg, byte[] Pk, bool Ok)> _resolve;
            private readonly Dictionary<string, (ConsumeReceipt R, byte[] Sig)> _seen = new Dictionary<string, (ConsumeReceipt, byte[])>();

            internal ReceiptSet(Func<byte[], (int Alg, byte[] Pk, bool Ok)> resolve)
            {
                _resolve = resolve;
            }

            /// <summary>
            /// Record a ledger-signed consume receipt, verifying it under the key
            /// <c>resolve(r.Ledger)</c> returns. Throws ConsumeReceiptUnsigned if the ledger is
            /// unnamed/unresolvable or the signature does not verify. Returns a non-null
            /// <see cref="ConsumeForkEvidence"/> when a previously-seen receipt for the same approval id
            /// conflicts (different position and/or ledger) -- the ConsumeFork condition; returns null
            /// otherwise (including a benign byte-identical duplicate).
            /// </summary>
            public ConsumeForkEvidence? Observe(ConsumeReceipt r, byte[] sig)
            {
                lock (_mu)
                {
                    (int Alg, byte[] Pk, bool Ok) resolved = _resolve(r.Ledger);
                    if (!resolved.Ok || r.Ledger.Length == 0 || !Cose.CoseVerify1Raw(resolved.Alg, resolved.Pk, r.Bytes(), sig))
                    {
                        throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify");
                    }
                    string key = Hex.Encode(r.ApprovalId);
                    if (_seen.TryGetValue(key, out (ConsumeReceipt R, byte[] Sig) prev))
                    {
                        if (BytesEqual(prev.R.Bytes(), r.Bytes()))
                        {
                            return null; // benign byte-identical duplicate
                        }
                        var fe = new ConsumeForkEvidence(r.ApprovalId, prev.R, prev.Sig, r, (byte[])sig.Clone());
                        return fe; // ConsumeFork: two ledger-signed receipts contradict on one approval id
                    }
                    _seen[key] = (r, (byte[])sig.Clone());
                    return null;
                }
            }
        }

        /// <summary>Make a fork detector that resolves a ledger id to its (alg, pubkey) via
        /// <paramref name="resolve"/> (which returns Ok=false for an unknown ledger id).</summary>
        public static ReceiptSet NewReceiptSet(Func<byte[], (int Alg, byte[] Pk, bool Ok)> resolve) => new ReceiptSet(resolve);

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
