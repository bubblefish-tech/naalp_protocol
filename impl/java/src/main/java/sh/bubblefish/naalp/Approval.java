// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * N-AALP C6 approval object + single-use consume ledger for the Java SDK (design.md §7; R-7.1..7.4).
 *
 * <p>An {@link ApprovalRecord} binds, under signature, the content id of the exact canonical argument
 * object it approves (§7.1); because the args are named by content id, mutating any argument changes
 * the id and the approval no longer matches (ApprovalMismatch). The consume ledger is a durable
 * compare-and-set set keyed by approval content id: the FIRST consumer of an id wins and every later
 * consume of the same id is rejected AlreadyConsumed (§7.2). Atomicity is honest, not decorative —
 * the membership check AND the append run inside ONE lock-held critical section (the single-writer
 * discipline, mirroring the Go reference's single mutex), so there is no read-then-write TOCTOU window
 * and a race spends an approval exactly once. Each winning consume is written and fsynced to the
 * write-ahead log before it returns (persist-before-ack). A held outcome is a distinct signed
 * non-success result ({@link HeldResult}, §7.4). Every rejection is fail-closed and causes no append.
 *
 * <p>An independent transcription of impl/go/approval (cross-checked against impl/python/naalp/approval).
 * The wire bodies (approval body, ledger entry) reuse the already-graded {@link Records} builders, so
 * they are byte-identical to Go/Rust/Python. Byte surfaces are graded against vectors/approval/cases.json;
 * the approval SIGNATURE is a RAW deterministic ML-DSA-65 signature over the body bytes
 * ({@link Cose#coseVerify1Raw}), demonstrated in isolation (the corpus carries no signature vector).
 *
 * <p>ALSO PORTED (T1.5, NAALP-REQ-121, design.md §7.5, graded against the SEPARATE independent corpus
 * vectors/consume_receipt/cases.json): the ledger-signed {@link ConsumeReceipt} binding an approval id
 * to the consuming ledger's own forward-only position ({@link Ledger#openLedgerSigned} +
 * {@link Ledger#consumeWithReceipt}), the {@link ConsumeForkEvidence} non-repudiable double-spend proof,
 * and the {@link ReceiptSet} fork detector. Also ported: the R-TDCS-5 approval audience binding
 * ({@link #verifyAudience}), the R-TDCS-3 party-visible coarse {@link Refusal} object (graded against
 * vectors/trust_decision/cases.json), and R-TDCS-4 freshness independence ({@link #verifyFreshIndependent}).
 */
public final class Approval {
    /** The width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero. */
    public static final int HEAD_SIZE = 48;

    private Approval() {}

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    private static String key(byte[] b) {
        return Hex.encode(b);
    }

    // ---- §7.1 the approval object body -----------------------------------------------------------

    /** The body of an Approval object (§7.1). Signed over its deterministic-CBOR bytes. {@code approves}
     * is the content id of the exact canonical args object; a changed argument changes the id and the
     * approval no longer matches (ApprovalMismatch). */
    public static final class ApprovalRecord {
        public final byte[] approves; // content id of the exact canonical args object (§7.1)
        public final String approver; // approver signer id
        public final long grant;      // granted effect class (0..3), the C5 effect
        public final byte[] nonce;    // anti-replay nonce (§7.3)
        public final long notAfter;   // expiry, epoch ms (§7.3)
        public final String audience; // R-TDCS-5 OPTIONAL valid-context; "" == absent (field 6 omitted)

        public ApprovalRecord(byte[] approves, String approver, long grant, byte[] nonce, long notAfter) {
            this(approves, approver, grant, nonce, notAfter, "");
        }

        /** (R-TDCS-5, design.md §25) An approval MAY name an audience: the OPTIONAL valid-context this
         * approval is restricted to. {@code audience == ""} means absent (field 6 omitted; unrestricted). */
        public ApprovalRecord(byte[] approves, String approver, long grant, byte[] nonce, long notAfter, String audience) {
            this.approves = approves.clone();
            this.approver = approver;
            this.grant = grant;
            this.nonce = nonce.clone();
            this.notAfter = notAfter;
            this.audience = audience == null ? "" : audience;
        }

        /** Deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6 is OMITTED
         * when audience is "" -- an empty string is not a distinct value, so an approval naming no
         * audience encodes byte-identically to a 5-field approval (R-TDCS-5, additive by design). Built
         * inline (not via the shared Records builder) so the 6-field variant needs no change there. */
        public byte[] bytes() {
            List<Cbor.Pair> pairs = new ArrayList<>(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(approves)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(approver)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(grant)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(nonce)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(notAfter))));
            if (!audience.isEmpty()) {
                pairs.add(new Cbor.Pair(new Cbor.U(6), new Cbor.T(audience)));
            }
            return Cbor.encode(new Cbor.M(pairs));
        }

        /** The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets). */
        public byte[] id() {
            return Cbor.contentId(bytes());
        }
    }

    /** Sign the approval body with a real deterministic ML-DSA key derived from {@code seed}. The signed
     * input is the approval body bytes DIRECTLY (matching the reference cose.Signer.Sign: raw message,
     * empty context, rnd=0 — there is NO COSE Sig_structure wrapping here). */
    public static byte[] signApproval(ApprovalRecord a, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, a.bytes());
    }

    /** Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact
     * args by content id, (3) not expired at {@code posTime}. Returns normally only if all three hold;
     * otherwise throws the specific named error and authorizes nothing. Check order is fail-closed:
     * BadSignature → ApprovalMismatch → ApprovalExpired. It does NOT consume — consumption is the
     * separate atomic ledger step (§7.2). */
    public static void verifyApproval(ApprovalRecord a, int alg, byte[] pk, byte[] sig,
                                      byte[] argsContentID, long posTime) {
        if (!Cose.coseVerify1Raw(alg, pk, a.bytes(), sig)) {
            throw new NaalpException("BadSignature", "approval signature does not verify");
        }
        if (!Arrays.equals(a.approves, argsContentID)) {
            throw new NaalpException("ApprovalMismatch", "approval does not bind these arguments' content id");
        }
        if (Long.compareUnsigned(posTime, a.notAfter) > 0) {
            throw new NaalpException("ApprovalExpired", "approval is past its not_after");
        }
    }

    /** (R-TDCS-5, design.md §25) Enforce the OPTIONAL audience binding. An approval that NAMES an
     * audience ({@code a.audience != ""}) is valid only in that context: a relying party checks it at
     * use and throws AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted
     * by the issuer's explicit choice and passes for any use context -- a deployment MAY require an
     * audience by local policy above this check. The check is mandatory WHEN a context is present,
     * never mandatory-presence (the JWT {@code aud} present-optional / check-mandatory shape). */
    public static void verifyAudience(ApprovalRecord a, String useContext) {
        if (!a.audience.isEmpty() && !a.audience.equals(useContext)) {
            throw new NaalpException("AudienceMismatch", "approval names an audience other than the use context");
        }
    }

    /** The composed, single-call consume choke point for the approval state machine (draft "## Approval
     * state machine"). It runs the table's precedence in ONE impl-owned place -- the exact sequence that
     * {@link Payment#authorizeCharge} and the mcp/agui/delegation callers each hand-assemble -- so a
     * caller (and the conformance suite) drives one realization of the reactions rather than re-deriving
     * the ordering at each call site:
     * <ol>
     *   <li>{@link #verifyApproval} checks the signature, then the args-content-id binding
     *   (ApprovalMismatch, which the draft says "takes precedence over every cell"), then expiry
     *   (ApprovalExpired) -- all BEFORE the ledger is consulted. So a request both past notAfter AND
     *   already in the ledger is refused ApprovalExpired, never AlreadyConsumed (the draft's
     *   expiry-over-consume rule), and the ledger is left untouched by the rejected request.</li>
     *   <li>The granted effect must be a valid class (0..3) and must cover the action's required
     *   effect; a grant outside the closed vocabulary, or one below the required effect, authorizes
     *   nothing and is refused ApprovalRequired (fail-closed; the grant-range guard is stricter than
     *   the raw callers).</li>
     *   <li>The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
     *   second returns AlreadyConsumed, and neither a rejected earlier step nor a losing race
     *   appends.</li>
     * </ol>
     * Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
     * returning the ledger entry. It does NOT enforce object audience -- that is
     * {@link Ledger#consumeObject}'s binding (design.md §2.5.3); consumeApproval is the
     * args-content-id/effect/single-use choke point. */
    public static LedgerEntry consumeApproval(ApprovalRecord a, int approverAlg, byte[] approverPk, byte[] aSig,
                                              byte[] argsContentID, long posTime, long requiredEffect,
                                              Ledger ledger, String by) {
        // BadSignature / ApprovalMismatch / ApprovalExpired -- all before the ledger (§ precedence).
        verifyApproval(a, approverAlg, approverPk, aSig, argsContentID, posTime);
        if (a.grant > Policy.DESTRUCTIVE) {
            // a grant outside the closed 0..3 effect vocabulary authorizes nothing.
            throw new NaalpException("ApprovalRequired", "action requires an approval that is not present");
        }
        if (!Policy.authorizes(a.grant, requiredEffect)) {
            // the approval's granted effect does not cover this action.
            throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover this action");
        }
        return ledger.consume(a.id(), by);
    }

    // ---- §7.4 the held (not-yet-granted) outcome -------------------------------------------------

    /** The distinct, signed, non-success result returned when an action requires an approval that has
     * not been granted (§7.4). It is never a silent success or a silent denial. */
    public static final class HeldResult {
        public final byte[] approves; // content id of the args whose approval is pending
        public final String reason;

        public HeldResult(byte[] approves, String reason) {
            this.approves = approves.clone();
            this.reason = reason;
        }

        /** Deterministic-CBOR encoding {1: approves, 2: reason}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(approves)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.T(reason)))));
        }
    }

    /** Sign a held result so the "not yet granted" outcome is itself attributable (real ML-DSA). */
    public static byte[] signHeld(HeldResult h, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, h.bytes());
    }

    // ---- §7.2 the consume ledger entry -----------------------------------------------------------

    /** One append to the consume ledger (§7.2). */
    public static final class LedgerEntry {
        public final long seq;         // ledger sequence position
        public final byte[] prev;      // prior chain head (HEAD_SIZE bytes; genesis is all-zero)
        public final byte[] approvalId; // the approval content id being consumed
        public final String by;        // consumer signer id

        public LedgerEntry(long seq, byte[] prev, byte[] approvalId, String by) {
            this.seq = seq;
            this.prev = prev.clone();
            this.approvalId = approvalId.clone();
            this.by = by;
        }

        /** Deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by} (reuses the spine
         * records builder). The head after this entry is SHA-384(bytes()); because bytes() carries
         * prev, editing any entry breaks the next entry's linkage. */
        public byte[] bytes() {
            return Records.ledgerEntry(seq, prev, approvalId, by);
        }

        /** This entry's chain head — the prev of the next entry. */
        public byte[] head() {
            return sha384(bytes());
        }
    }

    private static LedgerEntry parseEntry(byte[] rec) {
        Cbor.Value v = Cbor.decode(rec); // strict decoder: throws NonCanonical on a non-canonical body
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("LedgerCorrupt", "ledger entry is not a map");
        }
        Long seq = null;
        byte[] prev = null;
        byte[] aid = null;
        String by = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) {
                throw new NaalpException("LedgerCorrupt", "non-uint ledger entry key");
            }
            long k = ku.v;
            if (k == 1 && p.val instanceof Cbor.U u) {
                seq = u.v;
            } else if (k == 2 && p.val instanceof Cbor.B b) {
                prev = b.v;
            } else if (k == 3 && p.val instanceof Cbor.B b) {
                aid = b.v;
            } else if (k == 4 && p.val instanceof Cbor.T t) {
                by = t.v;
            } else {
                throw new NaalpException("LedgerCorrupt", "unknown or mistyped ledger entry field " + k);
            }
        }
        if (seq == null || prev == null || aid == null || by == null) {
            throw new NaalpException("LedgerCorrupt", "ledger entry missing a mandatory field");
        }
        return new LedgerEntry(seq, prev, aid, by);
    }

    /** The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through
     * {@link #consume} under a single lock (the single-writer discipline), and each winning consume is
     * written and fsynced to the WAL before it returns. Use {@link #open} to construct one. */
    public static final class Ledger {
        private final ReentrantLock lock = new ReentrantLock();
        private final FileChannel ch;
        private final Map<String, Long> consumed = new HashMap<>();
        private byte[] head = new byte[HEAD_SIZE]; // current chain head (genesis is all-zero)
        private long seq = 0;                       // next sequence number
        private final String ledgerId;              // consuming-authority NAME (§2.5.3 audience target)
        // T1.5 (NAALP-REQ-121): the ordering-authority identity (raw bytes; carried in every minted
        // ConsumeReceipt.Ledger) and its ML-DSA signing key, set only by openLedgerSigned. The SAME
        // identity backs BOTH the §2.5.3 audience check (ledgerId, above) and the REQ-121 receipt
        // signature -- one ledger, one identity, matching Go's single ledgerID field. signSeed == null
        // means unsigned: offers consume()/consumeObject() but not consumeWithReceipt() (LedgerUnsigned).
        private final byte[] receiptLedgerId;
        private final int signAlg;
        private final byte[] signSeed;

        private Ledger(FileChannel ch, String authority, byte[] receiptLedgerId, int signAlg, byte[] signSeed) {
            this.ch = ch;
            this.ledgerId = authority == null ? "" : authority;
            this.receiptLedgerId = receiptLedgerId == null ? new byte[0] : receiptLedgerId;
            this.signAlg = signAlg;
            this.signSeed = signSeed;
        }

        /** Open (creating if needed) a WAL-backed consume ledger at {@code path} and replay any existing
         * log to rebuild the consumed set and chain head. A log that does not hash-chain cleanly is
         * refused (LedgerCorrupt) rather than trusted. */
        public static Ledger open(Path path) {
            return open(path, "");
        }

        /** Open a WAL-backed consume ledger with a consuming-authority NAME (the §2.5.3 audience
         * target that {@link #consumeObject} enforces). Unsigned: offers consume()/consumeObject()
         * but not {@link #consumeWithReceipt} (fail-closed LedgerUnsigned). */
        public static Ledger open(Path path, String authority) {
            return openInternal(path, authority, new byte[0], 0, null);
        }

        /** Port-naming parity with the Go/Rust top-level {@code OpenLedger} constructor: an explicitly
         * unsigned ledger (no consuming-authority identity, no signing key). Equivalent to {@link #open(Path)}. */
        public static Ledger openLedger(Path path) {
            return open(path);
        }

        /** T1.5 (NAALP-REQ-121): open a WAL-backed consume ledger bound to its own ordering-authority
         * identity ({@code ledgerId}, the signer-id-form bytes carried in every minted
         * {@code ConsumeReceipt.Ledger}) and ML-DSA signing key, so it can mint ledger-signed consume
         * receipts via {@link #consumeWithReceipt}. The same identity also serves as the §2.5.3
         * consuming authority {@link #consumeObject} enforces. A zero-length {@code ledgerId} is
         * refused fail-closed (LedgerUnsigned): an unnamed ordering authority cannot sign the
         * anti-double-spend position. Mirrors Go/Rust {@code OpenLedgerSigned}. */
        public static Ledger openLedgerSigned(Path path, byte[] ledgerId, int alg, byte[] seed) {
            if (ledgerId == null || ledgerId.length == 0) {
                throw new NaalpException("LedgerUnsigned", "ledger was not opened with a signing key");
            }
            String authority = new String(ledgerId, StandardCharsets.UTF_8);
            return openInternal(path, authority, ledgerId.clone(), alg, seed == null ? null : seed.clone());
        }

        private static Ledger openInternal(Path path, String authority, byte[] receiptLedgerId, int alg, byte[] seed) {
            try {
                FileChannel ch = FileChannel.open(path,
                        StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
                Ledger l = new Ledger(ch, authority, receiptLedgerId, alg, seed);
                l.replay();
                return l;
            } catch (IOException e) {
                throw new NaalpException("LedgerIO", e.toString());
            }
        }

        private static int readFully(FileChannel ch, ByteBuffer buf) throws IOException {
            int total = 0;
            while (buf.hasRemaining()) {
                int r = ch.read(buf);
                if (r < 0) {
                    return total == 0 ? -1 : total;
                }
                total += r;
            }
            return total;
        }

        private void replay() throws IOException {
            ch.position(0);
            byte[] h = new byte[HEAD_SIZE];
            long s = 0;
            ByteBuffer lenBuf = ByteBuffer.allocate(4);
            while (true) {
                lenBuf.clear();
                int r = readFully(ch, lenBuf);
                if (r == -1) {
                    break; // clean EOF at a record boundary
                }
                if (r != 4) {
                    throw new NaalpException("LedgerCorrupt", "truncated length prefix");
                }
                lenBuf.flip();
                int n = lenBuf.getInt();
                ByteBuffer recBuf = ByteBuffer.allocate(n);
                if (readFully(ch, recBuf) != n) {
                    throw new NaalpException("LedgerCorrupt", "truncated record");
                }
                byte[] rec = recBuf.array();
                LedgerEntry e = parseEntry(rec);
                if (e.seq != s || !Arrays.equals(e.prev, h)) {
                    throw new NaalpException("LedgerCorrupt", "out-of-order seq or broken chain linkage");
                }
                consumed.put(key(e.approvalId), e.seq);
                h = sha384(rec);
                s++;
            }
            head = h;
            seq = s;
        }

        /** Atomically consume an approval id exactly once (§7.2). The first caller for a given id
         * appends a ledger entry (written and fsynced before returning) and returns it; every later
         * caller for the same id throws AlreadyConsumed with no append. The single lock serialises the
         * compare-and-set, so under a race exactly one caller wins. */
        public LedgerEntry consume(byte[] approvalId, String by) {
            lock.lock();
            try {
                String k = key(approvalId);
                if (consumed.containsKey(k)) {
                    throw new NaalpException("AlreadyConsumed", "approval already consumed");
                }
                LedgerEntry e = new LedgerEntry(seq, head, approvalId, by);
                byte[] rec = e.bytes();
                ByteBuffer framed = ByteBuffer.allocate(4 + rec.length);
                framed.putInt(rec.length);
                framed.put(rec);
                framed.flip();
                ch.position(ch.size());
                while (framed.hasRemaining()) {
                    ch.write(framed);
                }
                ch.force(true); // persist-before-ack (R-7.2 durability)
                consumed.put(k, e.seq);
                head = e.head();
                seq++;
                return e;
            } catch (IOException e) {
                throw new NaalpException("LedgerIO", e.toString());
            } finally {
                lock.unlock();
            }
        }

        /** Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at the
         * choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's
         * consuming authority, or the object is rejected WrongAudience with no ledger append. An
         * unnamed ledger (no authority) refuses LedgerUnsigned -- it cannot be the audience of any
         * object. The audience check is NEVER inside Envelope.verify (a relay/auditor legitimately
         * verifies objects addressed to others). Mirrors Go/Rust Ledger.ConsumeObject -- the authority
         * is this port's ledger NAME. */
        public LedgerEntry consumeObject(Envelope.Object o, byte[] approvalId, String by) {
            if (ledgerId.isEmpty()) {
                throw new NaalpException("LedgerUnsigned", "ledger has no consuming authority");
            }
            // fail-closed, before the CAS: throws NaalpException("WrongAudience") and appends nothing
            Envelope.checkAudience(o, ledgerId, true);
            return consume(approvalId, by);
        }

        /** T1.5 (NAALP-REQ-121): the compare-and-set MUTATION anchor. Performs the first-append-wins
         * CAS exactly as {@link #consume} AND, on the winning append, mints a ledger-signed
         * {@link ConsumeReceipt} binding the approval id to the entry's forward-only position (its
         * ledger seq), signed by the ledger's own key. The ledger must have been opened with
         * {@link #openLedgerSigned}; a plain ledger throws LedgerUnsigned (fail-closed). A second
         * consume of the same approval id throws AlreadyConsumed and mints NOTHING -- the first receipt
         * stands (first-append-wins). The receipt is signed BEFORE the WAL write, so a signing failure
         * records nothing. The single lock serialises concurrent callers, so under a race exactly one
         * wins and exactly one receipt is minted. */
        public ConsumeWithReceiptResult consumeWithReceipt(byte[] approvalId, String by) {
            lock.lock();
            try {
                if (signSeed == null || receiptLedgerId.length == 0) {
                    throw new NaalpException("LedgerUnsigned", "ledger was not opened with a signing key");
                }
                String k = key(approvalId);
                if (consumed.containsKey(k)) {
                    throw new NaalpException("AlreadyConsumed", "approval already consumed"); // first-append-wins: no second receipt
                }
                LedgerEntry e = new LedgerEntry(seq, head, approvalId, by);
                // the receipt binds the approval id to THIS consume's forward-only position (the entry
                // seq), signed by the ledger key (REQ-121); sign BEFORE touching the WAL so a signing
                // failure records nothing.
                ConsumeReceipt receipt = new ConsumeReceipt(receiptLedgerId, approvalId, e.seq);
                byte[] sig = Cose.mldsaSign(signAlg, signSeed, receipt.bytes());
                byte[] rec = e.bytes();
                ByteBuffer framed = ByteBuffer.allocate(4 + rec.length);
                framed.putInt(rec.length);
                framed.put(rec);
                framed.flip();
                ch.position(ch.size());
                while (framed.hasRemaining()) {
                    ch.write(framed);
                }
                ch.force(true); // persist-before-ack (R-7.2 durability)
                consumed.put(k, e.seq);
                head = e.head();
                seq++;
                return new ConsumeWithReceiptResult(e, receipt, sig);
            } catch (IOException e) {
                throw new NaalpException("LedgerIO", e.toString());
            } finally {
                lock.unlock();
            }
        }

        /** Whether an approval id has been consumed. */
        public boolean isConsumed(byte[] approvalId) {
            lock.lock();
            try {
                return consumed.containsKey(key(approvalId));
            } finally {
                lock.unlock();
            }
        }

        /** The current chain head (a copy). */
        public byte[] head() {
            lock.lock();
            try {
                return head.clone();
            } finally {
                lock.unlock();
            }
        }

        /** The number of consumed approvals. */
        public int len() {
            lock.lock();
            try {
                return consumed.size();
            } finally {
                lock.unlock();
            }
        }

        /** Flush and close the WAL file. */
        public void close() {
            lock.lock();
            try {
                ch.close();
            } catch (IOException e) {
                throw new NaalpException("LedgerIO", e.toString());
            } finally {
                lock.unlock();
            }
        }
    }

    // ---- §7.5 (T1.5, NAALP-REQ-121) the ledger-signed consume receipt ----------------------------

    /** The draft-01 (T1.5, NAALP-REQ-121) ledger-signed evidence that a consuming ledger -- the
     * ORDERING AUTHORITY -- bound an approval content id to its own forward-only position. The
     * anti-double-spend counter ({@code position}) rides under the LEDGER's signature, never the
     * requester's: the requester cannot forge the ledger's position or its signature. A partition that
     * spends one approval twice therefore leaves two ledger-signed receipts against one approval id,
     * each carrying a position drawn from forked state -- a contradiction authored by neither the
     * requester nor a thief, provable the instant the two receipts are compared (see
     * {@link ConsumeForkEvidence}). It does not PREVENT the second spend; it makes the double-spend
     * detectable in bytes neither party could repudiate. */
    public static final class ConsumeReceipt {
        public final byte[] ledger;     // the consuming ledger's signer id (the ordering authority; REQ-121)
        public final byte[] approvalId; // the approval content id consumed (the compare-and-set key)
        public final long position;     // the ledger's forward-only position bound to this consume

        public ConsumeReceipt(byte[] ledger, byte[] approvalId, long position) {
            this.ledger = ledger == null ? new byte[0] : ledger.clone();
            this.approvalId = approvalId.clone();
            this.position = position;
        }

        /** Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position} --
         * the exact bytes the ledger signs (T1.5). */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(ledger)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(approvalId)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(position)))));
        }
    }

    /** The three-part result of {@link Ledger#consumeWithReceipt}: the appended ledger entry, the
     * ledger-signed consume receipt, and its signature bytes. */
    public static final class ConsumeWithReceiptResult {
        public final LedgerEntry entry;
        public final ConsumeReceipt receipt;
        public final byte[] sig;

        public ConsumeWithReceiptResult(LedgerEntry entry, ConsumeReceipt receipt, byte[] sig) {
            this.entry = entry;
            this.receipt = receipt;
            this.sig = sig;
        }
    }

    /** Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is under
     * the ordering authority's signature). The signed input is the receipt {@link ConsumeReceipt#bytes()}. */
    public static byte[] signConsumeReceipt(ConsumeReceipt r, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, r.bytes());
    }

    /** Check that a consume receipt is a valid ledger-signed statement: the ledger id is present (an
     * unnamed ordering authority is not evidence) and the signature verifies under the ledger's key.
     * Fail-closed: either fault throws ConsumeReceiptUnsigned and authorizes nothing. */
    public static void verifyConsumeReceipt(ConsumeReceipt r, int alg, byte[] ledgerPk, byte[] sig) {
        if (r.ledger.length == 0) {
            throw new NaalpException("ConsumeReceiptUnsigned", "an unnamed ordering authority is not evidence");
        }
        if (!Cose.coseVerify1Raw(alg, ledgerPk, r.bytes(), sig)) {
            throw new NaalpException("ConsumeReceiptUnsigned", "consume receipt signature does not verify");
        }
    }

    /** (R-TDCS-4, design.md §25) Judge an approval's present-moment validity using time drawn from an
     * ordering authority STRUCTURALLY DISTINCT from the party being authenticated. It is the named
     * realization of the §18.2 seam -- "validity judged on the ordering position, never the signer's
     * clock" -- composing the existing verifiers and adding the distinctness check a relying party runs
     * so a party can never be the source of the time against which its own credential's expiry is
     * judged. It (1) verifies the approval binds argsContentId, is signed by the approver, and is
     * unexpired at posTime, where posTime is the ORDERING AUTHORITY's forward-only position (never a
     * clock the approver supplies); (2) verifies the consume receipt is ledger-signed (the position
     * rides under the ordering authority's key, never the requester's); and (3) rejects
     * FreshnessSelfAsserted when the ordering authority {@code r.ledger} IS the authenticated party
     * {@code partyId}. Fail-closed: any fault throws its named error and authorizes nothing. */
    public static void verifyFreshIndependent(
            ApprovalRecord a, int approverAlg, byte[] approverPk, byte[] aSig, byte[] argsContentId, long posTime,
            ConsumeReceipt r, int ledgerAlg, byte[] ledgerPk, byte[] rSig, byte[] partyId) {
        verifyApproval(a, approverAlg, approverPk, aSig, argsContentId, posTime);
        verifyConsumeReceipt(r, ledgerAlg, ledgerPk, rSig);
        if (Arrays.equals(r.ledger, partyId)) {
            throw new NaalpException("FreshnessSelfAsserted",
                    "the ordering authority that stamps freshness is the authenticated party itself");
        }
    }

    /** Resolves a ledger id to its ML-DSA verification key, or returns null when the ledger id is
     * unknown -- the fork-evidence / receipt-set analogue of an identity resolver. */
    public interface LedgerKeyResolver {
        LedgerVerifierKey resolve(byte[] ledgerId);
    }

    /** An alg + public key pair used to verify one ledger's consume-receipt signatures. */
    public static final class LedgerVerifierKey {
        public final int alg;
        public final byte[] pk;

        public LedgerVerifierKey(int alg, byte[] pk) {
            this.alg = alg;
            this.pk = pk;
        }
    }

    /** The non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content id received TWO
     * conflicting ledger-signed consume receipts -- a double spend made provable on comparison. It
     * carries both receipts and both ledger signatures; because a verifier checks each signature under
     * the key its receipt names, the contradiction is authored by neither the requester nor a thief.
     * Both positions (and, cross-ledger, both ledger ids) are surfaced so the contradiction is legible
     * to a human and to tooling. */
    public static final class ConsumeForkEvidence {
        public final byte[] approvalId; // the one approval content id spent twice
        public final ConsumeReceipt a;  // first receipt
        public final byte[] sigA;       // ledger A's signature over a.bytes()
        public final ConsumeReceipt b;  // second receipt (same approval id; different position and/or ledger)
        public final byte[] sigB;       // ledger B's signature over b.bytes()

        public ConsumeForkEvidence(byte[] approvalId, ConsumeReceipt a, byte[] sigA, ConsumeReceipt b, byte[] sigB) {
            this.approvalId = approvalId.clone();
            this.a = a;
            this.sigA = sigA.clone();
            this.b = b;
            this.sigB = sigB.clone();
        }

        /** Checks that this is a genuine fork: (1) the disputed approval id is present and BOTH
         * receipts name it; (2) the two receipts actually conflict -- they are NOT byte-identical (a
         * byte-identical re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures
         * verify under the keys their receipts name, resolved through {@code resolve}. Any failure
         * throws (fail-closed): a mismatched/absent approval id or a byte-identical pair is
         * ConsumeForkInvalid, and an unnamed/unresolvable ledger or a signature that does not verify is
         * ConsumeReceiptUnsigned. Returning normally means the double spend is proven and non-repudiable. */
        public void verify(LedgerKeyResolver resolve) {
            if (approvalId.length == 0) {
                throw new NaalpException("ConsumeForkInvalid", "fork evidence does not prove a double spend");
            }
            if (!Arrays.equals(a.approvalId, approvalId) || !Arrays.equals(b.approvalId, approvalId)) {
                throw new NaalpException("ConsumeForkInvalid", "both receipts must name the one disputed approval id");
            }
            if (Arrays.equals(a.bytes(), b.bytes())) {
                throw new NaalpException("ConsumeForkInvalid", "byte-identical receipts are a benign duplicate, not a fork");
            }
            LedgerVerifierKey ka = resolve.resolve(a.ledger);
            if (ka == null || a.ledger.length == 0) {
                throw new NaalpException("ConsumeReceiptUnsigned", "ledger A is unnamed or unresolvable");
            }
            LedgerVerifierKey kb = resolve.resolve(b.ledger);
            if (kb == null || b.ledger.length == 0) {
                throw new NaalpException("ConsumeReceiptUnsigned", "ledger B is unnamed or unresolvable");
            }
            if (!Cose.coseVerify1Raw(ka.alg, ka.pk, a.bytes(), sigA) || !Cose.coseVerify1Raw(kb.alg, kb.pk, b.bytes(), sigB)) {
                throw new NaalpException("ConsumeReceiptUnsigned", "a ledger signature does not verify");
            }
        }
    }

    /** Thrown by {@link ReceiptSet#observe} when a previously-seen receipt for the same approval id
     * conflicts with the one just observed; carries the non-repudiable {@link ConsumeForkEvidence}.
     * NaalpException is {@code final} (cannot be subclassed), so this carries its own {@code kind}
     * field ("ConsumeFork") in the same shape for callers that pattern-match on error kind. */
    public static final class ConsumeForkDetected extends RuntimeException {
        public final String kind = "ConsumeFork";
        public final ConsumeForkEvidence evidence;

        public ConsumeForkDetected(ConsumeForkEvidence evidence) {
            super("ConsumeFork: two ledger-signed receipts contradict on one approval id");
            this.evidence = evidence;
        }
    }

    /** Observes ledger-signed consume receipts, keyed by approval content id, and detects a fork (a
     * double spend) from the signed receipts alone (T1.5, NAALP-REQ-121) -- the consume-layer analogue
     * of an auditor's equivocation detection. It resolves each receipt's ledger verifier through
     * {@code resolve}, rejects any receipt whose ledger signature does not verify, and on a conflicting
     * second receipt for one approval id mints a non-repudiable {@link ConsumeForkEvidence}. */
    public static final class ReceiptSet {
        private final ReentrantLock lock = new ReentrantLock();
        private final LedgerKeyResolver resolve;
        private final Map<String, SeenReceipt> seen = new HashMap<>(); // approval-id hex -> first receipt seen

        private static final class SeenReceipt {
            final ConsumeReceipt r;
            final byte[] sig;

            SeenReceipt(ConsumeReceipt r, byte[] sig) {
                this.r = r;
                this.sig = sig;
            }
        }

        /** Makes a fork detector that resolves a ledger id to its verifier via {@code resolve} (which
         * returns null for an unknown ledger id). */
        public ReceiptSet(LedgerKeyResolver resolve) {
            this.resolve = resolve;
        }

        /** Port-naming parity with the Go/Rust top-level constructor {@code NewReceiptSet}. */
        public static ReceiptSet newReceiptSet(LedgerKeyResolver resolve) {
            return new ReceiptSet(resolve);
        }

        /** Records a ledger-signed consume receipt. Returns quietly (no evidence recorded) for a brand
         * new receipt or a benign byte-identical duplicate. Throws ConsumeReceiptUnsigned (fail-closed)
         * if the ledger is unnamed/unresolvable or the signature does not verify. Throws
         * {@link ConsumeForkDetected} -- carrying the non-repudiable evidence -- when a previously-seen
         * receipt for the same approval id conflicts (a different position and/or ledger). */
        public void observe(ConsumeReceipt r, byte[] sig) {
            lock.lock();
            try {
                LedgerVerifierKey k = resolve.resolve(r.ledger);
                if (k == null || r.ledger.length == 0 || !Cose.coseVerify1Raw(k.alg, k.pk, r.bytes(), sig)) {
                    throw new NaalpException("ConsumeReceiptUnsigned",
                            "receipt ledger is unnamed/unresolvable or its signature does not verify");
                }
                String key = Hex.encode(r.approvalId);
                SeenReceipt prev = seen.get(key);
                if (prev != null) {
                    if (Arrays.equals(prev.r.bytes(), r.bytes())) {
                        return; // benign byte-identical duplicate
                    }
                    throw new ConsumeForkDetected(new ConsumeForkEvidence(r.approvalId, prev.r, prev.sig, r, sig));
                }
                seen.put(key, new SeenReceipt(r, sig.clone()));
            } finally {
                lock.unlock();
            }
        }
    }

    // ---- R-TDCS-3 (design.md §25, C22) the party-visible coarse refusal object --------------------
    //
    // A refusal returned to the authenticated party carries ONLY a single value from a closed
    // vocabulary and the content id of the full signed record that carries the discriminating detail
    // -- a reference, not the reason. The detail exists, is signed, and is auditor-resolvable through
    // the record channel, but never reaches the adversary-facing surface, so repeated refusals cannot
    // serve an adaptive party as an oracle. A party-visible refusal that carries discriminating detail,
    // or omits the record content id, is a RefusalDetailLeak; an outcome outside the closed set is
    // UnknownRefusalOutcome.

    public static final long REFUSAL_DENIED = 0;       // the action is refused
    public static final long REFUSAL_HELD = 1;         // the action requires a further step not yet taken
    public static final long REFUSAL_UNVERIFIABLE = 2; // required evidence did not verify

    /** Reports whether {@code code} is in the closed refusal-outcome set. */
    public static boolean isKnownRefusalOutcome(long code) {
        return code == REFUSAL_DENIED || code == REFUSAL_HELD || code == REFUSAL_UNVERIFIABLE;
    }

    /** The party-visible coarse refusal body {1: outcome, 2: record}. {@code outcome} is the closed-set
     * coarse outcome; {@code record} is the T1 content id of the full signed record carrying the detail. */
    public static final class Refusal {
        public final long outcome;
        public final byte[] record;

        public Refusal(long outcome, byte[] record) {
            this.outcome = outcome;
            this.record = record.clone();
        }

        /** Deterministic-CBOR encoding {1: outcome, 2: record}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(outcome)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(record)))));
        }
    }

    /** Builds the party-visible refusal for a full signed record: it carries the coarse outcome and
     * the content id of {@code fullRecord}, and NOTHING drawn from inside {@code fullRecord} -- the
     * discriminating detail stays in the record, referenced only by its id. This is the coarse-to-party
     * split the closure property requires (R-TDCS-3). */
    public static Refusal refusalFromRecord(long outcome, byte[] fullRecord) {
        return new Refusal(outcome, Cbor.contentId(fullRecord));
    }

    /** Reconstructs a Refusal from its body bytes, enforcing that a party-visible refusal carries ONLY
     * {outcome, record} and nothing more (R-TDCS-3). It throws, fail-closed: a malformed body, any key
     * other than 1 and 2, a missing or empty record id (RefusalDetailLeak -- discriminating detail
     * leaked, or the auditor reference dropped), and an outcome outside the closed set
     * (UnknownRefusalOutcome). It authorizes nothing. */
    public static Refusal parseRefusal(byte[] b) {
        Cbor.Value v;
        try {
            v = Cbor.decode(b);
        } catch (NaalpException e) {
            throw new NaalpException("RefusalDetailLeak", "malformed refusal body");
        }
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("RefusalDetailLeak", "refusal body is not a map");
        }
        Long outcome = null;
        byte[] record = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) {
                throw new NaalpException("RefusalDetailLeak", "non-uint refusal key");
            }
            long k = ku.v;
            if (k == 1 && p.val instanceof Cbor.U u) {
                outcome = u.v;
            } else if (k == 2 && p.val instanceof Cbor.B bs) {
                record = bs.v;
            } else {
                throw new NaalpException("RefusalDetailLeak", "any field beyond {1,2} is leaked detail");
            }
        }
        if (outcome == null || record == null || record.length == 0) {
            throw new NaalpException("RefusalDetailLeak", "a refusal must carry the full-record content id");
        }
        if (!isKnownRefusalOutcome(outcome)) {
            throw new NaalpException("UnknownRefusalOutcome",
                    "refusal outcome is outside the closed set denied/held/unverifiable");
        }
        return new Refusal(outcome, record);
    }
}
