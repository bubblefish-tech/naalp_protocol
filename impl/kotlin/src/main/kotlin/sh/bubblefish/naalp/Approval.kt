// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.EOFException
import java.io.RandomAccessFile
import java.security.MessageDigest

//
// C6 approval object + durable single-use consume ledger for the Kotlin SDK (design.md §7;
// R-7.1..7.4).
//
// An ApprovalRecord binds, under signature, the content id of the exact canonical argument object it
// approves (§7.1); because the args are named by content id, mutating any argument changes the id and
// the approval no longer matches (ApprovalMismatch). The consume ledger is a durable compare-and-set
// set keyed by approval content id: the FIRST consumer of an id wins and every later consume of the
// same id is rejected AlreadyConsumed (§7.2). Atomicity is honest, not decorative — the membership
// check AND the append run inside ONE lock-held critical section (the single-writer discipline, as
// the Go single mutex), so there is no read-then-write TOCTOU window and a race spends an approval
// exactly once. Each winning consume is written and fsynced to the write-ahead log before it returns
// (persist-before-ack). A held outcome is a distinct signed non-success result (HeldResult, §7.4).
// Every rejection is fail-closed and causes no ledger append.
//
// Ported from impl/go/approval (cross-read against impl/python/naalp/approval.py). The approval
// SIGNATURE is a RAW deterministic ML-DSA-65 signature over the body bytes directly (Cose.mldsaSign
// / Cose.mldsaVerify), exactly as the reference cose.Signer/Verifier sign the body — there is NO COSE
// Sig_structure wrapping here. The record/entry bodies are graded against vectors/approval/cases.json.
//
// T1.5 (NAALP-REQ-121, design.md §7.5) — the ledger-signed ConsumeReceipt / ConsumeForkEvidence /
// ReceiptSet double-spend-evidence surface is PORTED below and graded against the independent
// vectors/consume_receipt/cases.json corpus (ApprovalKatTest.kt). The anti-double-spend counter
// (Position) rides under the CONSUMING LEDGER's signature, never the requester's, exactly as
// approval.go: Ledger.openLedgerSigned binds an ordering-authority identity + signing key,
// Ledger.consumeWithReceipt mints the receipt on the winning first-append-wins compare-and-set, and
// ReceiptSet.observe detects a fork (two conflicting ledger-signed receipts for one approval id) from
// the signed receipts alone. Kotlin port note (documented at ReceiptSet below): Go's simultaneous
// (evidence, error) return does not map onto Kotlin's exception idiom, so observe() returns null for
// "no fork" and the ConsumeForkEvidence for a genuine fork, while an unresolvable/unnamed ledger or a
// bad signature throws ConsumeReceiptUnsigned.
//
// design §25 (C22, R-TDCS) — three trust-decision closure-sovereignty surfaces are also ported: the
// R-TDCS-5 OPTIONAL audience binding on ApprovalRecord + verifyAudience; the R-TDCS-3 party-visible
// coarse Refusal object (refusalFromRecord/parseRefusal/isKnownRefusalOutcome) that never leaks the
// full record's discriminating detail; and R-TDCS-4 verifyFreshIndependent, which composes
// verifyApproval + verifyConsumeReceipt and rejects FreshnessSelfAsserted when the ordering authority
// IS the authenticated party. Graded against vectors/trust_decision/cases.json.
//
object Approval {

    // The width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.
    const val HEAD_SIZE = 48

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    private fun chainNext(entryBytes: ByteArray): ByteArray = sha384(entryBytes)

    // ---- §7.1 the approval object body ----

    // The body of an Approval object (§7.1). Signed over its deterministic-CBOR bytes. `approves` is
    // the content id of the exact canonical args object; a changed argument changes the id and the
    // approval no longer matches (ApprovalMismatch).
    class ApprovalRecord(
        approves: ByteArray,
        val approver: String,
        val grant: Long,
        nonce: ByteArray,
        val notAfter: Long,
        // R-TDCS-5 (design.md §25) OPTIONAL valid-context; "" == absent (field 6 omitted, unrestricted).
        val audience: String = "",
    ) {
        // content id of the exact canonical args object (§7.1).
        val approves: ByteArray = approves.copyOf()

        // anti-replay nonce (§7.3).
        val nonce: ByteArray = nonce.copyOf()

        // Deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6 is OMITTED
        // when audience is "" -- an empty string is not a distinct value, so an approval that names no
        // audience encodes byte-identically to a 5-field approval (R-TDCS-5, additive by design;
        // matches Go ApprovalRecord.Bytes()). The audience-absent case reuses the spine Records
        // builder so it stays byte-identical to the pre-existing 5-field encoding.
        fun bytes(): ByteArray {
            if (audience.isEmpty()) return Records.approvalBody(approves, approver, grant, nonce, notAfter)
            return Cbor.encode(
                Cbor.M(
                    listOf(
                        Cbor.Pair(Cbor.U(1), Cbor.B(approves)),
                        Cbor.Pair(Cbor.U(2), Cbor.T(approver)),
                        Cbor.Pair(Cbor.U(3), Cbor.U(grant)),
                        Cbor.Pair(Cbor.U(4), Cbor.B(nonce)),
                        Cbor.Pair(Cbor.U(5), Cbor.U(notAfter)),
                        Cbor.Pair(Cbor.U(6), Cbor.T(audience)),
                    )
                )
            )
        }

        // The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets).
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    // Sign the approval body with a real deterministic ML-DSA key derived from seed. The signed input
    // is the body bytes DIRECTLY (matching the reference cose.Signer.Sign: raw message, rnd=0).
    fun signApproval(a: ApprovalRecord, alg: Int, seed: ByteArray): ByteArray = Cose.mldsaSign(alg, seed, a.bytes())

    // Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact
    // args by content id, (3) not expired at posTime. Returns normally only if all three hold;
    // otherwise throws the specific named error and authorizes nothing. Check order is fail-closed:
    // BadSignature -> ApprovalMismatch -> ApprovalExpired. It does NOT consume — consumption is the
    // separate atomic ledger step (§7.2). A garbage/empty signature is BadSignature, never a crash.
    fun verifyApproval(a: ApprovalRecord, alg: Int, pubkey: ByteArray, sig: ByteArray, argsContentId: ByteArray, posTime: Long) {
        val ok = try {
            Cose.coseVerify1Raw(alg, pubkey, a.bytes(), sig)
        } catch (e: Exception) {
            false // a malformed/empty signature, or an alg this port does not verify, is a rejection (fail-closed)
        }
        if (!ok) {
            throw NaalpException("BadSignature", "approval signature does not verify")
        }
        if (!a.approves.contentEquals(argsContentId)) {
            throw NaalpException("ApprovalMismatch", "approval does not bind these arguments' content id")
        }
        if (posTime > a.notAfter) {
            throw NaalpException("ApprovalExpired", "approval is past its not_after")
        }
    }

    // ---- the composed, single-call consume choke point (draft "## Approval state machine") ----

    // The composed, single-call consume choke point for the approval state machine (draft "## Approval
    // state machine"). It runs the table's precedence in ONE impl-owned place -- the exact sequence
    // that payment.AuthorizeCharge and the mcp/agui/delegation callers each hand-assemble -- so a
    // caller (and the conformance suite) drives one realization of the reactions rather than
    // re-deriving the ordering at each call site. Mirrors Go approval.ConsumeApproval / Rust
    // consume_approval:
    //
    //  1. verifyApproval checks the signature, then the args-content-id binding (ApprovalMismatch,
    //     which the draft says "takes precedence over every cell"), then expiry (ApprovalExpired) --
    //     all BEFORE the ledger is consulted. So a request both past notAfter AND already in the
    //     ledger is refused ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume
    //     rule), and the ledger is left untouched by the rejected request.
    //  2. The granted effect must be a valid class (0..3) and must cover the action's required effect;
    //     a grant outside the closed vocabulary, or one below the required effect, authorizes nothing
    //     and is refused ApprovalRequired (fail-closed; the grant-range guard is stricter than the raw
    //     callers).
    //  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
    //     second throws AlreadyConsumed, and neither a rejected earlier step nor a losing race appends.
    //
    // Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
    // returning the ledger entry. It does NOT enforce object audience -- that is consumeObject's
    // binding (design.md §2.5.3); consumeApproval is the args-content-id/effect/single-use choke point.
    fun consumeApproval(
        a: ApprovalRecord,
        alg: Int,
        pubkey: ByteArray,
        aSig: ByteArray,
        argsContentId: ByteArray,
        posTime: Long,
        requiredEffect: Long,
        ledger: Ledger,
        by: String,
    ): LedgerEntry {
        verifyApproval(a, alg, pubkey, aSig, argsContentId, posTime) // BadSignature / ApprovalMismatch / ApprovalExpired -- all before the ledger
        if (a.grant > Policy.DESTRUCTIVE) {
            throw NaalpException("ApprovalRequired", "action requires an approval that is not present") // a grant outside the closed 0..3 effect vocabulary authorizes nothing
        }
        if (!Policy.authorizes(a.grant, requiredEffect)) {
            throw NaalpException("ApprovalRequired", "action requires an approval that is not present") // the approval's granted effect does not cover this action
        }
        return ledger.consume(a.id(), by)
    }

    // ---- R-TDCS-5 (design.md §25) OPTIONAL audience binding ----

    // Enforce the OPTIONAL audience binding. An approval that NAMES an audience (a.audience != "") is
    // valid only in that context: a relying party checks it at use and throws AudienceMismatch on a
    // mismatch. An approval that names NO audience is unrestricted by the issuer's explicit choice and
    // passes for any use context -- a deployment MAY require an audience by local policy above this
    // check. The check is mandatory WHEN a context is present, never mandatory-presence (the JWT `aud`
    // present-optional / check-mandatory shape). Mirrors Go approval.VerifyAudience exactly.
    fun verifyAudience(a: ApprovalRecord, useContext: String) {
        if (a.audience.isNotEmpty() && a.audience != useContext) {
            throw NaalpException("AudienceMismatch", "approval names an audience other than the use context")
        }
    }

    // ---- §7.4 the held (not-yet-granted) outcome ----

    // The distinct, signed, non-success result returned when an action requires an approval that has
    // not been granted (§7.4). It is never a silent success or a silent denial.
    class HeldResult(approves: ByteArray, val reason: String) {
        val approves: ByteArray = approves.copyOf()

        // Deterministic-CBOR encoding {1: approves, 2: reason}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(approves)),
                    Cbor.Pair(Cbor.U(2), Cbor.T(reason)),
                )
            )
        )
    }

    // Sign a held result so the "not yet granted" outcome is itself attributable (real ML-DSA).
    fun signHeld(h: HeldResult, alg: Int, seed: ByteArray): ByteArray = Cose.mldsaSign(alg, seed, h.bytes())

    // ---- §7.2 the consume ledger entry ----

    // One append to the consume ledger (§7.2).
    class LedgerEntry(val seq: Long, prev: ByteArray, approvalId: ByteArray, val by: String) {
        // prior chain head (HEAD_SIZE bytes; genesis is all-zero).
        val prev: ByteArray = prev.copyOf()

        // the approval content id being consumed.
        val approvalId: ByteArray = approvalId.copyOf()

        // Deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by} (reuses the spine
        // Records builder). The head after this entry is SHA-384(bytes()).
        fun bytes(): ByteArray = Records.ledgerEntry(seq, prev, approvalId, by)

        // This entry's chain head — the prev of the next entry.
        fun head(): ByteArray = chainNext(bytes())
    }

    // Open (creating if needed) a WAL-backed consume ledger at path and replay any existing log to
    // rebuild the consumed set and chain head. A log that does not hash-chain cleanly is refused
    // (LedgerCorrupt) rather than trusted.
    fun openLedger(path: String, authority: String = ""): Ledger {
        val raf = RandomAccessFile(path, "rw")
        val l = Ledger(raf, authority)
        l.replay()
        return l
    }

    // Open (creating if needed) a WAL-backed ledger AND bind it to its own ordering-authority identity
    // (receiptLedgerId, the signer-id form of the ledger key) and signing key (alg/seed), so it can
    // produce ledger-signed consume receipts via consumeWithReceipt (design.md §7.5; T1.5,
    // NAALP-REQ-121). An empty receiptLedgerId is refused fail-closed (LedgerUnsigned): an unnamed
    // ordering authority cannot sign the anti-double-spend position, so consumeWithReceipt would have
    // nothing accountable to emit. Mirrors Go approval.OpenLedgerSigned.
    fun openLedgerSigned(path: String, receiptLedgerId: ByteArray, alg: Int, seed: ByteArray): Ledger {
        if (receiptLedgerId.isEmpty()) {
            throw NaalpException("LedgerUnsigned", "ledger was not opened with a signing key")
        }
        val raf = RandomAccessFile(path, "rw")
        val l = Ledger(raf, "", receiptLedgerId.copyOf(), alg, seed.copyOf())
        l.replay()
        return l
    }

    // The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through
    // consume() under a single lock (the single-writer discipline), and each winning consume is
    // written and fsynced to the WAL before it returns. Use openLedger() to construct one.
    class Ledger internal constructor(
        private val f: RandomAccessFile,
        // consuming-authority NAME (§2.5.3 audience target); identity only, NOT a signed-ledger id
        private val ledgerId: String = "",
        // T1.5 (NAALP-REQ-121): this ledger's own ordering-authority identity + signing key. Set only
        // by openLedgerSigned; null for a plain openLedger (which offers consume(), not
        // consumeWithReceipt()). Distinct from [ledgerId] above -- that is the §2.5.3 audience NAME
        // string; this is the T1.5 receipt-signing identity (bytes, may differ in encoding).
        private val receiptLedgerId: ByteArray? = null,
        private val receiptAlg: Int = 0,
        private val receiptSeed: ByteArray? = null,
    ) {
        private val lock = Any()
        private val consumed = HashMap<String, Long>() // approval-id hex -> seq
        private var headState: ByteArray = ByteArray(HEAD_SIZE) // current chain head (genesis is all-zero)
        private var seqState: Long = 0 // next sequence number

        // Read the WAL from the start, rebuilding state and verifying the chain. Each record is
        // length-prefixed (uint32 big-endian) so the log is self-framing. An out-of-order seq or a
        // broken prev linkage is refused LedgerCorrupt.
        internal fun replay() {
            synchronized(lock) {
                f.seek(0)
                var head = ByteArray(HEAD_SIZE)
                var seq = 0L
                val lenBuf = ByteArray(4)
                while (true) {
                    val n0 = f.read(lenBuf)
                    if (n0 == -1) break
                    if (n0 != 4) throw NaalpException("LedgerCorrupt", "truncated length prefix")
                    val n = ((lenBuf[0].toInt() and 0xFF) shl 24) or
                        ((lenBuf[1].toInt() and 0xFF) shl 16) or
                        ((lenBuf[2].toInt() and 0xFF) shl 8) or
                        (lenBuf[3].toInt() and 0xFF)
                    val rec = ByteArray(n)
                    try {
                        f.readFully(rec)
                    } catch (e: EOFException) {
                        throw NaalpException("LedgerCorrupt", "truncated record")
                    }
                    val e = parseEntry(rec)
                    if (e.seq != seq || !e.prev.contentEquals(head)) {
                        throw NaalpException("LedgerCorrupt", "out-of-order seq or broken chain linkage")
                    }
                    consumed[Hex.encode(e.approvalId)] = e.seq
                    head = chainNext(rec)
                    seq++
                }
                headState = head
                seqState = seq
            }
        }

        // Atomically consume an approval id exactly once (§7.2). The first caller for a given id
        // appends a ledger entry (written and fsynced before returning) and returns it; every later
        // caller for the same id throws AlreadyConsumed with no append. The single lock serialises the
        // compare-and-set, so under a race exactly one caller wins.
        fun consume(approvalId: ByteArray, by: String): LedgerEntry {
            synchronized(lock) {
                val key = Hex.encode(approvalId)
                if (consumed.containsKey(key)) {
                    throw NaalpException("AlreadyConsumed", "approval already consumed")
                }
                val e = LedgerEntry(seqState, headState, approvalId, by)
                val rec = e.bytes()
                val framed = ByteArray(4 + rec.size)
                framed[0] = (rec.size ushr 24).toByte()
                framed[1] = (rec.size ushr 16).toByte()
                framed[2] = (rec.size ushr 8).toByte()
                framed[3] = rec.size.toByte()
                System.arraycopy(rec, 0, framed, 4, rec.size)
                f.seek(f.length())
                f.write(framed)
                f.fd.sync() // persist-before-ack (R-7.2 durability)
                consumed[key] = e.seq
                headState = e.head()
                seqState++
                return e
            }
        }

        // T1.5 (NAALP-REQ-121, design.md §7.5): perform the SAME first-append-wins compare-and-set as
        // consume() AND, on the winning append, return a ledger-signed ConsumeReceipt binding the
        // approval id to the entry's forward-only position (its ledger seq). Requires openLedgerSigned
        // (a plain ledger throws LedgerUnsigned, fail-closed). A second consume of the same approval id
        // throws AlreadyConsumed and signs nothing -- the first receipt stands (first-append-wins). The
        // receipt is signed BEFORE the WAL write, so a signing failure records nothing. The single lock
        // serialises concurrent callers, so under a race exactly one wins and exactly one receipt is
        // minted. Mirrors Go approval.Ledger.ConsumeWithReceipt.
        fun consumeWithReceipt(approvalId: ByteArray, by: String): Triple<LedgerEntry, ConsumeReceipt, ByteArray> {
            synchronized(lock) {
                val rid = receiptLedgerId
                val seed = receiptSeed
                if (rid == null || seed == null) {
                    throw NaalpException("LedgerUnsigned", "ledger was not opened with a signing key")
                }
                val key = Hex.encode(approvalId)
                if (consumed.containsKey(key)) {
                    // first-append-wins: the first receipt stands, no second receipt is minted.
                    throw NaalpException("AlreadyConsumed", "approval already consumed")
                }
                val e = LedgerEntry(seqState, headState, approvalId, by)
                // the receipt binds the approval id to THIS consume's forward-only position (the entry
                // seq), signed by the ledger key. Sign BEFORE touching the WAL so a signing failure
                // records nothing.
                val receipt = ConsumeReceipt(rid, approvalId, e.seq)
                val sig = Cose.mldsaSign(receiptAlg, seed, receipt.bytes())
                val rec = e.bytes()
                val framed = ByteArray(4 + rec.size)
                framed[0] = (rec.size ushr 24).toByte()
                framed[1] = (rec.size ushr 16).toByte()
                framed[2] = (rec.size ushr 8).toByte()
                framed[3] = rec.size.toByte()
                System.arraycopy(rec, 0, framed, 4, rec.size)
                f.seek(f.length())
                f.write(framed)
                f.fd.sync() // persist-before-ack (R-7.2 durability)
                consumed[key] = e.seq
                headState = e.head()
                seqState++
                return Triple(e, receipt, sig)
            }
        }

        // Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at the
        // choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's
        // consuming authority, or the object is rejected WrongAudience with no ledger append. An unnamed
        // ledger (no authority) refuses LedgerUnsigned -- it cannot be the audience of any object. The
        // audience check is NEVER inside Envelope.verify (a relay/auditor legitimately verifies objects
        // addressed to others). Mirrors Go/Rust Ledger.ConsumeObject -- the authority is this port's NAME.
        fun consumeObject(o: Envelope.Object, approvalId: ByteArray, by: String): LedgerEntry {
            if (ledgerId.isEmpty()) throw NaalpException("LedgerUnsigned", "ledger has no consuming authority")
            // fail-closed, before the CAS: throws NaalpException("WrongAudience") and appends nothing
            Envelope.checkAudience(o, ledgerId, true)
            return consume(approvalId, by)
        }

        // Whether an approval id has been consumed.
        fun isConsumed(approvalId: ByteArray): Boolean {
            synchronized(lock) {
                return consumed.containsKey(Hex.encode(approvalId))
            }
        }

        // The current chain head (a copy).
        fun head(): ByteArray {
            synchronized(lock) {
                return headState.copyOf()
            }
        }

        // The number of consumed approvals.
        fun size(): Int {
            synchronized(lock) {
                return consumed.size
            }
        }

        // Alias for size() -- kept as a distinct name matching Go's Ledger.Len for cross-port symbol
        // parity (the extractor indexes this literal name; size() is the pre-existing implementation).
        fun len(): Int = size()

        // Flush and close the WAL file.
        fun close() {
            synchronized(lock) {
                f.close()
            }
        }
    }

    // ---- T1.5 (NAALP-REQ-121, design.md §7.5) ledger-signed consume receipt ----

    // The draft-01 (T1.5, NAALP-REQ-121) ledger-signed evidence that a consuming ledger -- the
    // ORDERING AUTHORITY -- bound an approval content id to its own forward-only position. The
    // anti-double-spend counter (position) rides under the LEDGER's signature, never the requester's:
    // the requester cannot forge the ledger's position or its signature. A partition that spends one
    // approval twice therefore leaves two ledger-signed receipts against one approval id, each carrying
    // a position drawn from forked state -- a contradiction authored by neither the requester nor a
    // thief, provable the instant the two receipts are compared (see ConsumeForkEvidence). It does not
    // PREVENT the second spend; it makes the double-spend detectable in bytes neither party could
    // repudiate. Mirrors Go approval.ConsumeReceipt exactly.
    class ConsumeReceipt(ledger: ByteArray, approvalId: ByteArray, val position: Long) {
        // the consuming ledger's signer id (the ordering authority; REQ-121).
        val ledger: ByteArray = ledger.copyOf()

        // the approval content id consumed (the compare-and-set key).
        val approvalId: ByteArray = approvalId.copyOf()

        // Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position} --
        // the exact bytes the ledger signs (T1.5). position is carried as the full uint64 bit pattern
        // (Cbor.U), so a value up to 2^64-1 round-trips exactly.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(ledger)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(approvalId)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(position)),
                )
            )
        )
    }

    // Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is under
    // the ordering authority's signature). The signed input is the receipt bytes() directly (RAW, no
    // COSE Sig_structure wrapping -- same convention as signApproval).
    fun signConsumeReceipt(r: ConsumeReceipt, alg: Int, seed: ByteArray): ByteArray = Cose.mldsaSign(alg, seed, r.bytes())

    // Check that a consume receipt is a valid ledger-signed statement: the ledger id is present (an
    // unnamed ordering authority is not evidence) and the signature verifies under the ledger's key.
    // Fail-closed: either fault throws ConsumeReceiptUnsigned and authorizes nothing. (alg, pubkey)
    // MUST be the verifier resolved for r.ledger. Mirrors Go approval.VerifyConsumeReceipt.
    fun verifyConsumeReceipt(r: ConsumeReceipt, alg: Int, pubkey: ByteArray, sig: ByteArray) {
        if (r.ledger.isEmpty()) {
            throw NaalpException("ConsumeReceiptUnsigned", "an unnamed ordering authority is not evidence")
        }
        val ok = try {
            Cose.mldsaVerify(alg, pubkey, r.bytes(), sig)
        } catch (e: Exception) {
            false // a malformed/empty signature is not a verification, it is a rejection (fail-closed)
        }
        if (!ok) {
            throw NaalpException("ConsumeReceiptUnsigned", "ledger signature does not verify")
        }
    }

    // R-TDCS-4 (design.md §25) -- the ordering authority that stamps a credential's present-moment
    // position MUST be structurally distinct from the party whose credential's freshness is being
    // judged. A receipt whose ordering authority (r.ledger) IS the authenticated party is that party
    // asserting its own freshness -- the exact self-reference the closure property forbids -- and is
    // rejected FreshnessSelfAsserted, authorizing nothing.
    //
    // Judges an approval's present-moment validity using time drawn from an ordering authority
    // STRUCTURALLY DISTINCT from the party being authenticated. It is the named realization of the
    // §18.2 seam -- "validity judged on the ordering position, never the signer's clock" -- composing
    // verifyApproval + verifyConsumeReceipt and adding the distinctness check a relying party runs so a
    // party can never be the source of the time against which its own credential's expiry is judged.
    // It (1) verifies the approval binds argsContentId, is signed by the approver, and is unexpired at
    // posTime, where posTime is the ORDERING AUTHORITY's forward-only position (never a clock the
    // approver supplies); (2) verifies the consume receipt is ledger-signed (the position rides under
    // the ordering authority's key, never the requester's); and (3) rejects FreshnessSelfAsserted when
    // the ordering authority r.ledger IS the authenticated party partyId. Fail-closed: any fault throws
    // its named error and authorizes nothing. Mirrors Go approval.VerifyFreshIndependent.
    fun verifyFreshIndependent(
        a: ApprovalRecord, approverAlg: Int, approverPk: ByteArray, aSig: ByteArray, argsContentId: ByteArray, posTime: Long,
        r: ConsumeReceipt, ledgerAlg: Int, ledgerPk: ByteArray, rSig: ByteArray, partyId: ByteArray,
    ) {
        verifyApproval(a, approverAlg, approverPk, aSig, argsContentId, posTime)
        verifyConsumeReceipt(r, ledgerAlg, ledgerPk, rSig)
        if (r.ledger.contentEquals(partyId)) {
            throw NaalpException("FreshnessSelfAsserted", "the ordering authority that stamps freshness is the authenticated party itself")
        }
    }

    // The non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content id received TWO
    // conflicting ledger-signed consume receipts -- a double spend made provable on comparison. It
    // carries both receipts and both ledger signatures; because a verifier checks each signature under
    // the key its receipt names, the contradiction is authored by neither the requester nor a thief.
    // Both positions (and, cross-ledger, both ledger ids) are surfaced so the contradiction is legible
    // to a human and to tooling. Mirrors Go approval.ConsumeForkEvidence.
    class ConsumeForkEvidence(
        approvalId: ByteArray,
        val a: ConsumeReceipt, val sigA: ByteArray,
        val b: ConsumeReceipt, val sigB: ByteArray,
    ) {
        // the one approval content id spent twice.
        val approvalId: ByteArray = approvalId.copyOf()

        // Check that this is a genuine fork: (1) the disputed approval id is present and BOTH receipts
        // name it; (2) the two receipts actually conflict -- they are NOT byte-identical (a
        // byte-identical re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures
        // verify under the keys their receipts name, resolved through [resolve] (approval id ->
        // (alg, pubkey), or null if unresolvable). Any failure rejects the whole thing (fail-closed): a
        // mismatched/absent approval id or a byte-identical pair throws ConsumeForkInvalid, and an
        // unnamed/unresolvable ledger or a signature that does not verify throws
        // ConsumeReceiptUnsigned. Returns normally only on a clean, non-repudiable double-spend proof.
        fun verify(resolve: (ByteArray) -> kotlin.Pair<Int, ByteArray>?) {
            if (approvalId.isEmpty()) {
                throw NaalpException("ConsumeForkInvalid", "fork evidence does not prove a double spend")
            }
            if (!a.approvalId.contentEquals(approvalId) || !b.approvalId.contentEquals(approvalId)) {
                throw NaalpException("ConsumeForkInvalid", "both receipts must name the one disputed approval id")
            }
            if (a.bytes().contentEquals(b.bytes())) {
                throw NaalpException("ConsumeForkInvalid", "byte-identical receipts are a benign duplicate, not a fork")
            }
            if (a.ledger.isEmpty()) throw NaalpException("ConsumeReceiptUnsigned", "ledger a is unnamed")
            val (algA, pkA) = resolve(a.ledger) ?: throw NaalpException("ConsumeReceiptUnsigned", "ledger a is unresolvable")
            if (b.ledger.isEmpty()) throw NaalpException("ConsumeReceiptUnsigned", "ledger b is unnamed")
            val (algB, pkB) = resolve(b.ledger) ?: throw NaalpException("ConsumeReceiptUnsigned", "ledger b is unresolvable")
            val okA = try { Cose.mldsaVerify(algA, pkA, a.bytes(), sigA) } catch (e: Exception) { false }
            val okB = try { Cose.mldsaVerify(algB, pkB, b.bytes(), sigB) } catch (e: Exception) { false }
            if (!okA || !okB) throw NaalpException("ConsumeReceiptUnsigned", "ledger signature does not verify")
        }
    }

    // Detects a fork (a double spend) from ledger-signed consume receipts alone, keyed by approval
    // content id (T1.5, NAALP-REQ-121) -- the consume-layer analogue of the audit auditor's
    // equivocation detection. It resolves each receipt's ledger to (alg, pubkey) through [resolve],
    // rejects any receipt whose ledger signature does not verify, and on a conflicting second receipt
    // for one approval id mints a non-repudiable ConsumeForkEvidence.
    //
    // Kotlin port note: Go's ReceiptSet.Observe returns (*ConsumeForkEvidence, error) simultaneously --
    // that pairing does not map onto Kotlin's exception idiom, so here [observe] carries the fork/
    // no-fork axis on its RETURN VALUE (null = no fork -- a fresh receipt or a benign byte-identical
    // duplicate; non-null = a genuine fork, never an exception) and the verify-failure axis on a thrown
    // ConsumeReceiptUnsigned (an unresolvable/unnamed ledger, or a signature that fails to verify).
    class ReceiptSet(private val resolve: (ByteArray) -> kotlin.Pair<Int, ByteArray>?) {
        private val lock = Any()
        private val seen = HashMap<String, kotlin.Pair<ConsumeReceipt, ByteArray>>() // approval-id hex -> first receipt seen

        // Record a ledger-signed consume receipt. Throws ConsumeReceiptUnsigned if the ledger is
        // unnamed/unresolvable or the signature does not verify; returns a non-null ConsumeForkEvidence
        // when a previously-seen receipt for the same approval id conflicts (different position and/or
        // ledger); and null otherwise (including a benign byte-identical duplicate).
        fun observe(r: ConsumeReceipt, sig: ByteArray): ConsumeForkEvidence? {
            synchronized(lock) {
                if (r.ledger.isEmpty()) throw NaalpException("ConsumeReceiptUnsigned", "ledger is unnamed")
                val (alg, pk) = resolve(r.ledger) ?: throw NaalpException("ConsumeReceiptUnsigned", "ledger is unresolvable")
                val ok = try { Cose.mldsaVerify(alg, pk, r.bytes(), sig) } catch (e: Exception) { false }
                if (!ok) throw NaalpException("ConsumeReceiptUnsigned", "ledger signature does not verify")
                val key = Hex.encode(r.approvalId)
                val prev = seen[key]
                if (prev != null) {
                    if (prev.first.bytes().contentEquals(r.bytes())) return null // benign byte-identical duplicate
                    return ConsumeForkEvidence(r.approvalId, prev.first, prev.second, r, sig.copyOf())
                }
                seen[key] = kotlin.Pair(r, sig.copyOf())
                return null
            }
        }
    }

    // Make a fork detector that resolves a ledger id to (alg, pubkey) via resolve (which returns null
    // for an unknown ledger id). A distinct factory function alongside the ReceiptSet constructor,
    // matching Go's NewReceiptSet for cross-port symbol parity.
    fun newReceiptSet(resolve: (ByteArray) -> kotlin.Pair<Int, ByteArray>?): ReceiptSet = ReceiptSet(resolve)

    // ---- R-TDCS-3 (design.md §25, C22) party-visible coarse refusal object ----
    //
    // A refusal returned to the authenticated party carries ONLY a single value from a closed
    // vocabulary and the content id of the full signed record that carries the discriminating detail --
    // a reference, not the reason. The detail exists, is signed, and is auditor-resolvable through the
    // record channel, but never reaches the adversary-facing surface, so repeated refusals cannot serve
    // an adaptive party as an oracle. A party-visible refusal that carries discriminating detail, or
    // omits the record content id, is RefusalDetailLeak; an outcome outside the closed set is
    // UnknownRefusalOutcome. Mirrors Go approval/refusal.go exactly.

    const val REFUSAL_DENIED: Long = 0 // the action is refused
    const val REFUSAL_HELD: Long = 1 // the action requires a further step not yet taken
    const val REFUSAL_UNVERIFIABLE: Long = 2 // required evidence did not verify

    private val refusalOutcomeNames = mapOf(
        REFUSAL_DENIED to "denied", REFUSAL_HELD to "held", REFUSAL_UNVERIFIABLE to "unverifiable",
    )

    // Report whether code is in the closed refusal-outcome set.
    fun isKnownRefusalOutcome(code: Long): Boolean = refusalOutcomeNames.containsKey(code)

    // The party-visible coarse refusal body {1: outcome, 2: record}. outcome is the closed-set coarse
    // outcome; record is the T1 content id of the full signed record carrying the detail.
    class Refusal(val outcome: Long, record: ByteArray) {
        val record: ByteArray = record.copyOf()

        // Deterministic-CBOR encoding {1: outcome, 2: record}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.U(outcome)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(record)),
                )
            )
        )
    }

    // Build the party-visible refusal for a full signed record: it carries the coarse outcome and the
    // content id of fullRecord, and NOTHING drawn from inside fullRecord -- the discriminating detail
    // stays in the record, referenced only by its id. This is the coarse-to-party split the closure
    // property requires (R-TDCS-3).
    fun refusalFromRecord(outcome: Long, fullRecord: ByteArray): Refusal = Refusal(outcome, Cbor.contentId(fullRecord))

    // Reconstruct a Refusal from its body bytes, enforcing that a party-visible refusal carries ONLY
    // {outcome, record} and nothing more (R-TDCS-3). It rejects, fail-closed: a malformed body, any key
    // other than 1 and 2, a missing or empty record id (RefusalDetailLeak -- discriminating detail
    // leaked, or the auditor reference dropped), and an outcome outside the closed set
    // (UnknownRefusalOutcome). It authorizes nothing.
    fun parseRefusal(b: ByteArray): Refusal {
        val v = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("RefusalDetailLeak", "malformed refusal body")
        }
        if (v !is Cbor.M) throw NaalpException("RefusalDetailLeak", "refusal body is not a map")
        var outcome: Long? = null
        var record: ByteArray? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("RefusalDetailLeak", "non-uint refusal key")
            when (k.v) {
                1L -> {
                    val u = p.v as? Cbor.U ?: throw NaalpException("RefusalDetailLeak", "outcome not uint")
                    outcome = u.v
                }
                2L -> {
                    val bs = p.v as? Cbor.B ?: throw NaalpException("RefusalDetailLeak", "record not bstr")
                    record = bs.v
                }
                else -> throw NaalpException("RefusalDetailLeak", "any field beyond {1,2} is leaked detail")
            }
        }
        val oc = outcome ?: throw NaalpException("RefusalDetailLeak", "a refusal must carry an outcome")
        val rec = record ?: throw NaalpException("RefusalDetailLeak", "a refusal must carry the full-record content id")
        if (rec.isEmpty()) throw NaalpException("RefusalDetailLeak", "a refusal must carry the full-record content id")
        if (!isKnownRefusalOutcome(oc)) {
            throw NaalpException("UnknownRefusalOutcome", "refusal outcome is outside the closed set denied/held/unverifiable")
        }
        return Refusal(oc, rec)
    }

    // Decode a ledger entry from its deterministic-CBOR bytes. A malformed shape, a non-uint key, a
    // mistyped field, an unknown field, or a missing field is a corrupt log (LedgerCorrupt).
    private fun parseEntry(rec: ByteArray): LedgerEntry {
        val v = try {
            Cbor.decode(rec) // strict decoder: throws NonCanonical on a non-canonical body
        } catch (e: NaalpException) {
            throw NaalpException("LedgerCorrupt", "ledger entry is not canonical CBOR")
        }
        if (v !is Cbor.M) throw NaalpException("LedgerCorrupt", "ledger entry is not a map")
        var seq: Long? = null
        var prev: ByteArray? = null
        var aid: ByteArray? = null
        var by: String? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("LedgerCorrupt", "non-uint ledger entry key")
            when (k.v) {
                1L -> { val u = p.v; if (u !is Cbor.U) throw NaalpException("LedgerCorrupt", "seq not uint"); seq = u.v }
                2L -> { val b = p.v; if (b !is Cbor.B) throw NaalpException("LedgerCorrupt", "prev not bstr"); prev = b.v }
                3L -> { val b = p.v; if (b !is Cbor.B) throw NaalpException("LedgerCorrupt", "approval-id not bstr"); aid = b.v }
                4L -> { val t = p.v; if (t !is Cbor.T) throw NaalpException("LedgerCorrupt", "by not tstr"); by = t.v }
                else -> throw NaalpException("LedgerCorrupt", "unknown ledger entry key ${k.v}")
            }
        }
        if (seq == null || prev == null || aid == null || by == null) {
            throw NaalpException("LedgerCorrupt", "ledger entry missing a mandatory field")
        }
        return LedgerEntry(seq, prev, aid, by)
    }
}
