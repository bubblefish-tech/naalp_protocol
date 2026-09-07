// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

//
// C17 N-AALP-CONT flow continuation for the Kotlin SDK (design.md §20; R-CONT-1..7).
//
// N-AALP-CONT generalizes native streaming (one signed StreamOpen, cheap per-chunk data, one signed
// StreamCommit over a rolling digest) into a domain-agnostic flow:
//
//   - FlowOpen is the ONE full ML-DSA signature that fixes the flow's authority: its flow_id, its
//     effect ceiling, and the content-ids of the approvals that authorize it up to that ceiling. The
//     authority is reconstructable from the FlowOpen bytes ALONE (parseFlowOpen) — no session or
//     server state is needed to know what a continuation is allowed to do.
//   - Continuation is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link. Each
//     link's head is SHA-384(link body); its prev is the previous link's head; the genesis prev is
//     the FlowOpen's head, which anchors every link to THIS FlowOpen. A link carries its own effect,
//     which MUST stay at or below the ceiling (AboveCeiling otherwise — the cheap path can never
//     escalate past the one full signature + approval).
//   - Checkpoint lets a verifier confirm a contiguous prefix and DETECT A GAP (GapDetected).
//   - FlowCommit is a second full ML-DSA signature binding the whole ordered sequence with ONE
//     signature regardless of the number of continuations.
//
// A continuation replayed under a different FlowOpen fails: it carries the originating flow_open_id
// (WrongFlow) and its prev no longer chains to the other FlowOpen's head (ChainBroken). Domain
// separation is structural: FlowOpen (3 fields), Continuation (5 fields), Checkpoint (3 fields, a
// bstr head at 3), and FlowCommit (2 fields) are each a distinct deterministic-CBOR shape. Every
// check is fail-closed. Ported from impl/go/continuation (cross-read against
// impl/python/naalp/continuation.py); graded against vectors/continuation/cases.json. The FlowOpen /
// FlowCommit signatures are real deterministic ML-DSA-65 (COSE_Sign1) but not corpus-graded.
//
// The object is named [Cont] (not Continuation) so the cheap-link class can keep the spec name
// [Cont.Continuation].
//
object Cont {

    // The width of a chain head / prev link (SHA-384 = 48 bytes). A FlowOpen head anchors a flow's
    // continuation chain.
    const val HEAD_SIZE = 48

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    // Whether v is a value of the closed C5 effect lattice (0..3). An out-of-lattice value is rejected
    // RangeError, NEVER normalized to destructive — normalizing a CEILING to destructive would
    // silently make an out-of-range ceiling the MOST-permissive one (a fail-open).
    private fun inLattice(v: Long): Boolean = v in 0L..Policy.DESTRUCTIVE

    // ---- FlowOpen: the one full signature fixing the flow's authority (design.md §20.2) ----

    // Fixes a flow's identity, effect ceiling, and approval bindings. Signed with a full ML-DSA
    // signature (signFlowOpen); its authority is reconstructable from its bytes alone.
    class FlowOpen(flowId: ByteArray, val effectCeiling: Long, approvals: List<ByteArray>) {
        val flowId: ByteArray = flowId.copyOf()
        val approvals: List<ByteArray> = approvals.map { it.copyOf() }

        // Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(flowId)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(effectCeiling)),
                    Cbor.Pair(Cbor.U(3), Cbor.A(approvals.map { Cbor.B(it) })),
                )
            )
        )

        // The FlowOpen's SHA-384 head — the genesis prev that anchors the continuation chain.
        fun head(): ByteArray = sha384(bytes())

        // The FlowOpen's content-id — carried by every child object.
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    // Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An
    // out-of-lattice effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed
    // (ContMalformed) on any malformed shape.
    fun parseFlowOpen(b: ByteArray): FlowOpen {
        val m = decodeMap(b)
        val fid = bstrField(m, 1)
        val ceil = uintField(m, 2)
        val appsV = field(m, 3)
        if (fid == null || ceil == null || appsV == null || appsV !is Cbor.A) {
            throw NaalpException("ContMalformed", "object is not a well-formed FlowOpen body")
        }
        if (!inLattice(ceil)) {
            throw NaalpException("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
        }
        val apps = ArrayList<ByteArray>(appsV.items.size)
        for (e in appsV.items) {
            if (e !is Cbor.B) throw NaalpException("ContMalformed", "approval is not a bstr")
            apps.add(e.v)
        }
        return FlowOpen(fid, ceil, apps)
    }

    // ---- Continuation: the cheap hash-chain link (design.md §20.3) ----

    // One cheap link in a flow's chain. NOT individually signed; its authenticity derives from the
    // FlowOpen signature plus the hash chain plus the FlowCommit signature.
    class Continuation(flowOpenId: ByteArray, val seq: Long, val effect: Long, payloadId: ByteArray, prev: ByteArray) {
        val flowOpenId: ByteArray = flowOpenId.copyOf()
        val payloadId: ByteArray = payloadId.copyOf()
        val prev: ByteArray = prev.copyOf()

        // Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(flowOpenId)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(effect)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(payloadId)),
                    Cbor.Pair(Cbor.U(5), Cbor.B(prev)),
                )
            )
        )

        // This link's SHA-384 head — the prev of the next link.
        fun head(): ByteArray = sha384(bytes())
    }

    // The single audited decode path for untrusted Continuation wire bytes. Reconstructs the 5-field
    // body and range-checks the effect against the closed lattice (0..3): an out-of-lattice effect is
    // rejected RangeError, never carried as an unknown value. Fail-closed (ContMalformed).
    fun parseContinuation(b: ByteArray): Continuation {
        val m = decodeMap(b)
        val fid = bstrField(m, 1)
        val seq = uintField(m, 2)
        val effect = uintField(m, 3)
        val pid = bstrField(m, 4)
        val prev = bstrField(m, 5)
        if (fid == null || seq == null || effect == null || pid == null || prev == null) {
            throw NaalpException("ContMalformed", "object is not a well-formed Continuation body")
        }
        if (!inLattice(effect)) {
            throw NaalpException("RangeError", "effect is outside the closed 0..3 lattice")
        }
        return Continuation(fid, seq, effect, pid, prev)
    }

    // The CHEAP-path check of a single link against the flow's fixed authority: same flow (WrongFlow),
    // next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to the previous
    // head (ChainBroken). Performs no signature verification — that is what makes it cheap. Both the
    // ceiling and the link effect are closed effects; an out-of-lattice value is RangeError, never
    // normalized (fail-closed). Returns normally on success.
    fun verifyContinuation(c: Continuation, flowOpenId: ByteArray, prevHead: ByteArray, expectedSeq: Long, ceiling: Long) {
        if (!inLattice(ceiling)) throw NaalpException("RangeError", "ceiling is outside the closed 0..3 lattice")
        if (!inLattice(c.effect)) throw NaalpException("RangeError", "effect is outside the closed 0..3 lattice")
        if (!c.flowOpenId.contentEquals(flowOpenId)) throw NaalpException("WrongFlow", "object's flow_open_id does not match the FlowOpen")
        if (c.seq != expectedSeq) throw NaalpException("SeqGap", "continuation seq is not the next expected value")
        if (!Policy.authorizes(ceiling, c.effect)) throw NaalpException("AboveCeiling", "continuation effect exceeds the FlowOpen effect ceiling")
        if (!c.prev.contentEquals(prevHead)) throw NaalpException("ChainBroken", "continuation prev does not chain to the previous head")
    }

    // Verify a whole ordered continuation sequence starting from the FlowOpen and return the final
    // chain head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the one
    // full signature authorized.
    fun verifyChain(open: FlowOpen, conts: List<Continuation>): ByteArray {
        if (!inLattice(open.effectCeiling)) throw NaalpException("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
        val id = open.id()
        var prev = open.head()
        val ceiling = open.effectCeiling
        for ((i, c) in conts.withIndex()) {
            verifyContinuation(c, id, prev, i.toLong(), ceiling)
            prev = c.head()
        }
        return prev
    }

    // ---- Checkpoint: confirm a prefix, detect a gap (design.md §20.4) ----

    // Asserts the chain head after a contiguous prefix of continuations (seq 0..throughSeq).
    class Checkpoint(flowOpenId: ByteArray, val throughSeq: Long, head: ByteArray) {
        val flowOpenId: ByteArray = flowOpenId.copyOf()
        val head: ByteArray = head.copyOf()

        // Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(flowOpenId)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(throughSeq)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(head)),
                )
            )
        )
    }

    // The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body (field 3 a
    // bstr head). A 2-field FlowCommit look-alike is rejected here (missing field 3). Fail-closed
    // (ContMalformed).
    fun parseCheckpoint(b: ByteArray): Checkpoint {
        val m = decodeMap(b)
        val fid = bstrField(m, 1)
        val through = uintField(m, 2)
        val h = bstrField(m, 3)
        if (fid == null || through == null || h == null) {
            throw NaalpException("ContMalformed", "object is not a well-formed Checkpoint body")
        }
        return Checkpoint(fid, through, h)
    }

    // Confirm the prefix is exactly the contiguous sequence seq 0..through_seq and that its recomputed
    // head matches the checkpoint. A dropped or reordered link — a missing seq, a broken prev, or the
    // wrong count — is reported GapDetected. Returns normally on a clean confirmation.
    fun verifyCheckpoint(cp: Checkpoint, open: FlowOpen, prefix: List<Continuation>) {
        if (!cp.flowOpenId.contentEquals(open.id())) {
            throw NaalpException("WrongFlow", "checkpoint flow_open_id does not match the FlowOpen")
        }
        // through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq ==
        // u64::MAX (the all-ones Long, -1L) that addition would wrap and false-accept an EMPTY prefix
        // as covering the whole counter space — reject it as a gap instead (no MAX+1 contiguous links).
        if (cp.throughSeq == -1L) {
            throw NaalpException("GapDetected", "through_seq at u64::MAX admits no contiguous prefix")
        }
        if (prefix.size.toLong() != cp.throughSeq + 1) {
            throw NaalpException("GapDetected", "wrong count: a link is missing or extra")
        }
        val h = try {
            verifyChain(open, prefix)
        } catch (e: NaalpException) {
            throw NaalpException("GapDetected", "a seq/prev break inside the prefix is a gap")
        }
        if (!cp.head.contentEquals(h)) {
            throw NaalpException("GapDetected", "recomputed prefix head does not match the checkpoint")
        }
    }

    // ---- FlowCommit: the second full signature binding the whole sequence (design.md §20.5) ----

    // Binds a completed flow's final chain head under one full ML-DSA signature.
    class FlowCommit(flowOpenId: ByteArray, finalHead: ByteArray) {
        val flowOpenId: ByteArray = flowOpenId.copyOf()
        val finalHead: ByteArray = finalHead.copyOf()

        // Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} — the 2-field shape that
        // distinguishes it from the 3-field Checkpoint.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(flowOpenId)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(finalHead)),
                )
            )
        )
    }

    // ---- full-signature helpers (FlowOpen / FlowCommit) — real ML-DSA, isolation ----

    // The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).
    private fun protectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    // The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow).
    fun signFlowOpen(o: FlowOpen, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), o.bytes())

    // The tagged COSE_Sign1 over the FlowCommit body.
    fun signFlowCommit(c: FlowCommit, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), c.bytes())

    // Verify the FlowOpen's full signature, then reconstruct the authority from the signed body bytes
    // (fail-closed BadSignature).
    fun verifyFlowOpen(obj: ByteArray, alg: Int, pubkey: ByteArray): FlowOpen {
        val parts = Cose.parseSign1Raw(obj)
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(alg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "flow-open signature does not verify")
        }
        return parseFlowOpen(parts[1])
    }

    // Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head
    // equals the chain recomputed over the delivered continuations (CommitMismatch otherwise).
    fun verifyFlowCommit(obj: ByteArray, alg: Int, pubkey: ByteArray, open: FlowOpen, conts: List<Continuation>): FlowCommit {
        val parts = Cose.parseSign1Raw(obj)
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(alg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "flow-commit signature does not verify")
        }
        val m = decodeMap(parts[1])
        val fid = bstrField(m, 1)
        val fh = bstrField(m, 2)
        if (fid == null || fh == null) {
            throw NaalpException("ContMalformed", "object is not a well-formed FlowCommit body")
        }
        val fc = FlowCommit(fid, fh)
        if (!fc.flowOpenId.contentEquals(open.id())) {
            throw NaalpException("WrongFlow", "flow-commit does not bind this FlowOpen")
        }
        val final = verifyChain(open, conts)
        if (!fc.finalHead.contentEquals(final)) {
            throw NaalpException("CommitMismatch", "flow commit final_head does not match the recomputed chain")
        }
        return fc
    }

    // ---- small deterministic-CBOR field accessors ----

    private fun decodeMap(b: ByteArray): Cbor.M {
        val v = Cbor.decode(b) // strict decoder: propagates NonCanonical on a non-canonical body
        if (v !is Cbor.M) throw NaalpException("ContMalformed", "object is not a map")
        return v
    }

    private fun field(m: Cbor.M, k: Long): Cbor.Value? {
        for (p in m.pairs) {
            val key = p.k
            if (key is Cbor.U && key.v == k) return p.v
        }
        return null
    }

    private fun bstrField(m: Cbor.M, k: Long): ByteArray? {
        val v = field(m, k)
        return if (v is Cbor.B) v.v else null
    }

    private fun uintField(m: Cbor.M, k: Long): Long? {
        val v = field(m, k)
        return if (v is Cbor.U) v.v else null
    }
}
