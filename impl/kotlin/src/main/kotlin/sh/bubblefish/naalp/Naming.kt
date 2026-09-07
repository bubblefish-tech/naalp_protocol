// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * C19 - name bindings and the signed A2A task-state profile for the Kotlin SDK (design.md 22;
 * R-NAME-1..6, R-A2A-1..7).
 *
 * C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
 * object. Both reuse the C7 audit receipt-chain construction (8.1) unchanged - head = SHA-384(body),
 * genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or
 * omitting a record breaks the next record's linkage - and they add NO new envelope, encoding,
 * signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body
 * (COSE_Sign1, 4), reusing the T1 content-id framing (2.3) and the C7 chain.
 *
 * Task 4.1 - name bindings: a [NameBinding] {1:name,2:signer,3:seq,4:prev} maps a name to a signer id
 * and CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis prev is
 * zero). A key rotation is a NEW binding at the next seq naming the new signer. A binding is DATED BY
 * its chain position (seq); the envelope's created field is advisory only. A name's history is WALKABLE
 * offline ([walkHistory]), a deleted/omitted binding leaves a detectable HOLE at the first-broken
 * position ([detectHole]), and two bindings by ONE authority at the SAME (name, seq) naming DIFFERENT
 * signers are a FORK reported at that seq ([detectFork] / [NameForkProof]).
 *
 * Task 4.2 - the signed A2A task-state profile: [TaskState] codes are the IMPORTED A2A (Agent2Agent)
 * TaskState vocabulary (carriage, not adoption): the eight states submitted, working, input-required,
 * auth-required, completed, canceled, failed, rejected (A2A 4.1.3: start = submitted; terminal =
 * completed/canceled/failed/rejected; interrupted = input-required/auth-required). A [Transition]
 * {1:task,2:card,3:from,4:to,5:seq,6:prev} is one receipt-CHAINED signed state transition. The
 * legal-edge table is DERIVED from those documented A2A category rules; [verifyTransition] rejects an
 * illegal edge, and [verifyTaskChain] walks a task's transition chain enforcing the start state,
 * contiguity, the legal-edge table, prev/seq linkage, the card binding, and the signatures. card is the
 * content-id of the A2A Agent Card attestation (a C18 naalp-description-import, [Desc.Import]) that binds
 * the profile to an agent/operation; a transition carrying a foreign card is rejected.
 *
 * An independent transcription of impl/go/naming (cross-checked against impl/python/naalp/naming and
 * impl/java). The byte surfaces are graded against vectors/naming/cases.json; the chain verifiers run
 * over REAL deterministic ML-DSA-65 signed COSE_Sign1 objects (via [Cose.coseSign1]), and the two
 * cross-language pins (SHA-384 of the seq-0 signed binding and transition, seed = 0x11*32) prove
 * Kotlin == Go == Rust == Python byte-identical signed objects. Every check is fail-closed (15): a
 * failing object is rejected whole, returns its named error, and causes no state change.
 */
object Naming {
    /** The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. */
    const val HEAD_SIZE = 48

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    /** A fresh 48-octet zero prev - the empty-chain link (the C7 chain genesis). */
    fun genesis(): ByteArray = ByteArray(HEAD_SIZE)

    /** SHA-384 over a body - a 48-octet digest (the same construction as Audit.Receipt.head). */
    private fun head(b: ByteArray): ByteArray = sha384(b)

    /** T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets). */
    private fun contentId(b: ByteArray): ByteArray {
        val h = head(b)
        val out = ByteArray(2 + h.size)
        out[0] = 0x20
        out[1] = 0x30
        System.arraycopy(h, 0, out, 2, h.size)
        return out
    }

    // ---- the COSE_Sign1 signing/verification helpers (reuse the C2 layer, R-11.3) ----------------

    /** The bare {1: alg} COSE_Sign1 protected header (4), as the reference cose.Sign1 emits. */
    private fun protectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    private fun algFromProtected(prot: ByteArray): Int {
        val v = Cbor.decode(prot)
        if (v is Cbor.M) {
            for (p in v.pairs) {
                val k = p.k
                if (k is Cbor.U && k.v == 1L) {
                    val pv = p.v
                    if (pv is Cbor.N) return pv.v.toInt()
                    if (pv is Cbor.U) return pv.v.toInt()
                }
            }
        }
        throw NaalpException("NameMalformed", "protected header has no alg")
    }

    /**
     * Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
     * Check order (mirroring cose.Verify1): alg registry -> profile floor -> key-alg match -> signature.
     * Fail-closed with a named error.
     */
    private fun verifySign1(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ByteArray {
        val parts = Cose.parseSign1Raw(obj)
        val prot = parts[0]
        val payload = parts[1]
        val sig = parts[2]
        val halg = algFromProtected(prot)
        val (level, known) = Cose.algLevel(halg)
        if (!known) throw NaalpException("UnknownAlg", "unregistered alg $halg")
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (halg != alg) throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        val tbs = Cose.toBeSignedRaw(prot, payload)
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, sig)) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        return payload
    }

    // ==== Task 4.1 - name bindings ================================================================

    /**
     * Maps a name to a signer id at a chain position. It chains onto the prior binding for the same
     * name: [prev] is the prior binding's head (genesis for seq 0). A key rotation is a new binding at
     * the next seq naming the new signer. The binding is DATED BY seq; the envelope's created is advisory.
     */
    class NameBinding(val name: String, signer: ByteArray, val seq: Long, prev: ByteArray) {
        val signer: ByteArray = signer.copyOf()
        val prev: ByteArray = prev.copyOf()

        /** Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.T(name)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(signer)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(prev)),
                )
            )
        )

        /** The chain head after this binding: SHA-384 of the binding body (48 octets). */
        fun head(): ByteArray = Naming.head(bytes())

        /** The binding's T1 content-id (50 octets). */
        fun id(): ByteArray = contentId(bytes())
    }

    /**
     * Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4} map
     * with the right value types is NameMalformed (fail-closed).
     */
    fun parseNameBinding(b: ByteArray): NameBinding {
        val m = decodeMap(b)
        val name = tstrField(m, 1)
        val signer = bstrField(m, 2)
        val seq = uintField(m, 3)
        val prev = bstrField(m, 4)
        if (name == null || signer == null || seq == null || prev == null) {
            throw NaalpException("NameMalformed", "body is not a well-formed name binding")
        }
        return NameBinding(name, signer, seq, prev)
    }

    /** Produce the tagged COSE_Sign1 object over the binding body (real deterministic ML-DSA). */
    fun signBinding(nb: NameBinding, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), nb.bytes())

    /**
     * Verify the binding's full signature under the profile, then reconstruct it from the signed body
     * bytes. A bad signature is BadSignature; a malformed body is NameMalformed. Fail-closed.
     */
    fun verifyBinding(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): NameBinding =
        parseNameBinding(verifySign1(obj, profile, alg, pubkey))

    /** The (binding, tagged COSE_Sign1 object) pair a [Registrar.append] returns. */
    class SignedBinding(val binding: NameBinding, val obj: ByteArray)

    /**
     * A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
     * authority). Each append records a name -> signer mapping at the next chain position; a rotation is
     * simply an append naming the new signer. Signs with a real deterministic ML-DSA key from [seed].
     */
    class Registrar(private val name: String, private val alg: Int, seed: ByteArray) {
        private val seed: ByteArray = seed.copyOf()
        private var chainHead: ByteArray = genesis()
        private var seq: Long = 0

        /**
         * Record a binding of the registrar's name to [subject] at the next chain position, returning the
         * binding and its tagged COSE_Sign1 object. Seq increases by one per append; the head advances.
         */
        fun append(subject: ByteArray): SignedBinding {
            val nb = NameBinding(name, subject, seq, chainHead)
            val obj = signBinding(nb, alg, seed)
            chainHead = nb.head()
            seq++
            return SignedBinding(nb, obj)
        }
    }

    /**
     * One step of a walked name history: the chain position and the signer the name mapped to at that
     * position, with the chain head after it.
     */
    class NameEvent(val seq: Long, signer: ByteArray, head: ByteArray) {
        val signer: ByteArray = signer.copyOf()
        val head: ByteArray = head.copyOf()
    }

    /**
     * Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the ordered
     * signer succession. Requires every binding to name the SAME name, seq i to equal its index, and prev
     * to link to the previous binding's head (genesis zero for seq 0). A gap, reorder, omitted binding, or
     * a name change is NameChainBroken (fail-closed). The CURRENT signer is the last event's signer.
     */
    fun walkHistory(bindings: List<NameBinding>): List<NameEvent> {
        val events = ArrayList<NameEvent>(bindings.size)
        var h = genesis()
        var name: String? = null
        for (i in bindings.indices) {
            val nb = bindings[i]
            if (i == 0) {
                name = nb.name
            } else if (nb.name != name) {
                throw NaalpException("NameChainBroken", "a chain is for exactly one name")
            }
            if (nb.seq != i.toLong() || !nb.prev.contentEquals(h)) {
                throw NaalpException("NameChainBroken", "prev/seq does not chain to the previous binding")
            }
            h = nb.head()
            events.add(NameEvent(nb.seq, nb.signer, h))
        }
        return events
    }

    /**
     * Check a name-binding chain offline against the authority's key. Each element is the tagged
     * COSE_Sign1 object for one binding. Verifies every signature under the profile (verifyBinding), then
     * enforces structural continuity - every binding names the SAME name, seq i equals its index, prev
     * links to the previous head - returning the verified, ordered bindings. A bad signature is
     * BadSignature; a broken link, a seq gap, or a name change is NameChainBroken. Fail-closed.
     */
    fun verifyChain(objs: List<ByteArray>, profile: Long, alg: Int, pubkey: ByteArray): List<NameBinding> {
        var h = genesis()
        var name: String? = null
        val out = ArrayList<NameBinding>(objs.size)
        for (i in objs.indices) {
            val nb = verifyBinding(objs[i], profile, alg, pubkey)
            if (i == 0) {
                name = nb.name
            } else if (nb.name != name) {
                throw NaalpException("NameChainBroken", "a chain is for exactly one name")
            }
            if (nb.seq != i.toLong() || !nb.prev.contentEquals(h)) {
                throw NaalpException("NameChainBroken", "prev/seq does not chain to the previous binding")
            }
            h = nb.head()
            out.add(nb)
        }
        return out
    }

    /** The result of a hole/gap detection: the first-broken position and whether a break was found. */
    class Break(val position: Int, val broken: Boolean)

    /**
     * Report whether a presented (possibly gappy) binding list breaks contiguity - a deleted/omitted
     * binding - and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's seq
     * is not i or its prev does not link to the previous binding's head. A contiguous list returns
     * (0, false).
     */
    fun detectHole(bindings: List<NameBinding>): Break {
        var h = genesis()
        for (i in bindings.indices) {
            val nb = bindings[i]
            if (nb.seq != i.toLong() || !nb.prev.contentEquals(h)) {
                return Break(i, true)
            }
            h = nb.head()
        }
        return Break(0, false)
    }

    /**
     * Compare two bindings for the SAME name and report whether they equivocate - the SAME name and seq
     * but DIFFERENT bodies (a different signer or prev) - and, if so, the seq position at which they
     * conflict. A different name or seq is a legitimate distinct binding; byte-identical bindings are a
     * benign duplicate. Both non-fork cases return (0, false).
     */
    fun detectFork(a: NameBinding, b: NameBinding): Break {
        if (a.name != b.name || a.seq != b.seq) return Break(0, false)
        if (a.bytes().contentEquals(b.bytes())) return Break(0, false)
        return Break(a.seq.toInt(), true)
    }

    /**
     * Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority at
     * the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
     * objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the
     * proof is self-contained - any third party confirms both signatures against the accused key.
     */
    class NameForkProof(signer: ByteArray, signedA: ByteArray, signedB: ByteArray) {
        val signer: ByteArray = signer.copyOf()
        val signedA: ByteArray = signedA.copyOf()
        val signedB: ByteArray = signedB.copyOf()

        /**
         * Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the key
         * (which, because a single verifier checks both, proves one authority); (3) the two bindings share
         * one name and seq; and (4) their bodies differ. Returns the seq position at which it forks. An
         * unnamed signer, a different name/seq, or identical bodies is NameForkProofInvalid; a signature
         * that does not verify is BadSignature. Fail-closed.
         */
        fun verify(profile: Long, alg: Int, pubkey: ByteArray): Int {
            if (signer.isEmpty()) throw NaalpException("NameForkProofInvalid", "an unnamed accused is not evidence")
            val a = verifyBinding(signedA, profile, alg, pubkey)
            val b = verifyBinding(signedB, profile, alg, pubkey)
            val f = detectFork(a, b)
            if (!f.broken) throw NaalpException("NameForkProofInvalid", "not the same (name, seq) or identical bodies")
            return f.position
        }
    }

    // ==== Task 4.2 - the signed A2A task-state profile ============================================

    /** TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A 4.1.3). */
    const val STATE_SUBMITTED = 0L       // acknowledged, not yet started (the start state)
    const val STATE_WORKING = 1L         // actively processed
    const val STATE_INPUT_REQUIRED = 2L  // interrupted, awaiting client input
    const val STATE_AUTH_REQUIRED = 3L   // interrupted, awaiting authentication
    const val STATE_COMPLETED = 4L       // terminal success
    const val STATE_CANCELED = 5L        // terminal, canceled before completion
    const val STATE_FAILED = 6L          // terminal, finished with an error
    const val STATE_REJECTED = 7L        // terminal, the agent declined the task

    /** The A2A lifecycle start state (submitted). */
    const val START_STATE = STATE_SUBMITTED

    private val TERMINAL = longArrayOf(STATE_COMPLETED, STATE_CANCELED, STATE_FAILED, STATE_REJECTED)
    private val INTERRUPTED = longArrayOf(STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED)

    /** The A2A state name, or "unknown" for an out-of-range code. */
    fun stateName(s: Long): String = when (s) {
        STATE_SUBMITTED -> "submitted"
        STATE_WORKING -> "working"
        STATE_INPUT_REQUIRED -> "input-required"
        STATE_AUTH_REQUIRED -> "auth-required"
        STATE_COMPLETED -> "completed"
        STATE_CANCELED -> "canceled"
        STATE_FAILED -> "failed"
        STATE_REJECTED -> "rejected"
        else -> "unknown"
    }

    /** Whether s is one of the eight defined A2A states. */
    fun isState(s: Long): Boolean = s in STATE_SUBMITTED..STATE_REJECTED

    /** Whether s is a terminal state (completed/canceled/failed/rejected). */
    fun isTerminal(s: Long): Boolean = TERMINAL.any { it == s }

    /** Whether s is an interrupted state (input-required/auth-required). */
    fun isInterrupted(s: Long): Boolean = s == STATE_INPUT_REQUIRED || s == STATE_AUTH_REQUIRED

    private fun edgeKey(from: Long, to: Long): Long = (from shl 8) or to

    /**
     * The explicit A2A transition table: the legal (from, to) edges derived from the A2A category rules
     * (design 22.3). It is the authoritative source both [legalEdge] and [verifyTaskChain] consult.
     */
    private val LEGAL_EDGES: Set<Long> = buildLegalEdges()

    private fun buildLegalEdges(): Set<Long> {
        val active = longArrayOf(STATE_SUBMITTED, STATE_WORKING)
        val m = HashSet<Long>()
        m.add(edgeKey(STATE_SUBMITTED, STATE_WORKING)) // begin processing (the only active->active edge)
        for (s in active) for (t in INTERRUPTED) m.add(edgeKey(s, t)) // active -> interrupted
        for (s in active) for (t in TERMINAL) m.add(edgeKey(s, t))    // active -> terminal
        for (s in INTERRUPTED) m.add(edgeKey(s, STATE_WORKING))       // interrupted -> working (client acted)
        for (s in INTERRUPTED) for (t in TERMINAL) m.add(edgeKey(s, t)) // interrupted -> terminal
        return m
    }

    /**
     * Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
     * terminal state, an edge touching an undefined state, and any edge not in the table are all false.
     */
    fun legalEdge(from: Long, to: Long): Boolean {
        if (!isState(from) || !isState(to)) return false
        return LEGAL_EDGES.contains(edgeKey(from, to))
    }

    /** A copy of the legal transition table as a sorted list of [from, to] pairs. */
    fun legalEdges(): List<LongArray> {
        val out = LEGAL_EDGES.map { longArrayOf(it shr 8, it and 0xFF) }.toMutableList()
        out.sortWith(compareBy({ it[0] }, { it[1] }))
        return out
    }

    /**
     * The edge-legality gate: returns normally iff (from -> to) is a legal A2A edge, else throws
     * IllegalTransition. Fail-closed.
     */
    fun verifyTransition(from: Long, to: Long) {
        if (!legalEdge(from, to)) throw NaalpException("IllegalTransition", "not a legal A2A transition edge")
    }

    /**
     * One signed, receipt-CHAINED A2A task state transition (design 22.4). It chains onto the prior
     * transition of the same task: [prev] is the prior transition's head (genesis for seq 0). Dated by
     * seq. [card] is the content-id of the A2A Agent Card attestation (a C18 import) that binds this
     * profile to an agent/operation.
     */
    class Transition(task: ByteArray, card: ByteArray, val from: Long, val to: Long, val seq: Long, prev: ByteArray) {
        val task: ByteArray = task.copyOf()
        val card: ByteArray = card.copyOf()
        val prev: ByteArray = prev.copyOf()

        /** Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(task)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(card)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(from)),
                    Cbor.Pair(Cbor.U(4), Cbor.U(to)),
                    Cbor.Pair(Cbor.U(5), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(6), Cbor.B(prev)),
                )
            )
        )

        /** The chain head after this transition: SHA-384 of the transition body (48 octets). */
        fun head(): ByteArray = Naming.head(bytes())

        /** The transition's T1 content-id (50 octets). */
        fun id(): ByteArray = contentId(bytes())
    }

    /**
     * Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6}
     * map with the right value types is NameMalformed (fail-closed).
     */
    fun parseTransition(b: ByteArray): Transition {
        val m = decodeMap(b)
        val task = bstrField(m, 1)
        val card = bstrField(m, 2)
        val from = uintField(m, 3)
        val to = uintField(m, 4)
        val seq = uintField(m, 5)
        val prev = bstrField(m, 6)
        if (task == null || card == null || from == null || to == null || seq == null || prev == null) {
            throw NaalpException("NameMalformed", "body is not a well-formed task transition")
        }
        return Transition(task, card, from, to, seq, prev)
    }

    /** Produce the tagged COSE_Sign1 object over the transition body (real deterministic ML-DSA). */
    fun signTransition(t: Transition, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), t.bytes())

    /**
     * Verify a transition's full signature under the profile, reconstruct it from the signed body bytes,
     * AND check that its edge is legal. A bad signature is BadSignature; an illegal edge is
     * IllegalTransition. Fail-closed.
     */
    fun verifyTransitionObject(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): Transition {
        val t = parseTransition(verifySign1(obj, profile, alg, pubkey))
        verifyTransition(t.from, t.to)
        return t
    }

    /**
     * Walk a task's transition chain offline against the authority's key and the bound card attestation.
     * Enforces, in order and fail-closed: (1) the SIGNATURE of every transition (BadSignature otherwise);
     * (2) prev/seq linkage (each prev links to the prior head, genesis zero for seq 0; seq i == index) - a
     * gap/reorder is TaskChainBroken; (3) the CARD BINDING (every transition's card equals [card]) -
     * ForeignCard otherwise; and (4) the START STATE (seq-0's from is START_STATE), CONTIGUITY (each from
     * == the prior to), and the LEGAL-EDGE TABLE at every step (including the terminal-cannot-continue
     * rule) - IllegalTransition otherwise. Returns the verified, ordered transitions. It never authorizes;
     * it accepts or rejects.
     */
    fun verifyTaskChain(objs: List<ByteArray>, card: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): List<Transition> {
        var h = genesis()
        var prevTo = 0L
        val out = ArrayList<Transition>(objs.size)
        for (i in objs.indices) {
            val payload = verifySign1(objs[i], profile, alg, pubkey) // BadSignature (foreign/tampered)
            val t = parseTransition(payload)
            if (t.seq != i.toLong() || !t.prev.contentEquals(h)) {
                throw NaalpException("TaskChainBroken", "prev/seq does not chain to the previous transition")
            }
            if (!t.card.contentEquals(card)) {
                throw NaalpException("ForeignCard", "transition binds a card other than the profile's bound card")
            }
            if (i == 0) {
                if (t.from != START_STATE) throw NaalpException("IllegalTransition", "the first transition must leave the start state")
            } else if (t.from != prevTo) {
                throw NaalpException("IllegalTransition", "non-contiguous: this from must equal the prior to")
            }
            verifyTransition(t.from, t.to) // an illegal edge (incl. a from-terminal edge)
            h = t.head()
            prevTo = t.to
            out.add(t)
        }
        return out
    }

    /**
     * Report whether a presented (possibly gappy) transition list breaks contiguity - a deleted/omitted
     * or reordered transition - and, if so, the FIRST-BROKEN position. A contiguous list returns
     * (0, false).
     */
    fun detectTaskGap(transitions: List<Transition>): Break {
        var h = genesis()
        for (i in transitions.indices) {
            val t = transitions[i]
            if (t.seq != i.toLong() || !t.prev.contentEquals(h)) {
                return Break(i, true)
            }
            h = t.head()
        }
        return Break(0, false)
    }

    // ---- small deterministic-CBOR field accessors (strict decode; NonCanonical propagates) ---------

    private fun decodeMap(b: ByteArray): Cbor.M {
        val v = Cbor.decode(b) // strict decoder: throws NonCanonical on a non-canonical body
        if (v !is Cbor.M) throw NaalpException("NameMalformed", "body is not a map")
        return v
    }

    private fun field(m: Cbor.M, k: Long): Cbor.Value? {
        for (p in m.pairs) {
            val pk = p.k
            if (pk is Cbor.U && pk.v == k) return p.v
        }
        return null
    }

    private fun bstrField(m: Cbor.M, k: Long): ByteArray? {
        val v = field(m, k)
        return if (v is Cbor.B) v.v else null
    }

    private fun tstrField(m: Cbor.M, k: Long): String? {
        val v = field(m, k)
        return if (v is Cbor.T) v.v else null
    }

    private fun uintField(m: Cbor.M, k: Long): Long? {
        val v = field(m, k)
        return if (v is Cbor.U) v.v else null
    }
}
