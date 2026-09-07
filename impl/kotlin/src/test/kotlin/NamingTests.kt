// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess

//
// C19 name-bindings + signed A2A task-state profile conformance for the Kotlin SDK (design.md 22),
// graded against the shared independent corpus vectors/naming/cases.json (NOT produced by this code):
// the name-binding and task-transition body/head/content-id byte parity, the A2A Agent Card
// attestation content-id (a C18 naalp-description-import), the offline name-history walk, hole/fork
// detection with the non-repudiable NameForkProof, the A2A legal-edge table (every legal edge
// accepted, every illegal edge rejected), the signed task-chain verifier (illegal edge /
// non-contiguous / bad start / foreign card / gap / bad signature), the >2^53 seq round-trip, the
// minimal encodings, the strict canonical-key rejection, and the look-alike cross-parse rejection.
//
// CORPUS-GRADED (pure bytes / verdicts): every binding/transition body/head/id, the card import
// body/id, the legal + illegal edge tables, the walk succession, the hole/fork/gap positions, the
// >2^53 seq, the minimal/canonical/look-alike cases. CRYPTO-DEMONSTRATED IN ISOLATION with real
// FIPS-204 ML-DSA-65 (via BouncyCastle - Kotlin is a full-signature port): the chain verifiers, the
// fork proof, and the task-chain verifier run over real deterministic COSE_Sign1 objects. The two
// CROSS-LANGUAGE PINS (SHA-384 of the seq-0 signed binding and transition, seed = 0x11*32) are the
// Go+Rust+Python reference constants; asserting them proves Kotlin == Go == Rust == Python
// byte-identical signed objects.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
// "Tests" token the ten-language-parity gate indexes. Written test-first: [Naming] is absent until
// Naming.kt lands, so this fails RED with a kotlinc "unresolved reference: Naming". The recorded
// mutation forces Naming.legalEdge to accept every edge, which flips the named
// "illegal edge 4->1 rejected IllegalTransition" check on its assertion.
//

private var naFails = 0

// The Go + Rust + Python reference pins for the deterministic signed seq-0 binding/transition (seed=0x11*32).
private const val PIN_SIGNED_BINDING_SHA384 =
    "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91"
private const val PIN_SIGNED_TRANSITION_SHA384 =
    "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787"

private fun naCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        naFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- nesting-aware JSON access (Kotlin has no JSON library; the corpus has nested objects,
//      nested arrays, and braces inside string values, so the matcher skips quoted strings) ----

private fun naFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/naming/cases.json not found")
        val p = File(File(cur, "vectors"), "naming/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/naming/cases.json not found from ${File(".").absolutePath}")
}

private fun naMatchClose(s: String, open: Int): Int {
    val oc = s[open]
    val cc = if (oc == '{') '}' else ']'
    var depth = 0
    var inStr = false
    var i = open
    while (i < s.length) {
        val ch = s[i]
        if (inStr) {
            when (ch) {
                '\\' -> i++
                '"' -> inStr = false
            }
        } else {
            when (ch) {
                '"' -> inStr = true
                oc -> depth++
                cc -> { depth--; if (depth == 0) return i + 1 }
            }
        }
        i++
    }
    throw AssertionError("unbalanced from $open")
}

private fun naAfterKey(s: String, key: String): Int {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:").find(s)
        ?: throw AssertionError("key not found: $key")
    return m.range.last + 1
}

private fun naObjBlock(s: String, key: String): String {
    val open = s.indexOf('{', naAfterKey(s, key))
    val close = naMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

private fun naArrayBlock(s: String, key: String): String {
    val open = s.indexOf('[', naAfterKey(s, key))
    val close = naMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

private fun naSplitObjects(arrayInner: String): List<String> {
    val out = ArrayList<String>()
    var i = 0
    while (true) {
        val open = arrayInner.indexOf('{', i)
        if (open < 0) return out
        val close = naMatchClose(arrayInner, open)
        out.add(arrayInner.substring(open + 1, close - 1))
        i = close
    }
}

private fun naTopStrings(arrayInner: String): List<String> =
    Regex("\"([^\"]*)\"").findAll(arrayInner).map { it.groupValues[1] }.toList()

private fun naIntPairs(arrayInner: String): List<LongArray> =
    Regex("""\[\s*(\d+)\s*,\s*(\d+)\s*]""").findAll(arrayInner)
        .map { longArrayOf(it.groupValues[1].toLong(), it.groupValues[2].toLong()) }.toList()

private fun naIntList(arrayInner: String): List<Long> =
    Regex("(\\d+)").findAll(arrayInner).map { it.groupValues[1].toLong() }.toList()

private fun naField(scope: String, key: String): String {
    val m = Regex("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun naIntField(scope: String, key: String): Long {
    val m = Regex("\"" + key + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun naHb(s: String): ByteArray = Hex.decode(s)

private fun naErrKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private const val NA_ALG = Cose.ALG_MLDSA65
private const val NA_PROFILE = Cose.PROFILE_PUBLIC

private fun naSeed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

private fun naSha384Hex(b: ByteArray): String = Hex.encode(MessageDigest.getInstance("SHA-384").digest(b))

// ---- corpus-derived builders --------------------------------------------------------

private lateinit var naNameScope: String
private lateinit var naA2aScope: String

private fun naBindings(): List<Naming.NameBinding> {
    val nu = naField(naNameScope, "name_utf8")
    return naSplitObjects(naArrayBlock(naNameScope, "bindings")).map {
        Naming.NameBinding(nu, naHb(naField(it, "signer_hex")), naIntField(it, "seq"), naHb(naField(it, "prev_hex")))
    }
}

private fun naTransitions(): List<Naming.Transition> {
    val task = naField(naA2aScope, "task_utf8").toByteArray(Charsets.UTF_8)
    val card = naHb(naField(naObjBlock(naA2aScope, "card"), "card_id_hex"))
    return naSplitObjects(naArrayBlock(naA2aScope, "transitions")).map {
        Naming.Transition(task, card, naIntField(it, "from"), naIntField(it, "to"), naIntField(it, "seq"), naHb(naField(it, "prev_hex")))
    }
}

private fun naCardImport(): Desc.Import {
    val c = naObjBlock(naA2aScope, "card")
    val ops = naSplitObjects(naArrayBlock(c, "operations"))
        .map { Desc.Operation(naField(it, "name"), naIntField(it, "effect"), naIntField(it, "requires_approval")) }
    return Desc.Import(naHb(naField(c, "importer_hex")), naIntField(c, "format"), naHb(naField(c, "foreign_hex")), ops)
}

// ---- byte parity (design 22) -------------------------------------------------------

private fun naByteParity() {
    val bs = naSplitObjects(naArrayBlock(naNameScope, "bindings"))
    naCheck("bindings count == 3", bs.size.toString(), "3")
    val bindings = naBindings()
    for (i in bindings.indices) {
        val nb = bindings[i]
        val bv = bs[i]
        naCheck("binding[$i].bytes == oracle", Hex.encode(nb.bytes()), naField(bv, "body_hex"))
        naCheck("binding[$i].head == oracle", Hex.encode(nb.head()), naField(bv, "head_hex"))
        naCheck("binding[$i].id == oracle", Hex.encode(nb.id()), naField(bv, "id_hex"))
    }
    // The fork sibling b' at seq 1 also encodes byte-identically.
    val fp = naObjBlock(naObjBlock(naNameScope, "fork"), "b_prime")
    val bp = Naming.NameBinding(naField(naNameScope, "name_utf8"), naHb(naField(fp, "signer_hex")), naIntField(fp, "seq"), naHb(naField(fp, "prev_hex")))
    naCheck("fork b_prime body == oracle", Hex.encode(bp.bytes()), naField(fp, "body_hex"))

    val ts = naSplitObjects(naArrayBlock(naA2aScope, "transitions"))
    naCheck("transitions count == 4", ts.size.toString(), "4")
    val trs = naTransitions()
    for (i in trs.indices) {
        val tr = trs[i]
        val tv = ts[i]
        naCheck("transition[$i].bytes == oracle", Hex.encode(tr.bytes()), naField(tv, "body_hex"))
        naCheck("transition[$i].head == oracle", Hex.encode(tr.head()), naField(tv, "head_hex"))
        naCheck("transition[$i].id == oracle", Hex.encode(tr.id()), naField(tv, "id_hex"))
    }

    val c = naObjBlock(naA2aScope, "card")
    val im = naCardImport()
    naCheck("card import body == oracle", Hex.encode(im.bytes()), naField(c, "import_body_hex"))
    naCheck("card import id (the bound card) == oracle", Hex.encode(im.id()), naField(c, "card_id_hex"))
}

// ---- name-history walk --------------------------------------------------------------

private fun naWalkHistory() {
    val bindings = naBindings()
    val events = Naming.walkHistory(bindings)
    val walk = naSplitObjects(naArrayBlock(naNameScope, "walk"))
    naCheck("walk length == oracle", events.size.toString(), walk.size.toString())
    for (i in events.indices) {
        naCheck("walk[$i].seq == oracle", events[i].seq.toString(), naIntField(walk[i], "seq").toString())
        naCheck("walk[$i].signer == oracle", Hex.encode(events[i].signer), naField(walk[i], "signer_hex"))
    }
    val bs = naSplitObjects(naArrayBlock(naNameScope, "bindings"))
    naCheck("current signer == last binding's signer", Hex.encode(events.last().signer), naField(bs.last(), "signer_hex"))
    // A name change mid-chain breaks the walk (one name per chain).
    val b1 = bindings[1]
    val renamed = Naming.NameBinding("other.name", b1.signer, b1.seq, b1.prev)
    naCheck("name change mid-chain breaks the walk", naErrKind { Naming.walkHistory(listOf(bindings[0], renamed)) }, "NameChainBroken")
}

private fun naHoleDetected() {
    val bindings = naBindings()
    naCheck("contiguous chain has no hole", Naming.detectHole(bindings).broken.toString(), "false")
    val br = Naming.detectHole(listOf(bindings[0], bindings[2])) // seq 1 deleted
    naCheck("deleted binding leaves a hole", br.broken.toString(), "true")
    naCheck("hole position == oracle", br.position.toString(), naIntField(naObjBlock(naNameScope, "hole"), "first_hole_position").toString())
}

private fun naForkDetected() {
    val bindings = naBindings()
    val forkScope = naObjBlock(naNameScope, "fork")
    val fp = naObjBlock(forkScope, "b_prime")
    val bp = Naming.NameBinding(naField(naNameScope, "name_utf8"), naHb(naField(fp, "signer_hex")), naIntField(fp, "seq"), naHb(naField(fp, "prev_hex")))
    val f = Naming.detectFork(bindings[1], bp)
    naCheck("fork detected", f.broken.toString(), "true")
    naCheck("fork position == oracle", f.position.toString(), naIntField(forkScope, "position").toString())
    naCheck("identical bindings are not a fork", Naming.detectFork(bindings[1], bindings[1]).broken.toString(), "false")
    naCheck("different-seq bindings are not a fork", Naming.detectFork(bindings[1], bindings[2]).broken.toString(), "false")

    // Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
    val seed = naSeed(0x11)
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val fpk = Cose.mldsaKeygen("ML-DSA-65", naSeed(0x22))
    val sid = Identity.signerId(NA_ALG, pk)
    val signedA = Naming.signBinding(bindings[1], NA_ALG, seed)
    val signedB = Naming.signBinding(bp, NA_ALG, seed)
    val proof = Naming.NameForkProof(sid.toByteArray(Charsets.UTF_8), signedA, signedB)
    naCheck("signed fork proof verifies at the fork position", proof.verify(NA_PROFILE, NA_ALG, pk).toString(), naIntField(forkScope, "position").toString())
    naCheck("a foreign key does not verify the accused's signatures", naErrKind { proof.verify(NA_PROFILE, NA_ALG, fpk) }, "BadSignature")
    naCheck("an unnamed accused is NameForkProofInvalid", naErrKind { Naming.NameForkProof(ByteArray(0), signedA, signedB).verify(NA_PROFILE, NA_ALG, pk) }, "NameForkProofInvalid")
    naCheck("identical signed bodies are NameForkProofInvalid", naErrKind { Naming.NameForkProof(sid.toByteArray(Charsets.UTF_8), signedA, signedA).verify(NA_PROFILE, NA_ALG, pk) }, "NameForkProofInvalid")
}

private fun naChainVerifyFailClosed() {
    val seed = naSeed(0x11)
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val fpk = Cose.mldsaKeygen("ML-DSA-65", naSeed(0x22))
    val nu = naField(naNameScope, "name_utf8")
    val bs = naSplitObjects(naArrayBlock(naNameScope, "bindings"))
    // Build a signed chain via the Registrar (rotation A -> B -> C).
    val reg = Naming.Registrar(nu, NA_ALG, seed)
    val objs = ArrayList<ByteArray>()
    for (i in bs.indices) {
        val sb = reg.append(naHb(naField(bs[i], "signer_hex")))
        naCheck("registrar reproduces oracle body[$i]", Hex.encode(sb.binding.bytes()), naField(bs[i], "body_hex"))
        objs.add(sb.obj)
    }
    val verified = Naming.verifyChain(objs, NA_PROFILE, NA_ALG, pk)
    naCheck("verified chain walks fully", Naming.walkHistory(verified).size.toString(), bs.size.toString())
    // A reordered chain breaks the prev/seq linkage.
    naCheck("reordered chain rejected NameChainBroken", naErrKind { Naming.verifyChain(listOf(objs[0], objs[2], objs[1]), NA_PROFILE, NA_ALG, pk) }, "NameChainBroken")
    // A tampered object fails its signature.
    val corrupt = objs[1].copyOf()
    corrupt[corrupt.size - 1] = (corrupt[corrupt.size - 1].toInt() xor 0x01).toByte()
    naCheck("tampered object rejected BadSignature", naErrKind { Naming.verifyChain(listOf(objs[0], corrupt, objs[2]), NA_PROFILE, NA_ALG, pk) }, "BadSignature")
    // A foreign verifier authenticates none of the bindings.
    naCheck("foreign verifier rejects the chain BadSignature", naErrKind { Naming.verifyChain(objs, NA_PROFILE, NA_ALG, fpk) }, "BadSignature")
    naCheck("foreign verifier rejects a single binding BadSignature", naErrKind { Naming.verifyBinding(objs[0], NA_PROFILE, NA_ALG, fpk) }, "BadSignature")
}

// ---- A2A legal-edge table (THIS is the mutation-target assertion) --------------------

private fun naTransitionTable() {
    val legal = naIntPairs(naArrayBlock(naA2aScope, "legal_edges"))
    val illegal = naIntPairs(naArrayBlock(naA2aScope, "illegal_edges"))
    naCheck("legal-edge table size == oracle", Naming.legalEdges().size.toString(), legal.size.toString())
    for (e in legal) {
        naCheck("legal edge ${e[0]}->${e[1]} accepted", Naming.legalEdge(e[0], e[1]).toString(), "true")
        naCheck("legal edge ${e[0]}->${e[1]} verifyTransition no-error", naErrKind { Naming.verifyTransition(e[0], e[1]) }, "no-error")
    }
    for (e in illegal) {
        naCheck("illegal edge ${e[0]}->${e[1]} not legal", Naming.legalEdge(e[0], e[1]).toString(), "false")
        naCheck("illegal edge ${e[0]}->${e[1]} rejected IllegalTransition", naErrKind { Naming.verifyTransition(e[0], e[1]) }, "IllegalTransition")
    }
    // Categories match the oracle.
    val states = naObjBlock(naA2aScope, "states")
    naCheck("start state == oracle", Naming.START_STATE.toString(), naIntField(states, "start").toString())
    for (s in naIntList(naArrayBlock(states, "terminal"))) {
        naCheck("state $s is terminal", Naming.isTerminal(s).toString(), "true")
    }
    for (s in naIntList(naArrayBlock(states, "interrupted"))) {
        naCheck("state $s is interrupted", Naming.isInterrupted(s).toString(), "true")
    }
    // A terminal state has no legal out-edge.
    for (s in naIntList(naArrayBlock(states, "terminal"))) {
        for (to in 0L until 8L) {
            naCheck("terminal $s has no out-edge to $to", Naming.legalEdge(s, to).toString(), "false")
        }
    }
}

private fun naChainErr(trs: List<Naming.Transition>, card: ByteArray, seed: ByteArray, pk: ByteArray): String {
    val objs = trs.map { Naming.signTransition(it, NA_ALG, seed) }
    return naErrKind { Naming.verifyTaskChain(objs, card, NA_PROFILE, NA_ALG, pk) }
}

private fun naTaskChain() {
    val seed = naSeed(0x11)
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val card = naHb(naField(naObjBlock(naA2aScope, "card"), "card_id_hex"))
    val task = naField(naA2aScope, "task_utf8").toByteArray(Charsets.UTF_8)
    val trs = naTransitions()
    val objs = trs.map { Naming.signTransition(it, NA_ALG, seed) }
    naCheck("legal ordered lifecycle verifies (4 transitions)", Naming.verifyTaskChain(objs, card, NA_PROFILE, NA_ALG, pk).size.toString(), "4")

    val genesis = Naming.genesis()
    val t0 = Naming.Transition(task, card, Naming.STATE_SUBMITTED, Naming.STATE_WORKING, 0, genesis)
    // ILLEGAL edge inside a chain: working -> submitted.
    val illegal = Naming.Transition(task, card, Naming.STATE_WORKING, Naming.STATE_SUBMITTED, 1, t0.head())
    naCheck("illegal edge inside a chain rejected", naChainErr(listOf(t0, illegal), card, seed, pk), "IllegalTransition")
    // NON-CONTIGUOUS from: input-required -> working after seq-0.
    val noncontig = Naming.Transition(task, card, Naming.STATE_INPUT_REQUIRED, Naming.STATE_WORKING, 1, t0.head())
    naCheck("non-contiguous from rejected", naChainErr(listOf(t0, noncontig), card, seed, pk), "IllegalTransition")
    // BAD START: seq-0 does not leave the start state.
    val badstart = Naming.Transition(task, card, Naming.STATE_WORKING, Naming.STATE_INPUT_REQUIRED, 0, genesis)
    naCheck("bad start state rejected", naChainErr(listOf(badstart), card, seed, pk), "IllegalTransition")
    // FOREIGN CARD.
    val fc = Naming.Transition(task, naHb(naField(naA2aScope, "foreign_card_id_hex")), Naming.STATE_SUBMITTED, Naming.STATE_WORKING, 0, genesis)
    naCheck("foreign card rejected", naChainErr(listOf(fc), card, seed, pk), "ForeignCard")
    // GAP: present [t0, t2].
    naCheck("gapped chain rejected TaskChainBroken", naErrKind { Naming.verifyTaskChain(listOf(objs[0], objs[2]), card, NA_PROFILE, NA_ALG, pk) }, "TaskChainBroken")
    // BAD SIGNATURE.
    val corrupt = objs[0].copyOf()
    corrupt[corrupt.size - 1] = (corrupt[corrupt.size - 1].toInt() xor 0x01).toByte()
    naCheck("tampered transition rejected BadSignature", naErrKind { Naming.verifyTaskChain(listOf(corrupt, objs[1], objs[2], objs[3]), card, NA_PROFILE, NA_ALG, pk) }, "BadSignature")
}

private fun naTaskGap() {
    val trs = naTransitions()
    naCheck("contiguous transitions have no gap", Naming.detectTaskGap(trs).broken.toString(), "false")
    val g = Naming.detectTaskGap(listOf(trs[0], trs[2]))
    naCheck("gapped transitions detected", g.broken.toString(), "true")
    naCheck("task gap position == oracle", g.position.toString(), naIntField(naObjBlock(naA2aScope, "gap"), "first_gap_position").toString())
}

private fun naCardBindsProfile() {
    val seed = naSeed(0x11)
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val im = naCardImport()
    val card = im.id()
    naCheck("card id == oracle", Hex.encode(card), naField(naObjBlock(naA2aScope, "card"), "card_id_hex"))
    val submit = im.operation("submit") ?: throw AssertionError("submit operation missing")
    naCheck("submit op effect == idempotent_write", submit.effectClass().toString(), Policy.IDEMPOTENT_WRITE.toString())
    naCheck("submit op requires approval", submit.requiresApprovalFlag().toString(), "true")
    // A chain bound to this card verifies.
    val objs = naTransitions().map { Naming.signTransition(it, NA_ALG, seed) }
    naCheck("chain bound to the card verifies", Naming.verifyTaskChain(objs, card, NA_PROFILE, NA_ALG, pk).size.toString(), "4")
    // A different importer yields a different card id; a chain carrying it is refused.
    val other = Desc.Import("IMPORTER_ID_B".toByteArray(Charsets.UTF_8), im.format, im.foreign, im.operations)
    naCheck("a different importer yields a different card id", other.id().contentEquals(card).toString(), "false")
    val task = naField(naA2aScope, "task_utf8").toByteArray(Charsets.UTF_8)
    val foreignT = Naming.Transition(task, other.id(), Naming.STATE_SUBMITTED, Naming.STATE_WORKING, 0, Naming.genesis())
    naCheck("a chain carrying a foreign card is refused ForeignCard", naErrKind { Naming.verifyTaskChain(listOf(Naming.signTransition(foreignT, NA_ALG, seed)), card, NA_PROFILE, NA_ALG, pk) }, "ForeignCard")
}

private fun naMalformedRejected() {
    naCheck("empty CBOR array is NameMalformed (binding)", naErrKind { Naming.parseNameBinding(byteArrayOf(0x80.toByte())) }, "NameMalformed")
    naCheck("bare uint is NameMalformed (transition)", naErrKind { Naming.parseTransition(byteArrayOf(0x00)) }, "NameMalformed")
}

// ---- cross-language signed-object byte parity (Kotlin == Go == Rust == Python) -------

private fun naCrossLangPins() {
    val seed = naSeed(0x11)
    val nb = naBindings()[0]
    naCheck("cross-lang signed name-binding pin (SHA-384)", naSha384Hex(Naming.signBinding(nb, NA_ALG, seed)), PIN_SIGNED_BINDING_SHA384)
    val tr = naTransitions()[0]
    naCheck("cross-lang signed task-transition pin (SHA-384)", naSha384Hex(Naming.signTransition(tr, NA_ALG, seed)), PIN_SIGNED_TRANSITION_SHA384)
}

// ---- >2^53 seq round-trip, minimal, canonical-key, look-alike ------------------------

private fun naOversizedSeq() {
    val bn = naObjBlock(naNameScope, "big_seq")
    val bseq = naField(bn, "seq_str").toLong()
    naCheck("name big_seq > 2^53", (bseq > (1L shl 53)).toString(), "true")
    val nb = Naming.NameBinding(naField(naNameScope, "name_utf8"), naHb(naField(bn, "signer_hex")), bseq, naHb(naField(bn, "prev_hex")))
    naCheck("name big_seq body == oracle", Hex.encode(nb.bytes()), naField(bn, "body_hex"))
    naCheck("name big_seq round-trips", Naming.parseNameBinding(nb.bytes()).seq.toString(), bseq.toString())

    val ba = naObjBlock(naA2aScope, "big_seq")
    val tseq = naField(ba, "seq_str").toLong()
    val tr = Naming.Transition(naField(naA2aScope, "task_utf8").toByteArray(Charsets.UTF_8), naHb(naField(naObjBlock(naA2aScope, "card"), "card_id_hex")), naIntField(ba, "from"), naIntField(ba, "to"), tseq, naHb(naField(ba, "prev_hex")))
    naCheck("a2a big_seq body == oracle", Hex.encode(tr.bytes()), naField(ba, "body_hex"))
    naCheck("a2a big_seq round-trips", Naming.parseTransition(tr.bytes()).seq.toString(), tseq.toString())
}

private fun naMinimal() {
    val n = naObjBlock(naNameScope, "minimal")
    val nb = Naming.NameBinding(naField(n, "name_utf8"), naHb(naField(n, "signer_hex")), naIntField(n, "seq"), naHb(naField(n, "prev_hex")))
    naCheck("name minimal body == oracle", Hex.encode(nb.bytes()), naField(n, "body_hex"))
    naCheck("name minimal id == oracle", Hex.encode(nb.id()), naField(n, "id_hex"))
    naCheck("name minimal parses", (Naming.parseNameBinding(nb.bytes()).name == "").toString(), "true")
    val a = naObjBlock(naA2aScope, "minimal")
    val tr = Naming.Transition(naHb(naField(a, "task_hex")), naHb(naField(a, "card_hex")), naIntField(a, "from"), naIntField(a, "to"), naIntField(a, "seq"), naHb(naField(a, "prev_hex")))
    naCheck("a2a minimal body == oracle", Hex.encode(tr.bytes()), naField(a, "body_hex"))
    naCheck("a2a minimal parses", (Naming.parseTransition(tr.bytes()).seq == 0L).toString(), "true")
}

private fun naKeysOutOfOrder() {
    val koo = naObjBlock(naNameScope, "keys_out_of_order")
    val b0 = naSplitObjects(naArrayBlock(naNameScope, "bindings"))[0]
    val nb = Naming.NameBinding(naField(naNameScope, "name_utf8"), naHb(naField(b0, "signer_hex")), naIntField(b0, "seq"), naHb(naField(b0, "prev_hex")))
    naCheck("canonical binding body == oracle", Hex.encode(nb.bytes()), naField(koo, "canonical_binding_body_hex"))
    naCheck("canonical body decodes", naErrKind { Cbor.decode(naHb(naField(koo, "canonical_binding_body_hex"))) }, "no-error")
    naCheck("non-canonical (keys 4,3,2,1) rejected NonCanonical", naErrKind { Cbor.decode(naHb(naField(koo, "noncanonical_binding_body_hex"))) }, "NonCanonical")
}

private fun naLookAlike() {
    val la = naObjBlock(naNameScope, "look_alike")
    naCheck("a 4-field binding fed to parseTransition is NameMalformed", naErrKind { Naming.parseTransition(naHb(naField(la, "binding_body_hex"))) }, "NameMalformed")
    naCheck("a 6-field transition fed to parseNameBinding is NameMalformed", naErrKind { Naming.parseNameBinding(naHb(naField(la, "transition_body_hex"))) }, "NameMalformed")
}

private fun namingRun() {
    val json = naFindVector().readText(Charsets.UTF_8)
    naNameScope = naObjBlock(json, "name")
    naA2aScope = naObjBlock(json, "a2a")

    naByteParity()
    naWalkHistory()
    naHoleDetected()
    naForkDetected()
    naChainVerifyFailClosed()
    naTransitionTable()   // the mutation-target assertion
    naTaskChain()
    naTaskGap()
    naCardBindsProfile()
    naMalformedRejected()
    naCrossLangPins()
    naOversizedSeq()
    naMinimal()
    naKeysOutOfOrder()
    naLookAlike()
}

fun main() {
    println("naming conformance (Kotlin) - graded vs vectors/naming/cases.json")
    namingRun()
    println(if (naFails == 0) "NamingTests: PASS" else "NamingTests: FAIL ($naFails)")
    exitProcess(if (naFails == 0) 0 else 1)
}
