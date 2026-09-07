// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// C18 signed description / directory / import known-answer test for the Kotlin SDK (design.md §21;
// R-DESC-1..8), graded against the shared independent corpus vectors/description/cases.json (NOT
// produced by this code).
//
// CORPUS-GRADED (pure, no signature): the Description body + head + content id and each operation body;
// the Directory body/head/id for both versions; fork detection at the FIRST-DIFFERING member position
// (a member-substitution fork at position 1, a truncated-member fork at position 1, a different version
// is a legitimate succession not a fork, a duplicate is no fork); the Import body/head/id and the bound
// foreign content id; a foreign format outside the closed set {1,2,3} rejected UnknownDescriptionFormat.
// ISOLATION (real FIPS-204 ML-DSA-65 via BouncyCastle — Kotlin is a full-signature port; the corpus
// carries NO signed vector, so these are demonstrated with a fixed local seed, stated honestly, NOT
// corpus-graded): a signed Description re-verifies to the identical operation table regardless of the
// serving host (offline / third-party re-serve); a DirectoryForkProof by one signer returns the
// first-differing position; and the confused-deputy rule — the attested importer MUST equal the
// verifying key's self-certifying signer id, else ImporterMismatch; a foreign identity never authorizes.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the "Tests"
// token the ten-language-parity gate indexes. Written test-first: [Desc] is absent until Description.kt
// lands, so this fails RED with a kotlinc "unresolved reference: Desc". The load-bearing mutation — the
// firstMemberDifference byte comparison made to never differ (if (!a[i].contentEquals(b[i])) ->
// if (false)) — flips "directory fork detected at first-differing position 1" on its assertion.
//

private var deFails = 0

private fun deCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        deFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun deFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/description/cases.json not found")
        val p = File(File(cur, "vectors"), "description/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/description/cases.json not found from ${File(".").absolutePath}")
}

private fun deSection(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*").find(scope)
        ?: throw AssertionError("key not found: $key")
    var i = m.range.last + 1
    while (i < scope.length && scope[i].isWhitespace()) i++
    val open = scope[i]
    val close = when (open) { '{' -> '}'; '[' -> ']'; else -> throw AssertionError("not object/array at $key") }
    var depth = 0
    var inStr = false
    var esc = false
    val start = i
    while (i < scope.length) {
        val c = scope[i]
        if (inStr) {
            when {
                esc -> esc = false
                c == '\\' -> esc = true
                c == '"' -> inStr = false
            }
        } else {
            when (c) {
                '"' -> inStr = true
                open -> depth++
                close -> { depth--; if (depth == 0) return scope.substring(start, i + 1) }
            }
        }
        i++
    }
    throw AssertionError("unbalanced value at key: $key")
}

private fun deElements(arraySection: String): List<String> {
    val out = ArrayList<String>()
    var i = 1
    var inStr = false
    var esc = false
    var depth = 0
    var start = -1
    while (i < arraySection.length - 1) {
        val c = arraySection[i]
        if (inStr) {
            when {
                esc -> esc = false
                c == '\\' -> esc = true
                c == '"' -> inStr = false
            }
        } else {
            when (c) {
                '"' -> inStr = true
                '{' -> { if (depth == 0) start = i; depth++ }
                '}' -> { depth--; if (depth == 0 && start >= 0) { out.add(arraySection.substring(start, i + 1)); start = -1 } }
            }
        }
        i++
    }
    return out
}

// An array of quoted hex strings (member content-id lists), decoded to bytes.
private fun deHexArray(arraySection: String): List<ByteArray> {
    val out = ArrayList<ByteArray>()
    Regex("\"([0-9a-fA-F]*)\"").findAll(arraySection).forEach { out.add(Hex.decode(it.groupValues[1])) }
    return out
}

private fun deStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun deInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun deHex(s: String): ByteArray = Hex.decode(s)

private const val DE_ALG = Cose.ALG_MLDSA65
private val DE_SEED = ByteArray(32) { 5 }
private val DE_PK = Cose.mldsaKeygen("ML-DSA-65", DE_SEED)

private inline fun deKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun deOp(block: String): Desc.Operation =
    Desc.Operation(deStr(block, "name"), deInt(block, "effect"), deInt(block, "requires_approval"))

private fun descriptionRun() {
    val json = deFindVector().readText(Charsets.UTF_8)

    // 1. Description: each operation body, the whole body/head/id, a parse round-trip, and per-operation
    //    effect + approval-declaration accessors.
    val descSec = deSection(json, "description")
    // The description's top-level body_hex sits AFTER the operations array (whose elements each also carry
    // a body_hex); scope the top-level read to the tail so the nested op body_hex cannot shadow it.
    val opsSection = deSection(descSec, "operations")
    val descTail = descSec.substring(descSec.indexOf(opsSection) + opsSection.length)
    val descBodyHex = deStr(descTail, "body_hex")
    val opElems = deElements(opsSection)
    val ops = ArrayList<Desc.Operation>()
    for (ob in opElems) {
        val op = deOp(ob)
        deCheck("description op ${op.name} body == oracle", Hex.encode(op.bytes()), deStr(ob, "body_hex"))
        ops.add(op)
    }
    val desc = Desc.Description(deHex(deStr(descSec, "service_hex")), ops)
    deCheck("description body == oracle", Hex.encode(desc.bytes()), descBodyHex)
    deCheck("description head == oracle", Hex.encode(desc.head()), deStr(descTail, "head_hex"))
    deCheck("description id == oracle", Hex.encode(desc.id()), deStr(descTail, "id_hex"))
    deCheck("description parse round-trip == oracle", Hex.encode(Desc.parseDescription(desc.bytes()).bytes()), descBodyHex)
    val purge = desc.operation("purge") ?: throw AssertionError("purge operation missing")
    deCheck("description op purge effect class == destructive", purge.effectClass().toString(), Policy.DESTRUCTIVE.toString())
    deCheck("description op purge requires approval", purge.requiresApprovalFlag().toString(), "true")
    val status = desc.operation("status") ?: throw AssertionError("status operation missing")
    deCheck("description op status requires no approval", status.requiresApprovalFlag().toString(), "false")

    // 2. Directory: both versions' body/head/id, and fork detection at the first-differing member
    //    position. THIS is the mutation's target assertion.
    val dirSec = deSection(json, "directory")
    val dirId = deHex(deStr(dirSec, "directory_hex"))
    val membersA = deHexArray(deSection(dirSec, "members_a_hex"))
    val dirA = Desc.Directory(dirId, deInt(dirSec, "version"), membersA)
    val aSec = deSection(dirSec, "a")
    deCheck("directory a body == oracle", Hex.encode(dirA.bytes()), deStr(aSec, "body_hex"))
    deCheck("directory a head == oracle", Hex.encode(dirA.head()), deStr(aSec, "head_hex"))
    deCheck("directory a id == oracle", Hex.encode(dirA.id()), deStr(aSec, "id_hex"))

    val forkSec = deSection(dirSec, "fork")
    val membersB = deHexArray(deSection(forkSec, "members_b_hex"))
    val dirB = Desc.Directory(dirId, deInt(dirSec, "version"), membersB)
    val bSec = deSection(forkSec, "b")
    deCheck("directory fork b body == oracle", Hex.encode(dirB.bytes()), deStr(bSec, "body_hex"))
    deCheck("directory fork b head == oracle", Hex.encode(dirB.head()), deStr(bSec, "head_hex"))
    deCheck("directory fork b id == oracle", Hex.encode(dirB.id()), deStr(bSec, "id_hex"))
    val (fpos, ffork) = Desc.detectFork(dirA, dirB)
    deCheck("directory fork detected", ffork.toString(), "true")
    deCheck("directory fork detected at first-differing position 1", fpos.toString(), deInt(forkSec, "first_differing_position").toString())

    // a truncated member list forks at the length of the shorter list.
    val lenSec = deSection(dirSec, "length_fork")
    val membersShort = deHexArray(deSection(lenSec, "members_short_hex"))
    val dirShort = Desc.Directory(dirId, deInt(dirSec, "version"), membersShort)
    val (lpos, lfork) = Desc.detectFork(dirA, dirShort)
    deCheck("directory length fork detected", lfork.toString(), "true")
    deCheck("directory length fork at position 1", lpos.toString(), deInt(lenSec, "first_differing_position").toString())

    // a different version is a legitimate succession, not a fork.
    val dvSec = deSection(dirSec, "different_version")
    val dirV8 = Desc.Directory(dirId, deInt(dvSec, "version"), membersB)
    val (_, dvFork) = Desc.detectFork(dirA, dirV8)
    deCheck("directory different version is not a fork", dvFork.toString(), "false")

    // a duplicate (identical members) is not a fork.
    val (_, dupFork) = Desc.detectFork(dirA, dirA)
    deCheck("directory duplicate is not a fork", dupFork.toString(), "false")

    // 3. Import: body/head/id, the bound foreign content id, a parse round-trip, and an unknown foreign
    //    format rejected on decode.
    val impSec = deSection(json, "import")
    val impOps = deElements(deSection(impSec, "operations")).map { deOp(it) }
    val imp = Desc.Import(deHex(deStr(impSec, "importer_hex")), deInt(impSec, "format"), deHex(deStr(impSec, "foreign_hex")), impOps)
    deCheck("import body == oracle", Hex.encode(imp.bytes()), deStr(impSec, "body_hex"))
    deCheck("import head == oracle", Hex.encode(imp.head()), deStr(impSec, "head_hex"))
    deCheck("import id == oracle", Hex.encode(imp.id()), deStr(impSec, "id_hex"))
    deCheck("import foreign id == oracle", Hex.encode(imp.foreignId()), deStr(impSec, "foreign_id_hex"))
    deCheck("import parse round-trip == oracle", Hex.encode(Desc.parseImport(imp.bytes()).bytes()), deStr(impSec, "body_hex"))
    val unSec = deSection(impSec, "unknown_format")
    deCheck("import unknown format rejected", deKind { Desc.parseImport(deHex(deStr(unSec, "body_hex"))) }, deStr(unSec, "reject"))

    // 4. ISOLATION (real ML-DSA): the signed paths.
    // 4a. offline / third-party re-serve: a signed Description re-verifies to the identical bytes.
    val signedDesc = Desc.signDescription(desc, DE_ALG, DE_SEED)
    deCheck("iso signed Description re-verifies to identical bytes", Hex.encode(Desc.verifyDescription(signedDesc, Cose.PROFILE_PUBLIC, DE_ALG, DE_PK).bytes()), descBodyHex)
    // a tampered signature is BadSignature (fail-closed).
    val tampered = signedDesc.copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    deCheck("iso tampered Description rejected BadSignature", deKind { Desc.verifyDescription(tampered, Cose.PROFILE_PUBLIC, DE_ALG, DE_PK) }, "BadSignature")

    // 4b. DirectoryForkProof by one signer returns the first-differing position; a non-fork is rejected.
    val signedA = Desc.signDirectory(dirA, DE_ALG, DE_SEED)
    val signedB = Desc.signDirectory(dirB, DE_ALG, DE_SEED)
    val proof = Desc.DirectoryForkProof("accused".toByteArray(), signedA, signedB)
    deCheck("iso DirectoryForkProof position == 1", proof.verify(Cose.PROFILE_PUBLIC, DE_ALG, DE_PK).toString(), deInt(forkSec, "first_differing_position").toString())
    val signedV8 = Desc.signDirectory(dirV8, DE_ALG, DE_SEED)
    val notFork = Desc.DirectoryForkProof("accused".toByteArray(), signedA, signedV8)
    deCheck("iso non-fork proof rejected DirForkProofInvalid", deKind { notFork.verify(Cose.PROFILE_PUBLIC, DE_ALG, DE_PK) }, "DirForkProofInvalid")

    // 4c. confused-deputy: the attested importer MUST equal the verifying key's signer id.
    val keyId = Identity.signerId(DE_ALG, DE_PK)
    val goodImport = Desc.Import(keyId.toByteArray(Charsets.UTF_8), Desc.FORMAT_ANP_DESCRIPTION, deHex(deStr(impSec, "foreign_hex")), impOps)
    val signedImport = Desc.signImport(goodImport, DE_ALG, DE_SEED)
    val resolved = Desc.verifyImport(signedImport, Cose.PROFILE_PUBLIC, DE_ALG, DE_PK)
    deCheck("iso verifyImport authority == signer id", resolved.authorityId, keyId)
    deCheck("iso verifyImport foreign id bound == oracle", Hex.encode(resolved.foreignId), deStr(impSec, "foreign_id_hex"))
    // a foreign importer that is not the verifying key's signer id never authorizes.
    val mismatchImport = Desc.Import(deHex(deStr(impSec, "importer_hex")), Desc.FORMAT_ANP_DESCRIPTION, deHex(deStr(impSec, "foreign_hex")), impOps)
    val signedMismatch = Desc.signImport(mismatchImport, DE_ALG, DE_SEED)
    deCheck("iso verifyImport foreign importer rejected ImporterMismatch", deKind { Desc.verifyImport(signedMismatch, Cose.PROFILE_PUBLIC, DE_ALG, DE_PK) }, "ImporterMismatch")
}

fun main() {
    println("description conformance (Kotlin) — graded vs vectors/description/cases.json")
    descriptionRun()
    println(if (deFails == 0) "DescriptionTests: PASS" else "DescriptionTests: FAIL ($deFails)")
    exitProcess(if (deFails == 0) 0 else 1)
}
