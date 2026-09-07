// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess

/**
 * C21 portable gateway-decision known-answer test for the Kotlin SDK (design.md §24; R-GW-1..6), graded
 * against the shared independent corpus vectors/gateway/cases.json (NOT produced by this code).
 *
 * CORPUS-GRADED (pure): the deterministic body/head/content-id of the three decisions, the closed
 * decision vocabulary, and the strict-decoder rejections (keys-out-of-order NonCanonical, empty-vs-
 * absent policy, minimal decision, ui-event look-alike). CRYPTO-GRADED (real FIPS-204 ML-DSA-65 via
 * BouncyCastle — Kotlin is a full-signature port): the third-party re-serve property (sign then verify
 * then identical re-verify), foreign-key rejection, unknown-decision rejection, and the cross-language
 * pinned signed-decision SHA-384 that Go and Rust both pin (an independent authority for the bytes).
 *
 * KAT convention (a standalone main() exiting non-zero on any failure); the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Gateway] is absent until
 * Gateway.kt lands, so this fails RED with a kotlinc "unresolved reference: Gateway"; a mutation that
 * forces the encoded decision field to a constant flips "allow body == oracle" (and its head/id).
 */

private var gwFails = 0

// The cross-language pinned SHA-384 of the deterministic COSE_Sign1 object obtained by signing the DENY
// decision body with the shared all-0x11 32-byte ML-DSA-65 seed. Go and Rust both pin it (see
// impl/go/gateway/gateway_test.go const crossLangPinnedSignedDecisionSHA384 and vectors), so it is an
// independent (non-circular) authority for the signed bytes; Kotlin must reproduce it exactly.
private const val PIN_SIGNED_DENY_SHA384 =
    "774047d87f11f688c57d985e9cab632ea66d0abc8b9ec3d48d1c3063c54ef5df0f761ce8239cbf68302d547097f01047"

private fun gCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        gwFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- minimal regex JSON access (no JSON library on the Kotlin port) ----

private fun gFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/gateway/cases.json not found")
        val p = File(File(cur, "vectors"), "gateway/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/gateway/cases.json not found from ${File(".").absolutePath}")
}

/** The string value of a "key": "value" pair inside [scope] (value may be empty). */
private fun gField(scope: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

/** The integer value of a "key": <number> pair inside [scope]. */
private fun gIntField(scope: String, key: String): Long {
    val m = Regex("\"$key\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

/** The flat inner { ... } block of the object-valued field named [key] (no nesting). */
private fun gSubObject(json: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\\{([^{}]*)\\}", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("object key not found: $key")
    return m.groupValues[1]
}

/**
 * The body_hex value that immediately opens the object named [key]. Used for look_alike, whose note
 * carries a literal brace expression that would break the flat brace-free [gSubObject] matcher;
 * body_hex is the object's first field, before the note.
 */
private fun gOpeningBodyHex(json: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\\{\\s*\"body_hex\"\\s*:\\s*\"([^\"]*)\"").find(json)
        ?: throw AssertionError("opening body_hex not found for: $key")
    return m.groupValues[1]
}

/** The flat object blocks of the array named [arrayKey]. */
private fun gObjectBlocks(json: String, arrayKey: String): List<String> {
    val a = Regex("\"$arrayKey\"\\s*:\\s*\\[(.*?)\\]", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("array key not found: $arrayKey")
    return Regex("\\{([^{}]*)\\}", RegexOption.DOT_MATCHES_ALL).findAll(a.groupValues[1])
        .map { it.groupValues[1] }.toList()
}

private fun gSha384Hex(b: ByteArray): String =
    Hex.encode(MessageDigest.getInstance("SHA-384").digest(b))

// ---- nesting-aware JSON access (for the S1/S3/E6.3 evidence-record corpora, which nest objects
//      inside objects -- e.g. records{}, checkpoints{}.witness_cosign{}, edge_cases{}.
//      empty_vs_absent{}.empty_audience{} -- beyond the flat [^{}]* helpers above) ----

/** Locates vectors/[subdir]/cases.json by walking up from the working directory (mirrors
 * [gFindVector], generalized to the S1/S3/E6.3 corpora decision_record/checkpoint/
 * egress_attestation/). */
private fun gFindVectorNamed(subdir: String): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/$subdir/cases.json not found")
        val p = File(File(cur, "vectors"), "$subdir/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/$subdir/cases.json not found from ${File(".").absolutePath}")
}

/** Index just past the '{'/'[' at [open]'s match, skipping over double-quoted strings. */
private fun gMatchClose(s: String, open: Int): Int {
    val oc = s[open]
    val cc = if (oc == '{') '}' else ']'
    var depth = 0
    var inStr = false
    var i = open
    while (i < s.length) {
        val ch = s[i]
        if (inStr) {
            if (ch == '\\') {
                i++
            } else if (ch == '"') {
                inStr = false
            }
            i++
            continue
        }
        when {
            ch == '"' -> inStr = true
            ch == oc -> depth++
            ch == cc -> {
                depth--
                if (depth == 0) return i + 1
            }
        }
        i++
    }
    throw AssertionError("unbalanced from $open")
}

private fun gAfterKey(s: String, key: String): Int {
    val m = Regex("\"$key\"\\s*:").find(s) ?: throw AssertionError("key not found: $key")
    return m.range.last + 1
}

/** The inner content (braces stripped) of the object value that follows "key":. */
private fun gObjBlock(s: String, key: String): String {
    val open = s.indexOf('{', gAfterKey(s, key))
    val close = gMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

/** The inner content (brackets stripped) of the array value that follows "key":. */
private fun gArrayBlock(s: String, key: String): String {
    val open = s.indexOf('[', gAfterKey(s, key))
    val close = gMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

/** Returns `name -> innerContent` for a JSON object whose values are themselves objects, given the
 * flattened outer content of that object (as returned by [gObjBlock]); each inner content is itself
 * returned braces-stripped, exactly as [gObjBlock] would return it. Scalar sibling keys (whose value
 * is not an object) are skipped naturally, since the matcher requires the next non-whitespace token
 * after the colon to be a literal '{'. */
private fun gNamedObjectBlocks(outerBlockContent: String): LinkedHashMap<String, String> {
    val out = LinkedHashMap<String, String>()
    val km = Regex("\"([^\"]*)\"\\s*:\\s*\\{")
    var i = 0
    while (true) {
        val m = km.find(outerBlockContent, i) ?: break
        val name = m.groupValues[1]
        val open = m.range.last // position of the matched '{'
        val close = gMatchClose(outerBlockContent, open)
        out[name] = outerBlockContent.substring(open + 1, close - 1)
        i = close
    }
    return out
}

/** All double-quoted hex-looking tokens in a flattened JSON array body (e.g. governing_hex[],
 * path_hex[]), in order. */
private fun gHexStringArray(arrInner: String): List<String> {
    val trimmed = arrInner.trim()
    if (trimmed.isEmpty()) return emptyList()
    return Regex("\"([0-9a-fA-F]*)\"").findAll(trimmed).map { it.groupValues[1] }.toList()
}

/** The decoded byte-string array named [key] inside [scope]. */
private fun gHexArrayField(scope: String, key: String): List<ByteArray> =
    gHexStringArray(gArrayBlock(scope, key)).map { Hex.decode(it) }

/** An unsigned-64-bit integer field, via [java.lang.Long.parseUnsignedLong] -- `at_str` in the
 * checkpoint/egress-attestation corpora ranges up to 2^64-1, beyond a signed parse's range; carried
 * as a decimal STRING so no float64 decoder anywhere can round it. */
private fun gLongField(scope: String, key: String): Long {
    val m = Regex("\"$key\"\\s*:\\s*\"?(\\d+)\"?").find(scope) ?: throw AssertionError("int key not found: $key")
    return java.lang.Long.parseUnsignedLong(m.groupValues[1])
}

/** `consume_hex` may be a JSON string, null, or absent; the mandatory-quote [gField] matcher only
 * matches an actual quoted string, so null/absent both fall through to the empty (absent) byte
 * string -- exactly the DecisionRecord.consume "absent" convention. */
private fun gConsumeHexField(scope: String): ByteArray {
    val m = Regex("\"consume_hex\"\\s*:\\s*\"([0-9a-fA-F]*)\"").find(scope)
    return if (m != null) Hex.decode(m.groupValues[1]) else ByteArray(0)
}

/** Runs [block]; returns the named kind it throws, or "no-error". */
private fun gErrKind(block: () -> Unit): String = try {
    block()
    "no-error"
} catch (e: NaalpException) {
    e.kind
}

/** A GatewayDecision built from a corpus block carrying decision/effect/action_hex/policy_hex. */
private fun gDecFrom(block: String): Gateway.GatewayDecision =
    Gateway.GatewayDecision(
        gIntField(block, "decision"),
        Hex.decode(gField(block, "action_hex")),
        Hex.decode(gField(block, "policy_hex")),
        gIntField(block, "effect")
    )

/** The named kind thrown by parseDecision on [body], or "no-error". */
private fun gParseKind(body: ByteArray): String = try {
    Gateway.parseDecision(body)
    "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun gSeed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

private fun gatewayRun() {
    val json = gFindVector().readText(Charsets.UTF_8)

    // 1. the closed decision vocabulary is registered; an out-of-set code is not known.
    for (vb in gObjectBlocks(json, "decision_vocabulary")) {
        val name = gField(vb, "name")
        val code = gIntField(vb, "code")
        gCheck("vocab $name known", Gateway.isKnownDecision(code).toString(), "true")
        gCheck("vocab $name name", Gateway.decisionName(code), name)
    }
    val unknown = gIntField(json, "unknown_decision")
    gCheck("unknown decision not known", Gateway.isKnownDecision(unknown).toString(), "false")

    // 2. each decision body/head/id == the non-circular oracle, byte-for-byte.
    for (dn in listOf("allow", "deny", "hold")) {
        val block = gSubObject(json, dn)
        val d = gDecFrom(block)
        gCheck("$dn body == oracle", Hex.encode(d.bytes()), gField(block, "body_hex"))
        gCheck("$dn head == oracle", Hex.encode(d.head()), gField(block, "head_hex"))
        gCheck("$dn id == oracle", Hex.encode(d.id()), gField(block, "id_hex"))
    }

    // 3. edge #1: a canonical body encodes to the oracle and parses; a DESCENDING-key body is rejected
    //    NonCanonical by the strict decoder and GwMalformed by parseDecision.
    val koo = gSubObject(json, "keys_out_of_order")
    val kd = gDecFrom(koo)
    gCheck("keys-out-of-order canonical body == oracle", Hex.encode(kd.bytes()), gField(koo, "canonical_body_hex"))
    val canon = Hex.decode(gField(koo, "canonical_body_hex"))
    val noncanon = Hex.decode(gField(koo, "noncanonical_body_hex"))
    gCheck("canonical body parses", gParseKind(canon), "no-error")
    var cborKind: String = try {
        Cbor.decode(noncanon); "decoded"
    } catch (e: NaalpException) {
        e.kind
    }
    gCheck("descending-key body cbor-rejected", cborKind, "NonCanonical")
    gCheck("descending-key body parseDecision-rejected", gParseKind(noncanon), "GwMalformed")

    // 4. edge #2: an EMPTY policy identity is present, valid, and distinct by content-id from a
    //    populated one; both differ from a body whose policy field is ABSENT (rejected GwMalformed).
    val actionCid = Hex.decode(gField(json, "action_cid_hex"))
    val emptyB = gSubObject(json, "empty_policy")
    val popB = gSubObject(json, "populated_policy")
    val absB = gSubObject(json, "absent_field")
    val empty = Gateway.GatewayDecision(Gateway.DECISION_ALLOW, actionCid, ByteArray(0), 1)
    val populated = Gateway.GatewayDecision(Gateway.DECISION_ALLOW, actionCid, Hex.decode(gField(popB, "policy_hex")), 1)
    gCheck("empty-policy body == oracle", Hex.encode(empty.bytes()), gField(emptyB, "body_hex"))
    gCheck("empty-policy id == oracle", Hex.encode(empty.id()), gField(emptyB, "id_hex"))
    gCheck("populated-policy body == oracle", Hex.encode(populated.bytes()), gField(popB, "body_hex"))
    gCheck("populated-policy id == oracle", Hex.encode(populated.id()), gField(popB, "id_hex"))
    gCheck("empty vs populated ids distinct", (Hex.encode(empty.id()) != Hex.encode(populated.id())).toString(), "true")
    gCheck("empty policy parses", gParseKind(empty.bytes()), "no-error")
    gCheck("populated policy parses", gParseKind(populated.bytes()), "no-error")
    gCheck("absent policy field rejected", gParseKind(Hex.decode(gField(absB, "body_hex"))), "GwMalformed")

    // 5. edge #4: the minimal decision (allow, empty action, empty policy, read_only) encodes to the
    //    oracle bytes, has a stable content-id, and parses.
    val minB = gSubObject(json, "minimal")
    val minimal = gDecFrom(minB)
    gCheck("minimal body == oracle", Hex.encode(minimal.bytes()), gField(minB, "body_hex"))
    gCheck("minimal id == oracle", Hex.encode(minimal.id()), gField(minB, "id_hex"))
    gCheck("minimal parses", gParseKind(minimal.bytes()), "no-error")

    // 6. edge #5: a ui-event look-alike {1:bstr,2:uint,3:bstr,4:uint,5:bstr} — field 1 a bstr where the
    //    decision uint is required — is rejected GwMalformed.
    gCheck("ui-event look-alike rejected", gParseKind(Hex.decode(gOpeningBodyHex(json, "look_alike"))), "GwMalformed")

    // 7. CRYPTO-GRADED (real ML-DSA-65): the third-party re-serve property. A signed decision verifies
    //    offline and RE-VERIFIES IDENTICALLY (verifyDecision takes no serving-party identity); a foreign
    //    key never verifies it; an unknown-code decision is rejected.
    val deny = gDecFrom(gSubObject(json, "deny"))
    val gwSeed = gSeed(0x51)
    val gwPk = Cose.mldsaKeygen("ML-DSA-65", gwSeed)
    val obj = Gateway.signDecision(deny, Cose.ALG_MLDSA65, gwSeed)
    val byGateway = Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)
    val byThirdParty = Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)
    gCheck("verify resolves deny", byGateway.decision.toString(), Gateway.DECISION_DENY.toString())
    gCheck("resolved action == oracle action cid", Hex.encode(byThirdParty.action), gField(json, "action_cid_hex"))
    val reServeIdentical = byGateway.decision == byThirdParty.decision &&
        byGateway.action.contentEquals(byThirdParty.action) &&
        byGateway.policy.contentEquals(byThirdParty.policy) &&
        byGateway.effect == byThirdParty.effect
    gCheck("third-party re-serve identical", reServeIdentical.toString(), "true")

    val foreignPk = Cose.mldsaKeygen("ML-DSA-65", gSeed(0x52))
    var foreignKind = "no-error"
    try {
        Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, foreignPk)
    } catch (e: NaalpException) {
        foreignKind = e.kind
    }
    gCheck("foreign key rejected", foreignKind, "BadSignature")

    val bad = Gateway.GatewayDecision(unknown, actionCid, Hex.decode(gField(json, "policy_hex")), 0)
    val badObj = Gateway.signDecision(bad, Cose.ALG_MLDSA65, gwSeed)
    var unknownKind = "no-error"
    try {
        Gateway.verifyDecision(badObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)
    } catch (e: NaalpException) {
        unknownKind = e.kind
    }
    gCheck("unknown-code decision rejected", unknownKind, "UnknownGatewayDecision")

    // 8. the minimal decision verifies end-to-end (allow is known) with a fresh gateway key.
    val mSeed = gSeed(0x53)
    val mPk = Cose.mldsaKeygen("ML-DSA-65", mSeed)
    val mObj = Gateway.signDecision(minimal, Cose.ALG_MLDSA65, mSeed)
    var minVerify = "ok"
    try {
        Gateway.verifyDecision(mObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, mPk)
    } catch (e: NaalpException) {
        minVerify = e.kind
    }
    gCheck("minimal verifies end-to-end", minVerify, "ok")

    // 9. CROSS-LANGUAGE PIN: the signed DENY object (seed=0x11*32) has the SHA-384 Go and Rust pin —
    //    proving the two independent ML-DSA stacks emit byte-identical signed gateway-decision objects.
    val pinObj = Gateway.signDecision(deny, Cose.ALG_MLDSA65, gSeed(0x11))
    gCheck("cross-language signed-deny SHA-384 pin", gSha384Hex(pinObj), PIN_SIGNED_DENY_SHA384)

    // 10. R1 ordering (field 5) + R8 foreign-profile (field 6), graded against this SAME corpus's
    //     optional_fields{} block (mirrors GatewayKatTest.java's optional-fields section).
    runOptionalFields(json)
}

// =====================================================================================================
// Evidence-record family: S1 naalp-decision-record, S3 naalp-checkpoint-root/witness-cosign/
// inclusion-proof, E6.3 naalp-egress-attestation. Each graded against its OWN independent corpus
// (vectors/{decision_record,checkpoint,egress_attestation}/cases.json), mirroring
// impl/go/gateway/{decision_record,checkpoint,egress_attestation}_test.go and
// impl/java's GatewayKatTest.java / impl/python's test_{decision_record,checkpoint,egress_attestation}.py.
// =====================================================================================================

// ---- R1/R8 GatewayDecision optional fields (vectors/gateway/cases.json optional_fields{}) ---------

private fun runOptionalFields(json: String) {
    val of = gObjBlock(json, "optional_fields")

    // with_ordering: field 5 present (single-boundary), field 6 absent.
    val wo = gObjBlock(of, "with_ordering")
    val woOrd = gObjBlock(wo, "ordering")
    val ordWo = Gateway.OrderingDisclosure(gIntField(woOrd, "basis"), boundary = Hex.decode(gField(woOrd, "boundary_hex")))
    val dWo = Gateway.GatewayDecision(
        gIntField(wo, "decision"), Hex.decode(gField(wo, "action_hex")), Hex.decode(gField(wo, "policy_hex")),
        gIntField(wo, "effect"), ordWo, null
    )
    gCheck("with_ordering body == oracle", Hex.encode(dWo.bytes()), gField(wo, "body_hex"))
    gCheck("with_ordering id == oracle", Hex.encode(dWo.id()), gField(wo, "id_hex"))
    val parsedWo = Gateway.parseDecision(Hex.decode(gField(wo, "body_hex")))
    gCheck("with_ordering parsed has ordering", (parsedWo.ordering != null).toString(), "true")
    gCheck("with_ordering parsed has no foreign profile", (parsedWo.foreignProfile == null).toString(), "true")
    gCheck("with_ordering basis", parsedWo.ordering!!.basis.toString(), gIntField(woOrd, "basis").toString())
    gCheck("with_ordering boundary", Hex.encode(parsedWo.ordering!!.boundary), gField(woOrd, "boundary_hex"))
    parsedWo.ordering!!.validate() // no throw

    // with_foreign_profile: field 6 present, field 5 absent.
    val wf = gObjBlock(of, "with_foreign_profile")
    val wfFp = gObjBlock(wf, "foreign_profile")
    val fpWf = Gateway.ForeignProfilePin(gField(wfFp, "id"), gField(wfFp, "revision"))
    val dWf = Gateway.GatewayDecision(
        gIntField(wf, "decision"), Hex.decode(gField(wf, "action_hex")), Hex.decode(gField(wf, "policy_hex")),
        gIntField(wf, "effect"), null, fpWf
    )
    gCheck("with_foreign_profile body == oracle", Hex.encode(dWf.bytes()), gField(wf, "body_hex"))
    gCheck("with_foreign_profile id == oracle", Hex.encode(dWf.id()), gField(wf, "id_hex"))
    val parsedWf = Gateway.parseDecision(Hex.decode(gField(wf, "body_hex")))
    gCheck("with_foreign_profile parsed has no ordering", (parsedWf.ordering == null).toString(), "true")
    gCheck("with_foreign_profile parsed has foreign profile", (parsedWf.foreignProfile != null).toString(), "true")
    gCheck("with_foreign_profile id field", parsedWf.foreignProfile!!.id, gField(wfFp, "id"))
    gCheck("with_foreign_profile revision field", parsedWf.foreignProfile!!.revision, gField(wfFp, "revision"))
    parsedWf.foreignProfile!!.validate() // no throw

    // with_both: field 5 (external-mechanism, with relation) AND field 6 both present.
    val wb = gObjBlock(of, "with_both")
    val wbOrd = gObjBlock(wb, "ordering")
    val wbFp = gObjBlock(wb, "foreign_profile")
    val ordWb = Gateway.OrderingDisclosure(
        gIntField(wbOrd, "basis"),
        mechanism = Hex.decode(gField(wbOrd, "mechanism_hex")),
        relation = Hex.decode(gField(wbOrd, "relation_hex"))
    )
    val fpWb = Gateway.ForeignProfilePin(gField(wbFp, "id"), gField(wbFp, "revision"))
    val dWb = Gateway.GatewayDecision(
        gIntField(wb, "decision"), Hex.decode(gField(wb, "action_hex")), Hex.decode(gField(wb, "policy_hex")),
        gIntField(wb, "effect"), ordWb, fpWb
    )
    gCheck("with_both body == oracle", Hex.encode(dWb.bytes()), gField(wb, "body_hex"))
    gCheck("with_both id == oracle", Hex.encode(dWb.id()), gField(wb, "id_hex"))
    val parsedWb = Gateway.parseDecision(Hex.decode(gField(wb, "body_hex")))
    gCheck("with_both parsed has ordering", (parsedWb.ordering != null).toString(), "true")
    gCheck("with_both parsed has foreign profile", (parsedWb.foreignProfile != null).toString(), "true")
    parsedWb.ordering!!.validate()
    parsedWb.foreignProfile!!.validate()
    val seedWb = gSeed(0x71)
    val pkWb = Cose.mldsaKeygen("ML-DSA-65", seedWb)
    val objWb = Gateway.signDecision(dWb, Cose.ALG_MLDSA65, seedWb)
    gCheck(
        "with_both verifies end-to-end",
        gErrKind { Gateway.verifyDecision(objWb, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pkWb) },
        "no-error"
    )

    // foreign_profile_malformed: field 6 present but omits key 2 (revision). parseDecision decodes it
    // structurally fine; ForeignProfilePin.validate()/verifyDecision reject it.
    val fpm = gObjBlock(of, "foreign_profile_malformed")
    val fpmBody = Hex.decode(gField(fpm, "body_hex"))
    val parsedFpm = Gateway.parseDecision(fpmBody)
    gCheck("foreign_profile_malformed parsed has foreign profile", (parsedFpm.foreignProfile != null).toString(), "true")
    gCheck("foreign_profile_malformed validate rejected", gErrKind { parsedFpm.foreignProfile!!.validate() }, "ForeignProfileMalformed")
    val seedFpm = gSeed(0x72)
    val pkFpm = Cose.mldsaKeygen("ML-DSA-65", seedFpm)
    val objFpm = Cose.coseSign1(Cose.ALG_MLDSA65, seedFpm, Gateway.gatewayProtectedHeader(Cose.ALG_MLDSA65), fpmBody)
    gCheck(
        "foreign_profile_malformed verify rejected",
        gErrKind { Gateway.verifyDecision(objFpm, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pkFpm) },
        "ForeignProfileMalformed"
    )

    // ordering_malformed: field 5 basis=external-mechanism but key 2 (boundary) is ALSO present.
    val om = gObjBlock(of, "ordering_malformed")
    val omBody = Hex.decode(gField(om, "body_hex"))
    val parsedOm = Gateway.parseDecision(omBody)
    gCheck("ordering_malformed parsed has ordering", (parsedOm.ordering != null).toString(), "true")
    gCheck("ordering_malformed validate rejected", gErrKind { parsedOm.ordering!!.validate() }, "OrderingDisclosureMalformed")
    val seedOm = gSeed(0x73)
    val pkOm = Cose.mldsaKeygen("ML-DSA-65", seedOm)
    val objOm = Cose.coseSign1(Cose.ALG_MLDSA65, seedOm, Gateway.gatewayProtectedHeader(Cose.ALG_MLDSA65), omBody)
    gCheck(
        "ordering_malformed verify rejected",
        gErrKind { Gateway.verifyDecision(objOm, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pkOm) },
        "OrderingDisclosureMalformed"
    )

    // ForeignProfilePin.validate() direct unit tests (no oracle vector needed).
    gCheck("fp both present validates", gErrKind { Gateway.ForeignProfilePin("https://example.test/p", "1").validate() }, "no-error")
    gCheck("fp missing id rejected", gErrKind { Gateway.ForeignProfilePin("", "1").validate() }, "ForeignProfileMalformed")
    gCheck(
        "fp missing revision rejected",
        gErrKind { Gateway.ForeignProfilePin("https://example.test/p", "").validate() },
        "ForeignProfileMalformed"
    )
    gCheck("fp both empty rejected", gErrKind { Gateway.ForeignProfilePin("", "").validate() }, "ForeignProfileMalformed")

    // foreign profile extra key rejected: a field-6 map carrying a THIRD key (3) beyond {1,2} decodes
    // structurally (the extra key does not fail decode) but fails validate().
    val fpExtra = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.T("https://example-registry.test/profiles/acme")),
            Cbor.Pair(Cbor.U(2), Cbor.T("2026-01")),
            Cbor.Pair(Cbor.U(3), Cbor.T("unexpected"))
        )
    )
    val mExtra = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.U(Gateway.DECISION_ALLOW)),
            Cbor.Pair(Cbor.U(2), Cbor.B(Hex.decode(gField(json, "action_cid_hex")))),
            Cbor.Pair(Cbor.U(3), Cbor.B(Hex.decode(gField(json, "policy_hex")))),
            Cbor.Pair(Cbor.U(4), Cbor.U(1)),
            Cbor.Pair(Cbor.U(6), fpExtra)
        )
    )
    val extraBody = Cbor.encode(mExtra)
    val parsedExtra = Gateway.parseDecision(extraBody)
    gCheck("fp extra key parsed has foreign profile", (parsedExtra.foreignProfile != null).toString(), "true")
    gCheck("fp extra key id field", parsedExtra.foreignProfile!!.id, "https://example-registry.test/profiles/acme")
    gCheck("fp extra key revision field", parsedExtra.foreignProfile!!.revision, "2026-01")
    gCheck("fp extra key validate rejected", gErrKind { parsedExtra.foreignProfile!!.validate() }, "ForeignProfileMalformed")
}

// ---- S1 naalp-decision-record (vectors/decision_record/cases.json) --------------------------------

/** Reconstructs a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
 * fixture, mirroring decision_record_test.go's build() switch / GatewayKatTest.java's buildRecord()
 * exactly. */
private fun gBuildRecord(name: String, rv: String): Gateway.DecisionRecord {
    val action = Hex.decode(gField(rv, "action_hex"))
    val governing = gHexArrayField(rv, "governing_hex")
    val outcome = gIntField(rv, "outcome")
    val consume = gConsumeHexField(rv)
    var terms: Map<Long, Gateway.TermDisposition> = emptyMap()
    var enforcement = 0L
    val ordering: Gateway.OrderingDisclosure = when (name) {
        "allow_consuming", "allow_no_consume", "minimal", "correspondence_only" ->
            Gateway.correspondenceOnly()
        "deny_two_governing" ->
            Gateway.OrderingDisclosure(Gateway.ORDERING_SINGLE_BOUNDARY, boundary = "boundary-signer-X".toByteArray(Charsets.UTF_8))
        "hold_empty_governing", "external_mechanism" ->
            Gateway.OrderingDisclosure(
                Gateway.ORDERING_EXTERNAL_MECHANISM,
                mechanism = "external-log:acme-transparency-v1".toByteArray(Charsets.UTF_8),
                relation = Hex.decode("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56")
            )
        "single_boundary" ->
            Gateway.OrderingDisclosure(Gateway.ORDERING_SINGLE_BOUNDARY, boundary = "SIGNER_B-boundary".toByteArray(Charsets.UTF_8))
        "external_mechanism_no_relation" ->
            Gateway.OrderingDisclosure(
                Gateway.ORDERING_EXTERNAL_MECHANISM,
                mechanism = "external-log:acme-transparency-v1".toByteArray(Charsets.UTF_8)
            )
        "terms_valid" -> {
            terms = mapOf(
                1L to Gateway.TermDisposition(Gateway.TERM_OBSERVED),
                4L to Gateway.TermDisposition(Gateway.TERM_REPORTED, "boundary:relay-partner-3".toByteArray(Charsets.UTF_8))
            )
            Gateway.correspondenceOnly()
        }
        "enforcement_enforced" -> {
            enforcement = Gateway.ENFORCEMENT_ENFORCED
            Gateway.correspondenceOnly()
        }
        "enforcement_advised" -> {
            enforcement = Gateway.ENFORCEMENT_ADVISED
            Gateway.correspondenceOnly()
        }
        else -> throw AssertionError("unhandled record name $name -- add its ordering/terms/enforcement fixture")
    }
    return Gateway.DecisionRecord(action, governing, outcome, ordering, consume, terms, enforcement)
}

/** The named kind thrown by parseDecisionRecord/validateDecisionRecord on [body], or "". */
private fun gDrRejectKind(body: ByteArray): String = try {
    val d = Gateway.parseDecisionRecord(body)
    try {
        Gateway.validateDecisionRecord(d)
        ""
    } catch (e: NaalpException) {
        e.kind
    }
} catch (e: NaalpException) {
    e.kind
}

private fun runDecisionRecord() {
    val json = gFindVectorNamed("decision_record").readText(Charsets.UTF_8)

    // 1. the closed outcome vocabulary (reuses Gateway's gw-decision accessors) + ordering-basis
    //    vocabulary are registered.
    for (vb in gObjectBlocks(json, "outcome_vocabulary")) {
        val name = gField(vb, "name")
        val code = gIntField(vb, "code")
        gCheck("dr outcome vocab $name known", Gateway.isKnownDecision(code).toString(), "true")
        gCheck("dr outcome vocab $name name", Gateway.decisionName(code), name)
    }
    for (vb in gObjectBlocks(json, "ordering_basis_vocabulary")) {
        val name = gField(vb, "name")
        val code = gIntField(vb, "code")
        gCheck("dr ordering vocab $name known", Gateway.isKnownOrderingBasis(code).toString(), "true")
        gCheck("dr ordering vocab $name name", Gateway.orderingBasisName(code), name)
    }
    gCheck("dr unknown ordering basis 99 not known", Gateway.isKnownOrderingBasis(99).toString(), "false")

    // 2. every records{}/ordering_examples{} case: body/head/id == oracle, byte-for-byte; the parse
    //    round-trip re-encodes to the SAME canonical bytes; every case is POSITIVE.
    val recordsBlock = gObjBlock(json, "records")
    val orderingExamplesBlock = gObjBlock(json, "ordering_examples")
    val records = gNamedObjectBlocks(recordsBlock)
    val orderingExamples = gNamedObjectBlocks(orderingExamplesBlock)
    val allCases = LinkedHashMap<String, String>()
    allCases.putAll(records)
    allCases.putAll(orderingExamples)
    gCheck(
        "dr records/ordering_examples no name collision",
        allCases.size.toString(),
        (records.size + orderingExamples.size).toString()
    )
    for ((name, rv) in allCases) {
        val d = gBuildRecord(name, rv)
        gCheck("dr $name body == oracle", Hex.encode(d.bytes()), gField(rv, "body_hex"))
        gCheck("dr $name head == oracle", Hex.encode(d.head()), gField(rv, "head_hex"))
        gCheck("dr $name id == oracle", Hex.encode(d.id()), gField(rv, "id_hex"))
        val parsed = Gateway.parseDecisionRecord(d.bytes())
        gCheck("dr $name round-trip", Hex.encode(parsed.bytes()), gField(rv, "body_hex"))
        Gateway.validateDecisionRecord(parsed) // every records/ordering_examples case is POSITIVE
    }

    // 3. minimal, built directly (mandatory-field-only shell).
    val minB = records.getValue("minimal")
    val minimal = Gateway.DecisionRecord(
        Hex.decode(gField(minB, "action_hex")), gHexArrayField(minB, "governing_hex"), gIntField(minB, "outcome"),
        Gateway.correspondenceOnly()
    )
    gCheck("dr minimal direct body == oracle", Hex.encode(minimal.bytes()), gField(minB, "body_hex"))
    gCheck("dr minimal direct id == oracle", Hex.encode(minimal.id()), gField(minB, "id_hex"))
    Gateway.validateDecisionRecord(Gateway.parseDecisionRecord(minimal.bytes()))

    // 4. named negative rejections.
    val neg = gObjBlock(json, "negative")
    for (name in listOf(
        "deny_with_consume_rejected", "hold_with_consume_rejected",
        "terms_key_outside_field_set_rejected", "unknown_outcome_rejected", "look_alike"
    )) {
        val c = gObjBlock(neg, name)
        gCheck("dr negative $name", gDrRejectKind(Hex.decode(gField(c, "body_hex"))), gField(c, "reject"))
    }
    for ((key, value) in gNamedObjectBlocks(gObjBlock(neg, "ordering_malformed"))) {
        gCheck("dr ordering_malformed.$key", gDrRejectKind(Hex.decode(gField(value, "body_hex"))), gField(value, "reject"))
    }

    // keys_out_of_order: canonical decodes+validates cleanly; the descending-key body is rejected at
    // the CBOR layer (NonCanonical) before parseDecisionRecord's own checks run.
    val koo = gObjBlock(neg, "keys_out_of_order")
    Gateway.validateDecisionRecord(Gateway.parseDecisionRecord(Hex.decode(gField(koo, "canonical_body_hex"))))
    val kooCborKind = try {
        Cbor.decode(Hex.decode(gField(koo, "noncanonical_body_hex")))
        "decoded"
    } catch (e: NaalpException) {
        e.kind
    }
    gCheck("dr keys_out_of_order cbor-rejected", kooCborKind, "NonCanonical")
    gCheck(
        "dr keys_out_of_order parse-rejected",
        gDrRejectKind(Hex.decode(gField(koo, "noncanonical_body_hex"))),
        "DecisionMalformed"
    )

    // 5. third-party re-serve, using allow_consuming.
    val allowConsuming = records.getValue("allow_consuming")
    val acRecord = gBuildRecord("allow_consuming", allowConsuming)
    gCheck("dr allow_consuming body == oracle (re-check)", Hex.encode(acRecord.bytes()), gField(allowConsuming, "body_hex"))
    val seedProducer = gSeed(0x71)
    val seedForeign = gSeed(0x72)
    val producerPk = Cose.mldsaKeygen("ML-DSA-65", seedProducer)
    val foreignPk = Cose.mldsaKeygen("ML-DSA-65", seedForeign)
    val drObj = Gateway.signDecisionRecord(acRecord, Cose.ALG_MLDSA65, seedProducer)
    val byProducer = Gateway.verifyDecisionRecord(drObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, producerPk)
    val byThirdParty = Gateway.verifyDecisionRecord(drObj.copyOf(), Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, producerPk)
    gCheck("dr third-party action match", Hex.encode(byProducer.action), Hex.encode(byThirdParty.action))
    gCheck("dr third-party outcome allow", byThirdParty.outcome.toString(), Gateway.DECISION_ALLOW.toString())
    gCheck("dr third-party consume == oracle", Hex.encode(byThirdParty.consume), gField(allowConsuming, "consume_hex"))
    gCheck(
        "dr foreign key rejected",
        gErrKind { Gateway.verifyDecisionRecord(drObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, foreignPk) },
        "BadSignature"
    )

    // 6. sign/verify terms_valid end-to-end, exercising the terms map on the round trip.
    val termsValid = records.getValue("terms_valid")
    val tvRecord = gBuildRecord("terms_valid", termsValid)
    val tvSeed = gSeed(0x11)
    val tvPk = Cose.mldsaKeygen("ML-DSA-65", tvSeed)
    val tvObj = Gateway.signDecisionRecord(tvRecord, Cose.ALG_MLDSA65, tvSeed)
    val tvResolved = Gateway.verifyDecisionRecord(tvObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, tvPk)
    gCheck("dr terms_valid resolved terms[1].kind", tvResolved.terms.getValue(1L).kind.toString(), Gateway.TERM_OBSERVED.toString())
    gCheck("dr terms_valid resolved terms[4].kind", tvResolved.terms.getValue(4L).kind.toString(), Gateway.TERM_REPORTED.toString())
    gCheck(
        "dr terms_valid resolved terms[4].source",
        String(tvResolved.terms.getValue(4L).source, Charsets.UTF_8),
        "boundary:relay-partner-3"
    )
}

// ---- S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof -----------------------

private fun gCpFrom(cv: String): Gateway.CheckpointRoot = Gateway.CheckpointRoot(
    Hex.decode(gField(cv, "log_hex")), gIntField(cv, "size"), Hex.decode(gField(cv, "root_hex")),
    Hex.decode(gField(cv, "prev_hex")), gLongField(cv, "at_str")
)

private fun gWcFrom(wv: String): Gateway.WitnessCosign = Gateway.WitnessCosign(
    Hex.decode(gField(wv, "witness_hex")), Hex.decode(gField(wv, "root_hex")), gLongField(wv, "at_str")
)

private fun gCpRejectKind(body: ByteArray): String = try {
    Gateway.parseCheckpointRoot(body)
    "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun runCheckpoint() {
    val json = gFindVectorNamed("checkpoint").readText(Charsets.UTF_8)

    gCheck("cp genesisPrev == oracle", Hex.encode(Gateway.genesisPrev()), gField(gObjBlock(json, "genesis"), "prev_hex"))

    val checkpointsBlock = gObjBlock(json, "checkpoints")
    val checkpoints = gNamedObjectBlocks(checkpointsBlock)
    for ((name, cv) in checkpoints) {
        val c = gCpFrom(cv)
        gCheck("cp $name body == oracle", Hex.encode(c.bytes()), gField(cv, "body_hex"))
        gCheck("cp $name head == oracle", Hex.encode(c.head()), gField(cv, "head_hex"))
        gCheck("cp $name id == oracle", Hex.encode(c.id()), gField(cv, "id_hex"))
        gCheck("cp $name round-trip", Hex.encode(Gateway.parseCheckpointRoot(c.bytes()).bytes()), gField(cv, "body_hex"))
    }

    val witnesses = gNamedObjectBlocks(gObjBlock(json, "witness_cosigns"))
    for ((name, wv) in witnesses) {
        val w = gWcFrom(wv)
        gCheck("wc $name body == oracle", Hex.encode(w.bytes()), gField(wv, "body_hex"))
        gCheck("wc $name head == oracle", Hex.encode(w.head()), gField(wv, "head_hex"))
        gCheck("wc $name id == oracle", Hex.encode(w.id()), gField(wv, "id_hex"))
    }

    // fork evidence: two witness-cosigned roots at the SAME (log, size) carrying DIFFERENT root
    // values -- the log has signed two incompatible histories, and both signatures are the proof.
    val fe = gObjBlock(json, "fork_evidence")
    val cpABlock = gObjBlock(fe, "checkpoint_a")
    val cpBBlock = gObjBlock(fe, "checkpoint_b")
    gCheck("fork roots distinct", (gField(cpABlock, "root_hex") != gField(cpBBlock, "root_hex")).toString(), "true")
    gCheck("fork ids distinct", (gField(cpABlock, "id_hex") != gField(cpBBlock, "id_hex")).toString(), "true")
    val wcABlock = gObjBlock(cpABlock, "witness_cosign")
    val wcBBlock = gObjBlock(cpBBlock, "witness_cosign")
    val wcA = gWcFrom(wcABlock)
    val wcB = gWcFrom(wcBBlock)
    gCheck("fork wcA body == oracle", Hex.encode(wcA.bytes()), gField(wcABlock, "body_hex"))
    gCheck("fork wcB body == oracle", Hex.encode(wcB.bytes()), gField(wcBBlock, "body_hex"))
    val idA = Hex.decode(gField(cpABlock, "id_hex"))
    val idB = Hex.decode(gField(cpBBlock, "id_hex"))
    gCheck("fork wcA validates against A", gErrKind { Gateway.validateWitnessCosign(wcA, idA) }, "no-error")
    gCheck("fork wcB validates against B", gErrKind { Gateway.validateWitnessCosign(wcB, idB) }, "no-error")
    gCheck("fork wcA rejected against B", gErrKind { Gateway.validateWitnessCosign(wcA, idB) }, "WitnessRootMismatch")
    gCheck("fork wcB rejected against A", gErrKind { Gateway.validateWitnessCosign(wcB, idA) }, "WitnessRootMismatch")

    // inclusion proofs, each checked against its named checkpoint's resolved id/size/root.
    val checkpointFor = mapOf(
        "leaf3_of7" to "checkpoint0_size7",
        "leaf7_of8_newly_appended" to "checkpoint1_size8",
        "single_leaf_tree_empty_path" to "checkpoint_single_leaf"
    )
    val inclusionProofs = gNamedObjectBlocks(gObjBlock(json, "inclusion_proofs"))
    for ((name, iv) in inclusionProofs) {
        val cp = checkpoints.getValue(checkpointFor.getValue(name))
        gCheck("ip $name root matches checkpoint id", Hex.encode(gCpFrom(cp).id()), gField(iv, "root_hex"))

        val p = Gateway.InclusionProof(
            Hex.decode(gField(iv, "root_hex")), Hex.decode(gField(iv, "leaf_hex")), gIntField(iv, "index"),
            gHexArrayField(iv, "path_hex")
        )
        gCheck("ip $name body == oracle", Hex.encode(p.bytes()), gField(iv, "body_hex"))
        gCheck("ip $name head == oracle", Hex.encode(p.head()), gField(iv, "head_hex"))
        gCheck("ip $name id == oracle", Hex.encode(p.id()), gField(iv, "id_hex"))
        val parsed = Gateway.parseInclusionProof(p.bytes())
        val cpSize = gIntField(cp, "size")
        val cpRoot = Hex.decode(gField(cp, "root_hex"))
        gCheck(
            "ip $name verify",
            gErrKind { Gateway.verifyInclusionProof(parsed.leaf, parsed.index, cpSize, parsed.path, cpRoot) },
            "no-error"
        )
    }

    // negative: wrong index / wrong path / witness-root-mismatch / checkpoint malformed.
    val neg = gObjBlock(json, "negative")
    val cp0 = checkpoints.getValue("checkpoint0_size7")
    val root0 = Hex.decode(gField(cp0, "root_hex"))
    val size0 = gIntField(cp0, "size")

    val wi = gObjBlock(neg, "inclusion_wrong_index")
    val wiPath = gHexArrayField(wi, "path_hex")
    val wiLeaf = Hex.decode(gField(wi, "leaf_hex"))
    val wiIndex = gIntField(wi, "claimed_index")
    gCheck(
        "cp wrong index rejected",
        gErrKind { Gateway.verifyInclusionProof(wiLeaf, wiIndex, size0, wiPath, root0) },
        "InclusionProofInvalid"
    )

    val wp = gObjBlock(neg, "inclusion_wrong_path")
    val wpPath = gHexArrayField(wp, "path_hex")
    val wpLeaf = Hex.decode(gField(wp, "leaf_hex"))
    val wpIndex = gIntField(wp, "index")
    gCheck(
        "cp wrong path rejected",
        gErrKind { Gateway.verifyInclusionProof(wpLeaf, wpIndex, size0, wpPath, root0) },
        "InclusionProofInvalid"
    )

    val wm = gObjBlock(neg, "witness_root_mismatch")
    val wParsed = Gateway.parseWitnessCosign(Hex.decode(gField(wm, "cosign_body_hex")))
    gCheck("wm cosign root == oracle", Hex.encode(wParsed.root), gField(wm, "cosign_names_root_hex"))
    val wmAccompaniedId = Hex.decode(gField(wm, "checkpoint_accompanied_id_hex"))
    gCheck("wm rejected", gErrKind { Gateway.validateWitnessCosign(wParsed, wmAccompaniedId) }, gField(wm, "reject"))

    val ckoo = gObjBlock(neg, "checkpoint_keys_out_of_order")
    Gateway.parseCheckpointRoot(Hex.decode(gField(ckoo, "canonical_body_hex"))) // should parse
    val ckooCborKind = try {
        Cbor.decode(Hex.decode(gField(ckoo, "noncanonical_body_hex")))
        "decoded"
    } catch (e: NaalpException) {
        e.kind
    }
    gCheck("cp keys_out_of_order cbor-rejected", ckooCborKind, "NonCanonical")
    gCheck(
        "cp keys_out_of_order parse-rejected",
        gCpRejectKind(Hex.decode(gField(ckoo, "noncanonical_body_hex"))),
        "CheckpointMalformed"
    )

    val cmf = gObjBlock(neg, "checkpoint_missing_field")
    gCheck("cp missing field rejected", gCpRejectKind(Hex.decode(gField(cmf, "body_hex"))), gField(cmf, "reject"))

    // MTH({}) = HASH() -- the empty-list base case.
    val etk = gObjBlock(json, "empty_tree_kat")
    gCheck("cp merkleRoot(null) == oracle", Hex.encode(Gateway.merkleRoot(null)), gField(etk, "root_hex"))
    gCheck("cp merkleRoot([]) == oracle", Hex.encode(Gateway.merkleRoot(emptyList())), gField(etk, "root_hex"))

    // RFC 9162 self-fidelity: independently re-derives PATH()/recompute over SYNTHETIC leaves (never
    // the oracle's own numbers), catching an algorithmic defect the n in {1,7,8} byte-parity vectors
    // above do not reach.
    var total = 0
    for (n in 1..12) {
        val leaves = (0 until n).map { "synthetic-leaf-$it".toByteArray(Charsets.UTF_8) }
        val root = Gateway.merkleRoot(leaves)
        for (m in 0 until n) {
            val path = Gateway.generateInclusionProofPath(leaves, m)
            Gateway.verifyInclusionProof(leaves[m], m.toLong(), n.toLong(), path, root) // no throw
            total++
        }
    }
    gCheck("cp rfc9162 self-fidelity total (sum 1..12)", total.toString(), "78")

    val leaves5 = (0 until 5).map { "synthetic-leaf-$it".toByteArray(Charsets.UTF_8) }
    val root5 = Gateway.merkleRoot(leaves5)
    val path2 = Gateway.generateInclusionProofPath(leaves5, 2)
    gCheck(
        "cp tampered leaf rejected",
        gErrKind { Gateway.verifyInclusionProof("tampered-leaf".toByteArray(Charsets.UTF_8), 2L, 5L, path2, root5) },
        "InclusionProofInvalid"
    )

    // sign/verify in isolation (NOT corpus-graded: the corpus carries no signed COSE vector).
    val cp0Obj = gCpFrom(cp0)
    val cpSeed = gSeed(0x11)
    val cpPk = Cose.mldsaKeygen("ML-DSA-65", cpSeed)
    val cpObj = Gateway.signCheckpointRoot(cp0Obj, Cose.ALG_MLDSA65, cpSeed)
    val cpParts = Cose.parseSign1Raw(cpObj)
    gCheck(
        "cp sign/verify in isolation",
        Cose.coseVerify1Raw(Cose.ALG_MLDSA65, cpPk, Cose.toBeSignedRaw(cpParts[0], cpParts[1]), cpParts[2]).toString(),
        "true"
    )
    gCheck("cp sign payload == body", Hex.encode(cpParts[1]), Hex.encode(cp0Obj.bytes()))
}

// ---- E6.3 naalp-egress-attestation ------------------------------------------------------------------

private fun gAttFrom(av: String): Gateway.EgressAttestation = Gateway.EgressAttestation(
    gIntField(av, "binding"), Hex.decode(gField(av, "digest_hex")), gIntField(av, "effect"),
    Hex.decode(gField(av, "audience_hex")), gLongField(av, "at_str")
)

private fun gEgRejectKind(body: ByteArray): String = try {
    val a = Gateway.parseEgressAttestation(body)
    try {
        Gateway.validateEgressAttestation(a)
        ""
    } catch (e: NaalpException) {
        e.kind
    }
} catch (e: NaalpException) {
    e.kind
}

/** Mirrors TestEgressVendorOnlyMutation: the honest verifyEgressAttestation takes NO serving-party
 * identity, so a mutant "vendor-only" verifier that additionally requires servingParty == gatewayId
 * wrongly rejects a third party re-serving the identical bytes. */
private fun gMutantVerify(obj: ByteArray, gwPk: ByteArray, gatewayId: ByteArray, servingParty: ByteArray) {
    Gateway.verifyEgressAttestation(obj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)
    if (!servingParty.contentEquals(gatewayId)) {
        throw NaalpException("EgMalformed", "stands in for a not-served-by-vendor rejection")
    }
}

private fun runEgressAttestation() {
    val json = gFindVectorNamed("egress_attestation").readText(Charsets.UTF_8)

    val attestations = gNamedObjectBlocks(gObjBlock(json, "attestations"))
    for ((name, av) in attestations) {
        val a = gAttFrom(av)
        gCheck("eg $name body == oracle", Hex.encode(a.bytes()), gField(av, "body_hex"))
        gCheck("eg $name head == oracle", Hex.encode(a.head()), gField(av, "head_hex"))
        gCheck("eg $name id == oracle", Hex.encode(a.id()), gField(av, "id_hex"))
    }
    for (vb in gObjectBlocks(json, "binding_vocabulary")) {
        val name = gField(vb, "name")
        val code = gIntField(vb, "code")
        gCheck("eg binding vocab $name known", Gateway.isKnownBinding(code).toString(), "true")
        gCheck("eg binding vocab $name name", Gateway.bindingName(code), name)
    }
    val unknownBinding = gIntField(json, "unknown_binding")
    gCheck("eg unknown binding not known", Gateway.isKnownBinding(unknownBinding).toString(), "false")

    // oversized counter: at = 2^64-1, carried as a decimal string so no float64 decoder rounds it.
    val ec = gObjBlock(json, "edge_cases")
    val ov = gObjBlock(ec, "oversized_counter")
    gCheck("eg oversized at_str", gField(ov, "at_str"), "18446744073709551615")
    val oversized = gAttFrom(ov)
    gCheck("eg oversized at == 2^64-1", java.lang.Long.toUnsignedString(oversized.at), "18446744073709551615")
    gCheck("eg oversized body == oracle", Hex.encode(oversized.bytes()), gField(ov, "body_hex"))
    gCheck(
        "eg oversized parsed at",
        java.lang.Long.toUnsignedString(Gateway.parseEgressAttestation(oversized.bytes()).at),
        java.lang.Long.toUnsignedString(oversized.at)
    )

    // third-party re-serve.
    val seedGw = gSeed(0x61)
    val seedForeign = gSeed(0x62)
    val gwPk = Cose.mldsaKeygen("ML-DSA-65", seedGw)
    val foreignPk = Cose.mldsaKeygen("ML-DSA-65", seedForeign)
    val cb = gAttFrom(attestations.getValue("content_bound"))
    val egObj = Gateway.signEgressAttestation(cb, Cose.ALG_MLDSA65, seedGw)
    val byGateway = Gateway.verifyEgressAttestation(egObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)
    val byThirdParty = Gateway.verifyEgressAttestation(egObj.copyOf(), Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk)
    gCheck("eg re-serve binding match", byGateway.binding.toString(), byThirdParty.binding.toString())
    gCheck("eg re-serve digest match", Hex.encode(byGateway.digest), Hex.encode(byThirdParty.digest))
    gCheck("eg re-serve effect match", byGateway.effect.toString(), byThirdParty.effect.toString())
    gCheck("eg re-serve audience match", Hex.encode(byGateway.audience), Hex.encode(byThirdParty.audience))
    gCheck("eg re-serve at match", java.lang.Long.toUnsignedString(byGateway.at), java.lang.Long.toUnsignedString(byThirdParty.at))
    gCheck("eg re-serve binding content_bound", byThirdParty.binding.toString(), Gateway.BINDING_CONTENT_BOUND.toString())
    gCheck("eg re-serve digest == object cid", Hex.encode(byThirdParty.digest), gField(json, "object_cid_hex"))
    gCheck(
        "eg foreign key rejected",
        gErrKind { Gateway.verifyEgressAttestation(egObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, foreignPk) },
        "BadSignature"
    )

    val bad = Gateway.EgressAttestation(unknownBinding, Hex.decode(gField(json, "object_cid_hex")), 0, Hex.decode(gField(json, "audience_hex")), 0)
    val badObj = Gateway.signEgressAttestation(bad, Cose.ALG_MLDSA65, seedGw)
    gCheck(
        "eg unknown binding rejected",
        gErrKind { Gateway.verifyEgressAttestation(badObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk) },
        "UnknownEgressBinding"
    )

    // vendor-only mutation.
    val gatewayId = "gateway-id-0x61".toByteArray(Charsets.UTF_8)
    val thirdPartyId = "did:example:mirror-cache".toByteArray(Charsets.UTF_8)
    val cf = gAttFrom(attestations.getValue("content_free"))
    val cfObj = Gateway.signEgressAttestation(cf, Cose.ALG_MLDSA65, seedGw)
    Gateway.verifyEgressAttestation(cfObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, gwPk) // honest: no throw
    gCheck("eg vendor-only mutant accepts vendor", gErrKind { gMutantVerify(cfObj, gwPk, gatewayId, gatewayId) }, "no-error")
    gCheck("eg vendor-only mutant rejects third party", gErrKind { gMutantVerify(cfObj, gwPk, gatewayId, thirdPartyId) }, "EgMalformed")

    // content_free commitment open/verify pair.
    val co = gObjBlock(json, "commitment_open")
    val cfForCommit = gAttFrom(attestations.getValue("content_free"))
    gCheck("eg commitment digest == oracle", Hex.encode(cfForCommit.digest), gField(co, "commitment_hex"))
    val objectCid = Hex.decode(gField(co, "object_cid_hex"))
    val wrongObjectCid = Hex.decode(gField(co, "wrong_object_cid_hex"))
    val salt = Hex.decode(gField(co, "salt_hex"))
    val wrongSalt = Hex.decode(gField(co, "wrong_salt_hex"))
    gCheck("eg egressCommit == oracle", Hex.encode(Gateway.egressCommit(objectCid, salt)), gField(co, "commitment_hex"))
    gCheck("eg open commitment true", Gateway.openEgressCommitment(cfForCommit, objectCid, salt).toString(), "true")
    gCheck("eg open commitment wrong salt false", Gateway.openEgressCommitment(cfForCommit, objectCid, wrongSalt).toString(), "false")
    gCheck("eg open commitment wrong cid false", Gateway.openEgressCommitment(cfForCommit, wrongObjectCid, salt).toString(), "false")
    gCheck(
        "eg open commitment wrong both false",
        Gateway.openEgressCommitment(cfForCommit, wrongObjectCid, wrongSalt).toString(),
        "false"
    )
    val cbForCommit = gAttFrom(attestations.getValue("content_bound"))
    gCheck("eg content_bound never opens", Gateway.openEgressCommitment(cbForCommit, objectCid, salt).toString(), "false")

    // keys_out_of_order.
    val koo = gObjBlock(ec, "keys_out_of_order")
    val kooAtt = gAttFrom(koo)
    gCheck("eg koo body == oracle", Hex.encode(kooAtt.bytes()), gField(koo, "canonical_body_hex"))
    val canon = Hex.decode(gField(koo, "canonical_body_hex"))
    val noncanon = Hex.decode(gField(koo, "noncanonical_body_hex"))
    Cbor.decode(canon) // should decode
    Gateway.parseEgressAttestation(canon) // should parse
    val kooCborKind = try {
        Cbor.decode(noncanon)
        "decoded"
    } catch (e: NaalpException) {
        e.kind
    }
    gCheck("eg koo cbor-rejected", kooCborKind, "NonCanonical")
    gCheck("eg koo parse-rejected", gEgRejectKind(noncanon), "EgMalformed")

    // empty-vs-absent audience.
    val eva = gObjBlock(ec, "empty_vs_absent")
    val objectCidBytes = Hex.decode(gField(json, "object_cid_hex"))
    val emptyAudBlock = gObjBlock(eva, "empty_audience")
    val populatedAudBlock = gObjBlock(eva, "populated_audience")
    val emptyAud = Gateway.EgressAttestation(Gateway.BINDING_CONTENT_BOUND, objectCidBytes, 1, ByteArray(0), 1735689600000L)
    val populatedAud = Gateway.EgressAttestation(
        Gateway.BINDING_CONTENT_BOUND, objectCidBytes, 1, Hex.decode(gField(populatedAudBlock, "audience_hex")), 1735689600000L
    )
    gCheck("eg empty audience body == oracle", Hex.encode(emptyAud.bytes()), gField(emptyAudBlock, "body_hex"))
    gCheck("eg populated audience body == oracle", Hex.encode(populatedAud.bytes()), gField(populatedAudBlock, "body_hex"))
    gCheck("eg empty vs populated ids distinct", (Hex.encode(emptyAud.id()) != Hex.encode(populatedAud.id())).toString(), "true")
    gCheck("eg empty audience id == oracle", Hex.encode(emptyAud.id()), gField(emptyAudBlock, "id_hex"))
    Gateway.parseEgressAttestation(emptyAud.bytes())
    Gateway.parseEgressAttestation(populatedAud.bytes())
    val absentFieldBlock = gObjBlock(eva, "absent_field")
    gCheck("eg absent audience field rejected", gEgRejectKind(Hex.decode(gField(absentFieldBlock, "body_hex"))), "EgMalformed")

    // minimal.
    val minB = gObjBlock(ec, "minimal")
    val minimal = gAttFrom(minB)
    gCheck("eg minimal body == oracle", Hex.encode(minimal.bytes()), gField(minB, "body_hex"))
    gCheck("eg minimal id == oracle", Hex.encode(minimal.id()), gField(minB, "id_hex"))
    Gateway.parseEgressAttestation(minimal.bytes())
    val minSeed = gSeed(0x63)
    val minPk = Cose.mldsaKeygen("ML-DSA-65", minSeed)
    val minObj = Gateway.signEgressAttestation(minimal, Cose.ALG_MLDSA65, minSeed)
    gCheck(
        "eg minimal verifies end-to-end",
        gErrKind { Gateway.verifyEgressAttestation(minObj, Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, minPk) },
        "no-error"
    )

    // look_alike.
    val la = gObjBlock(ec, "look_alike")
    gCheck("eg look_alike rejected", gEgRejectKind(Hex.decode(gField(la, "body_hex"))), gField(la, "reject"))

    // ordering byte parity.
    for (vb in gObjectBlocks(json, "ordering_basis_vocabulary")) {
        val name = gField(vb, "name")
        val code = gIntField(vb, "code")
        gCheck("eg ordering vocab $name known", Gateway.isKnownOrderingBasis(code).toString(), "true")
        gCheck("eg ordering vocab $name name", Gateway.orderingBasisName(code), name)
    }
    val attestationsWithOrdering = gNamedObjectBlocks(gObjBlock(json, "attestations_with_ordering"))
    for ((name, av) in attestationsWithOrdering) {
        val base = gAttFrom(av)
        val ord = when (name) {
            "correspondence_only" -> Gateway.correspondenceOnly()
            "single_boundary" -> Gateway.OrderingDisclosure(
                Gateway.ORDERING_SINGLE_BOUNDARY,
                boundary = "boundary-signer-X".toByteArray(Charsets.UTF_8)
            )
            "external_mechanism" -> Gateway.OrderingDisclosure(
                Gateway.ORDERING_EXTERNAL_MECHANISM,
                mechanism = "external-log:acme-transparency-v1".toByteArray(Charsets.UTF_8),
                relation = Hex.decode("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56")
            )
            else -> throw AssertionError("unhandled attestations_with_ordering name $name")
        }
        val withOrd = Gateway.EgressAttestation(base.binding, base.digest, base.effect, base.audience, base.at, ord)
        gCheck("eg $name body == oracle", Hex.encode(withOrd.bytes()), gField(av, "body_hex"))
        gCheck("eg $name head == oracle", Hex.encode(withOrd.head()), gField(av, "head_hex"))
        gCheck("eg $name id == oracle", Hex.encode(withOrd.id()), gField(av, "id_hex"))
        val parsed = Gateway.parseEgressAttestation(withOrd.bytes())
        gCheck("eg $name parsed has ordering", (parsed.ordering != null).toString(), "true")
        gCheck("eg $name round-trip", Hex.encode(parsed.bytes()), gField(av, "body_hex"))
        Gateway.validateEgressAttestation(parsed) // no throw
    }
    val plain = Gateway.parseEgressAttestation(gAttFrom(attestations.getValue("content_bound")).bytes())
    gCheck("eg plain has no ordering", (plain.ordering == null).toString(), "true")

    // ordering negative.
    val negOrd = gObjBlock(json, "negative_ordering")
    val sbwm = gObjBlock(negOrd, "ordering_malformed_single_boundary_with_mechanism")
    gCheck("eg ordering malformed sbwm", gEgRejectKind(Hex.decode(gField(sbwm, "body_hex"))), gField(sbwm, "reject"))
    val uob = gObjBlock(negOrd, "unknown_ordering_basis")
    gCheck("eg unknown ordering basis", gEgRejectKind(Hex.decode(gField(uob, "body_hex"))), gField(uob, "reject"))

    // missing at (field 5) -- fields 1-4 correctly typed, field 5 absent.
    val missingAt = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.U(Gateway.BINDING_CONTENT_BOUND)),
            Cbor.Pair(Cbor.U(2), Cbor.B(byteArrayOf(0x20, 0x30))),
            Cbor.Pair(Cbor.U(3), Cbor.U(1)),
            Cbor.Pair(Cbor.U(4), Cbor.B(ByteArray(0)))
        )
    )
    gCheck("eg missing at field rejected", gEgRejectKind(Cbor.encode(missingAt)), "EgMalformed")
}

fun main() {
    println("gateway conformance (Kotlin) — graded vs vectors/gateway/cases.json")
    gatewayRun()
    println("decision-record conformance (Kotlin) — graded vs vectors/decision_record/cases.json")
    runDecisionRecord()
    println("checkpoint conformance (Kotlin) — graded vs vectors/checkpoint/cases.json")
    runCheckpoint()
    println("egress-attestation conformance (Kotlin) — graded vs vectors/egress_attestation/cases.json")
    runEgressAttestation()
    println(if (gwFails == 0) "GatewayTests: PASS" else "GatewayTests: FAIL ($gwFails)")
    exitProcess(if (gwFails == 0) 0 else 1)
}
