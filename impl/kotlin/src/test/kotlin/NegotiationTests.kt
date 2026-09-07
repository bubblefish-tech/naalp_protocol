// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess

//
// C20 governed-negotiation / advisory-risk-label / trust-reference known-answer test for the Kotlin
// SDK (design.md section 23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4), graded against the shared
// independent corpus vectors/negotiation/cases.json (NOT produced by this code).
//
// CORPUS-GRADED (pure): every negotiation message (offer/counter/accept/offer2/unknown-*) body + head
// + content id; the closed role/profile vocabularies; the four labeled-object bodies with AND without
// their carried labels + heads + ids; the two trust-ref bodies + heads + ids; the risk vocabulary and
// its gating/informing classes; the recognized-set validation (unknown non-critical dropped, unknown
// critical rejected); and the wire-format edge cases (descending-key NonCanonical, empty-vs-absent
// causes/labels, minimal offer/labeled-object/trust-ref, cross-kind look-alikes).
// CRYPTO-GRADED (real FIPS-204 ML-DSA-65 via BouncyCastle -- Kotlin is a full-signature port): the C20
// descent DAG over signed causally-linked messages (accept descends from offer via a counter; a
// non-descended accept rejected; foreign key rejected; unknown profile/role rejected at verify), the
// trust-ref content-id recompute (tampered record rejected; two registries symmetric), and the THREE
// cross-language pinned signed objects (offer / labeled-object / trust-ref) that Go and Rust also pin
// -- an independent (non-circular) authority proving the ML-DSA stacks emit byte-identical signed C20
// objects. The effect-class-unchanged invariant (a risk label NEVER changes the C5 effect) is graded
// directly.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
// "Tests" token the ten-language-parity gate indexes. Written test-first: [Negotiation] is absent
// until Negotiation.kt lands, so this fails RED with a kotlinc "unresolved reference: Negotiation";
// the load-bearing mutation -- LabeledObject.effectClass() consulting a gating label to escalate the
// effect -- flips "read_only + sensitive still read_only" on its assertion.
//

private var ngFails = 0

// The three cross-language pinned SHA-384 digests of the deterministic COSE_Sign1 objects obtained by
// signing the offer body, the read_only-with-labels labeled-object body, and the trust-ref A body with
// the shared all-0x11 32-byte ML-DSA-65 seed. Go and Rust both pin these (see
// impl/go/negotiation/negotiation_test.go), so they are an independent (non-circular) authority for the
// signed bytes; Kotlin must reproduce them exactly.
private const val PIN_SIGNED_OFFER_SHA384 =
    "28b5c4e082cfae270bcc0317ef95c88c451f5af7c0d984b2120496afad4870964845b699fe501bb8cd6fab99298729fd"
private const val PIN_SIGNED_LABELED_SHA384 =
    "c6f4ba4c897f2f34f075ec504cd8329da7b138764cac5f4b7dcd120348b15d36fab9bf55bb5302dd024f1b077ecc1a0c"
private const val PIN_SIGNED_TRUSTREF_SHA384 =
    "80a7d8302bdb01d0fec577a28a4cb0e37c540f80c4d588a8be8324d9e80229fbf3f6a850c6c50d24ca1991e03b84699f"

private fun ngCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        ngFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun ngFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/negotiation/cases.json not found")
        val p = File(File(cur, "vectors"), "negotiation/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/negotiation/cases.json not found from ${File(".").absolutePath}")
}

/**
 * The balanced object/array text of the FIRST [key] in [scope] whose value is an object or array. A
 * scalar-valued key (e.g. `roles.offer: 0`) is skipped so it cannot shadow the real object-valued
 * `offer: {...}`. String contents are honored so braces inside a note string never unbalance.
 */
private fun ngSection(scope: String, key: String): String {
    val re = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*")
    for (m in re.findAll(scope)) {
        var i = m.range.last + 1
        while (i < scope.length && scope[i].isWhitespace()) i++
        if (i >= scope.length) continue
        val open = scope[i]
        if (open != '{' && open != '[') continue // scalar value: not the object/array we want
        val close = if (open == '{') '}' else ']'
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
    throw AssertionError("object/array key not found: $key")
}

/** The top-level {...} object elements of an array section. */
private fun ngElements(arraySection: String): List<String> {
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

/** The quoted strings inside the array section named [key]. */
private fun ngStrArray(scope: String, key: String): List<String> {
    val arr = ngSection(scope, key)
    return Regex("\"([^\"]*)\"").findAll(arr.substring(1, arr.length - 1)).map { it.groupValues[1] }.toList()
}

/** The integers inside the array section named [key]. */
private fun ngIntArray(scope: String, key: String): List<Long> {
    val arr = ngSection(scope, key)
    return Regex("(\\d+)").findAll(arr.substring(1, arr.length - 1)).map { it.groupValues[1].toLong() }.toList()
}

private fun ngStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun ngInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun ngBool(scope: String, key: String): Boolean {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(true|false)").find(scope)
        ?: throw AssertionError("bool key not found: $key")
    return m.groupValues[1] == "true"
}

private fun ngSha384Hex(b: ByteArray): String = Hex.encode(MessageDigest.getInstance("SHA-384").digest(b))

private inline fun ngKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

/** Build a Message from a message vec sub-object (role, profile, causes_hex[]) and the shared neg id. */
private fun ngMsg(neg: ByteArray, mv: String): Negotiation.Message =
    Negotiation.Message(neg, ngInt(mv, "role"), ngInt(mv, "profile"), ngStrArray(mv, "causes_hex").map { Hex.decode(it) })

/** The RiskLabels carried in an array section of {code, critical} objects. */
private fun ngLabelsFrom(arraySection: String): List<Negotiation.RiskLabel> =
    ngElements(arraySection).map { Negotiation.RiskLabel(ngInt(it, "code"), ngInt(it, "critical")) }

private const val NG_ALG = Cose.ALG_MLDSA65

private fun negotiationRun() {
    val json = ngFindVector().readText(Charsets.UTF_8)
    val negSec = ngSection(json, "negotiation")
    val riskSec = ngSection(json, "risk")
    val trustSec = ngSection(json, "trust")
    val edgeSec = ngSection(json, "edge_cases")
    val neg = Hex.decode(ngStr(negSec, "negotiation_hex"))

    // 1. the closed role/profile vocabularies are registered; out-of-set codes are not known.
    val rolesSec = ngSection(negSec, "roles")
    for (r in listOf("offer" to Negotiation.ROLE_OFFER, "counter" to Negotiation.ROLE_COUNTER, "accept" to Negotiation.ROLE_ACCEPT)) {
        ngCheck("role ${r.first} code == oracle", r.second.toString(), ngInt(rolesSec, r.first).toString())
        ngCheck("role ${r.first} known", Negotiation.knownRole(r.second).toString(), "true")
    }
    ngCheck("unknown role not known", Negotiation.knownRole(9).toString(), "false")
    val profSec = ngSection(negSec, "profiles")
    for (p in listOf("baseline" to Negotiation.PROFILE_BASELINE, "streaming" to Negotiation.PROFILE_STREAMING, "batch" to Negotiation.PROFILE_BATCH)) {
        ngCheck("profile ${p.first} code == oracle", p.second.toString(), ngInt(profSec, p.first).toString())
        ngCheck("profile ${p.first} registered", Negotiation.isRegisteredProfile(p.second).toString(), "true")
    }
    ngCheck("unknown profile not registered", Negotiation.isRegisteredProfile(ngInt(negSec, "unknown_profile")).toString(), "false")

    // 2. each negotiation message body/head/id == the non-circular oracle; a valid body round-trips.
    for (name in listOf("offer", "counter", "accept", "offer2", "accept_not_descended", "unknown_profile_offer", "unknown_role_message")) {
        val mv = ngSection(negSec, name)
        val m = ngMsg(neg, mv)
        ngCheck("$name body == oracle", Hex.encode(m.bytes()), ngStr(mv, "body_hex"))
        ngCheck("$name head == oracle", Hex.encode(m.head()), ngStr(mv, "head_hex"))
        ngCheck("$name id == oracle", Hex.encode(m.id()), ngStr(mv, "id_hex"))
        ngCheck("$name parse round-trip == oracle", Hex.encode(Negotiation.parseMessage(m.bytes()).bytes()), ngStr(mv, "body_hex"))
    }

    // 3. labeled objects (with and without labels) body/head/id == oracle.
    val carried = ngLabelsFrom(ngSection(riskSec, "carried_on_labeled_objects"))
    for (lo in ngElements(ngSection(riskSec, "labeled_objects"))) {
        val eff = ngInt(lo, "effect")
        val name = ngStr(lo, "effect_name")
        val withSec = ngSection(lo, "with_labels")
        val withoutSec = ngSection(lo, "without_labels")
        val withObj = Negotiation.LabeledObject(eff, carried)
        val withoutObj = Negotiation.LabeledObject(eff, emptyList())
        ngCheck("labeled $name with-labels body == oracle", Hex.encode(withObj.bytes()), ngStr(withSec, "body_hex"))
        ngCheck("labeled $name with-labels head == oracle", Hex.encode(withObj.head()), ngStr(withSec, "head_hex"))
        ngCheck("labeled $name with-labels id == oracle", Hex.encode(withObj.id()), ngStr(withSec, "id_hex"))
        ngCheck("labeled $name without-labels body == oracle", Hex.encode(withoutObj.bytes()), ngStr(withoutSec, "body_hex"))
        ngCheck("labeled $name without-labels id == oracle", Hex.encode(withoutObj.id()), ngStr(withoutSec, "id_hex"))
    }

    // 4. trust refs A and B body/head/id == oracle.
    val registryA = Hex.decode(ngStr(trustSec, "registry_a_hex"))
    val registryB = Hex.decode(ngStr(trustSec, "registry_b_hex"))
    val subject = Hex.decode(ngStr(trustSec, "subject_hex"))
    val reference = Hex.decode(ngStr(trustSec, "reference_hex"))
    val record = Hex.decode(ngStr(trustSec, "external_record_hex"))
    val tamperedRec = Hex.decode(ngStr(trustSec, "tampered_record_hex"))
    val refASec = ngSection(trustSec, "ref_a")
    val refBSec = ngSection(trustSec, "ref_b")
    val refA = Negotiation.TrustRef(registryA, reference, subject)
    val refB = Negotiation.TrustRef(registryB, reference, subject)
    ngCheck("trust ref A body == oracle", Hex.encode(refA.bytes()), ngStr(refASec, "body_hex"))
    ngCheck("trust ref A head == oracle", Hex.encode(refA.head()), ngStr(refASec, "head_hex"))
    ngCheck("trust ref A id == oracle", Hex.encode(refA.id()), ngStr(refASec, "id_hex"))
    ngCheck("trust ref B body == oracle", Hex.encode(refB.bytes()), ngStr(refBSec, "body_hex"))
    ngCheck("trust ref B id == oracle", Hex.encode(refB.id()), ngStr(refBSec, "id_hex"))

    // 5. GOVERNED NEGOTIATION over signed causally-linked messages (real ML-DSA): sign+verify each,
    //    foreign key rejected; the accept descends from the offer via the counter; a non-descended
    //    accept is rejected NotDescended; unknown profile/role rejected; NotOffer/NotAccept.
    val seed = ByteArray(32) { 0x11 }
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val foreignPk = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32) { 0x22 })
    val offer = ngMsg(neg, ngSection(negSec, "offer"))
    val counter = ngMsg(neg, ngSection(negSec, "counter"))
    val accept = ngMsg(neg, ngSection(negSec, "accept"))
    val offer2 = ngMsg(neg, ngSection(negSec, "offer2"))
    val acceptBad = ngMsg(neg, ngSection(negSec, "accept_not_descended"))

    // The causes wiring reproduces the oracle: counter->offer, accept->counter, acceptBad->offer2.
    ngCheck("counter chains onto offer", Hex.encode(counter.causes[0]), Hex.encode(offer.id()))
    ngCheck("accept chains onto counter", Hex.encode(accept.causes[0]), Hex.encode(counter.id()))
    ngCheck("acceptBad chains onto offer2", Hex.encode(acceptBad.causes[0]), Hex.encode(offer2.id()))

    val verified = ArrayList<Negotiation.Message>()
    for (m in listOf(offer, counter, accept, offer2, acceptBad)) {
        val obj = Negotiation.signMessage(m, NG_ALG, seed)
        val vm = Negotiation.verifyMessage(obj, Cose.PROFILE_PUBLIC, NG_ALG, pk)
        ngCheck("verify ${Negotiation.roleName(m.role)} id round-trip", Hex.encode(vm.id()), Hex.encode(m.id()))
        ngCheck("verify ${Negotiation.roleName(m.role)} foreign key rejected", ngKind { Negotiation.verifyMessage(obj, Cose.PROFILE_PUBLIC, NG_ALG, foreignPk) }, "BadSignature")
        verified.add(vm)
    }
    val byId = Negotiation.indexById(verified)
    val descendsSec = ngSection(negSec, "descends")
    ngCheck("accept descends from offer", Negotiation.descends(accept, offer, byId).toString(), ngBool(descendsSec, "accept_from_offer").toString())
    ngCheck("acceptBad does not descend from offer", Negotiation.descends(acceptBad, offer, byId).toString(), ngBool(descendsSec, "accept_bad_from_offer").toString())
    ngCheck("verifyAccept agreed profile == oracle", Negotiation.verifyAccept(accept, offer, byId).toString(), ngInt(negSec, "agreed_profile").toString())
    ngCheck("verifyAccept non-descended rejected", ngKind { Negotiation.verifyAccept(acceptBad, offer, byId) }, "NotDescended")

    val unkProfObj = Negotiation.signMessage(ngMsg(neg, ngSection(negSec, "unknown_profile_offer")), NG_ALG, seed)
    ngCheck("unknown-profile message rejected", ngKind { Negotiation.verifyMessage(unkProfObj, Cose.PROFILE_PUBLIC, NG_ALG, pk) }, "UnknownProfile")
    val unkRoleObj = Negotiation.signMessage(ngMsg(neg, ngSection(negSec, "unknown_role_message")), NG_ALG, seed)
    ngCheck("unknown-role message rejected", ngKind { Negotiation.verifyMessage(unkRoleObj, Cose.PROFILE_PUBLIC, NG_ALG, pk) }, "UnknownRole")
    ngCheck("non-offer-as-offer rejected", ngKind { Negotiation.verifyAccept(accept, counter, byId) }, "NotOffer")
    ngCheck("non-accept-as-accept rejected", ngKind { Negotiation.verifyAccept(counter, offer, byId) }, "NotAccept")

    // 6. the LOAD-BEARING C20 invariant: carrying a risk label NEVER changes the effect class (the
    //    closed C5 lattice is untouched -- a risk label is an advisory dimension, not a fifth effect).
    for (lo in ngElements(ngSection(riskSec, "labeled_objects"))) {
        val eff = ngInt(lo, "effect")
        val name = ngStr(lo, "effect_name")
        val wantClass = Policy.normalizeEffect(eff)
        val withObj = Negotiation.LabeledObject(eff, carried)
        val withoutObj = Negotiation.LabeledObject(eff, emptyList())
        ngCheck("effect $name with-labels class unchanged", withObj.effectClass().toString(), wantClass.toString())
        ngCheck("effect $name without-labels class unchanged", withoutObj.effectClass().toString(), wantClass.toString())
        ngCheck("effect $name class == oracle", withObj.effectClass().toString(), ngInt(lo, "effect_class").toString())
    }
    val sensitive = Negotiation.LabeledObject(Policy.READ_ONLY, listOf(Negotiation.RiskLabel(Negotiation.RISK_SENSITIVE, 1)))
    ngCheck("read_only + sensitive still read_only", sensitive.effectClass().toString(), Policy.READ_ONLY.toString())

    // 7. the R-2.5 critical-extension rule over risk labels: vocabulary + classes match the oracle; the
    //    recognized set validates (unknown non-critical dropped); an unknown CRITICAL label is rejected;
    //    a malformed critical flag (outside {0,1}) is rejected MalformedCriticalFlag.
    for (vb in ngElements(ngSection(riskSec, "vocabulary"))) {
        val name = ngStr(vb, "name")
        val code = ngInt(vb, "code")
        ngCheck("vocab $name registered", Negotiation.isRegisteredRisk(code).toString(), "true")
        ngCheck("vocab $name class == oracle", Negotiation.riskClassName(Negotiation.riskClassOf(code)), ngStr(vb, "class"))
    }
    ngCheck("extensible range start == oracle", Negotiation.EXTENSIBLE_RANGE_START.toString(), ngInt(riskSec, "extensible_range_start").toString())
    val validateSec = ngSection(riskSec, "validate")
    val recSet = ngSection(validateSec, "recognized_set")
    val recognized = Negotiation.validateLabels(ngLabelsFrom(ngSection(recSet, "carried")))
    ngCheck("recognized set codes == oracle", recognized.map { it.code }.joinToString(","), ngIntArray(recSet, "recognized_codes").joinToString(","))
    val critSet = ngSection(validateSec, "unknown_critical_rejected")
    ngCheck("unknown critical rejected", ngKind { Negotiation.validateLabels(ngLabelsFrom(ngSection(critSet, "carried"))) }, ngStr(critSet, "error"))
    val badFlag = Negotiation.LabeledObject(0, listOf(Negotiation.RiskLabel(Negotiation.RISK_SENSITIVE, 2)))
    ngCheck("malformed critical flag rejected", ngKind { Negotiation.parseLabeledObject(badFlag.bytes()) }, "MalformedCriticalFlag")

    // 8. TRUST is CHECKABLE (content-id recompute) but NEVER weighed (no score on the wire): the
    //    reference recomputes over the record; a tampered record does not; two registries symmetric.
    ngCheck("trust ref A binds record", refA.bindsRecord(record).toString(), "true")
    ngCheck("trust ref A does not bind tampered", refA.bindsRecord(tamperedRec).toString(), "false")
    val trefObj = Negotiation.signTrustRef(refA, NG_ALG, seed)
    val resolved = Negotiation.verifyTrustRef(trefObj, Cose.PROFILE_PUBLIC, NG_ALG, pk, record)
    ngCheck("verifyTrustRef resolved reference == carried", Hex.encode(resolved.reference), Hex.encode(reference))
    ngCheck("verifyTrustRef tampered record rejected", ngKind { Negotiation.verifyTrustRef(trefObj, Cose.PROFILE_PUBLIC, NG_ALG, pk, tamperedRec) }, "ReferenceMismatch")
    ngCheck("verifyTrustRef foreign key rejected", ngKind { Negotiation.verifyTrustRef(trefObj, Cose.PROFILE_PUBLIC, NG_ALG, foreignPk, record) }, "BadSignature")
    val trefBObj = Negotiation.signTrustRef(refB, NG_ALG, seed)
    val resolvedB = Negotiation.verifyTrustRef(trefBObj, Cose.PROFILE_PUBLIC, NG_ALG, pk, record)
    ngCheck("two registries resolve same reference", Hex.encode(resolved.reference), Hex.encode(resolvedB.reference))
    ngCheck("two registries differ (symmetry fixture)", (Hex.encode(resolved.registry) != Hex.encode(resolvedB.registry)).toString(), "true")

    // 9. CROSS-LANGUAGE SIGNED PINS: the signed offer / labeled-object / trust-ref objects (seed=0x11*32)
    //    reproduce the SHA-384 Go and Rust pin -- byte-identical signed C20 objects across ML-DSA stacks.
    val offerObj = Negotiation.signMessage(offer, NG_ALG, seed)
    ngCheck("cross-language signed-offer SHA-384 pin", ngSha384Hex(offerObj), PIN_SIGNED_OFFER_SHA384)
    val labeled0 = Negotiation.LabeledObject(ngInt(ngElements(ngSection(riskSec, "labeled_objects"))[0], "effect"), carried)
    val labeledObj = Negotiation.signLabeledObject(labeled0, NG_ALG, seed)
    ngCheck("cross-language signed-labeled SHA-384 pin", ngSha384Hex(labeledObj), PIN_SIGNED_LABELED_SHA384)
    ngCheck("cross-language signed-trust-ref SHA-384 pin", ngSha384Hex(trefObj), PIN_SIGNED_TRUSTREF_SHA384)

    // 10. wire-format edge cases.
    val koo = ngSection(edgeSec, "keys_out_of_order")
    val canonOfferBody = Negotiation.Message(neg, Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, emptyList()).bytes()
    ngCheck("edge canonical offer body == oracle", Hex.encode(canonOfferBody), ngStr(koo, "canonical_offer_body_hex"))
    ngCheck("edge canonical offer parses", ngKind { Negotiation.parseMessage(canonOfferBody) }, "no-error")
    ngCheck("edge descending-key body cbor-rejected", ngKind { Cbor.decode(Hex.decode(ngStr(koo, "noncanonical_offer_body_hex"))) }, "NonCanonical")
    ngCheck("edge descending-key body parseMessage-rejected", ngKind { Negotiation.parseMessage(Hex.decode(ngStr(koo, "noncanonical_offer_body_hex"))) }, "NegMalformed")

    val eva = ngSection(edgeSec, "empty_vs_absent")
    val causesSec = ngSection(eva, "causes")
    val emptyCausesSec = ngSection(causesSec, "empty_present")
    val oneCauseSec = ngSection(causesSec, "one_cause")
    val emptyCauses = Negotiation.Message(neg, Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, emptyList())
    val oneCause = Negotiation.Message(neg, Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, listOf(Hex.decode(ngStr(oneCauseSec, "cause_hex"))))
    ngCheck("edge empty-causes body == oracle", Hex.encode(emptyCauses.bytes()), ngStr(emptyCausesSec, "body_hex"))
    ngCheck("edge one-cause body == oracle", Hex.encode(oneCause.bytes()), ngStr(oneCauseSec, "body_hex"))
    ngCheck("edge empty vs one-cause ids distinct", (Hex.encode(emptyCauses.id()) != Hex.encode(oneCause.id())).toString(), "true")
    ngCheck("edge empty-causes id == oracle", Hex.encode(emptyCauses.id()), ngStr(emptyCausesSec, "id_hex"))
    ngCheck("edge absent-causes rejected", ngKind { Negotiation.parseMessage(Hex.decode(ngStr(ngSection(causesSec, "absent_field"), "body_hex"))) }, "NegMalformed")

    val labelsSec = ngSection(eva, "labels")
    val emptyLabelsSec = ngSection(labelsSec, "empty_present")
    val oneLabelSec = ngSection(labelsSec, "one_label")
    val emptyLabels = Negotiation.LabeledObject(0, emptyList())
    val oneLabel = Negotiation.LabeledObject(0, listOf(Negotiation.RiskLabel(ngInt(oneLabelSec, "code"), ngInt(oneLabelSec, "critical"))))
    ngCheck("edge empty-labels body == oracle", Hex.encode(emptyLabels.bytes()), ngStr(emptyLabelsSec, "body_hex"))
    ngCheck("edge one-label body == oracle", Hex.encode(oneLabel.bytes()), ngStr(oneLabelSec, "body_hex"))
    ngCheck("edge empty vs one-label ids distinct", (Hex.encode(emptyLabels.id()) != Hex.encode(oneLabel.id())).toString(), "true")
    ngCheck("edge absent-labels rejected", ngKind { Negotiation.parseLabeledObject(Hex.decode(ngStr(ngSection(labelsSec, "absent_field"), "body_hex"))) }, "NegMalformed")

    val minimalSec = ngSection(edgeSec, "minimal")
    val minOfferSec = ngSection(minimalSec, "offer")
    val minOffer = Negotiation.Message(Hex.decode(ngStr(minOfferSec, "negotiation_hex")), Negotiation.ROLE_OFFER, Negotiation.PROFILE_BASELINE, emptyList())
    ngCheck("edge minimal offer body == oracle", Hex.encode(minOffer.bytes()), ngStr(minOfferSec, "body_hex"))
    ngCheck("edge minimal offer id == oracle", Hex.encode(minOffer.id()), ngStr(minOfferSec, "id_hex"))
    val minLabeledSec = ngSection(minimalSec, "labeled_object")
    val minLabeled = Negotiation.LabeledObject(ngInt(minLabeledSec, "effect"), emptyList())
    ngCheck("edge minimal labeled-object body == oracle", Hex.encode(minLabeled.bytes()), ngStr(minLabeledSec, "body_hex"))
    ngCheck("edge minimal labeled-object id == oracle", Hex.encode(minLabeled.id()), ngStr(minLabeledSec, "id_hex"))
    val minTrustSec = ngSection(minimalSec, "trust_ref")
    val minTrust = Negotiation.TrustRef(ByteArray(0), ByteArray(0), ByteArray(0))
    ngCheck("edge minimal trust-ref body == oracle", Hex.encode(minTrust.bytes()), ngStr(minTrustSec, "body_hex"))
    ngCheck("edge minimal trust-ref id == oracle", Hex.encode(minTrust.id()), ngStr(minTrustSec, "id_hex"))

    val lookSec = ngSection(edgeSec, "look_alike")
    val trAsMsg = ngSection(lookSec, "trust_ref_as_message")
    val msgAsTr = ngSection(lookSec, "message_as_trust_ref")
    ngCheck("edge trust-ref-as-message rejected", ngKind { Negotiation.parseMessage(Hex.decode(ngStr(trAsMsg, "body_hex"))) }, ngStr(trAsMsg, "reject"))
    ngCheck("edge message-as-trust-ref rejected", ngKind { Negotiation.parseTrustRef(Hex.decode(ngStr(msgAsTr, "body_hex"))) }, ngStr(msgAsTr, "reject"))
}

fun main() {
    println("negotiation conformance (Kotlin) -- graded vs vectors/negotiation/cases.json")
    negotiationRun()
    println(if (ngFails == 0) "NegotiationTests: PASS" else "NegotiationTests: FAIL ($ngFails)")
    exitProcess(if (ngFails == 0) 0 else 1)
}
