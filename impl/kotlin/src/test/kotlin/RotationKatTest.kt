// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed tests
 * for the Kotlin SDK.
 *
 * Mutation-surviving properties: (1) BYTE PARITY -- Envelope.signRotationObject over the fixed
 * worked fixture reproduces the Go/Rust/oracle bytes: the SHA-256 of the 6798-byte tag-98 object is
 * pinned and equals the Go rotation.sign reference (Kotlin == Go == Rust == Python == oracle on the
 * whole two-leg object). (2) Round-trip -- Envelope.verifyRotationObject accepts a co-signed
 * rotation (both legs, old then new). (3) Fail-closed reject family -- a tag-18 single-signature
 * rotation, a dropped old leg, a wrong-key old leg, a tag-98 object on a non-rotation (channel,kind),
 * and a Sovereign verifier over a rotation whose OLD key is below the profile floor are ALL rejected
 * with the named kind.
 *
 * Run (main()-driven, no test framework, mirrors WorkedExampleKat): compile the SDK sources plus
 * this file into a jar, then
 *   java -cp "rotation-kat.jar;<bcprov.jar>" sh.bubblefish.naalp.RotationKatTestKt
 */

private val OLD_SEED = ByteArray(32) { 0x0B }         // old ML-DSA-65 key
private val NEW_SEED = ByteArray(32) { 0x16 }         // new ML-DSA-65 key (go-forward)
private val FLOOR_OLD_SEED = ByteArray(32) { 0x21 }   // below-floor old ML-DSA-65 key (33)
private val FLOOR_NEW_SEED = ByteArray(32) { 0x2C }   // go-forward ML-DSA-87 key (44)
// SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical to
// the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language, non-circular
// anchor, not a Kotlin-only self-check).
private const val ROTATION_OBJECT_SHA256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194"

private val ROTATION_SIGNER = "SIGNER_NEW".toByteArray(Charsets.US_ASCII)
private const val ROTATION_NOT_BEFORE = 1785000000000L

private class RotationFailure(msg: String) : RuntimeException(msg)

private fun rotEq(what: String, got: Any?, want: Any?) {
    if (got != want) throw RotationFailure("$what:\n  got  = $got\n  want = $want")
    println("  ok  $what")
}

private fun sha256Hex(b: ByteArray): String =
    Hex.encode(MessageDigest.getInstance("SHA-256").digest(b))

private fun rotationRecord(): Cbor.M =
    // field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before}
    Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.T("signer-old")),
            Cbor.Pair(Cbor.U(2), Cbor.T("signer-new")),
            Cbor.Pair(Cbor.U(3), Cbor.U(ROTATION_NOT_BEFORE)),
        )
    )

private fun rotationWorkedObject(profile: Long = Cose.PROFILE_PUBLIC): Envelope.Object =
    Envelope.Object(
        kind = 0, channel = 3, tier = 0, signer = ROTATION_SIGNER,
        created = ROTATION_NOT_BEFORE, effect = 2, profile = profile, body = rotationRecord(),
    )

private val rotationKindOk = Envelope.KindValidator { ch, k -> ch == 3L && k == 0L }

private fun expectRejects(what: String, expectedKind: String, block: () -> Unit) {
    try {
        block()
        throw RotationFailure("$what: expected $expectedKind, no exception thrown")
    } catch (e: NaalpException) {
        rotEq("$what -> ${e.kind}", e.kind, expectedKind)
    }
}

fun main() {
    println("RotationKatTest — §5.2 rotation object (tag-98 COSE_Sign) KAT + fail-closed family")

    // 1. byte parity with the Go/Rust/oracle reference.
    val obj = Envelope.signRotationObject(rotationWorkedObject(), Cose.ALG_MLDSA65, OLD_SEED, Cose.ALG_MLDSA65, NEW_SEED)
    rotEq("object length", obj.size, 6798)
    rotEq("object sha256", sha256Hex(obj), ROTATION_OBJECT_SHA256)

    // 2. round-trip accept.
    val oldPk = Cose.mldsaKeygen("ML-DSA-65", OLD_SEED)
    val newPk = Cose.mldsaKeygen("ML-DSA-65", NEW_SEED)
    val obj2 = Envelope.signRotationObject(rotationWorkedObject(), Cose.ALG_MLDSA65, OLD_SEED, Cose.ALG_MLDSA65, NEW_SEED)
    val o = Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, rotationKindOk, obj2)
    rotEq("roundtrip (channel,kind)", listOf(o.channel, o.kind), listOf(3L, 0L))

    // 3. a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
    // rotation missing the old-key co-signature -> the general verify() rejects RotationUnauthorized.
    expectRejects("tag-18 single-sig", "RotationUnauthorized") {
        val signed = Envelope.sign(rotationWorkedObject(), Cose.ALG_MLDSA65, NEW_SEED) // tag-18
        Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, newPk, rotationKindOk, signed)
    }

    // 4. the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
    // Disabling the exactly-two-legs check in verifyRotationObject flips this test.
    expectRejects("old leg dropped", "RotationUnauthorized") {
        val full = Envelope.signRotationObject(rotationWorkedObject(), Cose.ALG_MLDSA65, OLD_SEED, Cose.ALG_MLDSA65, NEW_SEED)
        val rp = Cose.parseSignRaw(full)
        val oneLeg = Cose.assembleSignRaw(rp.bodyProt, rp.payload, listOf(rp.legs[1])) // keep only the new leg
        Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, rotationKindOk, oneLeg)
    }

    // 5. both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
    expectRejects("old leg wrong key", "RotationUnauthorized") {
        val wrongObj = Envelope.signRotationObject(rotationWorkedObject(), Cose.ALG_MLDSA65, NEW_SEED, Cose.ALG_MLDSA65, NEW_SEED)
        Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, rotationKindOk, wrongObj)
    }

    // 6. a tag-98 object built over a non-rotation (channel 4, kind 2) is UnknownKind.
    expectRejects("non-rotation kind", "UnknownKind") {
        val nonRot = Envelope.Object(
            kind = 2, channel = 4, tier = 0, signer = ROTATION_SIGNER,
            created = ROTATION_NOT_BEFORE, effect = 2, profile = Cose.PROFILE_PUBLIC, body = Cbor.T("hello"),
        )
        // sign() is only used here to obtain a valid (protected-header, payload) pair for this
        // object's fields -- protectedHeader() is private, so a real tag-18 object over the same
        // fields is parsed back with parseSign1Raw to recover the identical bytes
        // signatureLeg()/assembleSignRaw() need. The tag-18 signature itself is discarded.
        val signed = Envelope.sign(nonRot, Cose.ALG_MLDSA65, NEW_SEED)
        val parts = Cose.parseSign1Raw(signed)
        val bodyProt = parts[0]
        val payload = parts[1]
        val oldLeg = Cose.signatureLeg(bodyProt, Cose.ALG_MLDSA65, OLD_SEED, payload)
        val newLeg = Cose.signatureLeg(bodyProt, Cose.ALG_MLDSA65, NEW_SEED, payload)
        val nonRotObj = Cose.assembleSignRaw(bodyProt, payload, listOf(oldLeg, newLeg))
        val acceptAll = Envelope.KindValidator { _, _ -> true }
        Envelope.verifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, acceptAll, nonRotObj)
    }

    // 7. old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
    // leg yields ProfileDowngrade under the ratified fail-closed default.
    expectRejects("sovereign old leg floor", "ProfileDowngrade") {
        val floorOldPk = Cose.mldsaKeygen("ML-DSA-65", FLOOR_OLD_SEED)
        val floorNewPk = Cose.mldsaKeygen("ML-DSA-87", FLOOR_NEW_SEED)
        val floorObj = Envelope.signRotationObject(
            rotationWorkedObject(Cose.PROFILE_SOVEREIGN), Cose.ALG_MLDSA65, FLOOR_OLD_SEED, Cose.ALG_MLDSA87, FLOOR_NEW_SEED,
        )
        Envelope.verifyRotationObject(Cose.PROFILE_SOVEREIGN, Cose.ALG_MLDSA65, floorOldPk, Cose.ALG_MLDSA87, floorNewPk, rotationKindOk, floorObj)
    }

    println("RotationKatTest: PASS")
}
