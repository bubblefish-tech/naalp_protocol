// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

//
// C18 — the signed description / directory primitive for the Kotlin SDK (design.md §21; R-DESC-1..8).
//
// C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
// object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the connection
// or the host that served them: the same signed Description re-verifies byte-identically when an
// unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
// introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is
// an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (Policy) and the
// T1 content-id framing (§2.3) unchanged.
//
// Three wire objects:
//
//   - Description {1: service, 2: operations[]} lists a service's operations, each Operation
//     {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
//     parseDescription reconstructs the whole operation table from the bytes ALONE.
//   - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are content
//     ids. Two conflicting versions from ONE signer — same directory and version, different members — are
//     a FORK, detected at the FIRST-DIFFERING member POSITION (as the §8.5 audit fork-proof reports the
//     position of an equivocation).
//   - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
//     (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet (carriage, not
//     adoption) as a signed N-AALP attestation binding the foreign bytes' content id AND an N-AALP effect
//     mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly from the verifying key) is
//     the SOLE authorization identity; a foreign identity embedded in `foreign` never becomes an N-AALP
//     authorization identity — the confused-deputy rule, enforced normatively here (R-14.6).
//
// Every check is fail-closed (§15). Ported from impl/go/description (cross-read against
// impl/python/naalp/description.py); the byte surface (bodies, heads, content ids, foreign-id binding,
// fork position, closed foreign-format rejection) is graded against vectors/description/cases.json; the
// offline-verification, fork-proof, and confused-deputy paths use real deterministic ML-DSA-65 and are
// demonstrated in isolation (the corpus carries no signed vector).
//
// TWO honest deviations from the Go reference, stated (F4):
//   - NAMESPACE NAME. This namespace object is `Desc`, not `Description`, because the wire type is called
//     `Description`: naming both `Description` would force every reference to read `Description.Description`,
//     which reads as an error. (Kotlin permits `object X { class X }` — verified — so this is a clarity
//     choice, not a compiler requirement.) The wire types keep their reference names Description/Directory/
//     Import as `Desc.Description` / `Desc.Directory` / `Desc.Import`.
//   - NO VerifierKeyMismatch. Go's VerifyImport carries an ErrVerifierKeyMismatch guard because it takes
//     BOTH a separate (alg, pubkey) AND a cose.Verifier, and must bind them before deriving the authority
//     id. Like the Python port (and the committed Kotlin Gateway idiom), verifyImport here verifies with a
//     single (alg, pubkey) pair, so the authority id is ALWAYS derived from exactly the key that verified
//     the signature — the mismatch that guard prevents is structurally impossible, so there is no
//     VerifierKeyMismatch surface to port. It is not silently dropped; it is absent because the
//     vulnerability it guards cannot arise in this signature.
//
object Desc {
    // The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    const val HEAD_SIZE = 48

    // Foreign description format codes (design §21; the closed naalp-description-format registry).
    const val FORMAT_A2A_CARD = 1L        // A2A Agent Card
    const val FORMAT_ANP_DESCRIPTION = 2L // ANP Agent Description
    const val FORMAT_AGNTCY_BADGE = 3L    // AGNTCY Agent Badge

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    private fun isKnownFormat(fmt: Long): Boolean =
        fmt == FORMAT_A2A_CARD || fmt == FORMAT_ANP_DESCRIPTION || fmt == FORMAT_AGNTCY_BADGE

    // ---- Operation: one listed operation with its effect + approval declaration (design §21.2) ----

    // One entry of a Description or Import mapping: a named operation, its C5 effect class, and whether it
    // requires an approval. requiresApproval is the uint 1 (yes) / 0 (no) — no CBOR boolean (design §3.1).
    class Operation(val name: String, val effect: Long, val requiresApproval: Long) {
        fun toMap(): Cbor.M = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.T(name)),
                Cbor.Pair(Cbor.U(2), Cbor.U(effect)),
                Cbor.Pair(Cbor.U(3), Cbor.U(requiresApproval)),
            )
        )

        // Deterministic-CBOR encoding of the operation body {1:name,2:effect,3:requires_approval}.
        fun bytes(): ByteArray = Cbor.encode(toMap())

        // The per-operation effect, normalized fail-closed: an unrecognized value is destructive (R-6.2).
        fun effectClass(): Long = Policy.normalizeEffect(effect)

        // True iff the operation declares that it requires an approval.
        fun requiresApprovalFlag(): Boolean = requiresApproval == 1L
    }

    // Parse one operation map, rejecting a malformed shape (DescMalformed) or an approval flag outside
    // {0,1} (MalformedApprovalFlag). Fail-closed.
    private fun operationFromValue(v: Cbor.Value): Operation {
        if (v !is Cbor.M) throw NaalpException("DescMalformed", "operation is not a map")
        var name: String? = null
        var effect: Long? = null
        var req: Long? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("DescMalformed", "non-uint operation key")
            when (k.v) {
                1L -> { val t = p.v; if (t is Cbor.T) name = t.v }
                2L -> { val u = p.v; if (u is Cbor.U) effect = u.v }
                3L -> { val u = p.v; if (u is Cbor.U) req = u.v }
            }
        }
        if (name == null || effect == null || req == null) {
            throw NaalpException("DescMalformed", "operation missing a mandatory field")
        }
        if (req > 1L) throw NaalpException("MalformedApprovalFlag", "requires_approval is outside {0,1}")
        return Operation(name, effect, req)
    }

    private fun operationsFromValue(v: Cbor.Value): List<Operation> {
        if (v !is Cbor.A) throw NaalpException("DescMalformed", "operations is not an array")
        return v.items.map { operationFromValue(it) }
    }

    private fun operationsValue(ops: List<Operation>): Cbor.A = Cbor.A(ops.map { it.toMap() })

    private fun findOperation(ops: List<Operation>, name: String): Operation? = ops.firstOrNull { it.name == name }

    // ---- Description: a service's signed operation table (design §21.2) ----------------------------

    // A signed N-AALP object listing a service's operations. Its authority is in the signed bytes:
    // parseDescription reconstructs the whole operation table (each operation's effect and approval
    // declaration) from the bytes alone, so an unrelated host serving the same bytes yields a
    // byte-identical verification (offline-verifiable, not fetch-authenticated).
    class Description(service: ByteArray, val operations: List<Operation>) {
        val service: ByteArray = service.copyOf()

        // Deterministic-CBOR encoding {1: service, 2: operations[]}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(service)),
                    Cbor.Pair(Cbor.U(2), operationsValue(operations)),
                )
            )
        )

        // The Description's SHA-384 head (48 octets).
        fun head(): ByteArray = sha384(bytes())

        // The Description's T1 content-id (50 octets).
        fun id(): ByteArray = Cbor.contentId(bytes())

        // The named operation, or null if it is not listed.
        fun operation(name: String): Operation? = findOperation(operations, name)
    }

    // Reconstruct a Description from its body bytes ALONE — the offline-verifiable property.
    fun parseDescription(b: ByteArray): Description {
        val m = decodeMap(b)
        val svc = bstrField(m, 1) ?: throw NaalpException("DescMalformed", "description missing service")
        val opsV = field(m, 2) ?: throw NaalpException("DescMalformed", "description missing operations")
        return Description(svc, operationsFromValue(opsV))
    }

    // Produce the tagged COSE_Sign1 object over the Description body.
    fun signDescription(d: Description, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, descProtectedHeader(alg), d.bytes())

    // Verify the Description's full signature under the profile, then reconstruct the operation table from
    // the signed body bytes. Because the authority is the signature over the bytes, this returns the
    // identical Description regardless of which host served `obj` (R-DESC-1). Fail-closed.
    fun verifyDescription(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): Description =
        parseDescription(verifySign1(obj, profile, alg, pubkey))

    // ---- Directory: a signed collection of content ids, with fork detection (design §21.3) ----------

    // A signed collection object whose members are content ids. It carries a monotonic per-signer version
    // so two versions can be compared for equivocation.
    class Directory(directory: ByteArray, val version: Long, members: List<ByteArray>) {
        val directory: ByteArray = directory.copyOf()
        val members: List<ByteArray> = members.map { it.copyOf() }

        // Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(directory)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(version)),
                    Cbor.Pair(Cbor.U(3), Cbor.A(members.map { Cbor.B(it) })),
                )
            )
        )

        // The Directory's SHA-384 head (48 octets).
        fun head(): ByteArray = sha384(bytes())

        // The Directory's T1 content-id (50 octets).
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    // Reconstruct a Directory from its body bytes alone.
    fun parseDirectory(b: ByteArray): Directory {
        val m = decodeMap(b)
        val did = bstrField(m, 1)
        val ver = uintField(m, 2)
        val memV = field(m, 3)
        if (did == null || ver == null || memV == null || memV !is Cbor.A) {
            throw NaalpException("DescMalformed", "directory missing or malformed field")
        }
        val members = ArrayList<ByteArray>(memV.items.size)
        for (e in memV.items) {
            if (e !is Cbor.B) throw NaalpException("DescMalformed", "member is not a bstr")
            members.add(e.v)
        }
        return Directory(did, ver, members)
    }

    // Produce the tagged COSE_Sign1 object over the Directory body.
    fun signDirectory(d: Directory, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, descProtectedHeader(alg), d.bytes())

    // Verify the Directory's full signature under the profile, then reconstruct it from the signed body
    // bytes. Fail-closed.
    fun verifyDirectory(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): Directory =
        parseDirectory(verifySign1(obj, profile, alg, pubkey))

    // The first index at which two member lists differ, and whether they differ at all. If the lists share
    // a common prefix and one is longer, the difference is reported at the length of the shorter list.
    // Identical lists return (0, false).
    fun firstMemberDifference(a: List<ByteArray>, b: List<ByteArray>): kotlin.Pair<Int, Boolean> {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            if (!a[i].contentEquals(b[i])) return kotlin.Pair(i, true)
        }
        if (a.size != b.size) return kotlin.Pair(n, true)
        return kotlin.Pair(0, false)
    }

    // Compare two directory versions from ONE signer and report whether they equivocate — the SAME
    // directory id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING member POSITION. A
    // different directory id or version is a legitimate distinct object/succession, not a fork; identical
    // members are a benign duplicate. In both non-fork cases returns (0, false). The caller establishes the
    // "one signer" precondition by verifying both objects under the same key.
    fun detectFork(a: Directory, b: Directory): kotlin.Pair<Int, Boolean> {
        if (!a.directory.contentEquals(b.directory) || a.version != b.version) {
            return kotlin.Pair(0, false) // different directory or version — not a conflicting pair
        }
        return firstMemberDifference(a.members, b.members)
    }

    // Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer at
    // the SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN two
    // signed objects. Because a single verifier checks BOTH signed objects, the proof is self-contained.
    class DirectoryForkProof(signer: ByteArray, signedA: ByteArray, signedB: ByteArray) {
        val signer: ByteArray = signer.copyOf()
        val signedA: ByteArray = signedA.copyOf()
        val signedB: ByteArray = signedB.copyOf()

        // Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and return
        // the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is present; (2) BOTH
        // signed objects verify under the key (which, because a single verifier checks both, proves one
        // signer); (3) the two directories share one directory id and version; and (4) their member lists
        // differ. Any failure rejects the whole proof (fail-closed): an unnamed signer, a different
        // directory/version, or identical members is DirForkProofInvalid; a signature that does not verify
        // propagates BadSignature.
        fun verify(profile: Long, alg: Int, pubkey: ByteArray): Int {
            if (signer.isEmpty()) throw NaalpException("DirForkProofInvalid", "an unnamed accused is not evidence")
            val a = verifyDirectory(signedA, profile, alg, pubkey)
            val b = verifyDirectory(signedB, profile, alg, pubkey)
            val (pos, fork) = detectFork(a, b)
            if (!fork) {
                throw NaalpException("DirForkProofInvalid", "same directory+version identical members, or not the same versioned directory")
            }
            return pos
        }
    }

    // ---- Import: foreign description carried as a signed attestation (design §21.4) -----------------

    // Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed N-AALP
    // attestation. importer is the wrapping signer id (the sole authorization identity); foreign is the
    // foreign bytes verbatim; operations is the N-AALP effect mapping the importer attests. The foreign
    // bytes' content id is bound by foreignId.
    class Import(importer: ByteArray, val format: Long, foreign: ByteArray, val operations: List<Operation>) {
        val importer: ByteArray = importer.copyOf()
        val foreign: ByteArray = foreign.copyOf()

        // Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}.
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(importer)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(format)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(foreign)),
                    Cbor.Pair(Cbor.U(4), operationsValue(operations)),
                )
            )
        )

        // The Import's SHA-384 head (48 octets).
        fun head(): ByteArray = sha384(bytes())

        // The Import attestation's own T1 content-id (50 octets).
        fun id(): ByteArray = Cbor.contentId(bytes())

        // The T1 content id of the carried foreign bytes — the hash the attestation binds. A changed
        // foreign document yields a different foreignId, so an attestation binds the exact bytes.
        fun foreignId(): ByteArray = Cbor.contentId(foreign)

        // The named operation from the attested mapping, or null.
        fun operation(name: String): Operation? = findOperation(operations, name)
    }

    // Reconstruct an Import from its body bytes alone. A format code outside the closed
    // naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never carried
    // as an unknown format. Fail-closed.
    fun parseImport(b: ByteArray): Import {
        val m = decodeMap(b)
        val imp = bstrField(m, 1)
        val fmt = uintField(m, 2)
        val foreign = bstrField(m, 3)
        val opsV = field(m, 4)
        if (imp == null || fmt == null || foreign == null || opsV == null) {
            throw NaalpException("DescMalformed", "import missing a mandatory field")
        }
        if (!isKnownFormat(fmt)) {
            throw NaalpException("UnknownDescriptionFormat", "import format $fmt is outside the closed set {1,2,3}")
        }
        return Import(imp, fmt, foreign, operationsFromValue(opsV))
    }

    // Produce the tagged COSE_Sign1 object over the Import body.
    fun signImport(im: Import, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, descProtectedHeader(alg), im.bytes())

    // An Import that has passed signature verification and the confused-deputy check. authorityId is the
    // self-certifying signer id RECOMPUTED from the verifying key — the wrapping signer, and the only
    // authorization identity. It is never any identity parsed from the foreign bytes.
    class ResolvedImport(val authorityId: String, val format: Long, foreignId: ByteArray, val operations: List<Operation>) {
        val foreignId: ByteArray = foreignId.copyOf()
    }

    // Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively. It
    // (1) verifies the signed object under the profile with real crypto; (2) recomputes the wrapping
    // signer's SELF-CERTIFYING id from the verifying key (Identity.signerId); and (3) requires the
    // attestation's `importer` field to equal that recomputed id (ImporterMismatch otherwise). The returned
    // authorityId is that recomputed key id — the wrapping signer — so no field inside the carried foreign
    // bytes, including any foreign identity claim, can ever become the N-AALP authorization identity
    // (R-14.6). Any failure throws its named error and authorizes nothing (fail-closed).
    fun verifyImport(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ResolvedImport {
        val payload = verifySign1(obj, profile, alg, pubkey)
        val im = parseImport(payload)
        val keyId = Identity.signerId(alg, pubkey)
        // The authorization identity is the wrapping key's own id. The attestation's declared importer MUST
        // match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
        if (String(im.importer, Charsets.UTF_8) != keyId) {
            throw NaalpException("ImporterMismatch", "the attested importer is not the verifying key's signer id")
        }
        return ResolvedImport(keyId, im.format, im.foreignId(), im.operations)
    }

    // ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

    // The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits (matching
    // Gateway.gatewayProtectedHeader).
    private fun descProtectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    // Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
    // Mirrors Gateway.verifyDecision's checks: alg registry, profile floor, key-alg match, signature.
    // Fail-closed with a named error.
    private fun verifySign1(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ByteArray {
        val parts = Cose.parseSign1Raw(obj) // [protected, payload, signature]
        val halg = algFromProtected(parts[0])
        val (level, known) = Cose.algLevel(halg)
        if (!known) throw NaalpException("UnknownAlg", "unregistered alg $halg")
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (halg != alg) throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        return parts[1]
    }

    private fun algFromProtected(prot: ByteArray): Int {
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) throw NaalpException("DescMalformed", "protected header is not a map")
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L) {
                val value = p.v
                if (value is Cbor.N) return value.v.toInt()
                if (value is Cbor.U) return value.v.toInt()
            }
        }
        throw NaalpException("DescMalformed", "protected header has no alg")
    }

    // ---- small deterministic-CBOR field accessors ------------------------------------------------

    private fun decodeMap(b: ByteArray): Cbor.M {
        val v = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("DescMalformed", "body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) throw NaalpException("DescMalformed", "body is not a map")
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
