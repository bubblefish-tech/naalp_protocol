// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C18 signed description / directory / import primitive for the Swift SDK (design.md §21;
// R-DESC-1..8).
//
// C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
// object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the
// connection or the host that served them: the same signed Description re-verifies byte-identically
// when an unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
// introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object
// is an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (Policy) and
// the T1 content-id framing (§2.3) unchanged.
//
// Three wire objects (the namespace is `Description`; the service-description object is `Description.Doc`
// to avoid colliding with the namespace, mirroring the C# port):
//
//   - Doc {1: service, 2: operations[]} lists a service's operations, each Operation
//     {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
//     parseDescription reconstructs the whole operation table from the bytes ALONE.
//   - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are
//     content ids. Two conflicting versions from ONE signer — same directory and version, different
//     members — are a FORK, detected at the FIRST-DIFFERING member POSITION (as the §8.5 audit fork
//     proof reports the position of an equivocation).
//   - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
//     (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet (carriage,
//     not adoption) as a signed N-AALP attestation binding the foreign bytes' content id AND an N-AALP
//     effect mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly from the verifying
//     key) is the SOLE authorization identity; a foreign identity embedded in `foreign` never becomes an
//     N-AALP authorization identity — the confused-deputy rule, enforced normatively here (R-14.6).
//
// An independent transcription of impl/go/description (cross-read against impl/python/naalp/description.py),
// graded against the shared vectors/description/cases.json. The bodies, heads, content ids, the
// foreign-id binding, the fork first-differing position, and the closed foreign-format rejection are
// signature-independent and pure.
//
// CRYPTO SCOPE (PURE-ONLY): the byte surfaces above are pure and corpus-graded. Swift cannot
// deterministically sign or verify ML-DSA (FIPS 204) with SwiftDilithium 3.6.0, so the signed-object
// verify paths (verifyDescription / verifyDirectory / verifyImport / DirectoryForkProof.verify) mirror
// the committed Gateway idiom: a bare {1:alg} COSE_Sign1 with a real Ed25519 (RFC 8032) signature, and
// a faithful alg-registry -> profile-floor -> key-alg -> signature transcription. Ed25519 is level 0,
// below the level-3 profile floor, so a pure-Ed25519 object is rejected ProfileDowngrade; an ML-DSA
// object is refused at the signature step (Unavailable — never a false green). The positive signed
// verify (and thus a fully-crypto-verified DirectoryForkProof position and a post-signature
// ImporterMismatch) needs an ML-DSA level-3 signature the pure tier cannot produce (honest F2/F4); the
// fork position property is corpus-graded via detectFork, and the R-14.6 confused-deputy binding is
// exercised purely (the importer field is the wrapping signer id, never the foreign identity).
//
// DEVIATION (honest F4): Go's verifyImport carries a VerifierKeyMismatch guard because it takes BOTH an
// (alg, pubkey) pair AND a separate verifier and must bind them before deriving the authority id. This
// port — like Gateway/Delegation and the Python/Kotlin/C# ports — verifies with a SINGLE (alg, pubkey),
// so the authority id is ALWAYS derived from exactly the verifying key; the mismatch that guard prevents
// is structurally impossible. There is no VerifierKeyMismatch surface: it is absent because the
// vulnerability cannot arise in this signature, NOT silently dropped.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.

import Crypto
import Foundation

public enum Description {

    /// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    public static let HEAD_SIZE = 48

    // Foreign description format codes (the closed naalp-description-format registry, §21).
    public static let FORMAT_A2A_CARD: UInt64 = 1        // A2A Agent Card
    public static let FORMAT_ANP_DESCRIPTION: UInt64 = 2 // ANP Agent Description
    public static let FORMAT_AGNTCY_BADGE: UInt64 = 3    // AGNTCY Agent Badge

    /// Whether `fmt` is a registered foreign-description format (the closed set {1,2,3}).
    static func isKnownFormat(_ fmt: UInt64) -> Bool {
        return fmt == FORMAT_A2A_CARD || fmt == FORMAT_ANP_DESCRIPTION || fmt == FORMAT_AGNTCY_BADGE
    }

    static func head(_ b: [UInt8]) -> [UInt8] {
        return Array(SHA384.hash(data: Data(b)))
    }

    // ---- Operation: one listed operation with its effect + approval declaration (§21.2) ------------

    /// One entry of a Description or an Import mapping: a named operation, its C5 effect class, and
    /// whether it requires an approval. `requiresApproval` is the uint 1 (yes) / 0 (no) — the N-AALP
    /// spine carries no CBOR boolean (design §3.1).
    public struct Operation {
        public let name: String            // operation name (advisory routing key)
        public let effect: UInt64          // the operation's effect class (C5 lattice)
        public let requiresApproval: UInt64 // 1 if this operation requires an approval, 0 otherwise

        public init(_ name: String, _ effect: UInt64, _ requiresApproval: UInt64) {
            self.name = name
            self.effect = effect
            self.requiresApproval = requiresApproval
        }

        /// The operation as its CBOR map {1: name, 2: effect, 3: requires_approval}.
        func toMap() -> CborValue {
            return .m([
                (.u(1), .t(name)),
                (.u(2), .u(effect)),
                (.u(3), .u(requiresApproval)),
            ])
        }

        /// Deterministic-CBOR encoding of the operation body.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(toMap())
        }

        /// The per-operation effect, normalized fail-closed: an unrecognized value is destructive (R-6.2).
        public func effectClass() -> Int {
            return Policy.normalizeEffect(Int(effect))
        }

        /// True iff the operation declares that it requires an approval.
        public func requiresApprovalFlag() -> Bool {
            return requiresApproval == 1
        }
    }

    /// Parse one operation map, rejecting a malformed shape (DescMalformed) or an approval flag outside
    /// {0,1} (MalformedApprovalFlag). Fail-closed.
    static func operationFromValue(_ v: CborValue) throws -> Operation {
        guard case let .m(pairs) = v else {
            throw NaalpError("DescMalformed", "operation is not a map")
        }
        var name: String? = nil, effect: UInt64? = nil, req: UInt64? = nil
        for (k, val) in pairs {
            guard case let .u(key) = k else {
                throw NaalpError("DescMalformed", "non-uint operation key")
            }
            switch key {
            case 1:
                if case let .t(s) = val { name = s }
            case 2:
                if case let .u(u) = val { effect = u }
            case 3:
                if case let .u(u) = val { req = u }
            default:
                break
            }
        }
        guard let n = name, let e = effect, let r = req else {
            throw NaalpError("DescMalformed", "operation missing a mandatory field")
        }
        if r > 1 {
            throw NaalpError("MalformedApprovalFlag", "requires_approval is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted")
        }
        return Operation(n, e, r)
    }

    /// Parse the operations array.
    static func operationsFromValue(_ v: CborValue) throws -> [Operation] {
        guard case let .a(items) = v else {
            throw NaalpError("DescMalformed", "operations is not an array")
        }
        return try items.map { try operationFromValue($0) }
    }

    /// Encode an operations slice as a CBOR array of operation maps.
    static func operationsValue(_ ops: [Operation]) -> CborValue {
        return .a(ops.map { $0.toMap() })
    }

    /// The first operation with the given name.
    static func findOperation(_ ops: [Operation], _ name: String) -> Operation? {
        return ops.first { $0.name == name }
    }

    // ---- Doc: a service's signed operation table (§21.2) ------------------------------------------

    /// A signed N-AALP object listing a service's operations. Its authority is in the signed bytes:
    /// parseDescription reconstructs the whole operation table from the bytes alone, so an unrelated host
    /// serving the same bytes yields a byte-identical verification (offline-verifiable).
    public struct Doc {
        public let service: [UInt8]        // opaque service id
        public let operations: [Operation] // the listed operations

        public init(service: [UInt8], operations: [Operation]) {
            self.service = service
            self.operations = operations
        }

        /// Deterministic-CBOR encoding {1: service, 2: operations[]}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(service)),
                (.u(2), operationsValue(operations)),
            ]))
        }

        /// The Description's SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Description.head(try bytes()) }

        /// The Description's T1 content id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }

        /// The named operation, or nil if it is not listed.
        public func operation(_ name: String) -> Operation? { return findOperation(operations, name) }
    }

    /// Reconstruct a Doc from its body bytes ALONE — the offline-verifiable property.
    public static func parseDescription(_ b: [UInt8]) throws -> Doc {
        let m = try decodeMap(b)
        guard let svc = bstrField(m, 1), let opsV = field(m, 2) else {
            throw NaalpError("DescMalformed", "description missing service or operations")
        }
        return Doc(service: svc, operations: try operationsFromValue(opsV))
    }

    // ---- Directory: a signed collection of content-ids, with fork detection (§21.3) ---------------

    /// A signed collection object whose members are content ids (the same shape the §8.2 causal partial
    /// order uses for `causes`). It carries a monotonic per-signer version so two versions can be
    /// compared for equivocation.
    public struct Directory {
        public let directory: [UInt8]   // opaque directory id
        public let version: UInt64      // monotonic per-signer version
        public let members: [[UInt8]]   // content ids of the member objects

        public init(directory: [UInt8], version: UInt64, members: [[UInt8]]) {
            self.directory = directory
            self.version = version
            self.members = members
        }

        /// Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(directory)),
                (.u(2), .u(version)),
                (.u(3), .a(members.map { .b($0) })),
            ]))
        }

        /// The Directory's SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Description.head(try bytes()) }

        /// The Directory's T1 content id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }
    }

    /// Reconstruct a Directory from its body bytes alone.
    public static func parseDirectory(_ b: [UInt8]) throws -> Directory {
        let m = try decodeMap(b)
        guard let did = bstrField(m, 1), let ver = uintField(m, 2), let memV = field(m, 3),
              case let .a(items) = memV else {
            throw NaalpError("DescMalformed", "directory missing or malformed field")
        }
        var members: [[UInt8]] = []
        for e in items {
            guard case let .b(bs) = e else {
                throw NaalpError("DescMalformed", "member is not a bstr")
            }
            members.append(bs)
        }
        return Directory(directory: did, version: ver, members: members)
    }

    /// The first index at which two member lists differ, and whether they differ at all. If the lists
    /// share a common prefix and one is longer, the difference is reported at the length of the shorter
    /// list. Identical lists return (0, false).
    static func firstMemberDifference(_ a: [[UInt8]], _ b: [[UInt8]]) -> (position: Int, fork: Bool) {
        let n = min(a.count, b.count)
        for i in 0..<n {
            if a[i] != b[i] {
                return (i, true)
            }
        }
        if a.count != b.count {
            return (n, true)
        }
        return (0, false)
    }

    /// Compare two directory versions from ONE signer and report whether they equivocate — the SAME
    /// directory id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING member POSITION.
    /// A different directory id or version is a legitimate distinct object/succession, not a fork;
    /// identical members are a benign duplicate. In both non-fork cases returns (0, false). The caller
    /// establishes the "one signer" precondition by verifying both objects under the same key.
    public static func detectFork(_ a: Directory, _ b: Directory) -> (position: Int, fork: Bool) {
        if a.directory != b.directory || a.version != b.version {
            return (0, false) // different directory or version — not a conflicting pair
        }
        return firstMemberDifference(a.members, b.members)
    }

    // ---- Import: foreign description carried as a signed attestation (§21.4) -----------------------

    /// Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed N-AALP
    /// attestation. `importer` is the wrapping signer id (the sole authorization identity); `foreign` is
    /// the foreign bytes verbatim; `operations` is the N-AALP effect mapping the importer attests. The
    /// foreign bytes' content id is bound by foreignId().
    public struct Import {
        public let importer: [UInt8]       // the importing (wrapping) signer id — the SOLE authority (R-14.6)
        public let format: UInt64          // the foreign description format code
        public let foreign: [UInt8]        // the foreign description bytes, carried octet-for-octet
        public let operations: [Operation] // the N-AALP effect mapping the importer attests

        public init(importer: [UInt8], format: UInt64, foreign: [UInt8], operations: [Operation]) {
            self.importer = importer
            self.format = format
            self.foreign = foreign
            self.operations = operations
        }

        /// Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(importer)),
                (.u(2), .u(format)),
                (.u(3), .b(foreign)),
                (.u(4), operationsValue(operations)),
            ]))
        }

        /// The Import's SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Description.head(try bytes()) }

        /// The Import attestation's own T1 content id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }

        /// The T1 content id of the carried foreign bytes — the hash the attestation binds. A changed
        /// foreign document yields a different foreignId, so an attestation binds the exact bytes.
        public func foreignId() -> [UInt8] { return Cbor.contentId(foreign) }

        /// The named operation from the attested mapping, or nil.
        public func operation(_ name: String) -> Operation? { return findOperation(operations, name) }
    }

    /// Reconstruct an Import from its body bytes alone. A format code outside the closed
    /// naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never
    /// carried as an unknown format. Fail-closed.
    public static func parseImport(_ b: [UInt8]) throws -> Import {
        let m = try decodeMap(b)
        guard let imp = bstrField(m, 1), let fmt = uintField(m, 2), let foreign = bstrField(m, 3),
              let opsV = field(m, 4) else {
            throw NaalpError("DescMalformed", "import missing a mandatory field")
        }
        // The CDDL types field 2 as the closed enum {1,2,3}; a code outside the set is rejected on decode.
        if !isKnownFormat(fmt) {
            throw NaalpError("UnknownDescriptionFormat", "import format \(fmt) is outside the closed set {1,2,3}")
        }
        return Import(importer: imp, format: fmt, foreign: foreign, operations: try operationsFromValue(opsV))
    }

    /// An Import that has passed signature verification and the confused-deputy check. authorityID is the
    /// self-certifying signer id RECOMPUTED from the verifying key — the wrapping signer, and the only
    /// authorization identity. It is never any identity parsed from the foreign bytes.
    public struct ResolvedImport {
        public let authorityID: String    // the wrapping signer id, recomputed from the key (the sole authority)
        public let format: UInt64
        public let foreignID: [UInt8]      // the content id the attestation binds
        public let operations: [Operation]

        public init(authorityID: String, format: UInt64, foreignID: [UInt8], operations: [Operation]) {
            self.authorityID = authorityID
            self.format = format
            self.foreignID = foreignID
            self.operations = operations
        }
    }

    // ---- signed-object verification (bare {1: alg} COSE_Sign1; Gateway-style pure tier) ------------

    /// The bare {1: alg} COSE_Sign1 protected header (§4); `alg` is a negative COSE identifier carried as
    /// a negative CBOR integer whose argument is `-1 - alg`.
    static func protectedHeader(_ alg: Int) throws -> [UInt8] {
        let arg = UInt64(-1 - alg)
        return try Cbor.encode(.m([(.u(1), .n(arg))]))
    }

    /// Read the alg (label 1) value from an encoded protected header.
    static func algFromProtected(_ prot: [UInt8]) throws -> Int {
        let v = try Cbor.decode(prot)
        guard case let .m(pairs) = v else {
            throw NaalpError("DescMalformed", "protected header is not a map")
        }
        for (k, val) in pairs {
            if case let .u(kn) = k, kn == 1 {
                if case let .n(arg) = val { return -1 - Int(arg) }
                if case let .u(u) = val { return Int(u) }
            }
        }
        throw NaalpError("DescMalformed", "protected header has no alg")
    }

    /// Produce the tagged COSE_Sign1 object over `body`, signed with a real Ed25519 (RFC 8032) signature
    /// (the pure-tier stand-in for the reference's ML-DSA signer). `alg` names the header algorithm.
    static func signBody(_ body: [UInt8], _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(alg)
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, body))
        return try Cose.assembleSign1Raw(prot, body, sig)
    }

    /// Sign a Description into a tagged COSE_Sign1 object.
    public static func signDescription(_ d: Doc, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try signBody(try d.bytes(), alg, seed)
    }

    /// Sign a Directory into a tagged COSE_Sign1 object.
    public static func signDirectory(_ d: Directory, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try signBody(try d.bytes(), alg, seed)
    }

    /// Sign an Import into a tagged COSE_Sign1 object.
    public static func signImport(_ im: Import, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        return try signBody(try im.bytes(), alg, seed)
    }

    /// Verify a tagged COSE_Sign1 object under the profile floor and return the payload. Faithful
    /// transcription: alg registry (UnknownAlg) -> profile floor (ProfileDowngrade) -> key-alg match
    /// (KeyAlgMismatch) -> signature. PURE-ONLY Swift: Ed25519 is verified with real crypto (but a
    /// level-0 Ed25519 object never clears a profile floor, so it is rejected ProfileDowngrade first);
    /// an ML-DSA object is refused at the signature step (Unavailable — never a false green). Fail-closed.
    static func verifySign1(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> [UInt8] {
        let (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        let halg = try algFromProtected(prot)
        let (level, known) = Cose.algLevel(halg)
        if !known {
            throw NaalpError("UnknownAlg", "unregistered alg \(halg)")
        }
        if level < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "signature level below the profile minimum")
        }
        if halg != alg {
            throw NaalpError("KeyAlgMismatch", "alg \(halg) does not match the verifier key alg \(alg)")
        }
        if halg == Cose.ALG_ED25519 {
            if !Cose.ed25519Verify(pubkey, try Cose.toBeSignedRaw(prot, payload), sig) {
                throw NaalpError("BadSignature", "signature does not verify")
            }
            return payload
        }
        // ML-DSA verification is unavailable on the pure Swift port (skip-tracked, never a false green);
        // reachable only for a level-3+ object that cleared the floor (a pure Ed25519 object is rejected
        // at ProfileDowngrade before this point).
        throw NaalpError("Unavailable", "ML-DSA verification requires a deterministic-from-seed FIPS 204 path unavailable in SwiftDilithium 3.6.0")
    }

    /// Verify a Description's signed object under the profile, then reconstruct the operation table from
    /// the signed body bytes. Because the authority is the signature over the bytes, this returns the
    /// identical Description regardless of which host served `obj` (R-DESC-1). Fail-closed.
    public static func verifyDescription(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> Doc {
        return try parseDescription(try verifySign1(obj, profile, alg, pubkey))
    }

    /// Verify a Directory's signed object under the profile, then reconstruct it. Fail-closed.
    public static func verifyDirectory(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> Directory {
        return try parseDirectory(try verifySign1(obj, profile, alg, pubkey))
    }

    /// Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively.
    /// It (1) verifies the signed object under the profile; (2) recomputes the wrapping signer's
    /// SELF-CERTIFYING id from the verifying key (Identity.signerId); and (3) requires the attestation's
    /// `importer` field to equal that recomputed id (ImporterMismatch otherwise). The returned
    /// authorityID is that recomputed key id — the wrapping signer — so no field inside the carried
    /// foreign bytes, including any foreign identity claim, can ever become the N-AALP authorization
    /// identity (R-14.6). Any failure returns its named error and authorizes nothing (fail-closed).
    ///
    /// Single-(alg, pubkey) idiom: the authority id is always derived from exactly the verifying key, so
    /// the VerifierKeyMismatch guard the Go reference carries is structurally unnecessary here — absent
    /// because impossible, not dropped.
    public static func verifyImport(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> ResolvedImport {
        let payload = try verifySign1(obj, profile, alg, pubkey)
        let im = try parseImport(payload)
        let keyID = try Identity.signerId(alg, pubkey)
        // The authorization identity is the wrapping key's own id. The attestation's declared importer
        // MUST match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
        if String(bytes: im.importer, encoding: .utf8) != keyID {
            throw NaalpError("ImporterMismatch", "the attested importer is not the verifying key's signer id — a foreign identity never authorizes")
        }
        return ResolvedImport(authorityID: keyID, format: im.format, foreignID: im.foreignId(), operations: im.operations)
    }

    /// Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer
    /// at the SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN
    /// two signed objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed
    /// objects, the proof is self-contained — mirrors the draft-01 audit ForkProof.
    public struct DirectoryForkProof {
        public let signer: [UInt8]   // accused signer id (both signed objects verify under its key)
        public let signedA: [UInt8]  // the accused's first signed Directory (tagged COSE_Sign1)
        public let signedB: [UInt8]  // the accused's second signed Directory at the same (directory, version)

        public init(signer: [UInt8], signedA: [UInt8], signedB: [UInt8]) {
            self.signer = signer
            self.signedA = signedA
            self.signedB = signedB
        }

        /// Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and
        /// return the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is
        /// present; (2) BOTH signed objects verify under the key (which, because a single verifier checks
        /// both, proves one signer); (3) the two directories share one directory id and version; and (4)
        /// their member lists differ. Any failure rejects the whole proof (fail-closed): an unnamed
        /// signer, a different directory/version, or identical members is DirForkProofInvalid; a
        /// signature that does not verify propagates its named error (ProfileDowngrade / BadSignature).
        public func verify(_ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> Int {
            if signer.isEmpty {
                throw NaalpError("DirForkProofInvalid", "an unnamed accused is not evidence")
            }
            let a = try Description.verifyDirectory(signedA, profile, alg, pubkey)
            let b = try Description.verifyDirectory(signedB, profile, alg, pubkey)
            let (pos, fork) = Description.detectFork(a, b)
            if !fork {
                throw NaalpError("DirForkProofInvalid", "same directory+version identical members, or not the same versioned directory")
            }
            return pos
        }
    }

    // ---- small deterministic-CBOR field accessors -------------------------------------------------

    /// Decode `b` to a canonical CBOR map; a non-canonical body or a non-map is DescMalformed.
    static func decodeMap(_ b: [UInt8]) throws -> [(CborValue, CborValue)] {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("DescMalformed", "body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("DescMalformed", "body is not a map")
        }
        return pairs
    }

    static func field(_ m: [(CborValue, CborValue)], _ k: UInt64) -> CborValue? {
        for (key, val) in m {
            if case let .u(kn) = key, kn == k { return val }
        }
        return nil
    }

    static func bstrField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> [UInt8]? {
        if let v = field(m, k), case let .b(b) = v { return b }
        return nil
    }

    static func uintField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> UInt64? {
        if let v = field(m, k), case let .u(u) = v { return u }
        return nil
    }
}
