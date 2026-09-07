// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C18 signed description / directory / import conformance for the Swift SDK (design.md §21;
// R-DESC-1..8), graded against the shared independent corpus vectors/description/cases.json (NOT
// produced by this code): the Description body/head/id and each operation body; the Directory bodies
// (version A, the fork B, the length-fork, the different-version succession); the fork FIRST-DIFFERING
// position (member substitution / truncation / not-a-fork / duplicate); the Import body/head/id and
// the bound foreign-id; and the closed naalp-description-format rejection of an unknown format.
//
// CORPUS-GRADED (pure, signature-independent): all of the byte surfaces above, plus detectFork's
// positions — the load-bearing fork property lives here, not in the signature layer.
//
// ED25519-DEMONSTRATED / PROFILE-FLOORED (isolation, NOT corpus-graded): the signed-object verify
// paths. Swift is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204
// path), so verifyDirectory / verifyImport / DirectoryForkProof mirror the committed Gateway idiom
// (bare {1:alg} COSE_Sign1, real Ed25519 sign, alg-registry + profile-floor + key-alg + signature).
// The reference profile floor is level 3 (ML-DSA); a level-0 Ed25519 object is below it, so the
// reachable branch is ProfileDowngrade — the positive verify (and thus a fully-crypto-verified
// DirectoryForkProof position and a post-signature ImporterMismatch) needs an ML-DSA level-3 signature
// the pure tier cannot produce (honest F2/F4, mirroring the PHP/C# ports). The R-14.6 confused-deputy
// property is exercised purely: the attestation's importer field is the wrapping signer id, never the
// foreign identity embedded in the carried bytes, and foreignId binds the exact foreign bytes.
//
// DEVIATION (honest F4): Go's VerifyImport carries a VerifierKeyMismatch guard because it takes BOTH an
// (alg, pubkey) pair AND a separate verifier and must bind them before deriving the authority id. This
// port — like Gateway/Delegation and the Python/Kotlin/C# ports — verifies with a SINGLE (alg, pubkey),
// so the authority id is ALWAYS derived from exactly the verifying key; the mismatch that guard
// prevents is structurally impossible. There is no VerifierKeyMismatch surface: it is absent because
// the vulnerability cannot arise in this signature, NOT silently dropped.
//
// Written test-first: Naalp.Description is absent until Description.swift lands, so this fails RED with
// a compile error ("cannot find 'Description' in scope"). The load-bearing mutation disabling the
// element comparison in firstMemberDifference flips "directory A vs B fork detected".
//
// Run:  swift test --filter DescriptionTests

import Foundation
import XCTest
@testable import Naalp

final class DescriptionTests: XCTestCase {

    static func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    static func toHex(_ b: [UInt8]) -> String {
        let d = Array("0123456789abcdef")
        var s = ""
        for x in b { s.append(d[Int(x >> 4)]); s.append(d[Int(x & 0x0f)]) }
        return s
    }

    static func u64(_ v: Any?) throws -> UInt64 {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").uint64Value
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/description/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func loadVector() throws -> [String: Any] {
        guard let v = findVector() else {
            throw XCTSkip("vectors/description/cases.json not present (standalone build)")
        }
        return v
    }

    static func errKind(_ fn: () throws -> Void) -> String {
        do { try fn(); return "no-error" } catch let e as NaalpError { return e.kind } catch { return "\(type(of: error))" }
    }

    static func opsOf(_ arr: [[String: Any]]) throws -> [Description.Operation] {
        return try arr.map { o in
            Description.Operation(try XCTUnwrap(o["name"] as? String),
                                  try Self.u64(o["effect"]), try Self.u64(o["requires_approval"]))
        }
    }

    static func hexArray(_ v: Any?) throws -> [[UInt8]] {
        return (try XCTUnwrap(v as? [String])).map { hexToBytes($0) }
    }

    static func directory(_ id: [UInt8], _ version: UInt64, _ membersHex: Any?) throws -> Description.Directory {
        return Description.Directory(directory: id, version: version, members: try Self.hexArray(membersHex))
    }

    // ---- Description: the signed operation table body + each operation body ------------------------

    func testDescriptionBodyMatchesOracle() throws {
        let c = try Self.loadVector()
        let dv = try XCTUnwrap(c["description"] as? [String: Any])
        let doc = Description.Doc(service: Self.hexToBytes(try XCTUnwrap(dv["service_hex"] as? String)),
                                  operations: try Self.opsOf(try XCTUnwrap(dv["operations"] as? [[String: Any]])))
        XCTAssertEqual(Self.toHex(try doc.bytes()), dv["body_hex"] as? String, "description body == oracle")
        XCTAssertEqual(Self.toHex(try doc.head()), dv["head_hex"] as? String, "description head == oracle")
        XCTAssertEqual(Self.toHex(try doc.id()), dv["id_hex"] as? String, "description id == oracle")

        for o in try XCTUnwrap(dv["operations"] as? [[String: Any]]) {
            let op = Description.Operation(try XCTUnwrap(o["name"] as? String), try Self.u64(o["effect"]), try Self.u64(o["requires_approval"]))
            XCTAssertEqual(Self.toHex(try op.bytes()), o["body_hex"] as? String, "operation \(op.name) body == oracle")
        }

        // ParseDescription reconstructs the table from the bytes ALONE (offline-verifiable).
        let parsed = try Description.parseDescription(Self.hexToBytes(try XCTUnwrap(dv["body_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try parsed.bytes()), dv["body_hex"] as? String, "parsed description round-trips")
        let purge = try XCTUnwrap(parsed.operation("purge"), "purge listed")
        XCTAssertEqual(purge.effectClass(), Policy.DESTRUCTIVE, "purge effect == destructive")
        XCTAssertTrue(purge.requiresApprovalFlag(), "purge requires approval")
    }

    // a requires_approval flag outside {0,1} is rejected (the spine carries no CBOR boolean).
    func testMalformedApprovalFlagRejected() {
        let bad = CborValue.m([(.u(1), .t("op")), (.u(2), .u(0)), (.u(3), .u(2))])  // requires_approval = 2
        XCTAssertEqual(Self.errKind { _ = try Description.operationFromValue(bad) },
                       "MalformedApprovalFlag", "requires_approval 2 rejected")
    }

    // ---- Directory: the version A body, the fork B, the length-fork, the succession ---------------

    func testDirectoryBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let dir = try XCTUnwrap(c["directory"] as? [String: Any])
        let id = Self.hexToBytes(try XCTUnwrap(dir["directory_hex"] as? String))
        let ver = try Self.u64(dir["version"])

        let a = try Self.directory(id, ver, dir["members_a_hex"])
        let av = try XCTUnwrap(dir["a"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try a.bytes()), av["body_hex"] as? String, "directory A body == oracle")
        XCTAssertEqual(Self.toHex(try a.head()), av["head_hex"] as? String, "directory A head == oracle")
        XCTAssertEqual(Self.toHex(try a.id()), av["id_hex"] as? String, "directory A id == oracle")

        let forkV = try XCTUnwrap(dir["fork"] as? [String: Any])
        let b = try Self.directory(id, ver, forkV["members_b_hex"])
        let bv = try XCTUnwrap(forkV["b"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try b.bytes()), bv["body_hex"] as? String, "fork B body == oracle")
        XCTAssertEqual(Self.toHex(try b.head()), bv["head_hex"] as? String, "fork B head == oracle")
        XCTAssertEqual(Self.toHex(try b.id()), bv["id_hex"] as? String, "fork B id == oracle")

        let lf = try XCTUnwrap(dir["length_fork"] as? [String: Any])
        let shortDir = try Self.directory(id, ver, lf["members_short_hex"])
        XCTAssertEqual(Self.toHex(try shortDir.bytes()), lf["body_hex"] as? String, "length-fork short body == oracle")

        let dvv = try XCTUnwrap(dir["different_version"] as? [String: Any])
        let v8 = try Self.directory(id, try Self.u64(dvv["version"]), forkV["members_b_hex"])
        XCTAssertEqual(Self.toHex(try v8.bytes()), dvv["body_hex"] as? String, "different-version body == oracle")
    }

    // ---- fork detection at the FIRST-DIFFERING member position -------------------------------------
    // MUTATION TARGET: disabling the element comparison in firstMemberDifference makes the same-length
    // A-vs-B fork return fork=false, flipping "directory A vs B fork detected". (The length-fork branch
    // still fires, proving the flip is exactly this assertion.)
    func testDirectoryForkAtPosition() throws {
        let c = try Self.loadVector()
        let dir = try XCTUnwrap(c["directory"] as? [String: Any])
        let id = Self.hexToBytes(try XCTUnwrap(dir["directory_hex"] as? String))
        let ver = try Self.u64(dir["version"])
        let forkV = try XCTUnwrap(dir["fork"] as? [String: Any])
        let lf = try XCTUnwrap(dir["length_fork"] as? [String: Any])
        let dvv = try XCTUnwrap(dir["different_version"] as? [String: Any])

        let a = try Self.directory(id, ver, dir["members_a_hex"])
        let b = try Self.directory(id, ver, forkV["members_b_hex"])
        let shortDir = try Self.directory(id, ver, lf["members_short_hex"])
        let v8 = try Self.directory(id, try Self.u64(dvv["version"]), forkV["members_b_hex"])

        // member substitution: same directory + version, member[1] differs -> fork at position 1.
        let (pos, fork) = Description.detectFork(a, b)
        XCTAssertTrue(fork, "directory A vs B fork detected")
        XCTAssertEqual(pos, try XCTUnwrap((forkV["first_differing_position"] as? NSNumber)?.intValue), "A vs B fork position == oracle")

        // truncation: the shorter list forks at its length.
        let (lpos, lfork) = Description.detectFork(a, shortDir)
        XCTAssertTrue(lfork, "length-fork detected")
        XCTAssertEqual(lpos, try XCTUnwrap((lf["first_differing_position"] as? NSNumber)?.intValue), "length-fork position == oracle")

        // identical members => benign duplicate, not a fork (the corpus -1 sentinel).
        let (_, dupFork) = Description.detectFork(a, a)
        XCTAssertFalse(dupFork, "identical members are not a fork")
        XCTAssertEqual(try XCTUnwrap((dir["duplicate_first_differing_position"] as? NSNumber)?.intValue), -1, "duplicate corpus sentinel")

        // a different version is a legitimate succession, not a fork.
        let (_, verFork) = Description.detectFork(a, v8)
        XCTAssertFalse(verFork, "a different version is a succession, not a fork")

        // a different directory id is not a conflicting pair.
        let other = try Self.directory([0x00], ver, dir["members_a_hex"])
        let (_, otherFork) = Description.detectFork(a, other)
        XCTAssertFalse(otherFork, "a different directory id is not a conflicting pair")
    }

    // ---- Import: the attestation body + the bound foreign-id, and unknown-format rejection ---------

    func testImportBodyMatchesOracle() throws {
        let c = try Self.loadVector()
        let im = try XCTUnwrap(c["import"] as? [String: Any])
        let imp = Description.Import(importer: Self.hexToBytes(try XCTUnwrap(im["importer_hex"] as? String)),
                                    format: try Self.u64(im["format"]),
                                    foreign: Self.hexToBytes(try XCTUnwrap(im["foreign_hex"] as? String)),
                                    operations: try Self.opsOf(try XCTUnwrap(im["operations"] as? [[String: Any]])))
        XCTAssertEqual(Self.toHex(try imp.bytes()), im["body_hex"] as? String, "import body == oracle")
        XCTAssertEqual(Self.toHex(try imp.head()), im["head_hex"] as? String, "import head == oracle")
        XCTAssertEqual(Self.toHex(try imp.id()), im["id_hex"] as? String, "import id == oracle")
        XCTAssertEqual(Self.toHex(imp.foreignId()), im["foreign_id_hex"] as? String, "import foreign-id == oracle")

        // ParseImport round-trips the body bytes.
        let parsed = try Description.parseImport(Self.hexToBytes(try XCTUnwrap(im["body_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try parsed.bytes()), im["body_hex"] as? String, "parsed import round-trips")

        // a format outside the closed naalp-description-format set {1,2,3} is rejected on decode.
        let uf = try XCTUnwrap(im["unknown_format"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Description.parseImport(Self.hexToBytes(try XCTUnwrap(uf["body_hex"] as? String))) },
                       uf["reject"] as? String, "unknown format rejected")

        // R-14.6 (pure): the importer field is NOT the foreign identity embedded in the carried bytes.
        let foreignStr = String(bytes: imp.foreign, encoding: .utf8) ?? ""
        XCTAssertTrue(foreignStr.contains(try XCTUnwrap(im["foreign_asserted_identity"] as? String)), "foreign identity embedded")
        XCTAssertNotEqual(String(bytes: imp.importer, encoding: .utf8), im["foreign_asserted_identity"] as? String,
                          "the importer is not the foreign identity (confused-deputy)")
    }

    // ---- signed-object paths: reachable pure-tier branches + the fork proof structure --------------

    func testSignedPathsReachableBranches() throws {
        let c = try Self.loadVector()
        let dir = try XCTUnwrap(c["directory"] as? [String: Any])
        let id = Self.hexToBytes(try XCTUnwrap(dir["directory_hex"] as? String))
        let ver = try Self.u64(dir["version"])
        let forkV = try XCTUnwrap(dir["fork"] as? [String: Any])

        let a = try Self.directory(id, ver, dir["members_a_hex"])
        let b = try Self.directory(id, ver, forkV["members_b_hex"])

        let seed = [UInt8](repeating: 0x15, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let signerID = try Identity.signerId(Cose.ALG_ED25519, pk)

        let signedA = try Description.signDirectory(a, Cose.ALG_ED25519, seed)
        let signedB = try Description.signDirectory(b, Cose.ALG_ED25519, seed)

        // verifyDirectory floors a level-0 Ed25519 object (ProfileDowngrade); its success path needs
        // an ML-DSA level-3 signature the pure tier cannot produce.
        XCTAssertEqual(Self.errKind { _ = try Description.verifyDirectory(signedA, Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk) },
                       "ProfileDowngrade", "verifyDirectory floors Ed25519")
        // an unregistered alg is UnknownAlg.
        let bogus = try Description.signDirectory(a, -99, seed)
        XCTAssertEqual(Self.errKind { _ = try Description.verifyDirectory(bogus, Cose.PROFILE_PUBLIC, -99, pk) },
                       "UnknownAlg", "verifyDirectory rejects an unregistered alg")

        // DirectoryForkProof: an unnamed accused is rejected BEFORE any signature check (fail-closed).
        let unnamed = Description.DirectoryForkProof(signer: [], signedA: signedA, signedB: signedB)
        XCTAssertEqual(Self.errKind { _ = try unnamed.verify(Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk) },
                       "DirForkProofInvalid", "unnamed accused is not evidence")
        // a named fork proof reaches the signature layer, which floors Ed25519 (ProfileDowngrade); the
        // fork POSITION property itself is corpus-graded via detectFork above.
        let named = Description.DirectoryForkProof(signer: Array(signerID.utf8), signedA: signedA, signedB: signedB)
        XCTAssertEqual(Self.errKind { _ = try named.verify(Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk) },
                       "ProfileDowngrade", "named fork proof reaches the floored signature layer")

        // verifyImport likewise floors a level-0 Ed25519 import (the positive path + ImporterMismatch
        // need an ML-DSA signature); the R-14.6 confused-deputy binding is corpus/pure-graded above.
        let im = try XCTUnwrap(c["import"] as? [String: Any])
        let imp = Description.Import(importer: Array(signerID.utf8), format: Description.FORMAT_ANP_DESCRIPTION,
                                    foreign: Self.hexToBytes(try XCTUnwrap(im["foreign_hex"] as? String)),
                                    operations: try Self.opsOf(try XCTUnwrap(im["operations"] as? [[String: Any]])))
        let signedImp = try Description.signImport(imp, Cose.ALG_ED25519, seed)
        XCTAssertEqual(Self.errKind { _ = try Description.verifyImport(signedImp, Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk) },
                       "ProfileDowngrade", "verifyImport floors Ed25519")
    }
}
