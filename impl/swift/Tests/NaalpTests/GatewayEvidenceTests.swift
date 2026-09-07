// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Evidence-record family conformance for the Swift SDK (design.md §26; E6.3 egress-attestation +
// S1 decision-record + S3 checkpoint/witness-cosign/inclusion-proof), graded against the shared
// independent corpus vectors/{decision_record,checkpoint,egress_attestation}/cases.json (NOT
// produced by this code). Ported from impl/go/gateway/{decision_record,checkpoint,
// egress_attestation}_test.go and the verified impl/python + impl/java templates.
//
// CRYPTO SCOPE (FULL): unlike the base C21 GatewayDecision tests (Ed25519-only, written before
// ML-DSA landed on this port), the sign/verify round trips here use REAL deterministic FIPS-204
// ML-DSA-65 via swift-crypto's vendored BoringSSL (task #96/#142), exactly as the Java/Python
// templates — the signed object is byte-identical to the Go/Rust references and the third-party
// re-serve property is demonstrated with the real crypto the profile floor requires.
//
// Written test-first: DecisionRecord/CheckpointRoot/WitnessCosign/InclusionProof/EgressAttestation
// are absent until Gateway.swift carries the evidence-record family, so this fails RED with a
// compile error; a mutation to any bytes() field flips its *_hex assertion.
//
// Run:  swift test --filter GatewayEvidenceTests

import XCTest
@testable import Naalp

private func vectorAt(_ relPath: String) -> [String: Any]? {
    var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<8 {
        let p = dir.appendingPathComponent(relPath)
        if FileManager.default.fileExists(atPath: p.path),
           let data = try? Data(contentsOf: p),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return obj
        }
        dir = dir.deletingLastPathComponent()
    }
    return nil
}

private func loadVectorAt(_ relPath: String) throws -> [String: Any] {
    guard let v = vectorAt(relPath) else {
        throw XCTSkip("\(relPath) not present (standalone build)")
    }
    return v
}

/// A decimal-string `at`/counter value from the corpus (carried as a string so no float64 JSON
/// decoder anywhere in the toolchain can round a value past 2^53) parsed to UInt64.
private func uint64FromStr(_ s: String) throws -> UInt64 {
    return try XCTUnwrap(UInt64(s), "not a valid uint64 decimal string: \(s)")
}

// =====================================================================================================
// S1 naalp-decision-record
// =====================================================================================================

final class DecisionRecordConformanceTests: XCTestCase {

    static func vector() throws -> [String: Any] { try loadVectorAt("vectors/decision_record/cases.json") }

    /// Build the mandatory-field-only shell of a records{}/ordering_examples{} case; the ordering/
    /// terms/enforcement fixture is layered on by build() (mirroring the Python test's dr_from +
    /// _build / the Go test's drFrom + build).
    static func drFrom(_ rv: [String: Any]) throws -> DecisionRecord {
        let governingHex = try XCTUnwrap(rv["governing_hex"] as? [String])
        let governing = governingHex.map { GatewayTests.hexToBytes($0) }
        var consume: [UInt8] = []
        if let ch = rv["consume_hex"] as? String {
            consume = GatewayTests.hexToBytes(ch)
        }
        return DecisionRecord(action: GatewayTests.hexToBytes(try XCTUnwrap(rv["action_hex"] as? String)),
                              governing: governing, outcome: UInt64(try XCTUnwrap(rv["outcome"] as? Int)),
                              ordering: Gateway.correspondenceOnly(), consume: consume)
    }

    /// Reconstruct a records{}/ordering_examples{} case with its exact ordering/terms/enforcement
    /// fixture, mirroring decision_record_test.go's build() switch exactly.
    static func build(_ name: String, _ rv: [String: Any]) throws -> DecisionRecord {
        let d = try drFrom(rv)
        switch name {
        case "allow_consuming", "allow_no_consume", "minimal", "correspondence_only":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: Gateway.correspondenceOnly(), consume: d.consume)
        case "deny_two_governing":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: OrderingDisclosure(basis: Gateway.ORDERING_SINGLE_BOUNDARY,
                                                               boundary: Array("boundary-signer-X".utf8)),
                                  consume: d.consume)
        case "hold_empty_governing", "external_mechanism":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: OrderingDisclosure(
                                      basis: Gateway.ORDERING_EXTERNAL_MECHANISM,
                                      mechanism: Array("external-log:acme-transparency-v1".utf8),
                                      relation: GatewayTests.hexToBytes(
                                          "2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56")),
                                  consume: d.consume)
        case "single_boundary":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: OrderingDisclosure(basis: Gateway.ORDERING_SINGLE_BOUNDARY,
                                                               boundary: Array("SIGNER_B-boundary".utf8)),
                                  consume: d.consume)
        case "external_mechanism_no_relation":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: OrderingDisclosure(basis: Gateway.ORDERING_EXTERNAL_MECHANISM,
                                                               mechanism: Array("external-log:acme-transparency-v1".utf8)),
                                  consume: d.consume)
        case "terms_valid":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: Gateway.correspondenceOnly(), consume: d.consume,
                                  terms: [1: TermDisposition(kind: Gateway.TERM_OBSERVED),
                                          4: TermDisposition(kind: Gateway.TERM_REPORTED,
                                                             source: Array("boundary:relay-partner-3".utf8))])
        case "enforcement_enforced":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: Gateway.correspondenceOnly(), consume: d.consume,
                                  enforcement: Gateway.ENFORCEMENT_ENFORCED)
        case "enforcement_advised":
            return DecisionRecord(action: d.action, governing: d.governing, outcome: d.outcome,
                                  ordering: Gateway.correspondenceOnly(), consume: d.consume,
                                  enforcement: Gateway.ENFORCEMENT_ADVISED)
        default:
            XCTFail("unhandled record name \(name) -- add its ordering/terms/enforcement fixture")
            return d
        }
    }

    // 1. the closed outcome / ordering-basis vocabularies.
    func testVocabularies() throws {
        let c = try Self.vector()
        for e in try XCTUnwrap(c["outcome_vocabulary"] as? [[String: Any]]) {
            let code = UInt64(try XCTUnwrap(e["code"] as? Int))
            let name = try XCTUnwrap(e["name"] as? String)
            XCTAssertTrue(Gateway.isKnownDecision(code), name)
            XCTAssertEqual(Gateway.decisionName(code), name)
        }
        for e in try XCTUnwrap(c["ordering_basis_vocabulary"] as? [[String: Any]]) {
            let code = UInt64(try XCTUnwrap(e["code"] as? Int))
            let name = try XCTUnwrap(e["name"] as? String)
            XCTAssertTrue(Gateway.isKnownOrderingBasis(code), name)
            XCTAssertEqual(Gateway.orderingBasisName(code), name)
        }
        XCTAssertFalse(Gateway.isKnownOrderingBasis(99))
    }

    // 2. byte-exact body/head/content-id for EVERY records{} and ordering_examples{} case (each
    //    reconstructed field-by-field, never routed through the decoder), the parse round-trip, and
    //    full semantic validation (every case here is POSITIVE).
    func testDecisionRecordBodiesMatchOracle() throws {
        let c = try Self.vector()
        let records = try XCTUnwrap(c["records"] as? [String: Any])
        let orderingExamples = try XCTUnwrap(c["ordering_examples"] as? [String: Any])
        var all: [String: [String: Any]] = [:]
        for (k, v) in records { all[k] = v as? [String: Any] }
        for (k, v) in orderingExamples { all[k] = v as? [String: Any] }
        XCTAssertEqual(all.count, records.count + orderingExamples.count, "records/ordering_examples name collision")
        for (name, rv) in all {
            let d = try Self.build(name, rv)
            XCTAssertEqual(GatewayTests.toHex(try d.bytes()), rv["body_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try d.head()), rv["head_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try d.id()), rv["id_hex"] as? String, name)
            let parsed = try Gateway.parseDecisionRecord(try d.bytes())
            XCTAssertEqual(GatewayTests.toHex(try parsed.bytes()), rv["body_hex"] as? String, name)
            XCTAssertNoThrow(try Gateway.validateDecisionRecord(parsed), name)
        }
    }

    // 3. the smallest valid decision-record round-trips through parse+validate.
    func testMinimal() throws {
        let c = try Self.vector()
        let m = try XCTUnwrap((c["records"] as? [String: Any])?["minimal"] as? [String: Any])
        let d = DecisionRecord(action: [], governing: [], outcome: UInt64(try XCTUnwrap(m["outcome"] as? Int)),
                               ordering: Gateway.correspondenceOnly())
        XCTAssertEqual(GatewayTests.toHex(try d.bytes()), m["body_hex"] as? String)
        XCTAssertEqual(GatewayTests.toHex(try d.id()), m["id_hex"] as? String)
        let parsed = try Gateway.parseDecisionRecord(try d.bytes())
        XCTAssertNoThrow(try Gateway.validateDecisionRecord(parsed))
    }

    // 4. every named negative rejection: deny/hold-with-consume, terms-key-outside-field-set, unknown
    //    outcome, every ordering_malformed variant, the descending-key body (NonCanonical at the CBOR
    //    layer, DecisionMalformed once wrapped), and the gateway-decision look-alike.
    func testNegativeRejections() throws {
        let c = try Self.vector()
        let neg = try XCTUnwrap(c["negative"] as? [String: Any])

        func kindOf(_ bodyHex: String) throws -> String {
            let body = GatewayTests.hexToBytes(bodyHex)
            do {
                let d = try Gateway.parseDecisionRecord(body)
                try Gateway.validateDecisionRecord(d)
            } catch let e as NaalpError {
                return e.kind
            }
            return ""
        }

        for key in ["deny_with_consume_rejected", "hold_with_consume_rejected",
                    "terms_key_outside_field_set_rejected", "unknown_outcome_rejected", "look_alike"] {
            let e = try XCTUnwrap(neg[key] as? [String: Any])
            XCTAssertEqual(try kindOf(try XCTUnwrap(e["body_hex"] as? String)), e["reject"] as? String, key)
        }

        let orderingMalformed = try XCTUnwrap(neg["ordering_malformed"] as? [String: Any])
        for (name, ev) in orderingMalformed {
            let e = try XCTUnwrap(ev as? [String: Any])
            XCTAssertEqual(try kindOf(try XCTUnwrap(e["body_hex"] as? String)), e["reject"] as? String,
                           "ordering_malformed.\(name)")
        }

        // keys_out_of_order: the canonical body decodes+validates cleanly; the descending-key body is
        // rejected at the CBOR layer (NonCanonical) before parseDecisionRecord's own checks ever run.
        let koo = try XCTUnwrap(neg["keys_out_of_order"] as? [String: Any])
        let canonical = GatewayTests.hexToBytes(try XCTUnwrap(koo["canonical_body_hex"] as? String))
        let d = try Gateway.parseDecisionRecord(canonical)
        XCTAssertNoThrow(try Gateway.validateDecisionRecord(d))
        let noncanonical = GatewayTests.hexToBytes(try XCTUnwrap(koo["noncanonical_body_hex"] as? String))
        XCTAssertEqual(GatewayTests.errKind { _ = try Cbor.decode(noncanonical) }, "NonCanonical")
        XCTAssertEqual(GatewayTests.errKind { _ = try Gateway.parseDecisionRecord(noncanonical) }, "DecisionMalformed")
    }

    // 5. real ML-DSA-65 sign -> verify -> identical third-party re-serve; a foreign key is rejected
    //    (BadSignature).
    func testThirdPartyReserve() throws {
        let c = try Self.vector()
        let rv = try XCTUnwrap((c["records"] as? [String: Any])?["allow_consuming"] as? [String: Any])
        let d = try Self.build("allow_consuming", rv)
        XCTAssertEqual(GatewayTests.toHex(try d.bytes()), rv["body_hex"] as? String)

        let seedProducer = [UInt8](repeating: 0x71, count: 32)
        let seedForeign = [UInt8](repeating: 0x72, count: 32)
        let alg = Cose.ALG_MLDSA65
        let producerPk = try MlDsa.keygenFromSeed(seedProducer, alg)
        let foreignPk = try MlDsa.keygenFromSeed(seedForeign, alg)

        let obj = try Gateway.signDecisionRecord(d, alg, seedProducer)
        let byProducer = try Gateway.verifyDecisionRecord(obj, Cose.PROFILE_PUBLIC, alg, producerPk)
        let byThirdParty = try Gateway.verifyDecisionRecord(obj, Cose.PROFILE_PUBLIC, alg, producerPk)
        XCTAssertEqual(byProducer.action, byThirdParty.action)
        XCTAssertEqual(byProducer.outcome, byThirdParty.outcome)
        XCTAssertEqual(byThirdParty.outcome, Gateway.DECISION_ALLOW)
        XCTAssertEqual(GatewayTests.toHex(byThirdParty.consume), rv["consume_hex"] as? String)

        XCTAssertEqual(GatewayTests.errKind {
            _ = try Gateway.verifyDecisionRecord(obj, Cose.PROFILE_PUBLIC, alg, foreignPk)
        }, "BadSignature")
    }

    // 6. terms_valid signs and verifies end-to-end, carrying field 6 (terms) through the full
    //    signature-verification + semantic-validation path.
    func testSignVerifyTermsValid() throws {
        let c = try Self.vector()
        let rv = try XCTUnwrap((c["records"] as? [String: Any])?["terms_valid"] as? [String: Any])
        let d = try Self.build("terms_valid", rv)
        XCTAssertEqual(GatewayTests.toHex(try d.bytes()), rv["body_hex"] as? String)
        let seed = [UInt8](repeating: 0x11, count: 32)
        let alg = Cose.ALG_MLDSA65
        let pk = try MlDsa.keygenFromSeed(seed, alg)
        let obj = try Gateway.signDecisionRecord(d, alg, seed)
        let resolved = try Gateway.verifyDecisionRecord(obj, Cose.PROFILE_PUBLIC, alg, pk)
        XCTAssertEqual(resolved.terms[1]?.kind, Gateway.TERM_OBSERVED)
        XCTAssertEqual(resolved.terms[4]?.kind, Gateway.TERM_REPORTED)
        XCTAssertEqual(resolved.terms[4]?.source, Array("boundary:relay-partner-3".utf8))
    }
}

// =====================================================================================================
// S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof
// =====================================================================================================

final class CheckpointConformanceTests: XCTestCase {

    static func vector() throws -> [String: Any] { try loadVectorAt("vectors/checkpoint/cases.json") }

    // 1. genesis prev is HEAD_SIZE zero bytes.
    func testGenesisPrev() throws {
        let c = try Self.vector()
        let genesis = try XCTUnwrap(c["genesis"] as? [String: Any])
        XCTAssertEqual(GatewayTests.toHex(Gateway.genesisPrev()), genesis["prev_hex"] as? String)
        XCTAssertEqual(Gateway.genesisPrev().count, Gateway.HEAD_SIZE)
    }

    // 2. byte-exact body/head/content-id for every named checkpoint, and the parse round-trip.
    func testCheckpointsMatchOracle() throws {
        let c = try Self.vector()
        let checkpoints = try XCTUnwrap(c["checkpoints"] as? [String: Any])
        for (name, cv) in checkpoints {
            let e = try XCTUnwrap(cv as? [String: Any])
            let ck = CheckpointRoot(log: GatewayTests.hexToBytes(try XCTUnwrap(e["log_hex"] as? String)),
                                    size: UInt64(try XCTUnwrap(e["size"] as? Int)),
                                    root: GatewayTests.hexToBytes(try XCTUnwrap(e["root_hex"] as? String)),
                                    prev: GatewayTests.hexToBytes(try XCTUnwrap(e["prev_hex"] as? String)),
                                    at: try uint64FromStr(try XCTUnwrap(e["at_str"] as? String)))
            XCTAssertEqual(GatewayTests.toHex(try ck.bytes()), e["body_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try ck.head()), e["head_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try ck.id()), e["id_hex"] as? String, name)
            let parsed = try Gateway.parseCheckpointRoot(try ck.bytes())
            XCTAssertEqual(GatewayTests.toHex(try parsed.bytes()), e["body_hex"] as? String, name)
        }
    }

    // 3. byte-exact witness-cosigns, and ValidateWitnessCosign accepts a cosign naming its own
    //    accompanying checkpoint's content id.
    func testWitnessCosignsMatchOracle() throws {
        let c = try Self.vector()
        let cosigns = try XCTUnwrap(c["witness_cosigns"] as? [String: Any])
        for (name, wv) in cosigns {
            let e = try XCTUnwrap(wv as? [String: Any])
            let w = WitnessCosign(witness: GatewayTests.hexToBytes(try XCTUnwrap(e["witness_hex"] as? String)),
                                  root: GatewayTests.hexToBytes(try XCTUnwrap(e["root_hex"] as? String)),
                                  at: try uint64FromStr(try XCTUnwrap(e["at_str"] as? String)))
            XCTAssertEqual(GatewayTests.toHex(try w.bytes()), e["body_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try w.head()), e["head_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try w.id()), e["id_hex"] as? String, name)
            let parsed = try Gateway.parseWitnessCosign(try w.bytes())
            XCTAssertNoThrow(try Gateway.validateWitnessCosign(parsed, GatewayTests.hexToBytes(try XCTUnwrap(e["root_hex"] as? String))))
        }
    }

    // 4. two witness-cosigned naalp-checkpoint-root objects at the SAME (log, size) carrying
    //    DIFFERENT root values are fork evidence: a witness naming checkpoint A does not validate
    //    against checkpoint B's content id (WitnessRootMismatch).
    func testForkEvidence() throws {
        let c = try Self.vector()
        let fe = try XCTUnwrap(c["fork_evidence"] as? [String: Any])
        let a = try XCTUnwrap(fe["checkpoint_a"] as? [String: Any])
        let b = try XCTUnwrap(fe["checkpoint_b"] as? [String: Any])
        XCTAssertNotEqual(a["root_hex"] as? String, b["root_hex"] as? String, "fork: different roots at the same (log,size)")
        XCTAssertNotEqual(a["id_hex"] as? String, b["id_hex"] as? String, "fork: different content ids")

        let aId = GatewayTests.hexToBytes(try XCTUnwrap(a["id_hex"] as? String))
        let bId = GatewayTests.hexToBytes(try XCTUnwrap(b["id_hex"] as? String))
        let aWc = try XCTUnwrap(a["witness_cosign"] as? [String: Any])
        let bWc = try XCTUnwrap(b["witness_cosign"] as? [String: Any])
        let wA = try Gateway.parseWitnessCosign(GatewayTests.hexToBytes(try XCTUnwrap(aWc["body_hex"] as? String)))
        let wB = try Gateway.parseWitnessCosign(GatewayTests.hexToBytes(try XCTUnwrap(bWc["body_hex"] as? String)))
        XCTAssertNoThrow(try Gateway.validateWitnessCosign(wA, aId), "witness A names checkpoint A")
        XCTAssertNoThrow(try Gateway.validateWitnessCosign(wB, bId), "witness B names checkpoint B")
        XCTAssertEqual(GatewayTests.errKind { try Gateway.validateWitnessCosign(wA, bId) }, "WitnessRootMismatch",
                       "witness A does not name checkpoint B -- fork evidence")
    }

    // 5. byte-exact inclusion proofs (including the single-leaf empty-path case), the parse
    //    round-trip, generateInclusionProofPath reproducing the SAME audit path, and
    //    verifyInclusionProof recomputing the SAME named root.
    func testInclusionProofsMatchOracle() throws {
        let c = try Self.vector()
        let proofs = try XCTUnwrap(c["inclusion_proofs"] as? [String: Any])
        for (name, pv) in proofs {
            let e = try XCTUnwrap(pv as? [String: Any])
            let pathHex = try XCTUnwrap(e["path_hex"] as? [String])
            let path = pathHex.map { GatewayTests.hexToBytes($0) }
            let root = GatewayTests.hexToBytes(try XCTUnwrap(e["root_hex"] as? String))
            let leaf = GatewayTests.hexToBytes(try XCTUnwrap(e["leaf_hex"] as? String))
            let index = UInt64(try XCTUnwrap(e["index"] as? Int))
            let p = InclusionProof(root: root, leaf: leaf, index: index, path: path)
            XCTAssertEqual(GatewayTests.toHex(try p.bytes()), e["body_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try p.head()), e["head_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try p.id()), e["id_hex"] as? String, name)
            let parsed = try Gateway.parseInclusionProof(try p.bytes())
            XCTAssertEqual(GatewayTests.toHex(try parsed.bytes()), e["body_hex"] as? String, name)
        }

        // leaf3_of7's audit path is reproduced from the checkpoint0_size7 leaf set by
        // generateInclusionProofPath, and verifyInclusionProof recomputes to the SAME root.
        //
        // naalp-inclusion-proof's OWN `root` wire field (leaf3["root_hex"] above) is the T1
        // CONTENT-ID of the checkpoint it proves against (50 bytes; identical to
        // checkpoints.checkpoint0_size7.id_hex) -- design.md §26.5's explicit distinct-quantity
        // convention. verifyInclusionProof's `root` PARAMETER, in contrast, is the raw 48-byte
        // Merkle tree head the audit path recomputes to: the checkpoint's OWN `root` field
        // (checkpoints.checkpoint0_size7.root_hex), never its content-id. Confusing the two here
        // would be exactly the 48-vs-50-byte mixup the design comment warns against.
        let leaf3 = try XCTUnwrap(proofs["leaf3_of7"] as? [String: Any])
        let checkpoints = try XCTUnwrap(c["checkpoints"] as? [String: Any])
        let cp0 = try XCTUnwrap(checkpoints["checkpoint0_size7"] as? [String: Any])
        XCTAssertEqual(UInt64(try XCTUnwrap(cp0["size"] as? Int)), 7)
        XCTAssertEqual(leaf3["root_hex"] as? String, cp0["id_hex"] as? String,
                       "inclusion-proof.root names the checkpoint by content-id")
        let merkleRoot = GatewayTests.hexToBytes(try XCTUnwrap(cp0["root_hex"] as? String))
        let leaf = GatewayTests.hexToBytes(try XCTUnwrap(leaf3["leaf_hex"] as? String))
        let index = UInt64(try XCTUnwrap(leaf3["index"] as? Int))
        let path = (try XCTUnwrap(leaf3["path_hex"] as? [String])).map { GatewayTests.hexToBytes($0) }
        XCTAssertNoThrow(try Gateway.verifyInclusionProof(leaf, index, 7, path, merkleRoot))

        let singleLeaf = try XCTUnwrap(proofs["single_leaf_tree_empty_path"] as? [String: Any])
        XCTAssertEqual(try XCTUnwrap(singleLeaf["path_hex"] as? [String]).count, 0, "single-leaf tree: empty audit path")
        let cpSingle = try XCTUnwrap(checkpoints["checkpoint_single_leaf"] as? [String: Any])
        XCTAssertEqual(singleLeaf["root_hex"] as? String, cpSingle["id_hex"] as? String,
                       "inclusion-proof.root names the checkpoint by content-id")
        let slMerkleRoot = GatewayTests.hexToBytes(try XCTUnwrap(cpSingle["root_hex"] as? String))
        let slLeaf = GatewayTests.hexToBytes(try XCTUnwrap(singleLeaf["leaf_hex"] as? String))
        XCTAssertNoThrow(try Gateway.verifyInclusionProof(slLeaf, 0, 1, [], slMerkleRoot))
        XCTAssertEqual(try Gateway.generateInclusionProofPath([slLeaf], 0).count, 0)
    }

    // 6. MTH({}) = HASH() -- the empty-list base case (RFC 9162 §2.1.1).
    func testEmptyTreeKat() throws {
        let c = try Self.vector()
        let e = try XCTUnwrap(c["empty_tree_kat"] as? [String: Any])
        XCTAssertEqual(GatewayTests.toHex(Gateway.merkleRoot([])), e["root_hex"] as? String)
    }

    // 7. every named negative rejection: witness-root-mismatch, an inclusion proof claimed at the
    //    wrong index, an inclusion proof with a corrupted audit-path entry, the descending-key
    //    checkpoint body (NonCanonical at the CBOR layer, CheckpointMalformed once wrapped), and a
    //    checkpoint body missing a mandatory field.
    func testNegativeRejections() throws {
        let c = try Self.vector()
        let neg = try XCTUnwrap(c["negative"] as? [String: Any])
        let checkpoints = try XCTUnwrap(c["checkpoints"] as? [String: Any])
        let cp0 = try XCTUnwrap(checkpoints["checkpoint0_size7"] as? [String: Any])
        let size7 = UInt64(try XCTUnwrap(cp0["size"] as? Int))
        // As in testInclusionProofsMatchOracle: the vectors' own `root_hex` field on an
        // inclusion-proof case names the checkpoint by CONTENT-ID (50 bytes); the raw 48-byte
        // Merkle root verifyInclusionProof recomputes against is the checkpoint's OWN `root_hex`.
        let merkleRoot7 = GatewayTests.hexToBytes(try XCTUnwrap(cp0["root_hex"] as? String))

        let wrm = try XCTUnwrap(neg["witness_root_mismatch"] as? [String: Any])
        let w = try Gateway.parseWitnessCosign(GatewayTests.hexToBytes(try XCTUnwrap(wrm["cosign_body_hex"] as? String)))
        let accompaniedId = GatewayTests.hexToBytes(try XCTUnwrap(wrm["checkpoint_accompanied_id_hex"] as? String))
        XCTAssertEqual(GatewayTests.errKind { try Gateway.validateWitnessCosign(w, accompaniedId) }, wrm["reject"] as? String)

        let iwi = try XCTUnwrap(neg["inclusion_wrong_index"] as? [String: Any])
        XCTAssertEqual(iwi["root_hex"] as? String, cp0["id_hex"] as? String)
        let iwiPath = (try XCTUnwrap(iwi["path_hex"] as? [String])).map { GatewayTests.hexToBytes($0) }
        XCTAssertEqual(GatewayTests.errKind {
            try Gateway.verifyInclusionProof(GatewayTests.hexToBytes(try XCTUnwrap(iwi["leaf_hex"] as? String)),
                                             UInt64(try XCTUnwrap(iwi["claimed_index"] as? Int)), size7, iwiPath,
                                             merkleRoot7)
        }, iwi["reject"] as? String)

        let iwp = try XCTUnwrap(neg["inclusion_wrong_path"] as? [String: Any])
        XCTAssertEqual(iwp["root_hex"] as? String, cp0["id_hex"] as? String)
        let iwpPath = (try XCTUnwrap(iwp["path_hex"] as? [String])).map { GatewayTests.hexToBytes($0) }
        XCTAssertEqual(GatewayTests.errKind {
            try Gateway.verifyInclusionProof(GatewayTests.hexToBytes(try XCTUnwrap(iwp["leaf_hex"] as? String)),
                                             UInt64(try XCTUnwrap(iwp["index"] as? Int)), size7, iwpPath,
                                             merkleRoot7)
        }, iwp["reject"] as? String)

        let koo = try XCTUnwrap(neg["checkpoint_keys_out_of_order"] as? [String: Any])
        let canonical = GatewayTests.hexToBytes(try XCTUnwrap(koo["canonical_body_hex"] as? String))
        XCTAssertNoThrow(try Gateway.parseCheckpointRoot(canonical))
        let noncanonical = GatewayTests.hexToBytes(try XCTUnwrap(koo["noncanonical_body_hex"] as? String))
        XCTAssertEqual(GatewayTests.errKind { _ = try Cbor.decode(noncanonical) }, "NonCanonical")
        XCTAssertEqual(GatewayTests.errKind { _ = try Gateway.parseCheckpointRoot(noncanonical) }, "CheckpointMalformed")

        let cmf = try XCTUnwrap(neg["checkpoint_missing_field"] as? [String: Any])
        XCTAssertEqual(GatewayTests.errKind {
            _ = try Gateway.parseCheckpointRoot(GatewayTests.hexToBytes(try XCTUnwrap(cmf["body_hex"] as? String)))
        }, cmf["reject"] as? String)
    }

    // 8. real ML-DSA-65 sign round trip for a checkpoint and a witness cosign (mutation coverage for
    //    signCheckpointRoot/signWitnessCosign): Cose.coseVerify1 confirms the signature independently.
    func testSignCheckpointAndWitness() throws {
        let c = try Self.vector()
        let cp = try XCTUnwrap((c["checkpoints"] as? [String: Any])?["checkpoint_single_leaf"] as? [String: Any])
        let ck = CheckpointRoot(log: GatewayTests.hexToBytes(try XCTUnwrap(cp["log_hex"] as? String)),
                                size: UInt64(try XCTUnwrap(cp["size"] as? Int)),
                                root: GatewayTests.hexToBytes(try XCTUnwrap(cp["root_hex"] as? String)),
                                prev: GatewayTests.hexToBytes(try XCTUnwrap(cp["prev_hex"] as? String)),
                                at: try uint64FromStr(try XCTUnwrap(cp["at_str"] as? String)))
        let seed = [UInt8](repeating: 0x21, count: 32)
        let alg = Cose.ALG_MLDSA65
        let pk = try MlDsa.keygenFromSeed(seed, alg)
        let ckObj = try Gateway.signCheckpointRoot(ck, alg, seed)
        XCTAssertTrue(try Cose.coseVerify1(alg, pk, ckObj), "checkpoint signature verifies")

        let wCosign = WitnessCosign(witness: Array("W-1".utf8), root: try ck.id(), at: 1)
        let wObj = try Gateway.signWitnessCosign(wCosign, alg, seed)
        XCTAssertTrue(try Cose.coseVerify1(alg, pk, wObj), "witness-cosign signature verifies")
    }
}

// =====================================================================================================
// E6.3 naalp-egress-attestation
// =====================================================================================================

final class EgressAttestationConformanceTests: XCTestCase {

    static func vector() throws -> [String: Any] { try loadVectorAt("vectors/egress_attestation/cases.json") }

    // 1. the closed binding vocabulary; an out-of-set code is not known.
    func testBindingVocabulary() throws {
        let c = try Self.vector()
        for e in try XCTUnwrap(c["binding_vocabulary"] as? [[String: Any]]) {
            let code = UInt64(try XCTUnwrap(e["code"] as? Int))
            let name = try XCTUnwrap(e["name"] as? String)
            XCTAssertTrue(Gateway.isKnownBinding(code), name)
            XCTAssertEqual(Gateway.bindingName(code), name)
        }
        let unknown = UInt64(try XCTUnwrap(c["unknown_binding"] as? Int))
        XCTAssertFalse(Gateway.isKnownBinding(unknown))
        XCTAssertEqual(Gateway.bindingName(unknown), "unknown")
    }

    // 2. byte-exact body/head/content-id for content_bound and content_free, the parse round-trip,
    //    and validate() raises nothing.
    func testAttestationsMatchOracle() throws {
        let c = try Self.vector()
        let attestations = try XCTUnwrap(c["attestations"] as? [String: Any])
        for (name, av) in attestations {
            let e = try XCTUnwrap(av as? [String: Any])
            let a = EgressAttestation(binding: UInt64(try XCTUnwrap(e["binding"] as? Int)),
                                      digest: GatewayTests.hexToBytes(try XCTUnwrap(e["digest_hex"] as? String)),
                                      effect: UInt64(try XCTUnwrap(e["effect"] as? Int)),
                                      audience: GatewayTests.hexToBytes(try XCTUnwrap(e["audience_hex"] as? String)),
                                      at: try uint64FromStr(try XCTUnwrap(e["at_str"] as? String)))
            XCTAssertEqual(GatewayTests.toHex(try a.bytes()), e["body_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try a.head()), e["head_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try a.id()), e["id_hex"] as? String, name)
            let parsed = try Gateway.parseEgressAttestation(try a.bytes())
            XCTAssertNoThrow(try Gateway.validateEgressAttestation(parsed), name)
            XCTAssertEqual(GatewayTests.toHex(try parsed.bytes()), e["body_hex"] as? String, name)
        }
    }

    // 3. byte-exact body/head/content-id with field 6 (ordering) present, for all three bases.
    func testAttestationsWithOrderingMatchOracle() throws {
        let c = try Self.vector()
        let attestations = try XCTUnwrap(c["attestations_with_ordering"] as? [String: Any])
        for (name, av) in attestations {
            let e = try XCTUnwrap(av as? [String: Any])
            let a = try Gateway.parseEgressAttestation(GatewayTests.hexToBytes(try XCTUnwrap(e["body_hex"] as? String)))
            XCTAssertNotNil(a.ordering, name)
            XCTAssertEqual(GatewayTests.toHex(try a.bytes()), e["body_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try a.head()), e["head_hex"] as? String, name)
            XCTAssertEqual(GatewayTests.toHex(try a.id()), e["id_hex"] as? String, name)
            XCTAssertNoThrow(try Gateway.validateEgressAttestation(a), name)
        }
    }

    // 4. EgressCommit/OpenEgressCommitment: the commitment matches the oracle; a wrong salt or a
    //    wrong object-cid both fail to open; a content_bound attestation never opens.
    func testCommitmentOpen() throws {
        let c = try Self.vector()
        let co = try XCTUnwrap(c["commitment_open"] as? [String: Any])
        let objectCid = GatewayTests.hexToBytes(try XCTUnwrap(co["object_cid_hex"] as? String))
        let wrongObjectCid = GatewayTests.hexToBytes(try XCTUnwrap(co["wrong_object_cid_hex"] as? String))
        let salt = GatewayTests.hexToBytes(try XCTUnwrap(co["salt_hex"] as? String))
        let wrongSalt = GatewayTests.hexToBytes(try XCTUnwrap(co["wrong_salt_hex"] as? String))
        let commitment = GatewayTests.hexToBytes(try XCTUnwrap(co["commitment_hex"] as? String))

        XCTAssertEqual(GatewayTests.toHex(Gateway.egressCommit(objectCid, salt)), co["commitment_hex"] as? String)

        let freeAttestation = EgressAttestation(binding: Gateway.BINDING_CONTENT_FREE, digest: commitment,
                                                effect: 3, audience: [], at: 0)
        XCTAssertTrue(Gateway.openEgressCommitment(freeAttestation, objectCid, salt))
        XCTAssertFalse(Gateway.openEgressCommitment(freeAttestation, objectCid, wrongSalt), "wrong salt fails to open")
        XCTAssertFalse(Gateway.openEgressCommitment(freeAttestation, wrongObjectCid, salt), "wrong object-cid fails to open")

        let boundAttestation = EgressAttestation(binding: Gateway.BINDING_CONTENT_BOUND, digest: commitment,
                                                 effect: 3, audience: [], at: 0)
        XCTAssertFalse(Gateway.openEgressCommitment(boundAttestation, objectCid, salt), "content_bound never opens")
    }

    // 5. edge cases: descending top-level keys (NonCanonical at the CBOR layer, EgMalformed once
    //    wrapped); an empty audience is present-and-valid and distinct by content-id from a
    //    populated one, both distinct from an ABSENT audience field (rejected, field 4 mandatory);
    //    the full uint64 range for `at` (carried as a decimal string in the corpus so no float64
    //    JSON decoder anywhere can round it); the smallest valid attestation; and the
    //    gateway-decision look-alike (field 5 absent).
    func testEdgeCases() throws {
        let c = try Self.vector()
        let edge = try XCTUnwrap(c["edge_cases"] as? [String: Any])

        let koo = try XCTUnwrap(edge["keys_out_of_order"] as? [String: Any])
        let a = EgressAttestation(binding: UInt64(try XCTUnwrap(koo["binding"] as? Int)),
                                  digest: GatewayTests.hexToBytes(try XCTUnwrap(koo["digest_hex"] as? String)),
                                  effect: UInt64(try XCTUnwrap(koo["effect"] as? Int)),
                                  audience: GatewayTests.hexToBytes(try XCTUnwrap(koo["audience_hex"] as? String)),
                                  at: try uint64FromStr(try XCTUnwrap(koo["at_str"] as? String)))
        XCTAssertEqual(GatewayTests.toHex(try a.bytes()), koo["canonical_body_hex"] as? String)
        let noncanonical = GatewayTests.hexToBytes(try XCTUnwrap(koo["noncanonical_body_hex"] as? String))
        XCTAssertEqual(GatewayTests.errKind { _ = try Cbor.decode(noncanonical) }, "NonCanonical")
        XCTAssertEqual(GatewayTests.errKind { _ = try Gateway.parseEgressAttestation(noncanonical) }, "EgMalformed")

        let eva = try XCTUnwrap(edge["empty_vs_absent"] as? [String: Any])
        let emptyAud = try XCTUnwrap(eva["empty_audience"] as? [String: Any])
        let popAud = try XCTUnwrap(eva["populated_audience"] as? [String: Any])
        let emptyParsed = try Gateway.parseEgressAttestation(GatewayTests.hexToBytes(try XCTUnwrap(emptyAud["body_hex"] as? String)))
        let popParsed = try Gateway.parseEgressAttestation(GatewayTests.hexToBytes(try XCTUnwrap(popAud["body_hex"] as? String)))
        XCTAssertEqual(GatewayTests.toHex(try emptyParsed.bytes()), emptyAud["body_hex"] as? String)
        XCTAssertEqual(GatewayTests.toHex(try emptyParsed.id()), emptyAud["id_hex"] as? String)
        XCTAssertEqual(GatewayTests.toHex(try popParsed.id()), popAud["id_hex"] as? String)
        XCTAssertNotEqual(try emptyParsed.id(), try popParsed.id(), "empty != populated by id")
        let absent = try XCTUnwrap(eva["absent_field"] as? [String: Any])
        XCTAssertEqual(GatewayTests.errKind {
            _ = try Gateway.parseEgressAttestation(GatewayTests.hexToBytes(try XCTUnwrap(absent["body_hex"] as? String)))
        }, absent["reject"] as? String)

        let oc = try XCTUnwrap(edge["oversized_counter"] as? [String: Any])
        let ocAt = try XCTUnwrap(UInt64(oc["at_str"] as? String ?? ""))
        XCTAssertEqual(ocAt, UInt64.max)
        let ocA = EgressAttestation(binding: UInt64(try XCTUnwrap(oc["binding"] as? Int)),
                                    digest: GatewayTests.hexToBytes(try XCTUnwrap(oc["digest_hex"] as? String)),
                                    effect: UInt64(try XCTUnwrap(oc["effect"] as? Int)),
                                    audience: GatewayTests.hexToBytes(try XCTUnwrap(oc["audience_hex"] as? String)),
                                    at: ocAt)
        XCTAssertEqual(GatewayTests.toHex(try ocA.bytes()), oc["body_hex"] as? String)
        XCTAssertEqual(GatewayTests.toHex(try ocA.id()), oc["id_hex"] as? String)

        let minimal = try XCTUnwrap(edge["minimal"] as? [String: Any])
        let minA = EgressAttestation(binding: UInt64(try XCTUnwrap(minimal["binding"] as? Int)),
                                     digest: [], effect: UInt64(try XCTUnwrap(minimal["effect"] as? Int)),
                                     audience: [], at: try uint64FromStr(try XCTUnwrap(minimal["at_str"] as? String)))
        XCTAssertEqual(GatewayTests.toHex(try minA.bytes()), minimal["body_hex"] as? String)
        XCTAssertEqual(GatewayTests.toHex(try minA.id()), minimal["id_hex"] as? String)

        let lookAlike = try XCTUnwrap(edge["look_alike"] as? [String: Any])
        XCTAssertEqual(GatewayTests.errKind {
            _ = try Gateway.parseEgressAttestation(GatewayTests.hexToBytes(try XCTUnwrap(lookAlike["body_hex"] as? String)))
        }, lookAlike["reject"] as? String)
    }

    // 6. field-6 ordering-disclosure well-formedness violations decode structurally fine but fail
    //    validate() (OrderingDisclosureMalformed / UnknownOrderingBasis).
    func testNegativeOrdering() throws {
        let c = try Self.vector()
        let negOrdering = try XCTUnwrap(c["negative_ordering"] as? [String: Any])
        for (name, ev) in negOrdering {
            let e = try XCTUnwrap(ev as? [String: Any])
            let parsed = try Gateway.parseEgressAttestation(GatewayTests.hexToBytes(try XCTUnwrap(e["body_hex"] as? String)))
            XCTAssertNotNil(parsed.ordering, name)
            XCTAssertEqual(GatewayTests.errKind { try parsed.ordering!.validate() }, e["reject"] as? String, name)
        }
    }

    // 7. real ML-DSA-65 sign -> verify -> identical third-party re-serve for a content_free
    //    attestation; a foreign key is rejected (BadSignature).
    func testThirdPartyReserve() throws {
        let c = try Self.vector()
        let av = try XCTUnwrap((c["attestations"] as? [String: Any])?["content_free"] as? [String: Any])
        let a = EgressAttestation(binding: UInt64(try XCTUnwrap(av["binding"] as? Int)),
                                  digest: GatewayTests.hexToBytes(try XCTUnwrap(av["digest_hex"] as? String)),
                                  effect: UInt64(try XCTUnwrap(av["effect"] as? Int)),
                                  audience: GatewayTests.hexToBytes(try XCTUnwrap(av["audience_hex"] as? String)),
                                  at: try uint64FromStr(try XCTUnwrap(av["at_str"] as? String)))
        XCTAssertEqual(GatewayTests.toHex(try a.bytes()), av["body_hex"] as? String)

        let seedGateway = [UInt8](repeating: 0x31, count: 32)
        let seedForeign = [UInt8](repeating: 0x32, count: 32)
        let alg = Cose.ALG_MLDSA65
        let gatewayPk = try MlDsa.keygenFromSeed(seedGateway, alg)
        let foreignPk = try MlDsa.keygenFromSeed(seedForeign, alg)

        let obj = try Gateway.signEgressAttestation(a, alg, seedGateway)
        let byGateway = try Gateway.verifyEgressAttestation(obj, Cose.PROFILE_PUBLIC, alg, gatewayPk)
        let byThirdParty = try Gateway.verifyEgressAttestation(obj, Cose.PROFILE_PUBLIC, alg, gatewayPk)
        XCTAssertEqual(byGateway.digest, byThirdParty.digest)
        XCTAssertEqual(byThirdParty.binding, Gateway.BINDING_CONTENT_FREE)
        XCTAssertEqual(GatewayTests.errKind {
            _ = try Gateway.verifyEgressAttestation(obj, Cose.PROFILE_PUBLIC, alg, foreignPk)
        }, "BadSignature")
    }
}
