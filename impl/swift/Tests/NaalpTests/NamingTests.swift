// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C19 name-binding + signed A2A task-state profile conformance for the Swift SDK (design.md §22;
// R-NAME-1..6, R-A2A-1..7), graded against the shared independent corpus vectors/naming/cases.json
// (values from the corpus, NEVER produced by this code). C19 is two receipt-CHAINED, offline-walkable
// surfaces carried on N-AALP's own signed object; both reuse the C7 audit receipt-chain construction
// (head=SHA-384(body), genesis prev=48 zero bytes, monotonic seq, prior head carried in the body) and
// add NO new mechanism (R-11.3).
//
// CORPUS-GRADED (pure, signature-independent): (1) every NameBinding body/head/id and every Transition
// body/head/id — including the >2^53 seq round-trip and the empty-field minimal — matched byte-for-byte
// to the oracle (⟹ Go == Rust == Python); (2) the offline walk verdicts — WalkHistory signer
// succession, DetectHole/DetectFork/DetectTaskGap first-broken positions, and the task-chain structural
// walk (start-state, contiguity, prev/seq linkage, card binding, legal-edge table); (3) the A2A
// legal/illegal edge table; (4) the strict-decoder NonCanonical rejection and the binding<->transition
// look-alike NameMalformed rejections; and (5) the A2A Agent Card import content-id (card_id ==
// multihash(0x20, SHA-384(import_body)), both provided independently by the corpus — non-circular).
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): signBinding/verifyChain, NameForkProof.verify,
// and signTransition/verifyTaskChain over real Ed25519 (RFC 8032) signed objects verified through an
// INJECTED verify closure (the pure-tier stand-in for the reference's ML-DSA verifier). Swift is
// PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0). SIGNED-PIN NOTE (honest F2/F4): C19's cross-language
// SIGNED pins (a seq-0 binding and a seq-0 transition) are real deterministic ML-DSA (FIPS 204)
// COSE_Sign1 objects; they are NOT reproducible in the pure tier and are NOT faked here — the surfaces
// this port grades are the byte bodies/heads/ids and the walk/edge/decode verdicts, all
// signature-independent, and the signature BINDING is demonstrated in isolation with Ed25519.
//
// Written test-first: Naalp.Naming / NameBinding / Transition are absent until Naming.swift lands, so
// this fails RED with a compile error ("cannot find 'Naming' in scope"). The load-bearing mutation:
// making Naming.legalEdge return true unconditionally flips "illegal edge [4,1] rejected
// (IllegalTransition)" (and every other illegal-edge / from-terminal check) on its assertion.
//
// Run:  swift test --filter NamingTests

import XCTest
@testable import Naalp

final class NamingTests: XCTestCase {

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
            let p = dir.appendingPathComponent("vectors/naming/cases.json")
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
            throw XCTSkip("vectors/naming/cases.json not present (standalone build)")
        }
        return v
    }

    /// A deterministic Ed25519 keypair for a label, derived through Naalp's public SHA-384 content-id
    /// (first 32 octets of the digest). The pure-tier stand-in for the reference's ML-DSA signer.
    static func nmKey(_ label: String) throws -> (seed: [UInt8], pk: [UInt8]) {
        let seed = Array(Cbor.contentId(Array("naalp-naming-key:\(label)".utf8)).dropFirst(2).prefix(32))
        return (seed, try Cose.ed25519PublicKey(seed))
    }

    static func nmVerify(_ pk: [UInt8]) -> Naming.Verify {
        return { m, s in Cose.ed25519Verify(pk, m, s) }
    }

    // ===== Task 4.1 — name bindings =====

    // 1. every name-binding body, chain head, and content id are byte-identical to the oracle.
    func testBindingBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let name = try XCTUnwrap(nb["name_utf8"] as? String)
        let bindings = try XCTUnwrap(nb["bindings"] as? [[String: Any]])
        XCTAssertFalse(bindings.isEmpty, "corpus has bindings")
        for bj in bindings {
            let b = Naming.NameBinding(name: name, signer: Self.hexToBytes(try XCTUnwrap(bj["signer_hex"] as? String)),
                                       seq: try Self.u64(bj["seq"]), prev: Self.hexToBytes(try XCTUnwrap(bj["prev_hex"] as? String)))
            XCTAssertEqual(Self.toHex(try b.bytes()), bj["body_hex"] as? String, "binding body == oracle")
            XCTAssertEqual(Self.toHex(try b.head()), bj["head_hex"] as? String, "binding head == oracle")
            XCTAssertEqual(Self.toHex(try b.id()), bj["id_hex"] as? String, "binding id == oracle")
        }
    }

    // 2. a seq > 2^53 (0x0102030405060708) round-trips byte-exact (carried as a STRING in the corpus).
    func testBigSeqBinding() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let name = try XCTUnwrap(nb["name_utf8"] as? String)
        let bs = try XCTUnwrap(nb["big_seq"] as? [String: Any])
        let seq = try XCTUnwrap(UInt64(try XCTUnwrap(bs["seq_str"] as? String)), "seq_str parses as UInt64")
        let b = Naming.NameBinding(name: name, signer: Self.hexToBytes(try XCTUnwrap(bs["signer_hex"] as? String)),
                                   seq: seq, prev: Self.hexToBytes(try XCTUnwrap(bs["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try b.bytes()), bs["body_hex"] as? String, "big-seq binding body == oracle")
        XCTAssertEqual(Self.toHex(try b.head()), bs["head_hex"] as? String, "big-seq binding head == oracle")
        XCTAssertEqual(Self.toHex(try b.id()), bs["id_hex"] as? String, "big-seq binding id == oracle")
    }

    // 3. the all-empty minimal binding encodes exactly.
    func testMinimalBinding() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let mn = try XCTUnwrap(nb["minimal"] as? [String: Any])
        let b = Naming.NameBinding(name: try XCTUnwrap(mn["name_utf8"] as? String),
                                   signer: Self.hexToBytes(try XCTUnwrap(mn["signer_hex"] as? String)),
                                   seq: try Self.u64(mn["seq"]), prev: Self.hexToBytes(try XCTUnwrap(mn["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try b.bytes()), mn["body_hex"] as? String, "minimal binding body == oracle")
        XCTAssertEqual(Self.toHex(try b.head()), mn["head_hex"] as? String, "minimal binding head == oracle")
        XCTAssertEqual(Self.toHex(try b.id()), mn["id_hex"] as? String, "minimal binding id == oracle")
    }

    static func chain(_ nb: [String: Any]) throws -> [Naming.NameBinding] {
        let name = try XCTUnwrap(nb["name_utf8"] as? String)
        return try XCTUnwrap(nb["bindings"] as? [[String: Any]]).map { bj in
            Naming.NameBinding(name: name, signer: hexToBytes(try XCTUnwrap(bj["signer_hex"] as? String)),
                               seq: try u64(bj["seq"]), prev: hexToBytes(try XCTUnwrap(bj["prev_hex"] as? String)))
        }
    }

    // 4. WalkHistory verifies the chain offline and returns the signer succession == oracle.
    func testWalkHistory() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let chain = try Self.chain(nb)
        let walk = try XCTUnwrap(nb["walk"] as? [[String: Any]])
        let events = try Naming.walkHistory(chain)
        XCTAssertEqual(events.count, walk.count, "walk length == oracle")
        for (i, w) in walk.enumerated() {
            XCTAssertEqual(Self.toHex(events[i].signer), w["signer_hex"] as? String, "walk[\(i)] signer == oracle")
        }
        XCTAssertEqual(Self.toHex(events.last!.signer), walk.last?["signer_hex"] as? String, "current signer == last walk signer")
    }

    // 5. DetectHole: a deleted binding at seq 1 (present [0,2]) breaks contiguity at position 1; the full
    //    contiguous chain has no hole.
    func testDetectHole() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let chain = try Self.chain(nb)
        let (holePos, hole) = Naming.detectHole([chain[0], chain[2]])
        XCTAssertTrue(hole, "hole detected")
        XCTAssertEqual(UInt64(holePos), try Self.u64((nb["hole"] as? [String: Any])?["first_hole_position"]), "hole position == oracle")
        XCTAssertFalse(Naming.detectHole(chain).1, "full chain has no hole")
    }

    // 6. DetectFork: two bindings at the SAME (name, seq 1) naming DIFFERENT signers => a fork at seq 1;
    //    byte-identical bindings and different-seq bindings are NOT a fork.
    func testDetectFork() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let chain = try Self.chain(nb)
        let fork = try XCTUnwrap(nb["fork"] as? [String: Any])
        let fj = try XCTUnwrap(fork["b_prime"] as? [String: Any])
        let bPrime = Naming.NameBinding(name: try XCTUnwrap(nb["name_utf8"] as? String),
                                        signer: Self.hexToBytes(try XCTUnwrap(fj["signer_hex"] as? String)),
                                        seq: try Self.u64(fj["seq"]), prev: Self.hexToBytes(try XCTUnwrap(fj["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try bPrime.bytes()), fj["body_hex"] as? String, "b_prime body == oracle")
        let (forkPos, isFork) = Naming.detectFork(chain[1], bPrime)
        XCTAssertTrue(isFork, "fork detected")
        XCTAssertEqual(UInt64(forkPos), try Self.u64(fork["position"]), "fork position == oracle")
        XCTAssertFalse(Naming.detectFork(chain[1], chain[1]).1, "byte-identical bindings are not a fork")
        XCTAssertFalse(Naming.detectFork(chain[0], chain[1]).1, "different-seq bindings are not a fork")
    }

    // 7. the strict decoder rejects a non-canonical (descending-key) binding body as NonCanonical, and
    //    ParseNameBinding surfaces it as NameMalformed; the canonical form decodes.
    func testStrictDecodeAndParse() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let ko = try XCTUnwrap(nb["keys_out_of_order"] as? [String: Any])
        let noncanon = Self.hexToBytes(try XCTUnwrap(ko["noncanonical_binding_body_hex"] as? String))
        let canon = Self.hexToBytes(try XCTUnwrap(ko["canonical_binding_body_hex"] as? String))
        XCTAssertThrowsError(try Cbor.decode(noncanon), "non-canonical body rejected by strict decoder (NonCanonical)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, ko["reject"] as? String, "reject kind == oracle")
        }
        XCTAssertNoThrow(try Cbor.decode(canon), "canonical body decodes")
        XCTAssertThrowsError(try Naming.parseNameBinding(noncanon), "ParseNameBinding rejects non-canonical (NameMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NameMalformed")
        }
    }

    // 8. look-alike: a 4-field binding fed to ParseTransition and a 6-field transition fed to
    //    ParseNameBinding are both NameMalformed (the shapes do not cross).
    func testLookAlike() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let la = try XCTUnwrap(nb["look_alike"] as? [String: Any])
        let bindingBody = Self.hexToBytes(try XCTUnwrap(la["binding_body_hex"] as? String))
        let transitionBody = Self.hexToBytes(try XCTUnwrap(la["transition_body_hex"] as? String))
        XCTAssertThrowsError(try Naming.parseTransition(bindingBody), "binding body rejected by ParseTransition (NameMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NameMalformed")
        }
        XCTAssertThrowsError(try Naming.parseNameBinding(transitionBody), "transition body rejected by ParseNameBinding (NameMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NameMalformed")
        }
    }

    // 9. VerifyChain over REAL Ed25519-signed bindings (isolation): a well-signed contiguous chain
    //    verifies; a reordered chain is NameChainBroken; a tampered signature is BadSignature.
    func testSignedChainEd25519() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let chain = try Self.chain(nb)
        let key = try Self.nmKey("registrar")
        let signed = try chain.map { try Naming.signBinding($0, key.seed) }
        XCTAssertNoThrow(try Naming.verifyChain(signed, Self.nmVerify(key.pk)), "Ed25519-signed chain verifies")
        let reordered = [signed[0], signed[2], signed[1]]
        XCTAssertThrowsError(try Naming.verifyChain(reordered, Self.nmVerify(key.pk)), "reordered signed chain rejected (NameChainBroken)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NameChainBroken")
        }
        var badObj = signed
        var t = badObj[0]; t[t.count - 1] ^= 0x01; badObj[0] = t
        XCTAssertThrowsError(try Naming.verifyChain(badObj, Self.nmVerify(key.pk)), "tampered signed binding rejected (BadSignature)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature")
        }
    }

    // 9.5 the Registrar appends the same monotonic chain the oracle records: appending each vector signer
    //     as the subject at the next chain position yields a binding whose body == the oracle body_hex
    //     (signature-independent). MUTATION TARGET: dropping the chainHead advance (or the seq increment)
    //     in Registrar.append flips "registrar reproduces oracle body[1]" (prev/seq stop matching).
    func testRegistrarReproducesOracleBodies() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let name = try XCTUnwrap(nb["name_utf8"] as? String)
        let bindings = try XCTUnwrap(nb["bindings"] as? [[String: Any]])
        let key = try Self.nmKey("registrar")
        let reg = Naming.Registrar(name: name, seed: key.seed)
        for (i, b) in bindings.enumerated() {
            let subject = Self.hexToBytes(try XCTUnwrap(b["signer_hex"] as? String))
            let (binding, obj) = try reg.append(subject)
            XCTAssertEqual(Self.toHex(try binding.bytes()),
                           try XCTUnwrap(b["body_hex"] as? String),
                           "registrar reproduces oracle body[\(i)]")
            XCTAssertNoThrow(try Naming.verifyBinding(obj, Self.nmVerify(key.pk)),
                             "registrar object verifies (seq \(i))")
        }
    }

    // 10. NameForkProof: two same-key Ed25519-signed bindings at (name, seq 1) naming different signers is
    //     a non-repudiable fork proof reported at seq 1; an unnamed accused and identical bindings are not.
    func testNameForkProofEd25519() throws {
        let c = try Self.loadVector()
        let nb = try XCTUnwrap(c["name"] as? [String: Any])
        let chain = try Self.chain(nb)
        let fork = try XCTUnwrap(nb["fork"] as? [String: Any])
        let fj = try XCTUnwrap(fork["b_prime"] as? [String: Any])
        let bPrime = Naming.NameBinding(name: try XCTUnwrap(nb["name_utf8"] as? String),
                                        signer: Self.hexToBytes(try XCTUnwrap(fj["signer_hex"] as? String)),
                                        seq: try Self.u64(fj["seq"]), prev: Self.hexToBytes(try XCTUnwrap(fj["prev_hex"] as? String)))
        let key = try Self.nmKey("registrar")
        let signedB1 = try Naming.signBinding(chain[1], key.seed)
        let signedBPrime = try Naming.signBinding(bPrime, key.seed)
        let accused = Self.hexToBytes(try XCTUnwrap(fj["signer_hex"] as? String))

        let fp = Naming.NameForkProof(signer: accused, signedA: signedB1, signedB: signedBPrime)
        let pos = try fp.verify(Self.nmVerify(key.pk))
        XCTAssertEqual(UInt64(pos), try Self.u64(fork["position"]), "fork proof position == oracle")

        let unnamed = Naming.NameForkProof(signer: [], signedA: signedB1, signedB: signedBPrime)
        XCTAssertThrowsError(try unnamed.verify(Self.nmVerify(key.pk)), "unnamed accused rejected (NameForkProofInvalid)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NameForkProofInvalid")
        }
        let signedB1b = try Naming.signBinding(chain[1], key.seed)
        let same = Naming.NameForkProof(signer: accused, signedA: signedB1, signedB: signedB1b)
        XCTAssertThrowsError(try same.verify(Self.nmVerify(key.pk)), "identical bindings are not a fork proof (NameForkProofInvalid)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NameForkProofInvalid")
        }
    }

    // ===== Task 4.2 — the signed A2A task-state profile =====

    // 11. A2A state categories match the imported A2A vocabulary (§4.1.3).
    func testA2AStateCategories() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let states = try XCTUnwrap(a["states"] as? [String: Any])
        XCTAssertEqual(Naming.START_STATE, try Self.u64(states["start"]), "start state == oracle")
        for s in try XCTUnwrap(states["terminal"] as? [Any]) {
            XCTAssertTrue(Naming.isTerminal(try Self.u64(s)), "state \(s) is terminal")
        }
        for s in try XCTUnwrap(states["interrupted"] as? [Any]) {
            XCTAssertTrue(Naming.isInterrupted(try Self.u64(s)), "state \(s) is interrupted")
        }
        for s: UInt64 in 0...7 {
            XCTAssertTrue(Naming.isState(s), "state \(s) is a defined A2A state")
        }
        XCTAssertFalse(Naming.isState(8), "state 8 is NOT a defined state")
    }

    // 12. the A2A legal-edge table == oracle, both ways, and THE MUTATION TARGET: every listed legal edge
    //     is legal; every listed illegal edge is refused (IllegalTransition); the table has exactly the
    //     oracle's cardinality. Making legalEdge return true flips the illegal-edge checks.
    func testLegalEdgeTable() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let legal = try XCTUnwrap(a["legal_edges"] as? [[Any]])
        let illegal = try XCTUnwrap(a["illegal_edges"] as? [[Any]])
        for e in legal {
            XCTAssertTrue(Naming.legalEdge(try Self.u64(e[0]), try Self.u64(e[1])), "legal edge [\(e[0]),\(e[1])] accepted")
        }
        for e in illegal {
            XCTAssertThrowsError(try Naming.verifyTransition(try Self.u64(e[0]), try Self.u64(e[1])),
                                 "illegal edge [\(e[0]),\(e[1])] rejected (IllegalTransition)") {
                XCTAssertEqual(($0 as? NaalpError)?.kind, "IllegalTransition")
            }
        }
        XCTAssertEqual(Naming.legalEdges().count, legal.count, "legal-edge table cardinality == oracle")
    }

    // 13. the A2A Agent Card import content-id == multihash(0x20, SHA-384(import_body)) — non-circular
    //     (the corpus provides both the import body and its content id independently).
    func testCardContentId() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let card = try XCTUnwrap(a["card"] as? [String: Any])
        let importBody = Self.hexToBytes(try XCTUnwrap(card["import_body_hex"] as? String))
        XCTAssertEqual(Self.toHex(Cbor.contentId(importBody)), card["card_id_hex"] as? String, "card content-id == multihash(SHA-384(import_body))")
    }

    static func transitions(_ a: [String: Any]) throws -> (task: [UInt8], card: [UInt8], list: [Naming.Transition]) {
        let task = Array((try XCTUnwrap(a["task_utf8"] as? String)).utf8)
        let card = hexToBytes(try XCTUnwrap((a["card"] as? [String: Any])?["card_id_hex"] as? String))
        let list = try XCTUnwrap(a["transitions"] as? [[String: Any]]).map { tj in
            Naming.Transition(task: task, card: card, from: try u64(tj["from"]), to: try u64(tj["to"]),
                              seq: try u64(tj["seq"]), prev: hexToBytes(try XCTUnwrap(tj["prev_hex"] as? String)))
        }
        return (task, card, list)
    }

    // 14. every task-transition body, chain head, and content id are byte-identical to the oracle.
    func testTransitionBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let (_, _, list) = try Self.transitions(a)
        let raw = try XCTUnwrap(a["transitions"] as? [[String: Any]])
        XCTAssertFalse(list.isEmpty, "corpus has transitions")
        for (i, tr) in list.enumerated() {
            XCTAssertEqual(Self.toHex(try tr.bytes()), raw[i]["body_hex"] as? String, "transition \(i) body == oracle")
            XCTAssertEqual(Self.toHex(try tr.head()), raw[i]["head_hex"] as? String, "transition \(i) head == oracle")
            XCTAssertEqual(Self.toHex(try tr.id()), raw[i]["id_hex"] as? String, "transition \(i) id == oracle")
        }
    }

    // 15. big-seq + minimal transitions encode exactly.
    func testBigSeqAndMinimalTransition() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let (task, card, _) = try Self.transitions(a)
        let bs = try XCTUnwrap(a["big_seq"] as? [String: Any])
        let bigSeq = try XCTUnwrap(UInt64(try XCTUnwrap(bs["seq_str"] as? String)), "seq_str parses as UInt64")
        let trBig = Naming.Transition(task: task, card: card, from: try Self.u64(bs["from"]), to: try Self.u64(bs["to"]),
                                      seq: bigSeq, prev: Self.hexToBytes(try XCTUnwrap(bs["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try trBig.bytes()), bs["body_hex"] as? String, "big-seq transition body == oracle")
        XCTAssertEqual(Self.toHex(try trBig.head()), bs["head_hex"] as? String, "big-seq transition head == oracle")

        let mn = try XCTUnwrap(a["minimal"] as? [String: Any])
        let trMin = Naming.Transition(task: Self.hexToBytes(try XCTUnwrap(mn["task_hex"] as? String)),
                                      card: Self.hexToBytes(try XCTUnwrap(mn["card_hex"] as? String)),
                                      from: try Self.u64(mn["from"]), to: try Self.u64(mn["to"]),
                                      seq: try Self.u64(mn["seq"]), prev: Self.hexToBytes(try XCTUnwrap(mn["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try trMin.bytes()), mn["body_hex"] as? String, "minimal transition body == oracle")
        XCTAssertEqual(Self.toHex(try trMin.id()), mn["id_hex"] as? String, "minimal transition id == oracle")
    }

    // 16. DetectTaskGap: a deleted transition at seq 1 (present [0,2]) breaks contiguity at position 1.
    func testDetectTaskGap() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let (_, _, list) = try Self.transitions(a)
        let (gapPos, gap) = Naming.detectTaskGap([list[0], list[2]])
        XCTAssertTrue(gap, "task gap detected")
        XCTAssertEqual(UInt64(gapPos), try Self.u64((a["gap"] as? [String: Any])?["first_gap_position"]), "task gap position == oracle")
        XCTAssertFalse(Naming.detectTaskGap(list).1, "full transition chain has no gap")
    }

    // 17. the offline task-chain structural walk (start-state + contiguity + prev/seq linkage + card
    //     binding + legal-edge table, all at once) accepts the oracle's chain and returns it ordered.
    func testVerifyTaskChainStructure() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let (_, card, list) = try Self.transitions(a)
        let walked = try Naming.verifyTaskChainStructure(list, card)
        XCTAssertEqual(walked.count, list.count, "task-chain structural walk accepts the oracle chain")
    }

    // 18. task-chain fail-closed verdicts: a foreign card is ForeignCard; a gap is TaskChainBroken; the
    //     first transition must leave the start state; a from-terminal continuation is IllegalTransition.
    func testTaskChainFailClosed() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let (task, card, list) = try Self.transitions(a)
        let foreignCard = Self.hexToBytes(try XCTUnwrap(a["foreign_card_id_hex"] as? String))

        let foreignT0 = Naming.Transition(task: task, card: foreignCard, from: 0, to: 1, seq: 0, prev: Naming.genesis())
        XCTAssertThrowsError(try Naming.verifyTaskChainStructure([foreignT0], card), "foreign-card transition rejected (ForeignCard)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ForeignCard")
        }
        XCTAssertThrowsError(try Naming.verifyTaskChainStructure([list[0], list[2]], card), "gappy chain rejected (TaskChainBroken)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "TaskChainBroken")
        }
        let notStart = Naming.Transition(task: task, card: card, from: 1, to: 2, seq: 0, prev: Naming.genesis())
        XCTAssertThrowsError(try Naming.verifyTaskChainStructure([notStart], card), "chain not leaving the start state rejected (IllegalTransition)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "IllegalTransition")
        }
        let toTerminal = Naming.Transition(task: task, card: card, from: 0, to: 4, seq: 0, prev: Naming.genesis()) // 0->4 completed (legal)
        let fromTerminal = Naming.Transition(task: task, card: card, from: 4, to: 1, seq: 1, prev: try toTerminal.head()) // 4->1 (terminal cannot continue)
        XCTAssertThrowsError(try Naming.verifyTaskChainStructure([toTerminal, fromTerminal], card), "from-terminal continuation rejected (IllegalTransition)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "IllegalTransition")
        }
    }

    // 19. VerifyTaskChain over REAL Ed25519-signed transitions (isolation): a well-signed chain verifies;
    //     a tampered signature is BadSignature.
    func testSignedTaskChainEd25519() throws {
        let c = try Self.loadVector()
        let a = try XCTUnwrap(c["a2a"] as? [String: Any])
        let (_, card, list) = try Self.transitions(a)
        let key = try Self.nmKey("task-registrar")
        let signedT = try list.map { try Naming.signTransition($0, key.seed) }
        XCTAssertNoThrow(try Naming.verifyTaskChain(signedT, card, Self.nmVerify(key.pk)), "Ed25519-signed task chain verifies")
        var badT = signedT
        var x = badT[1]; x[x.count - 1] ^= 0x01; badT[1] = x
        XCTAssertThrowsError(try Naming.verifyTaskChain(badT, card, Self.nmVerify(key.pk)), "tampered signed transition rejected (BadSignature)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature")
        }
    }
}
