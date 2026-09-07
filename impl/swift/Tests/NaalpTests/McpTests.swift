// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NAALP-MCP binding-profile conformance for the Swift SDK (design.md §19; Companion-Spec Requirement
// 6.1), graded against the shared independent corpus vectors/mcp/cases.json (values from the corpus,
// NEVER produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): the annotation encoding, the published
// annotation->effect mapping table, the malformed-annotation rejections, the tool-call
// bodies/content-ids, the (tool_id,args_id) call binding, the more-severe effect resolution
// (accept / EffectUnderDeclared), the approval-binding call content-ids, and the edge cases
// (non-canonical rejection, empty-vs-absent annotations, minimal, look-alike).
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the per-call approval gate. AuthorizeCall
// REUSES the just-landed Swift Approval single-use consume ledger UNCHANGED for its §7 gate; Swift is
// PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204 path), so the
// approval signature is a real Ed25519 (RFC 8032) round-trip via the injected verifier: authorize
// once -> replay AlreadyConsumed -> a call with different arguments -> ApprovalRequired (held §7.3/§7.4,
// no ledger append). The signed-object VerifyToolCall path is the full faithful transcription; on the
// pure port a level-0 Ed25519 McpToolCall object is below the profile floor, so its reachable branch
// is ProfileDowngrade (its success path needs an ML-DSA level-3 signature the pure tier cannot
// produce) — stated honestly (F2/F4), mirroring the PHP/C# ports. The reference's ML-DSA
// cross-language signed pins are NOT reproducible here and are NOT fabricated.
//
// Written test-first: Naalp.Mcp is absent until Mcp.swift lands, so this fails RED with a compile
// error ("cannot find 'Mcp' in scope"). The load-bearing mutation flipping Mcp.DEFAULT_DESTRUCTIVE
// (true) makes the all-absent / destructive-default annotation sets map to non_idempotent_write(2)
// instead of destructive(3), flipping "annotation empty_all_absent mapped_effect == oracle".
//
// Run:  swift test --filter McpTests

import Foundation
import XCTest
@testable import Naalp

final class McpTests: XCTestCase {

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

    /// Cross-platform numeric read: corelibs-foundation deserializes JSON numbers as NSNumber.
    static func int(_ v: Any?) throws -> Int {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").intValue
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/mcp/cases.json")
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
            throw XCTSkip("vectors/mcp/cases.json not present (standalone build)")
        }
        return v
    }

    /// Build an Annotations from a corpus `hints` object {"1":1,"2":0,...} (uint keys 1..4 -> 0/1).
    static func annFromHints(_ hints: [String: Any]) -> Mcp.Annotations {
        var ro: Bool? = nil, de: Bool? = nil, idem: Bool? = nil, ow: Bool? = nil
        for (k, v) in hints {
            let val = ((v as? NSNumber)?.intValue ?? 0) == 1
            switch k {
            case "1": ro = val
            case "2": de = val
            case "3": idem = val
            case "4": ow = val
            default: break
            }
        }
        return Mcp.Annotations(readOnly: ro, destructive: de, idempotent: idem, openWorld: ow)
    }

    static func errKind(_ fn: () throws -> Void) -> String {
        do { try fn(); return "no-error" } catch let e as NaalpError { return e.kind } catch { return "\(type(of: error))" }
    }

    // 1. the annotation encoding + the published annotation->effect mapping table. THE MUTATION TARGET:
    //    flipping Mcp.DEFAULT_DESTRUCTIVE(true) maps the destructive-default sets to non_idempotent_write.
    func testAnnotationMappingMatchesOracle() throws {
        let c = try Self.loadVector()
        let anns = try XCTUnwrap(c["annotations"] as? [[String: Any]])
        XCTAssertFalse(anns.isEmpty, "corpus carried annotation cases")
        for a in anns {
            let name = try XCTUnwrap(a["name"] as? String)
            let ann = Self.annFromHints(try XCTUnwrap(a["hints"] as? [String: Any]))
            XCTAssertEqual(Self.toHex(try ann.encode()), a["annotations_hex"] as? String, "annotation \(name) encode == oracle")
            XCTAssertEqual(Mcp.mapAnnotationsToEffect(ann), try Self.int(a["mapped_effect"]), "annotation \(name) mapped_effect == oracle")
        }
    }

    // 2. every annotation set the oracle marks malformed is rejected, never defaulted to benign.
    func testMalformedAnnotationsRejected() throws {
        let c = try Self.loadVector()
        let mals = try XCTUnwrap(c["malformed_annotations"] as? [[String: Any]])
        XCTAssertFalse(mals.isEmpty, "corpus carried malformed-annotation cases")
        for m in mals {
            let name = try XCTUnwrap(m["name"] as? String)
            // The malformed set is structurally valid CBOR — the rejection is a profile rule, not a
            // codec rule (a decoder that accepted it would still be caught here).
            let decoded = try Cbor.decode(Self.hexToBytes(try XCTUnwrap(m["annotations_hex"] as? String)))
            XCTAssertEqual(Self.errKind { _ = try Mcp.annotationsFromValue(decoded) },
                           m["expect"] as? String, "malformed \(name) rejected")
        }
    }

    // 3. tool-call bodies, content ids, the annotation mapping, and the (tool_id,args_id) call binding.
    func testToolCallBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let calls = try XCTUnwrap(c["tool_calls"] as? [[String: Any]])
        XCTAssertFalse(calls.isEmpty, "corpus carried tool-call cases")
        for tv in calls {
            let name = try XCTUnwrap(tv["name"] as? String)
            let tool = Self.hexToBytes(try XCTUnwrap(tv["tool_hex"] as? String))
            let args = Self.hexToBytes(try XCTUnwrap(tv["args_hex"] as? String))
            let ann = Self.annFromHints(try XCTUnwrap(tv["hints"] as? [String: Any]))
            let tc = Mcp.ToolCall(tool, args, ann)

            XCTAssertEqual(Self.toHex(try ann.encode()), tv["annotations_hex"] as? String, "\(name) annotations == oracle")
            XCTAssertEqual(Self.toHex(try tc.bytes()), tv["body_hex"] as? String, "\(name) body == oracle")
            XCTAssertEqual(Self.toHex(try tc.contentId()), tv["content_id_hex"] as? String, "\(name) content id == oracle")
            XCTAssertEqual(Mcp.mapAnnotationsToEffect(ann), try Self.int(tv["annotation_mapped_effect"]), "\(name) mapped effect == oracle")

            let cb = tc.callBinding()
            XCTAssertEqual(Self.toHex(cb.toolID), tv["tool_id_hex"] as? String, "\(name) tool_id == oracle")
            XCTAssertEqual(Self.toHex(cb.argsID), tv["args_id_hex"] as? String, "\(name) args_id == oracle")
            XCTAssertEqual(Self.toHex(try cb.bytes()), tv["call_binding_hex"] as? String, "\(name) call binding == oracle")
            XCTAssertEqual(Self.toHex(try cb.contentId()), tv["call_content_id_hex"] as? String, "\(name) call content id == oracle")
        }
    }

    // 4. the more-severe effect resolution (the good-regulator attenuator): accept / EffectUnderDeclared.
    func testResolutionMatchesOracle() throws {
        let c = try Self.loadVector()
        let rows = try XCTUnwrap(c["resolution"] as? [[String: Any]])
        XCTAssertFalse(rows.isEmpty, "corpus carried resolution cases")
        for rv in rows {
            let name = try XCTUnwrap(rv["name"] as? String)
            let mapped = try Self.int(rv["annotation_mapped"])
            let declared = try Self.int(rv["declared"])
            let verdict = try XCTUnwrap(rv["verdict"] as? String)
            if verdict == "accept" {
                let (enforced, mismatch) = try Mcp.resolveEnforcedEffect(mapped, declared)
                XCTAssertEqual(enforced, try Self.int(rv["enforced"]), "\(name) enforced == oracle")
                XCTAssertEqual(mismatch, try XCTUnwrap(rv["mismatch"] as? Bool), "\(name) mismatch == oracle")
            } else {
                XCTAssertEqual(Self.errKind { _ = try Mcp.resolveEnforcedEffect(mapped, declared) },
                               verdict, "\(name) rejected \(verdict)")
            }
        }
    }

    // 5. the call binding content ids an approval binds (changed args / changed tool description) are
    //    each distinct, so a prior approval bound to one call cannot satisfy another.
    func testApprovalBindingContentIdsMatchOracle() throws {
        let c = try Self.loadVector()
        let binds = try XCTUnwrap(c["approval_binding"] as? [[String: Any]])
        XCTAssertGreaterThanOrEqual(binds.count, 3, "want >= 3 approval-binding cases")
        var ids = Set<String>()
        for av in binds {
            let name = try XCTUnwrap(av["name"] as? String)
            let tool = Self.hexToBytes(try XCTUnwrap(av["tool_hex"] as? String))
            let args = Self.hexToBytes(try XCTUnwrap(av["args_hex"] as? String))
            let cb = Mcp.newCallBinding(tool, args)
            XCTAssertEqual(Self.toHex(cb.toolID), av["tool_id_hex"] as? String, "\(name) tool_id == oracle")
            XCTAssertEqual(Self.toHex(cb.argsID), av["args_id_hex"] as? String, "\(name) args_id == oracle")
            XCTAssertEqual(Self.toHex(try cb.bytes()), av["call_binding_hex"] as? String, "\(name) binding == oracle")
            XCTAssertEqual(Self.toHex(try cb.contentId()), av["call_content_id_hex"] as? String, "\(name) call content id == oracle")
            ids.insert(try XCTUnwrap(av["call_content_id_hex"] as? String))
        }
        XCTAssertEqual(ids.count, binds.count, "each approval-binding call content id is distinct")
    }

    // 6. edge cases: non-canonical rejection, empty-vs-absent annotations, minimal, look-alike.
    func testEdgeCasesMatchOracle() throws {
        let c = try Self.loadVector()
        let ec = try XCTUnwrap(c["edge_cases"] as? [String: Any])

        // keys emitted descending -> the strict decoder rejects NonCanonical; the canonical form decodes.
        let koo = try XCTUnwrap(ec["keys_out_of_order"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Cbor.decode(Self.hexToBytes(try XCTUnwrap(koo["noncanonical_body_hex"] as? String))) },
                       "NonCanonical", "keys-out-of-order rejected NonCanonical")
        XCTAssertNoThrow(try Cbor.decode(Self.hexToBytes(try XCTUnwrap(koo["canonical_body_hex"] as? String))), "canonical body decodes")

        // an empty annotations map is PRESENT and valid (all MCP defaults -> destructive).
        let eva = try XCTUnwrap(ec["empty_vs_absent"] as? [String: Any])
        let empty = try XCTUnwrap(eva["empty_annotations"] as? [String: Any])
        let etc = try Mcp.toolCallFromBody(try Cbor.decode(Self.hexToBytes(try XCTUnwrap(empty["body_hex"] as? String))))
        XCTAssertEqual(Self.toHex(try etc.bytes()), empty["body_hex"] as? String, "empty-annotations body round-trips")
        XCTAssertEqual(Self.toHex(try etc.contentId()), empty["content_id_hex"] as? String, "empty-annotations content id == oracle")
        XCTAssertEqual(Mcp.mapAnnotationsToEffect(etc.annotations), try Self.int(empty["mapped_effect"]), "empty-annotations -> destructive")

        // a tool-call whose annotations field is ABSENT is rejected (distinct from empty).
        let absent = try XCTUnwrap(eva["absent_annotations"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Mcp.toolCallFromBody(try Cbor.decode(Self.hexToBytes(try XCTUnwrap(absent["body_hex"] as? String)))) },
                       absent["reject"] as? String, "absent annotations rejected")

        // the smallest valid tool-call: empty tool, empty args, empty annotations (-> destructive).
        let min = try XCTUnwrap(ec["minimal"] as? [String: Any])
        let mtc = Mcp.ToolCall(Self.hexToBytes(try XCTUnwrap(min["tool_hex"] as? String)),
                               Self.hexToBytes(try XCTUnwrap(min["args_hex"] as? String)), Mcp.Annotations())
        XCTAssertEqual(Self.toHex(try mtc.bytes()), min["body_hex"] as? String, "minimal body == oracle")
        XCTAssertEqual(Self.toHex(try mtc.contentId()), min["content_id_hex"] as? String, "minimal content id == oracle")
        XCTAssertEqual(Mcp.mapAnnotationsToEffect(mtc.annotations), try Self.int(min["mapped_effect"]), "minimal -> destructive")

        // a 2-field call-binding fed to the tool-call parser is rejected (a tool-call is 3 fields).
        let la = try XCTUnwrap(ec["look_alike"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Mcp.toolCallFromBody(try Cbor.decode(Self.hexToBytes(try XCTUnwrap(la["call_binding_body_hex"] as? String)))) },
                       la["reject"] as? String, "look-alike rejected")
    }

    // 7. a baseline-only endpoint rejects the tier-1 McpToolCall as UnknownKind (fail-closed).
    func testComposedKindValidator() {
        XCTAssertTrue(Mcp.composedKindValidator(Mcp.CHANNEL_BRIDGE, Mcp.KIND_MCP_TOOL_CALL), "composed accepts McpToolCall")
        XCTAssertTrue(Mcp.composedKindValidator(Mcp.CHANNEL_BRIDGE, 0), "composed still accepts baseline Carriage")
        XCTAssertFalse(Mcp.kindValidator(Mcp.CHANNEL_BRIDGE, 0), "tier-1-only validator rejects baseline Carriage")
        XCTAssertTrue(Mcp.kindValidator(Mcp.CHANNEL_BRIDGE, Mcp.KIND_MCP_TOOL_CALL), "tier-1 validator accepts McpToolCall")
    }

    /// Find an approval_binding case by name.
    static func binding(_ c: [String: Any], _ name: String) throws -> [String: Any] {
        let arr = try XCTUnwrap(c["approval_binding"] as? [[String: Any]])
        return try XCTUnwrap(arr.first { ($0["name"] as? String) == name }, "approval_binding \(name)")
    }

    // 8. ED25519-DEMONSTRATED (isolation): the per-call approval gate REUSES the §7 Approval consume
    //    ledger UNCHANGED. Authorize call A once (consumes single-use); replay is AlreadyConsumed; the
    //    SAME approval offered for call B (different args -> different call content id) does not bind
    //    (ApprovalRequired, no ledger append). Resolved is built directly (as the Delegation port does).
    func testApprovalGateInIsolation() throws {
        let c = try Self.loadVector()
        let baseAB = try Self.binding(c, "base_T_A")
        let changedAB = try Self.binding(c, "changed_args_T_B")
        let toolA = Self.hexToBytes(try XCTUnwrap(baseAB["tool_hex"] as? String))
        let argsA = Self.hexToBytes(try XCTUnwrap(baseAB["args_hex"] as? String))
        let argsB = Self.hexToBytes(try XCTUnwrap(changedAB["args_hex"] as? String))

        // the tool's annotations declare destructive (readOnly=false, destructive=true) -> destructive.
        let ann = Mcp.Annotations(readOnly: false, destructive: true)
        let tcA = Mcp.ToolCall(toolA, argsA, ann)
        let tcB = Mcp.ToolCall(toolA, argsB, ann)
        let rA = Mcp.Resolved(contentID: try tcA.contentId(), signer: Array("signer".utf8), toolCall: tcA,
                              annotationMapped: Policy.DESTRUCTIVE, declared: Policy.DESTRUCTIVE,
                              enforced: Policy.DESTRUCTIVE, mismatch: false)
        let rB = Mcp.Resolved(contentID: try tcB.contentId(), signer: Array("signer".utf8), toolCall: tcB,
                              annotationMapped: Policy.DESTRUCTIVE, declared: Policy.DESTRUCTIVE,
                              enforced: Policy.DESTRUCTIVE, mismatch: false)
        XCTAssertEqual(rA.enforced, Policy.DESTRUCTIVE, "more-severe resolution: enforced == destructive")

        // the human approval binds THE EXACT call A (its call-binding content id), grants destructive.
        let seed = [UInt8](repeating: 0x09, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let approverID = try Identity.signerId(Cose.ALG_ED25519, pk)
        let callCidA = try rA.toolCall.callBinding().contentId()
        let appr = Approval.ApprovalRecord(approves: callCidA, approver: approverID, grant: UInt64(Policy.DESTRUCTIVE),
                                           nonce: [1, 2, 3], notAfter: 1000)
        let apprSig = try Approval.signApproval(appr, seed)
        let verify: Approval.Verify = { m, s in Cose.ed25519Verify(pk, m, s) }

        let ledger = try Approval.Ledger.open(
            FileManager.default.temporaryDirectory.appendingPathComponent("naalp-mcp-\(UUID().uuidString).wal").path)
        defer { try? ledger.close() }

        // first authorization of call A succeeds and consumes the approval single-use.
        XCTAssertNoThrow(try Mcp.authorizeCall(rA, appr, verify, apprSig, "agent", 500, ledger), "call A authorized")
        // replaying the SAME call+approval is rejected AlreadyConsumed (no double-spend).
        XCTAssertThrowsError(try Mcp.authorizeCall(rA, appr, verify, apprSig, "agent", 500, ledger), "replay") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed", "spent approval is not fresh authority")
        }
        // the SAME approval offered for call B (different args -> different call content id) does not bind.
        XCTAssertThrowsError(try Mcp.authorizeCall(rB, appr, verify, apprSig, "agent", 500, ledger), "wrong call") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalRequired", "approval does not bind a different call")
        }
        XCTAssertEqual(ledger.len(), 1, "exactly one consume happened")
    }

    // 9. VerifyToolCall reachable branch on the pure port: a level-0 Ed25519 McpToolCall object passes
    //    every structural check (content id, ranges, header/body copies, composed kind dispatch) and is
    //    then floored (ProfileDowngrade) — the success path needs an ML-DSA level-3 signature the pure
    //    Swift tier cannot produce. This exercises the full VerifyToolCall wiring up to the floor.
    func testVerifyToolCallReachableBranch() throws {
        let c = try Self.loadVector()
        let baseAB = try Self.binding(c, "base_T_A")
        let toolA = Self.hexToBytes(try XCTUnwrap(baseAB["tool_hex"] as? String))
        let argsA = Self.hexToBytes(try XCTUnwrap(baseAB["args_hex"] as? String))
        let tc = Mcp.ToolCall(toolA, argsA, Mcp.Annotations(readOnly: false, destructive: true))

        let seed = [UInt8](repeating: 0x07, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let signerID = try Identity.signerId(Cose.ALG_ED25519, pk)
        var obj = try tc.envelopeObject(signer: Array(signerID.utf8), created: 100,
                                        profile: UInt64(Cose.PROFILE_PUBLIC), declared: Policy.DESTRUCTIVE, causes: [])
        let signed = try Envelope.signEd25519(&obj, seed)

        XCTAssertEqual(Self.errKind { _ = try Mcp.verifyToolCall(Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk, signed) },
                       "ProfileDowngrade", "verifyToolCall floors Ed25519 after full structural verification")

        // an out-of-lattice declared effect is rejected fail-closed at object assembly.
        XCTAssertThrowsError(try tc.envelopeObject(signer: Array(signerID.utf8), created: 100, profile: 1, declared: 4, causes: []), "declared 4") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "EffectOutsideLattice", "out-of-lattice declared effect rejected")
        }
    }
}
