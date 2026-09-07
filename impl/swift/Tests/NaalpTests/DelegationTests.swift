// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C15 multi-hop agent-delegation higher-tier conformance for the Swift SDK (design.md §18; R-DEL-1..8),
// graded against the shared independent corpus vectors/delegation/cases.json (values from the corpus,
// NEVER produced by this code).
//
// CORPUS-GRADED (pure, signature-independent):
//   - the DelegationGrant wire body + content id for every named grant (Grant.bytes / Grant.contentId);
//   - the D2 scope-containment truth table (scopeContained), both allows and denies;
//   - the D3 12-step leaf->root chain verdict for every scenario (verifyChain reproduces the oracle's
//     independently-computed verdict — authorized and every named deny), built from Resolved grants
//     directly (the envelope-integration layer, D3 step 3 = VerifyGrantObject, is not graded by this
//     corpus — see honest F2/F4 below);
//   - the D4 two-gate composition (AuthorizeDestructive) over the real §7 approval consume ledger built
//     in THIS wave: both gates authorize and consume once; a chain without a valid approval denies
//     ApprovalRequired with no ledger append; a valid approval with a broken chain denies with the D3
//     error (chain checked first); a replayed approval denies AlreadyConsumed.
//
// ED25519-DEMONSTRATED / PURE (isolation): the DelegationGrant object surface — envelopeObject builds the
// tier-1 Capability object (NonNFC subject/scope and out-of-lattice effect_cap rejected fail-closed);
// grantFromBody round-trips a body back to a Grant and rejects a malformed link (ChainBroken); the D4
// approval signature is a real Ed25519 (RFC 8032) sign/verify (the approver's key stands in for the
// reference's ML-DSA approver).
//
// HONEST F2/F4: the envelope-integration D3 step 3 (VerifyGrantObject via envelope.Verify) is NOT graded
// here — a level-0 Ed25519 grant object is floored (ProfileDowngrade) under every profile, so the pure
// tier cannot demonstrate a passing envelope-verified grant chain; the scenarios build Resolved grants
// directly (as the Go and C# reference test harnesses do). The reference's ML-DSA cross-language signed
// pins are NOT reproducible here and are NOT fabricated.
//
// VerifyGrantObject / KindValidator / ComposedKindValidator (this wave): the pre-crypto structural
// dispatch (a wrong channel/kind is rejected UnknownKind before the crypto layer) and the honest
// ProfileDowngrade floor on a genuine Ed25519-signed grant object ARE graded; the crypto success path
// remains unreachable in the pure tier for the reason above. KindValidator/ComposedKindValidator are
// graded directly (the shared corpus carries no kind-dispatch vectors for this surface).
//
// Written test-first: Naalp.Delegation is absent until Delegation.swift lands, so this fails RED with
// "cannot find 'Delegation' in scope". The load-bearing mutation weakening scopeContained's path-prefix
// rule (parent+"/" -> parent) flips ScopeContained("billingreports", "billing").
//
// Run:  swift test --filter DelegationTests

import Foundation
import XCTest
@testable import Naalp

final class DelegationTests: XCTestCase {

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

    static func intArray(_ v: Any?) -> [Int] {
        return (v as? [Any] ?? []).compactMap { ($0 as? NSNumber)?.intValue }
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/delegation/cases.json")
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
            throw XCTSkip("vectors/delegation/cases.json not present (standalone build)")
        }
        return v
    }

    /// A deterministic, unique-per-index synthetic ENVELOPE content id for a scenario grant. VerifyChain
    /// keys the GrantSet on this and resolves `causes` against it; the only property it needs is
    /// uniqueness per index, so the "grant#i:" prefix guarantees it even if two bodies coincide.
    static func synthCID(_ i: Int, _ g: Delegation.Grant) throws -> [UInt8] {
        return Cbor.contentId(Array("grant#\(i):".utf8) + (try g.bytes()))
    }

    // 1. every DelegationGrant body and its content id are byte-identical to the independent oracle.
    func testGrantBytesMatchOracle() throws {
        let c = try Self.loadVector()
        let grants = try XCTUnwrap(c["grants"] as? [[String: Any]])
        XCTAssertFalse(grants.isEmpty, "corpus has grant byte vectors")
        for gj in grants {
            let name = try XCTUnwrap(gj["name"] as? String)
            let g = Delegation.Grant(
                subject: try XCTUnwrap(gj["subject"] as? String),
                effectCap: try Self.u64(gj["effect_cap"]),
                maxDepth: try Self.u64(gj["max_depth"]),
                notBefore: try Self.u64(gj["not_before"]),
                notAfter: try Self.u64(gj["not_after"]),
                scope: gj["scope"] as? String ?? "")
            XCTAssertEqual(Self.toHex(try g.bytes()), gj["body_hex"] as? String, "grant \(name) body == oracle")
            XCTAssertEqual(Self.toHex(try g.contentId()), gj["content_id_hex"] as? String, "grant \(name) content-id == oracle")
        }
    }

    // 2. the D2 path-prefix containment truth table (both allows and denies) — the load-bearing mutation
    //    target: weakening parent+"/" to parent flips ScopeContained("billingreports", "billing").
    func testScopeContainment() throws {
        let c = try Self.loadVector()
        let rows = try XCTUnwrap(c["scope_containment"] as? [[String: Any]])
        XCTAssertFalse(rows.isEmpty, "corpus has scope-containment rows")
        for r in rows {
            let child = r["child"] as? String ?? ""
            let parent = r["parent"] as? String ?? ""
            let want = try XCTUnwrap(r["contained"] as? Bool)
            XCTAssertEqual(Delegation.scopeContained(child, parent), want, "ScopeContained(\(child), \(parent))")
        }
    }

    // 3. THE D3 chain-verdict grading: every oracle scenario, driven through verifyChain over Resolved
    //    grants built directly, yields the oracle's independently-computed verdict (authorized and every
    //    named deny — so a constant-authorize fails the denies and a constant-deny fails the allows).
    func testChainScenariosMatchOracle() throws {
        let c = try Self.loadVector()
        let scenarios = try XCTUnwrap(c["scenarios"] as? [[String: Any]])
        XCTAssertFalse(scenarios.isEmpty, "corpus has scenarios")
        for sc in scenarios {
            let name = sc["name"] as? String ?? "?"
            let scGrants = try XCTUnwrap(sc["grants"] as? [[String: Any]])

            // build the grant objects + their synthetic content ids (index-stable).
            var grantObjs: [Delegation.Grant] = []
            var issuers: [String] = []
            var causeIdx: [[Int]] = []
            for gj in scGrants {
                grantObjs.append(Delegation.Grant(
                    subject: try XCTUnwrap(gj["subject"] as? String),
                    effectCap: try Self.u64(gj["effect_cap"]),
                    maxDepth: try Self.u64(gj["max_depth"]),
                    notBefore: try Self.u64(gj["not_before"]),
                    notAfter: try Self.u64(gj["not_after"]),
                    scope: gj["scope"] as? String ?? ""))
                issuers.append(try XCTUnwrap(gj["issuer"] as? String))
                causeIdx.append(Self.intArray(gj["causes"]))
            }
            var grantCID: [[UInt8]] = []
            for (i, g) in grantObjs.enumerated() { grantCID.append(try Self.synthCID(i, g)) }

            var set: Delegation.GrantSet = [:]
            for i in grantObjs.indices {
                let causes = causeIdx[i].map { grantCID[$0] }
                set[grantCID[i]] = Delegation.Resolved(contentID: grantCID[i], issuer: issuers[i], grant: grantObjs[i], causes: causes)
            }

            let actionD = try XCTUnwrap(sc["action"] as? [String: Any])
            let action = Delegation.Action(
                signer: try XCTUnwrap(actionD["signer"] as? String),
                effect: try Self.u64(actionD["effect"]),
                scope: actionD["scope"] as? String ?? "",
                causes: Self.intArray(actionD["causes"]).map { grantCID[$0] })

            let anchors = Set((sc["anchors"] as? [String]) ?? [])
            var revoked = Delegation.Revocations()
            for r in (sc["revoked"] as? [[String: Any]]) ?? [] {
                revoked.revoke(grantCID[try XCTUnwrap((r["grant"] as? NSNumber)?.intValue)], at: try Self.u64(r["pos"]))
            }
            let now = try Self.u64(sc["now"])
            let expect = try XCTUnwrap(sc["expect"] as? String)

            do {
                try Delegation.verifyChain(action, set, anchors, revoked, now)
                XCTAssertEqual("authorized", expect, "scenario \(name): verdict")
            } catch let e as NaalpError {
                XCTAssertEqual(e.kind, expect, "scenario \(name): verdict")
            }
        }
    }

    // ---- D4 composition over the real §7 approval consume ledger built in THIS wave -----------------

    struct DSetup {
        let action: Delegation.Action
        let set: Delegation.GrantSet
        let anchors: Set<String>
        let ledger: Approval.Ledger
        let appr: Approval.ApprovalRecord
        let verify: Approval.Verify
        let apprSig: [UInt8]
        let argsCID: [UInt8]
    }

    /// A valid destructive A->M->B chain (leaf effect_cap admits destructive), a fresh consume ledger, and
    /// a valid Ed25519-signed approval over the action's args, granted-effect destructive.
    func makeDestructive() throws -> DSetup {
        let root = Delegation.Grant(subject: "M", effectCap: 3, maxDepth: 2, notBefore: 0, notAfter: 1_000_000, scope: "")
        let leaf = Delegation.Grant(subject: "B", effectCap: 3, maxDepth: 1, notBefore: 0, notAfter: 1_000_000, scope: "")
        let rootCID = try Self.synthCID(0, root)
        let leafCID = try Self.synthCID(1, leaf)
        var set: Delegation.GrantSet = [:]
        set[rootCID] = Delegation.Resolved(contentID: rootCID, issuer: "A", grant: root, causes: [])
        set[leafCID] = Delegation.Resolved(contentID: leafCID, issuer: "M", grant: leaf, causes: [rootCID])
        let action = Delegation.Action(signer: "B", effect: 3, scope: "", causes: [leafCID])

        let ledger = try Approval.Ledger.open(
            FileManager.default.temporaryDirectory.appendingPathComponent("naalp-del-\(UUID().uuidString).wal").path)

        let seed = [UInt8](repeating: 0x50, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let approverID = try Identity.signerId(Cose.ALG_ED25519, pk)
        let argsCID = Cbor.contentId(Array("the exact canonical action args".utf8))
        let appr = Approval.ApprovalRecord(approves: argsCID, approver: approverID, grant: 3, nonce: [1, 2, 3, 4], notAfter: 1_000_000)
        let sig = try Approval.signApproval(appr, seed)
        let verify: Approval.Verify = { m, s in Cose.ed25519Verify(pk, m, s) }
        return DSetup(action: action, set: set, anchors: ["A"], ledger: ledger, appr: appr, verify: verify, apprSig: sig, argsCID: argsCID)
    }

    // 4. both gates valid -> authorized and consumed exactly once, keyed by B.
    func testCompositionBothGatesAuthorizeAndConsume() throws {
        let s = try makeDestructive()
        defer { try? s.ledger.close() }
        XCTAssertNoThrow(try Delegation.authorizeDestructive(s.action, s.set, s.anchors, Delegation.Revocations(), 500,
                                                             s.appr, s.verify, s.apprSig, s.argsCID, s.ledger),
                         "both gates valid -> authorized")
        XCTAssertTrue(s.ledger.isConsumed(try s.appr.id()), "approval consumed after authorization")
    }

    // 5. a valid chain but no matching approval denies ApprovalRequired with NO ledger append (fail-closed).
    func testCompositionChainWithoutApproval() throws {
        let s = try makeDestructive()
        defer { try? s.ledger.close() }
        let otherArgs = Cbor.contentId(Array("some other args the approval does not bind".utf8))
        XCTAssertThrowsError(try Delegation.authorizeDestructive(s.action, s.set, s.anchors, Delegation.Revocations(), 500,
                                                                 s.appr, s.verify, s.apprSig, otherArgs, s.ledger),
                             "no matching approval") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalRequired", "no valid approval -> ApprovalRequired")
        }
        XCTAssertEqual(s.ledger.len(), 0, "no ledger append on a rejected action")
    }

    // 6. a valid approval but a broken chain (untrusted root) denies with the D3 error (chain checked
    //    first), consuming nothing.
    func testCompositionApprovalWithBrokenChain() throws {
        let s = try makeDestructive()
        defer { try? s.ledger.close() }
        XCTAssertThrowsError(try Delegation.authorizeDestructive(s.action, s.set, [], Delegation.Revocations(), 500,
                                                                 s.appr, s.verify, s.apprSig, s.argsCID, s.ledger),
                             "broken chain") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UntrustedChainRoot", "broken chain wins (chain checked first)")
        }
        XCTAssertEqual(s.ledger.len(), 0, "no ledger append when the chain gate fails")
    }

    // 7. an approval is single-use — a second destructive action consuming the same approval is denied
    //    AlreadyConsumed.
    func testCompositionApprovalReplayRejected() throws {
        let s = try makeDestructive()
        defer { try? s.ledger.close() }
        XCTAssertNoThrow(try Delegation.authorizeDestructive(s.action, s.set, s.anchors, Delegation.Revocations(), 500,
                                                             s.appr, s.verify, s.apprSig, s.argsCID, s.ledger),
                         "first authorization")
        XCTAssertThrowsError(try Delegation.authorizeDestructive(s.action, s.set, s.anchors, Delegation.Revocations(), 500,
                                                                 s.appr, s.verify, s.apprSig, s.argsCID, s.ledger),
                             "replay") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed", "spent approval is not fresh authority")
        }
    }

    // ---- pure grant-object surface demonstrations (isolation) ---------------------------------------

    // 8. envelopeObject builds the tier-1 Capability DelegationGrant object with the right routing fields;
    //    a non-NFC subject and an out-of-lattice effect_cap are rejected fail-closed.
    func testEnvelopeObjectBuildAndRejections() throws {
        let g = Delegation.Grant(subject: "agent:b", effectCap: 2, maxDepth: 1, notBefore: 0, notAfter: 1, scope: "billing")
        let obj = try Delegation.envelopeObject(g, issuer: Array("agent:a".utf8), created: 1,
                                                profile: UInt64(Cose.PROFILE_PUBLIC), causes: [])
        XCTAssertEqual(obj.kind, Delegation.KIND_DELEGATION_GRANT, "kind == DelegationGrant")
        XCTAssertEqual(obj.channel, Delegation.CHANNEL_CAPABILITY, "channel == Capability")
        XCTAssertEqual(obj.tier, Delegation.TIER, "tier == 1")
        XCTAssertEqual(obj.effect, UInt64(Delegation.GRANT_EFFECT), "grant's own effect == non_idempotent_write")

        let nonNFC = Delegation.Grant(subject: "e\u{0301}", effectCap: 0, maxDepth: 0, notBefore: 0, notAfter: 1, scope: "")
        XCTAssertThrowsError(try Delegation.envelopeObject(nonNFC, issuer: Array("agent:a".utf8), created: 1, profile: 1, causes: []), "non-NFC subject") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NonNFC", "non-NFC subject rejected")
        }
        let badCap = Delegation.Grant(subject: "agent:b", effectCap: 4, maxDepth: 0, notBefore: 0, notAfter: 1, scope: "")
        XCTAssertThrowsError(try Delegation.envelopeObject(badCap, issuer: Array("agent:a".utf8), created: 1, profile: 1, causes: []), "effect_cap 4") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "GrantMalformed", "out-of-lattice effect_cap rejected")
        }
    }

    // 9. grantFromBody round-trips a grant body back to a Grant, and rejects a malformed link (an
    //    out-of-lattice effect_cap in the body) ChainBroken (fail-closed, never normalized up).
    func testGrantFromBodyRoundTripAndReject() throws {
        let g = Delegation.Grant(subject: "délégué", effectCap: 1, maxDepth: 3, notBefore: 42, notAfter: 43, scope: "café/notes")
        let decoded = try Cbor.decode(try g.bytes())
        let g2 = try Delegation.grantFromBody(decoded)
        XCTAssertEqual(g2.subject, g.subject, "subject round-trips")
        XCTAssertEqual(g2.effectCap, g.effectCap, "effect_cap round-trips")
        XCTAssertEqual(g2.scope, g.scope, "scope round-trips")
        XCTAssertEqual(Self.toHex(try g2.bytes()), Self.toHex(try g.bytes()), "re-encoded body is byte-identical")

        // a body whose effect_cap is out of the closed lattice is an unverifiable link.
        let bad = CborValue.m([
            (.u(1), .t("agent:x")), (.u(2), .u(4)), (.u(3), .u(0)), (.u(4), .u(0)), (.u(5), .u(1)),
        ])
        XCTAssertThrowsError(try Delegation.grantFromBody(bad), "out-of-lattice effect_cap body") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ChainBroken", "malformed grant link rejected ChainBroken")
        }
    }

    // ---- kind validation: KindValidator / ComposedKindValidator (this wave) -------------------------
    // MUTATION TARGET: neutering composedKindValidator to always return true (fail-open) flips
    // "neither baseline nor delegation" below to true.

    func testKindValidatorAndComposedKindValidator() throws {
        // KindValidator accepts exactly the tier-1 (Capability, DelegationGrant) pair.
        XCTAssertTrue(Delegation.kindValidator(Delegation.CHANNEL_CAPABILITY, Delegation.KIND_DELEGATION_GRANT),
                      "tier-1 (Capability, DelegationGrant) accepted")
        XCTAssertFalse(Delegation.kindValidator(Delegation.CHANNEL_CAPABILITY, 0), "CapIssue is not the delegation kind")
        XCTAssertFalse(Delegation.kindValidator(0x0000, 0), "wrong channel entirely")

        // the frozen baseline alone (Channels.lookup) does not know DelegationGrant -- a baseline-only
        // endpoint correctly rejects it as UnknownKind, exactly as the tier model requires.
        XCTAssertThrowsError(try Channels.lookup(Int(Delegation.CHANNEL_CAPABILITY), Int(Delegation.KIND_DELEGATION_GRANT))) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownKind", "baseline registry does not know the tier-1 kind")
        }

        // ComposedKindValidator accepts the frozen baseline (registry untouched) OR the tier-1 grant.
        XCTAssertTrue(Delegation.composedKindValidator(Delegation.CHANNEL_CAPABILITY, Delegation.KIND_DELEGATION_GRANT),
                      "tier-1 kind accepted")
        XCTAssertTrue(Delegation.composedKindValidator(Delegation.CHANNEL_CAPABILITY, 0), "baseline CapIssue still accepted")
        XCTAssertTrue(Delegation.composedKindValidator(0x0000, 0), "baseline Control/Hello accepted")
        XCTAssertFalse(Delegation.composedKindValidator(0x0000, 99), "neither baseline nor delegation")
    }

    // ---- VerifyGrantObject: D3 step 3, the envelope-integration layer (this wave) -------------------
    // See the file header: the crypto SUCCESS path is not reachable in the pure Ed25519/ML-DSA-skip-
    // tracked tier (honest F2/F4); the pre-crypto structural dispatch below IS exercised and graded.

    func testVerifyGrantObjectStructuralChecksAndProfileFloor() throws {
        let g = Delegation.Grant(subject: "agent:b", effectCap: 2, maxDepth: 1, notBefore: 0, notAfter: 1_000_000, scope: "")
        let seed = [UInt8](repeating: 0x61, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let issuer = try Identity.signerId(Cose.ALG_ED25519, pk)

        // a genuine, correctly-channeled/kinded, real-Ed25519-signed grant object is always FLOORED
        // (ProfileDowngrade) -- honest F2/F4, matching the file header's documented limitation.
        var obj = try Delegation.envelopeObject(g, issuer: Array(issuer.utf8), created: 1,
                                                profile: UInt64(Cose.PROFILE_PUBLIC), causes: [])
        let signed = try Envelope.signEd25519(&obj, seed)
        XCTAssertThrowsError(try Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk, signed)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ProfileDowngrade", "pure Ed25519 floored under every profile")
        }

        // a wrong channel/kind object is rejected UnknownKind BEFORE the crypto layer -- the
        // pre-crypto structural dispatch (composedKindValidator) that IS exercised in the pure tier.
        var wrong = Envelope.Object(kind: 99, channel: 0x0000, signer: Array(issuer.utf8), created: 1,
                                    effect: UInt64(Delegation.GRANT_EFFECT), body: g.toMap(),
                                    tier: Delegation.TIER, profile: UInt64(Cose.PROFILE_PUBLIC), causes: [])
        let wrongSigned = try Envelope.signEd25519(&wrong, seed)
        XCTAssertThrowsError(try Delegation.verifyGrantObject(Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk, wrongSigned)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownKind", "wrong channel/kind rejected before the crypto layer")
        }
    }
}
