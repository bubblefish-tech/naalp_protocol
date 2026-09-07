// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C20 governed negotiation, advisory risk labels, and trust references for the Swift SDK (design.md §23;
// R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4), graded against the shared independent corpus
// vectors/negotiation/cases.json (values from the corpus, NEVER produced by this code). C20 adds three
// signed surfaces carried on N-AALP's own signed object; it introduces NO new envelope, encoding,
// signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body reusing
// the closed C5 effect lattice (Policy), the T1 content-id framing (§2.3), and the §8.2 causal partial
// order (`causes`) UNCHANGED.
//
// CORPUS-GRADED (pure, signature-independent): (1) every negotiation Message, RiskLabel, LabeledObject,
// and TrustRef body/head/id byte-for-byte to the oracle (⟹ Go == Rust == Python == Swift); (2) the C20
// descent DAG (an accept descends from its offer through a counter; a non-descended accept is rejected)
// and the agreed pre-registered profile; (3) the effect-class-unchanged invariant (carrying a risk label
// NEVER changes an object's effect class); (4) the R-2.5 critical-extension rule (unknown critical
// rejected, unknown non-critical ignored); (5) the trust-ref content-id recompute (checkable, never
// weighed) — two registries referencing the same record verify symmetrically; and (6) the wire edges:
// NonCanonical (keys-out-of-order) rejection, empty-vs-absent causes/labels distinctness, the minimal
// bodies, and the look-alike cross-kind NegMalformed rejections.
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): signMessage/verifyMessage,
// signLabeledObject/verifyLabeledObject, and signTrustRef/verifyTrustRef over real Ed25519 (RFC 8032)
// signed objects verified through an INJECTED verify closure (the pure-tier stand-in for the reference's
// ML-DSA verifier). Swift is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0). SIGNED-PIN NOTE (honest F2/F4):
// C20's THREE cross-language SIGNED pins (a signed offer, a signed read_only-with-labels labeled object,
// and a signed trust-ref A, each under the shared all-0x11 ML-DSA-65 seed) are real deterministic ML-DSA
// (FIPS 204) COSE_Sign1 objects; they are NOT reproducible in the pure tier and are NOT faked here — the
// surfaces this port grades are the byte bodies/heads/ids and the descent/label/trust verdicts, all
// signature-independent, and the signature BINDING is demonstrated in isolation with Ed25519.
//
// Written test-first: Naalp.Negotiation is absent until Negotiation.swift lands, so this fails RED with a
// compile error ("cannot find 'Negotiation' in scope"). The load-bearing mutation: making
// LabeledObject.effectClass consult a gating label to escalate the effect flips
// "read_only + sensitive resolves to read_only" in testRiskLabelEffectClassUnchanged.
//
// Run:  swift test --filter NegotiationTests

import XCTest
@testable import Naalp

final class NegotiationTests: XCTestCase {

    // ---- shared helpers ---------------------------------------------------------------------------

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
            let p = dir.appendingPathComponent("vectors/negotiation/cases.json")
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
            throw XCTSkip("vectors/negotiation/cases.json not present (standalone build)")
        }
        return v
    }

    /// A deterministic Ed25519 keypair for a label (the pure-tier stand-in for the reference's ML-DSA
    /// signer): seed = the first 32 octets of the SHA-384 content-id of a label string.
    static func negKey(_ label: String) throws -> (seed: [UInt8], pk: [UInt8]) {
        let seed = Array(Cbor.contentId(Array("naalp-negotiation-key:\(label)".utf8)).dropFirst(2).prefix(32))
        return (seed, try Cose.ed25519PublicKey(seed))
    }

    static func negVerify(_ pk: [UInt8]) -> Negotiation.Verify {
        return { m, s in Cose.ed25519Verify(pk, m, s) }
    }

    static func msgFrom(_ neg: [UInt8], _ d: [String: Any]) throws -> Negotiation.Message {
        let causesHex = (d["causes_hex"] as? [String]) ?? []
        return Negotiation.Message(negotiation: neg, role: try u64(d["role"]), profile: try u64(d["profile"]),
                                   causes: causesHex.map { hexToBytes($0) })
    }

    static func carriedLabels(_ risk: [String: Any]) throws -> [Negotiation.RiskLabel] {
        return try XCTUnwrap(risk["carried_on_labeled_objects"] as? [[String: Any]]).map { c in
            Negotiation.RiskLabel(code: try u64(c["code"]), critical: try u64(c["critical"]))
        }
    }

    static func labelsFrom(_ arr: [[String: Any]]) throws -> [Negotiation.RiskLabel] {
        return try arr.map { c in Negotiation.RiskLabel(code: try u64(c["code"]), critical: try u64(c["critical"])) }
    }

    // ===== Task 5.1 — governed negotiation: byte parity =====

    // 1. every negotiation Message body, chain head, and content id is byte-identical to the oracle.
    func testMessageBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let n = try XCTUnwrap(c["negotiation"] as? [String: Any])
        let neg = Self.hexToBytes(try XCTUnwrap(n["negotiation_hex"] as? String))
        for name in ["offer", "counter", "accept", "offer2", "accept_not_descended",
                     "unknown_profile_offer", "unknown_role_message"] {
            let d = try XCTUnwrap(n[name] as? [String: Any], "corpus has message \(name)")
            let m = try Self.msgFrom(neg, d)
            XCTAssertEqual(Self.toHex(try m.bytes()), d["body_hex"] as? String, "\(name) body == oracle")
            XCTAssertEqual(Self.toHex(try m.head()), d["head_hex"] as? String, "\(name) head == oracle")
            XCTAssertEqual(Self.toHex(try m.id()), d["id_hex"] as? String, "\(name) id == oracle")
        }
    }

    // 2. every LabeledObject (with and without labels) body/head/id is byte-identical to the oracle.
    func testLabeledObjectBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let risk = try XCTUnwrap(c["risk"] as? [String: Any])
        let labels = try Self.carriedLabels(risk)
        let los = try XCTUnwrap(risk["labeled_objects"] as? [[String: Any]])
        XCTAssertEqual(los.count, 4, "corpus has 4 labeled objects")
        for lo in los {
            let effect = try Self.u64(lo["effect"])
            let with = Negotiation.LabeledObject(effect: effect, labels: labels)
            let wl = try XCTUnwrap(lo["with_labels"] as? [String: Any])
            XCTAssertEqual(Self.toHex(try with.bytes()), wl["body_hex"] as? String, "with-labels body == oracle")
            XCTAssertEqual(Self.toHex(try with.head()), wl["head_hex"] as? String, "with-labels head == oracle")
            XCTAssertEqual(Self.toHex(try with.id()), wl["id_hex"] as? String, "with-labels id == oracle")
            let without = Negotiation.LabeledObject(effect: effect, labels: [])
            let wo = try XCTUnwrap(lo["without_labels"] as? [String: Any])
            XCTAssertEqual(Self.toHex(try without.bytes()), wo["body_hex"] as? String, "without-labels body == oracle")
            XCTAssertEqual(Self.toHex(try without.id()), wo["id_hex"] as? String, "without-labels id == oracle")
        }
    }

    // 3. both TrustRef bodies/heads/ids are byte-identical to the oracle.
    func testTrustRefBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let t = try XCTUnwrap(c["trust"] as? [String: Any])
        let reference = Self.hexToBytes(try XCTUnwrap(t["reference_hex"] as? String))
        let subject = Self.hexToBytes(try XCTUnwrap(t["subject_hex"] as? String))
        let refA = Negotiation.TrustRef(registry: Self.hexToBytes(try XCTUnwrap(t["registry_a_hex"] as? String)),
                                        reference: reference, subject: subject)
        let ra = try XCTUnwrap(t["ref_a"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try refA.bytes()), ra["body_hex"] as? String, "trust-ref A body == oracle")
        XCTAssertEqual(Self.toHex(try refA.head()), ra["head_hex"] as? String, "trust-ref A head == oracle")
        XCTAssertEqual(Self.toHex(try refA.id()), ra["id_hex"] as? String, "trust-ref A id == oracle")
        let refB = Negotiation.TrustRef(registry: Self.hexToBytes(try XCTUnwrap(t["registry_b_hex"] as? String)),
                                        reference: reference, subject: subject)
        let rb = try XCTUnwrap(t["ref_b"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try refB.bytes()), rb["body_hex"] as? String, "trust-ref B body == oracle")
    }

    // 4. the governed-negotiation checkpoint over REAL Ed25519-signed messages (isolation): an accept
    //    descends from its offer along the causes chain (via a counter) and yields the agreed pre-registered
    //    profile; a non-descended accept is NotDescended; an unknown profile/role is rejected at verify; a
    //    non-offer/non-accept is NotOffer/NotAccept; a foreign key never authenticates.
    func testNegotiationDescendFromOffer() throws {
        let c = try Self.loadVector()
        let n = try XCTUnwrap(c["negotiation"] as? [String: Any])
        let neg = Self.hexToBytes(try XCTUnwrap(n["negotiation_hex"] as? String))
        let key = try Self.negKey("registrar")
        let foreign = try Self.negKey("attacker")

        let offer = try Self.msgFrom(neg, try XCTUnwrap(n["offer"] as? [String: Any]))
        let counter = try Self.msgFrom(neg, try XCTUnwrap(n["counter"] as? [String: Any]))
        let accept = try Self.msgFrom(neg, try XCTUnwrap(n["accept"] as? [String: Any]))
        let offer2 = try Self.msgFrom(neg, try XCTUnwrap(n["offer2"] as? [String: Any]))
        let acceptBad = try Self.msgFrom(neg, try XCTUnwrap(n["accept_not_descended"] as? [String: Any]))

        // The causes wiring reproduces the oracle: counter->offer, accept->counter, acceptBad->offer2.
        XCTAssertEqual(counter.causes[0], try offer.id(), "counter chains onto the offer")
        XCTAssertEqual(accept.causes[0], try counter.id(), "accept chains onto the counter")
        XCTAssertEqual(acceptBad.causes[0], try offer2.id(), "acceptBad chains onto offer2")

        // Sign+verify every message under the real key (Ed25519 isolation); a foreign key is BadSignature.
        var verified: [Negotiation.Message] = []
        for m in [offer, counter, accept, offer2, acceptBad] {
            let obj = try Negotiation.signMessage(m, key.seed)
            let vm = try Negotiation.verifyMessage(obj, Self.negVerify(key.pk))
            XCTAssertEqual(try vm.id(), try m.id(), "verified message id == original")
            XCTAssertThrowsError(try Negotiation.verifyMessage(obj, Self.negVerify(foreign.pk)),
                                 "foreign-key verify rejected (BadSignature)") {
                XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature")
            }
            verified.append(vm)
        }
        let byID = try Negotiation.indexByID(verified)

        // The honest accept descends from the offer; the bad accept does not.
        XCTAssertEqual(try Negotiation.descends(accept, offer, byID),
                       try Self.boolField(n, "descends", "accept_from_offer"), "accept descends from offer")
        XCTAssertEqual(try Negotiation.descends(acceptBad, offer, byID),
                       try Self.boolField(n, "descends", "accept_bad_from_offer"), "acceptBad does not descend")

        let agreed = try Negotiation.verifyAccept(accept, offer, byID)
        XCTAssertEqual(agreed, try Self.u64(n["agreed_profile"]), "agreed profile == oracle")

        XCTAssertThrowsError(try Negotiation.verifyAccept(acceptBad, offer, byID),
                             "non-descended accept rejected (NotDescended)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NotDescended")
        }
        XCTAssertThrowsError(try Negotiation.verifyAccept(accept, counter, byID),
                             "non-offer as offer rejected (NotOffer)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NotOffer")
        }
        XCTAssertThrowsError(try Negotiation.verifyAccept(counter, offer, byID),
                             "non-accept as accept rejected (NotAccept)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NotAccept")
        }

        // An unknown profile and an unknown role are rejected at verify time.
        let unkProf = try Negotiation.signMessage(try Self.msgFrom(neg, try XCTUnwrap(n["unknown_profile_offer"] as? [String: Any])), key.seed)
        XCTAssertThrowsError(try Negotiation.verifyMessage(unkProf, Self.negVerify(key.pk)),
                             "unknown profile rejected (UnknownProfile)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownProfile")
        }
        let unkRole = try Negotiation.signMessage(try Self.msgFrom(neg, try XCTUnwrap(n["unknown_role_message"] as? [String: Any])), key.seed)
        XCTAssertThrowsError(try Negotiation.verifyMessage(unkRole, Self.negVerify(key.pk)),
                             "unknown role rejected (UnknownRole)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownRole")
        }

        // No free-form/runtime capability is negotiable: only the closed set is accepted.
        XCTAssertFalse(Negotiation.isRegisteredProfile(try Self.u64(n["unknown_profile"])), "unregistered profile rejected")
        for p in [Negotiation.PROFILE_BASELINE, Negotiation.PROFILE_STREAMING, Negotiation.PROFILE_BATCH] {
            XCTAssertTrue(Negotiation.isRegisteredProfile(p), "pre-registered profile \(p) recognized")
        }
    }

    static func boolField(_ d: [String: Any], _ a: String, _ b: String) throws -> Bool {
        return try XCTUnwrap((d[a] as? [String: Any])?[b] as? Bool)
    }

    // 5. THE LOAD-BEARING C20 INVARIANT (mutation target): carrying a risk label NEVER changes an object's
    //    effect class (the closed C5 lattice is untouched — a risk label is an advisory dimension, not a
    //    fifth effect). For every effect, the object carrying the gating "sensitive"/"egress" labels resolves
    //    to the SAME class as the identical object with no labels, and to the oracle's normalized effect.
    //    A read_only object carrying the gating "sensitive" label is still read_only. Making effectClass
    //    escalate on a gating label flips the last assertion.
    func testRiskLabelEffectClassUnchanged() throws {
        let c = try Self.loadVector()
        let risk = try XCTUnwrap(c["risk"] as? [String: Any])
        let labels = try Self.carriedLabels(risk)
        var sawGating = false
        for l in labels {
            let (cls, ok) = Negotiation.riskClassOf(l.code)
            if ok && cls == Negotiation.CLASS_GATING { sawGating = true }
        }
        XCTAssertTrue(sawGating, "corpus carries at least one gating label so the mutation seam is real")

        for lo in try XCTUnwrap(risk["labeled_objects"] as? [[String: Any]]) {
            let effect = try Self.u64(lo["effect"])
            let with = Negotiation.LabeledObject(effect: effect, labels: labels)
            let without = Negotiation.LabeledObject(effect: effect, labels: [])
            let want = Policy.normalizeEffect(Int(effect))
            XCTAssertEqual(with.effectClass(), want, "with-labels effect class == normalized effect")
            XCTAssertEqual(without.effectClass(), want, "without-labels effect class == normalized effect")
            XCTAssertEqual(with.effectClass(), without.effectClass(), "carrying labels did not change the class")
            XCTAssertEqual(UInt64(with.effectClass()), try Self.u64(lo["effect_class"]), "effect class == oracle")
        }

        let sensitive = Negotiation.LabeledObject(effect: UInt64(Policy.READ_ONLY),
                                                  labels: [Negotiation.RiskLabel(code: Negotiation.RISK_SENSITIVE, critical: 1)])
        XCTAssertEqual(sensitive.effectClass(), Policy.READ_ONLY,
                       "read_only + sensitive resolves to read_only; a risk label must NOT escalate the effect")
    }

    // 6. the R-2.5 critical-extension rule over risk labels: the vocabulary/class and extensible-range
    //    start match the oracle; a recognized-plus-unknown-noncritical set validates (the unknown
    //    non-critical is dropped); an unknown CRITICAL label is rejected; a malformed critical flag is
    //    rejected at parse.
    func testRiskLabelCriticalExtensionRule() throws {
        let c = try Self.loadVector()
        let risk = try XCTUnwrap(c["risk"] as? [String: Any])
        for e in try XCTUnwrap(risk["vocabulary"] as? [[String: Any]]) {
            let (cls, ok) = Negotiation.riskClassOf(try Self.u64(e["code"]))
            XCTAssertTrue(ok, "vocab label registered")
            XCTAssertEqual(Negotiation.riskClassName(cls), e["class"] as? String, "vocab class == oracle")
        }
        XCTAssertEqual(Negotiation.EXTENSIBLE_RANGE_START, try Self.u64(risk["extensible_range_start"]),
                       "extensible range start == oracle")

        let validate = try XCTUnwrap(risk["validate"] as? [String: Any])
        let recSet = try XCTUnwrap(validate["recognized_set"] as? [String: Any])
        let got = try Negotiation.validateLabels(try Self.labelsFrom(try XCTUnwrap(recSet["carried"] as? [[String: Any]])))
        let wantCodes = try XCTUnwrap(recSet["recognized_codes"] as? [Any])
        XCTAssertEqual(got.count, wantCodes.count, "recognized-label count == oracle")
        for (i, l) in got.enumerated() {
            XCTAssertEqual(l.code, try Self.u64(wantCodes[i]), "recognized[\(i)] code == oracle")
            XCTAssertTrue(Negotiation.isRegisteredRisk(l.code), "recognized[\(i)] is a standard label")
        }

        let critSet = try XCTUnwrap(validate["unknown_critical_rejected"] as? [String: Any])
        XCTAssertThrowsError(try Negotiation.validateLabels(try Self.labelsFrom(try XCTUnwrap(critSet["carried"] as? [[String: Any]]))),
                             "unknown critical rejected (UnknownCriticalRisk)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownCriticalRisk")
        }

        // A malformed critical flag (outside {0,1}) is rejected at parse time (no CBOR boolean).
        let badFlag = Negotiation.LabeledObject(effect: 0, labels: [Negotiation.RiskLabel(code: Negotiation.RISK_SENSITIVE, critical: 2)])
        XCTAssertThrowsError(try Negotiation.parseLabeledObject(try badFlag.bytes()),
                             "malformed critical flag rejected (MalformedCriticalFlag)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "MalformedCriticalFlag")
        }
    }

    // 6b. every standalone risk-label body {1:code, 2:critical} is byte-identical to the oracle, including
    //     the two extensible-range codes (4096, 8192) whose CBOR uint head is a 2-byte form — the only cases
    //     in the corpus that exercise a label code >= 24.
    func testRiskLabelBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let samples = try XCTUnwrap((c["risk"] as? [String: Any])?["sample_labels"] as? [String: Any])
        XCTAssertEqual(samples.count, 5, "corpus has 5 sample risk labels")
        for (name, raw) in samples {
            let d = try XCTUnwrap(raw as? [String: Any], "sample \(name) is an object")
            let label = Negotiation.RiskLabel(code: try Self.u64(d["code"]), critical: try Self.u64(d["critical"]))
            XCTAssertEqual(Self.toHex(try label.bytes()), d["body_hex"] as? String, "risk-label \(name) body == oracle")
        }
    }

    // 7. the C20 trust checkpoint over REAL Ed25519-signed trust refs (isolation): a carried reference
    //    VERIFIES (its content-id recomputes over the external record and its signature checks) but NOTHING
    //    on the wire scores it; a tampered record no longer recomputes (ReferenceMismatch); two DIFFERENT
    //    registries referencing the SAME record verify symmetrically (the wire weighs neither).
    func testTrustRefCheckableNeverWeighed() throws {
        let c = try Self.loadVector()
        let t = try XCTUnwrap(c["trust"] as? [String: Any])
        let key = try Self.negKey("registrar")
        let foreign = try Self.negKey("attacker")
        let record = Self.hexToBytes(try XCTUnwrap(t["external_record_hex"] as? String))
        let reference = Self.hexToBytes(try XCTUnwrap(t["reference_hex"] as? String))
        let tampered = Self.hexToBytes(try XCTUnwrap(t["tampered_record_hex"] as? String))
        let subject = Self.hexToBytes(try XCTUnwrap(t["subject_hex"] as? String))

        let refA = Negotiation.TrustRef(registry: Self.hexToBytes(try XCTUnwrap(t["registry_a_hex"] as? String)),
                                        reference: reference, subject: subject)
        XCTAssertTrue(refA.bindsRecord(record), "trust ref binds the external record it references")
        XCTAssertFalse(refA.bindsRecord(tampered), "trust ref does not bind a tampered record")

        let objA = try Negotiation.signTrustRef(refA, key.seed)
        let r = try Negotiation.verifyTrustRef(objA, Self.negVerify(key.pk), record)
        XCTAssertEqual(r.reference, reference, "resolved reference == carried content-id")
        XCTAssertThrowsError(try Negotiation.verifyTrustRef(objA, Self.negVerify(key.pk), tampered),
                             "tampered record rejected (ReferenceMismatch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ReferenceMismatch")
        }
        XCTAssertThrowsError(try Negotiation.verifyTrustRef(objA, Self.negVerify(foreign.pk), record),
                             "foreign-key verify rejected (BadSignature)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature")
        }

        let refB = Negotiation.TrustRef(registry: Self.hexToBytes(try XCTUnwrap(t["registry_b_hex"] as? String)),
                                        reference: reference, subject: subject)
        let objB = try Negotiation.signTrustRef(refB, key.seed)
        let rB = try Negotiation.verifyTrustRef(objB, Self.negVerify(key.pk), record)
        XCTAssertEqual(r.reference, rB.reference, "two registries -> same referenced record")
        XCTAssertNotEqual(r.registry, rB.registry, "the two registries differ (symmetry fixture)")
    }

    // ===== standard wire-format edge cases =====

    // 8. keys-out-of-order: the canonical offer body == oracle; a descending-key body is rejected
    //    NonCanonical by the strict decoder, and parseMessage surfaces it as NegMalformed.
    func testNegKeysOutOfOrderRejected() throws {
        let c = try Self.loadVector()
        let e = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["keys_out_of_order"] as? [String: Any])
        let offer = Negotiation.Message(negotiation: Array("neg-0001".utf8), role: Negotiation.ROLE_OFFER,
                                        profile: Negotiation.PROFILE_BASELINE, causes: [])
        XCTAssertEqual(Self.toHex(try offer.bytes()), e["canonical_offer_body_hex"] as? String, "canonical offer body == oracle")
        let canon = Self.hexToBytes(try XCTUnwrap(e["canonical_offer_body_hex"] as? String))
        let noncanon = Self.hexToBytes(try XCTUnwrap(e["noncanonical_offer_body_hex"] as? String))
        XCTAssertNoThrow(try Cbor.decode(canon), "canonical body decodes")
        XCTAssertNoThrow(try Negotiation.parseMessage(canon), "canonical body parses")
        XCTAssertThrowsError(try Cbor.decode(noncanon), "descending-key body rejected (NonCanonical)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, e["reject"] as? String)
        }
        XCTAssertThrowsError(try Negotiation.parseMessage(noncanon), "parseMessage rejects non-canonical (NegMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NegMalformed")
        }
    }

    // 9. empty-vs-absent causes: an empty causes[] is distinct on the wire and by content-id from a
    //    populated one; both differ from a body whose causes field is absent (rejected NegMalformed).
    func testNegEmptyVsAbsentCauses() throws {
        let c = try Self.loadVector()
        let ec = try XCTUnwrap((((c["edge_cases"] as? [String: Any])?["empty_vs_absent"] as? [String: Any])?["causes"]) as? [String: Any])
        let neg = Array("neg-0001".utf8)
        let empty = Negotiation.Message(negotiation: neg, role: Negotiation.ROLE_OFFER, profile: Negotiation.PROFILE_BASELINE, causes: [])
        let oneD = try XCTUnwrap(ec["one_cause"] as? [String: Any])
        let one = Negotiation.Message(negotiation: neg, role: Negotiation.ROLE_OFFER, profile: Negotiation.PROFILE_BASELINE,
                                      causes: [Self.hexToBytes(try XCTUnwrap(oneD["cause_hex"] as? String))])
        let emptyD = try XCTUnwrap(ec["empty_present"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try empty.bytes()), emptyD["body_hex"] as? String, "empty-causes body == oracle")
        XCTAssertEqual(Self.toHex(try one.bytes()), oneD["body_hex"] as? String, "one-cause body == oracle")
        XCTAssertNotEqual(try empty.id(), try one.id(), "empty and one-cause have distinct content-ids")
        XCTAssertEqual(Self.toHex(try empty.id()), emptyD["id_hex"] as? String, "empty-causes id == oracle")
        XCTAssertNoThrow(try Negotiation.parseMessage(try empty.bytes()))
        XCTAssertNoThrow(try Negotiation.parseMessage(try one.bytes()))
        let absentD = try XCTUnwrap(ec["absent_field"] as? [String: Any])
        XCTAssertThrowsError(try Negotiation.parseMessage(Self.hexToBytes(try XCTUnwrap(absentD["body_hex"] as? String))),
                             "absent causes field rejected (NegMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NegMalformed")
        }
    }

    // 10. empty-vs-absent labels: an empty labels[] is distinct by content-id from a populated one; both
    //     differ from a body whose labels field is absent (rejected NegMalformed).
    func testNegEmptyVsAbsentLabels() throws {
        let c = try Self.loadVector()
        let el = try XCTUnwrap((((c["edge_cases"] as? [String: Any])?["empty_vs_absent"] as? [String: Any])?["labels"]) as? [String: Any])
        let empty = Negotiation.LabeledObject(effect: 0, labels: [])
        let oneD = try XCTUnwrap(el["one_label"] as? [String: Any])
        let one = Negotiation.LabeledObject(effect: 0, labels: [Negotiation.RiskLabel(code: try Self.u64(oneD["code"]), critical: try Self.u64(oneD["critical"]))])
        let emptyD = try XCTUnwrap(el["empty_present"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try empty.bytes()), emptyD["body_hex"] as? String, "empty-labels body == oracle")
        XCTAssertEqual(Self.toHex(try one.bytes()), oneD["body_hex"] as? String, "one-label body == oracle")
        XCTAssertNotEqual(try empty.id(), try one.id(), "empty and one-label have distinct content-ids")
        XCTAssertEqual(Self.toHex(try empty.id()), emptyD["id_hex"] as? String, "empty-labels id == oracle")
        XCTAssertNoThrow(try Negotiation.parseLabeledObject(try empty.bytes()))
        XCTAssertNoThrow(try Negotiation.parseLabeledObject(try one.bytes()))
        let absentD = try XCTUnwrap(el["absent_field"] as? [String: Any])
        XCTAssertThrowsError(try Negotiation.parseLabeledObject(Self.hexToBytes(try XCTUnwrap(absentD["body_hex"] as? String))),
                             "absent labels field rejected (NegMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NegMalformed")
        }
    }

    // 11. the smallest legal offer, labeled-object, and trust-ref each encode to the oracle bytes, have a
    //     stable content-id, and round-trip through their Parse*.
    func testNegMinimal() throws {
        let c = try Self.loadVector()
        let m = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["minimal"] as? [String: Any])
        let od = try XCTUnwrap(m["offer"] as? [String: Any])
        let offer = Negotiation.Message(negotiation: [], role: Negotiation.ROLE_OFFER, profile: Negotiation.PROFILE_BASELINE, causes: [])
        XCTAssertEqual(Self.toHex(try offer.bytes()), od["body_hex"] as? String, "minimal offer body == oracle")
        XCTAssertEqual(Self.toHex(try offer.id()), od["id_hex"] as? String, "minimal offer id == oracle")
        XCTAssertNoThrow(try Negotiation.parseMessage(try offer.bytes()))
        let ld = try XCTUnwrap(m["labeled_object"] as? [String: Any])
        let lo = Negotiation.LabeledObject(effect: try Self.u64(ld["effect"]), labels: [])
        XCTAssertEqual(Self.toHex(try lo.bytes()), ld["body_hex"] as? String, "minimal labeled-object body == oracle")
        XCTAssertEqual(Self.toHex(try lo.id()), ld["id_hex"] as? String, "minimal labeled-object id == oracle")
        XCTAssertNoThrow(try Negotiation.parseLabeledObject(try lo.bytes()))
        let td = try XCTUnwrap(m["trust_ref"] as? [String: Any])
        let tr = Negotiation.TrustRef(registry: [], reference: [], subject: [])
        XCTAssertEqual(Self.toHex(try tr.bytes()), td["body_hex"] as? String, "minimal trust-ref body == oracle")
        XCTAssertEqual(Self.toHex(try tr.id()), td["id_hex"] as? String, "minimal trust-ref id == oracle")
        XCTAssertNoThrow(try Negotiation.parseTrustRef(try tr.bytes()))
    }

    // 12. look-alike cross-kind rejection: a trust-ref body {1:bstr,2:bstr,3:bstr} fed to parseMessage is
    //     NegMalformed (field 2 is not the uint role); a message body {1:bstr,2:uint,3:uint,4:arr} fed to
    //     parseTrustRef is NegMalformed (field 2 is not a bstr reference).
    func testNegLookAlikeRejected() throws {
        let c = try Self.loadVector()
        let la = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["look_alike"] as? [String: Any])
        let trm = try XCTUnwrap(la["trust_ref_as_message"] as? [String: Any])
        XCTAssertThrowsError(try Negotiation.parseMessage(Self.hexToBytes(try XCTUnwrap(trm["body_hex"] as? String))),
                             "trust-ref parsed as a message rejected (NegMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NegMalformed")
        }
        let mtr = try XCTUnwrap(la["message_as_trust_ref"] as? [String: Any])
        XCTAssertThrowsError(try Negotiation.parseTrustRef(Self.hexToBytes(try XCTUnwrap(mtr["body_hex"] as? String))),
                             "message parsed as a trust-ref rejected (NegMalformed)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NegMalformed")
        }
    }
}
