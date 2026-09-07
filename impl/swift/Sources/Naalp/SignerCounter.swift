// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T1.6 the OPTIONAL per-signer forward-only counter (design.md §2.5.2, NAALP-REQ-120) and
// DetectSignerDuplication (the set-level detector it exists for) for the Swift SDK, mirroring
// impl/go/envelope/signer_counter.go byte-for-byte and porting the exact detection algorithm.
// Graded against the independent oracle (tools/signer_counter_oracle.py ->
// vectors/signer_counter/cases.json) in SignerCounterKatTests.swift.

extension Envelope {

    /// The ext extension key under which an object OPTIONALLY carries a forward-only per-signer
    /// counter (design.md §2.5.2, NAALP-REQ-120 -- the per-signer counter). The value is a
    /// forward-only position (a uint) the signer increments on each object. It lives in the
    /// NON-CRITICAL ext map (field 11): a verifier that does not perform duplication-detection
    /// ignores it and the object still verifies (may-ignore). Because ext (field 11) is part of the
    /// signed body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature -- the
    /// deliberate contrast with the T1.5 consume-receipt position, which is signed by the LEDGER
    /// key. 14 is the next free ext/cext key: it does not collide with the safety-label ext key 1
    /// (§6.4) or the recheck ext/cext key 13 (T1.3). Byte-identical to impl/go, impl/rust.
    ///
    /// The counter is DETECTION, not prevention (NAALP-REQ-120; # Security Considerations): a
    /// single self-authored sequence proves nothing. It is a NON-CRITICAL field only -- placing it
    /// in the critical cext map (field 12) is an unrecognized critical extension and is rejected
    /// fail-closed (UnknownCriticalExt, the existing §2.5 rule), because a detection aid is never a
    /// must-understand verification gate.
    public static let SignerCounterKey: UInt64 = 14

    /// Returns the forward-only per-signer position `o` names (SignerCounterKey, §2.5.2): `present`
    /// is true iff a counter is named in the non-critical ext map (field 11) as a uint. The field is
    /// OPTIONAL -- absent (`present == false`) is valid. `present` is keyed on the KEY being
    /// present, not on the value: a present counter of value 0 returns (0, true).
    public static func signerCounter(_ o: Object) -> (seq: UInt64, present: Bool) {
        guard let ext = o.ext, case let .m(pairs) = ext else { return (0, false) }
        for (k, v) in pairs {
            if case let .u(kn) = k, kn == SignerCounterKey {
                if case let .u(val) = v {
                    return (val, true)
                }
                return (0, false)
            }
        }
        return (0, false)
    }

    /// Names `seq` as `o`'s forward-only per-signer position in the NON-CRITICAL ext map (field
    /// 11), covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and
    /// leaves any other extension entries intact. The counter is deliberately never placed in the
    /// critical cext map (it is detection, not a verification gate).
    public static func setSignerCounter(_ o: inout Object, _ seq: UInt64) {
        let entry: (CborValue, CborValue) = (.u(SignerCounterKey), .u(seq))
        if let existing = o.ext, case let .m(existingPairs) = existing {
            var pairs = existingPairs
            var replaced = false
            for i in 0..<pairs.count {
                if case let .u(kn) = pairs[i].0, kn == SignerCounterKey {
                    pairs[i] = entry
                    replaced = true
                    break
                }
            }
            if !replaced { pairs.append(entry) }
            o.ext = .m(pairs)
        } else {
            o.ext = .m([entry])
        }
    }

    /// Surfaces one detected per-signer counter conflict: two or more DISTINCT objects (distinct
    /// content ids) from the SAME signer id that carry the SAME forward-only counter value. A
    /// forward-only counter binds each value to at most one object, so a value bound to >= 2
    /// distinct objects is the observable fingerprint of the key incrementing in two places (key
    /// duplication). The finding surfaces BOTH sides of the contradiction: the reused `counter`
    /// value and every conflicting content id (`ids`, ascending by bytes) -- never a single flag
    /// with the evidence hidden.
    public struct DuplicationFinding {
        public var signer: [UInt8]   // the signer id whose forward-only counter was reused
        public var counter: UInt64   // the reused forward-only counter value
        public var ids: [[UInt8]]    // the content ids of the >= 2 conflicting objects, ascending by bytes

        public init(signer: [UInt8], counter: UInt64, ids: [[UInt8]]) {
            self.signer = signer
            self.counter = counter
            self.ids = ids
        }
    }

    /// Lexicographic byte comparison, mirroring Go's `bytes.Compare(a, b) < 0` (used to sort signer
    /// ids and, within a finding, the conflicting content ids -- deterministic output).
    private static func bytesLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        let n = min(a.count, b.count)
        for i in 0..<n where a[i] != b[i] {
            return a[i] < b[i]
        }
        return a.count < b.count
    }

    /// Scans a SET of PRESENTED objects for per-signer counter reuse. This is the whole point of
    /// the field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a signer id ONLY
    /// when two conflicting sequences from that signer physically MEET in the presented set -- a
    /// counter value bound to >= 2 distinct content ids by one signer. Given only ONE object per
    /// value (one sequence) it returns no findings; the second conflicting object must be present,
    /// unsuppressed, for the duplication to become provable. Objects with no counter do not
    /// participate. Output is deterministic (findings ordered by signer id then counter; ids within
    /// a finding ascending).
    ///
    /// It operates over the SET, never per object: a per-object boolean could never express "these
    /// two distinct objects reuse one position," and a single self-authored counter proves nothing
    /// on its own.
    public static func detectSignerDuplication(_ objs: [Object]) -> [DuplicationFinding] {
        // signer bytes -> counter -> a SET of content ids, deduping a byte-identical
        // re-presentation (one content id twice) so it is NOT a conflict.
        var groups: [[UInt8]: [UInt64: Set<[UInt8]>]] = [:]

        for o in objs {
            let (seq, present) = signerCounter(o)
            guard present else { continue } // a counter-less object does not participate in detection
            guard let id = try? o.contentId() else { continue } // an unencodable body cannot be a presented object
            var byCounter = groups[o.signer] ?? [:]
            var idset = byCounter[seq] ?? Set<[UInt8]>()
            idset.insert(id)
            byCounter[seq] = idset
            groups[o.signer] = byCounter
        }

        let signers = groups.keys.sorted(by: bytesLess)
        var findings: [DuplicationFinding] = []
        for sk in signers {
            guard let byCounter = groups[sk] else { continue }
            let counters = byCounter.keys.sorted()
            for c in counters {
                guard let idset = byCounter[c] else { continue }
                // A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
                // duplication. The >= 2 requirement is the detection-requires-both invariant: relax
                // it to >= 1 and a single sequence would flag (prevention theatre) -- the mutation
                // the "one sequence alone -> not flagged" test is built to catch.
                if idset.count < 2 { continue }
                let ids = idset.sorted(by: bytesLess)
                findings.append(DuplicationFinding(signer: sk, counter: c, ids: ids))
            }
        }
        return findings
    }
}
