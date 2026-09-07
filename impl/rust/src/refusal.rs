// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! R-TDCS-3 (design.md §25, C22) — the party-visible coarse refusal object. A refusal returned to
//! the authenticated party carries ONLY a single value from a closed vocabulary and the content id
//! of the full signed record that carries the discriminating detail — a reference, not the reason.
//! The detail exists, is signed, and is auditor-resolvable through the record channel, but never
//! reaches the adversary-facing surface, so repeated refusals cannot serve an adaptive party as an
//! oracle. A party-visible refusal that carries discriminating detail, or omits the record content
//! id, is a RefusalDetailLeak; an outcome outside the closed set is UnknownRefusalOutcome.
//!
//! The Rust half of the Go/Rust wire parity (impl/go/approval/refusal.go); graded against the
//! independent oracle vectors/trust_decision/cases.json (non-circular, F3).

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;

/// The closed refusal-outcome set (CDDL refusal-outcome).
pub const REFUSAL_DENIED: u64 = 0; // the action is refused
pub const REFUSAL_HELD: u64 = 1; // the action requires a further step not yet taken
pub const REFUSAL_UNVERIFIABLE: u64 = 2; // required evidence did not verify

/// Whether `code` is in the closed refusal-outcome set.
pub fn is_known_refusal_outcome(code: u64) -> bool {
    matches!(code, REFUSAL_DENIED | REFUSAL_HELD | REFUSAL_UNVERIFIABLE)
}

pub fn err_unknown_refusal_outcome() -> cose::Error {
    cose::Error {
        kind: "UnknownRefusalOutcome",
        msg: "refusal outcome is outside the closed set denied/held/unverifiable",
    }
}
pub fn err_refusal_detail_leak() -> cose::Error {
    cose::Error {
        kind: "RefusalDetailLeak",
        msg: "party-visible refusal carries discriminating detail or omits the record content id",
    }
}

/// T1 content-id framing multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || digest (50 octets).
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.push(0x20);
    out.push(0x30);
    out.extend_from_slice(&Sha384::digest(b));
    out
}

/// The party-visible coarse refusal body {1: outcome, 2: record}. `outcome` is the closed-set
/// coarse outcome; `record` is the T1 content id of the full signed record carrying the detail.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub outcome: u64,
    pub record: Vec<u8>,
}

impl Refusal {
    /// Deterministic-CBOR encoding {1: outcome, 2: record}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.outcome)),
            (Value::Uint(2), Value::Bstr(self.record.clone())),
        ]))
        .expect("encode refusal body")
    }
}

/// Build the party-visible refusal for a full signed record: it carries the coarse outcome and
/// the content id of `full_record`, and NOTHING drawn from inside `full_record` — the
/// discriminating detail stays in the record, referenced only by its id. This is the
/// coarse-to-party split the closure property requires (R-TDCS-3).
pub fn refusal_from_record(outcome: u64, full_record: &[u8]) -> Refusal {
    Refusal {
        outcome,
        record: content_id(full_record),
    }
}

/// Reconstruct a Refusal from its body bytes, enforcing that a party-visible refusal carries ONLY
/// {outcome, record} and nothing more (R-TDCS-3). Rejects, fail-closed: a malformed body, any key
/// other than 1 and 2 (or a wrong-typed 1/2), and a missing or empty record id
/// (RefusalDetailLeak — discriminating detail leaked, or the auditor reference dropped), and an
/// outcome outside the closed set (UnknownRefusalOutcome). Order matters: a malformed shape is
/// checked BEFORE the outcome vocabulary, so an unknown outcome with an otherwise-valid record
/// yields UnknownRefusalOutcome, while any other malformation yields RefusalDetailLeak first.
/// Authorizes nothing.
pub fn parse_refusal(b: &[u8]) -> Result<Refusal, cose::Error> {
    let v = cbor::decode(b).map_err(|_| err_refusal_detail_leak())?;
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_refusal_detail_leak()),
    };
    let mut outcome: Option<u64> = None;
    let mut record: Option<Vec<u8>> = None;
    for (k, val) in m {
        let key = match k {
            Value::Uint(n) => n,
            _ => return Err(err_refusal_detail_leak()),
        };
        match (key, val) {
            (1, Value::Uint(u)) => outcome = Some(u),
            (2, Value::Bstr(bs)) => record = Some(bs),
            // any field beyond {1,2}, or a wrong-typed 1/2, is leaked detail
            _ => return Err(err_refusal_detail_leak()),
        }
    }
    let (outcome, record) = match (outcome, record) {
        // a refusal must carry the full-record content id
        (Some(o), Some(r)) if !r.is_empty() => (o, r),
        _ => return Err(err_refusal_detail_leak()),
    };
    if !is_known_refusal_outcome(outcome) {
        return Err(err_unknown_refusal_outcome());
    }
    Ok(Refusal { outcome, record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const TDCS_WIRE_PATH: &str = "../../vectors/trust_decision/cases.json";

    fn load() -> J {
        serde_json::from_str(
            &std::fs::read_to_string(TDCS_WIRE_PATH).expect("read tdcs wire corpus"),
        )
        .expect("parse tdcs wire corpus")
    }

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    // tdcs3_refusal_coarse_and_no_leak: R-TDCS-3. refusal_from_record yields the exact oracle bytes
    // for each closed-set outcome, carries the full record's content id, and NEVER carries the
    // record's discriminating detail (the reason). parse_refusal round-trips a conformant refusal
    // and rejects every non-conformant shape: an unknown outcome, an extra field, a missing/empty
    // record id.
    #[test]
    fn tdcs3_refusal_coarse_and_no_leak() {
        let c = load();
        let r = &c["refusal"];
        let full_record = hexd(r["full_record_hex"].as_str().unwrap());
        let record_id = hexd(r["full_record_id_hex"].as_str().unwrap());
        let reason = r["leaked_reason"].as_str().unwrap().as_bytes().to_vec();

        for tc in r["cases"].as_array().unwrap() {
            let outcome = tc["outcome"].as_u64().unwrap();
            let name = tc["name"].as_str().unwrap();
            let ref_ = refusal_from_record(outcome, &full_record);
            let b = ref_.bytes();
            assert_eq!(
                hex::encode(&b),
                tc["record_hex"].as_str().unwrap(),
                "{name}: refusal bytes != oracle"
            );
            assert!(
                !contains(&b, &reason),
                "{name}: the record's reason LEAKED into the party-visible refusal"
            );
            assert!(
                contains(&b, &record_id),
                "{name}: refusal does not carry the full-record content id"
            );

            // Round-trip: a conformant refusal parses back to the same outcome + record id.
            let got = parse_refusal(&b)
                .unwrap_or_else(|e| panic!("{name}: conformant refusal rejected: {e:?}"));
            assert_eq!(got.outcome, outcome, "{name}: round-trip outcome mismatch");
            assert_eq!(got.record, record_id, "{name}: round-trip record mismatch");
        }

        // Non-conformant refusals a conformant parser MUST reject.
        let reject = &r["reject"];
        assert_eq!(
            parse_refusal(&hexd(reject["unknown_outcome_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "UnknownRefusalOutcome",
            "unknown refusal outcome must be rejected"
        );
        for (name, hex_key) in [
            ("extra field (leaked detail)", "detail_leak_extra_field_hex"),
            ("missing record id", "missing_record_hex"),
            ("empty record id", "empty_record_hex"),
        ] {
            let body = hexd(reject[hex_key].as_str().unwrap());
            assert_eq!(
                parse_refusal(&body).unwrap_err().kind,
                "RefusalDetailLeak",
                "{name} must be rejected RefusalDetailLeak"
            );
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return needle.is_empty();
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
