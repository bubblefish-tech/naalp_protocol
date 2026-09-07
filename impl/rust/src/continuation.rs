// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C17 — N-AALP-CONT flow continuation (design.md §20; R-CONT-1..7). The Rust half of the
//! two-implementation parity; byte-identical to impl/go/continuation.
//!
//! N-AALP-CONT generalizes the C9 native-streaming pattern (one signed StreamOpen, cheap chunks,
//! one signed StreamCommit) into a domain-agnostic flow: a FlowOpen is the ONE full ML-DSA
//! signature that fixes the flow's effect ceiling and approval bindings (authority reconstructable
//! from its bytes alone); cheap hash-chained Continuations extend it, each with an effect at or
//! below the ceiling (AboveCeiling otherwise); Checkpoints detect a dropped/reordered link
//! (GapDetected); a FlowCommit is a second full signature binding the whole ordered sequence with
//! one signature regardless of N. A continuation replayed under a different FlowOpen fails
//! (WrongFlow, and its prev no longer chains — ChainBroken). Domain separation is structural: the
//! four body shapes (3 / 5 / 3-with-bstr / 2 fields) are each distinct deterministic CBOR.

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;
use crate::policy;

/// Width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain.
pub const HEAD_SIZE: usize = 48;

pub fn err_wrong_flow() -> cose::Error {
    cose::Error {
        kind: "WrongFlow",
        msg: "object's flow_open_id does not match the FlowOpen",
    }
}
pub fn err_seq_gap() -> cose::Error {
    cose::Error {
        kind: "SeqGap",
        msg: "continuation seq is not the next expected value",
    }
}
pub fn err_above_ceiling() -> cose::Error {
    cose::Error {
        kind: "AboveCeiling",
        msg: "continuation effect exceeds the FlowOpen effect ceiling",
    }
}
pub fn err_chain_broken() -> cose::Error {
    cose::Error {
        kind: "ChainBroken",
        msg: "continuation prev does not chain to the previous head",
    }
}
pub fn err_gap_detected() -> cose::Error {
    cose::Error {
        kind: "GapDetected",
        msg: "checkpoint reveals a dropped or reordered continuation",
    }
}
pub fn err_commit_mismatch() -> cose::Error {
    cose::Error {
        kind: "CommitMismatch",
        msg: "flow commit final_head does not match the recomputed chain",
    }
}
pub fn err_malformed() -> cose::Error {
    cose::Error {
        kind: "ContMalformed",
        msg: "object is not a well-formed N-AALP-CONT body",
    }
}
pub fn err_range() -> cose::Error {
    cose::Error {
        kind: "RangeError",
        msg: "effect or effect_ceiling is outside the closed 0..3 lattice",
    }
}

/// Whether `v` is a value of the closed C5 effect lattice (0..3). The CDDL types both effect_ceiling
/// (naalp-flow-open field 2) and a continuation effect (naalp-continuation field 3) as the closed
/// `effect` enum, so an out-of-lattice value is rejected RangeError, NEVER normalized to destructive:
/// normalizing a CEILING to destructive would silently make an out-of-range ceiling the
/// most-permissive one (a fail-open), so a ceiling is range-checked, never normalize_effect'd.
fn in_lattice(v: u64) -> bool {
    v <= policy::DESTRUCTIVE as u64
}

/// SHA-384 over a body — a 48-octet chain head.
fn head(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

/// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x20u8, 0x30u8];
    v.extend_from_slice(&head(b));
    v
}

// ---- FlowOpen ---------------------------------------------------------------------------------

/// Fixes a flow's identity, effect ceiling, and approval bindings; signed with one full ML-DSA
/// signature; authority reconstructable from its bytes alone.
#[derive(Debug, Clone)]
pub struct FlowOpen {
    pub flow_id: Vec<u8>,
    pub effect_ceiling: u64,
    pub approvals: Vec<Vec<u8>>,
}

impl FlowOpen {
    /// Deterministic-CBOR {1: flow_id, 2: effect_ceiling, 3: approvals[]}.
    pub fn bytes(&self) -> Vec<u8> {
        let arr = Value::Arr(
            self.approvals
                .iter()
                .map(|a| Value::Bstr(a.clone()))
                .collect(),
        );
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.flow_id.clone())),
            (Value::Uint(2), Value::Uint(self.effect_ceiling)),
            (Value::Uint(3), arr),
        ]))
        .expect("encode flow open")
    }
    /// The genesis prev that anchors the continuation chain.
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// The content-id carried by every child object.
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a FlowOpen from its body bytes alone (the bearer-authority property).
pub fn parse_flow_open(b: &[u8]) -> Result<FlowOpen, cose::Error> {
    let m = decode_map(b)?;
    let flow_id = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let effect_ceiling = uint_field(&m, 2).ok_or_else(err_malformed)?;
    // The effect_ceiling is a CLOSED effect (0..3); an out-of-lattice ceiling is rejected on decode
    // (RangeError), never normalized — see in_lattice.
    if !in_lattice(effect_ceiling) {
        return Err(err_range());
    }
    let apps_v = field(&m, 3).ok_or_else(err_malformed)?;
    let arr = match apps_v {
        Value::Arr(a) => a,
        _ => return Err(err_malformed()),
    };
    let mut approvals = Vec::with_capacity(arr.len());
    for e in arr {
        match e {
            Value::Bstr(bs) => approvals.push(bs.clone()),
            _ => return Err(err_malformed()),
        }
    }
    Ok(FlowOpen {
        flow_id,
        effect_ceiling,
        approvals,
    })
}

// ---- Continuation -----------------------------------------------------------------------------

/// One cheap hash-chain link; not individually signed.
#[derive(Debug, Clone)]
pub struct Continuation {
    pub flow_open_id: Vec<u8>,
    pub seq: u64,
    pub effect: u64,
    pub payload_id: Vec<u8>,
    pub prev: Vec<u8>,
}

impl Continuation {
    /// Deterministic-CBOR {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.flow_open_id.clone())),
            (Value::Uint(2), Value::Uint(self.seq)),
            (Value::Uint(3), Value::Uint(self.effect)),
            (Value::Uint(4), Value::Bstr(self.payload_id.clone())),
            (Value::Uint(5), Value::Bstr(self.prev.clone())),
        ]))
        .expect("encode continuation")
    }
    /// This link's head — the prev of the next link.
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
}

/// The single audited decode path for untrusted Continuation wire bytes. It reconstructs the 5-field
/// body and range-checks the effect against the closed lattice (0..3): field 3 is typed `effect` (a
/// closed enum) in the CDDL, so an out-of-lattice effect is rejected RangeError on decode, never
/// carried as an unknown value into the cheap-path check. Fail-closed.
pub fn parse_continuation(b: &[u8]) -> Result<Continuation, cose::Error> {
    let m = decode_map(b)?;
    let flow_open_id = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let seq = uint_field(&m, 2).ok_or_else(err_malformed)?;
    let effect = uint_field(&m, 3).ok_or_else(err_malformed)?;
    let payload_id = bstr_field(&m, 4).ok_or_else(err_malformed)?;
    let prev = bstr_field(&m, 5).ok_or_else(err_malformed)?;
    if !in_lattice(effect) {
        return Err(err_range());
    }
    Ok(Continuation {
        flow_open_id,
        seq,
        effect,
        payload_id,
        prev,
    })
}

/// Cheap-path check of a single link: same flow (WrongFlow), next seq (SeqGap), effect within the
/// ceiling (AboveCeiling), prev chaining to the previous head (ChainBroken). No signature — the
/// cheap path. The cheap-vs-full cost is measured by the Go TestPhase2Measurement (~1us cheap vs
/// ~25us full on the reference box; exact numbers are machine-dependent).
pub fn verify_continuation(
    c: &Continuation,
    flow_open_id: &[u8],
    prev_head: &[u8],
    expected_seq: u64,
    ceiling: u8,
) -> Result<(), cose::Error> {
    // Both the ceiling and the link's effect are CLOSED effects (0..3). An out-of-lattice value is
    // RangeError — NOT normalize_effect'd — so neither an out-of-range ceiling silently becomes the
    // most-permissive class nor an out-of-range link effect is silently clamped below it (fail-closed).
    if !in_lattice(ceiling as u64) {
        return Err(err_range());
    }
    if !in_lattice(c.effect) {
        return Err(err_range());
    }
    if c.flow_open_id != flow_open_id {
        return Err(err_wrong_flow());
    }
    if c.seq != expected_seq {
        return Err(err_seq_gap());
    }
    if !policy::authorizes(ceiling, c.effect as u8) {
        return Err(err_above_ceiling());
    }
    if c.prev != prev_head {
        return Err(err_chain_broken());
    }
    Ok(())
}

/// Verify a whole ordered continuation sequence from the FlowOpen; returns the final chain head.
pub fn verify_chain(open: &FlowOpen, conts: &[Continuation]) -> Result<Vec<u8>, cose::Error> {
    // The ceiling is a closed effect (0..3); an out-of-lattice ceiling is rejected RangeError, never
    // normalized to destructive (which would make it the most-permissive ceiling — a fail-open).
    if !in_lattice(open.effect_ceiling) {
        return Err(err_range());
    }
    let id = open.id();
    let mut prev = open.head();
    let ceiling = open.effect_ceiling as u8;
    for (i, c) in conts.iter().enumerate() {
        verify_continuation(c, &id, &prev, i as u64, ceiling)?;
        prev = c.head();
    }
    Ok(prev)
}

// ---- Checkpoint -------------------------------------------------------------------------------

/// Asserts the chain head after a contiguous prefix (seq 0..through_seq).
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub flow_open_id: Vec<u8>,
    pub through_seq: u64,
    pub head: Vec<u8>,
}

impl Checkpoint {
    /// Deterministic-CBOR {1: flow_open_id, 2: through_seq, 3: head}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.flow_open_id.clone())),
            (Value::Uint(2), Value::Uint(self.through_seq)),
            (Value::Uint(3), Value::Bstr(self.head.clone())),
        ]))
        .expect("encode checkpoint")
    }
}

/// The single audited decode path for untrusted Checkpoint wire bytes. It reconstructs the 3-field
/// body (field 3 is a bstr head). It does not range-check through_seq (a full-range counter by the
/// CDDL); the u64::MAX overflow guard lives in verify_checkpoint, where the seq sizes the prefix.
/// Fail-closed on any malformed shape.
pub fn parse_checkpoint(b: &[u8]) -> Result<Checkpoint, cose::Error> {
    let m = decode_map(b)?;
    let flow_open_id = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let through_seq = uint_field(&m, 2).ok_or_else(err_malformed)?;
    let head = bstr_field(&m, 3).ok_or_else(err_malformed)?;
    Ok(Checkpoint {
        flow_open_id,
        through_seq,
        head,
    })
}

/// Confirm the prefix is exactly the contiguous sequence seq 0..through_seq and its recomputed head
/// matches. A dropped/reordered link, wrong count, or wrong head is GapDetected.
pub fn verify_checkpoint(
    cp: &Checkpoint,
    open: &FlowOpen,
    prefix: &[Continuation],
) -> Result<(), cose::Error> {
    if cp.flow_open_id != open.id() {
        return Err(err_wrong_flow());
    }
    // through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq ==
    // u64::MAX that addition overflows (a debug-build panic; a wrap in release) and would false-accept
    // an EMPTY prefix as covering the whole counter space — checked_add rejects it as a gap instead
    // (there can be no u64::MAX+1 contiguous links), matching the Go math.MaxUint64 guard.
    let expected = cp.through_seq.checked_add(1).ok_or_else(err_gap_detected)?;
    if prefix.len() as u64 != expected {
        return Err(err_gap_detected());
    }
    let h = match verify_chain(open, prefix) {
        Ok(h) => h,
        Err(_) => return Err(err_gap_detected()),
    };
    if cp.head != h {
        return Err(err_gap_detected());
    }
    Ok(())
}

// ---- FlowCommit -------------------------------------------------------------------------------

/// Binds a completed flow's final chain head under one full ML-DSA signature.
#[derive(Debug, Clone)]
pub struct FlowCommit {
    pub flow_open_id: Vec<u8>,
    pub final_head: Vec<u8>,
}

impl FlowCommit {
    /// Deterministic-CBOR {1: flow_open_id, 2: final_head} — the 2-field shape distinct from the
    /// 3-field Checkpoint.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.flow_open_id.clone())),
            (Value::Uint(2), Value::Bstr(self.final_head.clone())),
        ]))
        .expect("encode flow commit")
    }
}

// ---- Full-signature helpers (FlowOpen / FlowCommit) -------------------------------------------

pub fn sign_flow_open(o: &FlowOpen, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &o.bytes())
}
pub fn sign_flow_commit(c: &FlowCommit, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &c.bytes())
}

/// Verify the FlowOpen's full signature under the profile, then reconstruct the authority.
pub fn verify_flow_open(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<FlowOpen, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    parse_flow_open(&payload)
}

/// Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head
/// equals the chain recomputed over the delivered continuations.
pub fn verify_flow_commit(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
    open: &FlowOpen,
    conts: &[Continuation],
) -> Result<FlowCommit, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let m = decode_map(&payload)?;
    let flow_open_id = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let final_head = bstr_field(&m, 2).ok_or_else(err_malformed)?;
    let fc = FlowCommit {
        flow_open_id,
        final_head,
    };
    if fc.flow_open_id != open.id() {
        return Err(err_wrong_flow());
    }
    let recomputed = verify_chain(open, conts)?;
    if fc.final_head != recomputed {
        return Err(err_commit_mismatch());
    }
    Ok(fc)
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

fn decode_map(b: &[u8]) -> Result<Vec<(Value, Value)>, cose::Error> {
    match cbor::decode(b).map_err(|_| err_malformed())? {
        Value::Map(m) => Ok(m),
        _ => Err(err_malformed()),
    }
}

fn field(m: &[(Value, Value)], k: u64) -> Option<Value> {
    for (kk, vv) in m {
        if let Value::Uint(n) = kk {
            if *n == k {
                return Some(vv.clone());
            }
        }
    }
    None
}

fn bstr_field(m: &[(Value, Value)], k: u64) -> Option<Vec<u8>> {
    match field(m, k)? {
        Value::Bstr(b) => Some(b),
        _ => None,
    }
}

fn uint_field(m: &[(Value, Value)], k: u64) -> Option<u64> {
    match field(m, k)? {
        Value::Uint(u) => Some(u),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseVerifier;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/continuation/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn open_from(c: &J) -> FlowOpen {
        let approvals = c["flow_open"]["approvals_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| hexd(a.as_str().unwrap()))
            .collect();
        FlowOpen {
            flow_id: hexd(c["flow_open"]["flow_id_hex"].as_str().unwrap()),
            effect_ceiling: c["flow_open"]["effect_ceiling"].as_u64().unwrap(),
            approvals,
        }
    }

    fn conts_from(c: &J) -> Vec<Continuation> {
        let id = hexd(c["flow_open"]["id_hex"].as_str().unwrap());
        c["continuations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cc| Continuation {
                flow_open_id: id.clone(),
                seq: cc["seq"].as_u64().unwrap(),
                effect: cc["effect"].as_u64().unwrap(),
                payload_id: hexd(cc["payload_id_hex"].as_str().unwrap()),
                prev: hexd(cc["prev_hex"].as_str().unwrap()),
            })
            .collect()
    }

    // Byte-parity: Rust encoding == the same non-circular Python oracle, byte-for-byte -> therefore
    // Rust == Go on every wire object.
    #[test]
    fn bodies_match_oracle() {
        let c = load();
        let open = open_from(&c);
        assert_eq!(
            hex::encode(open.bytes()),
            c["flow_open"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(open.head()),
            c["flow_open"]["head_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(open.id()),
            c["flow_open"]["id_hex"].as_str().unwrap()
        );

        let conts = conts_from(&c);
        let arr = c["continuations"].as_array().unwrap();
        for (i, cc) in conts.iter().enumerate() {
            assert_eq!(
                hex::encode(cc.bytes()),
                arr[i]["body_hex"].as_str().unwrap()
            );
            assert_eq!(hex::encode(cc.head()), arr[i]["head_hex"].as_str().unwrap());
        }

        let cp = Checkpoint {
            flow_open_id: open.id(),
            through_seq: c["checkpoint"]["through_seq"].as_u64().unwrap(),
            head: hexd(c["checkpoint"]["head_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(cp.bytes()),
            c["checkpoint"]["body_hex"].as_str().unwrap()
        );

        let fc = FlowCommit {
            flow_open_id: open.id(),
            final_head: hexd(c["flow_commit"]["final_head_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(fc.bytes()),
            c["flow_commit"]["body_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn chain_reaches_final_head() {
        let c = load();
        let open = open_from(&c);
        let conts = conts_from(&c);
        let final_head = verify_chain(&open, &conts).expect("verify chain");
        assert_eq!(
            hex::encode(final_head),
            c["final_head_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn reconstruct_from_bytes_alone() {
        let c = load();
        let open = open_from(&c);
        let got = parse_flow_open(&open.bytes()).expect("parse");
        assert_eq!(got.effect_ceiling, open.effect_ceiling);
        assert_eq!(got.flow_id, open.flow_id);
        assert_eq!(got.approvals, open.approvals);
        assert_eq!(got.id(), open.id());
    }

    #[test]
    fn replay_under_different_flow_fails() {
        let c = load();
        let open_a = open_from(&c);
        let conts = conts_from(&c);
        let ceiling = policy::normalize_effect(open_a.effect_ceiling);
        let b_id = hexd(c["replay"]["flow_open_b_id_hex"].as_str().unwrap());
        let b_head = hexd(c["replay"]["flow_open_b_head_hex"].as_str().unwrap());

        // As delivered: still names flow A -> WrongFlow under B.
        assert_eq!(
            verify_continuation(&conts[0], &b_id, &b_head, 0, ceiling)
                .unwrap_err()
                .kind,
            "WrongFlow"
        );
        // Forged id -> prev no longer chains to B's head -> ChainBroken.
        let forged = Continuation {
            flow_open_id: b_id.clone(),
            seq: conts[0].seq,
            effect: conts[0].effect,
            payload_id: conts[0].payload_id.clone(),
            prev: conts[0].prev.clone(),
        };
        assert_eq!(
            verify_continuation(&forged, &b_id, &b_head, 0, ceiling)
                .unwrap_err()
                .kind,
            "ChainBroken"
        );
        // Positive control under FlowOpen A.
        verify_continuation(&conts[0], &open_a.id(), &open_a.head(), 0, ceiling).expect("under A");
    }

    #[test]
    fn above_ceiling_rejected() {
        let c = load();
        let open = open_from(&c);
        let ceiling = policy::normalize_effect(open.effect_ceiling);
        let above = Continuation {
            flow_open_id: open.id(),
            seq: c["above_ceiling"]["seq"].as_u64().unwrap(),
            effect: c["above_ceiling"]["effect"].as_u64().unwrap(),
            payload_id: hexd(c["above_ceiling"]["payload_id_hex"].as_str().unwrap()),
            prev: hexd(c["above_ceiling"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(above.bytes()),
            c["above_ceiling"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            verify_continuation(&above, &open.id(), &above.prev, above.seq, ceiling)
                .unwrap_err()
                .kind,
            "AboveCeiling"
        );
        // Within-ceiling positive control.
        let ok = Continuation {
            flow_open_id: open.id(),
            seq: above.seq,
            effect: policy::NON_IDEMPOTENT_WRITE as u64,
            payload_id: above.payload_id.clone(),
            prev: above.prev.clone(),
        };
        verify_continuation(&ok, &open.id(), &ok.prev, ok.seq, ceiling).expect("within ceiling");
    }

    #[test]
    fn checkpoint_detects_gap() {
        let c = load();
        let open = open_from(&c);
        let conts = conts_from(&c);
        let through = c["checkpoint"]["through_seq"].as_u64().unwrap();

        let cp = Checkpoint {
            flow_open_id: open.id(),
            through_seq: through,
            head: hexd(c["checkpoint"]["head_hex"].as_str().unwrap()),
        };
        verify_checkpoint(&cp, &open, &conts[..=(through as usize)]).expect("honest checkpoint");

        // Gap: claim through_seq 2 but deliver only [seq0, seq2].
        let gap_prefix = vec![
            Continuation {
                flow_open_id: conts[0].flow_open_id.clone(),
                seq: conts[0].seq,
                effect: conts[0].effect,
                payload_id: conts[0].payload_id.clone(),
                prev: conts[0].prev.clone(),
            },
            Continuation {
                flow_open_id: conts[2].flow_open_id.clone(),
                seq: conts[2].seq,
                effect: conts[2].effect,
                payload_id: conts[2].payload_id.clone(),
                prev: conts[2].prev.clone(),
            },
        ];
        let gap_cp = Checkpoint {
            flow_open_id: open.id(),
            through_seq: c["gap"]["through_seq"].as_u64().unwrap(),
            head: hexd(c["final_head_hex"].as_str().unwrap()),
        };
        assert_eq!(
            verify_checkpoint(&gap_cp, &open, &gap_prefix)
                .unwrap_err()
                .kind,
            "GapDetected"
        );

        // Tampered head -> GapDetected.
        let mut bad_head = hexd(c["checkpoint"]["head_hex"].as_str().unwrap());
        bad_head[0] ^= 0x01;
        let bad = Checkpoint {
            flow_open_id: open.id(),
            through_seq: through,
            head: bad_head,
        };
        assert_eq!(
            verify_checkpoint(&bad, &open, &conts[..=(through as usize)])
                .unwrap_err()
                .kind,
            "GapDetected"
        );
    }

    #[test]
    fn flow_commit_full_signature() {
        let c = load();
        let open = open_from(&c);
        let conts = conts_from(&c);
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let (fpk, _fsk) = cose::mldsa65_keypair_from_seed(&[0x22; 32]);
        let v = cose::MlDsa65Verifier(pk);
        let foreign = cose::MlDsa65Verifier(fpk);
        let s = cose::MlDsa65Signer(sk);

        let fc = FlowCommit {
            flow_open_id: open.id(),
            final_head: hexd(c["final_head_hex"].as_str().unwrap()),
        };
        let obj = sign_flow_commit(&fc, &s);
        verify_flow_commit(&obj, cose::PROFILE_PUBLIC, &v, &open, &conts).expect("honest commit");
        assert_eq!(
            verify_flow_commit(&obj, cose::PROFILE_PUBLIC, &foreign, &open, &conts)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        assert_eq!(
            verify_flow_commit(&obj, cose::PROFILE_PUBLIC, &v, &open, &conts[..2])
                .unwrap_err()
                .kind,
            "CommitMismatch"
        );
    }

    // Cross-language signature bit-identity: signing the FlowOpen with the shared 0x11*32 seed must
    // produce a COSE_Sign1 object whose SHA-384 equals the value the Go continuation test pins — i.e.
    // Go and Rust emit byte-identical signed FlowOpens (deterministic ML-DSA-65 over identical
    // canonical CBOR), so each accepts the other's objects. Mutation: any encoding/signing-input
    // drift makes the digest differ from the pin.
    #[test]
    fn cross_lang_signed_open_pin() {
        const PINNED: &str =
            "13d7ab1f7d96ddb79df596eaff2ec423d9d2fbe5aab4a88d1052fb7ccf36cceb07b7706d8b231dab7efd695aa5892e6a";
        let c = load();
        let open = open_from(&c);
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let obj = sign_flow_open(&open, &s);
        let digest = hex::encode(Sha384::digest(&obj));
        assert_eq!(
            digest, PINNED,
            "Rust signed FlowOpen digest differs from the Go pin (sig not byte-identical)"
        );
    }

    // C17 audit-fix 0a: effect_ceiling and a continuation effect are the CLOSED lattice (0..3); an
    // out-of-lattice value (4) is RangeError, never normalized to destructive. Byte-parity of the
    // forbidden bodies against the oracle proves Go == Rust == oracle on the reject case too.
    #[test]
    fn ceiling_out_of_lattice_rejected() {
        let c = load();
        let bad = c["range_reject"]["out_of_lattice_value"].as_u64().unwrap();
        assert!(bad > policy::DESTRUCTIVE as u64);
        let open = open_from(&c);

        let bad_open = FlowOpen {
            flow_id: open.flow_id.clone(),
            effect_ceiling: bad,
            approvals: open.approvals.clone(),
        };
        assert_eq!(
            hex::encode(bad_open.bytes()),
            c["range_reject"]["flow_open_ceiling_body_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            parse_flow_open(&bad_open.bytes()).unwrap_err().kind,
            "RangeError"
        );
        assert_eq!(verify_chain(&bad_open, &[]).unwrap_err().kind, "RangeError");

        let pid = content_id(b"step-0");
        let bad_cont = Continuation {
            flow_open_id: open.id(),
            seq: 0,
            effect: bad,
            payload_id: pid.clone(),
            prev: open.head(),
        };
        assert_eq!(
            hex::encode(bad_cont.bytes()),
            c["range_reject"]["continuation_effect_body_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            parse_continuation(&bad_cont.bytes()).unwrap_err().kind,
            "RangeError"
        );
        assert_eq!(
            verify_continuation(&bad_cont, &open.id(), &open.head(), 0, policy::DESTRUCTIVE)
                .unwrap_err()
                .kind,
            "RangeError"
        );
        // An out-of-lattice CEILING passed to verify_continuation is also RangeError.
        let ok_cont = Continuation {
            flow_open_id: open.id(),
            seq: 0,
            effect: 0,
            payload_id: pid,
            prev: open.head(),
        };
        assert_eq!(
            verify_continuation(&ok_cont, &open.id(), &open.head(), 0, bad as u8)
                .unwrap_err()
                .kind,
            "RangeError"
        );
    }

    // C17 audit-fix 0c: through_seq = u64::MAX overflows through_seq+1; verify_checkpoint rejects it
    // GapDetected (checked_add), and parse_checkpoint round-trips the >2^64 counter byte-exact.
    #[test]
    fn checkpoint_overflow_rejected() {
        let c = load();
        let open = open_from(&c);
        let through: u64 = c["checkpoint_overflow"]["through_seq_str"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(through, u64::MAX);
        let cp = Checkpoint {
            flow_open_id: open.id(),
            through_seq: through,
            head: hexd(c["checkpoint_overflow"]["head_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(cp.bytes()),
            c["checkpoint_overflow"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            verify_checkpoint(&cp, &open, &[]).unwrap_err().kind,
            "GapDetected"
        );
        let got = parse_checkpoint(&cp.bytes()).expect("parse overflow checkpoint");
        assert_eq!(got.through_seq, u64::MAX, "through_seq counter corrupted");
    }

    // C17 audit-fix 0e: parse_continuation is the single audited decode path; it round-trips a
    // well-formed body byte-exact (the effect=4 reject is covered above).
    #[test]
    fn parse_continuation_audited() {
        let c = load();
        for cc in conts_from(&c) {
            let got = parse_continuation(&cc.bytes()).expect("parse continuation");
            assert_eq!(
                got.bytes(),
                cc.bytes(),
                "parse_continuation did not round-trip byte-exact"
            );
        }
    }

    // Phase 6 edge case #3 (the >2^53 discipline): a continuation seq above 2^53 round-trips
    // byte-exact (u64 all the way). The oracle carries seq as a STRING; parse it with a u64 parser.
    #[test]
    fn oversized_seq_round_trip() {
        let c = load();
        let seq: u64 = c["big_seq"]["seq_str"].as_str().unwrap().parse().unwrap();
        assert!(seq > (1 << 53));
        let open = open_from(&c);
        let cc = Continuation {
            flow_open_id: open.id(),
            seq,
            effect: c["big_seq"]["effect"].as_u64().unwrap(),
            payload_id: hexd(c["big_seq"]["payload_id_hex"].as_str().unwrap()),
            prev: hexd(c["big_seq"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(cc.bytes()),
            c["big_seq"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(cc.head()),
            c["big_seq"]["head_hex"].as_str().unwrap()
        );
        let got = parse_continuation(&cc.bytes()).expect("parse big-seq");
        assert_eq!(got.seq, seq, ">2^53 seq corrupted on round-trip");
    }

    // Phase 6 edge case #4: the smallest valid FlowOpen encodes, has a stable id, and round-trips.
    #[test]
    fn minimal_flow_open() {
        let c = load();
        let apps: Vec<Vec<u8>> = c["minimal"]["approvals_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| hexd(a.as_str().unwrap()))
            .collect();
        let m = FlowOpen {
            flow_id: hexd(c["minimal"]["flow_id_hex"].as_str().unwrap()),
            effect_ceiling: c["minimal"]["effect_ceiling"].as_u64().unwrap(),
            approvals: apps,
        };
        assert_eq!(
            hex::encode(m.bytes()),
            c["minimal"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(m.head()),
            c["minimal"]["head_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(m.id()),
            c["minimal"]["id_hex"].as_str().unwrap()
        );
        let got = parse_flow_open(&m.bytes()).expect("parse minimal");
        assert_eq!(got.id(), m.id());
    }

    // Phase 6 edge case #2: an empty approvals[] is distinct on the wire and by content-id.
    #[test]
    fn empty_vs_nonempty_approvals() {
        let c = load();
        let fid = hexd(c["flow_open"]["flow_id_hex"].as_str().unwrap());
        let ceil = c["flow_open"]["effect_ceiling"].as_u64().unwrap();
        let empty = FlowOpen {
            flow_id: fid.clone(),
            effect_ceiling: ceil,
            approvals: vec![],
        };
        let one = FlowOpen {
            flow_id: fid,
            effect_ceiling: ceil,
            approvals: vec![hexd(c["flow_open"]["approvals_hex"][0].as_str().unwrap())],
        };
        assert_eq!(
            hex::encode(empty.bytes()),
            c["empty_vs_nonempty"]["empty_approvals"]["body_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(one.bytes()),
            c["empty_vs_nonempty"]["one_approval"]["body_hex"]
                .as_str()
                .unwrap()
        );
        assert_ne!(
            empty.id(),
            one.id(),
            "empty vs one-approval must differ by content-id"
        );
        assert_eq!(
            hex::encode(empty.id()),
            c["empty_vs_nonempty"]["empty_approvals"]["id_hex"]
                .as_str()
                .unwrap()
        );
    }

    // Phase 6 edge case #1: keys in descending order are rejected NonCanonical by the strict codec.
    #[test]
    fn keys_out_of_order_rejected() {
        let c = load();
        let canon = hexd(
            c["keys_out_of_order"]["canonical_commit_body_hex"]
                .as_str()
                .unwrap(),
        );
        let noncanon = hexd(
            c["keys_out_of_order"]["noncanonical_commit_body_hex"]
                .as_str()
                .unwrap(),
        );
        let open = open_from(&c);
        let fc = FlowCommit {
            flow_open_id: open.id(),
            final_head: hexd(c["final_head_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(fc.bytes()),
            c["keys_out_of_order"]["canonical_commit_body_hex"]
                .as_str()
                .unwrap()
        );
        assert!(
            cbor::decode(&canon).is_ok(),
            "canonical commit body should decode"
        );
        match cbor::decode(&noncanon) {
            Err(e) => assert_eq!(e.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key body accepted"),
        }
    }

    // Phase 6 edge case #5: a 2-field FlowCommit body fed to a sibling parser is rejected.
    #[test]
    fn look_alike_rejected_by_sibling() {
        let c = load();
        let commit_body = hexd(c["look_alike"]["flow_commit_body_hex"].as_str().unwrap());
        assert_eq!(
            parse_checkpoint(&commit_body).unwrap_err().kind,
            "ContMalformed"
        );
        assert_eq!(
            parse_continuation(&commit_body).unwrap_err().kind,
            "ContMalformed"
        );
    }

    #[test]
    fn flow_open_full_signature_and_determinism() {
        let c = load();
        let open = open_from(&c);
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let (fpk, _fsk) = cose::mldsa65_keypair_from_seed(&[0x22; 32]);
        let v = cose::MlDsa65Verifier(pk);
        let foreign = cose::MlDsa65Verifier(fpk);
        let s = cose::MlDsa65Signer(sk);

        let obj1 = sign_flow_open(&open, &s);
        let obj2 = sign_flow_open(&open, &s);
        assert_eq!(obj1, obj2, "deterministic ML-DSA signing");
        let got = verify_flow_open(&obj1, cose::PROFILE_PUBLIC, &v).expect("verify open");
        assert_eq!(got.effect_ceiling, open.effect_ceiling);
        assert_eq!(got.id(), open.id());
        assert_eq!(
            verify_flow_open(&obj1, cose::PROFILE_PUBLIC, &foreign)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        // silence unused-import warning for verify_raw scope on some builds
        let _ = v.verify_raw(&open.bytes(), &obj1);
    }
}
