// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C21 task 5B.2 — NAALP-AGUI UI-consent binding (design.md §24; R-AGUI-1..6). The Rust half of the
//! two-implementation parity; byte-identical to impl/go/agui.
//!
//! NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
//! tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
//! RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
//! mechanism (R-11.3): a UI event is an ordinary COSE_Sign1 over a deterministic-CBOR body, reusing
//! the C7 audit receipt-chain construction (§8.1) — head = SHA-384(body), genesis prev = 48 zero
//! bytes, monotonic seq, prior head in `prev` — and the §7 approval binding UNCHANGED.
//!
//!   - `UIEvent` {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
//!     `kind` is a closed set; `action` is the T1 content id of the action bytes shown.
//!
//! Load-bearing: `verify_consent` walks the shown chain (a hole is UIChainBroken, with `detect_hole`
//! reporting its position), takes the shown-and-approved action content id, requires the §7 approval to
//! bind it, and requires the action actually executed to hash to it — a SUBSTITUTED action has a
//! different content id and is rejected (ActionSubstituted). Fail-closed (§15).

use sha2::{Digest, Sha384};

use crate::approval;
use crate::cbor::{self, Value};
use crate::cose;

/// Width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.
pub const HEAD_SIZE: usize = 48;

/// UI event kinds — the closed AG-UI tool-lifecycle set transcribed to the spine.
pub const KIND_SHOWN: u64 = 0; // the action / tool call was shown (rendered) to the user
pub const KIND_ARGS_SHOWN: u64 = 1; // the arguments were shown to the user
pub const KIND_APPROVED: u64 = 2; // the user approved the shown action
pub const KIND_REJECTED: u64 = 3; // the user rejected the shown action

/// The kind name, or "unknown".
pub fn kind_name(code: u64) -> &'static str {
    match code {
        KIND_SHOWN => "shown",
        KIND_ARGS_SHOWN => "args-shown",
        KIND_APPROVED => "approved",
        KIND_REJECTED => "rejected",
        _ => "unknown",
    }
}

/// Whether `code` is one of the closed UI-event kinds.
pub fn is_known_kind(code: u64) -> bool {
    matches!(
        code,
        KIND_SHOWN | KIND_ARGS_SHOWN | KIND_APPROVED | KIND_REJECTED
    )
}

pub fn err_malformed() -> cose::Error {
    cose::Error {
        kind: "UIMalformed",
        msg: "object is not a well-formed N-AALP ui-event body",
    }
}
pub fn err_ui_chain_broken() -> cose::Error {
    cose::Error {
        kind: "UIChainBroken",
        msg: "ui-event prev/seq does not chain to the previous event (a gap, reorder, or omitted shown-event)",
    }
}
pub fn err_unknown_event_kind() -> cose::Error {
    cose::Error {
        kind: "UnknownUIEventKind",
        msg: "ui-event kind is outside the closed set shown/args-shown/approved/rejected",
    }
}
pub fn err_action_substituted() -> cose::Error {
    cose::Error {
        kind: "ActionSubstituted",
        msg:
            "the action being executed is not the exact action shown and approved in the UI stream",
    }
}
pub fn err_no_consent() -> cose::Error {
    cose::Error {
        kind: "UINoConsent",
        msg: "the shown chain carries no approved event — there is no human consent to bind",
    }
}

/// A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).
pub fn genesis() -> Vec<u8> {
    vec![0u8; HEAD_SIZE]
}

/// SHA-384 over a body — a 48-octet digest.
fn head(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

/// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
fn content_id_impl(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x20u8, 0x30u8];
    v.extend_from_slice(&head(b));
    v
}

/// The T1 content id of arbitrary ACTION bytes — what a UI event names and a human approval binds.
pub fn content_id(b: &[u8]) -> Vec<u8> {
    content_id_impl(b)
}

/// One shown tool-lifecycle event, chained onto the prior event by `prev`/`seq`.
#[derive(Debug, Clone)]
pub struct UIEvent {
    pub session: Vec<u8>,
    pub kind: u64,
    pub action: Vec<u8>, // content id of the exact action bytes shown at this step
    pub seq: u64,
    pub prev: Vec<u8>, // the prior event's head (HEAD_SIZE bytes; genesis is zero)
}

impl UIEvent {
    /// Deterministic-CBOR {1: session, 2: kind, 3: action, 4: seq, 5: prev}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.session.clone())),
            (Value::Uint(2), Value::Uint(self.kind)),
            (Value::Uint(3), Value::Bstr(self.action.clone())),
            (Value::Uint(4), Value::Uint(self.seq)),
            (Value::Uint(5), Value::Bstr(self.prev.clone())),
        ]))
        .expect("encode ui event")
    }
    /// The chain head after this event: SHA-384 of the body (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id_impl(&self.bytes())
    }
}

/// Reconstruct a UIEvent from its body bytes alone.
pub fn parse_ui_event(b: &[u8]) -> Result<UIEvent, cose::Error> {
    let m = decode_map(b)?;
    let session = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let kind = uint_field(&m, 2).ok_or_else(err_malformed)?;
    let action = bstr_field(&m, 3).ok_or_else(err_malformed)?;
    let seq = uint_field(&m, 4).ok_or_else(err_malformed)?;
    let prev = bstr_field(&m, 5).ok_or_else(err_malformed)?;
    Ok(UIEvent {
        session,
        kind,
        action,
        seq,
        prev,
    })
}

/// Produce the tagged COSE_Sign1 object over the event body.
pub fn sign_ui_event(e: &UIEvent, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &e.bytes())
}

/// Verify the event's signature under the profile, reconstruct it, and validate the kind against the
/// closed set (UnknownUIEventKind). A bad signature propagates (BadSignature). Fail-closed.
pub fn verify_ui_event(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<UIEvent, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let e = parse_ui_event(&payload)?;
    if !is_known_kind(e.kind) {
        return Err(err_unknown_event_kind());
    }
    Ok(e)
}

/// One step of a walked shown chain.
#[derive(Debug, Clone)]
pub struct ShownEvent {
    pub seq: u64,
    pub kind: u64,
    pub action: Vec<u8>,
    pub head: Vec<u8>,
}

/// Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered
/// shown events. Every event names the SAME session, seq i equals its index, the kind is in the closed
/// set, and prev links to the previous event's head (genesis for seq 0). A gap/reorder/omission or a
/// session change is UIChainBroken; an unknown kind is UnknownUIEventKind. Fail-closed.
pub fn walk_shown(events: &[UIEvent]) -> Result<Vec<ShownEvent>, cose::Error> {
    let mut out = Vec::with_capacity(events.len());
    let mut h = genesis();
    let mut session: Option<Vec<u8>> = None;
    for (i, e) in events.iter().enumerate() {
        match &session {
            None => session = Some(e.session.clone()),
            Some(s) if *s != e.session => return Err(err_ui_chain_broken()),
            _ => {}
        }
        if !is_known_kind(e.kind) {
            return Err(err_unknown_event_kind());
        }
        if e.seq != i as u64 || e.prev != h {
            return Err(err_ui_chain_broken());
        }
        h = e.head();
        out.push(ShownEvent {
            seq: e.seq,
            kind: e.kind,
            action: e.action.clone(),
            head: h.clone(),
        });
    }
    Ok(out)
}

/// Verify a UI event chain offline against the UI authority's key: verify every signature, then
/// enforce the same structural continuity as `walk_shown`. Fail-closed.
pub fn verify_shown_chain(
    objs: &[Vec<u8>],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Vec<UIEvent>, cose::Error> {
    let mut h = genesis();
    let mut session: Option<Vec<u8>> = None;
    let mut out = Vec::with_capacity(objs.len());
    for (i, obj) in objs.iter().enumerate() {
        let e = verify_ui_event(obj, profile, v)?;
        match &session {
            None => session = Some(e.session.clone()),
            Some(s) if *s != e.session => return Err(err_ui_chain_broken()),
            _ => {}
        }
        if e.seq != i as u64 || e.prev != h {
            return Err(err_ui_chain_broken());
        }
        h = e.head();
        out.push(e);
    }
    Ok(out)
}

/// Report whether a presented (possibly gappy) event list breaks contiguity — a deleted/omitted
/// shown-event — and, if so, the FIRST-BROKEN POSITION. A contiguous list returns None.
pub fn detect_hole(events: &[UIEvent]) -> Option<usize> {
    let mut h = genesis();
    for (i, e) in events.iter().enumerate() {
        if e.seq != i as u64 || e.prev != h {
            return Some(i);
        }
        h = e.head();
    }
    None
}

/// The content id of the action shown-and-approved in a walked chain, if any.
pub fn approved_action_cid(shown: &[ShownEvent]) -> Option<Vec<u8>> {
    shown
        .iter()
        .find(|ev| ev.kind == KIND_APPROVED)
        .map(|ev| ev.action.clone())
}

/// Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. Walk the shown
/// chain (UIChainBroken on a gap), take the shown-and-approved action content id (UINoConsent if none),
/// verify the §7 approval binds it (ApprovalMismatch / ApprovalExpired / BadSignature), and require the
/// action actually executed to hash to it (ActionSubstituted otherwise). Fail-closed.
pub fn verify_consent(
    chain: &[UIEvent],
    action_bytes: &[u8],
    appr: &approval::ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    appr_sig: &[u8],
    now: u64,
) -> Result<(), cose::Error> {
    let shown = walk_shown(chain)?;
    let shown_cid = approved_action_cid(&shown).ok_or_else(err_no_consent)?;
    // the human approval must be a valid signature binding the shown-and-approved action content id.
    approval::verify_approval(appr, approver_v, appr_sig, &shown_cid, now)?;
    // the action actually being executed MUST be the exact one shown and approved.
    if content_id_impl(action_bytes) != shown_cid {
        return Err(err_action_substituted());
    }
    Ok(())
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
    use crate::policy;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/agui/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }
    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk))
    }
    fn events_from(c: &J) -> Vec<UIEvent> {
        let session = hexd(c["session_hex"].as_str().unwrap());
        c["chain"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ev| UIEvent {
                session: session.clone(),
                kind: ev["kind"].as_u64().unwrap(),
                action: hexd(ev["action_hex"].as_str().unwrap()),
                seq: ev["seq"].as_u64().unwrap(),
                prev: hexd(ev["prev_hex"].as_str().unwrap()),
            })
            .collect()
    }
    fn mk_approval(action_cid: &[u8], nonce: u8, not_after: u64) -> approval::ApprovalRecord {
        approval::ApprovalRecord {
            approves: action_cid.to_vec(),
            approver: "human-approver".into(),
            grant: policy::NON_IDEMPOTENT_WRITE as u64,
            nonce: vec![nonce; 16],
            not_after,
            audience: String::new(),
        }
    }

    // Byte-parity: Rust encoding == oracle -> Rust == Go on every event body/head/id + action cid.
    #[test]
    fn bodies_match_oracle() {
        let c = load();
        let events = events_from(&c);
        for (i, ev) in events.iter().enumerate() {
            let want = &c["chain"]["events"][i];
            assert_eq!(
                hex::encode(ev.bytes()),
                want["body_hex"].as_str().unwrap(),
                "event {i} body"
            );
            assert_eq!(
                hex::encode(ev.head()),
                want["head_hex"].as_str().unwrap(),
                "event {i} head"
            );
            assert_eq!(
                hex::encode(ev.id()),
                want["id_hex"].as_str().unwrap(),
                "event {i} id"
            );
        }
        assert_eq!(
            hex::encode(content_id(&hexd(c["action_bytes_hex"].as_str().unwrap()))),
            c["action_cid_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(content_id(&hexd(
                c["substituted_bytes_hex"].as_str().unwrap()
            ))),
            c["substituted_cid_hex"].as_str().unwrap()
        );
        for e in c["kind_vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            assert!(is_known_kind(code));
            assert_eq!(kind_name(code), e["name"].as_str().unwrap());
        }
        assert!(!is_known_kind(c["unknown_kind"].as_u64().unwrap()));
    }

    // The C21 UI checkpoint: consent binds the exact shown action; the chain is receipt-verifiable; an
    // omitted shown-event is a detectable hole with position.
    #[test]
    fn consent_binds_exact_shown_action() {
        let c = load();
        let (ui_s, ui_v) = key(0x31);
        let (human_s, human_v) = key(0x32);
        let (_, foreign_v) = key(0x42);
        let events = events_from(&c);
        let action_bytes = hexd(c["action_bytes_hex"].as_str().unwrap());
        let action_cid = content_id(&action_bytes);
        let not_after: u64 = 1785000000000;
        let appr = mk_approval(&action_cid, 0x01, not_after);
        let appr_sig = approval::sign_approval(&appr, &human_s);

        // The shown chain verifies and its final head matches the oracle.
        let objs: Vec<Vec<u8>> = events.iter().map(|e| sign_ui_event(e, &ui_s)).collect();
        let verified =
            verify_shown_chain(&objs, cose::PROFILE_PUBLIC, &ui_v).expect("verify chain");
        assert_eq!(verified.len(), 3);
        let shown = walk_shown(&events).expect("walk");
        assert_eq!(
            hex::encode(&shown.last().unwrap().head),
            c["chain"]["final_head_hex"].as_str().unwrap()
        );
        assert_eq!(approved_action_cid(&shown).unwrap(), action_cid);

        // Honest consent verifies; a substituted action is rejected.
        verify_consent(
            &events,
            &action_bytes,
            &appr,
            &human_v,
            &appr_sig,
            not_after,
        )
        .expect("honest consent");
        let substituted = hexd(c["substituted_bytes_hex"].as_str().unwrap());
        assert_eq!(
            verify_consent(&events, &substituted, &appr, &human_v, &appr_sig, not_after)
                .unwrap_err()
                .kind,
            "ActionSubstituted"
        );
        // Foreign key -> BadSignature; expired -> ApprovalExpired; no approved event -> UINoConsent.
        assert_eq!(
            verify_consent(
                &events,
                &action_bytes,
                &appr,
                &foreign_v,
                &appr_sig,
                not_after
            )
            .unwrap_err()
            .kind,
            "BadSignature"
        );
        assert_eq!(
            verify_consent(
                &events,
                &action_bytes,
                &appr,
                &human_v,
                &appr_sig,
                not_after + 1
            )
            .unwrap_err()
            .kind,
            "ApprovalExpired"
        );
        assert_eq!(
            verify_consent(
                &events[..2],
                &action_bytes,
                &appr,
                &human_v,
                &appr_sig,
                not_after
            )
            .unwrap_err()
            .kind,
            "UINoConsent"
        );

        // An omitted shown-event is detected with its position; consent over the gappy chain refuses.
        let gappy = vec![events[0].clone(), events[2].clone()];
        assert_eq!(
            detect_hole(&gappy),
            Some(c["hole"]["position"].as_u64().unwrap() as usize)
        );
        assert_eq!(walk_shown(&gappy).unwrap_err().kind, "UIChainBroken");
        assert_eq!(
            verify_consent(&gappy, &action_bytes, &appr, &human_v, &appr_sig, not_after)
                .unwrap_err()
                .kind,
            "UIChainBroken"
        );
    }

    // REQUIRED checkpoint mutation (b): a UI profile that accepts an approval for a SUBSTITUTED action
    // fails. The honest verify_consent ties the executed bytes to the shown+approved content id; a
    // MUTANT that drops that tie wrongly accepts the substituted action.
    #[test]
    fn ui_substituted_action_mutation() {
        let c = load();
        let (human_s, human_v) = key(0x32);
        let events = events_from(&c);
        let action_cid = content_id(&hexd(c["action_bytes_hex"].as_str().unwrap()));
        let substituted = hexd(c["substituted_bytes_hex"].as_str().unwrap());
        let not_after: u64 = 1785000000000;
        let appr = mk_approval(&action_cid, 0x01, not_after);
        let appr_sig = approval::sign_approval(&appr, &human_s);

        // Honest: substituted action rejected.
        assert_eq!(
            verify_consent(&events, &substituted, &appr, &human_v, &appr_sig, not_after)
                .unwrap_err()
                .kind,
            "ActionSubstituted"
        );

        // Mutant: checks only that the human approved the SHOWN action, never that the executed action
        // equals it — wrongly accepts the substitution.
        let mutant = |chain: &[UIEvent], _action_bytes: &[u8]| -> Result<(), cose::Error> {
            let shown = walk_shown(chain)?;
            let shown_cid = approved_action_cid(&shown).ok_or_else(err_no_consent)?;
            approval::verify_approval(&appr, &human_v, &appr_sig, &shown_cid, not_after)
        };
        mutant(&events, &substituted).expect("mutant must reproduce the substitution bug");
    }

    // Cross-language pin: the signed approved UI event digest matches the Go pin.
    #[test]
    fn cross_lang_signed_ui_event_pin() {
        const PIN: &str = "30dcd1991bb850c630293b32a99ece28806fa7e552176231716f13b16f3f9c89bb48b7fe64bb5edeaf447971e300ee84";
        let c = load();
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let events = events_from(&c);
        let obj = sign_ui_event(&events[2], &s); // the approved event
        assert_eq!(
            hex::encode(Sha384::digest(&obj)),
            PIN,
            "signed ui-event digest differs from the Go pin"
        );
    }

    #[test]
    fn malformed_rejected() {
        assert_eq!(parse_ui_event(&[0x00]).unwrap_err().kind, "UIMalformed");
    }

    // Phase 6 edge case #3 (the >2^53 discipline): a ui-event seq above 2^53 round-trips byte-exact
    // (u64, no float64). Carried as a JSON string, parsed with u64.
    #[test]
    fn oversized_seq_round_trip() {
        let c = load();
        let seq: u64 = c["big_seq"]["seq_str"].as_str().unwrap().parse().unwrap();
        assert!(seq > (1 << 53));
        let e = UIEvent {
            session: hexd(c["session_hex"].as_str().unwrap()),
            kind: c["big_seq"]["kind"].as_u64().unwrap(),
            action: hexd(c["big_seq"]["action_hex"].as_str().unwrap()),
            seq,
            prev: hexd(c["big_seq"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(e.bytes()),
            c["big_seq"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            parse_ui_event(&e.bytes()).expect("parse").seq,
            seq,
            ">2^53 ui-event seq corrupted"
        );
    }

    // Phase 6 edge case #4: the smallest valid ui-event encodes, reconstructs, and has a stable id.
    #[test]
    fn minimal_event() {
        let c = load();
        let e = UIEvent {
            session: hexd(c["minimal"]["session_hex"].as_str().unwrap()),
            kind: c["minimal"]["kind"].as_u64().unwrap(),
            action: hexd(c["minimal"]["action_hex"].as_str().unwrap()),
            seq: c["minimal"]["seq"].as_u64().unwrap(),
            prev: hexd(c["minimal"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(e.bytes()),
            c["minimal"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(e.id()),
            c["minimal"]["id_hex"].as_str().unwrap()
        );
        parse_ui_event(&e.bytes()).expect("parse minimal");
    }

    // ---- standard wire-format edge cases (Part 1) --------------------------------------------

    // Edge case #1: a ui-event body with top-level keys DESCENDING (5,4,3,2,1) is rejected NonCanonical
    // by the strict shared decoder parse_ui_event routes through; the canonical body parses.
    #[test]
    fn keys_out_of_order_rejected() {
        let c = load();
        let e = &c["edge_cases"]["keys_out_of_order"];
        let ev = UIEvent {
            session: hexd(c["session_hex"].as_str().unwrap()),
            kind: KIND_SHOWN,
            action: hexd(e["action_hex"].as_str().unwrap()),
            seq: 0,
            prev: hexd(c["genesis_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(ev.bytes()),
            e["canonical_body_hex"].as_str().unwrap(),
            "canonical ui-event body"
        );
        let canon = hexd(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical body should decode");
        parse_ui_event(&canon).expect("canonical body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key ui-event body decoded (want NonCanonical)"),
        }
        assert_eq!(parse_ui_event(&noncanon).unwrap_err().kind, "UIMalformed");
    }

    // Edge case #2 (action field): an empty action is distinct by content-id from a populated one; both
    // differ from a body whose action field is ABSENT (rejected UIMalformed — field 3 is mandatory).
    #[test]
    fn empty_vs_absent_action() {
        let c = load();
        let ea = &c["edge_cases"]["empty_vs_absent"];
        let session = hexd(c["session_hex"].as_str().unwrap());
        let prev = hexd(c["genesis_hex"].as_str().unwrap());
        let empty = UIEvent {
            session: session.clone(),
            kind: KIND_SHOWN,
            action: vec![],
            seq: 0,
            prev: prev.clone(),
        };
        let populated = UIEvent {
            session,
            kind: KIND_SHOWN,
            action: hexd(ea["populated_action"]["action_hex"].as_str().unwrap()),
            seq: 0,
            prev,
        };
        assert_eq!(
            hex::encode(empty.bytes()),
            ea["empty_action"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(populated.bytes()),
            ea["populated_action"]["body_hex"].as_str().unwrap()
        );
        assert_ne!(
            empty.id(),
            populated.id(),
            "empty vs populated action must differ by content-id"
        );
        assert_eq!(
            hex::encode(empty.id()),
            ea["empty_action"]["id_hex"].as_str().unwrap()
        );
        parse_ui_event(&empty.bytes()).expect("empty action parses");
        parse_ui_event(&populated.bytes()).expect("populated action parses");
        assert_eq!(
            parse_ui_event(&hexd(ea["absent_field"]["body_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "UIMalformed"
        );
    }

    // Edge case #5: NAALP-AGUI defines a single body kind, so the look-alike is a near-miss — a
    // ui-event-shaped body lacking its field-5 chain back-pointer (prev), rejected UIMalformed.
    #[test]
    fn look_alike_rejected() {
        let c = load();
        let body = hexd(c["edge_cases"]["look_alike"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_ui_event(&body).unwrap_err().kind, "UIMalformed");
    }
}
