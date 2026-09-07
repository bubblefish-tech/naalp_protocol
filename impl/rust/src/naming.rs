// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C19 — name bindings and the signed A2A task-state profile (design.md §22; R-NAME-1..6,
//! R-A2A-1..7). The Rust half of the two-implementation parity; byte-identical to impl/go/naming.
//!
//! C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
//! object, both reusing the C7 audit receipt-chain construction (§8.1) unchanged — head =
//! SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body
//! so editing/omitting a record breaks the next record's linkage — and adding NO new envelope,
//! encoding, signature, identity, or audit mechanism (R-11.3).
//!
//! Task 4.1 — name bindings: a `NameBinding` {1: name, 2: signer, 3: seq, 4: prev} maps a name to a
//! signer id and CHAINS onto the prior binding for that name. A key ROTATION is a new binding at the
//! next seq naming the new signer. A binding is DATED BY its chain position (seq); the envelope's
//! `created` field is advisory only (§2.4). A name's history is WALKABLE offline (`walk_history`
//! returns the signer succession); a deleted binding leaves a detectable HOLE at the first-broken
//! position (`detect_hole`); two bindings by one authority at the same (name, seq) naming different
//! signers are a FORK reported at that seq (`detect_fork` / `NameForkProof`).
//!
//! Task 4.2 — the signed A2A task-state profile: `TaskState` is the imported A2A (Agent2Agent)
//! TaskState vocabulary (carriage, not adoption): submitted, working, input-required, auth-required,
//! completed, canceled, failed, rejected. The A2A spec (§4.1.3) defines the state set and the
//! terminal/interrupted categories normatively (start = submitted; terminal =
//! completed/canceled/failed/rejected; interrupted = input-required/auth-required); the legal-edge
//! table is derived from those category rules. A `Transition` {1: task, 2: card, 3: from, 4: to,
//! 5: seq, 6: prev} is one receipt-CHAINED signed state transition. `verify_transition` rejects an
//! illegal edge; `verify_task_chain` walks a task's transition chain enforcing the start state,
//! contiguity, the legal-edge table, the terminal-cannot-continue rule, prev/seq linkage, the card
//! binding, and the signatures. `card` is the content-id of the A2A Agent Card attestation (a C18
//! naalp-description-import) binding the profile to an agent/operation.
//!
//! Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
//! causes no state change.

use sha2::{Digest, Sha384};
use std::collections::BTreeSet;

use crate::cbor::{self, Value};
use crate::cose;

/// Width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis zero.
pub const HEAD_SIZE: usize = 48;

pub fn err_name_malformed() -> cose::Error {
    cose::Error {
        kind: "NameMalformed",
        msg: "object is not a well-formed N-AALP name-binding or task-transition body",
    }
}
pub fn err_name_chain_broken() -> cose::Error {
    cose::Error {
        kind: "NameChainBroken",
        msg: "name-binding prev/seq does not chain to the previous binding (a gap, reorder, or omitted binding)",
    }
}
pub fn err_name_fork_proof_invalid() -> cose::Error {
    cose::Error {
        kind: "NameForkProofInvalid",
        msg: "name fork proof does not prove equivocation (not one signer, not the same name+seq, or the same signer)",
    }
}
pub fn err_illegal_transition() -> cose::Error {
    cose::Error {
        kind: "IllegalTransition",
        msg: "A2A task transition is not a legal edge (unknown edge, self-loop, from a terminal state, or a non-contiguous from)",
    }
}
pub fn err_task_chain_broken() -> cose::Error {
    cose::Error {
        kind: "TaskChainBroken",
        msg: "task-transition prev/seq does not chain to the previous transition (a gap, reorder, or omitted transition)",
    }
}
pub fn err_foreign_card() -> cose::Error {
    cose::Error {
        kind: "ForeignCard",
        msg:
            "task transition binds a card attestation other than the profile's bound A2A Agent Card",
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
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x20u8, 0x30u8];
    v.extend_from_slice(&head(b));
    v
}

// ==== Task 4.1 — name bindings =================================================================

/// A name-to-signer binding at a chain position; it chains onto the prior binding (prev = the prior
/// Head; genesis for seq 0). A rotation is a new binding at the next seq naming the new signer. Dated
/// by seq; the envelope `created` field is advisory only.
#[derive(Debug, Clone)]
pub struct NameBinding {
    pub name: String,
    pub signer: Vec<u8>,
    pub seq: u64,
    pub prev: Vec<u8>,
}

impl NameBinding {
    /// Deterministic-CBOR {1: name, 2: signer, 3: seq, 4: prev}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.name.clone())),
            (Value::Uint(2), Value::Bstr(self.signer.clone())),
            (Value::Uint(3), Value::Uint(self.seq)),
            (Value::Uint(4), Value::Bstr(self.prev.clone())),
        ]))
        .expect("encode name binding")
    }
    /// The chain head after this binding: SHA-384(body) (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// The binding's T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a NameBinding from its body bytes alone.
pub fn parse_name_binding(b: &[u8]) -> Result<NameBinding, cose::Error> {
    let m = decode_map(b)?;
    let name = tstr_field(&m, 1).ok_or_else(err_name_malformed)?;
    let signer = bstr_field(&m, 2).ok_or_else(err_name_malformed)?;
    let seq = uint_field(&m, 3).ok_or_else(err_name_malformed)?;
    let prev = bstr_field(&m, 4).ok_or_else(err_name_malformed)?;
    Ok(NameBinding {
        name,
        signer,
        seq,
        prev,
    })
}

/// Produce the tagged COSE_Sign1 object over the binding body.
pub fn sign_binding(nb: &NameBinding, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &nb.bytes())
}

/// Verify the binding's full signature under the profile, then reconstruct it from the signed bytes.
pub fn verify_binding(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<NameBinding, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    parse_name_binding(&payload)
}

/// A naming authority that appends monotonic signed bindings for ONE name (mirroring audit::Authority).
pub struct Registrar<'a> {
    name: String,
    signer: &'a dyn cose::CoseSigner,
    head: Vec<u8>,
    seq: u64,
}

impl<'a> Registrar<'a> {
    /// Start a registrar for `name` with an empty (genesis) chain.
    pub fn new(name: &str, signer: &'a dyn cose::CoseSigner) -> Self {
        Registrar {
            name: name.to_string(),
            signer,
            head: genesis(),
            seq: 0,
        }
    }
    /// Record a binding of the name to `subject` at the next chain position; returns the binding and
    /// its tagged COSE_Sign1 object. Seq increases by one per append (monotonic).
    pub fn append(&mut self, subject: &[u8]) -> (NameBinding, Vec<u8>) {
        let nb = NameBinding {
            name: self.name.clone(),
            signer: subject.to_vec(),
            seq: self.seq,
            prev: self.head.clone(),
        };
        let obj = sign_binding(&nb, self.signer);
        self.head = nb.head();
        self.seq += 1;
        (nb, obj)
    }
}

/// One step of a walked name history: the chain position, the signer the name mapped to, and the head.
#[derive(Debug, Clone)]
pub struct NameEvent {
    pub seq: u64,
    pub signer: Vec<u8>,
    pub head: Vec<u8>,
}

/// Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the ordered
/// signer succession. Every binding must name the SAME name, seq i must equal its index, and prev
/// must link to the previous binding's head (genesis for seq 0). A gap/reorder/omission or a name
/// change is NameChainBroken. The CURRENT signer is the last event's signer.
pub fn walk_history(bindings: &[NameBinding]) -> Result<Vec<NameEvent>, cose::Error> {
    let mut events = Vec::with_capacity(bindings.len());
    let mut h = genesis();
    let mut name: Option<&str> = None;
    for (i, nb) in bindings.iter().enumerate() {
        match name {
            None => name = Some(&nb.name),
            Some(n) if n != nb.name => return Err(err_name_chain_broken()),
            _ => {}
        }
        if nb.seq != i as u64 || nb.prev != h {
            return Err(err_name_chain_broken());
        }
        h = nb.head();
        events.push(NameEvent {
            seq: nb.seq,
            signer: nb.signer.clone(),
            head: h.clone(),
        });
    }
    Ok(events)
}

/// Verify a name-binding chain against the authority's key. Each element is the tagged COSE_Sign1
/// object for one binding; every signature is verified (verify_binding), then structural continuity
/// is enforced. A bad signature propagates from verify1 (BadSignature); a broken link / seq gap /
/// name change is NameChainBroken. Returns the verified, ordered bindings. Fail-closed.
pub fn verify_chain(
    objs: &[Vec<u8>],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Vec<NameBinding>, cose::Error> {
    let mut h = genesis();
    let mut name: Option<String> = None;
    let mut out = Vec::with_capacity(objs.len());
    for (i, obj) in objs.iter().enumerate() {
        let nb = verify_binding(obj, profile, v)?;
        match &name {
            None => name = Some(nb.name.clone()),
            Some(n) if *n != nb.name => return Err(err_name_chain_broken()),
            _ => {}
        }
        if nb.seq != i as u64 || nb.prev != h {
            return Err(err_name_chain_broken());
        }
        h = nb.head();
        out.push(nb);
    }
    Ok(out)
}

/// Report whether a presented (possibly gappy) binding list breaks contiguity — a deleted/omitted
/// binding — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th binding's seq is not i
/// or its prev does not link to the previous binding's head. A contiguous list returns (0, false).
pub fn detect_hole(bindings: &[NameBinding]) -> (usize, bool) {
    let mut h = genesis();
    for (i, nb) in bindings.iter().enumerate() {
        if nb.seq != i as u64 || nb.prev != h {
            return (i, true);
        }
        h = nb.head();
    }
    (0, false)
}

/// Compare two bindings for the SAME name and report whether they equivocate — the SAME name and seq
/// but DIFFERENT bodies — and, if so, the seq POSITION. A different name/seq is a legitimate distinct
/// binding; byte-identical bindings are a benign duplicate; both non-fork cases return (0, false).
pub fn detect_fork(a: &NameBinding, b: &NameBinding) -> (usize, bool) {
    if a.name != b.name || a.seq != b.seq {
        return (0, false);
    }
    if a.bytes() == b.bytes() {
        return (0, false);
    }
    (a.seq as usize, true)
}

/// Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority at
/// the same (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
/// objects. Mirrors the directory / audit fork proof: a single verifier checking both signed objects
/// proves one authority, so the proof is self-contained.
#[derive(Debug, Clone)]
pub struct NameForkProof {
    pub signer: Vec<u8>,
    pub signed_a: Vec<u8>,
    pub signed_b: Vec<u8>,
}

impl NameForkProof {
    /// Check that this is a genuine name fork by the authority whose key is `v`, returning the seq
    /// POSITION. Accepts iff: the signer id is present; BOTH signed objects verify under `v` (proving
    /// one authority); the two bindings share one name and seq; and their bodies differ. Any failure
    /// rejects the whole proof (fail-closed): an unnamed signer, a different name/seq, or identical
    /// bodies is NameForkProofInvalid; a bad signature propagates from verify1 (BadSignature).
    pub fn verify(&self, profile: u32, v: &dyn cose::CoseVerifier) -> Result<usize, cose::Error> {
        if self.signer.is_empty() {
            return Err(err_name_fork_proof_invalid());
        }
        let a = verify_binding(&self.signed_a, profile, v)?;
        let b = verify_binding(&self.signed_b, profile, v)?;
        let (pos, fork) = detect_fork(&a, &b);
        if !fork {
            return Err(err_name_fork_proof_invalid());
        }
        Ok(pos)
    }
}

// ==== Task 4.2 — the signed A2A task-state profile ============================================

/// The imported A2A TaskState codes (carriage, not adoption). The state SET and the terminal/
/// interrupted categories are from the A2A specification (§4.1.3).
pub const STATE_SUBMITTED: u64 = 0; // "submitted" — acknowledged, not yet started (the start state)
pub const STATE_WORKING: u64 = 1; // "working" — actively processed
pub const STATE_INPUT_REQUIRED: u64 = 2; // "input-required" — interrupted, awaiting client input
pub const STATE_AUTH_REQUIRED: u64 = 3; // "auth-required" — interrupted, awaiting authentication
pub const STATE_COMPLETED: u64 = 4; // "completed" — terminal success
pub const STATE_CANCELED: u64 = 5; // "canceled" — terminal, canceled before completion
pub const STATE_FAILED: u64 = 6; // "failed" — terminal, finished with an error
pub const STATE_REJECTED: u64 = 7; // "rejected" — terminal, the agent declined the task

/// The A2A lifecycle start state (submitted).
pub const START_STATE: u64 = STATE_SUBMITTED;

/// The A2A name for a state code, or "unknown" for an out-of-range code.
pub fn state_name(s: u64) -> &'static str {
    match s {
        STATE_SUBMITTED => "submitted",
        STATE_WORKING => "working",
        STATE_INPUT_REQUIRED => "input-required",
        STATE_AUTH_REQUIRED => "auth-required",
        STATE_COMPLETED => "completed",
        STATE_CANCELED => "canceled",
        STATE_FAILED => "failed",
        STATE_REJECTED => "rejected",
        _ => "unknown",
    }
}

/// Whether s is one of the eight defined A2A states.
pub fn is_state(s: u64) -> bool {
    s <= STATE_REJECTED
}

/// Whether s is a terminal state (completed/canceled/failed/rejected): no transition may leave it.
pub fn is_terminal(s: u64) -> bool {
    matches!(
        s,
        STATE_COMPLETED | STATE_CANCELED | STATE_FAILED | STATE_REJECTED
    )
}

/// Whether s is an interrupted state (input-required/auth-required): awaiting client action.
pub fn is_interrupted(s: u64) -> bool {
    s == STATE_INPUT_REQUIRED || s == STATE_AUTH_REQUIRED
}

/// The explicit A2A transition table: the set of legal (from, to) edges derived from the A2A
/// category rules (design §22.3). Built once; consulted by legal_edge and verify_task_chain, and
/// graded Rust == Go == oracle.
fn legal_edge_set() -> BTreeSet<(u64, u64)> {
    let active = [STATE_SUBMITTED, STATE_WORKING];
    let interrupted = [STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED];
    let terminal = [
        STATE_COMPLETED,
        STATE_CANCELED,
        STATE_FAILED,
        STATE_REJECTED,
    ];
    let mut m: BTreeSet<(u64, u64)> = BTreeSet::new();
    m.insert((STATE_SUBMITTED, STATE_WORKING)); // begin processing (the only active->active edge)
    for &s in &active {
        for &t in &interrupted {
            m.insert((s, t)); // active -> interrupted
        }
    }
    for &s in &active {
        for &t in &terminal {
            m.insert((s, t)); // active -> terminal
        }
    }
    for &s in &interrupted {
        m.insert((s, STATE_WORKING)); // interrupted -> working (client acted)
    }
    for &s in &interrupted {
        for &t in &terminal {
            m.insert((s, t)); // interrupted -> terminal
        }
    }
    m
}

/// Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
/// terminal state, an edge touching an undefined state, and any edge not in the table are all false.
pub fn legal_edge(from: u64, to: u64) -> bool {
    if !is_state(from) || !is_state(to) {
        return false;
    }
    legal_edge_set().contains(&(from, to))
}

/// The legal transition table as a sorted slice of (from, to) pairs.
pub fn legal_edges() -> Vec<(u64, u64)> {
    legal_edge_set().into_iter().collect()
}

/// The edge-legality gate (rejects illegal edges): Ok iff (from -> to) is a legal edge, else
/// IllegalTransition. Fail-closed.
pub fn verify_transition(from: u64, to: u64) -> Result<(), cose::Error> {
    if legal_edge(from, to) {
        Ok(())
    } else {
        Err(err_illegal_transition())
    }
}

/// One signed, receipt-CHAINED A2A task state transition. It chains onto the prior transition of the
/// same task (prev = the prior Head; genesis for seq 0). Dated by seq. `card` is the content-id of
/// the A2A Agent Card attestation (a C18 import) binding this profile to an agent/operation.
#[derive(Debug, Clone)]
pub struct Transition {
    pub task: Vec<u8>,
    pub card: Vec<u8>,
    pub from: u64,
    pub to: u64,
    pub seq: u64,
    pub prev: Vec<u8>,
}

impl Transition {
    /// Deterministic-CBOR {1: task, 2: card, 3: from, 4: to, 5: seq, 6: prev}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.task.clone())),
            (Value::Uint(2), Value::Bstr(self.card.clone())),
            (Value::Uint(3), Value::Uint(self.from)),
            (Value::Uint(4), Value::Uint(self.to)),
            (Value::Uint(5), Value::Uint(self.seq)),
            (Value::Uint(6), Value::Bstr(self.prev.clone())),
        ]))
        .expect("encode transition")
    }
    /// The chain head after this transition: SHA-384(body) (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// The transition's T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a Transition from its body bytes alone.
pub fn parse_transition(b: &[u8]) -> Result<Transition, cose::Error> {
    let m = decode_map(b)?;
    let task = bstr_field(&m, 1).ok_or_else(err_name_malformed)?;
    let card = bstr_field(&m, 2).ok_or_else(err_name_malformed)?;
    let from = uint_field(&m, 3).ok_or_else(err_name_malformed)?;
    let to = uint_field(&m, 4).ok_or_else(err_name_malformed)?;
    let seq = uint_field(&m, 5).ok_or_else(err_name_malformed)?;
    let prev = bstr_field(&m, 6).ok_or_else(err_name_malformed)?;
    Ok(Transition {
        task,
        card,
        from,
        to,
        seq,
        prev,
    })
}

/// Produce the tagged COSE_Sign1 object over the transition body.
pub fn sign_transition(t: &Transition, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &t.bytes())
}

/// Verify a transition's full signature under the profile, reconstruct it, and check its edge is
/// legal (verify_transition). A bad signature propagates (BadSignature); an illegal edge is
/// IllegalTransition. Fail-closed.
pub fn verify_transition_object(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Transition, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let t = parse_transition(&payload)?;
    verify_transition(t.from, t.to)?;
    Ok(t)
}

/// Walk a task's transition chain against the authority's key and the bound card attestation. Each
/// element is the tagged COSE_Sign1 object for one transition. Enforces, in order and fail-closed:
/// (1) the signature of every transition (verify1) — BadSignature otherwise; (2) prev/seq linkage —
/// TaskChainBroken; (3) the CARD BINDING (every transition's card equals `card`) — ForeignCard;
/// (4) the START STATE (seq-0 from is START_STATE), CONTIGUITY (each from == the prior to), and the
/// LEGAL-EDGE TABLE at every step (incl. the terminal-cannot-continue rule) — IllegalTransition.
/// Returns the verified, ordered transitions.
pub fn verify_task_chain(
    objs: &[Vec<u8>],
    card: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Vec<Transition>, cose::Error> {
    let mut h = genesis();
    let mut prev_to: u64 = 0;
    let mut out = Vec::with_capacity(objs.len());
    for (i, obj) in objs.iter().enumerate() {
        cose::verify1(profile, v, obj)?;
        let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
        let t = parse_transition(&payload)?;
        if t.seq != i as u64 || t.prev != h {
            return Err(err_task_chain_broken());
        }
        if t.card != card {
            return Err(err_foreign_card());
        }
        if i == 0 {
            if t.from != START_STATE {
                return Err(err_illegal_transition());
            }
        } else if t.from != prev_to {
            return Err(err_illegal_transition());
        }
        verify_transition(t.from, t.to)?;
        h = t.head();
        prev_to = t.to;
        out.push(t);
    }
    Ok(out)
}

/// Report whether a presented (possibly gappy) transition list breaks contiguity — a deleted/omitted
/// or reordered transition — and, if so, the FIRST-BROKEN POSITION. A contiguous list returns
/// (0, false). (The gap-evident detector for the task chain, mirroring detect_hole.)
pub fn detect_task_gap(transitions: &[Transition]) -> (usize, bool) {
    let mut h = genesis();
    for (i, t) in transitions.iter().enumerate() {
        if t.seq != i as u64 || t.prev != h {
            return (i, true);
        }
        h = t.head();
    }
    (0, false)
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

fn decode_map(b: &[u8]) -> Result<Vec<(Value, Value)>, cose::Error> {
    match cbor::decode(b).map_err(|_| err_name_malformed())? {
        Value::Map(m) => Ok(m),
        _ => Err(err_name_malformed()),
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

fn tstr_field(m: &[(Value, Value)], k: u64) -> Option<String> {
    match field(m, k)? {
        Value::Tstr(s) => Some(s),
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
    use crate::description;
    use crate::policy;
    use fips204::traits::SerDes;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/naming/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn bindings_from(c: &J) -> Vec<NameBinding> {
        let name = c["name"]["name_utf8"].as_str().unwrap().to_string();
        c["name"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| NameBinding {
                name: name.clone(),
                signer: hexd(b["signer_hex"].as_str().unwrap()),
                seq: b["seq"].as_u64().unwrap(),
                prev: hexd(b["prev_hex"].as_str().unwrap()),
            })
            .collect()
    }

    fn card_import(c: &J) -> description::Import {
        let ops = c["a2a"]["card"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| description::Operation {
                name: o["name"].as_str().unwrap().to_string(),
                effect: o["effect"].as_u64().unwrap(),
                requires_approval: o["requires_approval"].as_u64().unwrap(),
            })
            .collect();
        description::Import {
            importer: hexd(c["a2a"]["card"]["importer_hex"].as_str().unwrap()),
            format: c["a2a"]["card"]["format"].as_u64().unwrap(),
            foreign: hexd(c["a2a"]["card"]["foreign_hex"].as_str().unwrap()),
            operations: ops,
        }
    }

    fn transitions_from(c: &J) -> Vec<Transition> {
        let task = c["a2a"]["task_utf8"].as_str().unwrap().as_bytes().to_vec();
        let card = hexd(c["a2a"]["card"]["card_id_hex"].as_str().unwrap());
        c["a2a"]["transitions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| Transition {
                task: task.clone(),
                card: card.clone(),
                from: t["from"].as_u64().unwrap(),
                to: t["to"].as_u64().unwrap(),
                seq: t["seq"].as_u64().unwrap(),
                prev: hexd(t["prev_hex"].as_str().unwrap()),
            })
            .collect()
    }

    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier, String) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        let pkb = pk.clone().into_bytes().to_vec();
        let id = crate::identity::signer_id(cose::ALG_MLDSA65, &pkb).expect("signer id");
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk), id)
    }

    // Byte-parity: Rust encoding == the same non-circular Python oracle -> Rust == Go on every wire
    // object body, head, id, and the card attestation content-id.
    #[test]
    fn bodies_match_oracle() {
        let c = load();
        let bindings = bindings_from(&c);
        for (i, nb) in bindings.iter().enumerate() {
            let bv = &c["name"]["bindings"][i];
            assert_eq!(hex::encode(nb.bytes()), bv["body_hex"].as_str().unwrap());
            assert_eq!(hex::encode(nb.head()), bv["head_hex"].as_str().unwrap());
            assert_eq!(hex::encode(nb.id()), bv["id_hex"].as_str().unwrap());
        }
        let bp = NameBinding {
            name: c["name"]["name_utf8"].as_str().unwrap().to_string(),
            signer: hexd(c["name"]["fork"]["b_prime"]["signer_hex"].as_str().unwrap()),
            seq: c["name"]["fork"]["b_prime"]["seq"].as_u64().unwrap(),
            prev: hexd(c["name"]["fork"]["b_prime"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(bp.bytes()),
            c["name"]["fork"]["b_prime"]["body_hex"].as_str().unwrap()
        );

        let transitions = transitions_from(&c);
        for (i, tr) in transitions.iter().enumerate() {
            let tv = &c["a2a"]["transitions"][i];
            assert_eq!(hex::encode(tr.bytes()), tv["body_hex"].as_str().unwrap());
            assert_eq!(hex::encode(tr.head()), tv["head_hex"].as_str().unwrap());
            assert_eq!(hex::encode(tr.id()), tv["id_hex"].as_str().unwrap());
        }

        let im = card_import(&c);
        assert_eq!(
            hex::encode(im.bytes()),
            c["a2a"]["card"]["import_body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(im.id()),
            c["a2a"]["card"]["card_id_hex"].as_str().unwrap()
        );
    }

    // A name-history walk: the signer succession (A -> B -> C) matches the oracle; the current signer
    // is the last event. A name change mid-chain breaks the walk.
    #[test]
    fn walk_history_matches_oracle() {
        let c = load();
        let bindings = bindings_from(&c);
        let events = walk_history(&bindings).expect("walk");
        let walk = c["name"]["walk"].as_array().unwrap();
        assert_eq!(events.len(), walk.len());
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.seq, walk[i]["seq"].as_u64().unwrap());
            assert_eq!(
                hex::encode(&e.signer),
                walk[i]["signer_hex"].as_str().unwrap()
            );
        }
        let cur = &events.last().unwrap().signer;
        let last = bindings.last().unwrap();
        assert_eq!(
            cur, &last.signer,
            "current signer is the last binding's signer"
        );

        let mut bad = bindings.clone();
        bad[1].name = "other.name".into();
        assert_eq!(
            walk_history(&[bad[0].clone(), bad[1].clone()])
                .unwrap_err()
                .kind,
            "NameChainBroken"
        );
    }

    // A deleted binding leaves a detected hole at the oracle position; a contiguous chain has no hole.
    #[test]
    fn name_hole_detected_with_position() {
        let c = load();
        let bindings = bindings_from(&c);
        assert!(!detect_hole(&bindings).1, "contiguous chain has no hole");
        let present = vec![bindings[0].clone(), bindings[2].clone()];
        let (pos, hole) = detect_hole(&present);
        assert!(hole);
        assert_eq!(
            pos as u64,
            c["name"]["hole"]["first_hole_position"].as_u64().unwrap()
        );
    }

    // Two bindings by one authority at the same (name, seq) naming different signers are a fork at the
    // oracle seq position; the signed NameForkProof is non-repudiable.
    #[test]
    fn name_fork_detected_with_position() {
        let c = load();
        let bindings = bindings_from(&c);
        let bp = NameBinding {
            name: c["name"]["name_utf8"].as_str().unwrap().to_string(),
            signer: hexd(c["name"]["fork"]["b_prime"]["signer_hex"].as_str().unwrap()),
            seq: c["name"]["fork"]["b_prime"]["seq"].as_u64().unwrap(),
            prev: hexd(c["name"]["fork"]["b_prime"]["prev_hex"].as_str().unwrap()),
        };
        let (pos, fork) = detect_fork(&bindings[1], &bp);
        assert!(fork);
        assert_eq!(pos as u64, c["name"]["fork"]["position"].as_u64().unwrap());
        assert!(
            !detect_fork(&bindings[1], &bindings[1]).1,
            "identical bindings are a duplicate"
        );
        assert!(
            !detect_fork(&bindings[1], &bindings[2]).1,
            "different seq is not a fork"
        );

        let (s, v, id) = key(0x11);
        let (_, foreign, _) = key(0x22);
        let signed_a = sign_binding(&bindings[1], &s);
        let signed_b = sign_binding(&bp, &s);
        let fp = NameForkProof {
            signer: id.clone().into_bytes(),
            signed_a: signed_a.clone(),
            signed_b: signed_b.clone(),
        };
        let gp = fp
            .verify(cose::PROFILE_PUBLIC, &v)
            .expect("honest fork proof");
        assert_eq!(gp as u64, c["name"]["fork"]["position"].as_u64().unwrap());
        assert_eq!(
            fp.verify(cose::PROFILE_PUBLIC, &foreign).unwrap_err().kind,
            "BadSignature"
        );
        let unnamed = NameForkProof {
            signer: vec![],
            signed_a: signed_a.clone(),
            signed_b: signed_b.clone(),
        };
        assert_eq!(
            unnamed.verify(cose::PROFILE_PUBLIC, &v).unwrap_err().kind,
            "NameForkProofInvalid"
        );
        let dup = NameForkProof {
            signer: id.into_bytes(),
            signed_a: signed_a.clone(),
            signed_b: signed_a,
        };
        assert_eq!(
            dup.verify(cose::PROFILE_PUBLIC, &v).unwrap_err().kind,
            "NameForkProofInvalid"
        );
    }

    // An honest signed chain verifies (via the Registrar appender); a reorder, a tampered object, and
    // a foreign key are each rejected with their named error.
    #[test]
    fn name_chain_verify_fail_closed() {
        let c = load();
        let (s, v, _) = key(0x11);
        let (_, foreign, _) = key(0x22);
        let name = c["name"]["name_utf8"].as_str().unwrap();
        let mut reg = Registrar::new(name, &s);
        let mut bindings = vec![];
        let mut objs: Vec<Vec<u8>> = vec![];
        for bv in c["name"]["bindings"].as_array().unwrap() {
            let (nb, obj) = reg.append(&hexd(bv["signer_hex"].as_str().unwrap()));
            bindings.push(nb);
            objs.push(obj);
        }
        for (i, nb) in bindings.iter().enumerate() {
            assert_eq!(
                hex::encode(nb.bytes()),
                c["name"]["bindings"][i]["body_hex"].as_str().unwrap()
            );
        }
        let verified = verify_chain(&objs, cose::PROFILE_PUBLIC, &v).expect("honest chain");
        assert_eq!(walk_history(&verified).unwrap().len(), bindings.len());

        let reordered = vec![objs[0].clone(), objs[2].clone(), objs[1].clone()];
        assert_eq!(
            verify_chain(&reordered, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "NameChainBroken"
        );

        let mut tampered = objs.clone();
        let mut corrupt = objs[1].clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x01;
        tampered[1] = corrupt;
        assert_eq!(
            verify_chain(&tampered, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        assert_eq!(
            verify_chain(&objs, cose::PROFILE_PUBLIC, &foreign)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        assert_eq!(
            verify_binding(&objs[0], cose::PROFILE_PUBLIC, &foreign)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
    }

    // The explicit A2A transition table matches the independently-listed oracle edge set: every legal
    // edge accepted, every illegal edge rejected, categories match, terminal states have no out-edge.
    #[test]
    fn transition_table_matches_oracle() {
        let c = load();
        let legal = c["a2a"]["legal_edges"].as_array().unwrap();
        assert_eq!(legal_edges().len(), legal.len());
        for e in legal {
            let (f, t) = (e[0].as_u64().unwrap(), e[1].as_u64().unwrap());
            assert!(legal_edge(f, t), "legal edge {}->{} rejected", f, t);
            assert!(verify_transition(f, t).is_ok());
        }
        for e in c["a2a"]["illegal_edges"].as_array().unwrap() {
            let (f, t) = (e[0].as_u64().unwrap(), e[1].as_u64().unwrap());
            assert!(!legal_edge(f, t), "illegal edge {}->{} accepted", f, t);
            assert_eq!(
                verify_transition(f, t).unwrap_err().kind,
                "IllegalTransition"
            );
        }
        assert_eq!(START_STATE, c["a2a"]["states"]["start"].as_u64().unwrap());
        for s in c["a2a"]["states"]["terminal"].as_array().unwrap() {
            let s = s.as_u64().unwrap();
            assert!(is_terminal(s));
            for to in 0u64..8 {
                assert!(
                    !legal_edge(s, to),
                    "terminal {} has an out-edge to {}",
                    s,
                    to
                );
            }
        }
        for s in c["a2a"]["states"]["interrupted"].as_array().unwrap() {
            assert!(is_interrupted(s.as_u64().unwrap()));
        }
    }

    // Grades state_name(), which until now was carried only in diagnostic strings and never
    // asserted. For each of the eight A2A states it cross-checks the oracle's independent code
    // assignment (vectors/naming/cases.json a2a.states) against the STATE_* constant it names, then
    // asserts state_name() returns the EXACT literal A2A spelling (naming.go:329-333 stateName; the
    // oracle's JSON keys use underscores where the wire name uses a hyphen, so the literal spelling
    // is pinned here rather than read back out of the JSON). An out-of-range code names "unknown".
    // Mutation: swap any two arms of state_name (or misspell one) and this fails.
    #[test]
    fn state_names_match_a2a_vocabulary() {
        let c = load();
        let states = &c["a2a"]["states"];
        let want: [(u64, u64, &str); 8] = [
            (STATE_SUBMITTED, states["submitted"].as_u64().unwrap(), "submitted"),
            (STATE_WORKING, states["working"].as_u64().unwrap(), "working"),
            (
                STATE_INPUT_REQUIRED,
                states["input_required"].as_u64().unwrap(),
                "input-required",
            ),
            (
                STATE_AUTH_REQUIRED,
                states["auth_required"].as_u64().unwrap(),
                "auth-required",
            ),
            (STATE_COMPLETED, states["completed"].as_u64().unwrap(), "completed"),
            (STATE_CANCELED, states["canceled"].as_u64().unwrap(), "canceled"),
            (STATE_FAILED, states["failed"].as_u64().unwrap(), "failed"),
            (STATE_REJECTED, states["rejected"].as_u64().unwrap(), "rejected"),
        ];
        for (state, oracle_code, want_name) in want {
            assert_eq!(
                state, oracle_code,
                "state constant does not match the oracle's code for {want_name}"
            );
            assert_eq!(state_name(state), want_name);
        }
        assert_eq!(state_name(255), "unknown");
    }

    // A task's LEGAL ordered lifecycle verifies; an illegal edge, a non-contiguous from, a bad start,
    // a foreign card, a gap, and a bad signature are each rejected.
    #[test]
    fn task_chain_legal_and_illegal() {
        let c = load();
        let (s, v, _) = key(0x11);
        let card = hexd(c["a2a"]["card"]["card_id_hex"].as_str().unwrap());
        let task = c["a2a"]["task_utf8"].as_str().unwrap().as_bytes().to_vec();

        let transitions = transitions_from(&c);
        let objs: Vec<Vec<u8>> = transitions.iter().map(|t| sign_transition(t, &s)).collect();
        verify_task_chain(&objs, &card, cose::PROFILE_PUBLIC, &v).expect("legal chain");
        for (i, tr) in transitions.iter().enumerate() {
            assert_eq!(
                hex::encode(tr.bytes()),
                c["a2a"]["transitions"][i]["body_hex"].as_str().unwrap()
            );
        }

        let t0 = Transition {
            task: task.clone(),
            card: card.clone(),
            from: STATE_SUBMITTED,
            to: STATE_WORKING,
            seq: 0,
            prev: genesis(),
        };
        let illegal = Transition {
            task: task.clone(),
            card: card.clone(),
            from: STATE_WORKING,
            to: STATE_SUBMITTED,
            seq: 1,
            prev: t0.head(),
        };
        let chain = vec![sign_transition(&t0, &s), sign_transition(&illegal, &s)];
        assert_eq!(
            verify_task_chain(&chain, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "IllegalTransition"
        );

        let non_contig = Transition {
            task: task.clone(),
            card: card.clone(),
            from: STATE_INPUT_REQUIRED,
            to: STATE_WORKING,
            seq: 1,
            prev: t0.head(),
        };
        let chain = vec![sign_transition(&t0, &s), sign_transition(&non_contig, &s)];
        assert_eq!(
            verify_task_chain(&chain, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "IllegalTransition"
        );

        let bad_start = Transition {
            task: task.clone(),
            card: card.clone(),
            from: STATE_WORKING,
            to: STATE_INPUT_REQUIRED,
            seq: 0,
            prev: genesis(),
        };
        let chain = vec![sign_transition(&bad_start, &s)];
        assert_eq!(
            verify_task_chain(&chain, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "IllegalTransition"
        );

        let foreign_card = hexd(c["a2a"]["foreign_card_id_hex"].as_str().unwrap());
        let fc = Transition {
            task: task.clone(),
            card: foreign_card,
            from: STATE_SUBMITTED,
            to: STATE_WORKING,
            seq: 0,
            prev: genesis(),
        };
        let chain = vec![sign_transition(&fc, &s)];
        assert_eq!(
            verify_task_chain(&chain, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "ForeignCard"
        );

        let present = vec![objs[0].clone(), objs[2].clone()];
        assert_eq!(
            verify_task_chain(&present, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "TaskChainBroken"
        );

        let mut bad = objs.clone();
        let mut corrupt = objs[0].clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0x01;
        bad[0] = corrupt;
        assert_eq!(
            verify_task_chain(&bad, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
    }

    // A deleted transition leaves a detected gap at the oracle position; a contiguous chain has none.
    #[test]
    fn task_gap_detected_with_position() {
        let c = load();
        let transitions = transitions_from(&c);
        assert!(!detect_task_gap(&transitions).1);
        let present = vec![transitions[0].clone(), transitions[2].clone()];
        let (pos, gap) = detect_task_gap(&present);
        assert!(gap);
        assert_eq!(
            pos as u64,
            c["a2a"]["gap"]["first_gap_position"].as_u64().unwrap()
        );
    }

    // The C18 -> C19 link: the A2A Agent Card attestation binds the task profile by content-id; the
    // card attests the operation effect mapping; a foreign card is rejected.
    #[test]
    fn card_attestation_binds_profile() {
        let c = load();
        let (s, v, _) = key(0x11);
        let im = card_import(&c);
        let card = im.id();
        assert_eq!(
            hex::encode(&card),
            c["a2a"]["card"]["card_id_hex"].as_str().unwrap()
        );
        let submit = im.operation("submit").expect("submit attested");
        assert_eq!(submit.effect_class(), policy::IDEMPOTENT_WRITE);
        assert!(submit.requires_approval_flag());

        let transitions = transitions_from(&c);
        let objs: Vec<Vec<u8>> = transitions.iter().map(|t| sign_transition(t, &s)).collect();
        verify_task_chain(&objs, &card, cose::PROFILE_PUBLIC, &v).expect("bound to the card");

        let other = description::Import {
            importer: b"IMPORTER_ID_B".to_vec(),
            format: im.format,
            foreign: im.foreign.clone(),
            operations: im.operations.clone(),
        };
        assert_ne!(
            other.id(),
            card,
            "a different importer yields a different card id"
        );
        let other_t = Transition {
            task: c["a2a"]["task_utf8"].as_str().unwrap().as_bytes().to_vec(),
            card: other.id(),
            from: STATE_SUBMITTED,
            to: STATE_WORKING,
            seq: 0,
            prev: genesis(),
        };
        let other_objs = vec![sign_transition(&other_t, &s)];
        assert_eq!(
            verify_task_chain(&other_objs, &card, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "ForeignCard"
        );
    }

    // A body that is not a well-formed binding/transition is NameMalformed (fail-closed).
    #[test]
    fn malformed_rejected() {
        assert_eq!(
            parse_name_binding(&[0x80]).unwrap_err().kind,
            "NameMalformed"
        ); // empty CBOR array
        assert_eq!(parse_transition(&[0x00]).unwrap_err().kind, "NameMalformed");
        // bare uint 0
    }

    // Cross-language signature bit-identity: signing the seq-0 name binding and the seq-0 transition
    // with the shared 0x11*32 seed must produce COSE_Sign1 objects whose SHA-384 equals the values the
    // Go naming test pins — Go and Rust emit byte-identical signed objects (deterministic ML-DSA-65
    // Phase 6 edge case #3 (the >2^53 discipline): a name-binding seq AND a task-transition seq above
    // 2^53 round-trip byte-exact (u64, no float64). Both carried as JSON strings, parsed with u64.
    #[test]
    fn naming_oversized_seq_round_trip() {
        let c = load();
        let bseq: u64 = c["name"]["big_seq"]["seq_str"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(bseq > (1 << 53));
        let nb = NameBinding {
            name: c["name"]["name_utf8"].as_str().unwrap().to_string(),
            signer: hexd(c["name"]["big_seq"]["signer_hex"].as_str().unwrap()),
            seq: bseq,
            prev: hexd(c["name"]["big_seq"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(nb.bytes()),
            c["name"]["big_seq"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            parse_name_binding(&nb.bytes()).expect("parse").seq,
            bseq,
            ">2^53 binding seq corrupted"
        );

        let tseq: u64 = c["a2a"]["big_seq"]["seq_str"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let tr = Transition {
            task: c["a2a"]["task_utf8"].as_str().unwrap().as_bytes().to_vec(),
            card: hexd(c["a2a"]["card"]["card_id_hex"].as_str().unwrap()),
            from: c["a2a"]["big_seq"]["from"].as_u64().unwrap(),
            to: c["a2a"]["big_seq"]["to"].as_u64().unwrap(),
            seq: tseq,
            prev: hexd(c["a2a"]["big_seq"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(tr.bytes()),
            c["a2a"]["big_seq"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            parse_transition(&tr.bytes()).expect("parse").seq,
            tseq,
            ">2^53 transition seq corrupted"
        );
    }

    // Phase 6 edge case #4: the smallest valid binding and transition encode + reconstruct.
    #[test]
    fn naming_minimal() {
        let c = load();
        let nb = NameBinding {
            name: c["name"]["minimal"]["name_utf8"]
                .as_str()
                .unwrap()
                .to_string(),
            signer: hexd(c["name"]["minimal"]["signer_hex"].as_str().unwrap()),
            seq: c["name"]["minimal"]["seq"].as_u64().unwrap(),
            prev: hexd(c["name"]["minimal"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(nb.bytes()),
            c["name"]["minimal"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(nb.id()),
            c["name"]["minimal"]["id_hex"].as_str().unwrap()
        );
        parse_name_binding(&nb.bytes()).expect("parse minimal binding");

        let tr = Transition {
            task: hexd(c["a2a"]["minimal"]["task_hex"].as_str().unwrap()),
            card: hexd(c["a2a"]["minimal"]["card_hex"].as_str().unwrap()),
            from: c["a2a"]["minimal"]["from"].as_u64().unwrap(),
            to: c["a2a"]["minimal"]["to"].as_u64().unwrap(),
            seq: c["a2a"]["minimal"]["seq"].as_u64().unwrap(),
            prev: hexd(c["a2a"]["minimal"]["prev_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(tr.bytes()),
            c["a2a"]["minimal"]["body_hex"].as_str().unwrap()
        );
        parse_transition(&tr.bytes()).expect("parse minimal transition");
    }

    // Phase 6 edge case #1: a descending-key binding body is rejected NonCanonical.
    #[test]
    fn naming_keys_out_of_order_rejected() {
        let c = load();
        let canon = hexd(
            c["name"]["keys_out_of_order"]["canonical_binding_body_hex"]
                .as_str()
                .unwrap(),
        );
        let noncanon = hexd(
            c["name"]["keys_out_of_order"]["noncanonical_binding_body_hex"]
                .as_str()
                .unwrap(),
        );
        let nb = bindings_from(&c).remove(0);
        assert_eq!(
            hex::encode(nb.bytes()),
            c["name"]["keys_out_of_order"]["canonical_binding_body_hex"]
                .as_str()
                .unwrap()
        );
        assert!(crate::cbor::decode(&canon).is_ok());
        match crate::cbor::decode(&noncanon) {
            Err(e) => assert_eq!(e.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key binding accepted"),
        }
    }

    // Phase 6 edge case #5: a 4-field binding and a 6-field transition are each rejected by the other's
    // parser.
    #[test]
    fn naming_look_alike_rejected_by_sibling() {
        let c = load();
        let binding_body = hexd(
            c["name"]["look_alike"]["binding_body_hex"]
                .as_str()
                .unwrap(),
        );
        let transition_body = hexd(
            c["name"]["look_alike"]["transition_body_hex"]
                .as_str()
                .unwrap(),
        );
        assert_eq!(
            parse_transition(&binding_body).unwrap_err().kind,
            "NameMalformed"
        );
        assert_eq!(
            parse_name_binding(&transition_body).unwrap_err().kind,
            "NameMalformed"
        );
    }

    // over identical canonical CBOR). Mutation: any encoding/signing-input drift breaks the pin.
    #[test]
    fn cross_lang_signed_binding_pin() {
        const PINNED: &str =
            "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91";
        let c = load();
        let nb = bindings_from(&c).remove(0);
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let obj = sign_binding(&nb, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&obj)),
            PINNED,
            "Rust signed name-binding digest differs from the Go pin"
        );
    }

    #[test]
    fn cross_lang_signed_transition_pin() {
        const PINNED: &str =
            "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787";
        let c = load();
        let tr = transitions_from(&c).remove(0);
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let obj = sign_transition(&tr, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&obj)),
            PINNED,
            "Rust signed transition digest differs from the Go pin"
        );
    }
}
