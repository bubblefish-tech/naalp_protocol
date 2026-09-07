// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C20 — governed negotiation, advisory risk labels, and trust (design.md §23; R-NEG-1..6,
//! R-RISK-1..6, R-TRUST-1..4). The Rust half of the two-implementation parity; byte-identical to
//! impl/go/negotiation.
//!
//! C20 adds three signed surfaces carried on N-AALP's own signed object, introducing NO new envelope,
//! encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary COSE_Sign1
//! over a deterministic-CBOR body, reusing the closed C5 effect lattice, the T1 content-id framing
//! (§2.3), and the §8.2 causal partial order (`causes`) UNCHANGED.
//!
//! Task 5.1 — governed negotiation: a `Message` {1: negotiation, 2: role, 3: profile, 4: causes[]} is
//! one signed step (offer / counter / accept), CAUSALLY LINKED to its predecessor by content-id in
//! `causes`. Each SELECTS a profile from a CLOSED, PRE-REGISTERED set (`Profile`) — no runtime-
//! generated handlers, no free-form capability strings. An accept MUST DESCEND from its offer:
//! `verify_accept` walks the causes DAG from the accept to the offer's content-id (NotDescended
//! otherwise). Unknown role/profile are rejected.
//!
//! Task 5.2 — advisory risk labels: a `RiskLabel` {1: code, 2: critical} + `LabeledObject`
//! {1: effect, 2: labels[]}. The vocabulary is closed — sensitive (gating), egress (gating),
//! reversible (informing) — plus a private extensible range. `validate_labels` applies R-2.5 (unknown
//! critical rejected, unknown non-critical ignored). LOAD-BEARING invariant: `LabeledObject::effect_class`
//! derives from field 7 ALONE — a risk label NEVER changes the effect class (the closed lattice is
//! untouched; a label is an advisory dimension, not a fifth effect).
//!
//! Task 5.3 — trust references: a `TrustRef` {1: registry, 2: reference, 3: subject} carries a
//! third-party trust statement as a CHECKABLE signed object. `reference` is the content-id of an
//! EXTERNAL (ERC-8004-style) registry record; `verify_trust_ref` recomputes it (`binds_record`). No
//! wire field weighs it — this module has no scoring function, by design; resolution is the relying
//! party's.
//!
//! Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
//! causes no state change.

use sha2::{Digest, Sha384};
use std::collections::HashMap;

use crate::cbor::{self, Value};
use crate::cose;
use crate::policy;

/// Width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
pub const HEAD_SIZE: usize = 48;

pub fn err_malformed() -> cose::Error {
    cose::Error { kind: "NegMalformed", msg: "object is not a well-formed N-AALP negotiation/risk-label/labeled-object/trust-ref body" }
}
pub fn err_unknown_role() -> cose::Error {
    cose::Error {
        kind: "UnknownRole",
        msg: "negotiation message role is not offer/counter/accept",
    }
}
pub fn err_unknown_profile() -> cose::Error {
    cose::Error {
        kind: "UnknownProfile",
        msg: "negotiation selects a profile outside the closed pre-registered set — no free-form or runtime capability is negotiable",
    }
}
pub fn err_not_descended() -> cose::Error {
    cose::Error {
        kind: "NotDescended",
        msg: "accept does not descend from its offer along the causes chain",
    }
}
pub fn err_not_offer() -> cose::Error {
    cose::Error {
        kind: "NotOffer",
        msg: "the object presented as the offer is not an offer role",
    }
}
pub fn err_not_accept() -> cose::Error {
    cose::Error {
        kind: "NotAccept",
        msg: "the object presented as the accept is not an accept role",
    }
}
pub fn err_critical_flag() -> cose::Error {
    cose::Error {
        kind: "MalformedCriticalFlag",
        msg: "risk-label critical flag is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted",
    }
}
pub fn err_unknown_critical_risk() -> cose::Error {
    cose::Error {
        kind: "UnknownCriticalRisk",
        msg: "an unknown risk label carried critical is rejected (R-2.5 critical-extension rule)",
    }
}
pub fn err_reference_mismatch() -> cose::Error {
    cose::Error {
        kind: "ReferenceMismatch",
        msg: "trust-ref reference content-id does not recompute over the presented external record",
    }
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

// ==== Task 5.1 — governed negotiation =========================================================

/// A negotiation message's role: the closed set offer / counter / accept.
pub const ROLE_OFFER: u64 = 0;
pub const ROLE_COUNTER: u64 = 1;
pub const ROLE_ACCEPT: u64 = 2;

/// Whether `r` is one of the three defined negotiation roles.
pub fn known_role(r: u64) -> bool {
    matches!(r, ROLE_OFFER | ROLE_COUNTER | ROLE_ACCEPT)
}

/// The role name ("offer"/"counter"/"accept"), or "unknown" for an out-of-range code — mirrors Go
/// Role.Name() (negotiation.go:108).
pub fn role_name(r: u64) -> &'static str {
    match r {
        ROLE_OFFER => "offer",
        ROLE_COUNTER => "counter",
        ROLE_ACCEPT => "accept",
        _ => "unknown",
    }
}

/// A PRE-REGISTERED negotiation profile code (the closed set). A negotiation SELECTS a pre-registered
/// profile; it never carries a free-form capability string or a runtime-generated handler.
pub const PROFILE_BASELINE: u64 = 0;
pub const PROFILE_STREAMING: u64 = 1;
pub const PROFILE_BATCH: u64 = 2;

/// Whether `p` is one of the pre-registered profiles.
pub fn is_registered_profile(p: u64) -> bool {
    matches!(p, PROFILE_BASELINE | PROFILE_STREAMING | PROFILE_BATCH)
}

/// The profile name ("baseline"/"streaming"/"batch"), or "unknown" for an unregistered code —
/// mirrors Go Profile.Name() (negotiation.go:133).
pub fn profile_name(p: u64) -> &'static str {
    match p {
        PROFILE_BASELINE => "baseline",
        PROFILE_STREAMING => "streaming",
        PROFILE_BATCH => "batch",
        _ => "unknown",
    }
}

/// One signed step of a governed negotiation (offer / counter / accept), causally linked to its
/// predecessor(s) by content-id in `causes` (empty for an offer), selecting a pre-registered profile.
#[derive(Debug, Clone)]
pub struct Message {
    pub negotiation: Vec<u8>,
    pub role: u64,
    pub profile: u64,
    pub causes: Vec<Vec<u8>>,
}

impl Message {
    /// Build an offer (the root of a negotiation): role offer, no causes.
    pub fn offer(negotiation: Vec<u8>, profile: u64) -> Message {
        Message {
            negotiation,
            role: ROLE_OFFER,
            profile,
            causes: vec![],
        }
    }
    /// Build a counter chaining onto `predecessor_id`.
    pub fn counter(negotiation: Vec<u8>, profile: u64, predecessor_id: Vec<u8>) -> Message {
        Message {
            negotiation,
            role: ROLE_COUNTER,
            profile,
            causes: vec![predecessor_id],
        }
    }
    /// Build an accept chaining onto `predecessor_id` (must descend from its offer).
    pub fn accept(negotiation: Vec<u8>, profile: u64, predecessor_id: Vec<u8>) -> Message {
        Message {
            negotiation,
            role: ROLE_ACCEPT,
            profile,
            causes: vec![predecessor_id],
        }
    }
    /// Deterministic-CBOR {1: negotiation, 2: role, 3: profile, 4: causes[]}.
    pub fn bytes(&self) -> Vec<u8> {
        let arr = Value::Arr(self.causes.iter().map(|c| Value::Bstr(c.clone())).collect());
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.negotiation.clone())),
            (Value::Uint(2), Value::Uint(self.role)),
            (Value::Uint(3), Value::Uint(self.profile)),
            (Value::Uint(4), arr),
        ]))
        .expect("encode negotiation message")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets) — the id a successor names in its causes.
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a Message from its body bytes alone. Does NOT validate role/profile against the closed
/// sets (that is `verify_message`'s job), so an unknown-role/profile message can be represented.
pub fn parse_message(b: &[u8]) -> Result<Message, cose::Error> {
    let m = decode_map(b)?;
    let negotiation = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let role = uint_field(&m, 2).ok_or_else(err_malformed)?;
    let profile = uint_field(&m, 3).ok_or_else(err_malformed)?;
    let causes_v = field(&m, 4).ok_or_else(err_malformed)?;
    let arr = match causes_v {
        Value::Arr(a) => a,
        _ => return Err(err_malformed()),
    };
    let mut causes = Vec::with_capacity(arr.len());
    for e in arr {
        match e {
            Value::Bstr(bs) => causes.push(bs.clone()),
            _ => return Err(err_malformed()),
        }
    }
    Ok(Message {
        negotiation,
        role,
        profile,
        causes,
    })
}

/// Produce the tagged COSE_Sign1 object over the Message body.
pub fn sign_message(m: &Message, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &m.bytes())
}

/// Verify the Message's signature under the profile, reconstruct it, and validate it against the
/// closed sets: the role MUST be offer/counter/accept (UnknownRole) and the profile MUST be
/// pre-registered (UnknownProfile). A bad signature propagates from verify1 (BadSignature).
pub fn verify_message(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Message, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let m = parse_message(&payload)?;
    if !known_role(m.role) {
        return Err(err_unknown_role());
    }
    if !is_registered_profile(m.profile) {
        return Err(err_unknown_profile());
    }
    Ok(m)
}

/// Build the content-id -> Message index the descent walk resolves predecessors through.
pub fn index_by_id(msgs: &[Message]) -> HashMap<Vec<u8>, Message> {
    let mut by_id = HashMap::with_capacity(msgs.len());
    for m in msgs {
        by_id.insert(m.id(), m.clone());
    }
    by_id
}

/// Whether `from` reaches `target_id` by following causes edges resolved through `by_id`: a real
/// reachability walk over the causal DAG. A cause that cannot be resolved through `by_id` cannot
/// extend the chain, so a forged pointer to an unseen id does not manufacture descent.
fn descends_impl(from: &Message, target_id: &[u8], by_id: &HashMap<Vec<u8>, Message>) -> bool {
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut stack: Vec<Vec<u8>> = from.causes.clone();
    while let Some(id) = stack.pop() {
        if id.as_slice() == target_id {
            return true;
        }
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(pred) = by_id.get(&id) {
            stack.extend(pred.causes.clone());
        }
    }
    false
}

/// Whether `accept` descends from `offer` by walking the causes DAG through `by_id`. The graph
/// predicate underlying `verify_accept`; performs no signature check.
pub fn descends(accept: &Message, offer: &Message, by_id: &HashMap<Vec<u8>, Message>) -> bool {
    descends_impl(accept, &offer.id(), by_id)
}

/// Check an accept against its offer over a set of verified messages, fail-closed. Requires `offer`
/// to be an offer selecting a pre-registered profile (NotOffer / UnknownProfile); `accept` to be an
/// accept selecting a pre-registered profile (NotAccept / UnknownProfile); and the accept to DESCEND
/// from the offer along the causes DAG (NotDescended otherwise). Returns the AGREED profile (the
/// accept's selected pre-registered profile). Authorizes nothing.
pub fn verify_accept(
    accept: &Message,
    offer: &Message,
    by_id: &HashMap<Vec<u8>, Message>,
) -> Result<u64, cose::Error> {
    if offer.role != ROLE_OFFER {
        return Err(err_not_offer());
    }
    if !is_registered_profile(offer.profile) {
        return Err(err_unknown_profile());
    }
    if accept.role != ROLE_ACCEPT {
        return Err(err_not_accept());
    }
    if !is_registered_profile(accept.profile) {
        return Err(err_unknown_profile());
    }
    if !descends(accept, offer, by_id) {
        return Err(err_not_descended());
    }
    Ok(accept.profile)
}

// ==== Task 5.2 — advisory risk labels =========================================================

/// A risk label's advisory class in the vocabulary: informing (0) or gating (1). A REGISTRY attribute
/// of the label code, distinct from the per-carriage critical flag.
pub const CLASS_INFORMING: u64 = 0;
pub const CLASS_GATING: u64 = 1;

/// The class name ("gating"/"informing"), or "" for an out-of-range value.
pub fn risk_class_name(c: u64) -> &'static str {
    match c {
        CLASS_INFORMING => "informing",
        CLASS_GATING => "gating",
        _ => "",
    }
}

/// Registered standard risk-label codes.
pub const RISK_SENSITIVE: u64 = 1; // gating: the object touches sensitive material
pub const RISK_EGRESS: u64 = 2; // gating: the object causes data egress
pub const RISK_REVERSIBLE: u64 = 3; // informing: the object's effect is reversible

/// The first code of the private/experimental extensible range. A code at or above it is not in the
/// standard vocabulary and is unknown to a verifier that lacks it.
pub const EXTENSIBLE_RANGE_START: u64 = 0x1000;

/// A code's vocabulary class, and whether the code is a registered standard label.
pub fn risk_class_of(code: u64) -> Option<u64> {
    match code {
        RISK_SENSITIVE => Some(CLASS_GATING),
        RISK_EGRESS => Some(CLASS_GATING),
        RISK_REVERSIBLE => Some(CLASS_INFORMING),
        _ => None,
    }
}

/// Whether `code` is in the closed standard vocabulary.
pub fn is_registered_risk(code: u64) -> bool {
    risk_class_of(code).is_some()
}

/// Whether `code` lies in the private/experimental extensible range.
pub fn in_extensible_range(code: u64) -> bool {
    code >= EXTENSIBLE_RANGE_START
}

/// One advisory risk label carried on an object. `critical` is the per-carriage must-understand flag
/// (1 = critical, 0 = advisory) — the uint 1/0, no CBOR boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskLabel {
    pub code: u64,
    pub critical: u64,
}

impl RiskLabel {
    /// Whether the label is carried critical (must-understand).
    pub fn is_critical(&self) -> bool {
        self.critical == 1
    }
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.code)),
            (Value::Uint(2), Value::Uint(self.critical)),
        ])
    }
    /// Deterministic-CBOR {1: code, 2: critical}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode risk label")
    }
}

fn risk_label_from_value(v: &Value) -> Result<RiskLabel, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_malformed()),
    };
    let code = uint_field(m, 1).ok_or_else(err_malformed)?;
    let critical = uint_field(m, 2).ok_or_else(err_malformed)?;
    if critical > 1 {
        return Err(err_critical_flag());
    }
    Ok(RiskLabel { code, critical })
}

/// Apply the critical-extension rule (R-2.5) to a set of carried risk labels: return the RECOGNIZED
/// (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL
/// label (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. NEVER inspects
/// or returns an effect — risk labels are an advisory dimension, never a fifth effect. Fail-closed.
pub fn validate_labels(labels: &[RiskLabel]) -> Result<Vec<RiskLabel>, cose::Error> {
    let mut recognized = Vec::with_capacity(labels.len());
    for l in labels {
        if l.critical > 1 {
            return Err(err_critical_flag());
        }
        if is_registered_risk(l.code) {
            recognized.push(l.clone());
            continue;
        }
        if l.is_critical() {
            return Err(err_unknown_critical_risk()); // R-2.5: an unknown must-understand label is rejected
        }
        // unknown non-critical: ignored (dropped from the recognized set)
    }
    Ok(recognized)
}

/// A minimal N-AALP object carrying an effect (field 7, C5) and a set of advisory risk labels. It
/// demonstrates — provably, in isolation — that carrying a risk label NEVER changes the effect class.
#[derive(Debug, Clone)]
pub struct LabeledObject {
    pub effect: u64,
    pub labels: Vec<RiskLabel>,
}

impl LabeledObject {
    /// Deterministic-CBOR {1: effect, 2: labels[]}.
    pub fn bytes(&self) -> Vec<u8> {
        let arr = Value::Arr(self.labels.iter().map(|l| l.to_value()).collect());
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.effect)),
            (Value::Uint(2), arr),
        ]))
        .expect("encode labeled object")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// The object's C5 effect class, derived from the effect field ALONE and normalized fail-closed
    /// (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels: a risk label
    /// is an advisory dimension, never a fifth effect, so the closed lattice is untouched by any label.
    /// The load-bearing C20 invariant; the mutation test proves read_only+sensitive stays read_only.
    pub fn effect_class(&self) -> u8 {
        policy::normalize_effect(self.effect)
    }
    /// Apply the critical-extension rule to the object's carried labels.
    pub fn validate_labels(&self) -> Result<Vec<RiskLabel>, cose::Error> {
        validate_labels(&self.labels)
    }
}

/// Reconstruct a LabeledObject from its body bytes alone.
pub fn parse_labeled_object(b: &[u8]) -> Result<LabeledObject, cose::Error> {
    let m = decode_map(b)?;
    let effect = uint_field(&m, 1).ok_or_else(err_malformed)?;
    let labels_v = field(&m, 2).ok_or_else(err_malformed)?;
    let arr = match labels_v {
        Value::Arr(a) => a,
        _ => return Err(err_malformed()),
    };
    let mut labels = Vec::with_capacity(arr.len());
    for e in arr {
        labels.push(risk_label_from_value(&e)?);
    }
    Ok(LabeledObject { effect, labels })
}

/// Produce the tagged COSE_Sign1 object over the LabeledObject body.
pub fn sign_labeled_object(o: &LabeledObject, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &o.bytes())
}

/// Verify the signature, reconstruct the object, and apply the critical-extension rule to its labels
/// (an unknown critical label is rejected). Returns the object and its recognized labels. The
/// object's effect class is unchanged by any label. Fail-closed.
pub fn verify_labeled_object(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<(LabeledObject, Vec<RiskLabel>), cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let o = parse_labeled_object(&payload)?;
    let recognized = validate_labels(&o.labels)?;
    Ok((o, recognized))
}

// ==== Task 5.3 — trust references (checkable, never weighed) ==================================

/// A third-party trust statement carried as a CHECKABLE signed object. `registry` is an opaque
/// external-registry identifier (an ERC-8004-style reputation/identity registry — a name, not a URL
/// the wire resolves); `reference` is the T1 content-id of the referenced external record; `subject`
/// is the opaque id the statement is about. NO field here weighs it — no score, rank, or ordering.
#[derive(Debug, Clone)]
pub struct TrustRef {
    pub registry: Vec<u8>,
    pub reference: Vec<u8>,
    pub subject: Vec<u8>,
}

impl TrustRef {
    /// Deterministic-CBOR {1: registry, 2: reference, 3: subject}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.registry.clone())),
            (Value::Uint(2), Value::Bstr(self.reference.clone())),
            (Value::Uint(3), Value::Bstr(self.subject.clone())),
        ]))
        .expect("encode trust ref")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// The TrustRef's own T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// Whether the carried `reference` is the T1 content-id of `record` — i.e. the reference recomputes
    /// over the presented external bytes. The CHECK a relying party runs; it computes NO score. A
    /// changed record yields a different content-id, so this returns false.
    pub fn binds_record(&self, record: &[u8]) -> bool {
        self.reference == content_id(record)
    }
    /// The content-id the trust ref binds (the carried external-record reference) — mirrors Go
    /// TrustRef.ReferenceID() (negotiation.go:553).
    pub fn reference_id(&self) -> Vec<u8> {
        self.reference.clone()
    }
}

/// Reconstruct a TrustRef from its body bytes alone.
pub fn parse_trust_ref(b: &[u8]) -> Result<TrustRef, cose::Error> {
    let m = decode_map(b)?;
    let registry = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let reference = bstr_field(&m, 2).ok_or_else(err_malformed)?;
    let subject = bstr_field(&m, 3).ok_or_else(err_malformed)?;
    Ok(TrustRef {
        registry,
        reference,
        subject,
    })
}

/// Produce the tagged COSE_Sign1 object over the TrustRef body.
pub fn sign_trust_ref(r: &TrustRef, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &r.bytes())
}

/// A TrustRef that has passed signature verification and the content-id recompute. It carries NO
/// score, rank, or trust weight — the protocol does not weigh trust; which statement to believe is
/// left to the relying party.
#[derive(Debug, Clone)]
pub struct ResolvedTrustRef {
    pub registry: Vec<u8>,
    pub reference: Vec<u8>,
    pub subject: Vec<u8>,
}

/// Verify a trust reference end-to-end: verify the signature under the profile; reconstruct it; and
/// confirm the reference by RECOMPUTING the external record's content-id and requiring it to equal the
/// carried reference (ReferenceMismatch otherwise). Returns the resolved reference — and NOTHING that
/// scores it: this module has no trust-weighting function, by design. Fail-closed.
pub fn verify_trust_ref(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
    external_record: &[u8],
) -> Result<ResolvedTrustRef, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let r = parse_trust_ref(&payload)?;
    if !r.binds_record(external_record) {
        return Err(err_reference_mismatch());
    }
    Ok(ResolvedTrustRef {
        registry: r.registry,
        reference: r.reference,
        subject: r.subject,
    })
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
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/negotiation/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn msg_from(c: &J, neg: &[u8], mv: &J) -> Message {
        let causes = mv["causes_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hexd(h.as_str().unwrap()))
            .collect();
        let _ = c;
        Message {
            negotiation: neg.to_vec(),
            role: mv["role"].as_u64().unwrap(),
            profile: mv["profile"].as_u64().unwrap(),
            causes,
        }
    }

    fn carried_labels(c: &J) -> Vec<RiskLabel> {
        c["risk"]["carried_on_labeled_objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| RiskLabel {
                code: l["code"].as_u64().unwrap(),
                critical: l["critical"].as_u64().unwrap(),
            })
            .collect()
    }

    fn labels_from(arr: &J) -> Vec<RiskLabel> {
        arr.as_array()
            .unwrap()
            .iter()
            .map(|l| RiskLabel {
                code: l["code"].as_u64().unwrap(),
                critical: l["critical"].as_u64().unwrap(),
            })
            .collect()
    }

    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk))
    }

    // Byte-parity: Rust encoding == the same non-circular Python oracle -> Rust == Go on every C20
    // wire object body, head, id.
    #[test]
    fn bodies_match_oracle() {
        let c = load();
        let neg = hexd(c["negotiation"]["negotiation_hex"].as_str().unwrap());
        for key in [
            "offer",
            "counter",
            "accept",
            "offer2",
            "accept_not_descended",
            "unknown_profile_offer",
            "unknown_role_message",
        ] {
            let mv = &c["negotiation"][key];
            let m = msg_from(&c, &neg, mv);
            assert_eq!(
                hex::encode(m.bytes()),
                mv["body_hex"].as_str().unwrap(),
                "{key} body"
            );
            assert_eq!(
                hex::encode(m.head()),
                mv["head_hex"].as_str().unwrap(),
                "{key} head"
            );
            assert_eq!(
                hex::encode(m.id()),
                mv["id_hex"].as_str().unwrap(),
                "{key} id"
            );
        }

        let labels = carried_labels(&c);
        for lo in c["risk"]["labeled_objects"].as_array().unwrap() {
            let effect = lo["effect"].as_u64().unwrap();
            let with = LabeledObject {
                effect,
                labels: labels.clone(),
            };
            assert_eq!(
                hex::encode(with.bytes()),
                lo["with_labels"]["body_hex"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(with.head()),
                lo["with_labels"]["head_hex"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(with.id()),
                lo["with_labels"]["id_hex"].as_str().unwrap()
            );
            let without = LabeledObject {
                effect,
                labels: vec![],
            };
            assert_eq!(
                hex::encode(without.bytes()),
                lo["without_labels"]["body_hex"].as_str().unwrap()
            );
        }

        let t = &c["trust"];
        let ref_a = TrustRef {
            registry: hexd(t["registry_a_hex"].as_str().unwrap()),
            reference: hexd(t["reference_hex"].as_str().unwrap()),
            subject: hexd(t["subject_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(ref_a.bytes()),
            t["ref_a"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(ref_a.head()),
            t["ref_a"]["head_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(ref_a.id()),
            t["ref_a"]["id_hex"].as_str().unwrap()
        );
        let ref_b = TrustRef {
            registry: hexd(t["registry_b_hex"].as_str().unwrap()),
            reference: hexd(t["reference_hex"].as_str().unwrap()),
            subject: hexd(t["subject_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(ref_b.bytes()),
            t["ref_b"]["body_hex"].as_str().unwrap()
        );
    }

    // Governed negotiation: an accept descends from its offer (via a counter) and yields the agreed
    // pre-registered profile; a non-descended accept is rejected; unknown profile/role are rejected.
    #[test]
    fn descend_from_offer() {
        let c = load();
        let neg = hexd(c["negotiation"]["negotiation_hex"].as_str().unwrap());
        let (s, v) = key(0x11);
        let (_, foreign) = key(0x22);

        let offer = msg_from(&c, &neg, &c["negotiation"]["offer"]);
        let counter = msg_from(&c, &neg, &c["negotiation"]["counter"]);
        let accept = msg_from(&c, &neg, &c["negotiation"]["accept"]);
        let offer2 = msg_from(&c, &neg, &c["negotiation"]["offer2"]);
        let accept_bad = msg_from(&c, &neg, &c["negotiation"]["accept_not_descended"]);

        assert_eq!(counter.causes[0], offer.id());
        assert_eq!(accept.causes[0], counter.id());
        assert_eq!(accept_bad.causes[0], offer2.id());

        let all = vec![
            offer.clone(),
            counter.clone(),
            accept.clone(),
            offer2.clone(),
            accept_bad.clone(),
        ];
        let mut verified = vec![];
        for m in &all {
            let obj = sign_message(m, &s);
            let vm = verify_message(&obj, cose::PROFILE_PUBLIC, &v).expect("verify message");
            assert_eq!(vm.id(), m.id());
            assert_eq!(
                verify_message(&obj, cose::PROFILE_PUBLIC, &foreign)
                    .unwrap_err()
                    .kind,
                "BadSignature"
            );
            verified.push(vm);
        }
        let by_id = index_by_id(&verified);

        assert!(
            descends(&accept, &offer, &by_id),
            "accept must descend from offer"
        );
        let agreed = verify_accept(&accept, &offer, &by_id).expect("honest accept");
        assert_eq!(agreed, c["negotiation"]["agreed_profile"].as_u64().unwrap());

        assert!(
            !descends(&accept_bad, &offer, &by_id),
            "accept_bad must NOT descend from offer"
        );
        assert_eq!(
            verify_accept(&accept_bad, &offer, &by_id).unwrap_err().kind,
            "NotDescended"
        );

        let unk_prof = sign_message(
            &msg_from(&c, &neg, &c["negotiation"]["unknown_profile_offer"]),
            &s,
        );
        assert_eq!(
            verify_message(&unk_prof, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "UnknownProfile"
        );
        let unk_role = sign_message(
            &msg_from(&c, &neg, &c["negotiation"]["unknown_role_message"]),
            &s,
        );
        assert_eq!(
            verify_message(&unk_role, cose::PROFILE_PUBLIC, &v)
                .unwrap_err()
                .kind,
            "UnknownRole"
        );

        assert_eq!(
            verify_accept(&accept, &counter, &by_id).unwrap_err().kind,
            "NotOffer"
        );
        assert_eq!(
            verify_accept(&counter, &offer, &by_id).unwrap_err().kind,
            "NotAccept"
        );

        assert!(!is_registered_profile(
            c["negotiation"]["unknown_profile"].as_u64().unwrap()
        ));
        for p in [PROFILE_BASELINE, PROFILE_STREAMING, PROFILE_BATCH] {
            assert!(is_registered_profile(p));
        }
    }

    // Grades three surfaces that were previously carried only in diagnostic strings and never
    // asserted: role_name()/profile_name() must equal the exact name string the independent oracle
    // assigns to each closed-set code (vectors/negotiation/cases.json negotiation.roles /
    // negotiation.profiles — the oracle's own name->code assignment, cross-checked against the
    // ROLE_*/PROFILE_* constants used to build the corpus), and TrustRef::reference_id() must return
    // exactly the carried reference bytes (trust.reference_hex). Mutation: swap any two arms of
    // role_name/profile_name, or have reference_id return subject instead of reference, and this
    // fails.
    #[test]
    fn role_profile_names_and_reference_id_match_oracle() {
        let c = load();
        let roles = c["negotiation"]["roles"].as_object().unwrap();
        assert_eq!(roles.len(), 3, "expected 3 roles in the corpus");
        for (name, code) in roles {
            assert_eq!(role_name(code.as_u64().unwrap()), name, "role {code}");
        }
        let profiles = c["negotiation"]["profiles"].as_object().unwrap();
        assert_eq!(profiles.len(), 3, "expected 3 profiles in the corpus");
        for (name, code) in profiles {
            assert_eq!(profile_name(code.as_u64().unwrap()), name, "profile {code}");
        }
        // An out-of-range code names neither.
        assert_eq!(role_name(99), "unknown");
        assert_eq!(profile_name(99), "unknown");

        let t = &c["trust"];
        let reference = hexd(t["reference_hex"].as_str().unwrap());
        let r = TrustRef {
            registry: hexd(t["registry_a_hex"].as_str().unwrap()),
            reference: reference.clone(),
            subject: hexd(t["subject_hex"].as_str().unwrap()),
        };
        assert_eq!(hex::encode(r.reference_id()), t["reference_hex"].as_str().unwrap());
        assert_eq!(r.reference_id(), reference);
    }

    // Load-bearing C20 invariant: carrying a risk label NEVER changes the effect class. For every
    // effect class, the object with the gating labels resolves to the SAME class as the same object
    // with no labels, and to the oracle's normalized effect. Mutation: if effect_class consulted a
    // gating label to escalate, the read_only+sensitive object would resolve to destructive => FAIL.
    #[test]
    fn risk_label_effect_class_unchanged() {
        let c = load();
        let labels = carried_labels(&c);
        assert!(
            labels
                .iter()
                .any(|l| risk_class_of(l.code) == Some(CLASS_GATING)),
            "corpus must carry a gating label so the mutation seam is exercised"
        );
        for lo in c["risk"]["labeled_objects"].as_array().unwrap() {
            let effect = lo["effect"].as_u64().unwrap();
            let with = LabeledObject {
                effect,
                labels: labels.clone(),
            };
            let without = LabeledObject {
                effect,
                labels: vec![],
            };
            let want = policy::normalize_effect(effect);
            assert_eq!(
                with.effect_class(),
                want,
                "a label changed the effect for {effect}"
            );
            assert_eq!(without.effect_class(), want);
            assert_eq!(
                with.effect_class(),
                without.effect_class(),
                "labels changed the effect class"
            );
            assert_eq!(
                with.effect_class() as u64,
                lo["effect_class"].as_u64().unwrap()
            );
        }
        let sensitive = LabeledObject {
            effect: policy::READ_ONLY as u64,
            labels: vec![RiskLabel {
                code: RISK_SENSITIVE,
                critical: 1,
            }],
        };
        assert_eq!(
            sensitive.effect_class(),
            policy::READ_ONLY,
            "a risk label must not escalate the effect"
        );
    }

    // R-2.5 over risk labels: an unknown critical label is rejected; an unknown non-critical label is
    // ignored; a recognized label is kept; the vocabulary/class matches the oracle.
    #[test]
    fn risk_label_critical_extension_rule() {
        let c = load();
        for e in c["risk"]["vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            let class = risk_class_of(code).expect("registered");
            assert_eq!(risk_class_name(class), e["class"].as_str().unwrap());
        }
        assert_eq!(
            EXTENSIBLE_RANGE_START,
            c["risk"]["extensible_range_start"].as_u64().unwrap()
        );

        let rec_set = labels_from(&c["risk"]["validate"]["recognized_set"]["carried"]);
        let got = validate_labels(&rec_set).expect("recognized set");
        let want: Vec<u64> = c["risk"]["validate"]["recognized_set"]["recognized_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap())
            .collect();
        assert_eq!(got.len(), want.len());
        for (i, l) in got.iter().enumerate() {
            assert_eq!(l.code, want[i]);
            assert!(is_registered_risk(l.code));
        }

        let crit_set = labels_from(&c["risk"]["validate"]["unknown_critical_rejected"]["carried"]);
        assert_eq!(
            validate_labels(&crit_set).unwrap_err().kind,
            "UnknownCriticalRisk"
        );

        let bad = LabeledObject {
            effect: 0,
            labels: vec![RiskLabel {
                code: RISK_SENSITIVE,
                critical: 2,
            }],
        };
        assert_eq!(
            parse_labeled_object(&bad.bytes()).unwrap_err().kind,
            "MalformedCriticalFlag"
        );
    }

    // A carried registry reference verifies (content-id recomputes + signature checks) but nothing on
    // the wire scores it; a tampered record no longer recomputes; two registries verify symmetrically.
    #[test]
    fn trust_ref_checkable_never_weighed() {
        let c = load();
        let t = &c["trust"];
        let (s, v) = key(0x11);
        let (_, foreign) = key(0x22);
        let record = hexd(t["external_record_hex"].as_str().unwrap());
        let reference = hexd(t["reference_hex"].as_str().unwrap());
        let tampered = hexd(t["tampered_record_hex"].as_str().unwrap());

        let ref_a = TrustRef {
            registry: hexd(t["registry_a_hex"].as_str().unwrap()),
            reference: reference.clone(),
            subject: hexd(t["subject_hex"].as_str().unwrap()),
        };
        assert!(
            ref_a.binds_record(&record),
            "ref must bind the external record"
        );
        assert!(
            !ref_a.binds_record(&tampered),
            "a tampered record must not recompute"
        );

        let obj = sign_trust_ref(&ref_a, &s);
        let r =
            verify_trust_ref(&obj, cose::PROFILE_PUBLIC, &v, &record).expect("honest trust ref");
        assert_eq!(r.reference, reference);
        assert_eq!(
            verify_trust_ref(&obj, cose::PROFILE_PUBLIC, &v, &tampered)
                .unwrap_err()
                .kind,
            "ReferenceMismatch"
        );
        assert_eq!(
            verify_trust_ref(&obj, cose::PROFILE_PUBLIC, &foreign, &record)
                .unwrap_err()
                .kind,
            "BadSignature"
        );

        let ref_b = TrustRef {
            registry: hexd(t["registry_b_hex"].as_str().unwrap()),
            reference: reference.clone(),
            subject: hexd(t["subject_hex"].as_str().unwrap()),
        };
        let obj_b = sign_trust_ref(&ref_b, &s);
        let r_b = verify_trust_ref(&obj_b, cose::PROFILE_PUBLIC, &v, &record).expect("registry B");
        assert_eq!(
            r.reference, r_b.reference,
            "same record, symmetric verification"
        );
        assert_ne!(
            r.registry, r_b.registry,
            "fixture: the two registries must differ"
        );
    }

    // A body that is not a well-formed message/label/object/ref is NegMalformed (fail-closed).
    #[test]
    fn malformed_rejected() {
        assert_eq!(parse_message(&[0x00]).unwrap_err().kind, "NegMalformed");
        assert_eq!(parse_trust_ref(&[0x80]).unwrap_err().kind, "NegMalformed");
        assert_eq!(
            parse_labeled_object(&[0x00]).unwrap_err().kind,
            "NegMalformed"
        );
    }

    // Cross-language signature bit-identity: signing the offer body, the read_only-with-labels labeled
    // object, and the trust-ref A body with the shared 0x11*32 seed must produce COSE_Sign1 objects
    // whose SHA-384 equals the values the Go negotiation test pins — Go and Rust emit byte-identical
    // signed C20 objects (deterministic ML-DSA-65 over identical canonical CBOR). Mutation: any
    // encoding/signing-input drift breaks a pin.
    #[test]
    fn cross_lang_signed_negotiation_pin() {
        const PIN_OFFER: &str = "28b5c4e082cfae270bcc0317ef95c88c451f5af7c0d984b2120496afad4870964845b699fe501bb8cd6fab99298729fd";
        const PIN_LABELED: &str = "c6f4ba4c897f2f34f075ec504cd8329da7b138764cac5f4b7dcd120348b15d36fab9bf55bb5302dd024f1b077ecc1a0c";
        const PIN_TRUSTREF: &str = "80a7d8302bdb01d0fec577a28a4cb0e37c540f80c4d588a8be8324d9e80229fbf3f6a850c6c50d24ca1991e03b84699f";
        let c = load();
        let neg = hexd(c["negotiation"]["negotiation_hex"].as_str().unwrap());
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);

        let offer = msg_from(&c, &neg, &c["negotiation"]["offer"]);
        let offer_obj = sign_message(&offer, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&offer_obj)),
            PIN_OFFER,
            "signed offer digest differs from the Go pin"
        );

        let labeled = LabeledObject {
            effect: c["risk"]["labeled_objects"][0]["effect"].as_u64().unwrap(),
            labels: carried_labels(&c),
        };
        let labeled_obj = sign_labeled_object(&labeled, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&labeled_obj)),
            PIN_LABELED,
            "signed labeled-object digest differs from the Go pin"
        );

        let tref = TrustRef {
            registry: hexd(c["trust"]["registry_a_hex"].as_str().unwrap()),
            reference: hexd(c["trust"]["reference_hex"].as_str().unwrap()),
            subject: hexd(c["trust"]["subject_hex"].as_str().unwrap()),
        };
        let tref_obj = sign_trust_ref(&tref, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&tref_obj)),
            PIN_TRUSTREF,
            "signed trust-ref digest differs from the Go pin"
        );
    }

    // ---- standard wire-format edge cases (Part 1) --------------------------------------------

    // Edge case #1: an offer body with top-level keys in DESCENDING order (4,3,2,1) is rejected
    // NonCanonical by the strict shared decoder parse_message routes through; the canonical body parses.
    #[test]
    fn keys_out_of_order_rejected() {
        let c = load();
        let e = &c["edge_cases"]["keys_out_of_order"];
        let offer = Message {
            negotiation: b"neg-0001".to_vec(),
            role: ROLE_OFFER,
            profile: PROFILE_BASELINE,
            causes: vec![],
        };
        assert_eq!(
            hex::encode(offer.bytes()),
            e["canonical_offer_body_hex"].as_str().unwrap(),
            "canonical offer body"
        );
        let canon = hexd(e["canonical_offer_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_offer_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical offer body should decode");
        parse_message(&canon).expect("canonical offer body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key offer body decoded (want NonCanonical)"),
        }
        assert_eq!(parse_message(&noncanon).unwrap_err().kind, "NegMalformed");
    }

    // Edge case #2 (causes[]): an empty causes[] is distinct by content-id from a populated one; both
    // differ from a body whose causes field is ABSENT (rejected NegMalformed — field 4 is mandatory).
    #[test]
    fn empty_vs_absent_causes() {
        let c = load();
        let ec = &c["edge_cases"]["empty_vs_absent"]["causes"];
        let neg = b"neg-0001".to_vec();
        let empty = Message {
            negotiation: neg.clone(),
            role: ROLE_OFFER,
            profile: PROFILE_BASELINE,
            causes: vec![],
        };
        let one = Message {
            negotiation: neg,
            role: ROLE_OFFER,
            profile: PROFILE_BASELINE,
            causes: vec![hexd(ec["one_cause"]["cause_hex"].as_str().unwrap())],
        };
        assert_eq!(
            hex::encode(empty.bytes()),
            ec["empty_present"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(one.bytes()),
            ec["one_cause"]["body_hex"].as_str().unwrap()
        );
        assert_ne!(
            empty.id(),
            one.id(),
            "empty vs one-cause must differ by content-id"
        );
        assert_eq!(
            hex::encode(empty.id()),
            ec["empty_present"]["id_hex"].as_str().unwrap()
        );
        parse_message(&empty.bytes()).expect("empty causes parses");
        parse_message(&one.bytes()).expect("one cause parses");
        assert_eq!(
            parse_message(&hexd(ec["absent_field"]["body_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "NegMalformed"
        );
    }

    // Edge case #2 (labels[]): an empty labels[] is distinct by content-id from a populated one; both
    // differ from a body whose labels field is ABSENT (rejected NegMalformed — field 2 is mandatory).
    #[test]
    fn empty_vs_absent_labels() {
        let c = load();
        let el = &c["edge_cases"]["empty_vs_absent"]["labels"];
        let empty = LabeledObject {
            effect: 0,
            labels: vec![],
        };
        let one = LabeledObject {
            effect: 0,
            labels: vec![RiskLabel {
                code: el["one_label"]["code"].as_u64().unwrap(),
                critical: el["one_label"]["critical"].as_u64().unwrap(),
            }],
        };
        assert_eq!(
            hex::encode(empty.bytes()),
            el["empty_present"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(one.bytes()),
            el["one_label"]["body_hex"].as_str().unwrap()
        );
        assert_ne!(
            empty.id(),
            one.id(),
            "empty vs one-label must differ by content-id"
        );
        assert_eq!(
            hex::encode(empty.id()),
            el["empty_present"]["id_hex"].as_str().unwrap()
        );
        parse_labeled_object(&empty.bytes()).expect("empty labels parses");
        parse_labeled_object(&one.bytes()).expect("one label parses");
        assert_eq!(
            parse_labeled_object(&hexd(el["absent_field"]["body_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "NegMalformed"
        );
    }

    // Edge case #4: the smallest legal offer, labeled-object, and trust-ref each encode to the oracle
    // bytes, have a stable content-id, and round-trip through their parse.
    #[test]
    fn minimal() {
        let c = load();
        let m = &c["edge_cases"]["minimal"];
        let offer = Message {
            negotiation: vec![],
            role: ROLE_OFFER,
            profile: PROFILE_BASELINE,
            causes: vec![],
        };
        assert_eq!(
            hex::encode(offer.bytes()),
            m["offer"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(offer.id()),
            m["offer"]["id_hex"].as_str().unwrap()
        );
        parse_message(&offer.bytes()).expect("parse minimal offer");
        let lo = LabeledObject {
            effect: m["labeled_object"]["effect"].as_u64().unwrap(),
            labels: vec![],
        };
        assert_eq!(
            hex::encode(lo.bytes()),
            m["labeled_object"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(lo.id()),
            m["labeled_object"]["id_hex"].as_str().unwrap()
        );
        parse_labeled_object(&lo.bytes()).expect("parse minimal labeled-object");
        let tr = TrustRef {
            registry: vec![],
            reference: vec![],
            subject: vec![],
        };
        assert_eq!(
            hex::encode(tr.bytes()),
            m["trust_ref"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(tr.id()),
            m["trust_ref"]["id_hex"].as_str().unwrap()
        );
        parse_trust_ref(&tr.bytes()).expect("parse minimal trust-ref");
    }

    // Edge case #5 (cross-KIND look-alike beyond the offer/accept role-literal): a trust-ref body fed to
    // parse_message and a message body fed to parse_trust_ref are each rejected NegMalformed.
    #[test]
    fn look_alike_rejected() {
        let c = load();
        let la = &c["edge_cases"]["look_alike"];
        assert_eq!(
            parse_message(&hexd(
                la["trust_ref_as_message"]["body_hex"].as_str().unwrap()
            ))
            .unwrap_err()
            .kind,
            "NegMalformed"
        );
        assert_eq!(
            parse_trust_ref(&hexd(
                la["message_as_trust_ref"]["body_hex"].as_str().unwrap()
            ))
            .unwrap_err()
            .kind,
            "NegMalformed"
        );
    }
}
