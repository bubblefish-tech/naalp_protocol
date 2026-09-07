// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C21 task 5B.3 — the portable gateway decision object (design.md §24; R-GW-1..6). The Rust half of
//! the two-implementation parity; byte-identical to impl/go/gateway.
//!
//! A `GatewayDecision` is a SIGNED decision object an enforcement gateway of ANY vendor emits as
//! PORTABLE EVIDENCE. Its authority is the SIGNATURE OVER THE BYTES, never the connection or host that
//! served them: `verify_decision` takes NO serving-party/connection identity, so the same signed
//! decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the third-party
//! re-serve property). It introduces NO new mechanism (R-11.3): an ordinary COSE_Sign1 over a
//! deterministic-CBOR body, reusing the closed C5 effect lattice (policy) and the T1 content-id framing.
//! This defines the EVIDENCE FORMAT ONLY — never a policy language.
//!
//!   - `GatewayDecision` {1: decision, 2: action, 3: policy, 4: effect}. `decision` is a closed set
//!     (allow / deny / hold); `action` is the T1 content id of the action decided about; `policy` is the
//!     opaque deciding-policy identity (a name, NOT a program); `effect` is the C5 effect class.
//!
//! Fail-closed (§15): a failing object is rejected whole, returns its named error, no state change.

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;
use crate::policy;

// Reuse the S1 `OrderingDisclosure` embeddable group (field 5, R1) unchanged — it lives in
// `crate::evidence_record` (byte-identical Rust half of the ordering-disclosure family already
// implemented there); re-exported here so `gateway::OrderingDisclosure` mirrors the Go package
// layout, where ordering.go lives directly inside `package gateway`.
pub use crate::evidence_record::OrderingDisclosure;

/// Width of a head / content-id digest (SHA-384 = 48 bytes).
pub const HEAD_SIZE: usize = 48;

/// Decision codes — the closed set a gateway may emit. A code outside the set is rejected.
pub const DECISION_ALLOW: u64 = 0;
pub const DECISION_DENY: u64 = 1;
pub const DECISION_HOLD: u64 = 2;

/// The decision name, or "unknown".
pub fn decision_name(code: u64) -> &'static str {
    match code {
        DECISION_ALLOW => "allow",
        DECISION_DENY => "deny",
        DECISION_HOLD => "hold",
        _ => "unknown",
    }
}

/// Whether `code` is one of the closed decision codes.
pub fn is_known_decision(code: u64) -> bool {
    matches!(code, DECISION_ALLOW | DECISION_DENY | DECISION_HOLD)
}

pub fn err_malformed() -> cose::Error {
    cose::Error {
        kind: "GwMalformed",
        msg: "object is not a well-formed N-AALP gateway-decision body",
    }
}
pub fn err_unknown_decision() -> cose::Error {
    cose::Error {
        kind: "UnknownGatewayDecision",
        msg: "gateway decision code is outside the closed set allow/deny/hold",
    }
}
/// Field 6 (naalp-foreign-profile-pin, R8): registered as code 129 in the FROZEN CDDL
/// naalp-error-code enum.
pub fn err_foreign_profile_malformed() -> cose::Error {
    cose::Error {
        kind: "ForeignProfileMalformed",
        msg: "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)",
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

/// A signed decision an enforcement gateway emits as portable evidence. `ordering` (field 5, R1)
/// and `foreign_profile` (field 6, R8) are OPTIONAL: `None` reads exactly as an absent field
/// (correspondence-only ordering / no foreign-profile pin) — never a stronger claim inferred from
/// silence.
#[derive(Debug, Clone)]
pub struct GatewayDecision {
    pub decision: u64,
    pub action: Vec<u8>, // content id of the action decided about
    pub policy: Vec<u8>, // the deciding policy's opaque identity (NOT a policy language)
    pub effect: u64,     // the C5 effect class of the action
    pub ordering: Option<OrderingDisclosure>, // OPTIONAL field 5 (R1)
    pub foreign_profile: Option<ForeignProfilePin>, // OPTIONAL field 6 (R8)
}

impl GatewayDecision {
    /// Deterministic-CBOR {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
    /// ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when `None`.
    pub fn bytes(&self) -> Vec<u8> {
        let mut pairs = vec![
            (Value::Uint(1), Value::Uint(self.decision)),
            (Value::Uint(2), Value::Bstr(self.action.clone())),
            (Value::Uint(3), Value::Bstr(self.policy.clone())),
            (Value::Uint(4), Value::Uint(self.effect)),
        ];
        if let Some(o) = &self.ordering {
            pairs.push((Value::Uint(5), ordering_to_value(o)));
        }
        if let Some(fp) = &self.foreign_profile {
            pairs.push((Value::Uint(6), fp.to_value()));
        }
        cbor::encode(&Value::Map(pairs)).expect("encode gateway decision")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// The decision's C5 effect class, normalized fail-closed (unknown -> destructive, R-6.2).
    pub fn effect_class(&self) -> u8 {
        policy::normalize_effect(self.effect)
    }
}

/// Reconstruct a GatewayDecision from its body bytes alone. Does NOT validate the decision code
/// against the closed set, the ordering-disclosure's basis-conditioned well-formedness, or the
/// foreign-profile-pin's field well-formedness (that is `verify_decision`'s job, mirroring the
/// decision-record parse/validate split). It DOES enforce field-1-4 presence/type and, when field
/// 5/6 is PRESENT, that it decodes to the expected CBOR shape: present-with-wrong-type fails here
/// (`err_malformed`), never silently treated as absent. Fail-closed on any malformed shape.
pub fn parse_decision(b: &[u8]) -> Result<GatewayDecision, cose::Error> {
    let m = decode_map(b)?;
    let decision = uint_field(&m, 1).ok_or_else(err_malformed)?;
    let action = bstr_field(&m, 2).ok_or_else(err_malformed)?;
    let policy_id = bstr_field(&m, 3).ok_or_else(err_malformed)?;
    let effect = uint_field(&m, 4).ok_or_else(err_malformed)?;
    let ordering = match field(&m, 5) {
        Some(v) => Some(ordering_from_value(&v).map_err(|_| err_malformed())?),
        None => None,
    };
    let foreign_profile = match field(&m, 6) {
        Some(v) => Some(foreign_profile_from_value(&v).ok_or_else(err_malformed)?),
        None => None,
    };
    Ok(GatewayDecision {
        decision,
        action,
        policy: policy_id,
        effect,
        ordering,
        foreign_profile,
    })
}

/// Encodes an `OrderingDisclosure` as a nested CBOR map VALUE {1: basis, ?2: boundary,
/// ?3: mechanism, ?4: relation} — mirrors `evidence_record::OrderingDisclosure::to_value` (private
/// to that module) exactly, since `gateway` and `evidence_record` are separate Rust modules.
fn ordering_to_value(o: &OrderingDisclosure) -> Value {
    let mut pairs = vec![(Value::Uint(1), Value::Uint(o.basis))];
    if let Some(b) = &o.boundary {
        pairs.push((Value::Uint(2), Value::Bstr(b.clone())));
    }
    if let Some(m) = &o.mechanism {
        pairs.push((Value::Uint(3), Value::Bstr(m.clone())));
    }
    if let Some(r) = &o.relation {
        pairs.push((Value::Uint(4), Value::Bstr(r.clone())));
    }
    Value::Map(pairs)
}

/// Decodes a nested ordering-disclosure map value, mirroring
/// `evidence_record::OrderingDisclosure::from_value` exactly: a key present under the WRONG CBOR
/// type fails decode, never silently treated as absent.
fn ordering_from_value(v: &Value) -> Result<OrderingDisclosure, ()> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(()),
    };
    let basis = uint_field(m, 1).ok_or(())?;
    let boundary = bstr_field(m, 2);
    let mechanism = bstr_field(m, 3);
    let relation = bstr_field(m, 4);
    if (field(m, 2).is_some() && boundary.is_none())
        || (field(m, 3).is_some() && mechanism.is_none())
        || (field(m, 4).is_some() && relation.is_none())
    {
        return Err(());
    }
    Ok(OrderingDisclosure {
        basis,
        boundary,
        mechanism,
        relation,
    })
}

/// The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
/// `GatewayDecision.foreign_profile` (field 6) iff the decision was over foreign-protocol
/// evidence: it pins the foreign evidence profile's identifier (an absolute URI) AND the revision
/// pinned at decision time — binding the reference, not just the class. Both fields are mandatory
/// tstr; the group carries no other keys. Never a top-level signed object — always embedded as
/// field 6 of its carrying naalp-gateway-decision, so it has no head/id of its own (mirroring
/// `OrderingDisclosure`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForeignProfilePin {
    pub id: String,
    pub revision: String,
    extra: bool, // an unrecognized key besides 1/2 was present in the decoded CBOR map
}

impl ForeignProfilePin {
    pub fn new(id: impl Into<String>, revision: impl Into<String>) -> Self {
        ForeignProfilePin {
            id: id.into(),
            revision: revision.into(),
            extra: false,
        }
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.id.clone())),
            (Value::Uint(2), Value::Tstr(self.revision.clone())),
        ])
    }

    /// Well-formedness (R8): both id and revision are mandatory non-empty tstr, and no key besides
    /// 1/2 may be present. A missing, empty, or extra field rejects the WHOLE carrying
    /// naalp-gateway-decision (ForeignProfileMalformed).
    pub fn validate(&self) -> Result<(), cose::Error> {
        if self.id.is_empty() || self.revision.is_empty() || self.extra {
            return Err(err_foreign_profile_malformed());
        }
        Ok(())
    }
}

/// Decodes a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
/// `ordering_from_value`: a key present under the WRONG CBOR type fails decode (`None`, never
/// silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving
/// the mandatory-presence check to `validate` (mirroring `OrderingDisclosure`'s own
/// decode/validate split). A key besides 1/2 marks the group `extra`, also caught by `validate` —
/// the closed 2-key set is enforced semantically, not by refusing to decode a map that merely
/// carries an extra key.
fn foreign_profile_from_value(v: &Value) -> Option<ForeignProfilePin> {
    let m = match v {
        Value::Map(m) => m,
        _ => return None,
    };
    let mut f = ForeignProfilePin::default();
    if field(m, 1).is_some() {
        f.id = tstr_field(m, 1)?;
    }
    if field(m, 2).is_some() {
        f.revision = tstr_field(m, 2)?;
    }
    for (k, _) in m {
        match k {
            Value::Uint(1) | Value::Uint(2) => {}
            _ => {
                f.extra = true;
                break;
            }
        }
    }
    Some(f)
}

/// Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway.
pub fn sign_decision(d: &GatewayDecision, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &d.bytes())
}

/// A GatewayDecision that has passed signature verification. It carries NOTHING about WHO served the
/// bytes — the authority is the signature, so the resolved evidence is identical regardless of the
/// serving party (the third-party re-serve property).
#[derive(Debug, Clone)]
pub struct ResolvedDecision {
    pub decision: u64,
    pub action: Vec<u8>,
    pub policy: Vec<u8>,
    pub effect: u8,
}

/// Verify a gateway decision end-to-end and return the resolved evidence. Verify the signature under
/// the profile against the GATEWAY's verifier `gateway_v`; reconstruct it (structural only); validate
/// the decision code against the closed set (UnknownGatewayDecision); if field 5 (ordering) is
/// present, its basis-conditioned well-formedness (UnknownOrderingBasis / OrderingDisclosureMalformed);
/// if field 6 (foreign-profile) is present, its own well-formedness (ForeignProfileMalformed).
/// Mandatory fields 1-4 are validated FIRST via `parse_decision`: a body failing a mandatory-field
/// check is GwMalformed regardless of any optional 5/6. It takes NO serving-party identity: the same
/// `obj` yields an identical ResolvedDecision whether the gateway or a third party served it (R-GW-3).
/// Fail-closed.
pub fn verify_decision(
    obj: &[u8],
    profile: u32,
    gateway_v: &dyn cose::CoseVerifier,
) -> Result<ResolvedDecision, cose::Error> {
    cose::verify1(profile, gateway_v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let d = parse_decision(&payload)?;
    if !is_known_decision(d.decision) {
        return Err(err_unknown_decision());
    }
    if let Some(o) = &d.ordering {
        o.check_well_formed()?;
    }
    if let Some(fp) = &d.foreign_profile {
        fp.validate()?;
    }
    Ok(ResolvedDecision {
        decision: d.decision,
        action: d.action.clone(),
        policy: d.policy.clone(),
        effect: policy::normalize_effect(d.effect),
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

fn tstr_field(m: &[(Value, Value)], k: u64) -> Option<String> {
    match field(m, k)? {
        Value::Tstr(s) => Some(s),
        _ => None,
    }
}

// ---- EgressAttestation: E6.3, HELD AT THE WIRE-FREEZE GATE (impl-behind-the-approval-gate) ---
//
// A naalp-egress-attestation is a SIGNED attestation a GATEWAY/SIDECAR emits that an object of a
// given effect class, bound to a given audience, crossed an egress boundary at a given time —
// third-party verifiable WITHOUT the payload. A near-clone of GatewayDecision above: the gateway
// is the SIGNER, and `verify_egress_attestation` takes NO serving-party/connection identity (the
// third-party re-serve property). It introduces NO new envelope, encoding, signature, or identity
// mechanism: an ordinary COSE_Sign1 over a deterministic-CBOR body, reusing the closed C5 effect
// lattice (policy) and the T1 content-id framing.
//
//   - `EgressAttestation` {1: binding, 2: digest, 3: effect, 4: audience, 5: at}. `binding` is a
//     closed set (content_bound=0 / content_free=1); `digest` is either the T1 content-id of the
//     crossed object (content_bound) or a hiding commitment SHA-384(content_id||salt)
//     (content_free); `effect` is the C5 effect class; `audience` is the bound destination
//     (empty-permitted); `at` is the crossing time in epoch milliseconds.
//
// Fail-closed (§15): a failing object is rejected whole, returns its named error, no state change.

/// Binding codes — the closed set an egress attestation may declare. A code outside the set is
/// rejected (UnknownEgressBinding).
pub const BINDING_CONTENT_BOUND: u64 = 0;
pub const BINDING_CONTENT_FREE: u64 = 1;

/// Whether `code` is one of the closed binding codes.
pub fn is_known_binding(code: u64) -> bool {
    matches!(code, BINDING_CONTENT_BOUND | BINDING_CONTENT_FREE)
}

/// The binding name, or "unknown".
pub fn binding_name(code: u64) -> &'static str {
    match code {
        BINDING_CONTENT_BOUND => "content_bound",
        BINDING_CONTENT_FREE => "content_free",
        _ => "unknown",
    }
}

pub fn err_egress_malformed() -> cose::Error {
    cose::Error {
        kind: "EgMalformed",
        msg: "object is not a well-formed N-AALP egress-attestation body",
    }
}
pub fn err_unknown_egress_binding() -> cose::Error {
    cose::Error {
        kind: "UnknownEgressBinding",
        msg: "egress attestation binding code is outside the closed set content_bound/content_free",
    }
}

/// A signed attestation a gateway/sidecar emits that an object crossed an egress boundary.
#[derive(Debug, Clone)]
pub struct EgressAttestation {
    pub binding: u64,
    pub digest: Vec<u8>,  // T1 content-id (content_bound) or commitment (content_free)
    pub effect: u64,      // the C5 effect class of the crossed object
    pub audience: Vec<u8>, // the bound destination (empty-permitted)
    pub at: u64,           // crossing time, epoch milliseconds
}

impl EgressAttestation {
    /// Deterministic-CBOR {1: binding, 2: digest, 3: effect, 4: audience, 5: at}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.binding)),
            (Value::Uint(2), Value::Bstr(self.digest.clone())),
            (Value::Uint(3), Value::Uint(self.effect)),
            (Value::Uint(4), Value::Bstr(self.audience.clone())),
            (Value::Uint(5), Value::Uint(self.at)),
        ]))
        .expect("encode egress attestation")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// The attestation's C5 effect class, normalized fail-closed (unknown -> destructive, R-6.2).
    pub fn effect_class(&self) -> u8 {
        policy::normalize_effect(self.effect)
    }
}

/// Reconstruct an EgressAttestation from its body bytes alone. Does NOT validate the binding code
/// against the closed set (that is `verify_egress_attestation`'s job). Fail-closed on a malformed
/// shape: every one of the five fields is mandatory.
pub fn parse_egress_attestation(b: &[u8]) -> Result<EgressAttestation, cose::Error> {
    let m = decode_map(b).map_err(|_| err_egress_malformed())?;
    let binding = uint_field(&m, 1).ok_or_else(err_egress_malformed)?;
    let digest = bstr_field(&m, 2).ok_or_else(err_egress_malformed)?;
    let effect = uint_field(&m, 3).ok_or_else(err_egress_malformed)?;
    let audience = bstr_field(&m, 4).ok_or_else(err_egress_malformed)?;
    let at = uint_field(&m, 5).ok_or_else(err_egress_malformed)?;
    Ok(EgressAttestation {
        binding,
        digest,
        effect,
        audience,
        at,
    })
}

/// Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway.
pub fn sign_egress_attestation(a: &EgressAttestation, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &a.bytes())
}

/// An EgressAttestation that has passed signature verification. Carries NOTHING about WHO served
/// the bytes — the authority is the signature, so the resolved evidence is identical regardless of
/// the serving party (the third-party re-serve property).
#[derive(Debug, Clone)]
pub struct ResolvedEgressAttestation {
    pub binding: u64,
    pub digest: Vec<u8>,
    pub effect: u8,
    pub audience: Vec<u8>,
    pub at: u64,
}

/// The semantic, closed-set check `parse_egress_attestation` deliberately does not perform
/// structurally (mirroring the Go reference's `ValidateEgressAttestation`, §15): the binding must be
/// in the closed set content_bound/content_free (`UnknownEgressBinding` otherwise).
pub fn validate_egress_attestation(a: &EgressAttestation) -> Result<(), cose::Error> {
    if !is_known_binding(a.binding) {
        return Err(err_unknown_egress_binding());
    }
    Ok(())
}

/// Verify an egress attestation end-to-end and return the resolved evidence. Verify the signature
/// under the profile against the GATEWAY's verifier `gateway_v`; reconstruct it; validate the
/// binding code against the closed set (`validate_egress_attestation`). Takes NO serving-party
/// identity: the same `obj` yields an identical ResolvedEgressAttestation whether the gateway or a
/// third party served it, mirroring `verify_decision`/R-GW-3. Fail-closed.
pub fn verify_egress_attestation(
    obj: &[u8],
    profile: u32,
    gateway_v: &dyn cose::CoseVerifier,
) -> Result<ResolvedEgressAttestation, cose::Error> {
    cose::verify1(profile, gateway_v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let a = parse_egress_attestation(&payload)?;
    validate_egress_attestation(&a)?;
    Ok(ResolvedEgressAttestation {
        binding: a.binding,
        digest: a.digest.clone(),
        effect: policy::normalize_effect(a.effect),
        audience: a.audience.clone(),
        at: a.at,
    })
}

// ---- content_free commitment open/verify pair ---------------------------------------------

/// The content_free hiding commitment over an object's T1 content-id and a salt:
/// SHA-384(object_cid || salt) (48 octets). Reveals nothing about `object_cid` without the salt.
pub fn egress_commit(object_cid: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(object_cid.len() + salt.len());
    b.extend_from_slice(object_cid);
    b.extend_from_slice(salt);
    head(&b)
}

/// Constant-time byte-slice equality (no `subtle` crate dependency in this workspace): every byte
/// pair is compared and the differences OR-accumulated, so the comparison takes the same number of
/// operations regardless of where (or whether) the inputs differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Proves which object crossed under a content_free attestation. Recomputes
/// `egress_commit(object_cid, salt)` and compares it, in constant time, against `a.digest`.
/// Returns true iff `a` is a content_free attestation AND the recomputed commitment matches: a
/// wrong salt or a wrong `object_cid` both fail to open (return false), and a content_bound
/// attestation never opens (its digest is not a commitment).
pub fn open_egress_commitment(a: &EgressAttestation, object_cid: &[u8], salt: &[u8]) -> bool {
    if a.binding != BINDING_CONTENT_FREE {
        return false;
    }
    let want = egress_commit(object_cid, salt);
    constant_time_eq(&want, &a.digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use fips204::traits::SerDes;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/gateway/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }
    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier, Vec<u8>) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        let pk_bytes = pk.clone().into_bytes().to_vec();
        let id = identity::signer_id(cose::ALG_MLDSA65, &pk_bytes).expect("signer id");
        (
            cose::MlDsa65Signer(sk),
            cose::MlDsa65Verifier(pk),
            id.into_bytes(),
        )
    }
    fn dec_from(dv: &J) -> GatewayDecision {
        GatewayDecision {
            decision: dv["decision"].as_u64().unwrap(),
            action: hexd(dv["action_hex"].as_str().unwrap()),
            policy: hexd(dv["policy_hex"].as_str().unwrap()),
            effect: dv["effect"].as_u64().unwrap(),
            ordering: None,
            foreign_profile: None,
        }
    }

    // Byte-parity: Rust encoding == oracle -> Rust == Go on every decision body/head/id.
    #[test]
    fn bodies_match_oracle() {
        let c = load();
        for k in ["allow", "deny", "hold"] {
            let dv = &c["decisions"][k];
            let d = dec_from(dv);
            assert_eq!(
                hex::encode(d.bytes()),
                dv["body_hex"].as_str().unwrap(),
                "{k} body"
            );
            assert_eq!(
                hex::encode(d.head()),
                dv["head_hex"].as_str().unwrap(),
                "{k} head"
            );
            assert_eq!(
                hex::encode(d.id()),
                dv["id_hex"].as_str().unwrap(),
                "{k} id"
            );
        }
        for e in c["decision_vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            assert!(is_known_decision(code));
            assert_eq!(decision_name(code), e["name"].as_str().unwrap());
        }
        assert!(!is_known_decision(c["unknown_decision"].as_u64().unwrap()));
    }

    // The C21 gateway checkpoint: a signed decision verifies offline and re-verifies IDENTICALLY when
    // served by a party other than the gateway.
    #[test]
    fn decision_third_party_re_serve() {
        let c = load();
        let (gw_s, gw_v, _) = key(0x51);
        let (_, foreign_v, _) = key(0x52);
        let d = dec_from(&c["decisions"]["deny"]);
        let obj = sign_decision(&d, &gw_s);

        let by_gateway =
            verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("served by gateway");
        let by_third_party =
            verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("re-served by a third party");
        assert_eq!(by_gateway.decision, by_third_party.decision);
        assert_eq!(by_gateway.action, by_third_party.action);
        assert_eq!(by_gateway.policy, by_third_party.policy);
        assert_eq!(by_gateway.effect, by_third_party.effect);
        assert_eq!(by_third_party.decision, DECISION_DENY);
        assert_eq!(
            hex::encode(&by_third_party.action),
            c["action_cid_hex"].as_str().unwrap()
        );

        // A foreign key never verifies; an unknown decision code is rejected.
        assert_eq!(
            verify_decision(&obj, cose::PROFILE_PUBLIC, &foreign_v)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        let bad = GatewayDecision {
            decision: c["unknown_decision"].as_u64().unwrap(),
            action: hexd(c["action_cid_hex"].as_str().unwrap()),
            policy: hexd(c["policy_hex"].as_str().unwrap()),
            effect: 0,
            ordering: None,
            foreign_profile: None,
        };
        let bad_obj = sign_decision(&bad, &gw_s);
        assert_eq!(
            verify_decision(&bad_obj, cose::PROFILE_PUBLIC, &gw_v)
                .unwrap_err()
                .kind,
            "UnknownGatewayDecision"
        );
    }

    // REQUIRED checkpoint mutation (c): a decision object that only verifies inside the vendor fails the
    // third-party re-serve case. The honest verify_decision takes no serving-party identity; a MUTANT
    // vendor-only verifier requires servingParty == gatewayID and wrongly rejects a third-party re-serve.
    #[test]
    fn gateway_vendor_only_mutation() {
        let c = load();
        let (gw_s, gw_v, gateway_id) = key(0x51);
        let third_party = b"did:example:mirror-cache".to_vec();
        let d = dec_from(&c["decisions"]["allow"]);
        let obj = sign_decision(&d, &gw_s);

        // Honest: re-serve by a third party verifies.
        verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("honest re-serve");

        // Mutant "vendor-only" verifier: also requires servingParty == gatewayID.
        let mutant = |obj: &[u8],
                      gv: &dyn cose::CoseVerifier,
                      gid: &[u8],
                      serving: &[u8]|
         -> Result<(), cose::Error> {
            verify_decision(obj, cose::PROFILE_PUBLIC, gv)?;
            if serving != gid {
                return Err(err_malformed()); // stands in for a "not served by the vendor" rejection
            }
            Ok(())
        };
        mutant(&obj, &gw_v, &gateway_id, &gateway_id).expect("mutant vendor-served");
        assert!(
            mutant(&obj, &gw_v, &gateway_id, &third_party).is_err(),
            "mutant vendor-only verifier accepted a third-party re-serve: the re-serve bug must reproduce"
        );
    }

    // Cross-language pin: the signed deny gateway-decision digest matches the Go pin.
    #[test]
    fn cross_lang_signed_decision_pin() {
        const PIN: &str = "774047d87f11f688c57d985e9cab632ea66d0abc8b9ec3d48d1c3063c54ef5df0f761ce8239cbf68302d547097f01047";
        let c = load();
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let d = dec_from(&c["decisions"]["deny"]);
        let obj = sign_decision(&d, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&obj)),
            PIN,
            "signed gateway-decision digest differs from the Go pin"
        );
    }

    #[test]
    fn malformed_rejected() {
        assert_eq!(parse_decision(&[0x00]).unwrap_err().kind, "GwMalformed");
    }

    // ---- standard wire-format edge cases (Part 1) --------------------------------------------

    // Edge case #1: a decision body with top-level keys DESCENDING (4,3,2,1) is rejected NonCanonical by
    // the strict shared decoder parse_decision routes through; the canonical body parses.
    #[test]
    fn keys_out_of_order_rejected() {
        let c = load();
        let e = &c["edge_cases"]["keys_out_of_order"];
        let d = GatewayDecision {
            decision: e["decision"].as_u64().unwrap(),
            action: hexd(e["action_hex"].as_str().unwrap()),
            policy: hexd(e["policy_hex"].as_str().unwrap()),
            effect: e["effect"].as_u64().unwrap(),
            ordering: None,
            foreign_profile: None,
        };
        assert_eq!(
            hex::encode(d.bytes()),
            e["canonical_body_hex"].as_str().unwrap(),
            "canonical decision body"
        );
        let canon = hexd(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical body should decode");
        parse_decision(&canon).expect("canonical body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key decision body decoded (want NonCanonical)"),
        }
        assert_eq!(parse_decision(&noncanon).unwrap_err().kind, "GwMalformed");
    }

    // Edge case #2 (policy field): an empty policy identity is distinct by content-id from a populated
    // one; both differ from a body whose policy field is ABSENT (rejected GwMalformed — field 3 is
    // mandatory).
    #[test]
    fn empty_vs_absent_policy() {
        let c = load();
        let ea = &c["edge_cases"]["empty_vs_absent"];
        let action = hexd(c["action_cid_hex"].as_str().unwrap());
        let empty = GatewayDecision {
            decision: DECISION_ALLOW,
            action: action.clone(),
            policy: vec![],
            effect: 1,
            ordering: None,
            foreign_profile: None,
        };
        let populated = GatewayDecision {
            decision: DECISION_ALLOW,
            action,
            policy: hexd(ea["populated_policy"]["policy_hex"].as_str().unwrap()),
            effect: 1,
            ordering: None,
            foreign_profile: None,
        };
        assert_eq!(
            hex::encode(empty.bytes()),
            ea["empty_policy"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(populated.bytes()),
            ea["populated_policy"]["body_hex"].as_str().unwrap()
        );
        assert_ne!(
            empty.id(),
            populated.id(),
            "empty vs populated policy must differ by content-id"
        );
        assert_eq!(
            hex::encode(empty.id()),
            ea["empty_policy"]["id_hex"].as_str().unwrap()
        );
        parse_decision(&empty.bytes()).expect("empty policy parses");
        parse_decision(&populated.bytes()).expect("populated policy parses");
        assert_eq!(
            parse_decision(&hexd(ea["absent_field"]["body_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "GwMalformed"
        );
    }

    // Edge case #4: the smallest valid decision (allow, empty action, empty policy, read_only) encodes
    // to the oracle bytes, has a stable content-id, round-trips, and verifies end-to-end.
    #[test]
    fn minimal_decision() {
        let c = load();
        let m = &c["edge_cases"]["minimal"];
        let d = GatewayDecision {
            decision: m["decision"].as_u64().unwrap(),
            action: hexd(m["action_hex"].as_str().unwrap()),
            policy: hexd(m["policy_hex"].as_str().unwrap()),
            effect: m["effect"].as_u64().unwrap(),
            ordering: None,
            foreign_profile: None,
        };
        assert_eq!(hex::encode(d.bytes()), m["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(d.id()), m["id_hex"].as_str().unwrap());
        parse_decision(&d.bytes()).expect("parse minimal");
        let (gw_s, gw_v, _) = key(0x53);
        let obj = sign_decision(&d, &gw_s);
        verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("verify minimal");
    }

    // Edge case #5: naalp-gateway-decision defines a single body kind, so the look-alike is a SIBLING
    // C21 body — a ui-event {1:bstr,2:uint,3:bstr,4:uint,5:bstr} whose field 1 is a bstr where the
    // decision uint is required. parse_decision rejects it GwMalformed.
    #[test]
    fn look_alike_rejected() {
        let c = load();
        let body = hexd(c["edge_cases"]["look_alike"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_decision(&body).unwrap_err().kind, "GwMalformed");
    }

    // ---- optional fields: R1 ordering (field 5) + R8 foreign-profile (field 6) ---------------

    // NON-REGRESSION: adding optional fields 5/6 must not perturb the pre-existing 4-field decision
    // bodies at all. Pins the allow/deny/hold body_hex values as they stood BEFORE this change,
    // independent of the vector file's own drift.
    #[test]
    fn existing_decision_bodies_unchanged() {
        const PINNED_ALLOW: &str = "a401000258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330401";
        const PINNED_DENY: &str = "a401010258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330403";
        const PINNED_HOLD: &str = "a401020258322030e29a76dd184988f9503d0fa62466876a9c7078edef4421bda446e62e53ef3911a8382861aeb9e4e97540db4838d5b1bd0355706f6c6963793a61636d652d6567726573732d76330402";
        let c = load();
        assert_eq!(c["decisions"]["allow"]["body_hex"].as_str().unwrap(), PINNED_ALLOW);
        assert_eq!(c["decisions"]["deny"]["body_hex"].as_str().unwrap(), PINNED_DENY);
        assert_eq!(c["decisions"]["hold"]["body_hex"].as_str().unwrap(), PINNED_HOLD);
        // And the Rust encoder itself still reproduces them for a GatewayDecision with
        // ordering/foreign_profile both None (the pre-existing zero value).
        for k in ["allow", "deny", "hold"] {
            let d = dec_from(&c["decisions"][k]);
            assert_eq!(
                hex::encode(d.bytes()),
                c["decisions"][k]["body_hex"].as_str().unwrap(),
                "{k} bytes with ordering/foreign_profile = None"
            );
        }
    }

    // with_ordering (field 5 only), with_foreign_profile (field 6 only), with_both (5 AND 6): Rust
    // encoding == oracle body/id, and parse_decision round-trips the optional fields back out exactly.
    #[test]
    fn optional_fields_round_trip() {
        let c = load();
        let of = &c["optional_fields"];

        // with_ordering
        {
            let wo = &of["with_ordering"];
            let d = GatewayDecision {
                decision: wo["decision"].as_u64().unwrap(),
                action: hexd(wo["action_hex"].as_str().unwrap()),
                policy: hexd(wo["policy_hex"].as_str().unwrap()),
                effect: wo["effect"].as_u64().unwrap(),
                ordering: Some(OrderingDisclosure {
                    basis: wo["ordering"]["basis"].as_u64().unwrap(),
                    boundary: Some(hexd(wo["ordering"]["boundary_hex"].as_str().unwrap())),
                    mechanism: None,
                    relation: None,
                }),
                foreign_profile: None,
            };
            assert_eq!(hex::encode(d.bytes()), wo["body_hex"].as_str().unwrap(), "with_ordering body");
            assert_eq!(hex::encode(d.id()), wo["id_hex"].as_str().unwrap(), "with_ordering id");
            let parsed = parse_decision(&hexd(wo["body_hex"].as_str().unwrap())).expect("parse with_ordering");
            let ordering = parsed.ordering.as_ref().expect("with_ordering.ordering is None, want Some");
            assert!(parsed.foreign_profile.is_none(), "with_ordering.foreign_profile is Some, want None (field 6 absent)");
            assert_eq!(ordering.basis, wo["ordering"]["basis"].as_u64().unwrap());
            assert_eq!(ordering.boundary.as_deref(), Some(hexd(wo["ordering"]["boundary_hex"].as_str().unwrap())).as_deref());
            ordering.check_well_formed().expect("single-boundary with boundary present must be well-formed");
        }

        // with_foreign_profile
        {
            let wf = &of["with_foreign_profile"];
            let d = GatewayDecision {
                decision: wf["decision"].as_u64().unwrap(),
                action: hexd(wf["action_hex"].as_str().unwrap()),
                policy: hexd(wf["policy_hex"].as_str().unwrap()),
                effect: wf["effect"].as_u64().unwrap(),
                ordering: None,
                foreign_profile: Some(ForeignProfilePin::new(
                    wf["foreign_profile"]["id"].as_str().unwrap(),
                    wf["foreign_profile"]["revision"].as_str().unwrap(),
                )),
            };
            assert_eq!(hex::encode(d.bytes()), wf["body_hex"].as_str().unwrap(), "with_foreign_profile body");
            assert_eq!(hex::encode(d.id()), wf["id_hex"].as_str().unwrap(), "with_foreign_profile id");
            let parsed = parse_decision(&hexd(wf["body_hex"].as_str().unwrap())).expect("parse with_foreign_profile");
            assert!(parsed.ordering.is_none(), "with_foreign_profile.ordering is Some, want None (field 5 absent)");
            let fp = parsed.foreign_profile.as_ref().expect("with_foreign_profile.foreign_profile is None, want Some");
            assert_eq!(fp.id, wf["foreign_profile"]["id"].as_str().unwrap());
            assert_eq!(fp.revision, wf["foreign_profile"]["revision"].as_str().unwrap());
            fp.validate().expect("both id/revision present and non-empty must validate");
        }

        // with_both
        {
            let wb = &of["with_both"];
            let d = GatewayDecision {
                decision: wb["decision"].as_u64().unwrap(),
                action: hexd(wb["action_hex"].as_str().unwrap()),
                policy: hexd(wb["policy_hex"].as_str().unwrap()),
                effect: wb["effect"].as_u64().unwrap(),
                ordering: Some(OrderingDisclosure {
                    basis: wb["ordering"]["basis"].as_u64().unwrap(),
                    boundary: None,
                    mechanism: Some(hexd(wb["ordering"]["mechanism_hex"].as_str().unwrap())),
                    relation: Some(hexd(wb["ordering"]["relation_hex"].as_str().unwrap())),
                }),
                foreign_profile: Some(ForeignProfilePin::new(
                    wb["foreign_profile"]["id"].as_str().unwrap(),
                    wb["foreign_profile"]["revision"].as_str().unwrap(),
                )),
            };
            assert_eq!(hex::encode(d.bytes()), wb["body_hex"].as_str().unwrap(), "with_both body");
            assert_eq!(hex::encode(d.id()), wb["id_hex"].as_str().unwrap(), "with_both id");
            let parsed = parse_decision(&hexd(wb["body_hex"].as_str().unwrap())).expect("parse with_both");
            let ordering = parsed.ordering.as_ref().expect("with_both.ordering is None");
            let fp = parsed.foreign_profile.as_ref().expect("with_both.foreign_profile is None");
            ordering.check_well_formed().expect("with_both ordering must be well-formed");
            fp.validate().expect("with_both foreign_profile must validate");

            // Full end-to-end: signs and verifies with both optional fields present.
            let (gw_s, gw_v, _) = key(0x71);
            let obj = sign_decision(&d, &gw_s);
            verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("verify_decision(with_both)");
        }
    }

    // Reject case (d): field 6 present but omits key 2 (revision). parse_decision decodes it
    // structurally fine (field 6 is a well-typed map; the missing sub-field is not a CBOR type
    // error); verify_decision's ForeignProfilePin::validate rejects the missing revision
    // (ForeignProfileMalformed) — proving the semantic check actually runs, not just the decode.
    #[test]
    fn foreign_profile_malformed_rejected() {
        let c = load();
        let body = hexd(c["optional_fields"]["foreign_profile_malformed"]["body_hex"].as_str().unwrap());

        let parsed = parse_decision(&body).expect("parse_decision(foreign_profile_malformed) should decode structurally");
        let fp = parsed.foreign_profile.as_ref().expect("foreign_profile is None, want Some (structural decode succeeds)");
        assert_eq!(fp.validate().unwrap_err().kind, "ForeignProfileMalformed");

        let (gw_s, gw_v, _) = key(0x72);
        let obj = cose::sign1(&gw_s, &body);
        assert_eq!(
            verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).unwrap_err().kind,
            "ForeignProfileMalformed"
        );
    }

    // Reject case (e): field 5 basis=external-mechanism(2) but key 2 (boundary) is ALSO present.
    // verify_decision's OrderingDisclosure::check_well_formed rejects it (OrderingDisclosureMalformed).
    #[test]
    fn ordering_malformed_rejected() {
        let c = load();
        let body = hexd(c["optional_fields"]["ordering_malformed"]["body_hex"].as_str().unwrap());

        let parsed = parse_decision(&body).expect("parse_decision(ordering_malformed) should decode structurally");
        let ordering = parsed.ordering.as_ref().expect("ordering is None, want Some (structural decode succeeds)");
        assert_eq!(ordering.check_well_formed().unwrap_err().kind, "OrderingDisclosureMalformed");

        let (gw_s, gw_v, _) = key(0x73);
        let obj = cose::sign1(&gw_s, &body);
        assert_eq!(
            verify_decision(&obj, cose::PROFILE_PUBLIC, &gw_v).unwrap_err().kind,
            "OrderingDisclosureMalformed"
        );
    }

    // Direct unit test of ForeignProfilePin::validate (no oracle vector needed): missing/empty id or
    // revision is rejected; both present and non-empty passes. Mutation: replace validate's body with
    // `Ok(())` unconditionally and every sub-case but the first flips from Err to a wrongly-accepted Ok.
    #[test]
    fn foreign_profile_pin_validate() {
        assert!(ForeignProfilePin::new("https://example.test/p", "1").validate().is_ok());
        assert_eq!(
            ForeignProfilePin::new("", "1").validate().unwrap_err().kind,
            "ForeignProfileMalformed"
        );
        assert_eq!(
            ForeignProfilePin::new("https://example.test/p", "").validate().unwrap_err().kind,
            "ForeignProfileMalformed"
        );
        assert_eq!(
            ForeignProfilePin::new("", "").validate().unwrap_err().kind,
            "ForeignProfileMalformed"
        );
    }

    // Exercises the "extra" branch of validate() end-to-end through parse_decision: a field-6 map
    // carrying a THIRD key (3) beyond the closed {1,2} set decodes structurally
    // (foreign_profile_from_value does not refuse an extra key at decode time — only a wrong-typed
    // 1/2 does that) but fails validate() (ForeignProfileMalformed), exactly as a missing or empty
    // field does. Hand-built directly (not oracle-driven): proves Rust's own encode-independent
    // decoder rejects a shape it never itself produces.
    #[test]
    fn foreign_profile_extra_key_rejected() {
        let c = load();
        let action = hexd(c["action_cid_hex"].as_str().unwrap());
        let policy_id = hexd(c["policy_hex"].as_str().unwrap());
        let fp_value = Value::Map(vec![
            (Value::Uint(1), Value::Tstr("https://example-registry.test/profiles/acme".to_string())),
            (Value::Uint(2), Value::Tstr("2026-01".to_string())),
            (Value::Uint(3), Value::Tstr("unexpected".to_string())),
        ]);
        let body = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(DECISION_ALLOW)),
            (Value::Uint(2), Value::Bstr(action)),
            (Value::Uint(3), Value::Bstr(policy_id)),
            (Value::Uint(4), Value::Uint(1)),
            (Value::Uint(6), fp_value),
        ]))
        .expect("encode extra-key foreign-profile body");

        let parsed = parse_decision(&body).expect("parse_decision(extra-key foreign-profile) should decode structurally");
        let fp = parsed.foreign_profile.as_ref().expect("foreign_profile is None, want Some");
        assert_eq!(fp.id, "https://example-registry.test/profiles/acme");
        assert_eq!(fp.revision, "2026-01");
        assert_eq!(fp.validate().unwrap_err().kind, "ForeignProfileMalformed");
    }

    // ---- EgressAttestation (E6.3, held at the wire-freeze gate) -------------------------------

    const EGRESS_VECTOR_PATH: &str = "../../vectors/egress_attestation/cases.json";

    fn load_egress() -> J {
        serde_json::from_str(&std::fs::read_to_string(EGRESS_VECTOR_PATH).expect("read egress corpus"))
            .expect("parse egress corpus")
    }

    // Parses an epoch-ms field from its decimal-string corpus representation (never a bare JSON
    // number — the nonce.derive seq lesson: a float64 JSON decoder anywhere in the toolchain would
    // silently round a value above 2^53; u64::from_str is lossless across the full uint64 range).
    fn at_u64(s: &str) -> u64 {
        s.parse::<u64>().expect("bad at_str")
    }

    fn att_from(av: &J) -> EgressAttestation {
        EgressAttestation {
            binding: av["binding"].as_u64().unwrap(),
            digest: hexd(av["digest_hex"].as_str().unwrap()),
            effect: av["effect"].as_u64().unwrap(),
            audience: hexd(av["audience_hex"].as_str().unwrap()),
            at: at_u64(av["at_str"].as_str().unwrap()),
        }
    }

    // Byte-parity: Rust encoding == oracle -> Rust == Go, for every attestation body/head/id,
    // including the full-width oversized-counter edge case.
    #[test]
    fn egress_bodies_match_oracle() {
        let c = load_egress();
        for k in ["content_bound", "content_free"] {
            let av = &c["attestations"][k];
            let a = att_from(av);
            assert_eq!(hex::encode(a.bytes()), av["body_hex"].as_str().unwrap(), "{k} body");
            assert_eq!(hex::encode(a.head()), av["head_hex"].as_str().unwrap(), "{k} head");
            assert_eq!(hex::encode(a.id()), av["id_hex"].as_str().unwrap(), "{k} id");
        }
        for e in c["binding_vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            assert!(is_known_binding(code));
            assert_eq!(binding_name(code), e["name"].as_str().unwrap());
        }
        assert!(!is_known_binding(c["unknown_binding"].as_u64().unwrap()));
    }

    // Field 5 (`at`) round-trips losslessly at the top of the uint64 range (2^64-1), carried
    // through the corpus as a decimal string, never a bare JSON number.
    #[test]
    fn egress_oversized_counter() {
        let c = load_egress();
        let e = &c["edge_cases"]["oversized_counter"];
        assert_eq!(e["at_str"].as_str().unwrap(), "18446744073709551615");
        let a = att_from(e);
        assert_eq!(a.at, u64::MAX);
        assert_eq!(hex::encode(a.bytes()), e["body_hex"].as_str().unwrap());
        let parsed = parse_egress_attestation(&a.bytes()).expect("parse oversized");
        assert_eq!(parsed.at, a.at, "precision lost round-tripping the oversized counter");
    }

    // Checkpoint mirroring decision_third_party_re_serve: a signed egress attestation verifies
    // offline and re-verifies IDENTICALLY when served by a party OTHER than the gateway.
    #[test]
    fn egress_attestation_third_party_re_serve() {
        let c = load_egress();
        let (gw_s, gw_v, _) = key(0x61);
        let (_, foreign_v, _) = key(0x62);
        let a = att_from(&c["attestations"]["content_bound"]);
        let obj = sign_egress_attestation(&a, &gw_s);

        let by_gateway = verify_egress_attestation(&obj, cose::PROFILE_PUBLIC, &gw_v)
            .expect("served by gateway");
        let by_third_party = verify_egress_attestation(&obj, cose::PROFILE_PUBLIC, &gw_v)
            .expect("re-served by a third party");
        assert_eq!(by_gateway.binding, by_third_party.binding);
        assert_eq!(by_gateway.digest, by_third_party.digest);
        assert_eq!(by_gateway.effect, by_third_party.effect);
        assert_eq!(by_gateway.audience, by_third_party.audience);
        assert_eq!(by_gateway.at, by_third_party.at);
        assert_eq!(by_third_party.binding, BINDING_CONTENT_BOUND);
        assert_eq!(
            hex::encode(&by_third_party.digest),
            c["object_cid_hex"].as_str().unwrap()
        );

        assert_eq!(
            verify_egress_attestation(&obj, cose::PROFILE_PUBLIC, &foreign_v)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        let bad = EgressAttestation {
            binding: c["unknown_binding"].as_u64().unwrap(),
            digest: hexd(c["object_cid_hex"].as_str().unwrap()),
            effect: 0,
            audience: hexd(c["audience_hex"].as_str().unwrap()),
            at: 0,
        };
        let bad_obj = sign_egress_attestation(&bad, &gw_s);
        assert_eq!(
            verify_egress_attestation(&bad_obj, cose::PROFILE_PUBLIC, &gw_v)
                .unwrap_err()
                .kind,
            "UnknownEgressBinding"
        );
    }

    #[test]
    fn validate_egress_attestation_direct() {
        let c = load_egress();
        let good = att_from(&c["attestations"]["content_bound"]);
        validate_egress_attestation(&good).expect("known binding validates");

        let bad = EgressAttestation {
            binding: c["unknown_binding"].as_u64().unwrap(),
            digest: hexd(c["object_cid_hex"].as_str().unwrap()),
            effect: 0,
            audience: hexd(c["audience_hex"].as_str().unwrap()),
            at: 0,
        };
        assert_eq!(
            validate_egress_attestation(&bad).unwrap_err().kind,
            "UnknownEgressBinding"
        );
    }

    // Mutant "vendor-only" verifier: the honest verify_egress_attestation takes no serving-party
    // identity; a mutant requiring servingParty == gatewayID wrongly rejects a third-party re-serve.
    #[test]
    fn egress_vendor_only_mutation() {
        let c = load_egress();
        let (gw_s, gw_v, gateway_id) = key(0x61);
        let third_party = b"did:example:mirror-cache".to_vec();
        let a = att_from(&c["attestations"]["content_free"]);
        let obj = sign_egress_attestation(&a, &gw_s);

        verify_egress_attestation(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("honest re-serve");

        let mutant = |obj: &[u8],
                      gv: &dyn cose::CoseVerifier,
                      gid: &[u8],
                      serving: &[u8]|
         -> Result<(), cose::Error> {
            verify_egress_attestation(obj, cose::PROFILE_PUBLIC, gv)?;
            if serving != gid {
                return Err(err_egress_malformed());
            }
            Ok(())
        };
        mutant(&obj, &gw_v, &gateway_id, &gateway_id).expect("mutant vendor-served");
        assert!(
            mutant(&obj, &gw_v, &gateway_id, &third_party).is_err(),
            "mutant vendor-only verifier accepted a third-party re-serve: the re-serve bug must reproduce"
        );
    }

    // The A7 opening-side checkpoint: a content_free digest is a hiding commitment
    // SHA-384(object_cid||salt); the CORRECT pair opens it, a WRONG salt or a WRONG object_cid
    // must both fail to open, and a content_bound attestation never opens.
    #[test]
    fn open_egress_commitment_wrong_salt_fails() {
        let c = load_egress();
        let co = &c["commitment_open"];
        let a = att_from(&c["attestations"]["content_free"]);
        assert_eq!(hex::encode(&a.digest), co["commitment_hex"].as_str().unwrap());

        let object_cid = hexd(co["object_cid_hex"].as_str().unwrap());
        let wrong_object_cid = hexd(co["wrong_object_cid_hex"].as_str().unwrap());
        let salt = hexd(co["salt_hex"].as_str().unwrap());
        let wrong_salt = hexd(co["wrong_salt_hex"].as_str().unwrap());

        assert_eq!(
            hex::encode(egress_commit(&object_cid, &salt)),
            co["commitment_hex"].as_str().unwrap()
        );
        assert!(
            open_egress_commitment(&a, &object_cid, &salt),
            "correct object_cid + correct salt must open"
        );
        assert!(
            !open_egress_commitment(&a, &object_cid, &wrong_salt),
            "correct object_cid + WRONG salt must fail to open"
        );
        assert!(
            !open_egress_commitment(&a, &wrong_object_cid, &salt),
            "WRONG object_cid + correct salt must fail to open"
        );
        assert!(!open_egress_commitment(&a, &wrong_object_cid, &wrong_salt));

        let bound = att_from(&c["attestations"]["content_bound"]);
        assert!(
            !open_egress_commitment(&bound, &object_cid, &salt),
            "a content_bound attestation must never open (digest is not a commitment)"
        );
    }

    // Cross-language pin: the signed content_free egress-attestation digest matches the Go pin.
    #[test]
    fn cross_lang_signed_egress_attestation_pin() {
        const PIN: &str = "d811b056d7a9710ab7049ff34b43628d5b6c9abb2e31bb24b486e9cb42ad853d4b78dc4f359e9b724efdad3eb6fe625a";
        let c = load_egress();
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let a = att_from(&c["attestations"]["content_free"]);
        let obj = sign_egress_attestation(&a, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&obj)),
            PIN,
            "signed egress-attestation digest differs from the Go pin"
        );
    }

    #[test]
    fn egress_malformed_rejected() {
        assert_eq!(
            parse_egress_attestation(&[0x00]).unwrap_err().kind,
            "EgMalformed"
        );
    }

    // Edge case #1: an attestation body with top-level keys DESCENDING (5,4,3,2,1) is rejected
    // NonCanonical by the strict shared decoder parse_egress_attestation routes through.
    #[test]
    fn egress_keys_out_of_order_rejected() {
        let c = load_egress();
        let e = &c["edge_cases"]["keys_out_of_order"];
        let a = att_from(e);
        assert_eq!(
            hex::encode(a.bytes()),
            e["canonical_body_hex"].as_str().unwrap(),
            "canonical attestation body"
        );
        let canon = hexd(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical body should decode");
        parse_egress_attestation(&canon).expect("canonical body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key attestation body decoded (want NonCanonical)"),
        }
        assert_eq!(
            parse_egress_attestation(&noncanon).unwrap_err().kind,
            "EgMalformed"
        );
    }

    // Edge case #2 (audience field 4): an empty audience is PRESENT and valid and DISTINCT by
    // content-id from a populated one; both differ from a body whose audience field is ABSENT
    // (rejected EgMalformed — field 4 is mandatory even though empty is permitted).
    #[test]
    fn egress_empty_vs_absent_audience() {
        let c = load_egress();
        let ea = &c["edge_cases"]["empty_vs_absent"];
        let object_cid = hexd(c["object_cid_hex"].as_str().unwrap());
        let empty = EgressAttestation {
            binding: BINDING_CONTENT_BOUND,
            digest: object_cid.clone(),
            effect: 1,
            audience: vec![],
            at: 1_735_689_600_000,
        };
        let populated = EgressAttestation {
            binding: BINDING_CONTENT_BOUND,
            digest: object_cid,
            effect: 1,
            audience: hexd(ea["populated_audience"]["audience_hex"].as_str().unwrap()),
            at: 1_735_689_600_000,
        };
        assert_eq!(
            hex::encode(empty.bytes()),
            ea["empty_audience"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(populated.bytes()),
            ea["populated_audience"]["body_hex"].as_str().unwrap()
        );
        assert_ne!(
            empty.id(),
            populated.id(),
            "empty vs populated audience must differ by content-id"
        );
        assert_eq!(
            hex::encode(empty.id()),
            ea["empty_audience"]["id_hex"].as_str().unwrap()
        );
        parse_egress_attestation(&empty.bytes()).expect("empty audience parses");
        parse_egress_attestation(&populated.bytes()).expect("populated audience parses");
        assert_eq!(
            parse_egress_attestation(&hexd(ea["absent_field"]["body_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "EgMalformed"
        );
    }

    // Edge case #4: the smallest valid attestation (content_bound, empty digest, empty audience,
    // read_only, at=0) encodes to the oracle bytes, has a stable content-id, round-trips, verifies.
    #[test]
    fn egress_minimal() {
        let c = load_egress();
        let m = &c["edge_cases"]["minimal"];
        let a = att_from(m);
        assert_eq!(hex::encode(a.bytes()), m["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(a.id()), m["id_hex"].as_str().unwrap());
        parse_egress_attestation(&a.bytes()).expect("parse minimal");
        let (gw_s, gw_v, _) = key(0x63);
        let obj = sign_egress_attestation(&a, &gw_s);
        verify_egress_attestation(&obj, cose::PROFILE_PUBLIC, &gw_v).expect("verify minimal");
    }

    // Edge case #5: naalp-egress-attestation is a near-clone of the SIBLING C21 body
    // naalp-gateway-decision {1:uint,2:bstr,3:bstr,4:uint} (four fields, no field 5) fed to
    // parse_egress_attestation, which requires five mandatory fields. Rejected EgMalformed.
    #[test]
    fn egress_look_alike_rejected() {
        let c = load_egress();
        let body = hexd(c["edge_cases"]["look_alike"]["body_hex"].as_str().unwrap());
        assert_eq!(
            parse_egress_attestation(&body).unwrap_err().kind,
            "EgMalformed"
        );
    }
}
