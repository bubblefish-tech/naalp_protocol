// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP C3 object envelope (design.md §2): the single signed object every kind,
//! channel, and transport reuses. The body is a deterministic-CBOR map (fields 1..12)
//! carried as the COSE_Sign1 payload; field 1 is the content id (§2.3). The protected
//! header carries the algorithm plus routing copies of the signer, profile, and
//! naalp-version (§2.1, §2.5). Every failure is fail-closed with a named error (§2.6).
//! Rust half of the two-implementation parity; byte-identical to impl/go by construction.

use crate::cbor::{self, Value};
use crate::cose::{self, CoseSigner, CoseVerifier};

// Object body field numbers (§2.1), the protected-header naalp-version (§2.5), and the header
// label are generated from spec/wire-constants.csv -- the one wire authority -- and pulled in here
// with `include!` so they are authored once and cannot be re-typed and drift across ports (see
// scripts/gen_wire_constants.py). draft-01 bumped naalp-version 1 -> 2 for the first -01 wire change.
include!("wire_constants_gen.rs");

/// The ext/cext extension key under which an object NAMES the re-check procedure for the claim in
/// its body (§2.5, NAALP-REQ-111(c) — the "checkable minimum"). The value is a procedure id into
/// the closed registry below. In the non-critical ext map (field 11) it is may-ignore; in the
/// critical cext map (field 12) it is must-understand and an unknown id is rejected fail-closed
/// (UnknownCriticalExt), the same C3 critical-extension rule reaching the procedure it names. 13
/// does not collide with the safety-label ext key 1 (§6.4). Byte-identical to impl/go.
pub const RECHECK_KEY: u64 = 13;

// The closed re-check procedure registry (design.md §2.5; T1.3); mirrors spec recheck-procedure
// and vectors/registry/recheck.csv.
pub const RECHECK_RECOMPUTE_CONTENT_ID: u64 = 1; // recompute the content id and compare (§2.3)
pub const RECHECK_VERIFY_COSE_SIGN1: u64 = 2; // verify the COSE_Sign1 signature (§4)
pub const RECHECK_WALK_CAUSES: u64 = 3; // walk the signed causal partial order offline (§8.2)
pub const RECHECK_REPLAY_CONSUME_CHECK: u64 = 4; // replay the single-use consume ledger (§7.2)

/// Reports whether `id` is a recognized re-check procedure. The registry is CLOSED: an id outside
/// it is unknown, and unknown-under-critical is rejected (§2.5).
pub fn is_known_recheck_procedure(id: u64) -> bool {
    (RECHECK_RECOMPUTE_CONTENT_ID..=RECHECK_REPLAY_CONSUME_CHECK).contains(&id)
}

/// The ext extension key under which an object OPTIONALLY carries a forward-only per-signer counter
/// (design.md §2.5.2, NAALP-REQ-120). The value is a forward-only position (a u64) the signer
/// increments on each object, carried in the NON-CRITICAL ext map (field 11): a verifier that does
/// not do duplication-detection ignores it (may-ignore). Because ext (field 11) is part of the
/// signed body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature — the
/// deliberate contrast with the T1.5 consume-receipt position, signed by the LEDGER key. 14 is the
/// next free ext/cext key: it collides with neither the safety-label ext key 1 (§6.4) nor the
/// recheck ext/cext key 13 (T1.3). It is DETECTION, not prevention (# Security Considerations), and
/// NON-CRITICAL only — placing it in the critical cext map is an unrecognized critical extension and
/// is rejected fail-closed (UnknownCriticalExt). Byte-identical to impl/go.
pub const SIGNER_COUNTER_KEY: u64 = 14;

/// The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
/// disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and whether
/// that boundary OBSERVED the event it describes first-hand or is RELAYING a report of it. Carried in
/// the NON-CRITICAL ext map (field 11, may-ignore), covered by the SIGNER's own COSE_Sign1 signature
/// (self-asserted). 15 is the next free ext/cext key: it collides with neither the safety-label ext
/// key 1 (§6.4), the recheck ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). It
/// establishes record-order / observational domain, NOT cross-boundary event precedence (# Security
/// Considerations); placing it in the critical cext map is an unrecognized critical extension and is
/// rejected fail-closed (UnknownCriticalExt). Byte-identical to impl/go.
pub const PRODUCING_BOUNDARY_KEY: u64 = 15;

/// The producing-boundary kind (design.md §2.5.4): a closed enum naming whether the emitting boundary
/// witnessed the event directly (observed) or is relaying a report of it (reported).
pub const PRODUCING_BOUNDARY_OBSERVED: u64 = 1;
pub const PRODUCING_BOUNDARY_REPORTED: u64 = 2;

// The producing-boundary value sub-map keys (design.md §2.5.4).
const PB_FIELD_BOUNDARY: u64 = 1; // bstr — the emitting trust boundary (party id)
const PB_FIELD_KIND: u64 = 2; // 1 observed / 2 reported
const PB_FIELD_REPORTING: u64 = 3; // bstr — report origin; present iff kind = reported

/// A decoded producing-boundary disclosure (PRODUCING_BOUNDARY_KEY, §2.5.4). `boundary` is the
/// emitting trust boundary (the same bstr party-id form as `Object::signer`). `kind` is
/// PRODUCING_BOUNDARY_OBSERVED or PRODUCING_BOUNDARY_REPORTED. `reporting` is `Some` ONLY when `kind`
/// is reported (an observer relays from no one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducingBoundary {
    pub boundary: Vec<u8>,
    pub kind: u64,
    pub reporting: Option<Vec<u8>>,
}

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
fn e_cid() -> cose::Error {
    err(
        "ContentIdMismatch",
        "id does not equal the recomputed content id",
    )
}
fn e_hbm() -> cose::Error {
    err(
        "HeaderBodyMismatch",
        "protected-header signer/profile disagree with the body",
    )
}
fn e_ucext() -> cose::Error {
    err("UnknownCriticalExt", "unrecognized critical extension key")
}
fn e_ukind() -> cose::Error {
    err("UnknownKind", "kind/channel not recognized by any surface")
}
fn e_range() -> cose::Error {
    err("RangeError", "field value outside its permitted range")
}
fn e_version() -> cose::Error {
    err("UnsupportedVersion", "unsupported naalp-version")
}
fn e_malformed() -> cose::Error {
    err("Malformed", "malformed object")
}
fn e_wrong_audience() -> cose::Error {
    err(
        "WrongAudience",
        "consume-once object audience is not this consuming authority (or absent)",
    )
}

/// Enforces the single-use consume binding (design.md §2.5.3). The CONSUMING AUTHORITY calls it at
/// the point of use — before the consume CAS — never inside [`verify`]: an in-transit relay or
/// auditor verifies objects addressed to OTHERS, so binding this into signature verification would
/// break relaying and receipt issuance. `self_authority` is the checking authority's own identity;
/// `consume_once` is true when the object's acceptance spends a single-use ledger resource.
/// Fail-closed: a consume-once object naming no audience, or an audience naming some X !=
/// self_authority, is WrongAudience; a non-consume-once object naming no audience is unrestricted.
/// Byte-identical behaviour to impl/go.
pub fn check_audience(
    o: &Object,
    self_authority: &str,
    consume_once: bool,
) -> Result<(), cose::Error> {
    if o.audience.is_empty() {
        if consume_once {
            return Err(e_wrong_audience());
        }
        return Ok(());
    }
    if o.audience != self_authority {
        return Err(e_wrong_audience());
    }
    Ok(())
}

/// A decoded N-AALP object body. `id` is set by [`sign`] (content id §2.3).
#[derive(Clone, Debug)]
pub struct Object {
    pub id: Vec<u8>,
    pub kind: u64,
    pub channel: u64,
    pub tier: u64,
    pub signer: Vec<u8>,
    pub created: u64,
    pub effect: u64,
    pub causes: Vec<Vec<u8>>,
    pub profile: u64,
    pub body: Value,
    pub ext: Option<Vec<(Value, Value)>>, // field 11 (non-critical); None = absent
    pub cext: Option<Vec<(Value, Value)>>, // field 12 (critical); None = absent
    pub audience: String, // field 13 single-use consume binding (§2.5.3); "" = absent (omitted)
    pub suite: u64,       // field 14 signed suite declaration (§4.2); 0 = absent (pure object)
}

/// The signed suite id carried in field 14 for the opt-in Public/Enterprise composite
/// (design.md §4.2). Field 14 is present iff the object's alg is the composite id; a
/// pure-ML-DSA object omits it and stays byte-identical to a pre-composite object. This
/// small-uint suite id is an N-AALP-provisional assignment. Byte-identical to impl/go.
pub const SUITE_MLDSA65_ED25519: u64 = 1;

/// Maps a composite signature alg id to its signed suite id (field 14); a non-composite alg
/// returns None, so field 14 is absent for a pure object.
fn composite_suite_for_alg(alg: i64) -> Option<u64> {
    match alg {
        cose::ALG_COMPOSITE_65_ED25519 => Some(SUITE_MLDSA65_ED25519),
        _ => None,
    }
}

impl Object {
    fn body_map(&self, include_id: bool) -> Value {
        let mut m: Vec<(Value, Value)> = Vec::with_capacity(12);
        if include_id {
            m.push((Value::Uint(FIELD_ID), Value::Bstr(self.id.clone())));
        }
        m.push((Value::Uint(FIELD_KIND), Value::Uint(self.kind)));
        m.push((Value::Uint(FIELD_CHANNEL), Value::Uint(self.channel)));
        m.push((Value::Uint(FIELD_TIER), Value::Uint(self.tier)));
        m.push((Value::Uint(FIELD_SIGNER), Value::Bstr(self.signer.clone())));
        m.push((Value::Uint(FIELD_CREATED), Value::Uint(self.created)));
        m.push((Value::Uint(FIELD_EFFECT), Value::Uint(self.effect)));
        m.push((
            Value::Uint(FIELD_CAUSES),
            Value::Arr(self.causes.iter().map(|c| Value::Bstr(c.clone())).collect()),
        ));
        m.push((Value::Uint(FIELD_PROFILE), Value::Uint(self.profile)));
        m.push((Value::Uint(FIELD_BODY), self.body.clone()));
        if let Some(ext) = &self.ext {
            m.push((Value::Uint(FIELD_EXT), Value::Map(ext.clone())));
        }
        if let Some(cext) = &self.cext {
            m.push((Value::Uint(FIELD_CEXT), Value::Map(cext.clone())));
        }
        if !self.audience.is_empty() {
            m.push((
                Value::Uint(FIELD_AUDIENCE),
                Value::Tstr(self.audience.clone()),
            ));
        }
        if self.suite != 0 {
            m.push((Value::Uint(FIELD_SUITE), Value::Uint(self.suite)));
        }
        Value::Map(m)
    }

    /// Content id over the body without field 1 (design.md §2.3).
    pub fn content_id(&self) -> Vec<u8> {
        cbor::content_id(&self.body_map(false)).expect("content id")
    }

    /// Returns the re-check procedure the object names (RECHECK_KEY, §2.5): `Some((id, critical))`
    /// where `critical` is true iff named in the cext map (field 12) and false iff in the ext map
    /// (field 11); cext takes precedence when both carry the key. `None` when no procedure is named
    /// (the claim is attributable-only, NAALP-REQ-111).
    pub fn recheck(&self) -> Option<(u64, bool)> {
        if let Some(cext) = &self.cext {
            if let Some(id) = map_get_uint(cext, RECHECK_KEY) {
                return Some((id, true));
            }
        }
        if let Some(ext) = &self.ext {
            if let Some(id) = map_get_uint(ext, RECHECK_KEY) {
                return Some((id, false));
            }
        }
        None
    }

    /// Names `proc_id` as the body claim's re-check procedure. `critical` places it in the cext map
    /// (field 12, must-understand); otherwise the ext map (field 11, may-ignore). Creates the
    /// carrier if absent and leaves other extension entries intact.
    pub fn set_recheck(&mut self, proc_id: u64, critical: bool) {
        let target = if critical {
            &mut self.cext
        } else {
            &mut self.ext
        };
        let m = target.get_or_insert_with(Vec::new);
        for entry in m.iter_mut() {
            if matches!(entry.0, Value::Uint(k) if k == RECHECK_KEY) {
                entry.1 = Value::Uint(proc_id);
                return;
            }
        }
        m.push((Value::Uint(RECHECK_KEY), Value::Uint(proc_id)));
    }

    /// Returns the forward-only per-signer position the object names (SIGNER_COUNTER_KEY, §2.5.2):
    /// `Some(seq)` iff a counter is named in the non-critical ext map (field 11) as a uint, else
    /// `None`. The field is OPTIONAL (`None` is valid). Presence is keyed on the KEY, not the value:
    /// a present counter of value 0 returns `Some(0)`.
    pub fn signer_counter(&self) -> Option<u64> {
        match &self.ext {
            Some(ext) => map_get_uint(ext, SIGNER_COUNTER_KEY),
            None => None,
        }
    }

    /// Names `seq` as this object's forward-only per-signer position in the NON-CRITICAL ext map
    /// (field 11), covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent
    /// and leaves other extension entries intact. The counter is deliberately never placed in the
    /// critical cext map (it is detection, not a verification gate).
    pub fn set_signer_counter(&mut self, seq: u64) {
        let m = self.ext.get_or_insert_with(Vec::new);
        for entry in m.iter_mut() {
            if matches!(entry.0, Value::Uint(k) if k == SIGNER_COUNTER_KEY) {
                entry.1 = Value::Uint(seq);
                return;
            }
        }
        m.push((Value::Uint(SIGNER_COUNTER_KEY), Value::Uint(seq)));
    }

    /// Returns the producing-boundary disclosure the object names (PRODUCING_BOUNDARY_KEY, §2.5.4):
    /// `Some(pb)` iff a WELL-FORMED disclosure is carried in the non-critical ext map (field 11) — a
    /// non-empty boundary (key 1), a kind (key 2) in {observed, reported}, and a reporting-boundary
    /// (key 3) absent unless the kind is reported. A malformed value is IGNORED (`None`) and the
    /// object still verifies (may-ignore). The field is OPTIONAL (`None` is valid). An unrecognized
    /// sub-key is ignored (may-ignore).
    pub fn producing_boundary(&self) -> Option<ProducingBoundary> {
        let ext = self.ext.as_ref()?;
        let pairs = match map_get_value(ext, PRODUCING_BOUNDARY_KEY)? {
            Value::Map(pairs) => pairs,
            _ => return None,
        };
        let (mut boundary, mut kind, mut reporting) = (None, None, None);
        for (key, val) in pairs {
            match key {
                Value::Uint(k) if *k == PB_FIELD_BOUNDARY => match val {
                    Value::Bstr(b) => boundary = Some(b.clone()),
                    _ => return None,
                },
                Value::Uint(k) if *k == PB_FIELD_KIND => match val {
                    Value::Uint(u) => kind = Some(*u),
                    _ => return None,
                },
                Value::Uint(k) if *k == PB_FIELD_REPORTING => match val {
                    Value::Bstr(b) => reporting = Some(b.clone()),
                    _ => return None,
                },
                Value::Uint(_) => {} // an unrecognized sub-key: may-ignore
                _ => return None,    // a non-uint sub-key is malformed
            }
        }
        let boundary = boundary?;
        if boundary.is_empty() {
            return None; // no boundary named
        }
        let kind = kind?;
        if kind != PRODUCING_BOUNDARY_OBSERVED && kind != PRODUCING_BOUNDARY_REPORTED {
            return None; // absent or out-of-enum kind
        }
        if reporting.is_some() && kind != PRODUCING_BOUNDARY_REPORTED {
            return None; // a reporting-boundary under observed: an observer relays from no one
        }
        Some(ProducingBoundary { boundary, kind, reporting })
    }

    /// Names `pb` as this object's producing-boundary disclosure in the NON-CRITICAL ext map
    /// (field 11), covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent
    /// and leaves other extension entries intact. The reporting-boundary is emitted ONLY when `Some`
    /// AND the kind is reported, so a caller cannot accidentally build a malformed
    /// observed-with-reporting disclosure (an observer relays from no one).
    pub fn set_producing_boundary(&mut self, pb: &ProducingBoundary) {
        let mut sub = vec![
            (Value::Uint(PB_FIELD_BOUNDARY), Value::Bstr(pb.boundary.clone())),
            (Value::Uint(PB_FIELD_KIND), Value::Uint(pb.kind)),
        ];
        if let Some(r) = &pb.reporting {
            if pb.kind == PRODUCING_BOUNDARY_REPORTED {
                sub.push((Value::Uint(PB_FIELD_REPORTING), Value::Bstr(r.clone())));
            }
        }
        let m = self.ext.get_or_insert_with(Vec::new);
        for entry in m.iter_mut() {
            if matches!(entry.0, Value::Uint(k) if k == PRODUCING_BOUNDARY_KEY) {
                entry.1 = Value::Map(sub);
                return;
            }
        }
        m.push((Value::Uint(PRODUCING_BOUNDARY_KEY), Value::Map(sub)));
    }
}

/// The value under key `k` in a CBOR map, if the key is present (any value type).
fn map_get_value(m: &[(Value, Value)], k: u64) -> Option<&Value> {
    for (key, val) in m {
        if matches!(key, Value::Uint(u) if *u == k) {
            return Some(val);
        }
    }
    None
}

/// The uint value under key `k` in a CBOR map, if present as a uint.
fn map_get_uint(m: &[(Value, Value)], k: u64) -> Option<u64> {
    for (key, val) in m {
        if matches!(key, Value::Uint(u) if *u == k) {
            return match val {
                Value::Uint(v) => Some(*v),
                _ => None,
            };
        }
    }
    None
}

/// One detected per-signer counter conflict: two or more DISTINCT objects (distinct content ids)
/// from the SAME signer id carrying the SAME forward-only counter value. A forward-only counter
/// binds each value to at most one object, so a value bound to >= 2 distinct objects is the
/// observable fingerprint of the key incrementing in two places (key duplication). The finding
/// surfaces BOTH sides: the reused `counter` and every conflicting content id (`ids`, ascending).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicationFinding {
    pub signer: Vec<u8>,
    pub counter: u64,
    pub ids: Vec<Vec<u8>>,
}

/// Scans a SET of PRESENTED objects for per-signer counter reuse. This is DETECTION, not prevention
/// (NAALP-REQ-120): it flags a signer id ONLY when two conflicting sequences from that signer
/// physically MEET in the presented set — a counter value bound to >= 2 distinct content ids by one
/// signer. Given only ONE object per value it returns no findings; the second conflicting object
/// must be present, unsuppressed, for the duplication to become provable. Objects with no counter do
/// not participate. Output is deterministic (findings ordered by signer id then counter; ids within
/// a finding ascending). It operates over the SET, never per object. Byte-identical to impl/go.
pub fn detect_signer_duplication(objs: &[Object]) -> Vec<DuplicationFinding> {
    use std::collections::{BTreeMap, BTreeSet};
    // signer -> counter -> set of content ids (BTreeMap/BTreeSet give the deterministic ascending
    // order; the set de-dups a byte-identical re-presentation so it is NOT a conflict).
    let mut groups: BTreeMap<Vec<u8>, BTreeMap<u64, BTreeSet<Vec<u8>>>> = BTreeMap::new();
    for o in objs {
        let seq = match o.signer_counter() {
            Some(s) => s,
            None => continue, // a counter-less object does not participate
        };
        let id = match cbor::content_id(&o.body_map(false)) {
            Ok(i) => i,
            Err(_) => continue, // a body that cannot be canonically encoded cannot be presented
        };
        groups
            .entry(o.signer.clone())
            .or_default()
            .entry(seq)
            .or_default()
            .insert(id);
    }
    let mut findings = Vec::new();
    for (signer, by_counter) in &groups {
        for (counter, idset) in by_counter {
            // A (signer, counter) binding two-or-more DISTINCT content ids is a detected
            // duplication. The `< 2` guard is the detection-requires-both invariant: relax it to
            // `< 1` (flag from one) and a single sequence would flag (prevention theatre).
            if idset.len() < 2 {
                continue;
            }
            let ids: Vec<Vec<u8>> = idset.iter().cloned().collect();
            findings.push(DuplicationFinding {
                signer: signer.clone(),
                counter: *counter,
                ids,
            });
        }
    }
    findings
}

fn protected_header(alg: i64, signer: &[u8], profile: u64) -> Vec<u8> {
    let naalp = Value::Map(vec![
        (Value::Uint(1), Value::Bstr(signer.to_vec())),
        (Value::Uint(2), Value::Uint(profile)),
        (Value::Uint(3), Value::Uint(NAALP_VERSION)),
    ]);
    let hdr = Value::Map(vec![
        (Value::Uint(1), Value::Nint(alg)),
        (Value::Tstr(NAALP_HEADER_LABEL.into()), naalp),
    ]);
    cbor::encode(&hdr).expect("encode protected header")
}

/// Assemble, content-id-bind, and sign a full N-AALP object. The signed suite field (14) is
/// set present iff the signer is a composite (§4.2), so a pure object omits it and stays
/// byte-identical to a pre-composite object.
pub fn sign(o: &mut Object, signer: &dyn CoseSigner) -> Vec<u8> {
    o.suite = composite_suite_for_alg(signer.alg()).unwrap_or(0);
    o.id = o.content_id();
    let payload = cbor::encode(&o.body_map(true)).expect("encode body");
    let prot = protected_header(signer.alg(), &o.signer, o.profile);
    let tbs = cose::to_be_signed_raw(&prot, &payload);
    let sig = signer.sign(&tbs);
    cose::assemble_sign1_raw(&prot, &payload, &sig)
}

/// Verify a signed N-AALP object end-to-end, offline. Check order (fail-closed): decode
/// -> content-id -> field ranges -> header/body copies + version -> critical extensions
/// -> kind/channel dispatch -> profile floor -> signature.
// Decoder-bound errors (design.md §3.4, R7). DepthExceeded is raised in cbor::decode_bounded
// and surfaced here via decode_and_check.
fn e_too_large() -> cose::Error {
    err("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
}
fn e_too_many_causes() -> cose::Error {
    err("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)")
}
fn e_too_many_extensions() -> cose::Error {
    err(
        "TooManyExtensions",
        "ext/cext exceeds the maximum cardinality (§3.4, R7)",
    )
}

pub fn verify(
    profile: u32,
    v: &dyn CoseVerifier,
    kind_ok: &dyn Fn(u64, u64) -> bool,
    known_cext: &[u64],
    obj: &[u8],
) -> Result<Object, cose::Error> {
    // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw
    // bytes, before any parse (RFC 8949 §10 decoder-memory guard).
    if obj.len() > MAX_OBJECT_SIZE as usize {
        return Err(e_too_large());
    }
    let (prot, payload, sig) = cose::parse_sign1_raw(obj).map_err(|_| e_malformed())?;
    let (o, alg) = decode_and_check(&prot, &payload, known_cext)?;

    // A Rotation object (Identity channel, kind 0) MUST be a tag-98 COSE_Sign co-signed by the
    // old AND new key (§5.2); a single-Sign1 rotation is missing the old-key co-signature, so it
    // is rejected here (RotationUnauthorized) rather than accepted on the new key alone. This is
    // the #143 STRENGTHENING; the co-signed path is verify_rotation_object.
    if is_rotation_object(o.channel, o.kind) {
        return Err(e_rotation_unauthorized());
    }

    // kind/channel surface dispatch.
    if !kind_ok(o.channel, o.kind) {
        return Err(e_ukind());
    }

    // profile floor + signed suite declaration + COSE signature (reuse the C2 registry).
    let level = cose::alg_level_of(alg).ok_or_else(cose::err_unknown_alg)?;
    let tbs = cose::to_be_signed_raw(&prot, &payload);

    if alg == cose::ALG_COMPOSITE_65_ED25519 {
        // Opt-in composite path (§4.2/§4.4/§4.5). Check order: CompositeRefused (Sovereign) ->
        // SuiteMismatch (field 14 must declare the matching suite) -> ProfileDowngrade ->
        // KeyAlgMismatch (a composite verifier is required) -> both-leg signature.
        if profile == cose::PROFILE_SOVEREIGN {
            return Err(cose::err_composite_refused());
        }
        if o.suite != SUITE_MLDSA65_ED25519 {
            return Err(cose::err_suite_mismatch());
        }
        if level < cose::profile_min_level_of(profile) {
            return Err(cose::err_downgrade());
        }
        if alg != v.alg() {
            return Err(cose::err_key_alg_mismatch());
        }
        // verify_detailed surfaces HybridIncomplete (single-leg failure) / Malformed via the
        // CompositeVerifier override; a non-composite verifier is already rejected above.
        return v.verify_detailed(&tbs, &sig).map(|_| o);
    }

    // pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
    if o.suite != 0 {
        return Err(cose::err_suite_mismatch());
    }
    if level < cose::profile_min_level_of(profile) {
        return Err(cose::err_downgrade());
    }
    if alg != v.alg() {
        return Err(cose::err_key_alg_mismatch());
    }
    if !v.verify_raw(&tbs, &sig) {
        return Err(cose::err_bad_signature());
    }
    Ok(o)
}

/// decode_and_check runs the tag-agnostic object checks over a (protected, payload) pair and
/// returns the decoded Object and its header alg: decode (NonCanonical surfaced) -> content-id ->
/// field ranges -> header/body copies + version -> critical extensions. It does NOT do the
/// kind/channel dispatch or the signature (those are tag-specific). The tag-18 verify and the
/// tag-98 rotation path both call it, so the two never drift on these checks.
fn decode_and_check(
    prot: &[u8],
    payload: &[u8],
    known_cext: &[u64],
) -> Result<(Object, i64), cose::Error> {
    let bv = cbor::decode_bounded(payload, MAX_NESTING_DEPTH as usize).map_err(|e| err(e.kind, e.msg))?; // NonCanonical / DepthExceeded surface here (§3.4, R7)
    let body = match bv {
        Value::Map(m) => m,
        _ => return Err(e_malformed()),
    };

    let mut claimed: Option<Vec<u8>> = None;
    let mut without_id: Vec<(Value, Value)> = Vec::with_capacity(body.len());
    for (k, val) in &body {
        if matches!(k, Value::Uint(FIELD_ID)) {
            match val {
                Value::Bstr(b) => claimed = Some(b.clone()),
                _ => return Err(e_malformed()),
            }
            continue;
        }
        without_id.push((k.clone(), val.clone()));
    }
    let claimed = claimed.ok_or_else(e_malformed)?;
    let recomputed = cbor::content_id(&Value::Map(without_id)).map_err(|_| e_malformed())?;
    if recomputed != claimed {
        return Err(e_cid());
    }

    let o = object_from_map(&body)?;

    if o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3 {
        return Err(e_range());
    }

    let (alg, h_signer, h_profile, h_version) = parse_protected(prot)?;
    if h_version != NAALP_VERSION {
        return Err(e_version());
    }
    if h_signer != o.signer || h_profile != o.profile {
        return Err(e_hbm());
    }

    if let Some(cext) = &o.cext {
        for (k, v) in cext {
            match k {
                Value::Uint(u) if *u == RECHECK_KEY => match v {
                    Value::Uint(id) if is_known_recheck_procedure(*id) => {}
                    Value::Uint(_) => return Err(e_ucext()),
                    _ => return Err(e_malformed()),
                },
                Value::Uint(u) if known_cext.contains(u) => {}
                _ => return Err(e_ucext()),
            }
        }
    }
    Ok((o, alg))
}

// --- C4 Rotation object: tag-98 COSE_Sign co-signed by old+new (design.md §5.2) --------
//
// A Rotation object is the ONE object carried as a COSE_Sign (tag 98); every other kind is a
// single COSE_Sign1 (tag 18). The single-Sign1 rotation gap (a rotation accepted on the new key
// alone) is closed by rejecting a tag-18 Rotation object in `verify` (RotationUnauthorized) and
// requiring the old+new co-signature here. Reuses the existing RotationUnauthorized kind.

fn e_rotation_unauthorized() -> cose::Error {
    err(
        "RotationUnauthorized",
        "rotation object not co-signed by the old key",
    )
}

/// Reports whether (channel, kind) selects the Identity-channel Rotation object (channel 0x0003,
/// kind 0; vectors/registry/channels.csv, design.md §5.2). Byte-identical to impl/go.
fn is_rotation_object(channel: u64, kind: u64) -> bool {
    channel == 3 && kind == 0
}

/// Whether `alg` is a composite (LAMPS) signature alg — undecided inside a rotation's old/new
/// co-signature, so rejected fail-closed.
fn is_composite_alg(alg: i64) -> bool {
    alg == cose::ALG_COMPOSITE_65_ED25519 || alg == cose::ALG_COMPOSITE_44_ED25519
}

/// OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): when a Sovereign/High
/// verifier checks a rotation whose OLD (authorizing) key is below the profile's signature floor,
/// does the floor gate the OLD leg too, or only the NEW (go-forward) leg? DEFAULT = FAIL-CLOSED:
/// the floor applies to BOTH legs. Set false to floor only the new leg. Byte-identical to impl/go.
const ROTATION_OLD_LEG_FLOOR_APPLIES: bool = true;

/// Build a Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in fixed
/// order (design.md §5.2); each leg signs the per-signer ToBeSigned over the full object payload,
/// and the body protected header names the NEW (go-forward) key. Permitted ONLY for the
/// Identity-channel Rotation object (channel 3, kind 0); a composite signer for either leg is
/// rejected fail-closed (Malformed). Byte-identical to impl/go.
pub fn sign_rotation(
    o: &mut Object,
    old_signer: &dyn CoseSigner,
    new_signer: &dyn CoseSigner,
) -> Result<Vec<u8>, cose::Error> {
    if !is_rotation_object(o.channel, o.kind) {
        return Err(e_ukind());
    }
    if is_composite_alg(old_signer.alg()) || is_composite_alg(new_signer.alg()) {
        return Err(e_malformed());
    }
    o.suite = 0; // a rotation object is never composite
    o.id = o.content_id();
    let payload = cbor::encode(&o.body_map(true)).expect("encode body");
    let body_prot = protected_header(new_signer.alg(), &o.signer, o.profile);
    let old_leg = cose::signature_leg(&body_prot, old_signer, &payload);
    let new_leg = cose::signature_leg(&body_prot, new_signer, &payload);
    Ok(cose::assemble_sign_raw(
        &body_prot,
        &payload,
        &[old_leg, new_leg],
    ))
}

/// Verify a tag-98 Rotation object (design.md §5.2): the same object-body checks as `verify`, then
/// EXACTLY two legs in fixed order (old-key then new-key) BOTH verifying over the object payload.
/// Any missing/wrong/bad old leg is RotationUnauthorized. `old_v` is the verifier's trusted old
/// key; `new_v` is the object's go-forward key (both supplied by the caller). Permitted ONLY for
/// (channel 3, kind 0). Byte-identical behaviour to impl/go.
pub fn verify_rotation_object(
    profile: u32,
    old_v: &dyn CoseVerifier,
    new_v: &dyn CoseVerifier,
    kind_ok: &dyn Fn(u64, u64) -> bool,
    known_cext: &[u64],
    obj: &[u8],
) -> Result<Object, cose::Error> {
    // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
    // object too, so it is size-checked on raw bytes before any parse.
    if obj.len() > MAX_OBJECT_SIZE as usize {
        return Err(e_too_large());
    }
    let (body_prot, payload, legs) = cose::parse_sign_raw(obj).map_err(|_| e_malformed())?;
    let (o, alg) = decode_and_check(&body_prot, &payload, known_cext)?;

    if !is_rotation_object(o.channel, o.kind) {
        return Err(e_ukind());
    }
    if !kind_ok(o.channel, o.kind) {
        return Err(e_ukind());
    }
    if is_composite_alg(alg) {
        return Err(e_malformed()); // composite-inside-rotation is undecided; fail-closed
    }
    if alg != new_v.alg() {
        return Err(cose::err_key_alg_mismatch());
    }

    // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
    if legs.len() != 2 {
        return Err(e_rotation_unauthorized());
    }
    let old_alg = cose::alg_from_protected(&legs[0].protected).map_err(|_| e_malformed())?;
    let new_alg = cose::alg_from_protected(&legs[1].protected).map_err(|_| e_malformed())?;
    if is_composite_alg(old_alg) || is_composite_alg(new_alg) {
        return Err(e_malformed());
    }
    if old_alg != old_v.alg() || new_alg != new_v.alg() {
        return Err(e_rotation_unauthorized());
    }

    // profile floor: NEW leg always; OLD (authorizing) leg iff the fail-closed toggle applies.
    let new_level = cose::alg_level_of(new_alg).ok_or_else(cose::err_unknown_alg)?;
    if new_level < cose::profile_min_level_of(profile) {
        return Err(cose::err_downgrade());
    }
    if ROTATION_OLD_LEG_FLOOR_APPLIES {
        let old_level = cose::alg_level_of(old_alg).ok_or_else(cose::err_unknown_alg)?;
        if old_level < cose::profile_min_level_of(profile) {
            return Err(cose::err_downgrade());
        }
    }

    // both legs MUST verify over the per-signer ToBeSigned; any missing/wrong/bad leg is
    // RotationUnauthorized (the old-key-mandatory semantics of identity::verify_rotation).
    let old_tbs = cose::signature_to_be_signed(&body_prot, old_alg, &payload);
    if !old_v.verify_raw(&old_tbs, &legs[0].sig) {
        return Err(e_rotation_unauthorized());
    }
    let new_tbs = cose::signature_to_be_signed(&body_prot, new_alg, &payload);
    if !new_v.verify_raw(&new_tbs, &legs[1].sig) {
        return Err(e_rotation_unauthorized());
    }
    Ok(o)
}

fn object_from_map(m: &[(Value, Value)]) -> Result<Object, cose::Error> {
    let mut o = Object {
        id: vec![],
        kind: 0,
        channel: 0,
        tier: 0,
        signer: vec![],
        created: 0,
        effect: 0,
        causes: vec![],
        profile: 0,
        body: Value::Uint(0),
        ext: None,
        cext: None,
        audience: String::new(),
        suite: 0,
    };
    let (mut hk, mut hc, mut ht, mut hs, mut hcr, mut he, mut hca, mut hp, mut hb) = (
        false, false, false, false, false, false, false, false, false,
    );
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => *u,
            _ => return Err(e_malformed()),
        };
        match key {
            FIELD_ID => match val {
                Value::Bstr(b) => o.id = b.clone(),
                _ => return Err(e_malformed()),
            },
            FIELD_KIND => {
                o.kind = as_uint(val)?;
                hk = true;
            }
            FIELD_CHANNEL => {
                o.channel = as_uint(val)?;
                hc = true;
            }
            FIELD_TIER => {
                o.tier = as_uint(val)?;
                ht = true;
            }
            FIELD_SIGNER => match val {
                Value::Bstr(b) => {
                    o.signer = b.clone();
                    hs = true;
                }
                _ => return Err(e_malformed()),
            },
            FIELD_CREATED => {
                o.created = as_uint(val)?;
                hcr = true;
            }
            FIELD_EFFECT => {
                o.effect = as_uint(val)?;
                he = true;
            }
            FIELD_CAUSES => match val {
                Value::Arr(a) => {
                    if a.len() > MAX_CAUSES as usize {
                        return Err(e_too_many_causes()); // causal fan-in bound (§3.4, R7)
                    }
                    for it in a {
                        match it {
                            Value::Bstr(b) => o.causes.push(b.clone()),
                            _ => return Err(e_malformed()),
                        }
                    }
                    hca = true;
                }
                _ => return Err(e_malformed()),
            },
            FIELD_PROFILE => {
                o.profile = as_uint(val)?;
                hp = true;
            }
            FIELD_BODY => {
                o.body = val.clone();
                hb = true;
            }
            FIELD_EXT => match val {
                Value::Map(mm) => {
                    if mm.len() > MAX_EXT as usize {
                        return Err(e_too_many_extensions()); // ext cardinality bound (§3.4, R7)
                    }
                    o.ext = Some(mm.clone());
                }
                _ => return Err(e_malformed()),
            },
            FIELD_CEXT => match val {
                Value::Map(mm) => {
                    if mm.len() > MAX_CEXT as usize {
                        return Err(e_too_many_extensions()); // cext cardinality bound (§3.4, R7)
                    }
                    o.cext = Some(mm.clone());
                }
                _ => return Err(e_malformed()),
            },
            FIELD_AUDIENCE => match val {
                Value::Tstr(s) => o.audience = s.clone(),
                _ => return Err(e_malformed()),
            },
            FIELD_SUITE => o.suite = as_uint(val)?,
            _ => return Err(e_malformed()), // unknown top-level field
        }
    }
    if hk && hc && ht && hs && hcr && he && hca && hp && hb {
        Ok(o)
    } else {
        Err(e_malformed())
    }
}

fn as_uint(v: &Value) -> Result<u64, cose::Error> {
    match v {
        Value::Uint(u) => Ok(*u),
        _ => Err(e_malformed()),
    }
}

fn parse_protected(prot: &[u8]) -> Result<(i64, Vec<u8>, u64, u64), cose::Error> {
    // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an empty
    // CBOR map (the 0x41A0 form — its unwrapped content is the single byte 0xA0) is the one
    // redundant encoding RFC 9052 §3 otherwise permits, and MUST be rejected as NonCanonical
    // before the header is interpreted (else it dies downstream as a generic Malformed / no-alg).
    if prot.len() == 1 && prot[0] == 0xA0 {
        return Err(err(
            "NonCanonical",
            "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)",
        ));
    }
    let pv = cbor::decode(prot).map_err(|_| e_malformed())?;
    let m = match pv {
        Value::Map(m) => m,
        _ => return Err(e_malformed()),
    };
    let (mut alg, mut signer, mut profile, mut version) = (0i64, vec![], 0u64, 0u64);
    let (mut have_alg, mut have_naalp) = (false, false);
    for (k, val) in &m {
        match k {
            Value::Uint(1) => match val {
                Value::Nint(a) => {
                    alg = *a;
                    have_alg = true;
                }
                _ => return Err(e_malformed()),
            },
            Value::Tstr(s) if s == NAALP_HEADER_LABEL => {
                let nm = match val {
                    Value::Map(nm) => nm,
                    _ => return Err(e_malformed()),
                };
                for (nk, nv) in nm {
                    match nk {
                        Value::Uint(1) => {
                            if let Value::Bstr(b) = nv {
                                signer = b.clone()
                            }
                        }
                        Value::Uint(2) => {
                            if let Value::Uint(u) = nv {
                                profile = *u
                            }
                        }
                        Value::Uint(3) => {
                            if let Value::Uint(u) = nv {
                                version = *u
                            }
                        }
                        _ => {}
                    }
                }
                have_naalp = true;
            }
            _ => {}
        }
    }
    if have_alg && have_naalp {
        Ok((alg, signer, profile, version))
    } else {
        Err(e_malformed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/envelope/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn build_object(c: &J) -> Object {
        let o = &c["object"];
        Object {
            id: vec![],
            kind: o["kind"].as_u64().unwrap(),
            channel: o["channel"].as_u64().unwrap(),
            tier: o["tier"].as_u64().unwrap(),
            signer: hex::decode(o["signer_hex"].as_str().unwrap()).unwrap(),
            created: o["created"].as_u64().unwrap(),
            effect: o["effect"].as_u64().unwrap(),
            causes: o["causes_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
                .collect(),
            profile: o["profile"].as_u64().unwrap(),
            body: Value::Tstr(o["body_str"].as_str().unwrap().to_string()),
            ext: None,
            cext: None,
            audience: String::new(),
            suite: 0,
        }
    }

    fn test_keys() -> (cose::MlDsa65Signer, cose::MlDsa65Verifier) {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&seed);
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk))
    }

    fn accept_kind(ch: u64, k: u64) -> bool {
        ch == 4 && k == 2
    }

    #[test]
    fn envelope_bytes_match_oracle() {
        let c = load();
        let o = build_object(&c);
        let ob = &c["object"];
        assert_eq!(
            hex::encode(o.content_id()),
            ob["content_id_hex"].as_str().unwrap(),
            "content-id"
        );
        assert_eq!(
            hex::encode(cbor::encode(&o.body_map(false)).unwrap()),
            ob["body_no_id_hex"].as_str().unwrap(),
            "body-no-id"
        );
        let mut o2 = o.clone();
        o2.id = o.content_id();
        assert_eq!(
            hex::encode(cbor::encode(&o2.body_map(true)).unwrap()),
            ob["payload_hex"].as_str().unwrap(),
            "payload"
        );
        let prot = protected_header(ob["alg"].as_i64().unwrap(), &o.signer, o.profile);
        assert_eq!(
            hex::encode(&prot),
            ob["protected_hex"].as_str().unwrap(),
            "protected"
        );
        let payload = cbor::encode(&o2.body_map(true)).unwrap();
        assert_eq!(
            hex::encode(cose::to_be_signed_raw(&prot, &payload)),
            ob["tobesigned_hex"].as_str().unwrap(),
            "tobesigned"
        );
    }

    // Grade the field-13 audience object byte-construction against the independent oracle (F3): the
    // SAME worked object plus the audience reproduces the oracle's body-no-id, content-id, payload,
    // and to-be-signed. Byte-identical to impl/go by construction.
    #[test]
    fn audience_bytes_match_oracle() {
        let c = load();
        let a = &c["object_with_audience"];
        let mut o = build_object(&c);
        o.audience = a["audience"].as_str().unwrap().to_string();
        assert_eq!(
            hex::encode(cbor::encode(&o.body_map(false)).unwrap()),
            a["body_no_id_hex"].as_str().unwrap(),
            "audience body-no-id"
        );
        assert_eq!(
            hex::encode(o.content_id()),
            a["content_id_hex"].as_str().unwrap(),
            "audience content-id"
        );
        let mut o2 = o.clone();
        o2.id = o.content_id();
        assert_eq!(
            hex::encode(cbor::encode(&o2.body_map(true)).unwrap()),
            a["payload_hex"].as_str().unwrap(),
            "audience payload"
        );
        let prot = protected_header(c["object"]["alg"].as_i64().unwrap(), &o.signer, o.profile);
        assert_eq!(
            hex::encode(&prot),
            a["protected_hex"].as_str().unwrap(),
            "audience protected"
        );
        let payload = cbor::encode(&o2.body_map(true)).unwrap();
        assert_eq!(
            hex::encode(cose::to_be_signed_raw(&prot, &payload)),
            a["tobesigned_hex"].as_str().unwrap(),
            "audience tobesigned"
        );
    }

    // The 3-branch point-of-use check (§2.5.3). Mutation-surviving: replacing check_audience's body
    // with Ok(()) flips the three reject cases below.
    #[test]
    fn check_audience_branches() {
        let mk = |aud: &str| Object {
            id: vec![],
            kind: 0,
            channel: 0,
            tier: 0,
            signer: vec![],
            created: 0,
            effect: 0,
            causes: vec![],
            profile: 0,
            body: Value::Uint(0),
            ext: None,
            cext: None,
            audience: aud.to_string(),
            suite: 0,
        };
        let sa = "authority-A";
        assert!(check_audience(&mk("authority-A"), sa, true).is_ok());
        assert_eq!(
            check_audience(&mk("authority-B"), sa, true)
                .unwrap_err()
                .kind,
            "WrongAudience"
        );
        assert_eq!(
            check_audience(&mk(""), sa, true).unwrap_err().kind,
            "WrongAudience"
        );
        assert!(check_audience(&mk(""), sa, false).is_ok());
        assert!(check_audience(&mk("authority-A"), sa, false).is_ok());
        assert_eq!(
            check_audience(&mk("authority-B"), sa, false)
                .unwrap_err()
                .kind,
            "WrongAudience"
        );
    }

    #[test]
    fn sign_verify_offline() {
        let c = load();
        let (s, v) = test_keys();
        let mut o = build_object(&c);
        let obj = sign(&mut o, &s);
        let got = verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj).expect("verify valid");
        assert_eq!((got.channel, got.kind, got.effect), (4, 2, 2));
    }

    // Decoder bounds (design.md §3.4, R7). Each bound is proven by a boundary pair: an
    // otherwise-valid object AT the limit verifies, and one past it is rejected with the
    // named error. "Otherwise valid" is load-bearing for mutation survival.

    fn make_causes(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|_| {
                let mut b = vec![0u8; 50]; // content-id-shaped bstr (multihash sha2-384)
                b[0] = 0x20;
                b[1] = 0x30;
                b
            })
            .collect()
    }

    fn make_ext_map(n: usize) -> Vec<(Value, Value)> {
        (0..n)
            .map(|i| (Value::Uint(100 + i as u64), Value::Uint(0)))
            .collect()
    }

    fn nest_arrays(k: usize) -> Value {
        let mut v = Value::Uint(0);
        for _ in 0..k {
            v = Value::Arr(vec![v]);
        }
        v
    }

    #[test]
    fn bounds_accept_at_limit() {
        let c = load();
        let (s, v) = test_keys();
        let accept = |name: &str, o: &mut Object| {
            let obj = sign(o, &s);
            verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj)
                .unwrap_or_else(|e| panic!("{} verify at-limit: {}", name, e.kind));
        };

        let mut oc = build_object(&c);
        oc.causes = make_causes(MAX_CAUSES as usize);
        accept("causes==MAX_CAUSES", &mut oc);

        let mut oe = build_object(&c);
        oe.ext = Some(make_ext_map(MAX_EXT as usize));
        accept("ext==MAX_EXT", &mut oe);

        // deepest scalar at exactly MAX_NESTING_DEPTH (body map depth 1 + field-10 value depth 2).
        let mut od = build_object(&c);
        od.body = nest_arrays(MAX_NESTING_DEPTH as usize - 2);
        accept("depth==MAX_NESTING_DEPTH", &mut od);
    }

    #[test]
    fn bounds_reject_over_limit() {
        let c = load();
        let (s, v) = test_keys();
        let expect = |name: &str, o: &mut Object, kind: &str| {
            let obj = sign(o, &s);
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj) {
                Err(e) => assert_eq!(e.kind, kind, "{}", name),
                Ok(_) => panic!("{}: expected {}, got Ok", name, kind),
            }
        };

        let mut oc = build_object(&c);
        oc.causes = make_causes(MAX_CAUSES as usize + 1);
        expect("TooManyCauses", &mut oc, "TooManyCauses");

        let mut oe = build_object(&c);
        oe.ext = Some(make_ext_map(MAX_EXT as usize + 1));
        expect("TooManyExtensions(ext)", &mut oe, "TooManyExtensions");

        // cext over the limit also yields TooManyExtensions: the cardinality check fires in
        // object_from_map before the critical-extension recognition check.
        let mut ox = build_object(&c);
        ox.cext = Some(make_ext_map(MAX_CEXT as usize + 1));
        expect("TooManyExtensions(cext)", &mut ox, "TooManyExtensions");

        let mut od = build_object(&c);
        od.body = nest_arrays(MAX_NESTING_DEPTH as usize - 1);
        expect("DepthExceeded", &mut od, "DepthExceeded");
    }

    #[test]
    fn bound_too_large() {
        let c = load();
        let (s, v) = test_keys();

        let mut under = build_object(&c);
        under.body = Value::Bstr(vec![0u8; MAX_OBJECT_SIZE as usize - 16384]);
        let uobj = sign(&mut under, &s);
        assert!(
            uobj.len() <= MAX_OBJECT_SIZE as usize,
            "under-limit object is {} bytes",
            uobj.len()
        );
        verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &uobj).expect("verify under-limit");

        let mut over = build_object(&c);
        over.body = Value::Bstr(vec![0u8; MAX_OBJECT_SIZE as usize]);
        let bobj = sign(&mut over, &s);
        assert!(
            bobj.len() > MAX_OBJECT_SIZE as usize,
            "over-limit object is only {} bytes",
            bobj.len()
        );
        match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &bobj) {
            Err(e) => assert_eq!(e.kind, "TooLarge"),
            Ok(_) => panic!("TooLarge: expected reject, got Ok"),
        }
    }

    // --- opt-in composite signature integration (design.md §4.2) ----------------------

    fn composite_test_keys() -> (cose::CompositeSigner, cose::CompositeVerifier) {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&seed);
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(b"naalp-composite-ed25519-seed-32b");
        let ed_vk = ed_sk.verifying_key();
        (
            cose::CompositeSigner {
                ml65: sk,
                ed: ed_sk,
            },
            cose::CompositeVerifier {
                ml65: pk,
                ed: ed_vk,
            },
        )
    }

    // Assemble a signed object using the object's CALLER-SET suite (bypassing sign's
    // present-iff-composite auto-derive), so a test can build SuiteMismatch cases.
    fn sign_whitebox(o: &mut Object, signer: &dyn cose::CoseSigner) -> Vec<u8> {
        o.id = o.content_id();
        let payload = cbor::encode(&o.body_map(true)).unwrap();
        let prot = protected_header(signer.alg(), &o.signer, o.profile);
        let sig = signer.sign(&cose::to_be_signed_raw(&prot, &payload));
        cose::assemble_sign1_raw(&prot, &payload, &sig)
    }

    #[test]
    fn composite_object_roundtrip() {
        let c = load();
        let (cs, cv) = composite_test_keys();
        let mut o = build_object(&c);
        let obj = sign(&mut o, &cs);
        assert_eq!(
            o.suite, SUITE_MLDSA65_ED25519,
            "composite sign sets field 14"
        );
        let got =
            verify(cose::PROFILE_PUBLIC, &cv, &accept_kind, &[], &obj).expect("verify composite");
        assert_eq!(got.suite, SUITE_MLDSA65_ED25519);
        let (_, pv) = test_keys();
        match verify(cose::PROFILE_PUBLIC, &pv, &accept_kind, &[], &obj) {
            Err(e) => assert_eq!(e.kind, "KeyAlgMismatch"),
            Ok(_) => panic!("pure verifier on composite object accepted"),
        }
    }

    #[test]
    fn composite_object_hybrid_incomplete() {
        let c = load();
        let (cs, cv) = composite_test_keys();
        let mut o = build_object(&c);
        let obj = sign(&mut o, &cs);
        let mut tampered = obj.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01; // corrupt the trailing Ed25519 leg byte
        match verify(cose::PROFILE_PUBLIC, &cv, &accept_kind, &[], &tampered) {
            Err(e) => assert_eq!(e.kind, "HybridIncomplete"),
            Ok(_) => panic!("tampered composite accepted"),
        }
    }

    #[test]
    fn composite_suite_mismatch() {
        let c = load();
        let (ps, pv) = test_keys();
        let (cs, cv) = composite_test_keys();
        // (a) pure alg (-49) but the body carries field 14.
        let mut oa = build_object(&c);
        oa.suite = SUITE_MLDSA65_ED25519;
        match verify(
            cose::PROFILE_PUBLIC,
            &pv,
            &accept_kind,
            &[],
            &sign_whitebox(&mut oa, &ps),
        ) {
            Err(e) => assert_eq!(e.kind, "SuiteMismatch"),
            Ok(_) => panic!("pure alg + field 14 accepted"),
        }
        // (b) composite alg but field 14 absent.
        let mut ob = build_object(&c);
        ob.suite = 0;
        match verify(
            cose::PROFILE_PUBLIC,
            &cv,
            &accept_kind,
            &[],
            &sign_whitebox(&mut ob, &cs),
        ) {
            Err(e) => assert_eq!(e.kind, "SuiteMismatch"),
            Ok(_) => panic!("composite alg + no field 14 accepted"),
        }
        // (c) composite alg but WRONG suite id.
        let mut oc = build_object(&c);
        oc.suite = SUITE_MLDSA65_ED25519 + 1;
        match verify(
            cose::PROFILE_PUBLIC,
            &cv,
            &accept_kind,
            &[],
            &sign_whitebox(&mut oc, &cs),
        ) {
            Err(e) => assert_eq!(e.kind, "SuiteMismatch"),
            Ok(_) => panic!("composite alg + wrong suite accepted"),
        }
    }

    #[test]
    fn composite_refused_by_sovereign() {
        let c = load();
        let (cs, cv) = composite_test_keys();
        let mut o = build_object(&c);
        let obj = sign(&mut o, &cs);
        match verify(cose::PROFILE_SOVEREIGN, &cv, &accept_kind, &[], &obj) {
            Err(e) => assert_eq!(e.kind, "CompositeRefused"),
            Ok(_) => panic!("sovereign accepted composite"),
        }
    }

    // --- #143 Rotation object (tag-98 COSE_Sign, old+new co-signature; §5.2) -----------

    fn rotation_kind_ok(ch: u64, k: u64) -> bool {
        ch == 3 && k == 0
    }

    fn mldsa65_pair(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk))
    }

    fn rotation_object(c: &J) -> Object {
        let mut o = build_object(c);
        o.channel = 3;
        o.kind = 0;
        o.effect = 2;
        o
    }

    #[test]
    fn rotation_round_trip() {
        let c = load();
        let (old_s, old_v) = mldsa65_pair(11);
        let (new_s, new_v) = mldsa65_pair(22);
        let mut o = rotation_object(&c);
        let obj = sign_rotation(&mut o, &old_s, &new_s).expect("sign rotation");
        let got = verify_rotation_object(
            cose::PROFILE_PUBLIC,
            &old_v,
            &new_v,
            &rotation_kind_ok,
            &[],
            &obj,
        )
        .expect("verify rotation");
        assert_eq!((got.channel, got.kind), (3, 0));
    }

    // gap-fix mutation anchor: a tag-18 single-signature Rotation object is rejected.
    #[test]
    fn rotation_tag18_single_sig_rejected() {
        let c = load();
        let (new_s, new_v) = mldsa65_pair(22);
        let mut o = rotation_object(&c);
        let obj = sign(&mut o, &new_s);
        match verify(cose::PROFILE_PUBLIC, &new_v, &rotation_kind_ok, &[], &obj) {
            Err(e) => assert_eq!(e.kind, "RotationUnauthorized"),
            Ok(_) => panic!("tag-18 single-sig rotation accepted"),
        }
    }

    #[test]
    fn rotation_old_leg_dropped() {
        let c = load();
        let (old_s, old_v) = mldsa65_pair(11);
        let (new_s, new_v) = mldsa65_pair(22);
        let mut o = rotation_object(&c);
        let obj = sign_rotation(&mut o, &old_s, &new_s).unwrap();
        let (body_prot, payload, legs) = cose::parse_sign_raw(&obj).unwrap();
        let one = cose::assemble_sign_raw(&body_prot, &payload, std::slice::from_ref(&legs[1]));
        match verify_rotation_object(
            cose::PROFILE_PUBLIC,
            &old_v,
            &new_v,
            &rotation_kind_ok,
            &[],
            &one,
        ) {
            Err(e) => assert_eq!(e.kind, "RotationUnauthorized"),
            Ok(_) => panic!("dropped old leg accepted"),
        }
    }

    #[test]
    fn rotation_old_leg_wrong_key() {
        let c = load();
        let (_, old_v) = mldsa65_pair(11);
        let (new_s, new_v) = mldsa65_pair(22);
        let mut o = rotation_object(&c);
        let obj = sign_rotation(&mut o, &new_s, &new_s).unwrap(); // both legs the NEW key
        match verify_rotation_object(
            cose::PROFILE_PUBLIC,
            &old_v,
            &new_v,
            &rotation_kind_ok,
            &[],
            &obj,
        ) {
            Err(e) => assert_eq!(e.kind, "RotationUnauthorized"),
            Ok(_) => panic!("wrong old-key leg accepted"),
        }
    }

    #[test]
    fn rotation_tag98_non_rotation_kind() {
        let c = load();
        let (old_s, old_v) = mldsa65_pair(11);
        let (new_s, new_v) = mldsa65_pair(22);
        let mut o = build_object(&c); // channel 4, kind 2 (NOT rotation)
        o.suite = 0;
        o.id = o.content_id();
        let payload = cbor::encode(&o.body_map(true)).unwrap();
        let body_prot = protected_header(new_s.alg(), &o.signer, o.profile);
        let old_leg = cose::signature_leg(&body_prot, &old_s, &payload);
        let new_leg = cose::signature_leg(&body_prot, &new_s, &payload);
        let obj = cose::assemble_sign_raw(&body_prot, &payload, &[old_leg, new_leg]);
        match verify_rotation_object(
            cose::PROFILE_PUBLIC,
            &old_v,
            &new_v,
            &accept_kind,
            &[],
            &obj,
        ) {
            Err(e) => assert_eq!(e.kind, "UnknownKind"),
            Ok(_) => panic!("tag-98 non-rotation kind accepted"),
        }
    }

    // OPEN-DECISION evidence: old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign (floor 5).
    // With the default toggle (floor applies to BOTH legs) the sub-floor OLD leg -> ProfileDowngrade.
    #[test]
    fn rotation_sovereign_old_leg_floor() {
        let c = load();
        let (old_pk, old_sk) = cose::mldsa65_keypair_from_seed(&[33u8; 32]);
        let (new_pk, new_sk) = cose::mldsa87_keypair_from_seed(&[44u8; 32]);
        let old_s = cose::MlDsa65Signer(old_sk);
        let old_v = cose::MlDsa65Verifier(old_pk);
        let new_s = cose::MlDsa87Signer(new_sk);
        let new_v = cose::MlDsa87Verifier(new_pk);
        let mut o = rotation_object(&c);
        o.profile = 3; // Sovereign object
        let obj = sign_rotation(&mut o, &old_s, &new_s).unwrap();
        match verify_rotation_object(
            cose::PROFILE_SOVEREIGN,
            &old_v,
            &new_v,
            &rotation_kind_ok,
            &[],
            &obj,
        ) {
            Err(e) => assert_eq!(e.kind, "ProfileDowngrade"),
            Ok(_) => panic!("sovereign old-leg floor accepted"),
        }
    }

    fn expect_kind(name: &str, obj: &[u8], kind: &str, ko: &dyn Fn(u64, u64) -> bool, kc: &[u64]) {
        let (_, v) = test_keys();
        match verify(cose::PROFILE_PUBLIC, &v, ko, kc, obj) {
            Err(e) => assert_eq!(e.kind, kind, "{name}"),
            Ok(_) => panic!("{name}: accepted, want {kind}"),
        }
    }

    #[test]
    fn failure_modes() {
        let c = load();
        let (s, _) = test_keys();

        let valid = sign(&mut build_object(&c), &s);
        let mut bad = valid.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        expect_kind("BadSignature", &bad, "BadSignature", &accept_kind, &[]);

        let mut bogus = vec![0u8; 50];
        bogus[0] = 0x20;
        bogus[1] = 0x30;
        expect_kind(
            "ContentIdMismatch",
            &sign_with_id(&mut build_object(&c), &s, &bogus),
            "ContentIdMismatch",
            &accept_kind,
            &[],
        );

        expect_kind(
            "HeaderBodyMismatch",
            &sign_with_header_profile(&mut build_object(&c), &s, 2),
            "HeaderBodyMismatch",
            &accept_kind,
            &[],
        );

        let mut oc = build_object(&c);
        oc.cext = Some(vec![(Value::Uint(100), Value::Uint(7))]);
        expect_kind(
            "UnknownCriticalExt",
            &sign(&mut oc, &s),
            "UnknownCriticalExt",
            &accept_kind,
            &[],
        );

        // NonCanonical: payload is a map with out-of-order keys.
        let nc = sign_raw_payload(&s, &hex::decode("a203000200").unwrap());
        expect_kind("NonCanonical", &nc, "NonCanonical", &accept_kind, &[]);

        expect_kind("UnknownKind", &valid, "UnknownKind", &|_, _| false, &[]);

        let mut orange = build_object(&c);
        orange.channel = 99;
        expect_kind(
            "RangeError",
            &sign(&mut orange, &s),
            "RangeError",
            &|_, _| true,
            &[],
        );

        // draft-01 wire is version 2; version 1 (the superseded pre-recheck wire) is now rejected.
        expect_kind(
            "UnsupportedVersion",
            &sign_with_version(&mut build_object(&c), &s, 1),
            "UnsupportedVersion",
            &accept_kind,
            &[],
        );
    }

    #[test]
    fn non_critical_ext_ignored() {
        let c = load();
        let (s, v) = test_keys();
        let mut o = build_object(&c);
        o.ext = Some(vec![(Value::Uint(100), Value::Uint(7))]);
        let obj = sign(&mut o, &s);
        verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj)
            .expect("non-critical ext ignored");
    }

    #[test]
    fn known_critical_ext_accepted() {
        let c = load();
        let (s, v) = test_keys();
        let mut o = build_object(&c);
        o.cext = Some(vec![(Value::Uint(100), Value::Uint(7))]);
        let obj = sign(&mut o, &s);
        verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[100], &obj)
            .expect("known critical ext accepted");
    }

    // --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111) --------------------

    const RECHECK_VECTOR_PATH: &str = "../../vectors/recheck/cases.json";

    fn load_recheck() -> J {
        serde_json::from_str(
            &std::fs::read_to_string(RECHECK_VECTOR_PATH).expect("read recheck corpus"),
        )
        .expect("parse recheck corpus")
    }

    // Build the base object and apply the case's recheck placement — the only variable per case.
    fn build_recheck(base: &J, placement: &str, proc_id: Option<u64>) -> Object {
        let mut o = Object {
            id: vec![],
            kind: base["kind"].as_u64().unwrap(),
            channel: base["channel"].as_u64().unwrap(),
            tier: base["tier"].as_u64().unwrap(),
            signer: hex::decode(base["signer_hex"].as_str().unwrap()).unwrap(),
            created: base["created"].as_u64().unwrap(),
            effect: base["effect"].as_u64().unwrap(),
            causes: base["causes_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
                .collect(),
            profile: base["profile"].as_u64().unwrap(),
            body: Value::Tstr(base["body_str"].as_str().unwrap().to_string()),
            ext: None,
            cext: None,
            audience: String::new(),
            suite: 0,
        };
        match placement {
            "cext" => o.set_recheck(proc_id.unwrap(), true),
            "ext" => o.set_recheck(proc_id.unwrap(), false),
            "ext_empty" => o.ext = Some(vec![]), // present but empty (no recheck)
            "absent" => {}
            _ => panic!("unknown placement {placement}"),
        }
        o
    }

    // Grade recheck body bytes AND accept/reject verdicts against the independent oracle
    // (tools/recheck_oracle.py). known_cext is empty throughout — recheck is enforced by the
    // envelope, not the caller's critical-extension set. Byte-identical to impl/go by construction.
    #[test]
    fn recheck_matches_oracle() {
        let c = load_recheck();
        assert_eq!(
            c["recheck_key"].as_u64().unwrap(),
            RECHECK_KEY,
            "recheck_key"
        );
        let base = &c["base_object"];
        let (s, v) = test_keys();

        for tc in c["cases"].as_array().unwrap() {
            let name = tc["name"].as_str().unwrap();
            let placement = tc["placement"].as_str().unwrap();
            let proc_id = tc["procedure_id"].as_u64();
            let o = build_recheck(base, placement, proc_id);

            assert_eq!(
                hex::encode(cbor::encode(&o.body_map(false)).unwrap()),
                tc["body_no_id_hex"].as_str().unwrap(),
                "{name}: body-no-id"
            );
            assert_eq!(
                hex::encode(o.content_id()),
                tc["content_id_hex"].as_str().unwrap(),
                "{name}: content-id"
            );
            let mut o2 = o.clone();
            o2.id = o.content_id();
            assert_eq!(
                hex::encode(cbor::encode(&o2.body_map(true)).unwrap()),
                tc["full_hex"].as_str().unwrap(),
                "{name}: full-body"
            );

            let mut o3 = build_recheck(base, placement, proc_id);
            let signed = sign(&mut o3, &s);
            let expect = tc["expect"].as_str().unwrap();
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed) {
                Ok(got) => {
                    assert_eq!(expect, "accept", "{name}: accepted, want {expect}");
                    let present = tc["present"].as_bool().unwrap();
                    match got.recheck() {
                        Some((id, critical)) => {
                            assert!(present, "{name}: recheck present but corpus says absent");
                            assert_eq!(id, proc_id.unwrap(), "{name}: recheck id");
                            assert_eq!(
                                critical,
                                tc["critical"].as_bool().unwrap(),
                                "{name}: critical"
                            );
                        }
                        None => assert!(!present, "{name}: recheck absent but corpus says present"),
                    }
                }
                Err(e) => assert_eq!(e.kind, expect, "{name}: got {}, want {expect}", e.kind),
            }
        }

        for neg in c["negatives"].as_array().unwrap() {
            let name = neg["name"].as_str().unwrap();
            let payload = hex::decode(neg["payload_hex"].as_str().unwrap()).unwrap();
            let obj = sign_raw_payload(&s, &payload);
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj) {
                Err(e) => assert_eq!(e.kind, neg["expect"].as_str().unwrap(), "negative {name}"),
                Ok(_) => panic!("negative {name}: accepted, want {}", neg["expect"]),
            }
        }
    }

    // Mutation anchor for the reject path: a CRITICAL recheck naming an UNKNOWN procedure MUST be
    // rejected with UnknownCriticalExt; mutating the verify recheck branch to accept flips this
    // pass->fail. A known critical procedure and an unknown non-critical procedure both verify.
    #[test]
    fn recheck_reject_path_is_real() {
        let c = load();
        let (s, v) = test_keys();

        let mut cu = build_object(&c);
        cu.set_recheck(99, true); // unknown, critical
        match verify(
            cose::PROFILE_PUBLIC,
            &v,
            &accept_kind,
            &[],
            &sign(&mut cu, &s),
        ) {
            Err(e) => assert_eq!(e.kind, "UnknownCriticalExt"),
            Ok(_) => panic!("critical unknown recheck must be rejected"),
        }

        let mut ck = build_object(&c);
        ck.set_recheck(RECHECK_WALK_CAUSES, true); // known, critical
        verify(
            cose::PROFILE_PUBLIC,
            &v,
            &accept_kind,
            &[],
            &sign(&mut ck, &s),
        )
        .expect("known critical recheck must verify");

        let mut nu = build_object(&c);
        nu.set_recheck(99, false); // unknown, non-critical -> ignored
        verify(
            cose::PROFILE_PUBLIC,
            &v,
            &accept_kind,
            &[],
            &sign(&mut nu, &s),
        )
        .expect("unknown non-critical recheck must be ignored");
    }

    #[test]
    fn recheck_reader_round_trip() {
        let c = load();
        let mut o = build_object(&c);
        assert!(o.recheck().is_none(), "fresh object has no recheck");
        o.set_recheck(RECHECK_VERIFY_COSE_SIGN1, false);
        assert_eq!(o.recheck(), Some((RECHECK_VERIFY_COSE_SIGN1, false)));
        o.set_recheck(RECHECK_REPLAY_CONSUME_CHECK, true); // critical takes precedence
        assert_eq!(o.recheck(), Some((RECHECK_REPLAY_CONSUME_CHECK, true)));
    }

    // --- T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) ------

    const COUNTER_VECTOR_PATH: &str = "../../vectors/signer_counter/cases.json";

    fn load_counter() -> J {
        serde_json::from_str(
            &std::fs::read_to_string(COUNTER_VECTOR_PATH).expect("read counter corpus"),
        )
        .expect("parse counter corpus")
    }

    // A counter from the corpus is a bare JSON number (<= 2^53) or a QUOTED decimal string
    // (> 2^53, so a float64 JSON decoder cannot round it -- R12 / NAALP-01-03). Read either form
    // as the exact u64; None for JSON null / absent.
    fn counter_u64(v: &J) -> Option<u64> {
        if let Some(n) = v.as_u64() {
            Some(n)
        } else {
            v.as_str()
                .map(|s| s.parse::<u64>().expect("counter is a u64 decimal string"))
        }
    }

    // Build the shared base object from logical fields, with optional signer/body overrides.
    fn build_counter_base(base: &J, signer_hex: Option<&str>, body_str: Option<&str>) -> Object {
        Object {
            id: vec![],
            kind: base["kind"].as_u64().unwrap(),
            channel: base["channel"].as_u64().unwrap(),
            tier: base["tier"].as_u64().unwrap(),
            signer: hex::decode(signer_hex.unwrap_or(base["signer_hex"].as_str().unwrap()))
                .unwrap(),
            created: base["created"].as_u64().unwrap(),
            effect: base["effect"].as_u64().unwrap(),
            causes: base["causes_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
                .collect(),
            profile: base["profile"].as_u64().unwrap(),
            body: Value::Tstr(
                body_str
                    .unwrap_or(base["body_str"].as_str().unwrap())
                    .to_string(),
            ),
            ext: None,
            cext: None,
            audience: String::new(),
            suite: 0,
        }
    }

    fn apply_counter_placement(o: &mut Object, placement: &str, counter: Option<u64>) {
        match placement {
            "ext" => o.set_signer_counter(counter.unwrap()),
            // the counter placed in the CRITICAL map is an unrecognized critical extension.
            "cext" => {
                o.cext = Some(vec![(
                    Value::Uint(SIGNER_COUNTER_KEY),
                    Value::Uint(counter.unwrap()),
                )])
            }
            "ext_empty" => o.ext = Some(vec![]), // present but empty (no counter)
            "absent" => {}
            _ => panic!("unknown placement {placement}"),
        }
    }

    // Grade counter body bytes AND accept/reject verdicts against the independent oracle
    // (tools/signer_counter_oracle.py). Byte-identical to impl/go by construction.
    #[test]
    fn signer_counter_matches_oracle() {
        let c = load_counter();
        assert_eq!(
            c["counter_key"].as_u64().unwrap(),
            SIGNER_COUNTER_KEY,
            "counter_key"
        );
        let base = &c["base_object"];
        let (s, v) = test_keys();

        for tc in c["cases"].as_array().unwrap() {
            let name = tc["name"].as_str().unwrap();
            let placement = tc["placement"].as_str().unwrap();
            let counter = counter_u64(&tc["counter"]);
            let signer_hex = tc["signer_hex"].as_str();
            let body_str = tc["body_str"].as_str();

            let mut o = build_counter_base(base, signer_hex, body_str);
            apply_counter_placement(&mut o, placement, counter);
            assert_eq!(
                hex::encode(cbor::encode(&o.body_map(false)).unwrap()),
                tc["body_no_id_hex"].as_str().unwrap(),
                "{name}: body-no-id"
            );
            assert_eq!(
                hex::encode(o.content_id()),
                tc["content_id_hex"].as_str().unwrap(),
                "{name}: content-id"
            );
            let mut o2 = o.clone();
            o2.id = o.content_id();
            assert_eq!(
                hex::encode(cbor::encode(&o2.body_map(true)).unwrap()),
                tc["full_hex"].as_str().unwrap(),
                "{name}: full-body"
            );

            let mut o3 = build_counter_base(base, signer_hex, body_str);
            apply_counter_placement(&mut o3, placement, counter);
            let signed = sign(&mut o3, &s);
            let expect = tc["expect"].as_str().unwrap();
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed) {
                Ok(got) => {
                    assert_eq!(expect, "accept", "{name}: accepted, want {expect}");
                    let present = tc["present"].as_bool().unwrap();
                    match got.signer_counter() {
                        Some(seq) => {
                            assert!(present, "{name}: counter present but corpus says absent");
                            assert_eq!(seq, counter.unwrap(), "{name}: counter value");
                        }
                        None => assert!(!present, "{name}: counter absent but corpus says present"),
                    }
                }
                Err(e) => assert_eq!(e.kind, expect, "{name}: got {}, want {expect}", e.kind),
            }
        }

        for neg in c["negatives"].as_array().unwrap() {
            let name = neg["name"].as_str().unwrap();
            let payload = hex::decode(neg["payload_hex"].as_str().unwrap()).unwrap();
            let obj = sign_raw_payload(&s, &payload);
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj) {
                Err(e) => assert_eq!(e.kind, neg["expect"].as_str().unwrap(), "negative {name}"),
                Ok(_) => panic!("negative {name}: accepted, want {}", neg["expect"]),
            }
        }
    }

    // The counter is folded into the SIGNER's COSE_Sign1 signed input (ext is part of the signed
    // body): flipping the counter in a signed object's payload breaks verification.
    #[test]
    fn signer_counter_under_signature() {
        let c = load_counter();
        let base = &c["base_object"];
        let (s, v) = test_keys();
        let mut o = build_counter_base(base, None, None);
        o.set_signer_counter(5);
        let signed = sign(&mut o, &s);
        let got =
            verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed).expect("verify valid");
        assert_eq!(got.signer_counter(), Some(5), "counter read-back");

        // tamper: counter=6, keep the original (counter=5) content id + reuse the original signature.
        let mut tampered = build_counter_base(base, None, None);
        tampered.set_signer_counter(6);
        tampered.id = o.id.clone();
        let payload = cbor::encode(&tampered.body_map(true)).unwrap();
        let prot = protected_header(s.alg(), &tampered.signer, tampered.profile);
        let (_, _, orig_sig) = cose::parse_sign1_raw(&signed).unwrap();
        let forged = cose::assemble_sign1_raw(&prot, &payload, &orig_sig);
        assert!(
            verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &forged).is_err(),
            "tampered counter must be rejected (the counter is under signature)"
        );
    }

    #[test]
    fn signer_counter_reader_round_trip() {
        let c = load_counter();
        let mut o = build_counter_base(&c["base_object"], None, None);
        assert!(o.signer_counter().is_none(), "fresh object has no counter");
        o.set_signer_counter(42);
        assert_eq!(o.signer_counter(), Some(42));
        o.set_signer_counter(0); // present with value zero
        assert_eq!(
            o.signer_counter(),
            Some(0),
            "present-zero counter reads back present"
        );
    }

    // --- NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4) --

    const PB_VECTOR_PATH: &str = "../../vectors/producing_boundary/cases.json";

    fn load_pb() -> J {
        serde_json::from_str(&std::fs::read_to_string(PB_VECTOR_PATH).expect("read pb corpus"))
            .expect("parse pb corpus")
    }

    // Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields, reproducing the
    // oracle bytes for well-formed AND malformed values (the malformed cases cannot be built via
    // set_producing_boundary by design, so they are constructed here).
    fn apply_pb_placement(o: &mut Object, tc: &J) {
        let placement = tc["placement"].as_str().unwrap();
        if placement == "absent" {
            return;
        }
        let mut sub: Vec<(Value, Value)> = vec![];
        if let Some(bh) = tc["boundary_hex"].as_str() {
            sub.push((Value::Uint(1), Value::Bstr(hex::decode(bh).unwrap())));
        }
        if let Some(k) = tc["kind"].as_u64() {
            sub.push((Value::Uint(2), Value::Uint(k)));
        }
        if let Some(rh) = tc["reporting_hex"].as_str() {
            sub.push((Value::Uint(3), Value::Bstr(hex::decode(rh).unwrap())));
        }
        let ext = vec![(Value::Uint(PRODUCING_BOUNDARY_KEY), Value::Map(sub))];
        match placement {
            "ext" => o.ext = Some(ext),
            "cext" => o.cext = Some(ext),
            _ => panic!("unknown placement {placement}"),
        }
    }

    // Grade disclosure body bytes, accept/reject verdicts, AND the parsed disclosure against the
    // independent oracle (tools/producing_boundary_oracle.py). Byte-identical to impl/go by construction.
    #[test]
    fn producing_boundary_matches_oracle() {
        let c = load_pb();
        assert_eq!(
            c["producing_boundary_key"].as_u64().unwrap(),
            PRODUCING_BOUNDARY_KEY,
            "producing_boundary_key"
        );
        let base = &c["base_object"];
        let (s, v) = test_keys();

        for tc in c["cases"].as_array().unwrap() {
            let name = tc["name"].as_str().unwrap();
            let mut o = build_counter_base(base, None, None);
            apply_pb_placement(&mut o, tc);
            assert_eq!(
                hex::encode(cbor::encode(&o.body_map(false)).unwrap()),
                tc["body_no_id_hex"].as_str().unwrap(),
                "{name}: body-no-id"
            );
            assert_eq!(
                hex::encode(o.content_id()),
                tc["content_id_hex"].as_str().unwrap(),
                "{name}: content-id"
            );
            let mut o2 = o.clone();
            o2.id = o.content_id();
            assert_eq!(
                hex::encode(cbor::encode(&o2.body_map(true)).unwrap()),
                tc["full_hex"].as_str().unwrap(),
                "{name}: full-body"
            );

            let mut o3 = build_counter_base(base, None, None);
            apply_pb_placement(&mut o3, tc);
            let signed = sign(&mut o3, &s);
            let expect = tc["expect"].as_str().unwrap();
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed) {
                Ok(got) => {
                    assert_eq!(expect, "accept", "{name}: accepted, want {expect}");
                    let present = tc["present"].as_bool().unwrap();
                    match got.producing_boundary() {
                        Some(pb) => {
                            assert!(present, "{name}: disclosure present but corpus says absent");
                            let surf = &tc["surfaced"];
                            assert_eq!(pb.kind, surf["kind"].as_u64().unwrap(), "{name}: kind");
                            assert_eq!(
                                hex::encode(&pb.boundary),
                                surf["boundary_hex"].as_str().unwrap(),
                                "{name}: boundary"
                            );
                            match (&pb.reporting, surf["reporting_hex"].as_str()) {
                                (Some(r), Some(h)) => {
                                    assert_eq!(hex::encode(r), h, "{name}: reporting")
                                }
                                (None, None) => {}
                                _ => panic!("{name}: reporting presence mismatch"),
                            }
                        }
                        None => {
                            assert!(!present, "{name}: disclosure absent but corpus says present")
                        }
                    }
                }
                Err(e) => assert_eq!(e.kind, expect, "{name}: got {}, want {expect}", e.kind),
            }
        }

        for neg in c["negatives"].as_array().unwrap() {
            let name = neg["name"].as_str().unwrap();
            let payload = hex::decode(neg["payload_hex"].as_str().unwrap()).unwrap();
            let obj = sign_raw_payload(&s, &payload);
            match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj) {
                Err(e) => assert_eq!(e.kind, neg["expect"].as_str().unwrap(), "negative {name}"),
                Ok(_) => panic!("negative {name}: accepted, want {}", neg["expect"]),
            }
        }
    }

    // The disclosure is folded into the SIGNER's COSE_Sign1 signed input (ext is part of the signed
    // body): changing the boundary in a signed object's payload without re-signing breaks verification.
    #[test]
    fn producing_boundary_under_signature() {
        let c = load_pb();
        let base = &c["base_object"];
        let (s, v) = test_keys();
        let x = hex::decode("424f554e444152595f58").unwrap();
        let y = hex::decode("4f524947494e5f59").unwrap();
        let mut o = build_counter_base(base, None, None);
        o.set_producing_boundary(&ProducingBoundary {
            boundary: x.clone(),
            kind: PRODUCING_BOUNDARY_OBSERVED,
            reporting: None,
        });
        let signed = sign(&mut o, &s);
        let got =
            verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed).expect("verify valid");
        assert_eq!(
            got.producing_boundary().unwrap().kind,
            PRODUCING_BOUNDARY_OBSERVED,
            "disclosure read-back"
        );
        let mut tampered = build_counter_base(base, None, None);
        tampered.set_producing_boundary(&ProducingBoundary {
            boundary: y.clone(),
            kind: PRODUCING_BOUNDARY_OBSERVED,
            reporting: None,
        });
        tampered.id = o.id.clone();
        let payload = cbor::encode(&tampered.body_map(true)).unwrap();
        let prot = protected_header(s.alg(), &tampered.signer, tampered.profile);
        let (_, _, orig_sig) = cose::parse_sign1_raw(&signed).unwrap();
        let forged = cose::assemble_sign1_raw(&prot, &payload, &orig_sig);
        assert!(
            verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &forged).is_err(),
            "tampered producing-boundary must be rejected (it is under signature)"
        );
    }

    #[test]
    fn producing_boundary_reader_round_trip() {
        let c = load_pb();
        let mut o = build_counter_base(&c["base_object"], None, None);
        assert!(o.producing_boundary().is_none(), "fresh object has no disclosure");
        let x = hex::decode("424f554e444152595f58").unwrap();
        let y = hex::decode("4f524947494e5f59").unwrap();
        o.set_producing_boundary(&ProducingBoundary {
            boundary: x.clone(),
            kind: PRODUCING_BOUNDARY_REPORTED,
            reporting: Some(y.clone()),
        });
        let pb = o.producing_boundary().unwrap();
        assert_eq!(pb.kind, PRODUCING_BOUNDARY_REPORTED);
        assert_eq!(pb.boundary, x);
        assert_eq!(pb.reporting, Some(y.clone()));
        // the setter drops a reporting-boundary under observed.
        o.set_producing_boundary(&ProducingBoundary {
            boundary: x.clone(),
            kind: PRODUCING_BOUNDARY_OBSERVED,
            reporting: Some(y.clone()),
        });
        let pb = o.producing_boundary().unwrap();
        assert_eq!(pb.kind, PRODUCING_BOUNDARY_OBSERVED);
        assert_eq!(pb.reporting, None, "observed disclosure must drop reporting");
    }

    // MUTATION ANCHOR (may-ignore): a malformed producing-boundary in the non-critical ext map
    // (reporting under observed) still Signs and Verifies, and is NOT surfaced. Removing the
    // "reporting under observed -> None" check flips present false->true and this test pass->fail.
    #[test]
    fn producing_boundary_malformed_ignored() {
        let c = load_pb();
        let base = &c["base_object"];
        let (s, v) = test_keys();
        let mut o = build_counter_base(base, None, None);
        o.ext = Some(vec![(
            Value::Uint(PRODUCING_BOUNDARY_KEY),
            Value::Map(vec![
                (Value::Uint(1), Value::Bstr(hex::decode("424f554e444152595f58").unwrap())),
                (Value::Uint(2), Value::Uint(PRODUCING_BOUNDARY_OBSERVED)),
                (Value::Uint(3), Value::Bstr(hex::decode("4f524947494e5f59").unwrap())),
            ]),
        )]);
        let signed = sign(&mut o, &s);
        let got = verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed)
            .expect("a malformed non-critical disclosure must be ignored, not rejected (may-ignore)");
        assert!(
            got.producing_boundary().is_none(),
            "a malformed disclosure (reporting under observed) must NOT be surfaced"
        );
    }

    // MUTATION ANCHOR (fail-closed): the disclosure in the CRITICAL cext map (field 12) is an
    // unrecognized critical extension -> UnknownCriticalExt.
    #[test]
    fn producing_boundary_cext_rejected() {
        let c = load_pb();
        let base = &c["base_object"];
        let (s, v) = test_keys();
        let mut o = build_counter_base(base, None, None);
        o.cext = Some(vec![(
            Value::Uint(PRODUCING_BOUNDARY_KEY),
            Value::Map(vec![
                (Value::Uint(1), Value::Bstr(hex::decode("424f554e444152595f58").unwrap())),
                (Value::Uint(2), Value::Uint(PRODUCING_BOUNDARY_OBSERVED)),
            ]),
        )]);
        let signed = sign(&mut o, &s);
        match verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed) {
            Err(e) => assert_eq!(
                e.kind, "UnknownCriticalExt",
                "cext producing-boundary must be UnknownCriticalExt"
            ),
            Ok(_) => panic!("cext producing-boundary must be rejected"),
        }
    }

    fn build_scenario_objects(base: &J, objs: &[J]) -> Vec<Object> {
        objs.iter()
            .map(|ro| {
                let mut o =
                    build_counter_base(base, ro["signer_hex"].as_str(), ro["body_str"].as_str());
                if let Some(cnt) = counter_u64(&ro["counter"]) {
                    o.set_signer_counter(cnt);
                }
                assert_eq!(
                    hex::encode(o.content_id()),
                    ro["content_id_hex"].as_str().unwrap(),
                    "scenario object content-id"
                );
                o
            })
            .collect()
    }

    // Grade detect_signer_duplication over every scenario in the independent oracle.
    #[test]
    fn detect_signer_duplication_matches_oracle() {
        let c = load_counter();
        let base = &c["base_object"];
        for sc in c["detection"]["scenarios"].as_array().unwrap() {
            let name = sc["name"].as_str().unwrap();
            let objs = build_scenario_objects(base, sc["objects"].as_array().unwrap());
            let findings = detect_signer_duplication(&objs);
            let expect = sc["expect"].as_array().unwrap();
            assert_eq!(findings.len(), expect.len(), "{name}: findings count");
            for (i, want) in expect.iter().enumerate() {
                assert_eq!(
                    hex::encode(&findings[i].signer),
                    want["signer_hex"].as_str().unwrap(),
                    "{name} finding {i}: signer"
                );
                assert_eq!(
                    findings[i].counter,
                    counter_u64(&want["counter"]).unwrap(),
                    "{name} finding {i}: counter"
                );
                let want_ids: Vec<String> = want["ids_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| h.as_str().unwrap().to_string())
                    .collect();
                let got_ids: Vec<String> = findings[i].ids.iter().map(hex::encode).collect();
                assert_eq!(got_ids, want_ids, "{name} finding {i}: ids");
            }
        }
    }

    // Case (a) + MUTATION ANCHOR: a single sequence MUST NOT be flagged (relaxing `< 2` to `< 1` in
    // detect_signer_duplication flips this pass->fail).
    #[test]
    fn detect_one_sequence_not_flagged() {
        let c = load_counter();
        let base = &c["base_object"];
        let mut one = build_counter_base(base, None, Some("holder"));
        one.set_signer_counter(5);
        assert!(
            detect_signer_duplication(&[one]).is_empty(),
            "one sequence alone must not be flagged"
        );

        let seq: Vec<Object> = ["s1", "s2", "s3"]
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let mut o = build_counter_base(base, None, Some(b));
                o.set_signer_counter((i + 1) as u64);
                o
            })
            .collect();
        assert!(
            detect_signer_duplication(&seq).is_empty(),
            "honest forward-only sequence must not be flagged"
        );
    }

    // Case (b): two conflicting sequences, same signer, same position, together -> flagged, both surfaced.
    #[test]
    fn detect_two_conflicting_flagged() {
        let c = load_counter();
        let base = &c["base_object"];
        let mut holder = build_counter_base(base, None, Some("holder"));
        holder.set_signer_counter(5);
        let mut thief = build_counter_base(base, None, Some("thief"));
        thief.set_signer_counter(5);
        let hid = holder.content_id();
        let tid = thief.content_id();
        let f = detect_signer_duplication(&[holder, thief]);
        assert_eq!(f.len(), 1, "two conflicting sequences must be flagged once");
        assert_eq!(f[0].counter, 5);
        assert_eq!(f[0].ids.len(), 2, "both conflicting content ids surfaced");
        assert!(
            f[0].ids.contains(&hid) && f[0].ids.contains(&tid),
            "the finding must surface both the holder's and the thief's content ids"
        );
    }

    // Case (c): forward-only-consistent sequences, and cross-signer at one value, are not flagged.
    #[test]
    fn detect_forward_only_consistent_not_flagged() {
        let c = load_counter();
        let base = &c["base_object"];
        let mut a5 = build_counter_base(base, None, Some("holder"));
        a5.set_signer_counter(5);
        let mut a6 = build_counter_base(base, None, Some("next"));
        a6.set_signer_counter(6);
        assert!(
            detect_signer_duplication(&[a5.clone(), a6]).is_empty(),
            "forward-only-consistent sequence must not be flagged"
        );

        let mut b5 = build_counter_base(base, Some("5349474e45525f42"), Some("other"));
        b5.set_signer_counter(5);
        assert!(
            detect_signer_duplication(&[a5, b5]).is_empty(),
            "different signers at one value must not be flagged"
        );
    }

    // Case (d) + MUTATION ANCHOR: an object with an ABSENT counter Signs and Verifies (the field is
    // OPTIONAL). Making the field mandatory flips this pass->fail.
    #[test]
    fn signer_counter_absent_validates() {
        let c = load_counter();
        let (s, v) = test_keys();
        let mut o = build_counter_base(&c["base_object"], None, None);
        assert!(
            o.signer_counter().is_none(),
            "object built without a counter must have none"
        );
        let signed = sign(&mut o, &s);
        let got = verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &signed)
            .expect("an object with an absent counter must verify (the field is OPTIONAL)");
        assert!(
            got.signer_counter().is_none(),
            "verified object must report no counter"
        );
    }

    // white-box helpers assembling objects with deliberately-off components.
    fn sign_with_id(o: &mut Object, s: &dyn CoseSigner, id: &[u8]) -> Vec<u8> {
        o.id = id.to_vec();
        let payload = cbor::encode(&o.body_map(true)).unwrap();
        let prot = protected_header(s.alg(), &o.signer, o.profile);
        let sig = s.sign(&cose::to_be_signed_raw(&prot, &payload));
        cose::assemble_sign1_raw(&prot, &payload, &sig)
    }
    fn sign_with_header_profile(o: &mut Object, s: &dyn CoseSigner, hp: u64) -> Vec<u8> {
        o.id = o.content_id();
        let payload = cbor::encode(&o.body_map(true)).unwrap();
        let prot = protected_header(s.alg(), &o.signer, hp); // mismatched profile copy
        let sig = s.sign(&cose::to_be_signed_raw(&prot, &payload));
        cose::assemble_sign1_raw(&prot, &payload, &sig)
    }
    fn sign_with_version(o: &mut Object, s: &dyn CoseSigner, version: u64) -> Vec<u8> {
        o.id = o.content_id();
        let payload = cbor::encode(&o.body_map(true)).unwrap();
        let naalp = Value::Map(vec![
            (Value::Uint(1), Value::Bstr(o.signer.clone())),
            (Value::Uint(2), Value::Uint(o.profile)),
            (Value::Uint(3), Value::Uint(version)),
        ]);
        let hdr = Value::Map(vec![
            (Value::Uint(1), Value::Nint(s.alg())),
            (Value::Tstr(NAALP_HEADER_LABEL.into()), naalp),
        ]);
        let prot = cbor::encode(&hdr).unwrap();
        let sig = s.sign(&cose::to_be_signed_raw(&prot, &payload));
        cose::assemble_sign1_raw(&prot, &payload, &sig)
    }
    fn sign_raw_payload(s: &dyn CoseSigner, payload: &[u8]) -> Vec<u8> {
        let prot = protected_header(s.alg(), b"SIGNER_A", 1);
        let sig = s.sign(&cose::to_be_signed_raw(prot.as_slice(), payload));
        cose::assemble_sign1_raw(&prot, payload, &sig)
    }
}
