// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! S1/S3 — the governed-decision accountability record and the neither-party anchor primitive
//! (design.md §26.4/§26.5; spec/naalp-draft-01.cddl naalp-decision-record / naalp-checkpoint-root /
//! naalp-witness-cosign / naalp-inclusion-proof, FROZEN commit c488c6d3). The Rust half of the
//! two-implementation parity; byte-identical to impl/go/evidencerecord and to the independent oracle
//! (tools/decision_record_oracle.py, tools/checkpoint_oracle.py).
//!
//! ## S1 — naalp-decision-record
//!
//! A `DecisionRecord` is the SIGNED record a governed decision point emits that it decided about an
//! action under a CLOSED, uniquely-selected condition set. It carries two legs of the T/T+n
//! accountability triple natively: UNIQUE SELECTION (field 2, the governing set in the clear as
//! content ids) and GOVERNED-AT-T (field 3, the consume-receipt spent at decision time). The third
//! leg, BINDING-FIXED-BY-T, is established OFF-RECORD by inclusion under a witnessed
//! naalp-checkpoint-root (S3, below). The record is deliberately CLOCK-FREE: no timestamp field
//! anywhere in the body — both time properties are POSITIONAL, never a self-asserted timestamp.
//!
//!   {1: action, 2: governing[], ?3: consume, 4: outcome, 5: ordering, ?6: terms, ?7: enforcement}
//!
//! `outcome` reuses the closed gw-decision set unchanged (allow/deny/hold, `crate::gateway`).
//! `ordering` is the embedded `ordering-disclosure` group {1: basis, ?2: boundary, ?3: mechanism,
//! ?4: relation}, MANDATORY and basis-conditioned fail-closed (never a silent default):
//! correspondence-only(0) -> keys 2/3/4 all absent; single-boundary(1) -> key 2 present, 3/4 absent;
//! external-mechanism(2) -> key 3 present (4 optional), key 2 absent. `terms` (field 6, optional) is
//! `{* uint => term-disposition}` keyed by THIS record's OWN field numbers 1..5 only — an out-of-set
//! key is TermDispositionMalformed. A deny/hold body carrying a `consume` ref is rejected
//! DecisionMalformed (nothing was consumed by a refusal).
//!
//! ## S3 — naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof
//!
//! A `CheckpointRoot` is a log operator's SIGNED Merkle tree head over a leaf set of record content
//! ids. Tree construction and inclusion-proof verification follow RFC 9162 §2.1 EXACTLY, profiled
//! with SHA-384: leaf hash = HASH(0x00||leaf), interior node = HASH(0x01||left||right). Checkpoints
//! chain by `prev` (genesis = 48 zero bytes) — the SAME receipt-chain idiom as the C7 audit chain
//! (`crate::audit`), NOT the same 48-byte quantity as the checkpoint's own Merkle root (field 3): the
//! root is the tree head at this checkpoint, `prev` is SHA-384 of the PRIOR checkpoint's own body.
//! `WitnessCosign` countersigns one exact checkpoint by content id (field 2 is a T1 content id, 50
//! bytes — a distinct quantity from the 48-byte chain link). `InclusionProof` proves a leaf existed in
//! the tree a witnessed checkpoint commits to (record cid as a leaf under a witnessed checkpoint =
//! existed-no-later-than the checkpoint, the binding-fixed-by-T leg); verification recomputes the
//! audit path bottom-up per RFC 9162 §2.1.3.2, fail-closed (InclusionProofInvalid).
//!
//! Fail-closed (§15): a failing object is rejected whole, returns its named error, no state change.
//!
//! Error kinds used here (DecisionMalformed=122, UnknownOrderingBasis=123,
//! OrderingDisclosureMalformed=124, TermDispositionMalformed=125, CheckpointMalformed=126,
//! WitnessRootMismatch=127, InclusionProofInvalid=128) are already registered in the FROZEN CDDL
//! `naalp-error-code` enum (spec/naalp-draft-01.cddl lines 563-569). They are surfaced here as local
//! `cose::Error{kind: "...", ...}` values — the SAME convention `crate::gateway`'s EgMalformed /
//! UnknownEgressBinding (already-frozen codes 120/121) already use — because the central
//! `crate::naalperror::NAMES` registry array is a 119-entry table that has not yet been extended past
//! `RebindUnauthorized` (119) on EITHER implementation (confirmed this session: impl/go/naalperror.go
//! carries the identical 119-entry array). Extending that shared table is a wire-authority-adjacent
//! change spanning Go, Rust, the CSV registry, and `scripts/registry_drift.py` together; it is left
//! for the orchestrator's atomic wire-authority convergence pass, tracked alongside the pre-existing
//! EgMalformed/UnknownEgressBinding gap rather than introduced ad hoc by this module.

use sha2::{Digest, Sha384};

use crate::audit;
use crate::cbor::{self, Value};
use crate::cose;
use crate::envelope;
use crate::gateway;

/// Width of a head / content-id digest, and of a Merkle tree node value (SHA-384 = 48 bytes).
pub const HEAD_SIZE: usize = 48;

/// The all-zero genesis `prev` value a checkpoint chain starts from (48 bytes).
pub const GENESIS: [u8; HEAD_SIZE] = [0u8; HEAD_SIZE];

/// The `HeadSize` all-zero `prev` value a log's first checkpoint chains from — a `Vec<u8>`-returning
/// accessor over [`GENESIS`], matching the Go reference's `GenesisPrev()` name and shape (Go has no
/// const-array primitive to expose directly, so it exposes the value through a function; this mirrors
/// that call surface rather than requiring callers to know about the underlying array constant).
pub fn genesis_prev() -> Vec<u8> {
    GENESIS.to_vec()
}

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}

// ---- S1 error kinds (CDDL codes 122-125) ------------------------------------------------------
pub fn err_decision_malformed() -> cose::Error {
    err(
        "DecisionMalformed",
        "object is not a well-formed N-AALP decision-record body",
    )
}
pub fn err_unknown_ordering_basis() -> cose::Error {
    err(
        "UnknownOrderingBasis",
        "ordering-disclosure basis is outside the closed set {0,1,2}",
    )
}
pub fn err_ordering_disclosure_malformed() -> cose::Error {
    err(
        "OrderingDisclosureMalformed",
        "ordering-disclosure fields are inconsistent with its own basis",
    )
}
pub fn err_term_disposition_malformed() -> cose::Error {
    err(
        "TermDispositionMalformed",
        "terms map carries a key outside the record's own field set, or a malformed value",
    )
}

// ---- S3 error kinds (CDDL codes 126-128) ------------------------------------------------------
pub fn err_checkpoint_malformed() -> cose::Error {
    err(
        "CheckpointMalformed",
        "object is not a well-formed N-AALP checkpoint-root body",
    )
}
pub fn err_witness_cosign_malformed() -> cose::Error {
    // Same registered kind as a checkpoint-root shape failure: naalp-witness-cosign is a sibling
    // production in the same S3 family with no distinct malformed code of its own in the CDDL.
    err(
        "CheckpointMalformed",
        "object is not a well-formed N-AALP witness-cosign body",
    )
}
pub fn err_witness_root_mismatch() -> cose::Error {
    err(
        "WitnessRootMismatch",
        "witness-cosign root does not match the content id of the checkpoint it accompanies",
    )
}
pub fn err_inclusion_proof_invalid() -> cose::Error {
    err(
        "InclusionProofInvalid",
        "inclusion-proof audit path does not recompute the named root",
    )
}
/// Reuses the C7 audit-chain error (design.md §26.5: checkpoints chain by `prev` the same idiom).
pub fn err_chain_broken() -> cose::Error {
    audit::err_chain_broken()
}
/// Non-repudiable evidence that a log operator signed two incompatible histories at one (log, size)
/// failed to be established (design.md §26.5, the same "both signatures are the proof" idiom as the
/// C7 `naalp-fork-proof`). Not itself a registered CDDL code — a caller-side judgment over two S3
/// objects and their signatures, exactly as `audit::ForkProof` is a caller-side judgment over two
/// Receipts.
pub fn err_checkpoint_fork_not_proven() -> cose::Error {
    err(
        "ForkProofInvalid",
        "the two checkpoints/cosigns do not prove log equivocation",
    )
}

/// SHA-384 digest of arbitrary bytes (48 octets).
fn sha384(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

/// T1 content-id framing: multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets),
/// exactly as every other N-AALP object in this family (design.md §2.3 / §26.2).
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + HEAD_SIZE);
    v.push(0x20u8);
    v.push(0x30u8);
    v.extend_from_slice(&sha384(b));
    v
}

// ---- small deterministic-CBOR field accessors (mirrors crate::gateway's local helpers) --------

fn decode_map(b: &[u8]) -> Result<Vec<(Value, Value)>, ()> {
    match cbor::decode(b) {
        Ok(Value::Map(m)) => Ok(m),
        _ => Err(()),
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

fn arr_bstr_field(m: &[(Value, Value)], k: u64) -> Option<Vec<Vec<u8>>> {
    match field(m, k)? {
        Value::Arr(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Value::Bstr(b) => out.push(b),
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

// =================================================================================================
// S1 — naalp-decision-record
// =================================================================================================

/// ordering-basis (design §26.3): the closed set an ordering-disclosure's field 1 may name.
pub const ORDERING_CORRESPONDENCE_ONLY: u64 = 0;
pub const ORDERING_SINGLE_BOUNDARY: u64 = 1;
pub const ORDERING_EXTERNAL_MECHANISM: u64 = 2;

pub fn is_known_ordering_basis(b: u64) -> bool {
    matches!(
        b,
        ORDERING_CORRESPONDENCE_ONLY | ORDERING_SINGLE_BOUNDARY | ORDERING_EXTERNAL_MECHANISM
    )
}

pub fn ordering_basis_name(b: u64) -> &'static str {
    match b {
        ORDERING_CORRESPONDENCE_ONLY => "correspondence-only",
        ORDERING_SINGLE_BOUNDARY => "single-boundary",
        ORDERING_EXTERNAL_MECHANISM => "external-mechanism",
        _ => "unknown",
    }
}

/// enforcement-disposition (design CDDL: 1-indexed, unlike the 0-indexed sets above).
pub const ENFORCEMENT_ENFORCED: u64 = 1;
pub const ENFORCEMENT_ADVISED: u64 = 2;

pub fn is_known_enforcement(e: u64) -> bool {
    matches!(e, ENFORCEMENT_ENFORCED | ENFORCEMENT_ADVISED)
}

/// term-disposition kind reuses the section 2.5.4 producing-boundary kind codes unchanged
/// (`crate::envelope::PRODUCING_BOUNDARY_OBSERVED` / `PRODUCING_BOUNDARY_REPORTED`); the CDDL types
/// term-disposition field 1 as a bare `uint` (not a closed enum reference), so no unknown-kind
/// rejection exists at this layer.
pub const TERM_DISPOSITION_OBSERVED: u64 = envelope::PRODUCING_BOUNDARY_OBSERVED;
pub const TERM_DISPOSITION_REPORTED: u64 = envelope::PRODUCING_BOUNDARY_REPORTED;

/// The embeddable `ordering-disclosure` group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation}
/// (design §26.3). Not a top-level object — carried as the value of decision-record field 5, with no
/// content-id of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderingDisclosure {
    pub basis: u64,
    pub boundary: Option<Vec<u8>>,
    pub mechanism: Option<Vec<u8>>,
    pub relation: Option<Vec<u8>>,
}

impl OrderingDisclosure {
    pub fn correspondence_only() -> Self {
        OrderingDisclosure {
            basis: ORDERING_CORRESPONDENCE_ONLY,
            boundary: None,
            mechanism: None,
            relation: None,
        }
    }
    pub fn single_boundary(boundary: Vec<u8>) -> Self {
        OrderingDisclosure {
            basis: ORDERING_SINGLE_BOUNDARY,
            boundary: Some(boundary),
            mechanism: None,
            relation: None,
        }
    }
    pub fn external_mechanism(mechanism: Vec<u8>, relation: Option<Vec<u8>>) -> Self {
        OrderingDisclosure {
            basis: ORDERING_EXTERNAL_MECHANISM,
            boundary: None,
            mechanism: Some(mechanism),
            relation,
        }
    }

    fn to_value(&self) -> Value {
        let mut pairs = vec![(Value::Uint(1), Value::Uint(self.basis))];
        if let Some(b) = &self.boundary {
            pairs.push((Value::Uint(2), Value::Bstr(b.clone())));
        }
        if let Some(m) = &self.mechanism {
            pairs.push((Value::Uint(3), Value::Bstr(m.clone())));
        }
        if let Some(r) = &self.relation {
            pairs.push((Value::Uint(4), Value::Bstr(r.clone())));
        }
        Value::Map(pairs)
    }

    fn from_value(v: &Value) -> Result<Self, ()> {
        let m = match v {
            Value::Map(m) => m,
            _ => return Err(()),
        };
        let basis = uint_field(m, 1).ok_or(())?;
        let boundary = bstr_field(m, 2);
        let mechanism = bstr_field(m, 3);
        let relation = bstr_field(m, 4);
        // Reject a value present under the wrong CBOR type (e.g. key 2 present but not a bstr) —
        // `bstr_field` silently treats a type mismatch the same as absent, which would let a
        // malformed group masquerade as well-formed; detect that by re-checking key presence.
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

    /// Basis-conditioned well-formedness (design §26.3), fail-closed on the WHOLE carrying record.
    /// The unknown-basis check runs FIRST (an out-of-set basis makes the per-basis rule meaningless).
    pub fn check_well_formed(&self) -> Result<(), cose::Error> {
        if !is_known_ordering_basis(self.basis) {
            return Err(err_unknown_ordering_basis());
        }
        let ok = match self.basis {
            ORDERING_CORRESPONDENCE_ONLY => {
                self.boundary.is_none() && self.mechanism.is_none() && self.relation.is_none()
            }
            ORDERING_SINGLE_BOUNDARY => {
                self.boundary.is_some() && self.mechanism.is_none() && self.relation.is_none()
            }
            ORDERING_EXTERNAL_MECHANISM => self.boundary.is_none() && self.mechanism.is_some(),
            _ => unreachable!(),
        };
        if !ok {
            return Err(err_ordering_disclosure_malformed());
        }
        Ok(())
    }
}

/// The embeddable `term-disposition` group {1: kind, ?2: source} (design §26.4 / §2.5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermDisposition {
    pub kind: u64,
    pub source: Option<Vec<u8>>,
}

impl TermDisposition {
    fn to_value(&self) -> Value {
        let mut pairs = vec![(Value::Uint(1), Value::Uint(self.kind))];
        if let Some(s) = &self.source {
            pairs.push((Value::Uint(2), Value::Bstr(s.clone())));
        }
        Value::Map(pairs)
    }

    fn from_value(v: &Value) -> Result<Self, ()> {
        let m = match v {
            Value::Map(m) => m,
            _ => return Err(()),
        };
        let kind = uint_field(m, 1).ok_or(())?;
        let source = bstr_field(m, 2);
        if field(m, 2).is_some() && source.is_none() {
            return Err(());
        }
        Ok(TermDisposition { kind, source })
    }
}

/// The governed-decision accountability record (S1). See module docs for the full field layout.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    pub action: Vec<u8>,
    pub governing: Vec<Vec<u8>>,
    pub consume: Option<Vec<u8>>,
    pub outcome: u64,
    pub ordering: OrderingDisclosure,
    /// Field 6, `{* uint => term-disposition}`, kept as an ordered pair list (cbor::encode sorts by
    /// encoded key regardless of insertion order, matching every other map in this codebase).
    pub terms: Option<Vec<(u64, TermDisposition)>>,
    pub enforcement: Option<u64>,
}

impl DecisionRecord {
    /// Deterministic-CBOR {1: action, 2: governing[], ?3: consume, 4: outcome, 5: ordering, ?6:
    /// terms, ?7: enforcement}.
    pub fn bytes(&self) -> Vec<u8> {
        let mut pairs = vec![
            (Value::Uint(1), Value::Bstr(self.action.clone())),
            (
                Value::Uint(2),
                Value::Arr(self.governing.iter().map(|g| Value::Bstr(g.clone())).collect()),
            ),
        ];
        if let Some(c) = &self.consume {
            pairs.push((Value::Uint(3), Value::Bstr(c.clone())));
        }
        pairs.push((Value::Uint(4), Value::Uint(self.outcome)));
        pairs.push((Value::Uint(5), self.ordering.to_value()));
        if let Some(terms) = &self.terms {
            let term_pairs = terms
                .iter()
                .map(|(k, td)| (Value::Uint(*k), td.to_value()))
                .collect();
            pairs.push((Value::Uint(6), Value::Map(term_pairs)));
        }
        if let Some(e) = self.enforcement {
            pairs.push((Value::Uint(7), Value::Uint(e)));
        }
        cbor::encode(&Value::Map(pairs)).expect("encode decision record")
    }
    /// SHA-384 head (48 octets). head = SHA-384(body), exactly as every N-AALP object in this family.
    pub fn head(&self) -> Vec<u8> {
        sha384(&self.bytes())
    }
    /// T1 content-id (50 octets): multihash(0x20, SHA-384(body)) — over the WHOLE encoded body (this
    /// production carries no self-referential id field, unlike the base envelope's field-1 split).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a `DecisionRecord` from its body bytes alone, performing ONLY structural checks
/// (mandatory-field presence and CBOR type). It does NOT validate the outcome against the closed
/// gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the deny/hold-with-
/// consume rule, or the terms key set — see [`validate_decision_record`], called here so the combined
/// entry point still rejects every negative case in `vectors/decision_record/cases.json["negative"]`
/// (mirroring the Go reference's ParseDecisionRecord/ValidateDecisionRecord split, §26.4).
pub fn parse_decision_record(b: &[u8]) -> Result<DecisionRecord, cose::Error> {
    let m = decode_map(b).map_err(|_| err_decision_malformed())?;

    let action = bstr_field(&m, 1).ok_or_else(err_decision_malformed)?;
    let governing = arr_bstr_field(&m, 2).ok_or_else(err_decision_malformed)?;
    let consume = bstr_field(&m, 3);
    if field(&m, 3).is_some() && consume.is_none() {
        return Err(err_decision_malformed());
    }
    let outcome = uint_field(&m, 4).ok_or_else(err_decision_malformed)?;
    let ordering_val = field(&m, 5).ok_or_else(err_decision_malformed)?;
    let ordering = OrderingDisclosure::from_value(&ordering_val).map_err(|_| err_decision_malformed())?;

    let terms = match field(&m, 6) {
        None => None,
        Some(Value::Map(tp)) => {
            let mut out = Vec::with_capacity(tp.len());
            for (k, v) in tp {
                let key = match k {
                    Value::Uint(n) => n,
                    _ => return Err(err_term_disposition_malformed()),
                };
                let td = TermDisposition::from_value(&v).map_err(|_| err_term_disposition_malformed())?;
                out.push((key, td));
            }
            Some(out)
        }
        Some(_) => return Err(err_term_disposition_malformed()),
    };

    let enforcement = uint_field(&m, 7);
    if field(&m, 7).is_some() && enforcement.is_none() {
        return Err(err_decision_malformed());
    }

    let d = DecisionRecord {
        action,
        governing,
        consume,
        outcome,
        ordering,
        terms,
        enforcement,
    };
    validate_decision_record(&d)?;
    Ok(d)
}

/// The semantic, closed-set, and basis-conditioned well-formedness checks `parse_decision_record`
/// deliberately does not perform structurally (mirroring the Go reference's `ValidateDecisionRecord`,
/// same check order, §26.4):
///
///  1. Outcome must be in the closed gw-decision set (`UnknownGatewayDecision`).
///  2. Ordering must satisfy its basis-conditioned well-formedness rule (`UnknownOrderingBasis` /
///     `OrderingDisclosureMalformed`, §26.3) — checked BEFORE the deny/hold-consume rule so a record
///     whose ordering is itself malformed is never additionally reported as a consume violation.
///  3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
///     (`DecisionMalformed`) — nothing was consumed, so a value here would assert authority spent for
///     an action the record's own outcome says was not taken.
///  4. Every terms map key must be one of the record's own field numbers 1..5
///     (`TermDispositionMalformed`) — the map discloses provenance of the record's OWN terms, not an
///     arbitrary side channel.
pub fn validate_decision_record(d: &DecisionRecord) -> Result<(), cose::Error> {
    if !gateway::is_known_decision(d.outcome) {
        return Err(gateway::err_unknown_decision());
    }
    d.ordering.check_well_formed()?; // UnknownOrderingBasis / OrderingDisclosureMalformed
    if d.outcome != gateway::DECISION_ALLOW && d.consume.is_some() {
        return Err(err_decision_malformed());
    }
    if let Some(terms) = &d.terms {
        for (key, _) in terms {
            if !(1..=5).contains(key) {
                return Err(err_term_disposition_malformed());
            }
        }
    }
    Ok(())
}

/// Produce the tagged COSE_Sign1 object over the decision-record body, signed by the decision point.
pub fn sign_decision_record(d: &DecisionRecord, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &d.bytes())
}

/// A `DecisionRecord` that has passed signature verification and full semantic validation, matching
/// the Go reference's `ResolvedDecisionRecord` (same field layout as `DecisionRecord` — the type
/// exists to distinguish "structurally parsed" from "signature-verified and validated" at the type
/// level, exactly as `ResolvedEgressAttestation` distinguishes an `EgressAttestation`).
#[derive(Debug, Clone)]
pub struct ResolvedDecisionRecord {
    pub action: Vec<u8>,
    pub governing: Vec<Vec<u8>>,
    pub consume: Option<Vec<u8>>,
    pub outcome: u64,
    pub ordering: OrderingDisclosure,
    pub terms: Option<Vec<(u64, TermDisposition)>>,
    pub enforcement: Option<u64>,
}

impl From<DecisionRecord> for ResolvedDecisionRecord {
    fn from(d: DecisionRecord) -> Self {
        ResolvedDecisionRecord {
            action: d.action,
            governing: d.governing,
            consume: d.consume,
            outcome: d.outcome,
            ordering: d.ordering,
            terms: d.terms,
            enforcement: d.enforcement,
        }
    }
}

/// Verify a decision record end-to-end: (1) the signed object under the profile with real crypto
/// (`cose::verify1`); (2) structural reconstruction (`parse_decision_record`); and (3) full semantic
/// validation (`validate_decision_record`, invoked inside `parse_decision_record`). Takes no
/// serving-party or connection identity — the authority is the signature over the bytes, mirroring
/// `verify_decision`/R-GW-3. Any failure returns its named error and resolves nothing (fail-closed).
pub fn verify_decision_record(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<ResolvedDecisionRecord, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    Ok(parse_decision_record(&payload)?.into())
}

// =================================================================================================
// S3 — naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof
// =================================================================================================

/// A log operator's SIGNED Merkle tree head over a leaf set of record content ids (design §26.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRoot {
    pub log: Vec<u8>,  // the log operator's signer id
    pub size: u64,     // leaf count at this checkpoint
    pub root: Vec<u8>, // the Merkle tree head over the leaf set (48 bytes)
    pub prev: Vec<u8>, // the prior checkpoint's OWN head (48 bytes; genesis = 48 zero bytes)
    pub at: u64,       // the log's time anchor, epoch ms (advisory)
}

impl CheckpointRoot {
    /// Deterministic-CBOR {1: log, 2: size, 3: root, 4: prev, 5: at}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.log.clone())),
            (Value::Uint(2), Value::Uint(self.size)),
            (Value::Uint(3), Value::Bstr(self.root.clone())),
            (Value::Uint(4), Value::Bstr(self.prev.clone())),
            (Value::Uint(5), Value::Uint(self.at)),
        ]))
        .expect("encode checkpoint root")
    }
    /// SHA-384 head (48 octets) — what the NEXT checkpoint's `prev` field names.
    pub fn head(&self) -> Vec<u8> {
        sha384(&self.bytes())
    }
    /// T1 content-id (50 octets) — what a `WitnessCosign`/`InclusionProof` names in field `root`.
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a `CheckpointRoot` from its body bytes alone. Every field is mandatory
/// (CheckpointMalformed on any missing/mistyped field).
pub fn parse_checkpoint_root(b: &[u8]) -> Result<CheckpointRoot, cose::Error> {
    let m = decode_map(b).map_err(|_| err_checkpoint_malformed())?;
    let log = bstr_field(&m, 1).ok_or_else(err_checkpoint_malformed)?;
    let size = uint_field(&m, 2).ok_or_else(err_checkpoint_malformed)?;
    let root = bstr_field(&m, 3).ok_or_else(err_checkpoint_malformed)?;
    let prev = bstr_field(&m, 4).ok_or_else(err_checkpoint_malformed)?;
    let at = uint_field(&m, 5).ok_or_else(err_checkpoint_malformed)?;
    Ok(CheckpointRoot {
        log,
        size,
        root,
        prev,
        at,
    })
}

pub fn sign_checkpoint_root(c: &CheckpointRoot, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &c.bytes())
}

pub fn verify_checkpoint_root(
    obj: &[u8],
    profile: u32,
    log_v: &dyn cose::CoseVerifier,
) -> Result<CheckpointRoot, cose::Error> {
    cose::verify1(profile, log_v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    parse_checkpoint_root(&payload)
}

/// Verify a chain of checkpoints offline against the log's key: checkpoint[0].prev must be
/// [`GENESIS`], and checkpoint[i].prev must equal checkpoint[i-1].head() — the SAME receipt-chain
/// idiom `crate::audit::verify_chain` uses over Receipts (design §26.5). Any reorder/omission breaks
/// a `prev` link (ChainBroken).
pub fn verify_checkpoint_chain(checkpoints: &[CheckpointRoot]) -> Result<(), cose::Error> {
    let mut want_prev = GENESIS.to_vec();
    for c in checkpoints {
        if c.prev != want_prev {
            return Err(err_chain_broken());
        }
        want_prev = c.head();
    }
    Ok(())
}

/// A witness's countersignature over one exact checkpoint by content id (design §26.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessCosign {
    pub witness: Vec<u8>, // the witness's signer id
    pub root: Vec<u8>,    // T1 content id (50 bytes) of the exact checkpoint cosigned
    pub at: u64,          // the witness's own time anchor, epoch ms (advisory)
}

impl WitnessCosign {
    /// Deterministic-CBOR {1: witness, 2: root, 3: at}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.witness.clone())),
            (Value::Uint(2), Value::Bstr(self.root.clone())),
            (Value::Uint(3), Value::Uint(self.at)),
        ]))
        .expect("encode witness cosign")
    }
    pub fn head(&self) -> Vec<u8> {
        sha384(&self.bytes())
    }
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

pub fn parse_witness_cosign(b: &[u8]) -> Result<WitnessCosign, cose::Error> {
    let m = decode_map(b).map_err(|_| err_witness_cosign_malformed())?;
    let witness = bstr_field(&m, 1).ok_or_else(err_witness_cosign_malformed)?;
    let root = bstr_field(&m, 2).ok_or_else(err_witness_cosign_malformed)?;
    let at = uint_field(&m, 3).ok_or_else(err_witness_cosign_malformed)?;
    Ok(WitnessCosign { witness, root, at })
}

pub fn sign_witness_cosign(c: &WitnessCosign, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &c.bytes())
}

pub fn verify_witness_cosign(
    obj: &[u8],
    profile: u32,
    witness_v: &dyn cose::CoseVerifier,
) -> Result<WitnessCosign, cose::Error> {
    cose::verify1(profile, witness_v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    parse_witness_cosign(&payload)
}

/// Whether `cosign` names the content id of `accompanying_checkpoint_cid` — the wire hook for the
/// neither-party property (design §26.5): a cosign presented alongside a checkpoint whose cid it
/// does NOT name proves nothing about that checkpoint. Fail-closed (WitnessRootMismatch).
pub fn check_witness_root(
    cosign: &WitnessCosign,
    accompanying_checkpoint_cid: &[u8],
) -> Result<(), cose::Error> {
    if cosign.root != accompanying_checkpoint_cid {
        return Err(err_witness_root_mismatch());
    }
    Ok(())
}

/// Alias of [`check_witness_root`], matching the Go reference's `ValidateWitnessCosign` name (design
/// §26.5/§26.8): `cosign` must name the exact content id of the checkpoint it accompanies.
pub fn validate_witness_cosign(
    cosign: &WitnessCosign,
    accompanied_checkpoint_id: &[u8],
) -> Result<(), cose::Error> {
    check_witness_root(cosign, accompanied_checkpoint_id)
}

/// Non-repudiable proof that a log operator signed two INCOMPATIBLE histories at one (log, size)
/// (design §26.5, the "both signatures are the proof" idiom, mirroring `audit::ForkProof`). Accepts
/// iff: the two checkpoints share (log, size) and differ in `root`; the log's own signature verifies
/// over BOTH checkpoint bodies; each witness-cosign names its accompanying checkpoint's content id;
/// and the witness's own signature verifies over BOTH cosign bodies. Any failure is
/// `ForkProofInvalid` (fail-closed) — a caller-side judgment over two S3 objects, not itself a
/// registered CDDL production.
#[allow(clippy::too_many_arguments)]
pub fn verify_checkpoint_fork(
    a: &CheckpointRoot,
    sig_a: &[u8],
    cosign_a: &WitnessCosign,
    sig_cosign_a: &[u8],
    b: &CheckpointRoot,
    sig_b: &[u8],
    cosign_b: &WitnessCosign,
    sig_cosign_b: &[u8],
    log_v: &dyn cose::CoseVerifier,
    witness_v: &dyn cose::CoseVerifier,
) -> Result<(), cose::Error> {
    if a.log != b.log || a.size != b.size {
        return Err(err_checkpoint_fork_not_proven()); // not one log operator at one checkpoint size
    }
    if a.root == b.root {
        return Err(err_checkpoint_fork_not_proven()); // same root named twice -> no equivocation
    }
    if !log_v.verify_raw(&a.bytes(), sig_a) || !log_v.verify_raw(&b.bytes(), sig_b) {
        return Err(err_checkpoint_fork_not_proven());
    }
    let a_cid = a.id();
    let b_cid = b.id();
    check_witness_root(cosign_a, &a_cid).map_err(|_| err_checkpoint_fork_not_proven())?;
    check_witness_root(cosign_b, &b_cid).map_err(|_| err_checkpoint_fork_not_proven())?;
    if !witness_v.verify_raw(&cosign_a.bytes(), sig_cosign_a)
        || !witness_v.verify_raw(&cosign_b.bytes(), sig_cosign_b)
    {
        return Err(err_checkpoint_fork_not_proven());
    }
    Ok(())
}

/// An inclusion proof: a leaf existed in the tree the named checkpoint commits to (design §26.5, RFC
/// 9162 §2.1.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub root: Vec<u8>,        // content id (50 bytes) of the naalp-checkpoint-root proven against
    pub leaf: Vec<u8>,        // the included record's own content id (the leaf value)
    pub index: u64,           // 0-based leaf position
    pub path: Vec<Vec<u8>>,   // leaf-to-root audit path (48-byte SHA-384 values each)
}

impl InclusionProof {
    /// Deterministic-CBOR {1: root, 2: leaf, 3: index, 4: path[]}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.root.clone())),
            (Value::Uint(2), Value::Bstr(self.leaf.clone())),
            (Value::Uint(3), Value::Uint(self.index)),
            (
                Value::Uint(4),
                Value::Arr(self.path.iter().map(|p| Value::Bstr(p.clone())).collect()),
            ),
        ]))
        .expect("encode inclusion proof")
    }
    pub fn head(&self) -> Vec<u8> {
        sha384(&self.bytes())
    }
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

pub fn parse_inclusion_proof(b: &[u8]) -> Result<InclusionProof, cose::Error> {
    let m = decode_map(b).map_err(|_| err_inclusion_proof_invalid())?;
    let root = bstr_field(&m, 1).ok_or_else(err_inclusion_proof_invalid)?;
    let leaf = bstr_field(&m, 2).ok_or_else(err_inclusion_proof_invalid)?;
    let index = uint_field(&m, 3).ok_or_else(err_inclusion_proof_invalid)?;
    let path = arr_bstr_field(&m, 4).ok_or_else(err_inclusion_proof_invalid)?;
    Ok(InclusionProof {
        root,
        leaf,
        index,
        path,
    })
}

// ---- RFC 9162 section 2.1 Merkle tree, SHA-384-profiled, verification side --------------------
//
// leaf hash = HASH(0x00||leaf); interior node = HASH(0x01||left||right) — RFC 9162 §2.1.1, quoted
// verbatim in tools/checkpoint_oracle.py's module docstring (fetched from
// https://www.rfc-editor.org/rfc/rfc9162.html this session, per rule B1/E8). The VERIFICATION side
// (MTH for a leaf set, and the §2.1.3.2 inclusion-proof recomputation) is the wire-relevant operation
// per design.md §26.5 ("verification recomputes the path bottom-up"); the fixed audit paths graded
// below are produced by the independent oracle. `generate_inclusion_proof_path` below additionally
// mirrors the Go reference's `GenerateInclusionProofPath` (RFC 9162 §2.1.2 PATH construction) for
// export-surface parity — a log-operator-side convenience, not itself a wire-relevant operation.

/// MTH({d}) = HASH(0x00 || d) — RFC 9162 §2.1.1, single-leaf case.
pub fn leaf_hash(leaf: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + leaf.len());
    b.push(0x00u8);
    b.extend_from_slice(leaf);
    sha384(&b)
}

/// The n>1 combining step: HASH(0x01 || left || right) — RFC 9162 §2.1.1.
pub fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + left.len() + right.len());
    b.push(0x01u8);
    b.extend_from_slice(left);
    b.extend_from_slice(right);
    sha384(&b)
}

/// k, the largest power of two STRICTLY smaller than n (RFC 9162 §2.1.1 notation), for n >= 2.
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash, RFC 9162 §2.1.1: MTH({})=HASH(); MTH({d0})=HASH(0x00||d0);
/// MTH(D_n)=HASH(0x01||MTH(D[0:k])||MTH(D[k:n])) for n>1, k = largest power of two < n.
pub fn mth(leaves: &[Vec<u8>]) -> Vec<u8> {
    let n = leaves.len();
    if n == 0 {
        return sha384(&[]);
    }
    if n == 1 {
        return leaf_hash(&leaves[0]);
    }
    let k = largest_pow2_lt(n);
    node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

/// Alias of [`mth`], matching the Go reference's `MerkleRoot` name.
pub fn merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
    mth(leaves)
}

/// RFC 9162 §2.1.2 PATH(index, leaves) audit-path generation, matching the Go reference's
/// `GenerateInclusionProofPath` name and shape (leaf-to-root sibling order — the returned vector's
/// FIRST entry is the leaf's immediate sibling, the LAST is closest to the root, exactly the order
/// [`InclusionProof`]'s `path` field carries, and the exact structural inverse of
/// [`recompute_inclusion_root`]). `InclusionProofInvalid` if `index` is out of range for `leaves`.
pub fn generate_inclusion_proof_path(
    leaves: &[Vec<u8>],
    index: i64,
) -> Result<Vec<Vec<u8>>, cose::Error> {
    if index < 0 || index as usize >= leaves.len() {
        return Err(err_inclusion_proof_invalid());
    }
    Ok(gen_path(leaves, index as usize))
}

fn gen_path(leaves: &[Vec<u8>], index: usize) -> Vec<Vec<u8>> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new(); // PATH(0, {d0}) = {} — the single-leaf base case
    }
    let k = largest_pow2_lt(n);
    if index < k {
        let mut out = gen_path(&leaves[..k], index);
        out.push(mth(&leaves[k..]));
        out
    } else {
        let mut out = gen_path(&leaves[k..], index - k);
        out.push(mth(&leaves[..k]));
        out
    }
}

/// RFC 9162 §2.1.3.2 inclusion-proof verification procedure, quoted in full in
/// tools/checkpoint_oracle.py's module docstring (the "shift fn/sn until LSB(fn) set or fn==0"
/// sub-step, step 4.b.ii, is the piece an initial paraphrase of the RFC dropped and the oracle's own
/// RFC-fidelity self-check caught — required for any tree_size that is not itself a power of two).
/// Returns the recomputed root on success; `InclusionProofInvalid` if `leaf_index >= tree_size`, if
/// the path runs out of tree before it runs out of elements (step 4.a's mid-loop `sn == 0` guard), or
/// if the terminal `sn == 0` check (step 5) fails.
pub fn recompute_inclusion_root(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash_value: &[u8],
    path: &[Vec<u8>],
) -> Result<Vec<u8>, cose::Error> {
    if leaf_index >= tree_size {
        return Err(err_inclusion_proof_invalid());
    }
    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = leaf_hash_value.to_vec();
    for p in path {
        if sn == 0 {
            return Err(err_inclusion_proof_invalid()); // ran out of tree before the path did
        }
        if (fn_ & 1) == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if (fn_ & 1) == 0 {
                // LSB(fn) not set: shift fn/sn together until it is, or fn reaches 0 (step 4.b.ii —
                // lets the last node on the right border of a non-power-of-two tree skip levels with
                // no sibling to consume).
                while (fn_ & 1) == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1; // step 4.c: unconditional, once per path element
        sn >>= 1;
    }
    if sn != 0 {
        return Err(err_inclusion_proof_invalid());
    }
    Ok(r)
}

/// Verify an inclusion proof against a checkpoint's Merkle root (field 3, 48 bytes) and tree size
/// (field 2): recompute the audit path bottom-up from the leaf and compare to `root`, fail-closed.
pub fn verify_inclusion_proof(
    proof: &InclusionProof,
    tree_size: u64,
    root: &[u8],
) -> Result<(), cose::Error> {
    let lh = leaf_hash(&proof.leaf);
    let computed = recompute_inclusion_root(proof.index, tree_size, &lh, &proof.path)?;
    if computed != root {
        return Err(err_inclusion_proof_invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use fips204::traits::SerDes;
    use serde_json::Value as J;

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

    // ---- S1: naalp-decision-record ------------------------------------------------------------

    const DR_VECTOR_PATH: &str = "../../vectors/decision_record/cases.json";

    fn load_dr() -> J {
        serde_json::from_str(&std::fs::read_to_string(DR_VECTOR_PATH).expect("read decision_record corpus"))
            .expect("parse decision_record corpus")
    }

    fn record_from(rv: &J, ordering: OrderingDisclosure, terms: Option<Vec<(u64, TermDisposition)>>) -> DecisionRecord {
        DecisionRecord {
            action: hexd(rv["action_hex"].as_str().unwrap()),
            governing: rv["governing_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| hexd(g.as_str().unwrap()))
                .collect(),
            consume: rv["consume_hex"].as_str().map(hexd),
            outcome: rv["outcome"].as_u64().unwrap(),
            ordering,
            terms,
            enforcement: None,
        }
    }

    #[test]
    fn decision_record_bodies_match_oracle() {
        let c = load_dr();
        let policy_a = hexd(c["policy_a_cid_hex"].as_str().unwrap());
        let consume = hexd(c["consume_receipt_cid_hex"].as_str().unwrap());

        // allow_consuming: [policy_a], ALLOW, correspondence-only, consume=consume.
        let d = record_from(&c["records"]["allow_consuming"], OrderingDisclosure::correspondence_only(), None);
        assert_eq!(hex::encode(d.bytes()), c["records"]["allow_consuming"]["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(d.head()), c["records"]["allow_consuming"]["head_hex"].as_str().unwrap());
        assert_eq!(hex::encode(d.id()), c["records"]["allow_consuming"]["id_hex"].as_str().unwrap());
        assert_eq!(d.governing, vec![policy_a.clone()]);
        assert_eq!(d.consume, Some(consume.clone()));

        // allow_no_consume: same as above minus consume; distinct content-id (isolates field 3).
        let d2 = record_from(&c["records"]["allow_no_consume"], OrderingDisclosure::correspondence_only(), None);
        assert_eq!(hex::encode(d2.bytes()), c["records"]["allow_no_consume"]["body_hex"].as_str().unwrap());
        assert_ne!(d.id(), d2.id(), "consume present-vs-absent must produce distinct content ids");

        // deny_two_governing: single-boundary ordering.
        let d3 = record_from(
            &c["records"]["deny_two_governing"],
            OrderingDisclosure::single_boundary(b"boundary-signer-X".to_vec()),
            None,
        );
        assert_eq!(hex::encode(d3.bytes()), c["records"]["deny_two_governing"]["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(d3.id()), c["records"]["deny_two_governing"]["id_hex"].as_str().unwrap());

        // hold_empty_governing: external-mechanism ordering with relation (a naalp-checkpoint-root
        // content id, S3 composition) — governing legitimately empty.
        let hold = &c["records"]["hold_empty_governing"];
        assert_eq!(hold["governing_hex"].as_array().unwrap().len(), 0);
        let checkpoint_relation_cid = {
            let mut b = vec![0x20u8, 0x30u8];
            b.extend_from_slice(&Sha384::digest(b"checkpoint-example"));
            b
        };
        let d_hold = DecisionRecord {
            action: hexd(c["action_cid_hex"].as_str().unwrap()),
            governing: vec![],
            consume: None,
            outcome: gateway::DECISION_HOLD,
            ordering: OrderingDisclosure::external_mechanism(
                b"external-log:acme-transparency-v1".to_vec(),
                Some(checkpoint_relation_cid),
            ),
            terms: None,
            enforcement: None,
        };
        assert_eq!(hex::encode(d_hold.bytes()), hold["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(d_hold.id()), hold["id_hex"].as_str().unwrap());
        d_hold.ordering.check_well_formed().expect("external-mechanism with relation is well-formed");

        // enforcement_enforced / enforcement_advised.
        let e1 = DecisionRecord {
            action: hexd(c["action_cid_hex"].as_str().unwrap()),
            governing: vec![policy_a.clone()],
            consume: None,
            outcome: gateway::DECISION_DENY,
            ordering: OrderingDisclosure::correspondence_only(),
            terms: None,
            enforcement: Some(ENFORCEMENT_ENFORCED),
        };
        assert_eq!(hex::encode(e1.bytes()), c["records"]["enforcement_enforced"]["body_hex"].as_str().unwrap());
        let e2 = DecisionRecord {
            enforcement: Some(ENFORCEMENT_ADVISED),
            ..e1.clone()
        };
        assert_eq!(hex::encode(e2.bytes()), c["records"]["enforcement_advised"]["body_hex"].as_str().unwrap());
        assert!(is_known_enforcement(ENFORCEMENT_ENFORCED) && is_known_enforcement(ENFORCEMENT_ADVISED));

        // terms_valid.
        let origin = b"boundary:relay-partner-3".to_vec();
        let tv = DecisionRecord {
            action: hexd(c["action_cid_hex"].as_str().unwrap()),
            governing: vec![policy_a],
            consume: Some(consume),
            outcome: gateway::DECISION_ALLOW,
            ordering: OrderingDisclosure::correspondence_only(),
            terms: Some(vec![
                (1, TermDisposition { kind: TERM_DISPOSITION_OBSERVED, source: None }),
                (4, TermDisposition { kind: TERM_DISPOSITION_REPORTED, source: Some(origin) }),
            ]),
            enforcement: None,
        };
        assert_eq!(hex::encode(tv.bytes()), c["records"]["terms_valid"]["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(tv.id()), c["records"]["terms_valid"]["id_hex"].as_str().unwrap());
        let parsed_tv = parse_decision_record(&tv.bytes()).expect("terms_valid parses");
        assert_eq!(parsed_tv.terms.unwrap().len(), 2);

        // minimal: empty action, empty governing, DENY, correspondence-only.
        let minimal = DecisionRecord {
            action: vec![],
            governing: vec![],
            consume: None,
            outcome: gateway::DECISION_DENY,
            ordering: OrderingDisclosure::correspondence_only(),
            terms: None,
            enforcement: None,
        };
        assert_eq!(hex::encode(minimal.bytes()), c["records"]["minimal"]["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(minimal.id()), c["records"]["minimal"]["id_hex"].as_str().unwrap());
        parse_decision_record(&minimal.bytes()).expect("minimal parses");

        // outcome vocabulary sanity, reused from crate::gateway.
        for e in c["outcome_vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            assert!(gateway::is_known_decision(code));
            assert_eq!(gateway::decision_name(code), e["name"].as_str().unwrap());
        }
        for e in c["ordering_basis_vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            assert!(is_known_ordering_basis(code));
            assert_eq!(ordering_basis_name(code), e["name"].as_str().unwrap());
        }
    }

    // Ordering-disclosure basis examples, isolating ONLY the ordering field over a shared base.
    #[test]
    fn ordering_examples_match_oracle() {
        let c = load_dr();
        // build_ordering_examples uses its OWN local action cid(b"action:read-report"), distinct
        // from the top-level action_cid_hex (cid(b"tool:export_customer_data")).
        let action_cid = {
            let mut b = vec![0x20u8, 0x30u8];
            b.extend_from_slice(&Sha384::digest(b"action:read-report"));
            b
        };
        let base = |ordering: OrderingDisclosure| DecisionRecord {
            action: action_cid.clone(),
            governing: vec![],
            consume: None,
            outcome: gateway::DECISION_DENY,
            ordering,
            terms: None,
            enforcement: None,
        };

        let corr = base(OrderingDisclosure::correspondence_only());
        assert_eq!(
            hex::encode(corr.bytes()),
            c["ordering_examples"]["correspondence_only"]["body_hex"].as_str().unwrap()
        );
        corr.ordering.check_well_formed().expect("correspondence-only is well-formed");

        let boundary = {
            // bytes.fromhex("5349474e45525f42") + b"-boundary" = "SIGNER_B" + "-boundary".
            let mut v = b"SIGNER_B".to_vec();
            v.extend_from_slice(b"-boundary");
            v
        };
        let sb = base(OrderingDisclosure::single_boundary(boundary));
        assert_eq!(
            hex::encode(sb.bytes()),
            c["ordering_examples"]["single_boundary"]["body_hex"].as_str().unwrap()
        );
        sb.ordering.check_well_formed().expect("single-boundary is well-formed");

        let mechanism = b"external-log:acme-transparency-v1".to_vec();
        // external_mechanism_no_relation first (no relation field).
        let em_no_rel = base(OrderingDisclosure::external_mechanism(mechanism.clone(), None));
        assert_eq!(
            hex::encode(em_no_rel.bytes()),
            c["ordering_examples"]["external_mechanism_no_relation"]["body_hex"].as_str().unwrap()
        );
        em_no_rel.ordering.check_well_formed().expect("external-mechanism (no relation) is well-formed");

        // external_mechanism WITH relation: recover the relation cid from the shared corpus field,
        // reconstructed exactly as the oracle built it: cid(b"checkpoint-example").
        let relation_cid = {
            let mut b = vec![0x20u8, 0x30u8];
            b.extend_from_slice(&Sha384::digest(b"checkpoint-example"));
            b
        };
        let em = base(OrderingDisclosure::external_mechanism(mechanism, Some(relation_cid)));
        assert_eq!(
            hex::encode(em.bytes()),
            c["ordering_examples"]["external_mechanism"]["body_hex"].as_str().unwrap()
        );
        em.ordering.check_well_formed().expect("external-mechanism (with relation) is well-formed");
    }

    // ---- S1 negative cases (every reject in vectors/decision_record/cases.json["negative"]) ----

    #[test]
    fn decision_record_negative_deny_hold_with_consume() {
        let c = load_dr();
        let body = hexd(c["negative"]["deny_with_consume_rejected"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_decision_record(&body).unwrap_err().kind, "DecisionMalformed");
        let body2 = hexd(c["negative"]["hold_with_consume_rejected"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_decision_record(&body2).unwrap_err().kind, "DecisionMalformed");
    }

    #[test]
    fn decision_record_negative_terms_key_outside_field_set() {
        let c = load_dr();
        let body = hexd(c["negative"]["terms_key_outside_field_set_rejected"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_decision_record(&body).unwrap_err().kind, "TermDispositionMalformed");
    }

    #[test]
    fn decision_record_negative_unknown_outcome() {
        let c = load_dr();
        let body = hexd(c["negative"]["unknown_outcome_rejected"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_decision_record(&body).unwrap_err().kind, "UnknownGatewayDecision");
    }

    #[test]
    fn decision_record_negative_ordering_malformed() {
        let c = load_dr();
        let om = &c["negative"]["ordering_malformed"];
        for (case, want) in [
            ("correspondence_with_boundary", "OrderingDisclosureMalformed"),
            ("single_boundary_with_mechanism", "OrderingDisclosureMalformed"),
            ("single_boundary_missing_boundary", "OrderingDisclosureMalformed"),
            ("external_mechanism_with_boundary", "OrderingDisclosureMalformed"),
            ("external_mechanism_missing_mechanism", "OrderingDisclosureMalformed"),
            ("unknown_ordering_basis", "UnknownOrderingBasis"),
        ] {
            let body = hexd(om[case]["body_hex"].as_str().unwrap());
            assert_eq!(
                parse_decision_record(&body).unwrap_err().kind,
                want,
                "case {case}"
            );
        }
    }

    #[test]
    fn decision_record_negative_keys_out_of_order() {
        let c = load_dr();
        let e = &c["negative"]["keys_out_of_order"];
        let canon = hexd(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical body should decode");
        parse_decision_record(&canon).expect("canonical body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key decision-record body decoded (want NonCanonical)"),
        }
        assert_eq!(parse_decision_record(&noncanon).unwrap_err().kind, "DecisionMalformed");
    }

    #[test]
    fn decision_record_negative_look_alike() {
        let c = load_dr();
        let body = hexd(c["negative"]["look_alike"]["body_hex"].as_str().unwrap());
        assert_eq!(parse_decision_record(&body).unwrap_err().kind, "DecisionMalformed");
    }

    #[test]
    fn decision_record_malformed_rejected() {
        assert_eq!(parse_decision_record(&[0x00]).unwrap_err().kind, "DecisionMalformed");
    }

    // Sign / verify round-trip and a rejected foreign-key signature.
    #[test]
    fn decision_record_sign_verify_round_trip() {
        let c = load_dr();
        let policy_a = hexd(c["policy_a_cid_hex"].as_str().unwrap());
        let d = DecisionRecord {
            action: hexd(c["action_cid_hex"].as_str().unwrap()),
            governing: vec![policy_a],
            consume: None,
            outcome: gateway::DECISION_DENY,
            ordering: OrderingDisclosure::correspondence_only(),
            terms: None,
            enforcement: None,
        };
        let (s, v, _) = key(0x71);
        let (_, foreign_v, _) = key(0x72);
        let obj = sign_decision_record(&d, &s);
        let resolved = verify_decision_record(&obj, cose::PROFILE_PUBLIC, &v).expect("verify");
        assert_eq!(resolved.outcome, gateway::DECISION_DENY);
        assert_eq!(
            verify_decision_record(&obj, cose::PROFILE_PUBLIC, &foreign_v)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
    }

    // validate_decision_record called directly (not through parse_decision_record), exercising
    // each of its four checks in isolation -- a mutation replacing any one branch with `Ok(())`
    // would leave exactly one of these four assertions failing.
    #[test]
    fn validate_decision_record_direct_checks() {
        let c = load_dr();
        let policy_a = hexd(c["policy_a_cid_hex"].as_str().unwrap());
        let base = DecisionRecord {
            action: hexd(c["action_cid_hex"].as_str().unwrap()),
            governing: vec![policy_a],
            consume: None,
            outcome: gateway::DECISION_DENY,
            ordering: OrderingDisclosure::correspondence_only(),
            terms: None,
            enforcement: None,
        };
        validate_decision_record(&base).expect("well-formed record validates");

        let mut bad_outcome = base.clone();
        bad_outcome.outcome = 9_999;
        assert_eq!(
            validate_decision_record(&bad_outcome).unwrap_err().kind,
            "UnknownGatewayDecision"
        );

        let mut bad_ordering = base.clone();
        bad_ordering.ordering = OrderingDisclosure {
            basis: ORDERING_SINGLE_BOUNDARY,
            boundary: None, // single-boundary basis requires a boundary -> malformed
            mechanism: None,
            relation: None,
        };
        assert_eq!(
            validate_decision_record(&bad_ordering).unwrap_err().kind,
            "OrderingDisclosureMalformed"
        );

        let mut bad_consume = base.clone();
        bad_consume.consume = Some(vec![0xAAu8; 50]); // deny outcome may not carry a consume ref
        assert_eq!(
            validate_decision_record(&bad_consume).unwrap_err().kind,
            "DecisionMalformed"
        );

        let mut bad_terms = base.clone();
        bad_terms.terms = Some(vec![(6, TermDisposition { kind: TERM_DISPOSITION_OBSERVED, source: None })]);
        assert_eq!(
            validate_decision_record(&bad_terms).unwrap_err().kind,
            "TermDispositionMalformed"
        );
    }

    // ---- S3: naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof -------------

    const CP_VECTOR_PATH: &str = "../../vectors/checkpoint/cases.json";

    fn load_cp() -> J {
        serde_json::from_str(&std::fs::read_to_string(CP_VECTOR_PATH).expect("read checkpoint corpus"))
            .expect("parse checkpoint corpus")
    }

    fn at_u64(s: &str) -> u64 {
        s.parse::<u64>().expect("bad at_str")
    }

    fn checkpoint_from(cv: &J) -> CheckpointRoot {
        CheckpointRoot {
            log: hexd(cv["log_hex"].as_str().unwrap()),
            size: cv["size"].as_u64().unwrap(),
            root: hexd(cv["root_hex"].as_str().unwrap()),
            prev: hexd(cv["prev_hex"].as_str().unwrap()),
            at: at_u64(cv["at_str"].as_str().unwrap()),
        }
    }

    fn witness_from(wv: &J) -> WitnessCosign {
        WitnessCosign {
            witness: hexd(wv["witness_hex"].as_str().unwrap()),
            root: hexd(wv["root_hex"].as_str().unwrap()),
            at: at_u64(wv["at_str"].as_str().unwrap()),
        }
    }

    fn inclusion_from(iv: &J) -> InclusionProof {
        InclusionProof {
            root: hexd(iv["root_hex"].as_str().unwrap()),
            leaf: hexd(iv["leaf_hex"].as_str().unwrap()),
            index: iv["index"].as_u64().unwrap(),
            path: iv["path_hex"].as_array().unwrap().iter().map(|p| hexd(p.as_str().unwrap())).collect(),
        }
    }

    #[test]
    fn checkpoint_bodies_match_oracle_and_chain() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        let cp1 = checkpoint_from(&c["checkpoints"]["checkpoint1_size8"]);
        let single = checkpoint_from(&c["checkpoints"]["checkpoint_single_leaf"]);

        for (cp, key_name) in [
            (&cp0, "checkpoint0_size7"),
            (&cp1, "checkpoint1_size8"),
            (&single, "checkpoint_single_leaf"),
        ] {
            let want = &c["checkpoints"][key_name];
            assert_eq!(hex::encode(cp.bytes()), want["body_hex"].as_str().unwrap(), "{key_name} body");
            assert_eq!(hex::encode(cp.head()), want["head_hex"].as_str().unwrap(), "{key_name} head");
            assert_eq!(hex::encode(cp.id()), want["id_hex"].as_str().unwrap(), "{key_name} id");
            parse_checkpoint_root(&cp.bytes()).expect("parses");
        }

        // Genesis: checkpoint0's prev is 48 zero bytes.
        assert_eq!(cp0.prev, GENESIS.to_vec());
        assert_eq!(cp0.prev.len(), HEAD_SIZE);

        // Chain: checkpoint1.prev == checkpoint0.head() (the SAME idiom as the C7 audit chain).
        assert_eq!(cp1.prev, cp0.head());
        verify_checkpoint_chain(&[cp0.clone(), cp1.clone()]).expect("valid two-checkpoint chain");

        // Reorder/substitution breaks the chain (mirrors audit::verify_chain's ChainBroken).
        assert_eq!(
            verify_checkpoint_chain(&[cp1.clone(), cp0.clone()]).unwrap_err().kind,
            "ChainBroken"
        );
    }

    #[test]
    fn genesis_prev_matches_genesis_const_and_oracle() {
        let c = load_cp();
        assert_eq!(genesis_prev(), GENESIS.to_vec());
        assert_eq!(genesis_prev().len(), HEAD_SIZE);
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        assert_eq!(cp0.prev, genesis_prev(), "checkpoint0's oracle prev must equal genesis_prev()");
    }

    #[test]
    fn witness_cosigns_match_oracle_and_root_check() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        let cp1 = checkpoint_from(&c["checkpoints"]["checkpoint1_size8"]);
        let w0 = witness_from(&c["witness_cosigns"]["witness_ok_checkpoint0"]);
        let w1 = witness_from(&c["witness_cosigns"]["witness_ok_checkpoint1"]);

        assert_eq!(hex::encode(w0.bytes()), c["witness_cosigns"]["witness_ok_checkpoint0"]["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(w1.bytes()), c["witness_cosigns"]["witness_ok_checkpoint1"]["body_hex"].as_str().unwrap());
        assert_eq!(w0.root, cp0.id());
        assert_eq!(w1.root, cp1.id());
        check_witness_root(&w0, &cp0.id()).expect("cosign matches checkpoint0");
        check_witness_root(&w1, &cp1.id()).expect("cosign matches checkpoint1");

        // Negative: WitnessRootMismatch — a cosign naming checkpoint1's cid, presented alongside checkpoint0.
        let mm = &c["negative"]["witness_root_mismatch"];
        let mismatch_cosign = WitnessCosign {
            witness: w0.witness.clone(),
            root: hexd(mm["cosign_names_root_hex"].as_str().unwrap()),
            at: w0.at,
        };
        assert_eq!(hex::encode(mismatch_cosign.bytes()), mm["cosign_body_hex"].as_str().unwrap());
        let accompanying_cid = hexd(mm["checkpoint_accompanied_id_hex"].as_str().unwrap());
        assert_eq!(accompanying_cid, cp0.id());
        assert_eq!(
            check_witness_root(&mismatch_cosign, &accompanying_cid).unwrap_err().kind,
            "WitnessRootMismatch"
        );
    }

    // validate_witness_cosign is the Go-reference-named alias of check_witness_root; exercise it
    // directly on the same positive/negative pair so a mutation dropping the delegation (e.g.
    // always Ok(())) is caught independently of check_witness_root's own test.
    #[test]
    fn validate_witness_cosign_matches_check_witness_root() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        let w0 = witness_from(&c["witness_cosigns"]["witness_ok_checkpoint0"]);
        validate_witness_cosign(&w0, &cp0.id()).expect("cosign matches checkpoint0");

        let mm = &c["negative"]["witness_root_mismatch"];
        let mismatch_cosign = WitnessCosign {
            witness: w0.witness.clone(),
            root: hexd(mm["cosign_names_root_hex"].as_str().unwrap()),
            at: w0.at,
        };
        let accompanying_cid = hexd(mm["checkpoint_accompanied_id_hex"].as_str().unwrap());
        assert_eq!(
            validate_witness_cosign(&mismatch_cosign, &accompanying_cid).unwrap_err().kind,
            "WitnessRootMismatch"
        );
    }

    #[test]
    fn fork_evidence_matches_oracle_and_is_provable() {
        let c = load_cp();
        let fe = &c["fork_evidence"];
        let checkpoint_a = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        // fork_evidence.checkpoint_b names its own root/id independently; reconstruct its CheckpointRoot
        // from the shared (log, size, prev, at) of checkpoint_a plus its own divergent root.
        let checkpoint_b = CheckpointRoot {
            log: checkpoint_a.log.clone(),
            size: checkpoint_a.size,
            root: hexd(fe["checkpoint_b"]["root_hex"].as_str().unwrap()),
            prev: checkpoint_a.prev.clone(),
            at: checkpoint_a.at,
        };
        assert_eq!(hex::encode(checkpoint_b.id()), fe["checkpoint_b"]["id_hex"].as_str().unwrap());
        assert_ne!(checkpoint_a.root, checkpoint_b.root, "fork fixture must diverge");
        assert_eq!(checkpoint_a.log, checkpoint_b.log);
        assert_eq!(checkpoint_a.size, checkpoint_b.size);

        let cosign_a = witness_from(&fe["checkpoint_a"]["witness_cosign"]);
        let cosign_b = witness_from(&fe["checkpoint_b"]["witness_cosign"]);
        assert_eq!(cosign_a.root, checkpoint_a.id());
        assert_eq!(cosign_b.root, checkpoint_b.id());

        // Sign both checkpoints under ONE log key, both cosigns under ONE witness key, and prove.
        let (log_s, log_v, _) = key(0x81);
        let (witness_s, witness_v, _) = key(0x82);
        let sig_a = { use cose::CoseSigner; log_s.sign(&checkpoint_a.bytes()) };
        let sig_b = { use cose::CoseSigner; log_s.sign(&checkpoint_b.bytes()) };
        let sig_ca = { use cose::CoseSigner; witness_s.sign(&cosign_a.bytes()) };
        let sig_cb = { use cose::CoseSigner; witness_s.sign(&cosign_b.bytes()) };

        verify_checkpoint_fork(
            &checkpoint_a, &sig_a, &cosign_a, &sig_ca,
            &checkpoint_b, &sig_b, &cosign_b, &sig_cb,
            &log_v, &witness_v,
        )
        .expect("valid fork evidence must prove");

        // Same-root fixture is NOT fork evidence.
        assert_eq!(
            verify_checkpoint_fork(
                &checkpoint_a, &sig_a, &cosign_a, &sig_ca,
                &checkpoint_a, &sig_a, &cosign_a, &sig_ca,
                &log_v, &witness_v,
            )
            .unwrap_err()
            .kind,
            "ForkProofInvalid"
        );
    }

    #[test]
    fn empty_tree_kat() {
        let c = load_cp();
        let want = hexd(c["empty_tree_kat"]["root_hex"].as_str().unwrap());
        assert_eq!(mth(&[]), want);
        assert_eq!(mth(&[]), Sha384::digest(b"").to_vec());
    }

    // merkle_root is the Go-reference-named alias of mth; cross-checked against the independent
    // oracle's checkpoint0_size7 root (tools/checkpoint_oracle.py's leaves7 = cid("record-%d")),
    // not merely against mth itself, so a mutation dropping the delegation to a wrong hash is caught.
    #[test]
    fn merkle_root_matches_mth_and_oracle() {
        let c = load_cp();
        assert_eq!(merkle_root(&[]), mth(&[]));
        let want_empty = hexd(c["empty_tree_kat"]["root_hex"].as_str().unwrap());
        assert_eq!(merkle_root(&[]), want_empty);

        let leaves7: Vec<Vec<u8>> = (0..7u32).map(|i| content_id(format!("record-{i}").as_bytes())).collect();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        assert_eq!(merkle_root(&leaves7), mth(&leaves7));
        assert_eq!(
            merkle_root(&leaves7), cp0.root,
            "merkle_root(leaves7) must match checkpoint0's independent-oracle root"
        );
    }

    #[test]
    fn inclusion_proofs_match_oracle() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        let cp1 = checkpoint_from(&c["checkpoints"]["checkpoint1_size8"]);
        let single = checkpoint_from(&c["checkpoints"]["checkpoint_single_leaf"]);

        let p3 = inclusion_from(&c["inclusion_proofs"]["leaf3_of7"]);
        assert_eq!(hex::encode(p3.bytes()), c["inclusion_proofs"]["leaf3_of7"]["body_hex"].as_str().unwrap());
        assert_eq!(p3.root, cp0.id());
        verify_inclusion_proof(&p3, cp0.size, &cp0.root).expect("leaf3_of7 verifies against checkpoint0's root");

        let p7 = inclusion_from(&c["inclusion_proofs"]["leaf7_of8_newly_appended"]);
        assert_eq!(p7.root, cp1.id());
        verify_inclusion_proof(&p7, cp1.size, &cp1.root).expect("leaf7_of8 verifies against checkpoint1's root");

        let ps = inclusion_from(&c["inclusion_proofs"]["single_leaf_tree_empty_path"]);
        assert!(ps.path.is_empty(), "PATH(0,{{d0}}) = {{}} — RFC 9162 base case");
        assert_eq!(ps.root, single.id());
        verify_inclusion_proof(&ps, single.size, &single.root).expect("single-leaf tree verifies");
    }

    // generate_inclusion_proof_path (the Go reference's GenerateInclusionProofPath, RFC 9162 §2.1.2
    // PATH construction) reconstructed against the SAME leaf set the independent oracle used for
    // checkpoint0_size7 (tools/checkpoint_oracle.py's leaves7 = cid("record-%d") for i in 0..7); the
    // generated path is compared byte-for-byte against the oracle's own leaf3_of7 path_hex fixture —
    // a non-circular check, since the expected path came from the independent oracle, not from this
    // function itself.
    #[test]
    fn generate_inclusion_proof_path_matches_oracle_leaf3_of7() {
        let c = load_cp();
        let leaves7: Vec<Vec<u8>> = (0..7u32).map(|i| content_id(format!("record-{i}").as_bytes())).collect();

        let path = generate_inclusion_proof_path(&leaves7, 3).expect("path for index 3");
        let want_path: Vec<Vec<u8>> = c["inclusion_proofs"]["leaf3_of7"]["path_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| hexd(p.as_str().unwrap()))
            .collect();
        assert_eq!(path, want_path, "generated path must match the independent oracle's leaf3_of7 path");

        // Round-trip: the generated path also verifies against the tree's own MTH root.
        let root7 = mth(&leaves7);
        let proof = InclusionProof {
            root: Vec::new(),
            leaf: leaves7[3].clone(),
            index: 3,
            path: path.clone(),
        };
        verify_inclusion_proof(&proof, leaves7.len() as u64, &root7).expect("generated path verifies");

        assert_eq!(
            generate_inclusion_proof_path(&leaves7, -1).unwrap_err().kind,
            "InclusionProofInvalid"
        );
        assert_eq!(
            generate_inclusion_proof_path(&leaves7, leaves7.len() as i64).unwrap_err().kind,
            "InclusionProofInvalid"
        );
    }

    #[test]
    fn inclusion_proof_negative_wrong_index_and_path() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);

        let wi = &c["negative"]["inclusion_wrong_index"];
        let proof_wi = InclusionProof {
            root: hexd(wi["root_hex"].as_str().unwrap()),
            leaf: hexd(wi["leaf_hex"].as_str().unwrap()),
            index: wi["claimed_index"].as_u64().unwrap(),
            path: wi["path_hex"].as_array().unwrap().iter().map(|p| hexd(p.as_str().unwrap())).collect(),
        };
        let result_wi = verify_inclusion_proof(&proof_wi, cp0.size, &cp0.root);
        assert!(result_wi.is_err(), "wrong-index inclusion proof must fail to verify");
        assert_eq!(result_wi.unwrap_err().kind, "InclusionProofInvalid");

        let wp = &c["negative"]["inclusion_wrong_path"];
        let proof_wp = InclusionProof {
            root: hexd(wp["root_hex"].as_str().unwrap()),
            leaf: hexd(wp["leaf_hex"].as_str().unwrap()),
            index: wp["index"].as_u64().unwrap(),
            path: wp["path_hex"].as_array().unwrap().iter().map(|p| hexd(p.as_str().unwrap())).collect(),
        };
        assert_eq!(
            verify_inclusion_proof(&proof_wp, cp0.size, &cp0.root).unwrap_err().kind,
            "InclusionProofInvalid"
        );
    }

    #[test]
    fn checkpoint_negative_keys_out_of_order_and_missing_field() {
        let c = load_cp();
        let e = &c["negative"]["checkpoint_keys_out_of_order"];
        let canon = hexd(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical body should decode");
        parse_checkpoint_root(&canon).expect("canonical body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key checkpoint body decoded (want NonCanonical)"),
        }
        assert_eq!(parse_checkpoint_root(&noncanon).unwrap_err().kind, "CheckpointMalformed");

        let missing = &c["negative"]["checkpoint_missing_field"];
        let body = hexd(missing["body_hex"].as_str().unwrap());
        assert_eq!(parse_checkpoint_root(&body).unwrap_err().kind, "CheckpointMalformed");
    }

    #[test]
    fn checkpoint_sign_verify_round_trip() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        let (s, v, _) = key(0x91);
        let (_, foreign_v, _) = key(0x92);
        let obj = sign_checkpoint_root(&cp0, &s);
        let resolved = verify_checkpoint_root(&obj, cose::PROFILE_PUBLIC, &v).expect("verify");
        assert_eq!(resolved.size, cp0.size);
        assert_eq!(
            verify_checkpoint_root(&obj, cose::PROFILE_PUBLIC, &foreign_v).unwrap_err().kind,
            "BadSignature"
        );
    }

    #[test]
    fn witness_cosign_sign_verify_round_trip() {
        let c = load_cp();
        let cp0 = checkpoint_from(&c["checkpoints"]["checkpoint0_size7"]);
        let w0 = witness_from(&c["witness_cosigns"]["witness_ok_checkpoint0"]);
        let (s, v, _) = key(0xA1);
        let obj = sign_witness_cosign(&w0, &s);
        let resolved = verify_witness_cosign(&obj, cose::PROFILE_PUBLIC, &v).expect("verify");
        check_witness_root(&resolved, &cp0.id()).expect("resolved cosign matches checkpoint0");
    }
}
