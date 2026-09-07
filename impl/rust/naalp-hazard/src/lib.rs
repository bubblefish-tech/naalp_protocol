// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `naalp-hazard` — Manufacturing Add-ons Component F, the physical-hazard authorization
//! extension (design.md addendum; requirements F1-F5; wire authority
//! `spec/naalp-draft-01.cddl` (the frozen MANUFACTURING PHYSICAL-HAZARD productions).
//!
//! **STATUS: FROZEN 2026-09-01** (Shawn-approved wire bytes). The `naalp-hazard-claim`
//! (critical `cext` key 16) and `naalp-hazard-authorization` (Governance `0x0004` kind 7)
//! productions are merged into the normative `spec/naalp-draft-01.cddl` `naalp-artifact`
//! reachability root; the channel kind is registered in `vectors/registry/channels.csv`,
//! the ext key in `extension-keys.csv`, and the three error codes (130/131/132) in
//! `error-codes.csv`. This crate is the Rust reference impl of the hazard body decode +
//! coverage, graded in isolation against the frozen `vectors/hazard` corpus; the ten-port
//! propagation is a tracked follow-on (the conformance CI grades it).
//!
//! `effect` (envelope field 7, `naalp::policy`) describes DATA reversibility. `hazard` is a
//! new, ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still
//! be a high physical hazard. The two dimensions are never merged and neither derives the
//! other.
//!
//! This crate adds no new cryptography and no new CBOR codec of its own: every encode call
//! delegates to [`naalp::cbor::encode`] / [`naalp::cbor::content_id`], exactly as
//! `naalp::naalpcore` and `naalp-ffi` add no crypto/encoding of their own over the graded
//! `naalp` core (see `impl/rust/src/naalpcore.rs`).
//!
//! ## The fail-closed rules (F2, F3)
//! - [`HazardClass::from_code`] is the ONE fail-closed decode entry point: any missing or
//!   out-of-range raw value normalizes to [`HazardClass::MotionInSharedSpace`] — the highest
//!   class — never to `None` or any weaker class. This mirrors
//!   `naalp::policy::normalize_effect`'s unknown-to-`destructive` rule, extended to a
//!   domain-distinct closed set.
//! - [`hazard_authorized`] requires an EXACT class match (not a `<=` ceiling the way the
//!   effect lattice's `authorizes` works) AND full containment of the claim's envelope
//!   inside the grant's on every axis, the speed bound, and the time window. Any single
//!   failing dimension denies the WHOLE claim — there is no partial authorization.
//! - [`hazard_authorized_optional`] additionally covers the case where an action carries NO
//!   hazard claim at all: there is no envelope to check containment against, so it denies
//!   immediately with a distinct error ([`err_hazard_unknown`]) rather than fabricating a
//!   sentinel envelope and running the ordinary coverage check.

use naalp::cbor::{self, Value};
use naalp::cose;
use naalp::identity;

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}

/// (`HazardMalformed`) a hazard-claim/hazard-authorization/envelope body is not the CDDL
/// shape (`spec/naalp-draft-01.cddl`), a spatial-bounds axis has `min > max`, `axes` is empty, or
/// `frame` is not Unicode NFC.
pub fn err_hazard_malformed() -> cose::Error {
    err(
        "HazardMalformed",
        "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid",
    )
}

/// (`HazardNotCovered`, design's `E_HAZARD_UNCOV`) a well-formed claim's class or envelope is
/// not fully covered by the presented authorization.
pub fn err_hazard_not_covered() -> cose::Error {
    err(
        "HazardNotCovered",
        "declared hazard class or envelope is not fully covered by the authorization",
    )
}

/// (`HazardUnknown`, design's `E_HAZARD_UNKNOWN`) the hazard value for an action requiring
/// one is unrecognized or absent, and — for the fully-absent case — no envelope exists to
/// check coverage against at all.
pub fn err_hazard_unknown() -> cose::Error {
    err(
        "HazardUnknown",
        "hazard value unrecognized or absent; no claim to check coverage against",
    )
}

// ---- hazard-class (F2: closed, fail-closed to the highest class) -----------------------------

/// The closed five-value hazard-class vocabulary (`spec/naalp-draft-01.cddl`). `MotionInSharedSpace`
/// is BOTH a named class (4) and the fail-closed default for an unrecognized or absent raw
/// value (F2) — the assumption that "the producer did not tell us" is at least as dangerous
/// as the worst named class.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HazardClass {
    None,
    ToolActuation,
    Thermal,
    EnergyRelease,
    MotionInSharedSpace,
}

impl HazardClass {
    /// The CDDL wire code (0..4).
    pub fn code(self) -> u8 {
        match self {
            HazardClass::None => 0,
            HazardClass::ToolActuation => 1,
            HazardClass::Thermal => 2,
            HazardClass::EnergyRelease => 3,
            HazardClass::MotionInSharedSpace => 4,
        }
    }

    /// Fail-closed decode (F2). `None` (the raw value was absent) or any value outside
    /// 0..=4 (unrecognized) normalizes to [`HazardClass::MotionInSharedSpace`] — never to a
    /// weaker class, and never a decode failure (there is no "invalid hazard" outcome; there
    /// is only "the worst case we must assume"). This is `u64`-typed rather than the
    /// `u8`-typed sketch in the Manufacturing Add-ons source triple (tasks.md Task F2, dated
    /// 2026-08-20) so a malformed wire value outside even the `u8` range still normalizes
    /// correctly rather than failing to parse.
    pub fn from_code(code: Option<u64>) -> HazardClass {
        match code {
            Some(0) => HazardClass::None,
            Some(1) => HazardClass::ToolActuation,
            Some(2) => HazardClass::Thermal,
            Some(3) => HazardClass::EnergyRelease,
            Some(4) => HazardClass::MotionInSharedSpace,
            _ => HazardClass::MotionInSharedSpace, // F2: unknown/absent -> highest class
        }
    }

    fn to_value(self) -> Value {
        Value::Uint(self.code() as u64)
    }
}

// ---- spatial-bounds ----------------------------------------------------------------------

/// A named coordinate frame plus a signed axis-aligned bounding region in that frame,
/// integer millimeters (`spec/naalp-draft-01.cddl` `spatial-bounds`). Fixed-point, not the source
/// triple's `float`: the N-AALP CBOR subset (`naalp::cbor::Value`) carries no floats, so a
/// hazard envelope stays inside the same deterministic-CBOR discipline as every other
/// production.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpatialBounds {
    pub frame: String,
    /// Per-axis `(min, max)`, millimeters, signed. MUST be non-empty; every entry MUST
    /// satisfy `min <= max`.
    pub axes: Vec<(i64, i64)>,
}

fn int_value(v: i64) -> Value {
    if v >= 0 {
        Value::Uint(v as u64)
    } else {
        Value::Nint(v)
    }
}

fn int_from_value(v: &Value) -> Option<i64> {
    match v {
        Value::Uint(u) => i64::try_from(*u).ok(),
        Value::Nint(n) => Some(*n),
        _ => None,
    }
}

impl SpatialBounds {
    /// Structural validity (`spec/naalp-draft-01.cddl`): non-empty axes, every `min <= max`, `frame`
    /// non-empty and Unicode NFC.
    pub fn is_well_formed(&self) -> bool {
        if self.axes.is_empty() {
            return false;
        }
        if self.axes.iter().any(|(min, max)| min > max) {
            return false;
        }
        identity::require_nfc(&self.frame).is_ok() && !self.frame.is_empty()
    }

    fn to_value(&self) -> Value {
        let axes = self
            .axes
            .iter()
            .map(|(min, max)| Value::Arr(vec![int_value(*min), int_value(*max)]))
            .collect();
        Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.frame.clone())),
            (Value::Uint(2), Value::Arr(axes)),
        ])
    }

    /// Deterministic-CBOR encoding of `{1:frame,2:axes}`. Malformed input still encodes
    /// (encoding is not the validity gate); callers MUST check [`Self::is_well_formed`]
    /// before treating a `SpatialBounds` as authoritative, exactly as `from_value` does on
    /// decode.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode spatial-bounds")
    }

    /// Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed key or
    /// value, a missing key, empty axes, an axis with `min > max`, or a non-NFC/empty frame —
    /// fail-closed (`HazardMalformed`), never a partially-valid result.
    pub fn from_value(v: &Value) -> Result<SpatialBounds, cose::Error> {
        let m = match v {
            Value::Map(m) => m,
            _ => return Err(err_hazard_malformed()),
        };
        let mut frame: Option<String> = None;
        let mut axes: Option<Vec<(i64, i64)>> = None;
        for (k, val) in m {
            let key = match k {
                Value::Uint(u) => *u,
                _ => return Err(err_hazard_malformed()),
            };
            match key {
                1 => {
                    frame = match val {
                        Value::Tstr(s) => Some(s.clone()),
                        _ => return Err(err_hazard_malformed()),
                    };
                }
                2 => {
                    let items = match val {
                        Value::Arr(a) if !a.is_empty() => a,
                        _ => return Err(err_hazard_malformed()),
                    };
                    let mut out = Vec::with_capacity(items.len());
                    for it in items {
                        let pair = match it {
                            Value::Arr(p) if p.len() == 2 => p,
                            _ => return Err(err_hazard_malformed()),
                        };
                        let min = int_from_value(&pair[0]).ok_or_else(err_hazard_malformed)?;
                        let max = int_from_value(&pair[1]).ok_or_else(err_hazard_malformed)?;
                        if min > max {
                            return Err(err_hazard_malformed());
                        }
                        out.push((min, max));
                    }
                    axes = Some(out);
                }
                _ => return Err(err_hazard_malformed()),
            }
        }
        match (frame, axes) {
            (Some(frame), Some(axes)) => {
                let sb = SpatialBounds { frame, axes };
                if sb.is_well_formed() {
                    Ok(sb)
                } else {
                    Err(err_hazard_malformed())
                }
            }
            _ => Err(err_hazard_malformed()),
        }
    }
}

/// Full containment (F3): same frame id (a bound in one frame says nothing about a bound in
/// a different, unrelated frame), the SAME axis count in the SAME order, and every claim
/// axis's `[min,max]` a subset of the matching grant axis's `[min,max]`.
pub fn spatial_contained(claim: &SpatialBounds, grant: &SpatialBounds) -> bool {
    if claim.frame != grant.frame {
        return false;
    }
    if claim.axes.len() != grant.axes.len() {
        return false;
    }
    claim
        .axes
        .iter()
        .zip(grant.axes.iter())
        .all(|((cmin, cmax), (gmin, gmax))| cmin >= gmin && cmax <= gmax)
}

// ---- hazard-window -------------------------------------------------------------------------

/// A validity window, epoch ms, the same convention as `naalp-object` field 6 (`created`)
/// and `naalp-delegation-grant` fields 4/5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HazardWindow {
    pub not_before: u64,
    pub not_after: u64,
}

impl HazardWindow {
    fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.not_before)),
            (Value::Uint(2), Value::Uint(self.not_after)),
        ])
    }

    fn from_value(v: &Value) -> Result<HazardWindow, cose::Error> {
        let m = match v {
            Value::Map(m) => m,
            _ => return Err(err_hazard_malformed()),
        };
        let (mut not_before, mut not_after) = (None, None);
        for (k, val) in m {
            let key = match k {
                Value::Uint(u) => *u,
                _ => return Err(err_hazard_malformed()),
            };
            let n = match val {
                Value::Uint(u) => *u,
                _ => return Err(err_hazard_malformed()),
            };
            match key {
                1 => not_before = Some(n),
                2 => not_after = Some(n),
                _ => return Err(err_hazard_malformed()),
            }
        }
        match (not_before, not_after) {
            (Some(not_before), Some(not_after)) => Ok(HazardWindow {
                not_before,
                not_after,
            }),
            _ => Err(err_hazard_malformed()),
        }
    }
}

// ---- hazard-envelope -----------------------------------------------------------------------

/// The full physical envelope a claim or an authorization bounds itself by. All three
/// fields are MANDATORY on the wire (`spec/naalp-draft-01.cddl`) — a silently-absent axis would be
/// fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states so
/// explicitly with wide numeric bounds; the wire never infers permissiveness from silence
/// here (deliberate contrast with `naalp-delegation-grant`'s optional `scope`).
#[derive(Clone, Debug, PartialEq)]
pub struct HazardEnvelope {
    pub spatial: SpatialBounds,
    /// Max instantaneous speed, millimeters per second.
    pub speed_bound_mm_s: u64,
    pub window: HazardWindow,
}

impl HazardEnvelope {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), self.spatial.to_value()),
            (Value::Uint(2), Value::Uint(self.speed_bound_mm_s)),
            (Value::Uint(3), self.window.to_value()),
        ])
    }

    /// Deterministic-CBOR encoding of `{1:spatial,2:speed_bound,3:window}`.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode hazard-envelope")
    }

    /// The envelope's content id (T1 framing, `naalp::cbor::content_id`): a pure function of
    /// the bytes above.
    pub fn content_id(&self) -> Result<Vec<u8>, cbor::Error> {
        cbor::content_id(&self.to_value())
    }

    /// Parse a `hazard-envelope` map; fail-closed on any missing/malformed field.
    pub fn from_value(v: &Value) -> Result<HazardEnvelope, cose::Error> {
        let m = match v {
            Value::Map(m) => m,
            _ => return Err(err_hazard_malformed()),
        };
        let (mut spatial, mut speed, mut window) = (None, None, None);
        for (k, val) in m {
            let key = match k {
                Value::Uint(u) => *u,
                _ => return Err(err_hazard_malformed()),
            };
            match key {
                1 => spatial = Some(SpatialBounds::from_value(val)?),
                2 => {
                    speed = match val {
                        Value::Uint(u) => Some(*u),
                        _ => return Err(err_hazard_malformed()),
                    }
                }
                3 => window = Some(HazardWindow::from_value(val)?),
                _ => return Err(err_hazard_malformed()),
            }
        }
        match (spatial, speed, window) {
            (Some(spatial), Some(speed_bound_mm_s), Some(window)) => Ok(HazardEnvelope {
                spatial,
                speed_bound_mm_s,
                window,
            }),
            _ => Err(err_hazard_malformed()),
        }
    }
}

/// Full containment (F3): [`spatial_contained`] AND `claim.speed_bound_mm_s <=
/// grant.speed_bound_mm_s` AND the claim's window is a sub-interval of the grant's
/// (`grant.not_before <= claim.not_before` and `claim.not_after <= grant.not_after`).
pub fn envelope_contained(claim: &HazardEnvelope, grant: &HazardEnvelope) -> bool {
    spatial_contained(&claim.spatial, &grant.spatial)
        && claim.speed_bound_mm_s <= grant.speed_bound_mm_s
        && grant.window.not_before <= claim.window.not_before
        && claim.window.not_after <= grant.window.not_after
}

// ---- naalp-hazard-claim / naalp-hazard-authorization ----------------------------------------

/// A signed physical-hazard claim (`spec/naalp-draft-01.cddl` `naalp-hazard-claim`). Carriage (the
/// object it accompanies and how) is a wire-impact decision documented in the design.md
/// addendum, not this crate's concern.
#[derive(Clone, Debug, PartialEq)]
pub struct HazardClaim {
    pub class: HazardClass,
    pub envelope: HazardEnvelope,
}

/// A signed physical-hazard authorization ("a grant" in requirements F3's language;
/// `spec/naalp-draft-01.cddl` `naalp-hazard-authorization`). Same shape as [`HazardClaim`]
/// deliberately (§ design rationale, `spec/naalp-draft-01.cddl`): one envelope shape for both sides
/// keeps the containment check symmetric.
#[derive(Clone, Debug, PartialEq)]
pub struct HazardAuthorization {
    pub class: HazardClass,
    pub envelope: HazardEnvelope,
}

fn hazard_body_to_value(class: HazardClass, envelope: &HazardEnvelope) -> Value {
    Value::Map(vec![
        (Value::Uint(1), class.to_value()),
        (Value::Uint(2), envelope.to_value()),
    ])
}

fn hazard_body_from_value(v: &Value) -> Result<(HazardClass, HazardEnvelope), cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_hazard_malformed()),
    };
    let (mut class_code, mut envelope) = (None, None);
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => *u,
            _ => return Err(err_hazard_malformed()),
        };
        match key {
            1 => {
                class_code = match val {
                    Value::Uint(u) if *u <= 4 => Some(*u),
                    _ => return Err(err_hazard_malformed()), // an out-of-range class on the
                    // WIRE (not merely "absent") is a malformed body, not a normalize-to-4
                    // input: F2's fail-closed normalization is for the DECODE step that
                    // produces a class from a less-structured source (see
                    // HazardClass::from_code), not for a CDDL-invalid `hazard-class` value
                    // already claiming to be well-formed.
                }
            }
            2 => envelope = Some(HazardEnvelope::from_value(val)?),
            _ => return Err(err_hazard_malformed()),
        }
    }
    match (class_code, envelope) {
        (Some(code), Some(envelope)) => Ok((HazardClass::from_code(Some(code)), envelope)),
        _ => Err(err_hazard_malformed()),
    }
}

impl HazardClaim {
    fn to_value(&self) -> Value {
        hazard_body_to_value(self.class, &self.envelope)
    }

    /// Deterministic-CBOR encoding of `{1:class,2:envelope}`.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode hazard-claim")
    }

    /// The claim's content id (T1 framing).
    pub fn content_id(&self) -> Result<Vec<u8>, cbor::Error> {
        cbor::content_id(&self.to_value())
    }

    /// Parse a `naalp-hazard-claim` body. Both `class` and `envelope` are mandatory — a
    /// claim declaring one and omitting the other is `HazardMalformed`, not partially valid.
    pub fn from_value(v: &Value) -> Result<HazardClaim, cose::Error> {
        let (class, envelope) = hazard_body_from_value(v)?;
        Ok(HazardClaim { class, envelope })
    }
}

impl HazardAuthorization {
    fn to_value(&self) -> Value {
        hazard_body_to_value(self.class, &self.envelope)
    }

    /// Deterministic-CBOR encoding of `{1:class,2:envelope}`.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode hazard-authorization")
    }

    /// The authorization's content id (T1 framing).
    pub fn content_id(&self) -> Result<Vec<u8>, cbor::Error> {
        cbor::content_id(&self.to_value())
    }

    /// Parse a `naalp-hazard-authorization` body.
    pub fn from_value(v: &Value) -> Result<HazardAuthorization, cose::Error> {
        let (class, envelope) = hazard_body_from_value(v)?;
        Ok(HazardAuthorization { class, envelope })
    }
}

// ---- F3: grant-coverage authorization -------------------------------------------------------

/// Authorize a well-formed, present claim against an authorization (F3): EXACT class match
/// (not a `<=` ceiling — see the module doc) AND [`envelope_contained`]. Any single failing
/// dimension denies the WHOLE claim (`HazardNotCovered`) — there is no partial
/// authorization and no fail-open branch.
pub fn hazard_authorized(
    claim: &HazardClaim,
    grant: &HazardAuthorization,
) -> Result<(), cose::Error> {
    if claim.class != grant.class {
        return Err(err_hazard_not_covered());
    }
    if !envelope_contained(&claim.envelope, &grant.envelope) {
        return Err(err_hazard_not_covered());
    }
    Ok(())
}

/// Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
/// present-but-unrecognized class byte inside a claim). `None` — no hazard-claim object
/// exists at all for an action that requires one — denies immediately
/// (`HazardUnknown`/`err_hazard_unknown`) rather than fabricating a sentinel envelope and
/// running the ordinary coverage check: there is no envelope to check containment against,
/// so the honest outcome is a distinct error, not a coverage denial that implies an
/// envelope was compared.
pub fn hazard_authorized_optional(
    claim: Option<&HazardClaim>,
    grant: &HazardAuthorization,
) -> Result<(), cose::Error> {
    match claim {
        None => Err(err_hazard_unknown()),
        Some(c) => hazard_authorized(c, grant),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../../vectors/hazard/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read hazard corpus"))
            .expect("parse hazard corpus")
    }

    fn env(frame: &str, axes: &[(i64, i64)], speed: u64, w: (u64, u64)) -> HazardEnvelope {
        HazardEnvelope {
            spatial: SpatialBounds {
                frame: frame.to_string(),
                axes: axes.to_vec(),
            },
            speed_bound_mm_s: speed,
            window: HazardWindow {
                not_before: w.0,
                not_after: w.1,
            },
        }
    }

    // ---- F2: fail-closed class decode (mutation anchor: a constant HazardClass::None
    // return would pass none of the non-zero cases; a constant MotionInSharedSpace would
    // fail the exact 0..3 cases). ----------------------------------------------------------
    #[test]
    fn from_code_fail_closed_matches_oracle() {
        let c = load();
        for row in c["from_code"].as_array().unwrap() {
            let input = row["code"].as_u64();
            let want = row["class"].as_u64().unwrap() as u8;
            assert_eq!(
                HazardClass::from_code(input).code(),
                want,
                "from_code({:?})",
                input
            );
        }
        // Explicit oracle-independent assertions of the two named fail-closed cases (F2).
        assert_eq!(
            HazardClass::from_code(None),
            HazardClass::MotionInSharedSpace,
            "absent must normalize to the highest class"
        );
        assert_eq!(
            HazardClass::from_code(Some(9)),
            HazardClass::MotionInSharedSpace,
            "unknown code must normalize to the highest class"
        );
        assert_eq!(
            HazardClass::from_code(Some(u64::MAX)),
            HazardClass::MotionInSharedSpace,
            "an out-of-u8-range code must still normalize, not panic or wrap"
        );
        // The four in-range codes decode to themselves, never collapsing to the default.
        for code in 0u64..=4 {
            assert_eq!(HazardClass::from_code(Some(code)).code() as u64, code);
        }
    }

    // ---- byte-level: encode matches the independent oracle (⟹ Go == Rust once Go ports). --
    #[test]
    fn claim_and_authorization_bytes_match_oracle() {
        let c = load();
        for row in c["bodies"].as_array().unwrap() {
            let class = HazardClass::from_code(Some(row["class"].as_u64().unwrap()));
            let axes: Vec<(i64, i64)> = row["axes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let p = p.as_array().unwrap();
                    (p[0].as_i64().unwrap(), p[1].as_i64().unwrap())
                })
                .collect();
            let e = env(
                row["frame"].as_str().unwrap(),
                &axes,
                row["speed_bound_mm_s"].as_u64().unwrap(),
                (
                    row["not_before"].as_u64().unwrap(),
                    row["not_after"].as_u64().unwrap(),
                ),
            );
            let claim = HazardClaim {
                class,
                envelope: e.clone(),
            };
            let auth = HazardAuthorization { class, envelope: e };
            let want = row["body_hex"].as_str().unwrap();
            assert_eq!(hex::encode(claim.bytes()), want, "claim {}", row["name"]);
            assert_eq!(
                hex::encode(auth.bytes()),
                want,
                "authorization {} (same shape as claim)",
                row["name"]
            );
            assert_eq!(
                hex::encode(claim.content_id().unwrap()),
                row["content_id_hex"].as_str().unwrap(),
                "claim {} content-id",
                row["name"]
            );
        }
    }

    // Round-trip: from_value(to_value(x)) == x for every oracle body.
    #[test]
    fn round_trip_matches_oracle() {
        let c = load();
        for row in c["bodies"].as_array().unwrap() {
            let axes: Vec<(i64, i64)> = row["axes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let p = p.as_array().unwrap();
                    (p[0].as_i64().unwrap(), p[1].as_i64().unwrap())
                })
                .collect();
            let e = env(
                row["frame"].as_str().unwrap(),
                &axes,
                row["speed_bound_mm_s"].as_u64().unwrap(),
                (
                    row["not_before"].as_u64().unwrap(),
                    row["not_after"].as_u64().unwrap(),
                ),
            );
            let claim = HazardClaim {
                class: HazardClass::from_code(Some(row["class"].as_u64().unwrap())),
                envelope: e,
            };
            let got = HazardClaim::from_value(&claim.to_value()).expect("round-trip decode");
            assert_eq!(got, claim, "round-trip {}", row["name"]);
        }
    }

    // ---- F3: coverage matrix (mutation anchor: a constant Ok(()) fails the deny rows; a
    // constant Err fails the allow rows) -----------------------------------------------------
    #[test]
    fn coverage_matches_oracle() {
        let c = load();
        let rows = c["coverage"].as_array().unwrap();
        assert!(!rows.is_empty());
        let (mut allows, mut denies) = (0, 0);
        for row in rows {
            let mk = |k: &str| -> HazardEnvelope {
                let o = &row[k];
                let axes: Vec<(i64, i64)> = o["axes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        let p = p.as_array().unwrap();
                        (p[0].as_i64().unwrap(), p[1].as_i64().unwrap())
                    })
                    .collect();
                env(
                    o["frame"].as_str().unwrap(),
                    &axes,
                    o["speed_bound_mm_s"].as_u64().unwrap(),
                    (
                        o["not_before"].as_u64().unwrap(),
                        o["not_after"].as_u64().unwrap(),
                    ),
                )
            };
            let claim = HazardClaim {
                class: HazardClass::from_code(row["claim_class_code"].as_u64()),
                envelope: mk("claim_envelope"),
            };
            let grant = HazardAuthorization {
                class: HazardClass::from_code(row["grant_class_code"].as_u64()),
                envelope: mk("grant_envelope"),
            };
            let want_ok = row["authorized"].as_bool().unwrap();
            let res = hazard_authorized(&claim, &grant);
            if want_ok {
                allows += 1;
                assert!(res.is_ok(), "{}: want authorized, got {:?}", row["name"], res);
            } else {
                denies += 1;
                match res {
                    Err(e) => assert_eq!(e.kind, "HazardNotCovered", "{}", row["name"]),
                    Ok(()) => panic!("{}: want denied, got authorized", row["name"]),
                }
            }
        }
        assert!(allows > 0 && denies > 0, "matrix needs both allows and denies");
    }

    // F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all):
    // distinct from an in-range-but-mismatched class, and distinct from an unrecognized
    // class byte inside a present claim (covered by coverage_matches_oracle's normalized
    // rows).
    #[test]
    fn absent_claim_denies_with_distinct_error() {
        let grant = HazardAuthorization {
            class: HazardClass::ToolActuation,
            envelope: env("cell-7/world", &[(0, 1000), (0, 1000), (0, 500)], 500, (0, 1000)),
        };
        match hazard_authorized_optional(None, &grant) {
            Err(e) => assert_eq!(e.kind, "HazardUnknown"),
            Ok(()) => panic!("an absent claim must never authorize"),
        }
        // A present, well-covered claim still authorizes through the same entry point.
        let claim = HazardClaim {
            class: HazardClass::ToolActuation,
            envelope: env("cell-7/world", &[(100, 200), (100, 200), (0, 100)], 100, (10, 900)),
        };
        assert!(hazard_authorized_optional(Some(&claim), &grant).is_ok());
    }

    // ---- structural malformation (fail-closed, never partially valid) ---------------------
    #[test]
    fn malformed_bodies_rejected() {
        // empty axes
        let bad = SpatialBounds {
            frame: "f".into(),
            axes: vec![],
        };
        assert!(!bad.is_well_formed());
        assert_eq!(
            SpatialBounds::from_value(&bad.to_value()).unwrap_err().kind,
            "HazardMalformed"
        );

        // min > max
        let bad2 = SpatialBounds {
            frame: "f".into(),
            axes: vec![(10, -10)],
        };
        assert!(!bad2.is_well_formed());

        // non-NFC frame
        let bad3 = SpatialBounds {
            frame: "e\u{0301}".into(), // 'e' + combining acute (NFD, not NFC)
            axes: vec![(0, 1)],
        };
        assert!(!bad3.is_well_formed());

        // wrong shape entirely (not a map)
        assert_eq!(
            HazardClaim::from_value(&Value::Uint(0)).unwrap_err().kind,
            "HazardMalformed"
        );

        // class present, envelope missing
        let partial = Value::Map(vec![(Value::Uint(1), Value::Uint(1))]);
        assert_eq!(
            HazardClaim::from_value(&partial).unwrap_err().kind,
            "HazardMalformed"
        );

        // an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not
        // silently normalized -- see hazard_body_from_value's doc comment.
        let good_env = env("f", &[(0, 1)], 1, (0, 1)).to_value();
        let out_of_range = Value::Map(vec![
            (Value::Uint(1), Value::Uint(99)),
            (Value::Uint(2), good_env),
        ]);
        assert_eq!(
            HazardClaim::from_value(&out_of_range).unwrap_err().kind,
            "HazardMalformed"
        );
    }

    // ---- containment truth table (independent of the oracle file, direct assertions) ------
    #[test]
    fn spatial_contained_truth_table() {
        let grant = SpatialBounds {
            frame: "f".into(),
            axes: vec![(0, 100), (0, 100)],
        };
        // fully inside -> contained
        let inside = SpatialBounds {
            frame: "f".into(),
            axes: vec![(10, 90), (10, 90)],
        };
        assert!(spatial_contained(&inside, &grant));
        // equal bounds -> contained (closed interval)
        let equal = SpatialBounds {
            frame: "f".into(),
            axes: vec![(0, 100), (0, 100)],
        };
        assert!(spatial_contained(&equal, &grant));
        // one axis pokes outside -> not contained
        let outside = SpatialBounds {
            frame: "f".into(),
            axes: vec![(10, 90), (10, 101)],
        };
        assert!(!spatial_contained(&outside, &grant));
        // different frame -> never contained regardless of numeric bounds
        let wrong_frame = SpatialBounds {
            frame: "g".into(),
            axes: vec![(10, 90), (10, 90)],
        };
        assert!(!spatial_contained(&wrong_frame, &grant));
        // fewer axes -> never contained
        let fewer = SpatialBounds {
            frame: "f".into(),
            axes: vec![(10, 90)],
        };
        assert!(!spatial_contained(&fewer, &grant));
    }

    #[test]
    fn envelope_contained_window_and_speed() {
        let grant = env("f", &[(0, 100)], 500, (100, 900));
        let ok = env("f", &[(0, 100)], 500, (100, 900)); // exact edges, closed interval
        assert!(envelope_contained(&ok, &grant));
        let speed_over = env("f", &[(0, 100)], 501, (100, 900));
        assert!(!envelope_contained(&speed_over, &grant));
        let starts_early = env("f", &[(0, 100)], 500, (99, 900));
        assert!(!envelope_contained(&starts_early, &grant));
        let ends_late = env("f", &[(0, 100)], 500, (100, 901));
        assert!(!envelope_contained(&ends_late, &grant));
    }
}
