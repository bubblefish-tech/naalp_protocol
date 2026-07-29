// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C5 — the closed effect vocabulary, the fail-closed unknown->destructive rule,
//! effect-as-authorization-input, and the optional signed safety label (design.md §6;
//! requirements R-6.1..6.5).
//!
//! The effect (envelope field 7) is a closed four-value set aligned 1:1 with the N-PAMP
//! Bridge SafetyLabel u8 (N-PAMP draft-01 spec/companion/10_bridge_framework.md §7):
//! read_only=0, idempotent_write=1, non_idempotent_write=2, destructive=3, forming a
//! lattice with destructive at the top. N-PAMP states the label "describes intent and does
//! not replace authorization"; N-AALP closes that hole here (§6.3): an endpoint grants a
//! maximum effect (a capability) to an AUTHENTICATED signer id, and an object is authorized
//! iff its effect does not exceed the grant. Every rejection is fail-closed.

use crate::cbor::{self, Value};
use crate::cose;

/// The closed four-value effect set (design.md §6.1).
pub const READ_ONLY: u8 = 0;
pub const IDEMPOTENT_WRITE: u8 = 1;
pub const NON_IDEMPOTENT_WRITE: u8 = 2;
pub const DESTRUCTIVE: u8 = 3;

const SAFETY_LABEL_NAMES: [&str; 4] =
    ["read_only", "idempotent_write", "non_idempotent_write", "destructive"];

/// N-PAMP SafetyLabel name for a normalized effect (0..3).
pub fn safety_label_name(e: u8) -> &'static str {
    SAFETY_LABEL_NAMES[e as usize]
}

/// N-PAMP Bridge SafetyLabel u8 (design.md §6.1: identity map, so carriage over the Bridge
/// is loss-free).
pub fn safety_label_byte(e: u8) -> u8 {
    e
}

/// Map an N-PAMP SafetyLabel u8 back to an N-AALP effect. An unrecognized byte is treated
/// as destructive (R-6.2 / N-PAMP §7 fail-safe), never as a weaker class.
pub fn effect_from_safety_label_byte(b: u8) -> u8 {
    normalize_effect(b as u64)
}

/// Map a raw effect value to the closed set. Any value outside 0..3 is an effect the
/// evaluator does not recognize and is treated as the most dangerous class, destructive,
/// so the evaluator never fails open (R-6.2). Reusable by carriage (T11), where a foreign
/// Bridge SafetyLabel byte may carry a value this draft does not define.
pub fn normalize_effect(v: u64) -> u8 {
    if v <= 3 {
        v as u8
    } else {
        DESTRUCTIVE
    }
}

/// Whether an action of class `action` is permitted under a capability (or object) whose
/// effect ceiling is `ceiling` — the design §6.1 lattice: action <= ceiling.
pub fn authorizes(ceiling: u8, action: u8) -> bool {
    action <= ceiling
}

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_effect_not_authorized() -> cose::Error {
    err("EffectNotAuthorized", "object effect exceeds the granted capability")
}
pub fn err_unauthenticated_principal() -> cose::Error {
    err(
        "UnauthenticatedPrincipal",
        "an authorization identity must be signature-derived, not transport/foreign/client-asserted",
    )
}
pub fn err_malformed_safety_label() -> cose::Error {
    err("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
}

/// Where a claimed identity came from. Only a signature-derived identity is an
/// authorization principal (R-6.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrincipalSource {
    /// the verified COSE signature's signer id
    Signature,
    /// e.g. a TLS peer name / connection tag
    TransportMetadata,
    /// e.g. an X-Agent-ID or a carried foreign header
    ForeignHeader,
    /// e.g. a self-asserted clientInfo.name
    ClientName,
}

/// Return the authorization principal id iff it is signature-derived and non-empty (R-6.5).
/// A transport-metadata, foreign-header, or client-supplied name is refused — it is never
/// treated as an authorization identity.
pub fn resolve_auth_principal(src: PrincipalSource, id: &str) -> Result<String, cose::Error> {
    if src != PrincipalSource::Signature || id.is_empty() {
        return Err(err_unauthenticated_principal());
    }
    Ok(id.to_string())
}

/// A capability an endpoint issues to an authenticated signer id: the most dangerous effect
/// that principal may carry. `max_effect == READ_ONLY` is the least-privilege default.
pub struct Grant {
    pub principal: String,
    pub max_effect: u8,
}

impl Grant {
    /// The endpoint policy check that makes the effect an authorization input, not a hint
    /// (R-6.3). It (1) resolves the presenter's identity, refusing any non-signature source
    /// (R-6.5); (2) requires that identity to match the grant's principal; (3) normalizes
    /// the object's effect fail-closed (R-6.2) and denies it if it exceeds the ceiling.
    /// Performs no side effect and returns a named error on failure.
    pub fn authorize_object(
        &self,
        src: PrincipalSource,
        presented: &str,
        object_effect: u64,
    ) -> Result<(), cose::Error> {
        let who = resolve_auth_principal(src, presented)?;
        if who != self.principal {
            return Err(err_effect_not_authorized());
        }
        if !authorizes(self.max_effect, normalize_effect(object_effect)) {
            return Err(err_effect_not_authorized());
        }
        Ok(())
    }
}

/// The non-critical ext key under which the optional safety label is carried (ext[1],
/// design.md §6.4). Recorded in vectors/registry (T14).
pub const SAFETY_LABEL_EXT_KEY: u64 = 1;

/// The OPTIONAL signed safety annotation (R-6.4). Attributable to the object's signer and
/// auditable; an ACCOUNTABLE CLAIM, not a guarantee the content is safe (design.md §6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyLabel {
    pub risk: String,
    pub scope: String,
}

impl SafetyLabel {
    /// Encode the safety label as its CBOR map {1: risk, 2: scope}.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.risk.clone())),
            (Value::Uint(2), Value::Tstr(self.scope.clone())),
        ])
    }

    /// Deterministic-CBOR bytes of the safety-label map.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode safety label")
    }

    /// An ext map carrying only this safety label, ready to place in an object's field 11.
    pub fn ext(&self) -> Vec<(Value, Value)> {
        vec![(Value::Uint(SAFETY_LABEL_EXT_KEY), self.to_value())]
    }
}

/// Extract the optional safety label from an object's ext map. Returns `Ok(Some(label))`
/// when a well-formed label is present, `Ok(None)` when absent, and
/// `Err(MalformedSafetyLabel)` when the ext[1] entry is present but not exactly
/// {1:tstr, 2:tstr} — a malformed label is rejected, never silently accepted.
pub fn safety_label_from_ext(ext: &[(Value, Value)]) -> Result<Option<SafetyLabel>, cose::Error> {
    for (k, val) in ext {
        if !matches!(k, Value::Uint(n) if *n == SAFETY_LABEL_EXT_KEY) {
            continue;
        }
        let m = match val {
            Value::Map(m) => m,
            _ => return Err(err_malformed_safety_label()),
        };
        let (mut risk, mut scope) = (None, None);
        for (kk, vv) in m {
            let key = match kk {
                Value::Uint(n) => *n,
                _ => return Err(err_malformed_safety_label()),
            };
            let s = match vv {
                Value::Tstr(s) => s.clone(),
                _ => return Err(err_malformed_safety_label()),
            };
            match key {
                1 => risk = Some(s),
                2 => scope = Some(s),
                _ => return Err(err_malformed_safety_label()),
            }
        }
        return match (risk, scope) {
            (Some(r), Some(sc)) => Ok(Some(SafetyLabel { risk: r, scope: sc })),
            _ => Err(err_malformed_safety_label()),
        };
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/effect/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    // The four names and the identity Bridge SafetyLabel mapping equal the independent
    // oracle (⟹ Go == Rust, which grades the same file).
    #[test]
    fn effect_names_and_bridge_match_oracle() {
        let c = load();
        let effects = c["effects"].as_array().unwrap();
        assert_eq!(effects.len(), 4);
        for e in effects {
            let v = e["value"].as_u64().unwrap() as u8;
            assert_eq!(safety_label_name(v), e["safety_label"].as_str().unwrap());
            assert_eq!(safety_label_byte(v), v);
        }
        for m in c["bridge_mapping"].as_array().unwrap() {
            let u8v = m["npamp_u8"].as_u64().unwrap() as u8;
            assert_eq!(effect_from_safety_label_byte(u8v), m["effect"].as_u64().unwrap() as u8);
        }
    }

    // R-6.2 — any unrecognized effect value normalizes to destructive and never fails open.
    #[test]
    fn normalize_unknown_is_destructive() {
        let c = load();
        for v in 0u64..=3 {
            assert_eq!(normalize_effect(v), v as u8);
        }
        let unknown = c["unknown_normalization"].as_array().unwrap();
        assert!(!unknown.is_empty());
        for u in unknown {
            let got = normalize_effect(u["input"].as_u64().unwrap());
            assert_eq!(got, u["effect"].as_u64().unwrap() as u8);
            assert_eq!(got, DESTRUCTIVE);
        }
        assert_eq!(effect_from_safety_label_byte(200), DESTRUCTIVE);
    }

    // R-6.3 — the full granted×effect authorize/deny table holds; a constant policy fails
    // because the matrix has both allows and denies.
    #[test]
    fn authorization_matrix() {
        let c = load();
        let matrix = c["authorization_matrix"].as_array().unwrap();
        assert_eq!(matrix.len(), 16);
        let (mut allows, mut denies) = (0, 0);
        for r in matrix {
            let granted = r["granted"].as_u64().unwrap() as u8;
            let effect = r["effect"].as_u64().unwrap();
            let allow = r["allow"].as_bool().unwrap();
            let g = Grant { principal: "pA".into(), max_effect: granted };
            let res = g.authorize_object(PrincipalSource::Signature, "pA", effect);
            if allow {
                allows += 1;
                assert!(res.is_ok(), "granted={} effect={}: want allow, got {:?}", granted, effect, res);
            } else {
                denies += 1;
                assert_eq!(res.unwrap_err().kind, "EffectNotAuthorized");
            }
            assert_eq!(authorizes(granted, normalize_effect(effect)), allow);
        }
        assert!(allows > 0 && denies > 0);
    }

    // R-6.5 — only a signature-derived identity is an authorization principal.
    #[test]
    fn principal_source_gate() {
        let c = load();
        let src_of = |s: &str| match s {
            "signature" => PrincipalSource::Signature,
            "transport_metadata" => PrincipalSource::TransportMetadata,
            "foreign_header" => PrincipalSource::ForeignHeader,
            "client_name" => PrincipalSource::ClientName,
            other => panic!("unknown source {}", other),
        };
        let g = Grant { principal: "pA".into(), max_effect: DESTRUCTIVE };
        for ps in c["principal_sources"].as_array().unwrap() {
            let src = src_of(ps["source"].as_str().unwrap());
            let accepted = ps["accepted"].as_bool().unwrap();
            assert_eq!(resolve_auth_principal(src, "pA").is_ok(), accepted);
            let res = g.authorize_object(src, "pA", READ_ONLY as u64);
            if accepted {
                assert!(res.is_ok());
            } else {
                assert_eq!(res.unwrap_err().kind, "UnauthenticatedPrincipal");
            }
        }
    }

    // The safety-label CBOR equals the independently constructed bytes (⟹ Go == Rust).
    #[test]
    fn safety_label_bytes_match_oracle() {
        let c = load();
        let sl = &c["safety_label"];
        let label = SafetyLabel {
            risk: sl["risk"].as_str().unwrap().into(),
            scope: sl["scope"].as_str().unwrap().into(),
        };
        assert_eq!(hex::encode(label.encode()), sl["cbor_hex"].as_str().unwrap());
    }

    fn keypair(seed_byte: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer, Vec<u8>) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed_byte; 32]);
        use fips204::traits::SerDes;
        let pk_bytes = pk.clone().into_bytes().to_vec();
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk), pk_bytes)
    }

    fn mk_obj(signer: &[u8], label: &SafetyLabel) -> envelope::Object {
        envelope::Object {
            id: vec![],
            kind: 0,
            channel: 0,
            tier: 0,
            signer: signer.to_vec(),
            created: 1000,
            effect: IDEMPOTENT_WRITE as u64,
            causes: vec![],
            profile: cose::PROFILE_PUBLIC as u64,
            body: Value::Uint(0),
            ext: Some(label.ext()),
            cext: None,
        }
    }

    // R-6.4 — the optional safety label is carried in the signed body: two objects differing
    // only in the label sign to different bytes, each recovers its own label, and splicing one
    // object's body under the other's signature is rejected as BadSignature.
    #[test]
    fn safety_label_bound_under_signature() {
        let (v, s, signer) = keypair(5);
        let kind_ok = |_c: u64, _k: u64| true;
        let low = SafetyLabel { risk: "low".into(), scope: "cache".into() };
        let high = SafetyLabel { risk: "elevated".into(), scope: "billing-records".into() };

        let mut oa = mk_obj(&signer, &low);
        let signed_a = envelope::sign(&mut oa, &s);
        let mut ob = mk_obj(&signer, &high);
        let signed_b = envelope::sign(&mut ob, &s);
        assert_ne!(signed_a, signed_b, "differing labels produced identical signed bytes");

        let ra = envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed_a).expect("verify a");
        let got_a = safety_label_from_ext(ra.ext.as_deref().unwrap_or(&[])).unwrap().unwrap();
        assert_eq!(got_a, low);
        let rb = envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed_b).expect("verify b");
        let got_b = safety_label_from_ext(rb.ext.as_deref().unwrap_or(&[])).unwrap().unwrap();
        assert_eq!(got_b, high);

        let (prot_a, _pa, sig_a) = cose::parse_sign1_raw(&signed_a).unwrap();
        let (_pbprot, payload_b, _sb) = cose::parse_sign1_raw(&signed_b).unwrap();
        let forge = cose::assemble_sign1_raw(&prot_a, &payload_b, &sig_a);
        match envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &forge) {
            Err(e) => assert_eq!(e.kind, "BadSignature"),
            Ok(_) => panic!("spliced label accepted"),
        }
    }

    // Absent label is Ok(None); a malformed ext[1] is rejected.
    #[test]
    fn safety_label_ext_errors() {
        assert_eq!(safety_label_from_ext(&[]).unwrap(), None);
        let bad = vec![(Value::Uint(SAFETY_LABEL_EXT_KEY), Value::Uint(9))];
        assert_eq!(safety_label_from_ext(&bad).unwrap_err().kind, "MalformedSafetyLabel");
        let bad2 = vec![(
            Value::Uint(SAFETY_LABEL_EXT_KEY),
            Value::Map(vec![(Value::Uint(1), Value::Tstr("x".into()))]),
        )];
        assert!(safety_label_from_ext(&bad2).is_err());
    }
}
