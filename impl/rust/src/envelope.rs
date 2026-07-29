// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP C3 object envelope (design.md §2): the single signed object every kind,
//! channel, and transport reuses. The body is a deterministic-CBOR map (fields 1..12)
//! carried as the COSE_Sign1 payload; field 1 is the content id (§2.3). The protected
//! header carries the algorithm plus routing copies of the signer, profile, and
//! naalp-version (§2.1, §2.5). Every failure is fail-closed with a named error (§2.6).
//! Rust half of the two-implementation parity; byte-identical to impl/go by construction.

use crate::cbor::{self, Value};
use crate::cose::{self, CoseSigner, CoseVerifier};

// Object body field numbers (design.md §2.1).
pub const FIELD_ID: u64 = 1;
pub const FIELD_KIND: u64 = 2;
pub const FIELD_CHANNEL: u64 = 3;
pub const FIELD_TIER: u64 = 4;
pub const FIELD_SIGNER: u64 = 5;
pub const FIELD_CREATED: u64 = 6;
pub const FIELD_EFFECT: u64 = 7;
pub const FIELD_CAUSES: u64 = 8;
pub const FIELD_PROFILE: u64 = 9;
pub const FIELD_BODY: u64 = 10;
pub const FIELD_EXT: u64 = 11;
pub const FIELD_CEXT: u64 = 12;

pub const NAALP_VERSION: u64 = 1;
const NAALP_HEADER_LABEL: &str = "naalp";

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
fn e_cid() -> cose::Error { err("ContentIdMismatch", "id does not equal the recomputed content id") }
fn e_hbm() -> cose::Error { err("HeaderBodyMismatch", "protected-header signer/profile disagree with the body") }
fn e_ucext() -> cose::Error { err("UnknownCriticalExt", "unrecognized critical extension key") }
fn e_ukind() -> cose::Error { err("UnknownKind", "kind/channel not recognized by any surface") }
fn e_range() -> cose::Error { err("RangeError", "field value outside its permitted range") }
fn e_version() -> cose::Error { err("UnsupportedVersion", "unsupported naalp-version") }
fn e_malformed() -> cose::Error { err("Malformed", "malformed object") }

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
    pub ext: Option<Vec<(Value, Value)>>,  // field 11 (non-critical); None = absent
    pub cext: Option<Vec<(Value, Value)>>, // field 12 (critical); None = absent
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
        Value::Map(m)
    }

    /// Content id over the body without field 1 (design.md §2.3).
    pub fn content_id(&self) -> Vec<u8> {
        cbor::content_id(&self.body_map(false)).expect("content id")
    }
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

/// Assemble, content-id-bind, and sign a full N-AALP object.
pub fn sign(o: &mut Object, signer: &dyn CoseSigner) -> Vec<u8> {
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
pub fn verify(
    profile: u32,
    v: &dyn CoseVerifier,
    kind_ok: &dyn Fn(u64, u64) -> bool,
    known_cext: &[u64],
    obj: &[u8],
) -> Result<Object, cose::Error> {
    let (prot, payload, sig) = cose::parse_sign1_raw(obj).map_err(|_| e_malformed())?;

    let bv = cbor::decode(&payload).map_err(|e| err(e.kind, e.msg))?; // NonCanonical surfaces here
    let body = match bv {
        Value::Map(m) => m,
        _ => return Err(e_malformed()),
    };

    // content-id over the body without field 1.
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

    // field ranges (RangeError): channel 0..=19, effect 0..=3, profile 1..=3.
    if o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3 {
        return Err(e_range());
    }

    // protected-header copies vs body (HeaderBodyMismatch) + version.
    let (alg, h_signer, h_profile, h_version) = parse_protected(&prot)?;
    if h_version != NAALP_VERSION {
        return Err(e_version());
    }
    if h_signer != o.signer || h_profile != o.profile {
        return Err(e_hbm());
    }

    // critical extensions: any unrecognized key rejects.
    if let Some(cext) = &o.cext {
        for (k, _) in cext {
            match k {
                Value::Uint(u) if known_cext.contains(u) => {}
                _ => return Err(e_ucext()),
            }
        }
    }

    // kind/channel surface dispatch.
    if !kind_ok(o.channel, o.kind) {
        return Err(e_ukind());
    }

    // profile floor + COSE signature (reuse the C2 registry + verifier).
    let level = cose::alg_level_of(alg).ok_or_else(cose::err_unknown_alg)?;
    if level < cose::profile_min_level_of(profile) {
        return Err(cose::err_downgrade());
    }
    if alg != v.alg() {
        return Err(cose::err_key_alg_mismatch());
    }
    let tbs = cose::to_be_signed_raw(&prot, &payload);
    if !v.verify_raw(&tbs, &sig) {
        return Err(cose::err_bad_signature());
    }
    Ok(o)
}

fn object_from_map(m: &[(Value, Value)]) -> Result<Object, cose::Error> {
    let mut o = Object {
        id: vec![], kind: 0, channel: 0, tier: 0, signer: vec![], created: 0,
        effect: 0, causes: vec![], profile: 0, body: Value::Uint(0), ext: None, cext: None,
    };
    let (mut hk, mut hc, mut ht, mut hs, mut hcr, mut he, mut hca, mut hp, mut hb) =
        (false, false, false, false, false, false, false, false, false);
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
            FIELD_KIND => { o.kind = as_uint(val)?; hk = true; }
            FIELD_CHANNEL => { o.channel = as_uint(val)?; hc = true; }
            FIELD_TIER => { o.tier = as_uint(val)?; ht = true; }
            FIELD_SIGNER => match val {
                Value::Bstr(b) => { o.signer = b.clone(); hs = true; }
                _ => return Err(e_malformed()),
            },
            FIELD_CREATED => { o.created = as_uint(val)?; hcr = true; }
            FIELD_EFFECT => { o.effect = as_uint(val)?; he = true; }
            FIELD_CAUSES => match val {
                Value::Arr(a) => {
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
            FIELD_PROFILE => { o.profile = as_uint(val)?; hp = true; }
            FIELD_BODY => { o.body = val.clone(); hb = true; }
            FIELD_EXT => match val {
                Value::Map(mm) => o.ext = Some(mm.clone()),
                _ => return Err(e_malformed()),
            },
            FIELD_CEXT => match val {
                Value::Map(mm) => o.cext = Some(mm.clone()),
                _ => return Err(e_malformed()),
            },
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
                Value::Nint(a) => { alg = *a; have_alg = true; }
                _ => return Err(e_malformed()),
            },
            Value::Tstr(s) if s == NAALP_HEADER_LABEL => {
                let nm = match val {
                    Value::Map(nm) => nm,
                    _ => return Err(e_malformed()),
                };
                for (nk, nv) in nm {
                    match nk {
                        Value::Uint(1) => if let Value::Bstr(b) = nv { signer = b.clone() },
                        Value::Uint(2) => if let Value::Uint(u) = nv { profile = *u },
                        Value::Uint(3) => if let Value::Uint(u) = nv { version = *u },
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
            causes: o["causes_hex"].as_array().unwrap().iter()
                .map(|h| hex::decode(h.as_str().unwrap()).unwrap()).collect(),
            profile: o["profile"].as_u64().unwrap(),
            body: Value::Tstr(o["body_str"].as_str().unwrap().to_string()),
            ext: None,
            cext: None,
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

    fn accept_kind(ch: u64, k: u64) -> bool { ch == 4 && k == 2 }

    #[test]
    fn envelope_bytes_match_oracle() {
        let c = load();
        let o = build_object(&c);
        let ob = &c["object"];
        assert_eq!(hex::encode(o.content_id()), ob["content_id_hex"].as_str().unwrap(), "content-id");
        assert_eq!(hex::encode(cbor::encode(&o.body_map(false)).unwrap()),
                   ob["body_no_id_hex"].as_str().unwrap(), "body-no-id");
        let mut o2 = o.clone();
        o2.id = o.content_id();
        assert_eq!(hex::encode(cbor::encode(&o2.body_map(true)).unwrap()),
                   ob["payload_hex"].as_str().unwrap(), "payload");
        let prot = protected_header(ob["alg"].as_i64().unwrap(), &o.signer, o.profile);
        assert_eq!(hex::encode(&prot), ob["protected_hex"].as_str().unwrap(), "protected");
        let payload = cbor::encode(&o2.body_map(true)).unwrap();
        assert_eq!(hex::encode(cose::to_be_signed_raw(&prot, &payload)),
                   ob["tobesigned_hex"].as_str().unwrap(), "tobesigned");
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
        expect_kind("ContentIdMismatch", &sign_with_id(&mut build_object(&c), &s, &bogus),
                    "ContentIdMismatch", &accept_kind, &[]);

        expect_kind("HeaderBodyMismatch", &sign_with_header_profile(&mut build_object(&c), &s, 2),
                    "HeaderBodyMismatch", &accept_kind, &[]);

        let mut oc = build_object(&c);
        oc.cext = Some(vec![(Value::Uint(100), Value::Uint(7))]);
        expect_kind("UnknownCriticalExt", &sign(&mut oc, &s), "UnknownCriticalExt", &accept_kind, &[]);

        // NonCanonical: payload is a map with out-of-order keys.
        let nc = sign_raw_payload(&s, &hex::decode("a203000200").unwrap());
        expect_kind("NonCanonical", &nc, "NonCanonical", &accept_kind, &[]);

        expect_kind("UnknownKind", &valid, "UnknownKind", &|_, _| false, &[]);

        let mut orange = build_object(&c);
        orange.channel = 99;
        expect_kind("RangeError", &sign(&mut orange, &s), "RangeError", &|_, _| true, &[]);

        expect_kind("UnsupportedVersion", &sign_with_version(&mut build_object(&c), &s, 2),
                    "UnsupportedVersion", &accept_kind, &[]);
    }

    #[test]
    fn non_critical_ext_ignored() {
        let c = load();
        let (s, v) = test_keys();
        let mut o = build_object(&c);
        o.ext = Some(vec![(Value::Uint(100), Value::Uint(7))]);
        let obj = sign(&mut o, &s);
        verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[], &obj).expect("non-critical ext ignored");
    }

    #[test]
    fn known_critical_ext_accepted() {
        let c = load();
        let (s, v) = test_keys();
        let mut o = build_object(&c);
        o.cext = Some(vec![(Value::Uint(100), Value::Uint(7))]);
        let obj = sign(&mut o, &s);
        verify(cose::PROFILE_PUBLIC, &v, &accept_kind, &[100], &obj).expect("known critical ext accepted");
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
