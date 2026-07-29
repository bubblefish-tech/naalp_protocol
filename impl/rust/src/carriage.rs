// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C12 — foreign carriage by class (design.md §13; R-14.1..14.8, R-18.6).
//!
//! N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed
//! N-AALP carriage object interpreted by a carriage CLASS, not a bespoke per-protocol mapping
//! (R-14.1). Five structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE
//! class make any protocol — including an undefined one — carriable immediately on an
//! experimental protocol id with no registration (R-18.6). The foreign field is carried VERBATIM
//! and MUST NOT be re-serialized, canonicalized, summarized, or rewritten (R-14.4). The carriage
//! object's signer remains the authority — a foreign identity never becomes an N-AALP
//! authorization identity (R-14.6).

use crate::cbor::{self, Value};
use crate::cose;
use crate::envelope;

// Carriage classes (design.md §13.2).
pub const CLASS_JSONRPC: u64 = 0;
pub const CLASS_HTTP: u64 = 1;
pub const CLASS_MSG: u64 = 2;
pub const CLASS_STREAM: u64 = 3;
pub const CLASS_DOC: u64 = 4;
pub const CLASS_OPAQUE: u64 = 5;

const CLASS_NAMES: [&str; 6] = ["JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"];

pub fn class_name(c: u64) -> &'static str {
    if (c as usize) < CLASS_NAMES.len() {
        CLASS_NAMES[c as usize]
    } else {
        "unknown"
    }
}

pub fn err_not_delivered() -> cose::Error {
    cose::Error { kind: "NotDelivered", msg: "a below-foreign failure; the message was not delivered" }
}
pub fn err_mapping_unrepresentable() -> cose::Error {
    cose::Error { kind: "MappingError", msg: "an N-AALP semantic cannot be represented by this carriage class" }
}
pub fn err_malformed() -> cose::Error {
    cose::Error { kind: "Malformed", msg: "malformed carriage body" }
}

/// The body of a carriage object (design.md §13.2).
#[derive(Debug)]
pub struct CarriageBody {
    pub protocol_id: u64,
    pub class: u64,
    pub content_type: u64,
    pub correlation: Vec<u8>,
    pub method: String,
    pub foreign: Vec<u8>, // carried octet-for-octet (R-14.4)
}

impl CarriageBody {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.protocol_id)),
            (Value::Uint(2), Value::Uint(self.class)),
            (Value::Uint(3), Value::Uint(self.content_type)),
            (Value::Uint(4), Value::Bstr(self.correlation.clone())),
            (Value::Uint(5), Value::Tstr(self.method.clone())),
            (Value::Uint(6), Value::Bstr(self.foreign.clone())),
        ])
    }
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode carriage body")
    }
}

/// Reject a class outside the defined set with a typed mapping error, never a silent drop (R-14.8).
pub fn validate_class(class: u64) -> Result<(), cose::Error> {
    if class > CLASS_OPAQUE {
        return Err(err_mapping_unrepresentable());
    }
    Ok(())
}

/// Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4) without parsing,
/// canonicalizing, or rewriting the foreign bytes.
pub fn carry(
    protocol_id: u64,
    class: u64,
    content_type: u64,
    correlation: Vec<u8>,
    method: String,
    foreign: Vec<u8>,
) -> Result<CarriageBody, cose::Error> {
    validate_class(class)?;
    Ok(CarriageBody { protocol_id, class, content_type, correlation, method, foreign })
}

/// Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet.
pub fn carriage_from_value(v: &Value) -> Result<CarriageBody, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_malformed()),
    };
    let (mut pid, mut class, mut ct, mut corr, mut method, mut foreign) =
        (None, None, None, None, None, None);
    for (k, val) in m {
        let key = match k {
            Value::Uint(n) => *n,
            _ => return Err(err_malformed()),
        };
        match (key, val) {
            (1, Value::Uint(u)) => pid = Some(*u),
            (2, Value::Uint(u)) => class = Some(*u),
            (3, Value::Uint(u)) => ct = Some(*u),
            (4, Value::Bstr(b)) => corr = Some(b.clone()),
            (5, Value::Tstr(s)) => method = Some(s.clone()),
            (6, Value::Bstr(b)) => foreign = Some(b.clone()),
            _ => return Err(err_malformed()),
        }
    }
    match (pid, class, ct, corr, method, foreign) {
        (Some(protocol_id), Some(class), Some(content_type), Some(correlation), Some(method), Some(foreign)) => {
            validate_class(class)?;
            Ok(CarriageBody { protocol_id, class, content_type, correlation, method, foreign })
        }
        _ => Err(err_malformed()),
    }
}

/// Protocol id ranges (design.md §13.4): standards 0x01-0x0F, experimental 0x10-0x7F, private
/// 0x80-0xFF; 0x00 reserved.
pub fn protocol_range(id: u64) -> &'static str {
    match id {
        0x00 => "reserved",
        0x01..=0x0F => "standards",
        0x10..=0x7F => "experimental",
        0x80..=0xFF => "private",
        _ => "invalid",
    }
}

/// Records whether a carried message was actually delivered; never claims delivery not achieved.
#[derive(Debug)]
pub struct DeliveryReport {
    pub delivered: bool,
}

/// A failed below-foreign delivery yields delivered=false and NotDelivered — never a false
/// "delivered" (R-14.8).
pub fn report(delivered_below: bool) -> Result<DeliveryReport, cose::Error> {
    if !delivered_below {
        return Err(err_not_delivered());
    }
    Ok(DeliveryReport { delivered: true })
}

/// The authorizing principal of a carriage object: the N-AALP signer (envelope field 5), never a
/// foreign principal inside the foreign bytes (R-14.6). Reads only the signed envelope.
pub fn carriage_authority(o: &envelope::Object) -> &[u8] {
    &o.signer
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const CLASS_DIRS: [(&str, u64); 6] = [
        ("jsonrpc", CLASS_JSONRPC),
        ("http", CLASS_HTTP),
        ("msg", CLASS_MSG),
        ("stream", CLASS_STREAM),
        ("doc", CLASS_DOC),
        ("opaque", CLASS_OPAQUE),
    ];

    fn load_class(dir: &str) -> J {
        let p = format!("../../vectors/carriage/{}/cases.json", dir);
        serde_json::from_str(&std::fs::read_to_string(&p).expect("read")).expect("parse")
    }

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    #[test]
    fn per_class_octet_exact_round_trip() {
        for (dir, cls) in CLASS_DIRS {
            let c = load_class(dir);
            assert_eq!(c["class"].as_u64().unwrap(), cls, "{}", dir);
            let foreign = hexd(c["foreign_hex"].as_str().unwrap());
            let cb = carry(
                c["protocol_id"].as_u64().unwrap(),
                cls,
                c["content_type"].as_u64().unwrap(),
                hexd(c["correlation_hex"].as_str().unwrap()),
                c["method"].as_str().unwrap().to_string(),
                foreign.clone(),
            )
            .expect("carry");
            assert_eq!(hex::encode(cb.bytes()), c["body_hex"].as_str().unwrap(), "{} body", dir);
            let v = cbor::decode(&cb.bytes()).expect("decode");
            let rec = carriage_from_value(&v).expect("from value");
            assert_eq!(rec.foreign, foreign, "{} foreign not octet-identical", dir);
            assert_eq!(rec.protocol_id, c["protocol_id"].as_u64().unwrap());
            assert_eq!(rec.method, c["method"].as_str().unwrap());
        }
    }

    #[test]
    fn opaque_undefined_protocol() {
        let c = load_class("opaque");
        assert_eq!(protocol_range(c["protocol_id"].as_u64().unwrap()), "experimental");
        let blob = vec![0x00u8, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80];
        let cb = carry(c["protocol_id"].as_u64().unwrap(), CLASS_OPAQUE, 1, vec![], String::new(), blob.clone()).unwrap();
        let rec = carriage_from_value(&cbor::decode(&cb.bytes()).unwrap()).unwrap();
        assert_eq!(rec.foreign, blob);
    }

    #[test]
    fn registry() {
        let text = std::fs::read_to_string("../../vectors/registry/protocols.csv").expect("read csv");
        let mut rows = 0;
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let cols: Vec<&str> = line.split(',').collect();
            let id = u64::from_str_radix(cols[0].trim_start_matches("0x"), 16).expect("id");
            assert_eq!(protocol_range(id), "standards", "row {}", cols[0]);
            assert_eq!(cols[3], "standards");
            rows += 1;
        }
        assert!(rows > 0, "registry empty");
        for (id, want) in [(0x00u64, "reserved"), (0x01, "standards"), (0x0F, "standards"), (0x10, "experimental"), (0x7F, "experimental"), (0x80, "private"), (0xFF, "private")] {
            assert_eq!(protocol_range(id), want, "range {:#x}", id);
        }
    }

    #[test]
    fn mapping_error_on_unknown_class() {
        assert_eq!(carry(0x10, 99, 0, vec![], "x".into(), b"y".to_vec()).unwrap_err().kind, "MappingError");
    }

    #[test]
    fn not_delivered() {
        assert_eq!(report(false).unwrap_err().kind, "NotDelivered");
        assert!(report(true).unwrap().delivered);
    }

    #[test]
    fn identity_containment() {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[80; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        let (v, s) = (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk));
        let kind_ok = |_c: u64, _k: u64| true;

        let foreign = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"from":"attacker-principal"}}"#.to_vec();
        let cb = carry(0x01, CLASS_JSONRPC, 0, vec![1, 2, 3, 4], "tools/call".into(), foreign.clone()).unwrap();
        let mut o = envelope::Object {
            id: vec![], kind: 0, channel: 13, tier: 0, signer: pkb.clone(), created: 100,
            effect: 0, causes: vec![], profile: cose::PROFILE_PUBLIC as u64,
            body: cb.to_value(), ext: None, cext: None,
        };
        let signed = envelope::sign(&mut o, &s);
        let ov = envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed).expect("verify");
        // authority = the N-AALP signer, not the foreign principal.
        assert_eq!(carriage_authority(&ov), pkb.as_slice());
        assert!(!carriage_authority(&ov).windows(b"attacker-principal".len()).any(|w| w == b"attacker-principal"));
        let rec = carriage_from_value(&ov.body).expect("carriage from body");
        assert_eq!(rec.foreign, foreign, "foreign not recovered octet-exact");
        assert!(rec.foreign.windows(b"attacker-principal".len()).any(|w| w == b"attacker-principal"));
    }
}
