// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP deterministic CBOR (RFC 8949 §4.2.1) and object content-id (design.md §2.3).
//! C1 spine component. This module is the Rust half of the two-implementation parity
//! proof; it reproduces the exact bytes emitted by the independent Python oracle
//! (`tools/cbor_oracle.py`) and rejects the same non-canonical inputs.

use sha2::{Digest, Sha384};

/// A CBOR value in the subset the N-AALP spine uses (design.md §3.1): unsigned
/// integers, byte strings, text strings, arrays, and maps. No floats, tags,
/// negatives, or booleans.
#[derive(Clone, Debug)]
pub enum Value {
    Uint(u64),
    /// CBOR negative integer (major type 1); value < 0. The object body uses no
    /// negatives (a surface rule), but the COSE protected header (§4) encodes negative
    /// algorithm ids (e.g. ML-DSA-65 = -49), so the codec supports major type 1.
    Nint(i64),
    Bstr(Vec<u8>),
    Tstr(String),
    Arr(Vec<Value>),
    Map(Vec<(Value, Value)>),
    /// CBOR tag (major type 6): a tag number applied to a tagged content value. N-AALP
    /// uses tags to make a signed object self-identifying — COSE_Sign1 = tag 18, the
    /// hybrid COSE_Sign = tag 98 (RFC 9052, design.md §4.2).
    Tag(u64, Box<Value>),
}

/// An encode/decode failure carrying a stable `kind` (e.g. "NonCanonical").
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: &'static str,
    pub msg: &'static str,
}

fn nc(msg: &'static str) -> Error {
    Error { kind: "NonCanonical", msg }
}

/// Shortest-form head for a major type and argument `n`.
fn enc_head(major: u8, n: u64) -> Vec<u8> {
    let mt = major << 5;
    if n < 24 {
        vec![mt | n as u8]
    } else if n < 0x100 {
        vec![mt | 24, n as u8]
    } else if n < 0x1_0000 {
        vec![mt | 25, (n >> 8) as u8, n as u8]
    } else if n < 0x1_0000_0000 {
        vec![mt | 26, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    } else {
        vec![
            mt | 27,
            (n >> 56) as u8, (n >> 48) as u8, (n >> 40) as u8, (n >> 32) as u8,
            (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8,
        ]
    }
}

/// Deterministic CBOR encoding of `v` (RFC 8949 §4.2.1).
pub fn encode(v: &Value) -> Result<Vec<u8>, Error> {
    match v {
        Value::Uint(n) => Ok(enc_head(0, *n)),
        Value::Nint(n) => {
            if *n >= 0 {
                return Err(Error { kind: "Unencodable", msg: "Nint must be negative" });
            }
            Ok(enc_head(1, !*n as u64)) // !n == -1 - n (two's complement), no overflow
        }
        Value::Bstr(b) => {
            let mut o = enc_head(2, b.len() as u64);
            o.extend_from_slice(b);
            Ok(o)
        }
        Value::Tstr(s) => {
            let b = s.as_bytes();
            let mut o = enc_head(3, b.len() as u64);
            o.extend_from_slice(b);
            Ok(o)
        }
        Value::Arr(items) => {
            let mut o = enc_head(4, items.len() as u64);
            for it in items {
                o.extend_from_slice(&encode(it)?);
            }
            Ok(o)
        }
        Value::Tag(n, content) => {
            let mut o = enc_head(6, *n);
            o.extend_from_slice(&encode(content)?);
            Ok(o)
        }
        Value::Map(pairs) => {
            let mut encs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(pairs.len());
            let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
            for (k, val) in pairs {
                let ek = encode(k)?;
                let ev = encode(val)?;
                if !seen.insert(ek.clone()) {
                    return Err(nc("duplicate map key"));
                }
                encs.push((ek, ev));
            }
            encs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut o = enc_head(5, pairs.len() as u64);
            for (ek, ev) in encs {
                o.extend_from_slice(&ek);
                o.extend_from_slice(&ev);
            }
            Ok(o)
        }
    }
}

/// Object content-id (design.md §2.3): multihash(0x20, SHA-384(canonical body without
/// field 1)). Caller passes the body map with the id field omitted; result is the
/// 50-byte id `0x20 0x30 || digest`.
pub fn content_id(body_without_id: &Value) -> Result<Vec<u8>, Error> {
    let enc = encode(body_without_id)?;
    let digest = Sha384::digest(&enc); // 48 bytes
    let mut out = Vec::with_capacity(2 + digest.len());
    out.push(0x20); // multihash code sha2-384
    out.push(0x30); // digest length 48
    out.extend_from_slice(&digest);
    Ok(out)
}

/// Decode exactly one canonical CBOR item, rejecting any non-canonical input or
/// trailing bytes (fail-closed, R-3.4).
pub fn decode(data: &[u8]) -> Result<Value, Error> {
    let (v, rest) = decode_one(data)?;
    if !rest.is_empty() {
        return Err(nc("trailing bytes after item"));
    }
    Ok(v)
}

fn decode_one(b: &[u8]) -> Result<(Value, &[u8]), Error> {
    if b.is_empty() {
        return Err(nc("unexpected end of input"));
    }
    let ib = b[0];
    let major = ib >> 5;
    let ai = ib & 0x1f;
    let (arg, rest) = read_arg(ai, &b[1..])?;
    match major {
        0 => Ok((Value::Uint(arg), rest)),
        1 => {
            if arg > i64::MAX as u64 {
                return Err(nc("negative integer out of supported range"));
            }
            Ok((Value::Nint(!(arg as i64)), rest)) // !arg == -1 - arg
        }
        2 => {
            let n = arg as usize;
            if rest.len() < n {
                return Err(nc("byte string longer than input"));
            }
            Ok((Value::Bstr(rest[..n].to_vec()), &rest[n..]))
        }
        3 => {
            let n = arg as usize;
            if rest.len() < n {
                return Err(nc("text string longer than input"));
            }
            let s = std::str::from_utf8(&rest[..n]).map_err(|_| nc("text string is not valid UTF-8"))?;
            Ok((Value::Tstr(s.to_string()), &rest[n..]))
        }
        4 => {
            let mut items = Vec::with_capacity(arg as usize);
            let mut cur = rest;
            for _ in 0..arg {
                let (it, c) = decode_one(cur)?;
                items.push(it);
                cur = c;
            }
            Ok((Value::Arr(items), cur))
        }
        5 => {
            let mut pairs = Vec::with_capacity(arg as usize);
            let mut cur = rest;
            let mut prev_key: Option<&[u8]> = None;
            for _ in 0..arg {
                let key_start = cur;
                let (k, c) = decode_one(cur)?;
                cur = c;
                let kbytes = &key_start[..key_start.len() - cur.len()];
                if let Some(pk) = prev_key {
                    match pk.cmp(kbytes) {
                        std::cmp::Ordering::Greater => return Err(nc("map keys not in canonical order")),
                        std::cmp::Ordering::Equal => return Err(nc("duplicate map key")),
                        std::cmp::Ordering::Less => {}
                    }
                }
                prev_key = Some(kbytes);
                let (val, c2) = decode_one(cur)?;
                cur = c2;
                pairs.push((k, val));
            }
            Ok((Value::Map(pairs), cur))
        }
        6 => {
            let (content, rest2) = decode_one(rest)?;
            Ok((Value::Tag(arg, Box::new(content)), rest2))
        }
        _ => Err(nc("major type not used in the N-AALP spine")),
    }
}

/// Read a head argument, enforcing shortest form and rejecting reserved (28-30) and
/// indefinite (31) additional information.
fn read_arg(ai: u8, b: &[u8]) -> Result<(u64, &[u8]), Error> {
    match ai {
        0..=23 => Ok((ai as u64, b)),
        24 => {
            if b.is_empty() {
                return Err(nc("truncated 1-byte argument"));
            }
            let n = b[0] as u64;
            if n < 24 {
                return Err(nc("argument not in shortest form"));
            }
            Ok((n, &b[1..]))
        }
        25 => {
            if b.len() < 2 {
                return Err(nc("truncated 2-byte argument"));
            }
            let n = ((b[0] as u64) << 8) | b[1] as u64;
            if n < 0x100 {
                return Err(nc("argument not in shortest form"));
            }
            Ok((n, &b[2..]))
        }
        26 => {
            if b.len() < 4 {
                return Err(nc("truncated 4-byte argument"));
            }
            let n = ((b[0] as u64) << 24) | ((b[1] as u64) << 16) | ((b[2] as u64) << 8) | b[3] as u64;
            if n < 0x1_0000 {
                return Err(nc("argument not in shortest form"));
            }
            Ok((n, &b[4..]))
        }
        27 => {
            if b.len() < 8 {
                return Err(nc("truncated 8-byte argument"));
            }
            let mut n: u64 = 0;
            for &byte in &b[..8] {
                n = (n << 8) | byte as u64;
            }
            if n < 0x1_0000_0000 {
                return Err(nc("argument not in shortest form"));
            }
            Ok((n, &b[8..]))
        }
        _ => Err(nc("reserved or indefinite-length additional information")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/cbor/cases.json";

    fn load() -> J {
        let s = std::fs::read_to_string(VECTOR_PATH).expect("read corpus");
        serde_json::from_str(&s).expect("parse corpus")
    }

    fn build_value(j: &J) -> Value {
        let arr = j.as_array().unwrap();
        match arr[0].as_str().unwrap() {
            "u" => Value::Uint(arr[1].as_u64().unwrap()),
            "b" => Value::Bstr(hex::decode(arr[1].as_str().unwrap()).unwrap()),
            "s" => Value::Tstr(arr[1].as_str().unwrap().to_string()),
            "arr" => Value::Arr(arr[1].as_array().unwrap().iter().map(build_value).collect()),
            "map" => Value::Map(
                arr[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        let pp = p.as_array().unwrap();
                        (build_value(&pp[0]), build_value(&pp[1]))
                    })
                    .collect(),
            ),
            t => panic!("bad tag {t}"),
        }
    }

    fn body_without_id(obj: &serde_json::Map<String, J>) -> Value {
        let mut keys: Vec<u64> = obj.keys().map(|k| k.parse::<u64>().unwrap()).collect();
        keys.sort_unstable();
        let pairs = keys
            .into_iter()
            .map(|k| (Value::Uint(k), build_value(&obj[&k.to_string()])))
            .collect();
        Value::Map(pairs)
    }

    #[test]
    fn positives_match_oracle() {
        let root = load();
        let positives = root["positives"].as_array().unwrap();
        assert!(!positives.is_empty(), "no positive cases");
        for p in positives {
            let name = p["name"].as_str().unwrap();
            let obj = p["obj_without_id"].as_object().unwrap();
            let body = body_without_id(obj);

            let body_enc = encode(&body).unwrap();
            assert_eq!(hex::encode(&body_enc), p["body_no1_hex"].as_str().unwrap(), "{name}: body_no1");

            let id = content_id(&body).unwrap();
            assert_eq!(hex::encode(&id), p["id_hex"].as_str().unwrap(), "{name}: content-id");

            let mut full_pairs = vec![(Value::Uint(1), Value::Bstr(id.clone()))];
            if let Value::Map(pairs) = &body {
                full_pairs.extend(pairs.clone());
            }
            let full = Value::Map(full_pairs);
            let full_enc = encode(&full).unwrap();
            let full_hex = p["full_hex"].as_str().unwrap();
            assert_eq!(hex::encode(&full_enc), full_hex, "{name}: full");

            // Round-trip: canonical bytes decode and re-encode identically.
            let want = hex::decode(full_hex).unwrap();
            let decoded = decode(&want).unwrap();
            assert_eq!(encode(&decoded).unwrap(), want, "{name}: round-trip");
        }
    }

    #[test]
    fn negatives_rejected() {
        let root = load();
        let negatives = root["negatives"].as_array().unwrap();
        assert!(!negatives.is_empty(), "no negative cases");
        for n in negatives {
            let name = n["name"].as_str().unwrap();
            let raw = hex::decode(n["bytes_hex"].as_str().unwrap()).unwrap();
            let expect = n["expect"].as_str().unwrap();
            match decode(&raw) {
                Ok(v) => panic!("{name}: expected rejection, decoded {v:?}"),
                Err(e) => assert_eq!(e.kind, expect, "{name}: wrong error kind"),
            }
        }
    }

    #[test]
    fn sha384_kat() {
        let root = load();
        let kat = &root["sha384_kat"];
        let d = Sha384::digest(kat["input_utf8"].as_str().unwrap().as_bytes());
        assert_eq!(hex::encode(d), kat["digest_hex"].as_str().unwrap());
    }

    // Mutation guard: a constant encoder or constant digest would fail these.
    #[test]
    fn encode_is_not_constant() {
        let a = encode(&Value::Map(vec![(Value::Uint(1), Value::Uint(0))])).unwrap();
        let b = encode(&Value::Map(vec![(Value::Uint(1), Value::Uint(1))])).unwrap();
        assert_ne!(a, b, "encoder produced identical bytes for different inputs");
        let ida = content_id(&Value::Map(vec![(Value::Uint(2), Value::Tstr("x".into()))])).unwrap();
        let idb = content_id(&Value::Map(vec![(Value::Uint(2), Value::Tstr("y".into()))])).unwrap();
        assert_ne!(ida, idb, "content-id identical for different bodies");
        assert_eq!((ida[0], ida[1], ida.len()), (0x20, 0x30, 50), "content-id framing");
    }

    // R-3.3 "absent != empty" edge case (design.md §3.3): an optional field present but
    // empty must encode differently from the same object with that field absent, produce
    // a different content id, and both must round-trip with the distinction preserved.
    // Independent of the vector file; mutation-surviving (a constant encoder collapses
    // the two to equal).
    #[test]
    fn empty_vs_absent_optional() {
        let base = vec![
            (Value::Uint(2), Value::Uint(0)),
            (Value::Uint(10), Value::Tstr("x".into())),
        ];
        let absent = Value::Map(base.clone());
        let mut empty_pairs = base.clone();
        empty_pairs.push((Value::Uint(11), Value::Map(vec![]))); // field 11 present, empty
        let empty = Value::Map(empty_pairs);

        let ea = encode(&absent).unwrap();
        let eb = encode(&empty).unwrap();
        assert_ne!(ea, eb, "absent optional encoded identically to present-empty");
        assert_ne!(
            content_id(&absent).unwrap(),
            content_id(&empty).unwrap(),
            "absent vs present-empty produced identical content ids"
        );

        for enc in [ea.clone(), eb.clone()] {
            let v = decode(&enc).unwrap();
            assert_eq!(encode(&v).unwrap(), enc, "round-trip not identical");
        }

        // present-empty keeps key 11 as an empty map; absent has no key 11.
        if let Value::Map(m) = decode(&eb).unwrap() {
            match m.iter().find(|(k, _)| matches!(k, Value::Uint(11))) {
                Some((_, Value::Map(inner))) => assert!(inner.is_empty(), "field 11 not empty"),
                _ => panic!("present-empty field 11 lost on round-trip"),
            }
        } else {
            panic!("not a map");
        }
        if let Value::Map(m) = decode(&ea).unwrap() {
            assert!(
                m.iter().all(|(k, _)| !matches!(k, Value::Uint(11))),
                "absent field 11 appeared after round-trip"
            );
        }
    }

    // Negative-integer (major type 1) codec extension for COSE algorithm ids, graded
    // against the RFC 8949 Appendix A worked examples (independent authority).
    // Mutation-surviving: a constant encoder fails the fixed hex expectations.
    #[test]
    fn nint_rfc8949() {
        let cases: [(i64, &str); 7] = [
            (-1, "20"), (-10, "29"), (-100, "3863"), (-1000, "3903e7"), // RFC 8949 App. A
            (-49, "3830"), // COSE ML-DSA-65
            (-50, "3831"), // COSE ML-DSA-87
            (-19, "32"),   // COSE Ed25519
        ];
        for (v, want) in cases {
            let enc = encode(&Value::Nint(v)).unwrap();
            assert_eq!(hex::encode(&enc), want, "encode Nint({v})");
            let dec = decode(&hex::decode(want).unwrap()).unwrap();
            assert!(matches!(dec, Value::Nint(x) if x == v), "decode {want} -> Nint({v})");
        }
        assert!(encode(&Value::Nint(0)).is_err(), "Nint(0) must be unencodable");
    }
}
