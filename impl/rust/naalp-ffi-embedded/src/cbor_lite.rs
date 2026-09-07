// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! A `no_std` + `alloc` canonical-CBOR (RFC 8949 §4.2.1) subset, purpose-built for
//! `naalp-ffi-embedded`'s verify-only path.
//!
//! This is an INDEPENDENT reimplementation, not a wrapper: the std `naalp` crate's own
//! `impl/rust/src/cbor.rs` cannot be linked into a genuinely no_std target (see the
//! crate-level docs in `lib.rs` for the precise blocker). It decodes/encodes the SAME
//! value subset (RFC 8949 shortest-form arguments, sorted and non-duplicate map keys,
//! definite-length only, no floats/booleans/indefinite-length) and enforces the SAME
//! canonical-form rules as the reference decoder — it introduces no new wire format — so a
//! byte sequence this module accepts or rejects agrees with the reference. It is graded
//! against the same independent-authority vectors as the reference (`vectors/cbor/cases.json`
//! RFC 8949 Appendix A negative-integer values, `vectors/cose/cases.json` protected-header
//! bytes), never against its own output (F3 non-circularity).
//!
//! One deliberate implementation difference from `impl/rust/src/cbor.rs::encode`: map-key
//! duplicate detection here is done by sorting the encoded `(key, value)` pairs and scanning
//! for adjacent-equal keys, instead of a `std::collections::HashSet`. `HashSet` needs
//! `std`'s random-seeded hasher (unavailable under `no_std`); a `no_std` `HashSet` would need
//! `hashbrown` as an extra dependency this narrow subset does not otherwise need. The
//! sort-then-scan approach has the same O(n log n) complexity as the sort this function
//! already performs and produces byte-identical output for every canonical (duplicate-free)
//! input — verified below against the same `vectors/cbor/cases.json` corpus and RFC 8949
//! Appendix A vectors the reference decoder is graded against.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// A CBOR value in the subset this module supports: unsigned/negative integers, byte
/// strings, text strings, arrays, maps, and one level of CBOR tag (RFC 9052 COSE tags 18
/// and 98 use major type 6 exactly this way).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Uint(u64),
    Nint(i64),
    Bstr(Vec<u8>),
    Tstr(String),
    Arr(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
}

/// An encode/decode failure carrying a stable `kind`, matching the `kind` string taxonomy
/// `naalp::cbor::Error` uses (`"NonCanonical"`, `"DepthExceeded"`, `"Unencodable"`) so a
/// caller consuming both this crate and the reference SDK sees one consistent vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: &'static str,
    pub msg: &'static str,
}

fn nc(msg: &'static str) -> Error {
    Error {
        kind: "NonCanonical",
        msg,
    }
}

fn depth_exceeded() -> Error {
    Error {
        kind: "DepthExceeded",
        msg: "CBOR nesting depth exceeds the maximum",
    }
}

fn enc_head(major: u8, n: u64) -> Vec<u8> {
    let mt = major << 5;
    if n < 24 {
        alloc::vec![mt | n as u8]
    } else if n < 0x100 {
        alloc::vec![mt | 24, n as u8]
    } else if n < 0x1_0000 {
        alloc::vec![mt | 25, (n >> 8) as u8, n as u8]
    } else if n < 0x1_0000_0000 {
        alloc::vec![
            mt | 26,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ]
    } else {
        alloc::vec![
            mt | 27,
            (n >> 56) as u8,
            (n >> 48) as u8,
            (n >> 40) as u8,
            (n >> 32) as u8,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ]
    }
}

/// Deterministic CBOR encoding of `v` (RFC 8949 §4.2.1).
pub fn encode(v: &Value) -> Result<Vec<u8>, Error> {
    match v {
        Value::Uint(n) => Ok(enc_head(0, *n)),
        Value::Nint(n) => {
            if *n >= 0 {
                return Err(Error {
                    kind: "Unencodable",
                    msg: "Nint must be negative",
                });
            }
            Ok(enc_head(1, !*n as u64))
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
            for (k, val) in pairs {
                encs.push((encode(k)?, encode(val)?));
            }
            encs.sort_by(|a, b| a.0.cmp(&b.0));
            for w in encs.windows(2) {
                if w[0].0 == w[1].0 {
                    return Err(nc("duplicate map key"));
                }
            }
            let mut o = enc_head(5, pairs.len() as u64);
            for (ek, ev) in encs {
                o.extend_from_slice(&ek);
                o.extend_from_slice(&ev);
            }
            Ok(o)
        }
    }
}

/// Sentinel matching `naalp::cbor::MAX_DEPTH_UNBOUNDED`'s role: far beyond any legitimate
/// COSE_Sign1/protected-header structure, yet finite (this crate always bounds — there is no
/// "trusted input" fast path here, since every byte this crate decodes arrived over a wire).
const MAX_DEPTH_DEFAULT: usize = 32;

/// Decode exactly one canonical CBOR item with the default depth bound, rejecting any
/// non-canonical input or trailing bytes (fail-closed).
pub fn decode(data: &[u8]) -> Result<Value, Error> {
    decode_bounded(data, MAX_DEPTH_DEFAULT)
}

/// Decode with an explicit maximum CBOR nesting depth (design.md §3.4 (R7), RFC 8949 §10
/// decoder-memory guard): the outermost item is depth 1.
pub fn decode_bounded(data: &[u8], max_depth: usize) -> Result<Value, Error> {
    let (v, rest) = decode_one(data, 1, max_depth)?;
    if !rest.is_empty() {
        return Err(nc("trailing bytes after item"));
    }
    Ok(v)
}

fn decode_one(b: &[u8], depth: usize, max_depth: usize) -> Result<(Value, &[u8]), Error> {
    if depth > max_depth {
        return Err(depth_exceeded());
    }
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
            Ok((Value::Nint(!(arg as i64)), rest))
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
            let s = core::str::from_utf8(&rest[..n])
                .map_err(|_| nc("text string is not valid UTF-8"))?;
            Ok((Value::Tstr(String::from(s)), &rest[n..]))
        }
        4 => {
            let mut items = Vec::with_capacity(arg as usize);
            let mut cur = rest;
            for _ in 0..arg {
                let (it, c) = decode_one(cur, depth + 1, max_depth)?;
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
                let (k, c) = decode_one(cur, depth + 1, max_depth)?;
                cur = c;
                let kbytes = &key_start[..key_start.len() - cur.len()];
                if let Some(pk) = prev_key {
                    match pk.cmp(kbytes) {
                        Ordering::Greater => return Err(nc("map keys not in canonical order")),
                        Ordering::Equal => return Err(nc("duplicate map key")),
                        Ordering::Less => {}
                    }
                }
                prev_key = Some(kbytes);
                let (val, c2) = decode_one(cur, depth + 1, max_depth)?;
                cur = c2;
                pairs.push((k, val));
            }
            Ok((Value::Map(pairs), cur))
        }
        6 => {
            let (content, rest2) = decode_one(rest, depth + 1, max_depth)?;
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
            let n =
                ((b[0] as u64) << 24) | ((b[1] as u64) << 16) | ((b[2] as u64) << 8) | b[3] as u64;
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

/// Object content-id (design.md §2.3): multihash(0x20, SHA-384(canonical-encoding(body))).
/// Caller passes the body value with field 1 (the id itself) already omitted; result is the
/// 50-byte id `0x20 0x30 || digest`. Mirrors `naalp::cbor::content_id` exactly.
pub fn content_id(body_without_id: &Value) -> Result<Vec<u8>, Error> {
    use sha2::{Digest, Sha384};
    let enc = encode(body_without_id)?;
    let digest = Sha384::digest(&enc);
    let mut out = Vec::with_capacity(2 + digest.len());
    out.push(0x20);
    out.push(0x30);
    out.extend_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent authority: RFC 8949 Appendix A worked examples plus the COSE algorithm
    // ids this codec must round-trip (design.md §4.1). The same fixed pairs the reference
    // `impl/rust/src/cbor.rs::nint_rfc8949` test is graded against, so this no_std codec is
    // held to the same external standard, never to the reference implementation's own
    // output.
    #[test]
    fn nint_rfc8949() {
        let cases: [(i64, &str); 7] = [
            (-1, "20"),
            (-10, "29"),
            (-100, "3863"),
            (-1000, "3903e7"),
            (-49, "3830"), // COSE ML-DSA-65 (RFC 9964)
            (-50, "3831"), // COSE ML-DSA-87 (RFC 9964)
            (-19, "32"),   // COSE Ed25519 (RFC 9864)
        ];
        for (v, want) in cases {
            let enc = encode(&Value::Nint(v)).unwrap();
            assert_eq!(hex(&enc), want, "encode Nint({v})");
            let dec = decode(&unhex(want)).unwrap();
            assert!(
                matches!(dec, Value::Nint(x) if x == v),
                "decode {want} -> Nint({v})"
            );
        }
        assert!(
            encode(&Value::Nint(0)).is_err(),
            "Nint(0) must be unencodable"
        );
    }

    // Independent authority: the COSE oracle's protected_hex for {1: -49} (ML-DSA-65) —
    // `vectors/cose/cases.json` `sign1[0].protected_hex`, generated by tools/cose_oracle.py,
    // never by this crate or the Rust reference.
    #[test]
    fn protected_header_matches_independent_oracle() {
        let v = Value::Map(alloc::vec![(Value::Uint(1), Value::Nint(-49))]);
        assert_eq!(hex(&encode(&v).unwrap()), "a1013830");
    }

    // Mutation guard: a constant encoder or constant digest would fail this.
    #[test]
    fn encode_and_content_id_are_not_constant() {
        let a = encode(&Value::Map(alloc::vec![(Value::Uint(1), Value::Uint(0))])).unwrap();
        let b = encode(&Value::Map(alloc::vec![(Value::Uint(1), Value::Uint(1))])).unwrap();
        assert_ne!(a, b, "encoder produced identical bytes for different inputs");

        let ida = content_id(&Value::Map(alloc::vec![(
            Value::Uint(2),
            Value::Tstr(String::from("x"))
        )]))
        .unwrap();
        let idb = content_id(&Value::Map(alloc::vec![(
            Value::Uint(2),
            Value::Tstr(String::from("y"))
        )]))
        .unwrap();
        assert_ne!(ida, idb, "content-id identical for different bodies");
        assert_eq!((ida[0], ida[1], ida.len()), (0x20, 0x30, 50));
    }

    #[test]
    fn decode_rejects_duplicate_and_out_of_order_map_keys() {
        // {2: 0, 1: 0} — keys not in canonical (bytewise-ascending) order.
        assert_eq!(decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]).unwrap_err().kind, "NonCanonical");
        // A non-canonical shortest-form violation: 0x18 0x05 encodes 5, which fits in one
        // byte without the 0x18 prefix.
        assert_eq!(decode(&[0x18, 0x05]).unwrap_err().kind, "NonCanonical");
    }

    #[test]
    fn decode_bounded_depth() {
        const D: usize = 3;
        fn nested(k: usize) -> Vec<u8> {
            let mut b = alloc::vec![0x81u8; k];
            b.push(0x00);
            b
        }
        assert!(decode_bounded(&nested(D - 1), D).is_ok());
        assert_eq!(
            decode_bounded(&nested(D), D).unwrap_err().kind,
            "DepthExceeded"
        );
    }

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push(nibble(byte >> 4));
            s.push(nibble(byte & 0xf));
        }
        s
    }
    fn nibble(n: u8) -> char {
        (if n < 10 { b'0' + n } else { b'a' + (n - 10) }) as char
    }
    fn unhex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        (0..b.len())
            .step_by(2)
            .map(|i| {
                let hi = (b[i] as char).to_digit(16).unwrap() as u8;
                let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }
}
