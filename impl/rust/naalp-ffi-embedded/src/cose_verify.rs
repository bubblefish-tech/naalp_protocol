// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! COSE_Sign1 (RFC 9052 §4.2/§4.4) parse and ML-DSA-65 (RFC 9964) verify-only path for a
//! constrained, `no_std` target — the Manufacturing Add-ons Component A3 embedded tier.
//!
//! Scope, precisely: this module verifies the cryptographic COSE_Sign1 envelope (protected
//! header parse, `Sig_structure` ["Signature1", protected, external_aad, payload]
//! reconstruction per RFC 9052 §4.4, ML-DSA-65 signature check) and exposes the decoded
//! payload bytes and a standalone `content_id` function a caller can use to check payload
//! integrity — mirroring `impl/rust/src/cose.rs::verify1` and
//! `impl/rust/src/cbor.rs::content_id` for the ML-DSA-65 algorithm only. It does NOT
//! replicate the frozen `(channel, kind)` -> effect registry admission check
//! (`naalp::channels::check_effect`) or the Ed25519/composite hybrid legs
//! (`cose::verify_hybrid`/`cose::verify_composite`): those require either the full channel
//! registry table (a data surface, not a crypto primitive, and out of scope for a maximal
//! *verify/parse* subset) or classical-crypto dependencies (`ed25519-dalek`) this pass did
//! not extend to `no_std`. A caller needing registry admission performs it itself using the
//! decoded `(protected, payload)` this module returns — the same caller-side split
//! `naalp-ffi`'s own `naalp_verify` already documents for body-shape interpretation.

extern crate alloc;

use alloc::vec::Vec;

use fips204::ml_dsa_65::{PublicKey, PK_LEN, SIG_LEN};
use fips204::traits::{SerDes as _, Verifier as _};

use crate::cbor_lite::{self, Value};

/// COSE algorithm id for ML-DSA-65 (RFC 9964), matching `naalp::cose::ALG_MLDSA65`.
pub const ALG_MLDSA65: i64 = -49;

/// COSE_Sign1 CBOR tag (RFC 9052).
pub const TAG_SIGN1: u64 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: &'static str,
}

fn e(kind: &'static str) -> Error {
    Error { kind }
}

/// The COSE_Sign1 `{1: alg}` protected header, matching `naalp::cose::protected_header`.
fn protected_header(alg: i64) -> Vec<u8> {
    cbor_lite::encode(&Value::Map(alloc::vec![(Value::Uint(1), Value::Nint(alg))]))
        .expect("encode header")
}

/// COSE_Sign1 signing input over an already-serialized protected header (RFC 9052 §4.4):
/// det-CBOR of `["Signature1", protected, external_aad(empty), payload]`. Byte-identical
/// construction to `naalp::cose::to_be_signed_raw`.
pub fn to_be_signed_raw(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let ss = Value::Arr(alloc::vec![
        Value::Tstr(alloc::string::String::from("Signature1")),
        Value::Bstr(protected.to_vec()),
        Value::Bstr(Vec::new()),
        Value::Bstr(payload.to_vec()),
    ]);
    cbor_lite::encode(&ss).expect("encode Sig_structure")
}

/// COSE_Sign1 signing input for a bare `{1: alg}` protected header.
pub fn to_be_signed(alg: i64, payload: &[u8]) -> Vec<u8> {
    to_be_signed_raw(&protected_header(alg), payload)
}

/// Decode a tagged COSE_Sign1 into raw (protected, payload, signature) byte strings.
/// Mirrors `naalp::cose::parse_sign1_raw`.
pub fn parse_sign1_raw(obj: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let v = cbor_lite::decode(obj).map_err(|_| e("Malformed"))?;
    let (num, content) = match v {
        Value::Tag(n, c) => (n, *c),
        _ => return Err(e("Malformed")),
    };
    if num != TAG_SIGN1 {
        return Err(e("Malformed"));
    }
    let arr = match content {
        Value::Arr(a) if a.len() == 4 => a,
        _ => return Err(e("Malformed")),
    };
    let prot = match &arr[0] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e("Malformed")),
    };
    let payload = match &arr[2] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e("Malformed")),
    };
    let sig = match &arr[3] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e("Malformed")),
    };
    Ok((prot, payload, sig))
}

/// Extract the `alg` (protected-header field 1) value. Mirrors
/// `naalp::cose::alg_from_protected`, including the §3.1.1 (R5) rejection of the redundant
/// `0x41A0` empty-protected-header encoding.
pub fn alg_from_protected(prot: &[u8]) -> Result<i64, Error> {
    if prot.len() == 1 && prot[0] == 0xA0 {
        return Err(e("NonCanonical"));
    }
    let pv = cbor_lite::decode(prot).map_err(|_| e("Malformed"))?;
    if let Value::Map(m) = pv {
        for (k, v) in &m {
            if matches!(k, Value::Uint(1)) {
                return match v {
                    Value::Nint(a) => Ok(*a),
                    Value::Uint(a) => Ok(*a as i64),
                    _ => Err(e("Malformed")),
                };
            }
        }
    }
    Err(e("Malformed"))
}

/// A verified COSE_Sign1 object's raw fields: the serialized protected header and the
/// payload bytes, exactly as `naalp-ffi`'s `naalp_verify` documents (interpretation of the
/// payload shape — opaque `bstr` vs. a further-encoded CBOR value — is the caller's job).
#[derive(Debug)]
pub struct Verified {
    pub protected: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Verify a tagged COSE_Sign1 object as an ML-DSA-65 signature under `pubkey` (1952 raw
/// bytes). Check order matches `naalp::cose::verify1`'s ML-DSA-65 branch: parse -> alg check
/// -> signature. Fail-closed: any check failure rejects the whole object with a named
/// [`Error`] and returns no partial result.
pub fn verify_mldsa65_sign1(pubkey: &[u8], obj: &[u8]) -> Result<Verified, Error> {
    let (prot, payload, sig) = parse_sign1_raw(obj)?;
    let alg = alg_from_protected(&prot)?;
    if alg != ALG_MLDSA65 {
        return Err(e("UnknownAlg"));
    }
    if sig.len() != SIG_LEN {
        return Err(e("BadSignature"));
    }
    let pk_arr: [u8; PK_LEN] = pubkey.try_into().map_err(|_| e("InvalidArgument"))?;
    let pk = PublicKey::try_from_bytes(pk_arr).map_err(|_| e("InvalidArgument"))?;
    let tbs = to_be_signed_raw(&prot, &payload);
    let mut sig_arr = [0u8; SIG_LEN];
    sig_arr.copy_from_slice(&sig);
    if !pk.verify(&tbs, &sig_arr, &[]) {
        return Err(e("BadSignature"));
    }
    Ok(Verified {
        protected: prot,
        payload,
    })
}

/// Object content-id (design.md §2.3), re-exported for a caller that has decoded the
/// payload into a [`Value`] and needs to check it against a claimed id (field 1).
pub fn content_id(body_without_id: &Value) -> Result<Vec<u8>, cbor_lite::Error> {
    cbor_lite::content_id(body_without_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::{InMemoryMlDsa65KeyProvider, KeyProvider as _};

    fn assemble_sign1(protected: &[u8], payload: &[u8], sig: &[u8]) -> Vec<u8> {
        cbor_lite::encode(&Value::Tag(
            TAG_SIGN1,
            alloc::boxed::Box::new(Value::Arr(alloc::vec![
                Value::Bstr(protected.to_vec()),
                Value::Map(alloc::vec![]),
                Value::Bstr(payload.to_vec()),
                Value::Bstr(sig.to_vec()),
            ])),
        ))
        .unwrap()
    }

    // Independent authority: `vectors/cose/cases.json` `sign1[0]` (alg -49), generated by
    // tools/cose_oracle.py — protected_hex and tobesigned_hex are asserted byte-for-byte
    // against this module's own construction, never against the reference implementation's
    // *output* on the same input (F3).
    #[test]
    fn to_be_signed_matches_independent_oracle() {
        let payload = unhex("a10700");
        let protected = protected_header(ALG_MLDSA65);
        assert_eq!(hex(&protected), "a1013830");
        let tbs = to_be_signed_raw(&protected, &payload);
        assert_eq!(hex(&tbs), "846a5369676e61747572653144a10138304043a10700");
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = InMemoryMlDsa65KeyProvider::from_seed(&[0x21u8; 32]);
        let payload = b"hello from naalp-ffi-embedded".to_vec();
        let protected = protected_header(ALG_MLDSA65);
        let tbs = to_be_signed_raw(&protected, &payload);
        let sig = kp.sign(&tbs).expect("sign");
        let obj = assemble_sign1(&protected, &payload, &sig);

        let verified = verify_mldsa65_sign1(&kp.public_key().unwrap(), &obj).expect("verify");
        assert_eq!(verified.payload, payload);
        assert_eq!(verified.protected, protected);
    }

    // MUTATION ANCHOR (fail-closed on tamper): a one-bit flip anywhere in the signed bytes
    // must be rejected. If `verify_mldsa65_sign1` were replaced by an unconditional Ok, this
    // assertion flips pass -> fail. Witnessed in RED-EVIDENCE.md.
    #[test]
    fn verify_rejects_tampered_bytes() {
        let kp = InMemoryMlDsa65KeyProvider::from_seed(&[0x22u8; 32]);
        let payload = b"tamper me".to_vec();
        let protected = protected_header(ALG_MLDSA65);
        let tbs = to_be_signed_raw(&protected, &payload);
        let sig = kp.sign(&tbs).expect("sign");
        let obj = assemble_sign1(&protected, &payload, &sig);
        let pk = kp.public_key().unwrap();

        for i in 0..obj.len() {
            let mut tampered = obj.clone();
            tampered[i] ^= 0x01;
            assert!(
                verify_mldsa65_sign1(&pk, &tampered).is_err(),
                "byte {i} flip must be rejected"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let a = InMemoryMlDsa65KeyProvider::from_seed(&[0x41u8; 32]);
        let b = InMemoryMlDsa65KeyProvider::from_seed(&[0x42u8; 32]);
        let payload = b"signed by a".to_vec();
        let protected = protected_header(ALG_MLDSA65);
        let tbs = to_be_signed_raw(&protected, &payload);
        let sig = a.sign(&tbs).expect("sign");
        let obj = assemble_sign1(&protected, &payload, &sig);

        let err = verify_mldsa65_sign1(&b.public_key().unwrap(), &obj).unwrap_err();
        assert_eq!(err.kind, "BadSignature");
    }

    #[test]
    fn verify_rejects_unregistered_alg() {
        // A COSE_Sign1 whose protected header names Ed25519 (-19), not ML-DSA-65.
        let protected = protected_header(-19);
        let payload = unhex("a10700");
        let obj = assemble_sign1(&protected, &payload, &[0u8; SIG_LEN]);
        let dummy_pk = [0u8; PK_LEN];
        let err = verify_mldsa65_sign1(&dummy_pk, &obj).unwrap_err();
        assert_eq!(err.kind, "UnknownAlg");
    }

    #[test]
    fn content_id_deterministic_and_matches_reference_shape() {
        let a = Value::Map(alloc::vec![(Value::Uint(2), Value::Tstr(alloc::string::String::from("alpha")))]);
        let b = Value::Map(alloc::vec![(Value::Uint(2), Value::Tstr(alloc::string::String::from("beta")))]);
        let id_a1 = content_id(&a).unwrap();
        let id_a2 = content_id(&a).unwrap();
        let id_b = content_id(&b).unwrap();
        assert_eq!(id_a1, id_a2);
        assert_ne!(id_a1, id_b);
        assert_eq!((id_a1[0], id_a1[1], id_a1.len()), (0x20, 0x30, 50));
    }

    fn hex(b: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(b.len() * 2);
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
