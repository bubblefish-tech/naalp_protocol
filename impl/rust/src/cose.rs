// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP C2 signing layer: COSE_Sign1 (RFC 9052) over the deterministic-CBOR object
//! body, crypto-agility by the COSE `alg` header, the three-profile table with a
//! Sovereign level-5 floor, and the optional Ed25519+ML-DSA hybrid (COSE_Sign, accepted
//! only if both legs verify). Rust half of the two-implementation parity proof: signing
//! uses the FIPS 204 deterministic path (rnd=0) so it reproduces impl/go byte-for-byte.

use crate::cbor::{self, Value};
use fips204::traits::{Signer as _, Verifier as _};

// COSE algorithm ids (design.md §4.1; ML-DSA from RFC 9964, Ed25519 from RFC 9864).
pub const ALG_MLDSA65: i64 = -49;
pub const ALG_MLDSA87: i64 = -50;
pub const ALG_ED25519: i64 = -19;

// COSE CBOR tags (RFC 9052).
pub const TAG_SIGN1: u64 = 18;
pub const TAG_SIGN: u64 = 98;

// Crypto profiles (design.md §4.4).
pub const PROFILE_PUBLIC: u32 = 1;
pub const PROFILE_ENTERPRISE: u32 = 2;
pub const PROFILE_SOVEREIGN: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: &'static str,
    pub msg: &'static str,
}

macro_rules! err {
    ($k:expr, $m:expr) => {
        Error { kind: $k, msg: $m }
    };
}

fn e_unknown_alg() -> Error { err!("UnknownAlg", "algorithm id not in the N-AALP registry") }
fn e_downgrade() -> Error { err!("ProfileDowngrade", "signature level below the profile minimum") }
fn e_hybrid() -> Error { err!("HybridIncomplete", "hybrid requires both signatures to verify") }
fn e_badsig() -> Error { err!("BadSignature", "signature verification failed") }
fn e_keyalg() -> Error { err!("KeyAlgMismatch", "key algorithm does not match object header") }
fn e_malformed() -> Error { err!("Malformed", "malformed COSE object") }

/// NIST security level for a registered algorithm; None if unregistered.
fn alg_level(alg: i64) -> Option<i32> {
    match alg {
        ALG_MLDSA87 => Some(5),
        ALG_MLDSA65 => Some(3),
        ALG_ED25519 => Some(0), // classical, hybrid leg only
        _ => None,
    }
}

/// Minimum signature level a profile accepts (design.md §4.4): Sovereign refuses below
/// level 5; Public/Enterprise require a post-quantum level-3 signature.
fn profile_min_level(profile: u32) -> i32 {
    if profile == PROFILE_SOVEREIGN {
        5
    } else {
        3
    }
}

fn protected_header(alg: i64) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![(Value::Uint(1), Value::Nint(alg))])).expect("encode header")
}

/// COSE_Sign1 signing input over an already-serialized protected header (RFC 9052 §4.4).
/// The single signing construction (R-2.1); to_be_signed and the C3 envelope build on it.
pub fn to_be_signed_raw(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let ss = Value::Arr(vec![
        Value::Tstr("Signature1".into()),
        Value::Bstr(protected.to_vec()),
        Value::Bstr(vec![]),
        Value::Bstr(payload.to_vec()),
    ]);
    cbor::encode(&ss).expect("encode Sig_structure")
}

/// COSE_Sign1 signing input for a bare {1: alg} protected header.
pub fn to_be_signed(alg: i64, payload: &[u8]) -> Vec<u8> {
    to_be_signed_raw(&protected_header(alg), payload)
}

/// NIST security level for a registered algorithm (exported for the C3 envelope).
pub fn alg_level_of(alg: i64) -> Option<i32> {
    alg_level(alg)
}

/// Minimum signature level a profile accepts (exported for the C3 envelope).
pub fn profile_min_level_of(profile: u32) -> i32 {
    profile_min_level(profile)
}

/// Error constructors reused by the C3 envelope so error Kinds stay uniform.
pub fn err_unknown_alg() -> Error { e_unknown_alg() }
pub fn err_downgrade() -> Error { e_downgrade() }
pub fn err_bad_signature() -> Error { e_badsig() }
pub fn err_key_alg_mismatch() -> Error { e_keyalg() }

/// Per-signer COSE_Signature signing input for a COSE_Sign (hybrid, RFC 9052 §4.4).
fn signature_to_be_signed(body_prot: &[u8], signer_alg: i64, payload: &[u8]) -> Vec<u8> {
    let sprot = protected_header(signer_alg);
    let ss = Value::Arr(vec![
        Value::Tstr("Signature".into()),
        Value::Bstr(body_prot.to_vec()),
        Value::Bstr(sprot),
        Value::Bstr(vec![]),
        Value::Bstr(payload.to_vec()),
    ]);
    cbor::encode(&ss).expect("encode Sig_structure")
}

pub trait CoseSigner {
    fn alg(&self) -> i64;
    fn sign(&self, tbs: &[u8]) -> Vec<u8>;
}

pub trait CoseVerifier {
    fn alg(&self) -> i64;
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool;
}

// ML-DSA signers use the FIPS 204 deterministic path: try_sign_with_seed(&[0u8;32], ...)
// substitutes rnd = 0^32, matching CIRCL's SignTo(randomized=false).
pub struct MlDsa65Signer(pub fips204::ml_dsa_65::PrivateKey);
impl CoseSigner for MlDsa65Signer {
    fn alg(&self) -> i64 { ALG_MLDSA65 }
    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        self.0.try_sign_with_seed(&[0u8; 32], tbs, &[]).expect("mldsa65 sign").to_vec()
    }
}

pub struct MlDsa87Signer(pub fips204::ml_dsa_87::PrivateKey);
impl CoseSigner for MlDsa87Signer {
    fn alg(&self) -> i64 { ALG_MLDSA87 }
    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        self.0.try_sign_with_seed(&[0u8; 32], tbs, &[]).expect("mldsa87 sign").to_vec()
    }
}

pub struct MlDsa65Verifier(pub fips204::ml_dsa_65::PublicKey);
impl CoseVerifier for MlDsa65Verifier {
    fn alg(&self) -> i64 { ALG_MLDSA65 }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        let arr: &[u8; fips204::ml_dsa_65::SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.0.verify(msg, arr, &[])
    }
}

pub struct MlDsa87Verifier(pub fips204::ml_dsa_87::PublicKey);
impl CoseVerifier for MlDsa87Verifier {
    fn alg(&self) -> i64 { ALG_MLDSA87 }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        let arr: &[u8; fips204::ml_dsa_87::SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.0.verify(msg, arr, &[])
    }
}

pub struct Ed25519Verifier(pub ed25519_dalek::VerifyingKey);
impl CoseVerifier for Ed25519Verifier {
    fn alg(&self) -> i64 { ALG_ED25519 }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let arr: [u8; 64] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.0.verify(msg, &ed25519_dalek::Signature::from_bytes(&arr)).is_ok()
    }
}

// A fixed-seed RNG yielding the FIPS 204 key-generation seed (ξ), so try_keygen_with_rng
// derives a keypair deterministically from a seed (reproducing NIST ACVP keyGen vectors).
struct SeedRng {
    seed: [u8; 32],
}
impl fips204::RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.copy_from_slice(&self.seed);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), fips204::RngError> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl fips204::CryptoRng for SeedRng {}

/// Derive an ML-DSA-65 keypair from a 32-byte FIPS 204 key-generation seed (ξ).
pub fn mldsa65_keypair_from_seed(
    seed: &[u8; 32],
) -> (fips204::ml_dsa_65::PublicKey, fips204::ml_dsa_65::PrivateKey) {
    fips204::ml_dsa_65::try_keygen_with_rng(&mut SeedRng { seed: *seed }).expect("keygen")
}

/// Derive an ML-DSA-87 keypair from a 32-byte FIPS 204 key-generation seed (ξ).
pub fn mldsa87_keypair_from_seed(
    seed: &[u8; 32],
) -> (fips204::ml_dsa_87::PublicKey, fips204::ml_dsa_87::PrivateKey) {
    fips204::ml_dsa_87::try_keygen_with_rng(&mut SeedRng { seed: *seed }).expect("keygen")
}

/// Tagged COSE_Sign1 over an already-serialized protected header (used by the envelope).
pub fn assemble_sign1_raw(protected: &[u8], payload: &[u8], sig: &[u8]) -> Vec<u8> {
    let obj = Value::Tag(
        TAG_SIGN1,
        Box::new(Value::Arr(vec![
            Value::Bstr(protected.to_vec()),
            Value::Map(vec![]),
            Value::Bstr(payload.to_vec()),
            Value::Bstr(sig.to_vec()),
        ])),
    );
    cbor::encode(&obj).expect("encode COSE_Sign1")
}

fn assemble_sign1(alg: i64, payload: &[u8], sig: &[u8]) -> Vec<u8> {
    assemble_sign1_raw(&protected_header(alg), payload, sig)
}

/// Produce a tagged COSE_Sign1 object over `payload`.
pub fn sign1(signer: &dyn CoseSigner, payload: &[u8]) -> Vec<u8> {
    let tbs = to_be_signed(signer.alg(), payload);
    let sig = signer.sign(&tbs);
    assemble_sign1(signer.alg(), payload, &sig)
}

fn alg_from_protected(prot: &[u8]) -> Result<i64, Error> {
    let pv = cbor::decode(prot).map_err(|_| e_malformed())?;
    if let Value::Map(m) = pv {
        for (k, v) in &m {
            if matches!(k, Value::Uint(1)) {
                return match v {
                    Value::Nint(a) => Ok(*a),
                    Value::Uint(a) => Ok(*a as i64),
                    _ => Err(e_malformed()),
                };
            }
        }
    }
    Err(e_malformed())
}

/// Decode a tagged COSE_Sign1 into raw (protected, payload, signature) byte strings; the
/// C3 envelope decodes the protected header itself.
pub fn parse_sign1_raw(obj: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let v = cbor::decode(obj).map_err(|_| e_malformed())?;
    let (num, content) = match v {
        Value::Tag(n, c) => (n, *c),
        _ => return Err(e_malformed()),
    };
    if num != TAG_SIGN1 {
        return Err(e_malformed());
    }
    let arr = match content {
        Value::Arr(a) if a.len() == 4 => a,
        _ => return Err(e_malformed()),
    };
    let prot = match &arr[0] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e_malformed()),
    };
    let payload = match &arr[2] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e_malformed()),
    };
    let sig = match &arr[3] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e_malformed()),
    };
    Ok((prot, payload, sig))
}

fn parse_sign1(obj: &[u8]) -> Result<(i64, Vec<u8>, Vec<u8>), Error> {
    let (prot, payload, sig) = parse_sign1_raw(obj)?;
    let alg = alg_from_protected(&prot)?;
    Ok((alg, payload, sig))
}

/// Verify a tagged COSE_Sign1 object under a profile policy. Check order: UnknownAlg ->
/// ProfileDowngrade -> KeyAlgMismatch -> signature.
pub fn verify1(profile: u32, v: &dyn CoseVerifier, obj: &[u8]) -> Result<(), Error> {
    let (alg, payload, sig) = parse_sign1(obj)?;
    let level = alg_level(alg).ok_or_else(e_unknown_alg)?;
    if level < profile_min_level(profile) {
        return Err(e_downgrade());
    }
    if alg != v.alg() {
        return Err(e_keyalg());
    }
    let tbs = to_be_signed(alg, &payload);
    if !v.verify_raw(&tbs, &sig) {
        return Err(e_badsig());
    }
    Ok(())
}

/// Produce a tagged COSE_Sign hybrid object (Ed25519 leg + ML-DSA leg) over `payload`.
pub fn sign_hybrid(
    ed_sk: &ed25519_dalek::SigningKey,
    ml: &dyn CoseSigner,
    payload: &[u8],
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let body_prot: Vec<u8> = vec![]; // empty protected header -> zero-length bstr

    let ed_tbs = signature_to_be_signed(&body_prot, ALG_ED25519, payload);
    let ed_sig = ed_sk.sign(&ed_tbs).to_bytes().to_vec();
    let ed_prot = protected_header(ALG_ED25519);

    let ml_tbs = signature_to_be_signed(&body_prot, ml.alg(), payload);
    let ml_sig = ml.sign(&ml_tbs);
    let ml_prot = protected_header(ml.alg());

    let sigs = Value::Arr(vec![
        Value::Arr(vec![Value::Bstr(ed_prot), Value::Map(vec![]), Value::Bstr(ed_sig)]),
        Value::Arr(vec![Value::Bstr(ml_prot), Value::Map(vec![]), Value::Bstr(ml_sig)]),
    ]);
    let obj = Value::Tag(
        TAG_SIGN,
        Box::new(Value::Arr(vec![
            Value::Bstr(body_prot),
            Value::Map(vec![]),
            Value::Bstr(payload.to_vec()),
            sigs,
        ])),
    );
    cbor::encode(&obj).expect("encode COSE_Sign")
}

/// Verify a tagged COSE_Sign hybrid object: accepted only if BOTH the Ed25519 and ML-DSA
/// legs verify (R-4.4). The ML-DSA leg must meet the profile level floor.
pub fn verify_hybrid(
    profile: u32,
    ed_v: &dyn CoseVerifier,
    ml_v: &dyn CoseVerifier,
    obj: &[u8],
) -> Result<(), Error> {
    let v = cbor::decode(obj).map_err(|_| e_malformed())?;
    let (num, content) = match v {
        Value::Tag(n, c) => (n, *c),
        _ => return Err(e_malformed()),
    };
    if num != TAG_SIGN {
        return Err(e_malformed());
    }
    let arr = match content {
        Value::Arr(a) if a.len() == 4 => a,
        _ => return Err(e_malformed()),
    };
    let body_prot = match &arr[0] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e_malformed()),
    };
    let payload = match &arr[2] {
        Value::Bstr(b) => b.clone(),
        _ => return Err(e_malformed()),
    };
    let sigs = match &arr[3] {
        Value::Arr(a) => a.clone(),
        _ => return Err(e_malformed()),
    };

    let (mut ed_ok, mut ml_ok) = (false, false);
    for sv in &sigs {
        let entry = match sv {
            Value::Arr(a) if a.len() == 3 => a,
            _ => return Err(e_malformed()),
        };
        let sprot = match &entry[0] {
            Value::Bstr(b) => b.clone(),
            _ => return Err(e_malformed()),
        };
        let sig = match &entry[2] {
            Value::Bstr(b) => b.clone(),
            _ => return Err(e_malformed()),
        };
        let alg = alg_from_protected(&sprot)?;
        let tbs = signature_to_be_signed(&body_prot, alg, &payload);
        if alg == ALG_ED25519 {
            if ed_v.verify_raw(&tbs, &sig) {
                ed_ok = true;
            }
        } else if alg == ml_v.alg() {
            let level = alg_level(alg).unwrap_or(0);
            if level < profile_min_level(profile) {
                return Err(e_downgrade());
            }
            if ml_v.verify_raw(&tbs, &sig) {
                ml_ok = true;
            }
        } else {
            return Err(e_unknown_alg());
        }
    }
    if !ed_ok || !ml_ok {
        return Err(e_hybrid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use fips204::traits::SerDes;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/cose/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn mldsa65_key_from_nist(c: &J) -> (fips204::ml_dsa_65::PublicKey, fips204::ml_dsa_65::PrivateKey) {
        super::mldsa65_keypair_from_seed(&keygen_seed(c, "ML-DSA-65"))
    }
    fn mldsa87_key_from_nist(c: &J) -> (fips204::ml_dsa_87::PublicKey, fips204::ml_dsa_87::PrivateKey) {
        super::mldsa87_keypair_from_seed(&keygen_seed(c, "ML-DSA-87"))
    }
    fn keygen_seed(c: &J, param: &str) -> [u8; 32] {
        for kv in c["mldsa_keygen"].as_array().unwrap() {
            if kv["param"] == param {
                let s = hex::decode(kv["seed_hex"].as_str().unwrap()).unwrap();
                let mut a = [0u8; 32];
                a.copy_from_slice(&s);
                return a;
            }
        }
        panic!("no keygen seed for {param}");
    }

    #[test]
    fn tobesigned_matches_oracle() {
        let c = load();
        let cases = c["sign1"].as_array().unwrap();
        assert!(!cases.is_empty());
        for cse in cases {
            let alg = cse["alg"].as_i64().unwrap();
            let payload = hex::decode(cse["payload_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                hex::encode(protected_header(alg)),
                cse["protected_hex"].as_str().unwrap(),
                "protected alg {alg}"
            );
            assert_eq!(
                hex::encode(to_be_signed(alg, &payload)),
                cse["tobesigned_hex"].as_str().unwrap(),
                "tobesigned alg {alg}"
            );
        }
    }

    #[test]
    fn hybrid_tobesigned_matches_oracle() {
        let c = load();
        let h = &c["hybrid"];
        let payload = hex::decode(h["payload_hex"].as_str().unwrap()).unwrap();
        let body: Vec<u8> = vec![];
        assert_eq!(
            hex::encode(signature_to_be_signed(&body, h["ed"]["alg"].as_i64().unwrap(), &payload)),
            h["ed"]["tobesigned_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(signature_to_be_signed(&body, h["ml"]["alg"].as_i64().unwrap(), &payload)),
            h["ml"]["tobesigned_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn mldsa_keygen_matches_nist() {
        let c = load();
        for kv in c["mldsa_keygen"].as_array().unwrap() {
            let param = kv["param"].as_str().unwrap();
            let got = match param {
                "ML-DSA-65" => mldsa65_key_from_nist(&c).0.into_bytes().to_vec(),
                "ML-DSA-87" => mldsa87_key_from_nist(&c).0.into_bytes().to_vec(),
                _ => panic!("unexpected {param}"),
            };
            assert_eq!(hex::encode(got), kv["pk_hex"].as_str().unwrap(), "{param} keygen vs NIST");
        }
    }

    #[test]
    fn ed25519_rfc8032() {
        let c = load();
        let ed = &c["ed25519_rfc8032_test1"];
        let seed: [u8; 32] = hex::decode(ed["sk_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(hex::encode(sk.verifying_key().to_bytes()), ed["pk_hex"].as_str().unwrap());
        let msg = hex::decode(ed["msg_hex"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(sk.sign(&msg).to_bytes()), ed["sig_hex"].as_str().unwrap());
    }

    #[test]
    fn sign1_roundtrip_and_tamper() {
        let c = load();
        let (pk, sk) = mldsa65_key_from_nist(&c);
        let payload = [0xa1u8, 0x07, 0x00];
        let obj = sign1(&MlDsa65Signer(sk), &payload);
        verify1(PROFILE_PUBLIC, &MlDsa65Verifier(pk.clone()), &obj).expect("verify valid");
        let mut tampered = obj.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        match verify1(PROFILE_PUBLIC, &MlDsa65Verifier(pk), &tampered) {
            Err(e) => assert_eq!(e.kind, "BadSignature"),
            Ok(_) => panic!("tampered signature accepted"),
        }
    }

    #[test]
    fn deterministic_signature() {
        let c = load();
        let (_, sk) = mldsa65_key_from_nist(&c);
        let payload = [0xa1u8, 0x07, 0x00];
        let a = sign1(&MlDsa65Signer(sk.clone()), &payload);
        let b = sign1(&MlDsa65Signer(sk), &payload);
        assert_eq!(a, b, "ML-DSA signing must be deterministic");
    }

    #[test]
    fn profile_downgrade() {
        let c = load();
        let (pk, sk) = mldsa65_key_from_nist(&c);
        let obj = sign1(&MlDsa65Signer(sk), &[0xa1, 0x07, 0x00]);
        match verify1(PROFILE_SOVEREIGN, &MlDsa65Verifier(pk), &obj) {
            Err(e) => assert_eq!(e.kind, "ProfileDowngrade"),
            Ok(_) => panic!("sovereign accepted sub-level-5"),
        }
        let (pk87, sk87) = mldsa87_key_from_nist(&c);
        let obj87 = sign1(&MlDsa87Signer(sk87), &[0xa1, 0x07, 0x00]);
        verify1(PROFILE_SOVEREIGN, &MlDsa87Verifier(pk87), &obj87).expect("sovereign accepts ML-DSA-87");
    }

    #[test]
    fn unknown_alg() {
        let c = load();
        let (pk, _) = mldsa65_key_from_nist(&c);
        let obj = assemble_sign1(-99, &[0xa1, 0x07, 0x00], &[0u8; 8]);
        match verify1(PROFILE_PUBLIC, &MlDsa65Verifier(pk), &obj) {
            Err(e) => assert_eq!(e.kind, "UnknownAlg"),
            Ok(_) => panic!("unknown alg accepted"),
        }
    }

    #[test]
    fn hybrid_accept_and_incomplete() {
        let c = load();
        let (pk, sk) = mldsa65_key_from_nist(&c);
        let ed = &c["ed25519_rfc8032_test1"];
        let seed: [u8; 32] = hex::decode(ed["sk_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed_pk = ed_sk.verifying_key();
        let payload = [0xa1u8, 0x07, 0x00];

        let obj = sign_hybrid(&ed_sk, &MlDsa65Signer(sk), &payload);
        verify_hybrid(PROFILE_PUBLIC, &Ed25519Verifier(ed_pk), &MlDsa65Verifier(pk.clone()), &obj)
            .expect("verify hybrid");
        let mut tampered = obj.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        match verify_hybrid(PROFILE_PUBLIC, &Ed25519Verifier(ed_pk), &MlDsa65Verifier(pk), &tampered) {
            Err(e) => assert_eq!(e.kind, "HybridIncomplete"),
            Ok(_) => panic!("tampered hybrid accepted"),
        }
    }
}
