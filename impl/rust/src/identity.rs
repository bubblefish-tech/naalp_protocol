// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP C4 identity and key lifecycle (design.md §5): the self-certifying signer id
//! (PeerHandle form), key rotation (co-signed old+new), revocation, and foreign-identity
//! linkage. The signer id is a pure function of the public key:
//!   signer = multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))
//! Rust half of the two-implementation parity; each impl matches the same independent
//! oracle, so Go == Rust on every signer id.

use crate::cbor::{self, Value};
use crate::cose::{self, CoseSigner, CoseVerifier};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

// multiformats multicodec key-type codes and the sha2-256 multihash code.
const CODE_ED25519: u64 = 0xED;
const CODE_MLDSA65: u64 = 0x1211;
const CODE_MLDSA87: u64 = 0x1212;
const MH_SHA256: u64 = 0x12;

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
fn e_signer_mismatch() -> cose::Error { err("SignerMismatch", "signer id does not equal the recomputed id") }
fn e_rotation_unauth() -> cose::Error { err("RotationUnauthorized", "rotation not co-signed by the old key") }
fn e_nonnfc() -> cose::Error { err("NonNFC", "identity/scope string is not Unicode NFC") }
fn e_unknown_alg() -> cose::Error { err("UnknownAlg", "no multicodec for the algorithm") }

fn multicodec_for(alg: i64) -> Option<u64> {
    match alg {
        cose::ALG_ED25519 => Some(CODE_ED25519),
        cose::ALG_MLDSA65 => Some(CODE_MLDSA65),
        cose::ALG_MLDSA87 => Some(CODE_MLDSA87),
        _ => None,
    }
}

/// Unsigned LEB128 varint (multiformats varint).
fn uvarint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            return out;
        }
    }
}

fn base32_lower_nopad(data: &[u8]) -> String {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567"); // RFC 4648 base32, lowercase
    spec.encoding().expect("base32 spec").encode(data) // padding defaults to none
}

/// Derive the self-certifying signer id for a public key (design.md §5.1).
pub fn signer_id(alg: i64, pubkey: &[u8]) -> Result<String, cose::Error> {
    let mc = multicodec_for(alg).ok_or_else(e_unknown_alg)?;
    let mut tagged = uvarint(mc);
    tagged.extend_from_slice(pubkey);
    let digest = Sha256::digest(&tagged);
    let mut mh = uvarint(MH_SHA256);
    mh.extend_from_slice(&uvarint(digest.len() as u64));
    mh.extend_from_slice(&digest);
    Ok(format!("b{}", base32_lower_nopad(&mh)))
}

/// Recompute the id from the key and reject a mismatch (R-5.1).
pub fn check_signer(claimed: &str, alg: i64, pubkey: &[u8]) -> Result<(), cose::Error> {
    if signer_id(alg, pubkey)? != claimed {
        return Err(e_signer_mismatch());
    }
    Ok(())
}

/// Reject an identity/resource/scope string that is not Unicode NFC (design.md §3.1).
pub fn require_nfc(s: &str) -> Result<(), cose::Error> {
    if s.nfc().collect::<String>() == s {
        Ok(())
    } else {
        Err(e_nonnfc())
    }
}

// ---- key lifecycle -------------------------------------------------------------------

#[derive(Clone)]
pub struct RotationRecord {
    pub old: String,
    pub new: String,
    pub not_before: u64,
}
impl RotationRecord {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.old.clone())),
            (Value::Uint(2), Value::Tstr(self.new.clone())),
            (Value::Uint(3), Value::Uint(self.not_before)),
        ]))
        .expect("encode rotation")
    }
}

/// Co-sign a rotation with BOTH the old and new keys (§5.2).
pub fn sign_rotation(r: &RotationRecord, old: &dyn CoseSigner, new: &dyn CoseSigner) -> (Vec<u8>, Vec<u8>) {
    let m = r.bytes();
    (old.sign(&m), new.sign(&m))
}

/// Verify a rotation is authorized: both keys derive the record's ids and both signatures
/// verify. A substitution not co-signed by the old key is RotationUnauthorized (§5.2).
pub fn verify_rotation(
    r: &RotationRecord,
    old_v: &dyn CoseVerifier,
    new_v: &dyn CoseVerifier,
    old_pub: &[u8],
    new_pub: &[u8],
    old_sig: &[u8],
    new_sig: &[u8],
) -> Result<(), cose::Error> {
    if check_signer(&r.old, old_v.alg(), old_pub).is_err() {
        return Err(e_rotation_unauth());
    }
    if check_signer(&r.new, new_v.alg(), new_pub).is_err() {
        return Err(e_rotation_unauth());
    }
    let m = r.bytes();
    if !old_v.verify_raw(&m, old_sig) || !new_v.verify_raw(&m, new_sig) {
        return Err(e_rotation_unauth());
    }
    Ok(())
}

#[derive(Clone)]
pub struct RevocationRecord {
    pub key: String,
    pub not_after: u64,
}
impl RevocationRecord {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.key.clone())),
            (Value::Uint(2), Value::Uint(self.not_after)),
        ]))
        .expect("encode revocation")
    }
}

pub fn verify_revocation(
    r: &RevocationRecord,
    v: &dyn CoseVerifier,
    pubkey: &[u8],
    sig: &[u8],
) -> Result<(), cose::Error> {
    check_signer(&r.key, v.alg(), pubkey)?;
    if !v.verify_raw(&r.bytes(), sig) {
        return Err(cose::err_bad_signature());
    }
    Ok(())
}

/// An object fixed at authoritative position `pos_time` after not_after is revoked (§5.3).
pub fn revoked_at(r: &RevocationRecord, pos_time: u64) -> bool {
    pos_time > r.not_after
}

#[derive(Clone)]
pub struct ForeignLinkRecord {
    pub controls: String,
    pub foreign_id: String,
    pub not_after: u64,
}
impl ForeignLinkRecord {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.controls.clone())),
            (Value::Uint(2), Value::Tstr(self.foreign_id.clone())),
            (Value::Uint(3), Value::Uint(self.not_after)),
        ]))
        .expect("encode foreign link")
    }
}

/// Whether a foreign-identity link confers linkage at time `now`. A non-NFC foreign_id is
/// rejected (NonNFC). An expired link or a bad cross-signature confers NO linkage but is
/// not an error (it simply does not link, §5.4); it never overrides the key-derived id.
pub fn verify_foreign_link(
    r: &ForeignLinkRecord,
    foreign_v: &dyn CoseVerifier,
    foreign_pub: &[u8],
    sig: &[u8],
    now: u64,
) -> Result<bool, cose::Error> {
    let _ = foreign_pub;
    require_nfc(&r.foreign_id)?;
    if now > r.not_after {
        return Ok(false); // expired: confers no authority
    }
    if !foreign_v.verify_raw(&r.bytes(), sig) {
        return Ok(false); // bad/absent cross-signature: no linkage
    }
    Ok(true)
}

// ---- durable identity thread (R-1.4) -------------------------------------------------

pub struct RotationEvidence {
    pub record: RotationRecord,
    pub old_v: cose::MlDsa65Verifier,
    pub new_v: cose::MlDsa65Verifier,
    pub old_pub: Vec<u8>,
    pub new_pub: Vec<u8>,
    pub old_sig: Vec<u8>,
    pub new_sig: Vec<u8>,
}

pub struct Thread {
    pub root: String,
    pub current: String,
    pub chain: Vec<String>,
}
impl Thread {
    pub fn attributable(&self, signer: &str) -> bool {
        self.chain.iter().any(|id| id == signer)
    }
}

/// Verify an ordered rotation chain and return the durable identity thread (R-1.4).
pub fn resolve_thread(evs: &[RotationEvidence]) -> Result<Thread, cose::Error> {
    if evs.is_empty() {
        return Err(e_rotation_unauth());
    }
    let root = evs[0].record.old.clone();
    let mut chain = vec![root.clone()];
    let mut prev_new = root.clone();
    for e in evs {
        if e.record.old != prev_new {
            return Err(e_rotation_unauth());
        }
        verify_rotation(&e.record, &e.old_v, &e.new_v, &e.old_pub, &e.new_pub, &e.old_sig, &e.new_sig)?;
        chain.push(e.record.new.clone());
        prev_new = e.record.new.clone();
    }
    Ok(Thread { root, current: prev_new, chain })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/identity/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn keypair(seed_byte: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer, Vec<u8>, String) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed_byte; 32]);
        use fips204::traits::SerDes;
        let pk_bytes = pk.clone().into_bytes().to_vec();
        let id = signer_id(cose::ALG_MLDSA65, &pk_bytes).unwrap();
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk), pk_bytes, id)
    }

    #[test]
    fn signer_id_matches_oracle() {
        let c = load();
        let signers = c["signers"].as_array().unwrap();
        assert!(!signers.is_empty());
        for s in signers {
            let alg = s["alg"].as_i64().unwrap();
            let pubkey = hex::decode(s["pubkey_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                signer_id(alg, &pubkey).unwrap(),
                s["signer_id"].as_str().unwrap(),
                "{}",
                s["name"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn signer_mismatch() {
        let c = load();
        let s = &c["signers"][0];
        let alg = s["alg"].as_i64().unwrap();
        let pubkey = hex::decode(s["pubkey_hex"].as_str().unwrap()).unwrap();
        check_signer(s["signer_id"].as_str().unwrap(), alg, &pubkey).expect("correct id");
        match check_signer("bwrongidwrongid", alg, &pubkey) {
            Err(e) => assert_eq!(e.kind, "SignerMismatch"),
            Ok(_) => panic!("mismatch accepted"),
        }
    }

    #[test]
    fn nfc_check() {
        let c = load();
        let nfc = String::from_utf8(hex::decode(c["nfc"]["nfc_utf8_hex"].as_str().unwrap()).unwrap()).unwrap();
        let nfd = String::from_utf8(hex::decode(c["nfc"]["nfd_utf8_hex"].as_str().unwrap()).unwrap()).unwrap();
        require_nfc(&nfc).expect("nfc accepted");
        match require_nfc(&nfd) {
            Err(e) => assert_eq!(e.kind, "NonNFC"),
            Ok(_) => panic!("nfd accepted"),
        }
    }

    #[test]
    fn rotation_vs_substitution() {
        let (v1, s1, p1, id1) = keypair(1);
        let (v2, s2, p2, id2) = keypair(2);
        let rec = RotationRecord { old: id1, new: id2, not_before: 1000 };
        let (osig, nsig) = sign_rotation(&rec, &s1, &s2);
        verify_rotation(&rec, &v1, &v2, &p1, &p2, &osig, &nsig).expect("valid rotation");
        let mut bad = osig.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        match verify_rotation(&rec, &v1, &v2, &p1, &p2, &bad, &nsig) {
            Err(e) => assert_eq!(e.kind, "RotationUnauthorized"),
            Ok(_) => panic!("substitution accepted"),
        }
    }

    #[test]
    fn revocation() {
        let (v, s, p, id) = keypair(7);
        let rec = RevocationRecord { key: id, not_after: 100 };
        let sig = s.sign(&rec.bytes());
        verify_revocation(&rec, &v, &p, &sig).expect("valid revocation");
        assert!(revoked_at(&rec, 101));
        assert!(!revoked_at(&rec, 100) && !revoked_at(&rec, 99));
    }

    #[test]
    fn foreign_link() {
        let c = load();
        let (vf, sf, pf, _) = keypair(9);
        let (_, _, _, controls) = keypair(1);
        let rec = ForeignLinkRecord { controls: controls.clone(), foreign_id: "did:example:abc".into(), not_after: 100 };
        let sig = sf.sign(&rec.bytes());
        assert!(verify_foreign_link(&rec, &vf, &pf, &sig, 50).unwrap());
        assert!(!verify_foreign_link(&rec, &vf, &pf, &sig, 200).unwrap()); // expired -> ignored
        let mut bad = sig.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(!verify_foreign_link(&rec, &vf, &pf, &bad, 50).unwrap()); // bad sig -> ignored
        // Non-NFC foreign_id: use the oracle's known-NFD bytes (a source literal's é could
        // be either normalization form, which would make this test unreliable).
        let nfd_id = String::from_utf8(hex::decode(c["nfc"]["nfd_utf8_hex"].as_str().unwrap()).unwrap()).unwrap();
        let nfd = ForeignLinkRecord { controls, foreign_id: nfd_id, not_after: 100 };
        match verify_foreign_link(&nfd, &vf, &pf, &sig, 50) {
            Err(e) => assert_eq!(e.kind, "NonNFC"),
            Ok(_) => panic!("non-NFC accepted"),
        }
    }

    #[test]
    fn attribution_across_rotation() {
        let (v1, s1, p1, id1) = keypair(1);
        let (v2, s2, p2, id2) = keypair(2);
        let (v3, s3, p3, id3) = keypair(3);
        let rec12 = RotationRecord { old: id1.clone(), new: id2.clone(), not_before: 1000 };
        let (o12, n12) = sign_rotation(&rec12, &s1, &s2);
        let rec23 = RotationRecord { old: id2.clone(), new: id3.clone(), not_before: 2000 };
        let (o23, n23) = sign_rotation(&rec23, &s2, &s3);
        let evs = vec![
            RotationEvidence { record: rec12, old_v: v1, new_v: v2, old_pub: p1, new_pub: p2.clone(), old_sig: o12, new_sig: n12 },
            RotationEvidence { record: rec23, old_v: keypair(2).0, new_v: v3, old_pub: p2, new_pub: p3, old_sig: o23, new_sig: n23 },
        ];
        let th = resolve_thread(&evs).expect("resolve thread");
        assert_eq!(th.root, id1);
        assert_eq!(th.current, id3);
        assert!(th.attributable(&id1)); // pre-rotation id still attributable
        assert!(th.attributable(&id3));
        assert!(!th.attributable("bstranger"));
    }
}
