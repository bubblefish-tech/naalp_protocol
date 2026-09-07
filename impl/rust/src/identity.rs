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
fn e_signer_mismatch() -> cose::Error {
    err(
        "SignerMismatch",
        "signer id does not equal the recomputed id",
    )
}
fn e_rotation_unauth() -> cose::Error {
    err(
        "RotationUnauthorized",
        "rotation not co-signed by the old key",
    )
}
fn e_nonnfc() -> cose::Error {
    err("NonNFC", "identity/scope string is not Unicode NFC")
}
fn e_unknown_alg() -> cose::Error {
    err("UnknownAlg", "no multicodec for the algorithm")
}

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

/// Derive the self-certifying signer id for a composite key pair (design.md §5.1). The SHA-256
/// preimage is the multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged
/// Ed25519 public key — using only existing official multicodecs — so stripping or substituting
/// either leg changes the id (=> SignerMismatch before verify). `mldsa_alg` selects the ML-DSA
/// multicodec (0x1211 for ML-DSA-65, 0x1212 for ML-DSA-87); the classical leg is always Ed25519.
pub fn composite_signer_id(
    mldsa_alg: i64,
    mldsa_pub: &[u8],
    ed_pub: &[u8],
) -> Result<String, cose::Error> {
    let mc = match mldsa_alg {
        cose::ALG_MLDSA65 => CODE_MLDSA65,
        cose::ALG_MLDSA87 => CODE_MLDSA87,
        _ => return Err(e_unknown_alg()),
    };
    let mut preimage = uvarint(mc);
    preimage.extend_from_slice(mldsa_pub);
    preimage.extend_from_slice(&uvarint(CODE_ED25519));
    preimage.extend_from_slice(ed_pub);
    let digest = Sha256::digest(&preimage);
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
pub fn sign_rotation(
    r: &RotationRecord,
    old: &dyn CoseSigner,
    new: &dyn CoseSigner,
) -> (Vec<u8>, Vec<u8>) {
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

/// Confirm a revocation is validly signed (§5.3): by the key it revokes, or by a
/// deployer-configured recovery key. `recovery_ids` is the deployer's set of authorized
/// recovery-key signer ids; a revocation whose signer is neither `r.key` nor a member of
/// `recovery_ids` is rejected SignerMismatch (§5.5), fail-closed — an empty `recovery_ids`
/// admits only the revoked key itself. The signer id is recomputed from the presented key
/// and checked BEFORE the signature.
pub fn verify_revocation(
    r: &RevocationRecord,
    v: &dyn CoseVerifier,
    pubkey: &[u8],
    sig: &[u8],
    recovery_ids: &[String],
) -> Result<(), cose::Error> {
    let id = signer_id(v.alg(), pubkey)?;
    if id != r.key && !recovery_ids.iter().any(|rid| rid == &id) {
        return Err(e_signer_mismatch());
    }
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
        verify_rotation(
            &e.record, &e.old_v, &e.new_v, &e.old_pub, &e.new_pub, &e.old_sig, &e.new_sig,
        )?;
        chain.push(e.record.new.clone());
        prev_new = e.record.new.clone();
    }
    Ok(Thread {
        root,
        current: prev_new,
        chain,
    })
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
        (
            cose::MlDsa65Verifier(pk),
            cose::MlDsa65Signer(sk),
            pk_bytes,
            id,
        )
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

    // Grade the composite signer-id (derived from BOTH keys) against the independent oracle
    // (design.md §5.1; F3), and confirm leg-stripping changes the id.
    #[test]
    fn composite_signer_id_matches_oracle() {
        let c = load();
        let comp = &c["composite"];
        let mldsa_alg = comp["mldsa_alg"].as_i64().unwrap();
        let mldsa_pub = hex::decode(comp["mldsa_pubkey_hex"].as_str().unwrap()).unwrap();
        let ed_pub = hex::decode(comp["ed_pubkey_hex"].as_str().unwrap()).unwrap();
        let got = composite_signer_id(mldsa_alg, &mldsa_pub, &ed_pub).unwrap();
        assert_eq!(
            got,
            comp["signer_id"].as_str().unwrap(),
            "composite signer id"
        );
        let pure = signer_id(mldsa_alg, &mldsa_pub).unwrap();
        assert_ne!(
            got, pure,
            "composite id must differ from the pure ML-DSA id (leg-stripping)"
        );
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
        let nfc =
            String::from_utf8(hex::decode(c["nfc"]["nfc_utf8_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let nfd =
            String::from_utf8(hex::decode(c["nfc"]["nfd_utf8_hex"].as_str().unwrap()).unwrap())
                .unwrap();
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
        let rec = RotationRecord {
            old: id1,
            new: id2,
            not_before: 1000,
        };
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
        let rec = RevocationRecord {
            key: id,
            not_after: 100,
        };
        let sig = s.sign(&rec.bytes());
        verify_revocation(&rec, &v, &p, &sig, &[]).expect("valid revocation");
        assert!(revoked_at(&rec, 101));
        assert!(!revoked_at(&rec, 100) && !revoked_at(&rec, 99));
    }

    #[test]
    fn foreign_link() {
        let c = load();
        let (vf, sf, pf, _) = keypair(9);
        let (_, _, _, controls) = keypair(1);
        let rec = ForeignLinkRecord {
            controls: controls.clone(),
            foreign_id: "did:example:abc".into(),
            not_after: 100,
        };
        let sig = sf.sign(&rec.bytes());
        assert!(verify_foreign_link(&rec, &vf, &pf, &sig, 50).unwrap());
        assert!(!verify_foreign_link(&rec, &vf, &pf, &sig, 200).unwrap()); // expired -> ignored
        let mut bad = sig.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(!verify_foreign_link(&rec, &vf, &pf, &bad, 50).unwrap()); // bad sig -> ignored
                                                                          // Non-NFC foreign_id: use the oracle's known-NFD bytes (a source literal's é could
                                                                          // be either normalization form, which would make this test unreliable).
        let nfd_id =
            String::from_utf8(hex::decode(c["nfc"]["nfd_utf8_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let nfd = ForeignLinkRecord {
            controls,
            foreign_id: nfd_id,
            not_after: 100,
        };
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
        let rec12 = RotationRecord {
            old: id1.clone(),
            new: id2.clone(),
            not_before: 1000,
        };
        let (o12, n12) = sign_rotation(&rec12, &s1, &s2);
        let rec23 = RotationRecord {
            old: id2.clone(),
            new: id3.clone(),
            not_before: 2000,
        };
        let (o23, n23) = sign_rotation(&rec23, &s2, &s3);
        let evs = vec![
            RotationEvidence {
                record: rec12,
                old_v: v1,
                new_v: v2,
                old_pub: p1,
                new_pub: p2.clone(),
                old_sig: o12,
                new_sig: n12,
            },
            RotationEvidence {
                record: rec23,
                old_v: keypair(2).0,
                new_v: v3,
                old_pub: p2,
                new_pub: p3,
                old_sig: o23,
                new_sig: n23,
            },
        ];
        let th = resolve_thread(&evs).expect("resolve thread");
        assert_eq!(th.root, id1);
        assert_eq!(th.current, id3);
        assert!(th.attributable(&id1)); // pre-rotation id still attributable
        assert!(th.attributable(&id3));
        assert!(!th.attributable("bstranger"));
    }

    // ==== identity_records_oracle.py: the eleven RECORD + THREAD surfaces that previously had NO
    // independent oracle (F3) — RevocationRecord, RevokedAt, VerifyRevocation, ForeignLinkRecord,
    // VerifyForeignLink, RotationEvidence, Thread, Thread.attributable, ResolveThread. See
    // vectors/identity_records/cases.json for the full non-circular derivation notes. ==============

    const RECORDS_VECTOR_PATH: &str = "../../vectors/identity_records/cases.json";

    fn load_records() -> J {
        serde_json::from_str(&std::fs::read_to_string(RECORDS_VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).expect("bad hex")
    }

    // verifier_from builds an MlDsa65Verifier from a raw public-key hex string — never from a
    // seed — matching how a real verifier only ever holds a candidate PUBLIC key.
    fn verifier_from(pub_hex: &str) -> (cose::MlDsa65Verifier, Vec<u8>) {
        let pub_bytes = hx(pub_hex);
        let v = crate::easy::verifier_from_public_key(&pub_bytes).expect("reconstruct verifier");
        (v, pub_bytes)
    }

    // ---- RevocationRecord.bytes (§5.3) ---------------------------------------------------------

    #[test]
    fn revocation_record_bytes_matches_oracle() {
        let c = load_records();
        let cases = c["revocation"]["record_bytes"].as_array().unwrap();
        assert!(!cases.is_empty());
        for tc in cases {
            let r = RevocationRecord {
                key: tc["key"].as_str().unwrap().to_string(),
                not_after: tc["not_after"].as_u64().unwrap(),
            };
            let want = tc["bytes_hex"].as_str().unwrap();
            assert_eq!(hex::encode(r.bytes()), want, "{}", tc["name"]);
        }
    }

    // ---- RevokedAt (§5.3) — set-based scenarios graded via a thin selection loop, since the impl's
    //      revoked_at(record, position) is a pure per-record boolean. MUTATION ANCHOR:
    //      "at_boundary_still_valid" pins `>` vs `>=`. --------------------------------------------

    #[test]
    fn revoked_at_matches_oracle() {
        let c = load_records();
        let scenarios = c["revocation"]["revoked_at"].as_array().unwrap();
        assert!(!scenarios.is_empty());
        for sc in scenarios {
            let query_key = sc["query_key"].as_str().unwrap();
            let query_position = sc["query_position"].as_u64().unwrap();
            let expect_revoked = sc["expect_revoked"].as_bool().unwrap();
            let expect_not_after = sc["expect_not_after"].as_u64();
            let mut revoked = false;
            let mut not_after = 0u64;
            for rv in sc["revocations"].as_array().unwrap() {
                let key = rv["key"].as_str().unwrap();
                if key != query_key {
                    continue;
                }
                let na = rv["not_after"].as_u64().unwrap();
                let rec = RevocationRecord {
                    key: key.to_string(),
                    not_after: na,
                };
                if revoked_at(&rec, query_position) {
                    revoked = true;
                    not_after = na;
                }
            }
            assert_eq!(revoked, expect_revoked, "{}", sc["name"]);
            if expect_revoked {
                assert_eq!(Some(not_after), expect_not_after, "{}", sc["name"]);
            }
        }
    }

    // ---- VerifyRevocation (§5.3, §5.5) ---------------------------------------------------------
    // §5.3 permits a Revocation to be signed by the key it revokes OR by a deployer-configured
    // recovery key. verify_revocation takes the deployer's authorized recovery-id set and accepts a
    // signer iff its recomputed id equals record.key or is a member of that set, then verifies the
    // signature (membership BEFORE signature, fail-closed). MUTATION ANCHORS:
    // "recovery_key_not_configured_reject" (a valid recovery-key signature with an EMPTY authorized
    // set -> SignerMismatch) and "wrong_key_reject" — dropping the membership guard flips both to
    // accept. (Shawn approved option (a), 2026-08-21; the earlier recovery-key deferral is resolved.)

    #[test]
    fn verify_revocation_matches_oracle() {
        let c = load_records();
        let cases = c["revocation"]["verify"].as_array().unwrap();
        assert!(cases.len() >= 7);
        for tc in cases {
            let name = tc["name"].as_str().unwrap();
            let (v, pub_bytes) = verifier_from(tc["candidate_pubkey_hex"].as_str().unwrap());
            let rec = RevocationRecord {
                key: tc["record"]["key"].as_str().unwrap().to_string(),
                not_after: tc["record"]["not_after"].as_u64().unwrap(),
            };
            let sig = hx(tc["sig_hex"].as_str().unwrap());
            let recovery_ids: Vec<String> = tc["authorized_recovery_ids"]
                .as_array()
                .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
                .unwrap_or_default();
            let got = verify_revocation(&rec, &v, &pub_bytes, &sig, &recovery_ids);
            let expect_valid = tc["expect_valid"].as_bool().unwrap();
            let expect_kind = tc["expect_error_kind"].as_str().unwrap_or("");
            match (expect_valid, got) {
                (true, Ok(())) => {}
                (true, Err(e)) => panic!("{}: expected valid, got {:?}", name, e.kind),
                (false, Ok(())) => panic!("{}: expected reject, got accept", name),
                (false, Err(e)) => {
                    if !expect_kind.is_empty() {
                        assert_eq!(e.kind, expect_kind, "{}", name);
                    }
                }
            }
        }
    }

    // ---- ForeignLinkRecord.bytes (§5.4) --------------------------------------------------------
    // MUTATION ANCHOR: collapsing NFC/NFD to the same bytes would flip the not-equal assertion.

    #[test]
    fn foreign_link_record_bytes_matches_oracle() {
        let c = load_records();
        let cases = c["foreign_link"]["record_bytes"].as_array().unwrap();
        assert!(cases.len() >= 2);
        let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for tc in cases {
            let r = ForeignLinkRecord {
                controls: tc["controls"].as_str().unwrap().to_string(),
                foreign_id: tc["foreign_id"].as_str().unwrap().to_string(),
                not_after: tc["not_after"].as_u64().unwrap(),
            };
            let want = tc["bytes_hex"].as_str().unwrap();
            let got = hex::encode(r.bytes());
            assert_eq!(got, want, "{}", tc["name"]);
            seen.insert(tc["name"].as_str().unwrap().to_string(), got);
        }
        assert_ne!(
            seen.get("nfc_form"),
            seen.get("nfd_form_different_bytes"),
            "NFC and NFD foreign_id forms must encode to different bytes"
        );
    }

    // ---- VerifyForeignLink (§5.4, §5.5) --------------------------------------------------------
    // Valid+unexpired, the not_after boundary (MUTATION ANCHOR for `now > NotAfter`), expiry
    // (ignored, no error), wrong-key (ignored, no error — the SAME bucket as expiry per §5.5), and
    // non-NFC foreign_id (NonNFC, checked before expiry/signature).

    #[test]
    fn verify_foreign_link_matches_oracle() {
        let c = load_records();
        let cases = c["foreign_link"]["verify"].as_array().unwrap();
        assert!(!cases.is_empty());
        for tc in cases {
            let name = tc["name"].as_str().unwrap();
            let (v, pub_bytes) = verifier_from(tc["candidate_pubkey_hex"].as_str().unwrap());
            let rec = ForeignLinkRecord {
                controls: tc["record"]["controls"].as_str().unwrap().to_string(),
                foreign_id: tc["record"]["foreign_id"].as_str().unwrap().to_string(),
                not_after: tc["record"]["not_after"].as_u64().unwrap(),
            };
            let sig = hx(tc["sig_hex"].as_str().unwrap());
            let now = tc["now"].as_u64().unwrap();
            let expect_kind = tc["expect_error_kind"].as_str().unwrap_or("");
            let got = verify_foreign_link(&rec, &v, &pub_bytes, &sig, now);
            if !expect_kind.is_empty() {
                match got {
                    Err(e) => assert_eq!(e.kind, expect_kind, "{}", name),
                    Ok(linked) => panic!(
                        "{}: expected error kind {}, got linked={}",
                        name, expect_kind, linked
                    ),
                }
                continue;
            }
            let linked = got.unwrap_or_else(|e| panic!("{}: unexpected error {:?}", name, e.kind));
            let expect_linked = tc["expect_linked"].as_bool().unwrap();
            assert_eq!(linked, expect_linked, "{}", name);
            if expect_linked {
                assert_eq!(
                    rec.controls,
                    tc["expect_controls"].as_str().unwrap(),
                    "{}",
                    name
                );
                assert_eq!(
                    rec.foreign_id,
                    tc["expect_foreign_id"].as_str().unwrap(),
                    "{}",
                    name
                );
            }
        }
    }

    // ---- RotationEvidence / Thread / ResolveThread (§5.2, R-1.4) ------------------------------

    fn build_evidence(evs: &[J]) -> Vec<RotationEvidence> {
        evs.iter()
            .map(|e| {
                let rec = RotationRecord {
                    old: e["old"].as_str().unwrap().to_string(),
                    new: e["new"].as_str().unwrap().to_string(),
                    not_before: e["not_before"].as_u64().unwrap(),
                };
                let want_bytes = e["record_bytes_hex"].as_str().unwrap();
                assert_eq!(
                    hex::encode(rec.bytes()),
                    want_bytes,
                    "RotationRecord.bytes() (RotationEvidence input)"
                );
                let (old_v, old_pub) = verifier_from(e["old_pubkey_hex"].as_str().unwrap());
                let (new_v, new_pub) = verifier_from(e["new_pubkey_hex"].as_str().unwrap());
                RotationEvidence {
                    record: rec,
                    old_v,
                    new_v,
                    old_pub,
                    new_pub,
                    old_sig: hx(e["old_sig_hex"].as_str().unwrap()),
                    new_sig: hx(e["new_sig_hex"].as_str().unwrap()),
                }
            })
            .collect()
    }

    // ResolveThread: empty chain, single link, a 3-link contiguous chain, and TWO distinct
    // broken-chain shapes — "broken_link_old_mismatch" pins the CONTIGUITY guard (`e.old !=
    // prev_new`), and "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE guard
    // (verify_rotation), isolating one guard from the other. MUTATION ANCHORS.

    #[test]
    fn resolve_thread_matches_oracle() {
        let c = load_records();
        let cases = c["thread"]["resolve"].as_array().unwrap();
        assert!(!cases.is_empty());
        for tc in cases {
            let name = tc["name"].as_str().unwrap();
            let evs_json: Vec<J> = tc["evidence"].as_array().unwrap().clone();
            let evs = build_evidence(&evs_json);
            let got = resolve_thread(&evs);
            let expect_error = tc["expect_error"].as_str().unwrap_or("");
            if !expect_error.is_empty() {
                match got {
                    Err(e) => assert_eq!(e.kind, expect_error, "{}", name),
                    Ok(_) => panic!("{}: expected error {}, got accept", name, expect_error),
                }
                continue;
            }
            let th = got.unwrap_or_else(|e| panic!("{}: unexpected error {:?}", name, e.kind));
            let want = &tc["expect_thread"];
            assert_eq!(th.root, want["root"].as_str().unwrap(), "{}", name);
            assert_eq!(th.current, want["current"].as_str().unwrap(), "{}", name);
            let want_chain: Vec<String> = want["chain"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(th.chain, want_chain, "{}", name);
        }
    }

    // Thread.attributable: root/intermediate/current keys are attributable; an unrelated key is
    // not. "unrelated_key_not_attributable" is the MUTATION ANCHOR (an always-true stub flips it).

    #[test]
    fn thread_attributable_matches_oracle() {
        let c = load_records();
        let cases = c["thread"]["attributable"].as_array().unwrap();
        assert!(!cases.is_empty());
        for tc in cases {
            let th_json = &tc["thread"];
            let th = Thread {
                root: th_json["root"].as_str().unwrap().to_string(),
                current: th_json["current"].as_str().unwrap().to_string(),
                chain: th_json["chain"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect(),
            };
            let query = tc["query"].as_str().unwrap();
            let expect = tc["expect"].as_bool().unwrap();
            assert_eq!(th.attributable(query), expect, "{}", tc["name"]);
        }
    }
}
