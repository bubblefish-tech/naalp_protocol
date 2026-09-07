// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP C2 signing layer: COSE_Sign1 (RFC 9052) over the deterministic-CBOR object
//! body, crypto-agility by the COSE `alg` header, the three-profile table with a
//! Sovereign level-5 floor, and the optional Ed25519+ML-DSA hybrid (COSE_Sign, accepted
//! only if both legs verify). Rust half of the two-implementation parity proof: signing
//! uses the FIPS 204 deterministic path (rnd=0) so it reproduces impl/go byte-for-byte.

use crate::cbor::{self, Value};
use fips204::traits::{Signer as _, Verifier as _};
use sha2::{Digest as _, Sha512};

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

// Composite COSE algorithm ids (design.md §4.2/§4.4). N-AALP owns these provisional
// private-use identifiers (COSE Algorithms range "integers less than -65536" is Private Use)
// until IANA assigns public composite code points. Only ALG_COMPOSITE_65_ED25519 is
// implemented this wave; ALG_COMPOSITE_44_ED25519 is RESERVED (registered, not graded).
pub const ALG_COMPOSITE_65_ED25519: i64 = -65537; // COMPSIG-MLDSA65-Ed25519-SHA512
pub const ALG_COMPOSITE_44_ED25519: i64 = -65538; // COMPSIG-MLDSA44-Ed25519-SHA512 (edge; RESERVED)

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

fn e_unknown_alg() -> Error {
    err!("UnknownAlg", "algorithm id not in the N-AALP registry")
}
fn e_downgrade() -> Error {
    err!(
        "ProfileDowngrade",
        "signature level below the profile minimum"
    )
}
fn e_hybrid() -> Error {
    err!(
        "HybridIncomplete",
        "hybrid requires both signatures to verify"
    )
}
fn e_badsig() -> Error {
    err!("BadSignature", "signature verification failed")
}
fn e_keyalg() -> Error {
    err!(
        "KeyAlgMismatch",
        "key algorithm does not match object header"
    )
}
fn e_malformed() -> Error {
    err!("Malformed", "malformed COSE object")
}
fn e_composite_refused() -> Error {
    err!(
        "CompositeRefused",
        "sovereign profile refuses a composite object"
    )
}
fn e_suite_mismatch() -> Error {
    err!(
        "SuiteMismatch",
        "signed suite declaration disagrees with the signature alg"
    )
}

/// NIST security level for a registered algorithm; None if unregistered.
fn alg_level(alg: i64) -> Option<i32> {
    match alg {
        ALG_MLDSA87 => Some(5),
        ALG_MLDSA65 => Some(3),
        ALG_COMPOSITE_65_ED25519 => Some(3), // PQ leg is ML-DSA-65 (level 3); Public/Enterprise only
        ALG_ED25519 => Some(0),              // classical, hybrid leg only
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
pub fn err_unknown_alg() -> Error {
    e_unknown_alg()
}
pub fn err_downgrade() -> Error {
    e_downgrade()
}
pub fn err_bad_signature() -> Error {
    e_badsig()
}
pub fn err_key_alg_mismatch() -> Error {
    e_keyalg()
}
pub fn err_composite_refused() -> Error {
    e_composite_refused()
}
pub fn err_suite_mismatch() -> Error {
    e_suite_mismatch()
}

/// Per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4): det-CBOR of
/// ["Signature", body_protected, sign_protected, external_aad(empty), payload].
pub fn signature_to_be_signed(body_prot: &[u8], signer_alg: i64, payload: &[u8]) -> Vec<u8> {
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
    /// The raw public-key bytes of the verifying key, so a caller can bind an out-of-band signer-id
    /// derivation to the SAME key that actually verified — closing the confused-deputy gap where an
    /// id is derived from a public key different from the one the signature was checked against
    /// (design.md §21.4).
    fn pub_key(&self) -> Vec<u8>;
    /// Verify with a typed verdict. Default: BadSignature on failure. CompositeVerifier overrides
    /// this to distinguish HybridIncomplete (a single-leg failure) from Malformed (a structural
    /// one), so the C3 envelope surfaces the composite verdict through a `&dyn CoseVerifier`.
    fn verify_detailed(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if self.verify_raw(msg, sig) {
            Ok(())
        } else {
            Err(e_badsig())
        }
    }
}

// ML-DSA signers use the FIPS 204 deterministic path: try_sign_with_seed(&[0u8;32], ...)
// substitutes rnd = 0^32, matching CIRCL's SignTo(randomized=false).
pub struct MlDsa65Signer(pub fips204::ml_dsa_65::PrivateKey);
impl CoseSigner for MlDsa65Signer {
    fn alg(&self) -> i64 {
        ALG_MLDSA65
    }
    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        self.0
            .try_sign_with_seed(&[0u8; 32], tbs, &[])
            .expect("mldsa65 sign")
            .to_vec()
    }
}

pub struct MlDsa87Signer(pub fips204::ml_dsa_87::PrivateKey);
impl CoseSigner for MlDsa87Signer {
    fn alg(&self) -> i64 {
        ALG_MLDSA87
    }
    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        self.0
            .try_sign_with_seed(&[0u8; 32], tbs, &[])
            .expect("mldsa87 sign")
            .to_vec()
    }
}

pub struct MlDsa65Verifier(pub fips204::ml_dsa_65::PublicKey);
impl CoseVerifier for MlDsa65Verifier {
    fn alg(&self) -> i64 {
        ALG_MLDSA65
    }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        let arr: &[u8; fips204::ml_dsa_65::SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.0.verify(msg, arr, &[])
    }
    fn pub_key(&self) -> Vec<u8> {
        use fips204::traits::SerDes as _;
        self.0.clone().into_bytes().to_vec()
    }
}

pub struct MlDsa87Verifier(pub fips204::ml_dsa_87::PublicKey);
impl CoseVerifier for MlDsa87Verifier {
    fn alg(&self) -> i64 {
        ALG_MLDSA87
    }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        let arr: &[u8; fips204::ml_dsa_87::SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.0.verify(msg, arr, &[])
    }
    fn pub_key(&self) -> Vec<u8> {
        use fips204::traits::SerDes as _;
        self.0.clone().into_bytes().to_vec()
    }
}

pub struct Ed25519Verifier(pub ed25519_dalek::VerifyingKey);
impl CoseVerifier for Ed25519Verifier {
    fn alg(&self) -> i64 {
        ALG_ED25519
    }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let arr: [u8; 64] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.0
            .verify(msg, &ed25519_dalek::Signature::from_bytes(&arr))
            .is_ok()
    }
    fn pub_key(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
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
) -> (
    fips204::ml_dsa_65::PublicKey,
    fips204::ml_dsa_65::PrivateKey,
) {
    fips204::ml_dsa_65::try_keygen_with_rng(&mut SeedRng { seed: *seed }).expect("keygen")
}

/// Derive an ML-DSA-87 keypair from a 32-byte FIPS 204 key-generation seed (ξ).
pub fn mldsa87_keypair_from_seed(
    seed: &[u8; 32],
) -> (
    fips204::ml_dsa_87::PublicKey,
    fips204::ml_dsa_87::PrivateKey,
) {
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

pub fn alg_from_protected(prot: &[u8]) -> Result<i64, Error> {
    // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
    // wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
    // before interpreting the header — the empty protected header is pinned to 0x40.
    if prot.len() == 1 && prot[0] == 0xA0 {
        return Err(err!(
            "NonCanonical",
            "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)"
        ));
    }
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
    // Sovereign refuses a composite object outright (§4.4/§4.5), a distinct verdict from the
    // generic level floor, so the layers agree with the envelope's CompositeRefused.
    if alg == ALG_COMPOSITE_65_ED25519 && profile == PROFILE_SOVEREIGN {
        return Err(e_composite_refused());
    }
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
        Value::Arr(vec![
            Value::Bstr(ed_prot),
            Value::Map(vec![]),
            Value::Bstr(ed_sig),
        ]),
        Value::Arr(vec![
            Value::Bstr(ml_prot),
            Value::Map(vec![]),
            Value::Bstr(ml_sig),
        ]),
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

// --- Opt-in LAMPS composite signature (design.md §4.2) --------------------------------

// The IETF LAMPS composite construction (draft-ietf-lamps-pq-composite-sigs rev-19).
// COMPOSITE_PREFIX is the fixed ASCII domain string; COMPOSITE_LABEL_MLDSA65_ED25519 is the
// suite's LAMPS algorithm label. Both are the ASCII octets of their strings.
const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const COMPOSITE_LABEL_MLDSA65_ED25519: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// The LAMPS composite message representative M' for a suite label and composite context ctx
/// over the COSE ToBeSigned bytes M (design.md §4.2): `M' = Prefix || Label || len(ctx) ||
/// ctx || PH(M)`. len(ctx) is a single length octet; PH is SHA-512. For N-AALP the composite
/// context is EMPTY (callers pass `&[]`), so the octet is 0x00 and ctx adds no bytes. Both
/// legs sign this M'. (ctx is a parameter so the same construction reproduces the LAMPS WG
/// reference vectors, which use a non-empty context.)
pub fn compute_mprime(label: &[u8], ctx: &[u8], m: &[u8]) -> Vec<u8> {
    let h = Sha512::digest(m);
    let mut out =
        Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + ctx.len() + h.len());
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(label);
    out.push(ctx.len() as u8); // len(ctx) as a single length octet
    out.extend_from_slice(ctx);
    out.extend_from_slice(&h);
    out
}

/// Signs one COSE_Sign1 whose signature value is the IETF LAMPS composite of an ML-DSA-65 leg
/// (pure ML-DSA, context = the suite Label octets) and an Ed25519 leg (no context), both over
/// M'; the value is `mldsaSig || tradSig` (ML-DSA first). Rust half of the byte-parity proof:
/// the ML-DSA leg is deterministic (seed = 0^32 => rnd = 0), so it reproduces impl/go.
pub struct CompositeSigner {
    pub ml65: fips204::ml_dsa_65::PrivateKey,
    pub ed: ed25519_dalek::SigningKey,
}
impl CoseSigner for CompositeSigner {
    fn alg(&self) -> i64 {
        ALG_COMPOSITE_65_ED25519
    }
    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mprime = compute_mprime(COMPOSITE_LABEL_MLDSA65_ED25519, &[], tbs);
        let mldsa_sig = self
            .ml65
            .try_sign_with_seed(&[0u8; 32], &mprime, COMPOSITE_LABEL_MLDSA65_ED25519)
            .expect("mldsa65 composite sign");
        let ed_sig = self.ed.sign(&mprime).to_bytes();
        let mut out = Vec::with_capacity(mldsa_sig.len() + ed_sig.len());
        out.extend_from_slice(&mldsa_sig); // ML-DSA first (LAMPS order)
        out.extend_from_slice(&ed_sig);
        out
    }
}

/// Verifies a LAMPS composite signature: valid iff BOTH the ML-DSA-65 and Ed25519 legs
/// validate over M'. Implements Verifier; `verify_raw` reports the both-legs verdict, while
/// the C3 envelope calls [`verify_composite`] to distinguish HybridIncomplete from Malformed.
pub struct CompositeVerifier {
    pub ml65: fips204::ml_dsa_65::PublicKey,
    pub ed: ed25519_dalek::VerifyingKey,
}
impl CompositeVerifier {
    /// Raw component public keys; the composite signer-id is derived from BOTH via
    /// identity::composite_signer_id (design.md §5.1).
    pub fn ml65_pub(&self) -> Vec<u8> {
        use fips204::traits::SerDes as _;
        self.ml65.clone().into_bytes().to_vec()
    }
    pub fn ed_pub(&self) -> Vec<u8> {
        self.ed.to_bytes().to_vec()
    }
}
impl CoseVerifier for CompositeVerifier {
    fn alg(&self) -> i64 {
        ALG_COMPOSITE_65_ED25519
    }
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        verify_composite(self, msg, sig).is_ok()
    }
    fn pub_key(&self) -> Vec<u8> {
        let mut out = self.ml65_pub();
        out.extend_from_slice(&self.ed_pub());
        out
    }
    fn verify_detailed(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        verify_composite(self, msg, sig)
    }
}

/// Validate a LAMPS composite signature value over the COSE ToBeSigned bytes M. Splits the
/// value at the fixed ML-DSA-65 signature size (a value of the wrong length is Malformed),
/// recomputes M', and verifies the ML-DSA leg (context = Label) and the Ed25519 leg (no
/// context). Valid IFF both validate; any single-leg failure is HybridIncomplete. A stripped
/// lone leg has no valid composite because M' binds both components (RFC 9955 Strong
/// Non-Separability; §4.2/§4.5).
pub fn verify_composite(v: &CompositeVerifier, m: &[u8], sig: &[u8]) -> Result<(), Error> {
    const ML: usize = fips204::ml_dsa_65::SIG_LEN;
    const ED: usize = 64;
    if sig.len() != ML + ED {
        return Err(e_malformed());
    }
    let mprime = compute_mprime(COMPOSITE_LABEL_MLDSA65_ED25519, &[], m);
    let (ml_bytes, ed_bytes) = sig.split_at(ML);
    let ml_arr: &[u8; ML] = match ml_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(e_malformed()),
    };
    let mldsa_ok = v
        .ml65
        .verify(&mprime, ml_arr, COMPOSITE_LABEL_MLDSA65_ED25519);
    let ed_arr: [u8; ED] = match ed_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return Err(e_malformed()),
    };
    let ed_ok = {
        use ed25519_dalek::Verifier;
        v.ed.verify(&mprime, &ed25519_dalek::Signature::from_bytes(&ed_arr))
            .is_ok()
    };
    if !mldsa_ok || !ed_ok {
        return Err(e_hybrid());
    }
    Ok(())
}

// --- COSE_Sign (tag 98) multi-signature support (C4 Rotation object, §5.2) -------------

/// One COSE_Signature of a COSE_Sign object: its serialized protected header ({1: alg}) and sig.
pub struct CoseSignLeg {
    pub protected: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Build one COSE_Signature leg: sign the per-signer ToBeSigned over the body protected header,
/// returning the leg's {1: alg} protected header and signature value.
pub fn signature_leg(body_prot: &[u8], signer: &dyn CoseSigner, payload: &[u8]) -> CoseSignLeg {
    let sprot = protected_header(signer.alg());
    let tbs = signature_to_be_signed(body_prot, signer.alg(), payload);
    let sig = signer.sign(&tbs);
    CoseSignLeg {
        protected: sprot,
        sig,
    }
}

/// Assemble a tagged COSE_Sign (tag 98) over an already-serialized body protected header, with
/// the given legs in order (each carries an empty unprotected header).
pub fn assemble_sign_raw(body_prot: &[u8], payload: &[u8], legs: &[CoseSignLeg]) -> Vec<u8> {
    let sigs = Value::Arr(
        legs.iter()
            .map(|l| {
                Value::Arr(vec![
                    Value::Bstr(l.protected.clone()),
                    Value::Map(vec![]),
                    Value::Bstr(l.sig.clone()),
                ])
            })
            .collect(),
    );
    let obj = Value::Tag(
        TAG_SIGN,
        Box::new(Value::Arr(vec![
            Value::Bstr(body_prot.to_vec()),
            Value::Map(vec![]),
            Value::Bstr(payload.to_vec()),
            sigs,
        ])),
    );
    cbor::encode(&obj).expect("encode COSE_Sign")
}

/// Decode a tagged COSE_Sign (tag 98) into its body protected header, payload, and ordered legs.
pub fn parse_sign_raw(obj: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<CoseSignLeg>), Error> {
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
    let mut legs = Vec::with_capacity(sigs.len());
    for sv in &sigs {
        let entry = match sv {
            Value::Arr(a) if a.len() == 3 => a,
            _ => return Err(e_malformed()),
        };
        let sp = match &entry[0] {
            Value::Bstr(b) => b.clone(),
            _ => return Err(e_malformed()),
        };
        let sg = match &entry[2] {
            Value::Bstr(b) => b.clone(),
            _ => return Err(e_malformed()),
        };
        legs.push(CoseSignLeg {
            protected: sp,
            sig: sg,
        });
    }
    Ok((body_prot, payload, legs))
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

    fn mldsa65_key_from_nist(
        c: &J,
    ) -> (
        fips204::ml_dsa_65::PublicKey,
        fips204::ml_dsa_65::PrivateKey,
    ) {
        super::mldsa65_keypair_from_seed(&keygen_seed(c, "ML-DSA-65"))
    }
    fn mldsa87_key_from_nist(
        c: &J,
    ) -> (
        fips204::ml_dsa_87::PublicKey,
        fips204::ml_dsa_87::PrivateKey,
    ) {
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
            hex::encode(signature_to_be_signed(
                &body,
                h["ed"]["alg"].as_i64().unwrap(),
                &payload
            )),
            h["ed"]["tobesigned_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(signature_to_be_signed(
                &body,
                h["ml"]["alg"].as_i64().unwrap(),
                &payload
            )),
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
            assert_eq!(
                hex::encode(got),
                kv["pk_hex"].as_str().unwrap(),
                "{param} keygen vs NIST"
            );
        }
    }

    #[test]
    fn ed25519_rfc8032() {
        let c = load();
        let ed = &c["ed25519_rfc8032_test1"];
        let seed: [u8; 32] = hex::decode(ed["sk_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            hex::encode(sk.verifying_key().to_bytes()),
            ed["pk_hex"].as_str().unwrap()
        );
        let msg = hex::decode(ed["msg_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(sk.sign(&msg).to_bytes()),
            ed["sig_hex"].as_str().unwrap()
        );
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
        verify1(PROFILE_SOVEREIGN, &MlDsa87Verifier(pk87), &obj87)
            .expect("sovereign accepts ML-DSA-87");
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
        let seed: [u8; 32] = hex::decode(ed["sk_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed_pk = ed_sk.verifying_key();
        let payload = [0xa1u8, 0x07, 0x00];

        let obj = sign_hybrid(&ed_sk, &MlDsa65Signer(sk), &payload);
        verify_hybrid(
            PROFILE_PUBLIC,
            &Ed25519Verifier(ed_pk),
            &MlDsa65Verifier(pk.clone()),
            &obj,
        )
        .expect("verify hybrid");
        let mut tampered = obj.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        match verify_hybrid(
            PROFILE_PUBLIC,
            &Ed25519Verifier(ed_pk),
            &MlDsa65Verifier(pk),
            &tampered,
        ) {
            Err(e) => assert_eq!(e.kind, "HybridIncomplete"),
            Ok(_) => panic!("tampered hybrid accepted"),
        }
    }

    // Deterministic composite keypair: ML-DSA-65 from the NIST keyGen seed, Ed25519 from the
    // RFC 8032 §7.1 seed.
    fn composite_keys(
        c: &J,
    ) -> (
        fips204::ml_dsa_65::PrivateKey,
        fips204::ml_dsa_65::PublicKey,
        ed25519_dalek::SigningKey,
        ed25519_dalek::VerifyingKey,
    ) {
        let (pk, sk) = mldsa65_key_from_nist(c);
        let seed: [u8; 32] = hex::decode(c["ed25519_rfc8032_test1"]["sk_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed_vk = ed_sk.verifying_key();
        (sk, pk, ed_sk, ed_vk)
    }

    // Grade the composite protected header ({1:-65537}), the COSE ToBeSigned M, and the LAMPS
    // message representative M' against the independent oracle (design.md §4.2; F3).
    #[test]
    fn composite_mprime_matches_oracle() {
        let c = load();
        let comp = &c["composite"];
        assert_eq!(comp["alg"].as_i64().unwrap(), ALG_COMPOSITE_65_ED25519);
        let payload = hex::decode(comp["payload_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(protected_header(ALG_COMPOSITE_65_ED25519)),
            comp["protected_hex"].as_str().unwrap()
        );
        let tbs = to_be_signed(ALG_COMPOSITE_65_ED25519, &payload);
        assert_eq!(hex::encode(&tbs), comp["tobesigned_hex"].as_str().unwrap());
        let label = hex::decode(comp["label_hex"].as_str().unwrap()).unwrap();
        let ctx = hex::decode(comp["ctx_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(compute_mprime(&label, &ctx, &tbs)),
            comp["mprime_hex"].as_str().unwrap()
        );
    }

    // A composite signature verifies iff BOTH legs validate; tampering either leg yields
    // HybridIncomplete; a wrong-length value is Malformed. The deterministic Ed25519 leg
    // verifies against M' recomputed with the oracle label (internal label == oracle label).
    #[test]
    fn composite_roundtrip_and_leg_failures() {
        use ed25519_dalek::Verifier as _;
        let c = load();
        let (sk, pk, ed_sk, ed_vk) = composite_keys(&c);
        let payload = hex::decode(c["composite"]["payload_hex"].as_str().unwrap()).unwrap();
        let tbs = to_be_signed(ALG_COMPOSITE_65_ED25519, &payload);
        let sig = CompositeSigner {
            ml65: sk,
            ed: ed_sk,
        }
        .sign(&tbs);
        assert_eq!(sig.len(), fips204::ml_dsa_65::SIG_LEN + 64);
        let v = CompositeVerifier {
            ml65: pk,
            ed: ed_vk,
        };
        verify_composite(&v, &tbs, &sig).expect("verify valid composite");

        // internal label == oracle label.
        let label = hex::decode(c["composite"]["label_hex"].as_str().unwrap()).unwrap();
        let mprime_oracle = compute_mprime(&label, &[], &tbs);
        let ed_leg: [u8; 64] = sig[fips204::ml_dsa_65::SIG_LEN..].try_into().unwrap();
        ed_vk
            .verify(
                &mprime_oracle,
                &ed25519_dalek::Signature::from_bytes(&ed_leg),
            )
            .expect("Ed25519 leg over M'(oracle label) -> internal label matches oracle");

        // tamper the ML-DSA leg -> HybridIncomplete.
        let mut t_ml = sig.clone();
        t_ml[0] ^= 0x01;
        assert_eq!(
            verify_composite(&v, &tbs, &t_ml).unwrap_err().kind,
            "HybridIncomplete"
        );
        // tamper the Ed25519 leg -> HybridIncomplete.
        let mut t_ed = sig.clone();
        let n = t_ed.len();
        t_ed[n - 1] ^= 0x01;
        assert_eq!(
            verify_composite(&v, &tbs, &t_ed).unwrap_err().kind,
            "HybridIncomplete"
        );
        // wrong length -> Malformed.
        assert_eq!(
            verify_composite(&v, &tbs, &sig[..n - 1]).unwrap_err().kind,
            "Malformed"
        );
    }

    // bar 3 (non-separability): the ML-DSA leg alone, presented as a plain ML-DSA-65 COSE_Sign1
    // over the payload, MUST fail pure verify1 — the leg signed M', not the plain ToBeSigned.
    #[test]
    fn composite_leg_stripped_fails_pure_verify() {
        let c = load();
        let (sk, pk, ed_sk, _) = composite_keys(&c);
        let payload = hex::decode(c["composite"]["payload_hex"].as_str().unwrap()).unwrap();
        let tbs = to_be_signed(ALG_COMPOSITE_65_ED25519, &payload);
        let sig = CompositeSigner {
            ml65: sk,
            ed: ed_sk,
        }
        .sign(&tbs);
        let ml_leg = &sig[..fips204::ml_dsa_65::SIG_LEN];
        let stripped = assemble_sign1(ALG_MLDSA65, &payload, ml_leg);
        match verify1(PROFILE_PUBLIC, &MlDsa65Verifier(pk), &stripped) {
            Err(e) => assert_eq!(e.kind, "BadSignature"),
            Ok(_) => panic!("stripped ML-DSA leg verified as a plain object (separability!)"),
        }
    }

    #[test]
    fn composite_deterministic() {
        let c = load();
        let (sk, _pk, ed_sk, _ed_vk) = composite_keys(&c);
        let payload = hex::decode(c["composite"]["payload_hex"].as_str().unwrap()).unwrap();
        let tbs = to_be_signed(ALG_COMPOSITE_65_ED25519, &payload);
        let a = CompositeSigner {
            ml65: sk.clone(),
            ed: ed_sk.clone(),
        }
        .sign(&tbs);
        let b = CompositeSigner {
            ml65: sk,
            ed: ed_sk,
        }
        .sign(&tbs);
        assert_eq!(a, b, "composite signing must be deterministic");
    }
}
