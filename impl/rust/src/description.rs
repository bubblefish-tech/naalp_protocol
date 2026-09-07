// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C18 — the signed description / directory primitive (design.md §21; R-DESC-1..8). The Rust half of
//! the two-implementation parity; byte-identical to impl/go/description.
//!
//! C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer on N-AALP's own signed object:
//! authority lives in the SIGNED BYTES, never in the connection/host that served them, so the same
//! signed Description re-verifies byte-identically when an unrelated host serves it. Three wire
//! objects: a Description {1: service, 2: operations[]} lists a service's operations (each Operation
//! {1: name, 2: effect, 3: requires_approval} carrying its C5 effect + approval declaration); a
//! Directory {1: directory, 2: version, 3: members[]} is a signed collection of content-ids with
//! FORK detection (two versions from one signer at the same directory+version but differing members
//! are detected at the FIRST-DIFFERING member position, as the audit fork-proof reports position); an
//! Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
//! (A2A Agent Card / ANP Agent Description / AGNTCY Agent Badge) octet-for-octet (carriage, not
//! adoption) as a signed attestation binding the foreign bytes' content-id and an N-AALP effect
//! mapping — the IMPORTER (the wrapping signer, recomputed self-certifyingly from the key) is the
//! sole authorization identity; a foreign identity inside the bytes never becomes one (R-14.6).

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;
use crate::identity;
use crate::policy;

/// Width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
pub const HEAD_SIZE: usize = 48;

/// Foreign description format codes (design.md §21; naalp-description-format registry).
pub const FORMAT_A2A_CARD: u64 = 1; // A2A Agent Card
pub const FORMAT_ANP_DESCRIPTION: u64 = 2; // ANP Agent Description
pub const FORMAT_AGNTCY_BADGE: u64 = 3; // AGNTCY Agent Badge

pub fn err_malformed() -> cose::Error {
    cose::Error {
        kind: "DescMalformed",
        msg: "object is not a well-formed N-AALP description/directory/import body",
    }
}
pub fn err_approval_flag() -> cose::Error {
    cose::Error {
        kind: "MalformedApprovalFlag",
        msg: "requires_approval is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted",
    }
}
pub fn err_fork_proof_invalid() -> cose::Error {
    cose::Error {
        kind: "DirForkProofInvalid",
        msg: "directory fork proof does not prove equivocation (not one signer, not the same directory+version, or identical members)",
    }
}
pub fn err_importer_mismatch() -> cose::Error {
    cose::Error {
        kind: "ImporterMismatch",
        msg: "the attested importer does not match the verifying key's self-certifying signer id — a foreign identity never authorizes",
    }
}
pub fn err_unknown_format() -> cose::Error {
    cose::Error {
        kind: "UnknownDescriptionFormat",
        msg: "import format is outside the closed naalp-description-format set {1,2,3}",
    }
}
pub fn err_verifier_key_mismatch() -> cose::Error {
    cose::Error {
        kind: "VerifierKeyMismatch",
        msg: "the (alg, pubkey) the authority id is derived from is not the key that verified the signature",
    }
}

/// Whether `fmt_code` is a registered foreign-description format (the closed naalp-description-format
/// set {1,2,3}). A code outside the set is rejected fail-closed — the CDDL types field 2 as the closed
/// enum, not an open uint.
fn is_known_format(fmt_code: u64) -> bool {
    fmt_code == FORMAT_A2A_CARD
        || fmt_code == FORMAT_ANP_DESCRIPTION
        || fmt_code == FORMAT_AGNTCY_BADGE
}

/// SHA-384 over a body — a 48-octet digest.
fn head(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

/// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x20u8, 0x30u8];
    v.extend_from_slice(&head(b));
    v
}

// ---- Operation --------------------------------------------------------------------------------

/// One listed operation: a named operation, its C5 effect class, and whether it requires an approval
/// (the uint 1/0 — the spine carries no CBOR boolean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub name: String,
    pub effect: u64,
    pub requires_approval: u64,
}

impl Operation {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.name.clone())),
            (Value::Uint(2), Value::Uint(self.effect)),
            (Value::Uint(3), Value::Uint(self.requires_approval)),
        ])
    }
    /// Deterministic-CBOR encoding of the operation body.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode operation")
    }
    /// Per-operation effect accessor, normalized fail-closed (unknown -> destructive, R-6.2).
    pub fn effect_class(&self) -> u8 {
        policy::normalize_effect(self.effect)
    }
    /// Per-operation approval-declaration accessor: true iff the operation requires an approval.
    pub fn requires_approval_flag(&self) -> bool {
        self.requires_approval == 1
    }
}

fn operation_from_value(v: &Value) -> Result<Operation, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_malformed()),
    };
    let name = tstr_field(m, 1).ok_or_else(err_malformed)?;
    let effect = uint_field(m, 2).ok_or_else(err_malformed)?;
    let req = uint_field(m, 3).ok_or_else(err_malformed)?;
    if req > 1 {
        return Err(err_approval_flag());
    }
    Ok(Operation {
        name,
        effect,
        requires_approval: req,
    })
}

fn operations_from_value(v: &Value) -> Result<Vec<Operation>, cose::Error> {
    let arr = match v {
        Value::Arr(a) => a,
        _ => return Err(err_malformed()),
    };
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        out.push(operation_from_value(e)?);
    }
    Ok(out)
}

fn operations_value(ops: &[Operation]) -> Value {
    Value::Arr(ops.iter().map(|op| op.to_value()).collect())
}

fn find_operation<'a>(ops: &'a [Operation], name: &str) -> Option<&'a Operation> {
    ops.iter().find(|op| op.name == name)
}

// ---- Description ------------------------------------------------------------------------------

/// A signed N-AALP object listing a service's operations; authority is in the signed bytes, so an
/// unrelated host serving the same bytes yields a byte-identical verification (offline-verifiable).
#[derive(Debug, Clone)]
pub struct Description {
    pub service: Vec<u8>,
    pub operations: Vec<Operation>,
}

impl Description {
    /// Deterministic-CBOR {1: service, 2: operations[]}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.service.clone())),
            (Value::Uint(2), operations_value(&self.operations)),
        ]))
        .expect("encode description")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// The named operation and whether it is listed (the per-operation effect+approval accessor).
    pub fn operation(&self, name: &str) -> Option<&Operation> {
        find_operation(&self.operations, name)
    }
}

/// Reconstruct a Description from its body bytes alone (offline-verifiable: the operation table is in
/// the bytes, no live fetch or host state).
pub fn parse_description(b: &[u8]) -> Result<Description, cose::Error> {
    let m = decode_map(b)?;
    let service = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let ops_v = field(&m, 2).ok_or_else(err_malformed)?;
    let operations = operations_from_value(&ops_v)?;
    Ok(Description {
        service,
        operations,
    })
}

/// Produce the tagged COSE_Sign1 object over the Description body.
pub fn sign_description(d: &Description, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &d.bytes())
}

/// Verify the Description's full signature under the profile, then reconstruct the operation table
/// from the signed body bytes. Returns the identical Description regardless of which host served
/// `obj` (R-DESC-1).
pub fn verify_description(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Description, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    parse_description(&payload)
}

// ---- Directory --------------------------------------------------------------------------------

/// A signed collection object whose members are content-ids (the causal-partial-order shape), with a
/// monotonic per-signer version so two versions can be compared for equivocation.
#[derive(Debug, Clone)]
pub struct Directory {
    pub directory: Vec<u8>,
    pub version: u64,
    pub members: Vec<Vec<u8>>,
}

impl Directory {
    /// Deterministic-CBOR {1: directory, 2: version, 3: members[]}.
    pub fn bytes(&self) -> Vec<u8> {
        let arr = Value::Arr(
            self.members
                .iter()
                .map(|m| Value::Bstr(m.clone()))
                .collect(),
        );
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.directory.clone())),
            (Value::Uint(2), Value::Uint(self.version)),
            (Value::Uint(3), arr),
        ]))
        .expect("encode directory")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Reconstruct a Directory from its body bytes alone.
pub fn parse_directory(b: &[u8]) -> Result<Directory, cose::Error> {
    let m = decode_map(b)?;
    let directory = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let version = uint_field(&m, 2).ok_or_else(err_malformed)?;
    let mem_v = field(&m, 3).ok_or_else(err_malformed)?;
    let arr = match mem_v {
        Value::Arr(a) => a,
        _ => return Err(err_malformed()),
    };
    let mut members = Vec::with_capacity(arr.len());
    for e in arr {
        match e {
            Value::Bstr(bs) => members.push(bs.clone()),
            _ => return Err(err_malformed()),
        }
    }
    Ok(Directory {
        directory,
        version,
        members,
    })
}

/// Produce the tagged COSE_Sign1 object over the Directory body.
pub fn sign_directory(d: &Directory, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &d.bytes())
}

/// Verify the Directory's full signature under the profile, then reconstruct it.
pub fn verify_directory(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<Directory, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    parse_directory(&payload)
}

/// The first index at which two member lists differ, and whether they differ at all. A common prefix
/// with one longer list differs at the length of the shorter list. Identical lists return (0, false).
fn first_member_difference(a: &[Vec<u8>], b: &[Vec<u8>]) -> (usize, bool) {
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return (i, true);
        }
    }
    if a.len() != b.len() {
        return (n, true);
    }
    (0, false)
}

/// Compare two directory versions from ONE signer and report whether they equivocate — SAME directory
/// id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING member POSITION (as the
/// §8.5 audit fork-proof reports the position of an equivocation). A different directory id or version
/// is a legitimate distinct object/succession, not a fork; identical members are a benign duplicate.
/// In both non-fork cases it returns (0, false). The "one signer" precondition is established by
/// verifying both objects under the same key (see `DirectoryForkProof::verify`).
pub fn detect_fork(a: &Directory, b: &Directory) -> (usize, bool) {
    if a.directory != b.directory || a.version != b.version {
        return (0, false);
    }
    first_member_difference(&a.members, &b.members)
}

/// Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer at
/// the same (directory, version) listing DIFFERENT members, carried as the accused signer's OWN two
/// signed objects. Mirrors the draft-01 audit ForkProof: a single verifier checking both signed
/// objects proves one signer, so the proof is self-contained.
#[derive(Debug, Clone)]
pub struct DirectoryForkProof {
    pub signer: Vec<u8>,
    pub signed_a: Vec<u8>,
    pub signed_b: Vec<u8>,
}

impl DirectoryForkProof {
    /// Check that this is a genuine directory fork by the signer whose key is `v`, returning the
    /// FIRST-DIFFERING member POSITION. Accepts iff: the signer id is present; BOTH signed objects
    /// verify under `v` (proving one signer); the two directories share one directory id and version;
    /// and their member lists differ. Any failure rejects the whole proof (fail-closed): an unnamed
    /// signer, a different directory/version, or identical members is DirForkProofInvalid; a bad
    /// signature propagates from `verify1` (BadSignature). `v` MUST be the verifier for `self.signer`.
    pub fn verify(&self, profile: u32, v: &dyn cose::CoseVerifier) -> Result<usize, cose::Error> {
        if self.signer.is_empty() {
            return Err(err_fork_proof_invalid());
        }
        let a = verify_directory(&self.signed_a, profile, v)?;
        let b = verify_directory(&self.signed_b, profile, v)?;
        let (pos, fork) = detect_fork(&a, &b);
        if !fork {
            return Err(err_fork_proof_invalid());
        }
        Ok(pos)
    }
}

// ---- Import -----------------------------------------------------------------------------------

/// A foreign description format carried octet-for-octet (carriage, not adoption) as a signed
/// attestation. `importer` is the wrapping signer id (the sole authorization identity); `foreign` is
/// the foreign bytes verbatim; `operations` is the attested N-AALP effect mapping.
#[derive(Debug, Clone)]
pub struct Import {
    pub importer: Vec<u8>,
    pub format: u64,
    pub foreign: Vec<u8>,
    pub operations: Vec<Operation>,
}

impl Import {
    /// Deterministic-CBOR {1: importer, 2: format, 3: foreign, 4: operations[]}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.importer.clone())),
            (Value::Uint(2), Value::Uint(self.format)),
            (Value::Uint(3), Value::Bstr(self.foreign.clone())),
            (Value::Uint(4), operations_value(&self.operations)),
        ]))
        .expect("encode import")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// The Import attestation's own T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// The T1 content-id of the carried foreign bytes — the hash the attestation binds.
    pub fn foreign_id(&self) -> Vec<u8> {
        content_id(&self.foreign)
    }
    /// The named operation from the attested mapping and whether it is listed.
    pub fn operation(&self, name: &str) -> Option<&Operation> {
        find_operation(&self.operations, name)
    }
}

/// Reconstruct an Import from its body bytes alone.
pub fn parse_import(b: &[u8]) -> Result<Import, cose::Error> {
    let m = decode_map(b)?;
    let importer = bstr_field(&m, 1).ok_or_else(err_malformed)?;
    let format = uint_field(&m, 2).ok_or_else(err_malformed)?;
    // The CDDL types field 2 as the closed naalp-description-format enum {1,2,3}; a code outside the
    // set is rejected on decode (fail-closed), never carried as an unknown format.
    if !is_known_format(format) {
        return Err(err_unknown_format());
    }
    let foreign = bstr_field(&m, 3).ok_or_else(err_malformed)?;
    let ops_v = field(&m, 4).ok_or_else(err_malformed)?;
    let operations = operations_from_value(&ops_v)?;
    Ok(Import {
        importer,
        format,
        foreign,
        operations,
    })
}

/// Produce the tagged COSE_Sign1 object over the Import body.
pub fn sign_import(im: &Import, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &im.bytes())
}

/// An Import that has passed signature verification and the confused-deputy check. `authority_id` is
/// the self-certifying signer id RECOMPUTED from the verifying key (the wrapping signer) — never any
/// identity parsed from the foreign bytes.
#[derive(Debug, Clone)]
pub struct ResolvedImport {
    pub authority_id: String,
    pub format: u64,
    pub foreign_id: Vec<u8>,
    pub operations: Vec<Operation>,
}

/// Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively. It
/// (1) verifies the signed object under the profile with real crypto; (2) recomputes the wrapping
/// signer's SELF-CERTIFYING id from the verifying key (alg + pubkey); and (3) requires the
/// attestation's `importer` field to equal that recomputed id (ImporterMismatch otherwise). The
/// returned `authority_id` is that recomputed key id — the wrapping signer — so no field inside the
/// carried foreign bytes, including any foreign identity claim, can become the authorization identity
/// (R-14.6). Any failure returns its named error and authorizes nothing (fail-closed).
pub fn verify_import(
    obj: &[u8],
    profile: u32,
    alg: i64,
    pubkey: &[u8],
    v: &dyn cose::CoseVerifier,
) -> Result<ResolvedImport, cose::Error> {
    // Confused-deputy containment: the authority id is derived from (alg, pubkey), but the signature
    // is checked with v. If those are not the SAME key, a caller could verify with key A yet mint an
    // authority id for key B. Bind them to the verifying key BEFORE any authority is derived: alg MUST
    // equal v.alg() and pubkey MUST equal v.pub_key() (VerifierKeyMismatch otherwise). Fail-closed.
    if alg != v.alg() || pubkey != v.pub_key().as_slice() {
        return Err(err_verifier_key_mismatch());
    }
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let im = parse_import(&payload)?;
    let key_id = identity::signer_id(alg, pubkey)?;
    // The authorization identity is the wrapping key's own id. The declared importer MUST match it: a
    // signer can only ever import AS ITSELF, never as a foreign identity it names.
    if im.importer.as_slice() != key_id.as_bytes() {
        return Err(err_importer_mismatch());
    }
    Ok(ResolvedImport {
        authority_id: key_id,
        format: im.format,
        foreign_id: im.foreign_id(),
        operations: im.operations,
    })
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

fn decode_map(b: &[u8]) -> Result<Vec<(Value, Value)>, cose::Error> {
    match cbor::decode(b).map_err(|_| err_malformed())? {
        Value::Map(m) => Ok(m),
        _ => Err(err_malformed()),
    }
}

fn field(m: &[(Value, Value)], k: u64) -> Option<Value> {
    for (kk, vv) in m {
        if let Value::Uint(n) = kk {
            if *n == k {
                return Some(vv.clone());
            }
        }
    }
    None
}

fn bstr_field(m: &[(Value, Value)], k: u64) -> Option<Vec<u8>> {
    match field(m, k)? {
        Value::Bstr(b) => Some(b),
        _ => None,
    }
}

fn tstr_field(m: &[(Value, Value)], k: u64) -> Option<String> {
    match field(m, k)? {
        Value::Tstr(s) => Some(s),
        _ => None,
    }
}

fn uint_field(m: &[(Value, Value)], k: u64) -> Option<u64> {
    match field(m, k)? {
        Value::Uint(u) => Some(u),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::SerDes;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/description/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn ops_from(arr: &J) -> Vec<Operation> {
        arr.as_array()
            .unwrap()
            .iter()
            .map(|o| Operation {
                name: o["name"].as_str().unwrap().to_string(),
                effect: o["effect"].as_u64().unwrap(),
                requires_approval: o["requires_approval"].as_u64().unwrap(),
            })
            .collect()
    }

    fn desc_from(c: &J) -> Description {
        Description {
            service: hexd(c["description"]["service_hex"].as_str().unwrap()),
            operations: ops_from(&c["description"]["operations"]),
        }
    }

    fn members_from(arr: &J) -> Vec<Vec<u8>> {
        arr.as_array()
            .unwrap()
            .iter()
            .map(|m| hexd(m.as_str().unwrap()))
            .collect()
    }

    fn dir_a_from(c: &J) -> Directory {
        Directory {
            directory: hexd(c["directory"]["directory_hex"].as_str().unwrap()),
            version: c["directory"]["version"].as_u64().unwrap(),
            members: members_from(&c["directory"]["members_a_hex"]),
        }
    }

    fn import_from(c: &J) -> Import {
        Import {
            importer: hexd(c["import"]["importer_hex"].as_str().unwrap()),
            format: c["import"]["format"].as_u64().unwrap(),
            foreign: hexd(c["import"]["foreign_hex"].as_str().unwrap()),
            operations: ops_from(&c["import"]["operations"]),
        }
    }

    /// A real ML-DSA-65 keypair, its raw public-key bytes, and its self-certifying signer id.
    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier, Vec<u8>, String) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        let pkb = pk.clone().into_bytes().to_vec();
        let id = identity::signer_id(cose::ALG_MLDSA65, &pkb).expect("signer id");
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk), pkb, id)
    }

    // Byte-parity: Rust encoding == the same non-circular Python oracle -> therefore Rust == Go on
    // every wire object body, head, id, and each operation.
    #[test]
    fn bodies_match_oracle() {
        let c = load();

        let d = desc_from(&c);
        assert_eq!(
            hex::encode(d.bytes()),
            c["description"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(d.head()),
            c["description"]["head_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(d.id()),
            c["description"]["id_hex"].as_str().unwrap()
        );
        let op_arr = c["description"]["operations"].as_array().unwrap();
        for (i, op) in d.operations.iter().enumerate() {
            assert_eq!(
                hex::encode(op.bytes()),
                op_arr[i]["body_hex"].as_str().unwrap()
            );
        }

        let da = dir_a_from(&c);
        assert_eq!(
            hex::encode(da.bytes()),
            c["directory"]["a"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(da.head()),
            c["directory"]["a"]["head_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(da.id()),
            c["directory"]["a"]["id_hex"].as_str().unwrap()
        );
        let db = Directory {
            directory: da.directory.clone(),
            version: da.version,
            members: members_from(&c["directory"]["fork"]["members_b_hex"]),
        };
        assert_eq!(
            hex::encode(db.bytes()),
            c["directory"]["fork"]["b"]["body_hex"].as_str().unwrap()
        );

        let im = import_from(&c);
        assert_eq!(
            hex::encode(im.bytes()),
            c["import"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(im.head()),
            c["import"]["head_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(im.id()),
            c["import"]["id_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(im.foreign_id()),
            c["import"]["foreign_id_hex"].as_str().unwrap()
        );
    }

    // The per-operation effect + approval-declaration accessors reflect the oracle exactly, over a
    // corpus that exercises both effect extremes and both approval states (no constant accessor passes).
    #[test]
    fn operation_accessors_match_oracle() {
        let c = load();
        let d = desc_from(&c);
        let (mut ro, mut de, mut at, mut af) = (false, false, false, false);
        for o in c["description"]["operations"].as_array().unwrap() {
            let name = o["name"].as_str().unwrap();
            let op = d.operation(name).expect("op present");
            assert_eq!(
                op.effect_class(),
                policy::normalize_effect(o["effect"].as_u64().unwrap())
            );
            assert_eq!(
                op.requires_approval_flag(),
                o["requires_approval"].as_u64().unwrap() == 1
            );
            match op.effect_class() {
                policy::READ_ONLY => ro = true,
                policy::DESTRUCTIVE => de = true,
                _ => {}
            }
            if op.requires_approval_flag() {
                at = true
            } else {
                af = true
            }
        }
        assert!(
            ro && de && at && af,
            "corpus must exercise both effect extremes and both approval states"
        );
        assert!(d.operation("no-such-op").is_none());
    }

    // A requires_approval outside {0,1} is rejected MalformedApprovalFlag (no CBOR boolean).
    #[test]
    fn malformed_approval_flag_rejected() {
        let c = load();
        let bad = Description {
            service: hexd(c["description"]["service_hex"].as_str().unwrap()),
            operations: vec![Operation {
                name: "x".into(),
                effect: 0,
                requires_approval: 2,
            }],
        };
        assert_eq!(
            parse_description(&bad.bytes()).unwrap_err().kind,
            "MalformedApprovalFlag"
        );
        parse_description(&desc_from(&c).bytes()).expect("well-formed parses");
    }

    // Checkpoint property #1: a signed Description re-verifies byte-identically when an unrelated host
    // serves the identical bytes; a foreign key is rejected.
    #[test]
    fn description_offline_reverify_when_reserved() {
        let c = load();
        let d = desc_from(&c);
        let (s, v, _, _) = key(0x11);
        let (_, foreign, _, _) = key(0x22);
        let obj = sign_description(&d, &s);

        let got1 = verify_description(&obj, cose::PROFILE_PUBLIC, &v).expect("host 1");
        let reserved = obj.clone(); // an unrelated host relays the exact bytes
        let got2 = verify_description(&reserved, cose::PROFILE_PUBLIC, &v).expect("host 2");
        assert_eq!(got1.id(), got2.id());
        assert_eq!(got1.bytes(), got2.bytes());
        assert_eq!(got1.id(), d.id());
        for o in &d.operations {
            let ro = got2.operation(&o.name).expect("op reconstructs");
            assert_eq!(ro.effect_class(), o.effect_class());
            assert_eq!(ro.requires_approval_flag(), o.requires_approval_flag());
        }
        assert_eq!(
            verify_description(&obj, cose::PROFILE_PUBLIC, &foreign)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
    }

    // Checkpoint property #2: two conflicting directory versions from one signer are detected as a
    // fork at the first-differing member position; a duplicate / different version / different
    // directory is not a fork.
    #[test]
    fn directory_fork_detected_with_position() {
        let c = load();
        let da = dir_a_from(&c);
        let db = Directory {
            directory: da.directory.clone(),
            version: da.version,
            members: members_from(&c["directory"]["fork"]["members_b_hex"]),
        };
        let (pos, fork) = detect_fork(&da, &db);
        assert!(fork);
        assert_eq!(
            pos as u64,
            c["directory"]["fork"]["first_differing_position"]
                .as_u64()
                .unwrap()
        );

        let short = Directory {
            directory: da.directory.clone(),
            version: da.version,
            members: members_from(&c["directory"]["length_fork"]["members_short_hex"]),
        };
        let (lpos, lfork) = detect_fork(&da, &short);
        assert!(lfork);
        assert_eq!(
            lpos as u64,
            c["directory"]["length_fork"]["first_differing_position"]
                .as_u64()
                .unwrap()
        );

        assert!(!detect_fork(&da, &da).1, "identical members are not a fork");
        let dv8 = Directory {
            directory: da.directory.clone(),
            version: c["directory"]["different_version"]["version"]
                .as_u64()
                .unwrap(),
            members: db.members.clone(),
        };
        assert!(
            !detect_fork(&da, &dv8).1,
            "a different version is not a fork"
        );
        let other = Directory {
            directory: b"dir-other".to_vec(),
            version: da.version,
            members: db.members.clone(),
        };
        assert!(
            !detect_fork(&da, &other).1,
            "a different directory id is not a fork"
        );
    }

    // The signed fork proof carries the accused's OWN two signed directory objects; verify returns
    // the first-differing position iff both verify under one key and they genuinely equivocate.
    #[test]
    fn directory_fork_proof_non_repudiable() {
        let c = load();
        let (s, v, _, id) = key(0x11);
        let (_, foreign, _, _) = key(0x22);
        let da = dir_a_from(&c);
        let db = Directory {
            directory: da.directory.clone(),
            version: da.version,
            members: members_from(&c["directory"]["fork"]["members_b_hex"]),
        };
        let signed_a = sign_directory(&da, &s);
        let signed_b = sign_directory(&db, &s);

        let fp = DirectoryForkProof {
            signer: id.clone().into_bytes(),
            signed_a: signed_a.clone(),
            signed_b: signed_b.clone(),
        };
        let pos = fp
            .verify(cose::PROFILE_PUBLIC, &v)
            .expect("honest fork proof");
        assert_eq!(
            pos as u64,
            c["directory"]["fork"]["first_differing_position"]
                .as_u64()
                .unwrap()
        );

        assert_eq!(
            fp.verify(cose::PROFILE_PUBLIC, &foreign).unwrap_err().kind,
            "BadSignature"
        );

        let unnamed = DirectoryForkProof {
            signer: vec![],
            signed_a: signed_a.clone(),
            signed_b: signed_b.clone(),
        };
        assert_eq!(
            unnamed.verify(cose::PROFILE_PUBLIC, &v).unwrap_err().kind,
            "DirForkProofInvalid"
        );

        let dup = DirectoryForkProof {
            signer: id.clone().into_bytes(),
            signed_a: signed_a.clone(),
            signed_b: signed_a.clone(),
        };
        assert_eq!(
            dup.verify(cose::PROFILE_PUBLIC, &v).unwrap_err().kind,
            "DirForkProofInvalid"
        );

        let dv8 = Directory {
            directory: da.directory.clone(),
            version: c["directory"]["different_version"]["version"]
                .as_u64()
                .unwrap(),
            members: db.members.clone(),
        };
        let signed_v8 = sign_directory(&dv8, &s);
        let succ = DirectoryForkProof {
            signer: id.into_bytes(),
            signed_a,
            signed_b: signed_v8,
        };
        assert_eq!(
            succ.verify(cose::PROFILE_PUBLIC, &v).unwrap_err().kind,
            "DirForkProofInvalid"
        );
    }

    // Checkpoint property #3: an imported foreign card drives an N-AALP effect mapping, and the
    // identity embedded in the foreign bytes never becomes the authorization identity — the wrapping
    // signer, recomputed from the key, is the sole authority.
    #[test]
    fn import_foreign_identity_never_authorizes() {
        let c = load();
        let (honest_s, honest_v, honest_pk, honest_id) = key(0x11);
        let (attacker_s, attacker_v, attacker_pk, attacker_id) = key(0x22);

        let foreign = hexd(c["import"]["foreign_hex"].as_str().unwrap());
        let foreign_identity = c["import"]["foreign_asserted_identity"].as_str().unwrap();
        assert!(
            String::from_utf8_lossy(&foreign).contains(foreign_identity),
            "fixture: foreign identity must be present in the foreign bytes"
        );

        let im = Import {
            importer: honest_id.clone().into_bytes(),
            format: c["import"]["format"].as_u64().unwrap(),
            foreign: foreign.clone(),
            operations: ops_from(&c["import"]["operations"]),
        };
        let obj = sign_import(&im, &honest_s);
        let r = verify_import(
            &obj,
            cose::PROFILE_PUBLIC,
            cose::ALG_MLDSA65,
            &honest_pk,
            &honest_v,
        )
        .expect("honest import");
        assert_eq!(
            r.authority_id, honest_id,
            "authority must be the wrapping signer"
        );
        assert_ne!(
            r.authority_id, foreign_identity,
            "foreign identity leaked into authority"
        );
        assert_eq!(r.foreign_id, im.foreign_id());
        let submit = r
            .operations
            .iter()
            .find(|o| o.name == "submit")
            .expect("submit mapped");
        assert_eq!(submit.effect_class(), policy::IDEMPOTENT_WRITE);
        assert!(submit.requires_approval_flag());

        // Confused-deputy: an attacker writes the victim's id into the body and signs with their OWN
        // key -> ImporterMismatch (a signer can only import as itself).
        let forged = Import {
            importer: honest_id.clone().into_bytes(),
            format: c["import"]["format"].as_u64().unwrap(),
            foreign: foreign.clone(),
            operations: ops_from(&c["import"]["operations"]),
        };
        let forged_obj = sign_import(&forged, &attacker_s);
        assert_eq!(
            verify_import(
                &forged_obj,
                cose::PROFILE_PUBLIC,
                cose::ALG_MLDSA65,
                &attacker_pk,
                &attacker_v
            )
            .unwrap_err()
            .kind,
            "ImporterMismatch"
        );

        // The SAME foreign bytes imported by the attacker AS ITSELF yield a DIFFERENT authority than
        // the honest import — the foreign id never determines authority.
        let selfimp = Import {
            importer: attacker_id.clone().into_bytes(),
            format: c["import"]["format"].as_u64().unwrap(),
            foreign,
            operations: ops_from(&c["import"]["operations"]),
        };
        let self_obj = sign_import(&selfimp, &attacker_s);
        let r2 = verify_import(
            &self_obj,
            cose::PROFILE_PUBLIC,
            cose::ALG_MLDSA65,
            &attacker_pk,
            &attacker_v,
        )
        .expect("attacker-as-self");
        assert_eq!(r2.authority_id, attacker_id);
        assert_ne!(r2.authority_id, honest_id);
    }

    // C18 audit-fix 0d: field 2 (format) is the CLOSED naalp-description-format enum {1,2,3}; a code
    // outside the set (99) is well-formed CBOR but rejected UnknownDescriptionFormat on decode.
    #[test]
    fn unknown_import_format_rejected() {
        let c = load();
        let bad = Import {
            importer: hexd(c["import"]["importer_hex"].as_str().unwrap()),
            format: c["import"]["unknown_format"]["format"].as_u64().unwrap(),
            foreign: hexd(c["import"]["foreign_hex"].as_str().unwrap()),
            operations: ops_from(&c["import"]["operations"]),
        };
        assert_eq!(
            hex::encode(bad.bytes()),
            c["import"]["unknown_format"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            parse_import(&bad.bytes()).unwrap_err().kind,
            "UnknownDescriptionFormat"
        );
        parse_import(&import_from(&c).bytes()).expect("well-formed import parses");
    }

    // C18 audit-fix 0b: verify_import derives the authority id from (alg, pubkey) but checks the
    // signature with v. A caller passing v for key A and pubkey for key B is the confused deputy —
    // the id would be minted for B though A signed. The fix binds (alg, pubkey) to the verifying key
    // (VerifierKeyMismatch otherwise). Mutation: remove the binding and v(A)+pubkey(B) resolves B.
    #[test]
    fn verifier_key_mismatch_rejected() {
        let c = load();
        let (s_a, v_a, pk_a, id_a) = key(0x11);
        let (_s_b, v_b, pk_b, _id_b) = key(0x22);

        let im = Import {
            importer: id_a.clone().into_bytes(),
            format: c["import"]["format"].as_u64().unwrap(),
            foreign: hexd(c["import"]["foreign_hex"].as_str().unwrap()),
            operations: ops_from(&c["import"]["operations"]),
        };
        let obj = sign_import(&im, &s_a);

        // Positive control: v(A) + pubkey(A) resolves authority A.
        let r = verify_import(&obj, cose::PROFILE_PUBLIC, cose::ALG_MLDSA65, &pk_a, &v_a)
            .expect("key-matched import");
        assert_eq!(r.authority_id, id_a);
        // Confused deputy: verify with A, pubkey is B -> VerifierKeyMismatch (before any authority).
        assert_eq!(
            verify_import(&obj, cose::PROFILE_PUBLIC, cose::ALG_MLDSA65, &pk_b, &v_a)
                .unwrap_err()
                .kind,
            "VerifierKeyMismatch"
        );
        // Mismatched alg with v for A -> VerifierKeyMismatch.
        assert_eq!(
            verify_import(&obj, cose::PROFILE_PUBLIC, cose::ALG_MLDSA87, &pk_a, &v_a)
                .unwrap_err()
                .kind,
            "VerifierKeyMismatch"
        );
        // v(B)+pubkey(B) on an A-signed object: the guard passes (key-consistent) but the signature
        // fails -> BadSignature, proving the guard is specifically (alg,pubkey)-vs-v, not blanket.
        assert_eq!(
            verify_import(&obj, cose::PROFILE_PUBLIC, cose::ALG_MLDSA65, &pk_b, &v_b)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
    }

    // Cross-language signature bit-identity: signing the Description with the shared 0x11*32 seed must
    // produce a COSE_Sign1 object whose SHA-384 equals the value the Go description test pins — Go and
    // Rust emit byte-identical signed Descriptions (deterministic ML-DSA-65 over identical canonical
    // CBOR). Mutation: any encoding/signing-input drift makes the digest differ from the pin.
    #[test]
    fn cross_lang_signed_description_pin() {
        const PINNED: &str =
            "c8aa348b49c469c7565a292b1ebe3e92af7763705bba728e8ef1b39379a30a0d213f6640ef997a26aaa0dd1550401a23";
        let c = load();
        let d = desc_from(&c);
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let obj = sign_description(&d, &s);
        let digest = hex::encode(Sha384::digest(&obj));
        assert_eq!(
            digest, PINNED,
            "Rust signed Description digest differs from the Go pin (sig not byte-identical)"
        );
    }
}
