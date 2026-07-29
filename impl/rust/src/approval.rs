// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C6 — the approval object that binds exact canonical arguments by content id, and the
//! durable, hash-chained, single-use consume ledger (design.md §7; requirements R-7.1..7.4).
//!
//! An Approval binds, under signature, the content id of the exact argument object it
//! approves (§7.1); mutating any argument changes the id and the approval no longer matches
//! (ApprovalMismatch). The consume ledger is a durable compare-and-set set keyed by approval
//! content id: the first consumer wins, a second consume is rejected (AlreadyConsumed) (§7.2).
//! Atomicity comes from a write-ahead log written and fsynced before a consume returns
//! (persist-before-ack) and a single mutex (single-writer discipline), so exactly one
//! concurrent consumer succeeds. A held outcome is a distinct signed non-success result
//! (§7.4). Every rejection is fail-closed and appends nothing.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;

/// Width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.
pub const HEAD_SIZE: usize = 48;

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_approval_mismatch() -> cose::Error {
    err("ApprovalMismatch", "approval does not bind these arguments' content id")
}
pub fn err_approval_expired() -> cose::Error {
    err("ApprovalExpired", "approval is past its not_after")
}
pub fn err_already_consumed() -> cose::Error {
    err("AlreadyConsumed", "approval already consumed")
}
pub fn err_approval_required() -> cose::Error {
    err("ApprovalRequired", "action requires an approval that is not present")
}
pub fn err_ledger_corrupt() -> cose::Error {
    err("LedgerCorrupt", "consume ledger hash chain does not verify")
}

/// Errors from ledger operations: a protocol-level `Cose` error (AlreadyConsumed /
/// LedgerCorrupt) or an underlying `Io` failure of the write-ahead log. IO failures are not
/// dressed up as protocol errors.
#[derive(Debug)]
pub enum LedgerError {
    Io(std::io::Error),
    Cose(cose::Error),
}

impl LedgerError {
    /// The protocol error Kind, if this is a Cose error (for tests/callers matching on Kind).
    pub fn cose_kind(&self) -> Option<&str> {
        match self {
            LedgerError::Cose(c) => Some(c.kind),
            LedgerError::Io(_) => None,
        }
    }
}

/// Content id with the T1 framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || digest.
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + HEAD_SIZE);
    out.push(0x20);
    out.push(0x30);
    out.extend_from_slice(&Sha384::digest(b));
    out
}

/// The body of an Approval object (design.md §7.1), signed with the C2 crypto over its
/// deterministic-CBOR bytes; wrapping it as a Governance-channel (0x0004) object is T12.
pub struct ApprovalRecord {
    pub approves: Vec<u8>, // content id of the exact canonical args object (§7.1)
    pub approver: String,  // approver signer id
    pub grant: u64,        // granted effect class (0..3), the C5 effect
    pub nonce: Vec<u8>,    // anti-replay nonce (§7.3)
    pub not_after: u64,    // expiry, epoch ms (§7.3)
}

impl ApprovalRecord {
    /// Deterministic-CBOR encoding of the approval body {1..5}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.approves.clone())),
            (Value::Uint(2), Value::Tstr(self.approver.clone())),
            (Value::Uint(3), Value::Uint(self.grant)),
            (Value::Uint(4), Value::Bstr(self.nonce.clone())),
            (Value::Uint(5), Value::Uint(self.not_after)),
        ]))
        .expect("encode approval body")
    }

    /// The approval content id (the ledger key): multihash(0x20, SHA-384(body)).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Sign the approval body with the approver's key.
pub fn sign_approval(a: &ApprovalRecord, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    signer.sign(&a.bytes())
}

/// Check that an approval is signed by the approver's key, binds the exact args by content
/// id, and has not expired at `pos_time`. Returns Ok only if all three hold; otherwise the
/// specific named error. Does NOT consume — that is a separate atomic ledger step (§7.2).
pub fn verify_approval(
    a: &ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    sig: &[u8],
    args_content_id: &[u8],
    pos_time: u64,
) -> Result<(), cose::Error> {
    if !approver_v.verify_raw(&a.bytes(), sig) {
        return Err(cose::err_bad_signature());
    }
    if a.approves != args_content_id {
        return Err(err_approval_mismatch());
    }
    if pos_time > a.not_after {
        return Err(err_approval_expired());
    }
    Ok(())
}

/// The distinct, signed, non-success result returned when an action requires an approval that
/// has not been granted (design.md §7.4). Never a silent success or denial.
pub struct HeldResult {
    pub approves: Vec<u8>,
    pub reason: String,
}

impl HeldResult {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.approves.clone())),
            (Value::Uint(2), Value::Tstr(self.reason.clone())),
        ]))
        .expect("encode held result")
    }
}

/// Sign a held result so the "not yet granted" outcome is itself attributable.
pub fn sign_held(h: &HeldResult, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    signer.sign(&h.bytes())
}

/// One append to the consume ledger (design.md §7.2).
#[derive(Clone, Debug)]
pub struct LedgerEntry {
    pub seq: u64,
    pub prev: Vec<u8>,        // prior chain head (HEAD_SIZE bytes; genesis is all-zero)
    pub approval_id: Vec<u8>, // the approval content id being consumed
    pub by: String,           // consumer signer id
}

impl LedgerEntry {
    /// Deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by}. The head after
    /// this entry is SHA-384(bytes()); because bytes() carries prev, editing any entry breaks
    /// the next entry's linkage.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.seq)),
            (Value::Uint(2), Value::Bstr(self.prev.clone())),
            (Value::Uint(3), Value::Bstr(self.approval_id.clone())),
            (Value::Uint(4), Value::Tstr(self.by.clone())),
        ]))
        .expect("encode ledger entry")
    }
}

fn parse_entry(rec: &[u8]) -> Result<LedgerEntry, cose::Error> {
    let v = cbor::decode(rec).map_err(|_| err_ledger_corrupt())?;
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_ledger_corrupt()),
    };
    let (mut seq, mut prev, mut aid, mut by) = (None, None, None, None);
    for (k, val) in m {
        let key = match k {
            Value::Uint(n) => n,
            _ => return Err(err_ledger_corrupt()),
        };
        match (key, val) {
            (1, Value::Uint(u)) => seq = Some(u),
            (2, Value::Bstr(b)) => prev = Some(b),
            (3, Value::Bstr(b)) => aid = Some(b),
            (4, Value::Tstr(s)) => by = Some(s),
            _ => return Err(err_ledger_corrupt()),
        }
    }
    match (seq, prev, aid, by) {
        (Some(seq), Some(prev), Some(approval_id), Some(by)) => {
            Ok(LedgerEntry { seq, prev, approval_id, by })
        }
        _ => Err(err_ledger_corrupt()),
    }
}

fn chain_next(entry_bytes: &[u8]) -> Vec<u8> {
    Sha384::digest(entry_bytes).to_vec()
}

struct LedgerInner {
    f: File,
    consumed: HashMap<Vec<u8>, u64>,
    head: Vec<u8>,
    seq: u64,
}

/// The durable, hash-chained, single-use consume set (design.md §7.2). All state mutation
/// goes through `consume` under a single mutex (single-writer discipline), and each
/// successful consume is written and fsynced to the WAL before it returns.
pub struct Ledger {
    inner: Mutex<LedgerInner>,
}

/// Open (creating if needed) a WAL-backed ledger at `path`, replaying any existing log to
/// rebuild the consumed set and chain head. A log that does not hash-chain cleanly is refused
/// (LedgerCorrupt).
pub fn open_ledger(path: &std::path::Path) -> Result<Ledger, LedgerError> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(LedgerError::Io)?;
    let (consumed, head, seq) = replay(&mut f)?;
    Ok(Ledger { inner: Mutex::new(LedgerInner { f, consumed, head, seq }) })
}

fn replay(f: &mut File) -> Result<(HashMap<Vec<u8>, u64>, Vec<u8>, u64), LedgerError> {
    f.seek(SeekFrom::Start(0)).map_err(LedgerError::Io)?;
    let mut consumed = HashMap::new();
    let mut head = vec![0u8; HEAD_SIZE];
    let mut seq = 0u64;
    loop {
        let mut len_buf = [0u8; 4];
        match f.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(LedgerError::Io(e)),
        }
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut rec = vec![0u8; n];
        f.read_exact(&mut rec).map_err(LedgerError::Io)?;
        let e = parse_entry(&rec).map_err(LedgerError::Cose)?;
        if e.seq != seq || e.prev != head {
            return Err(LedgerError::Cose(err_ledger_corrupt()));
        }
        consumed.insert(e.approval_id.clone(), e.seq);
        head = chain_next(&rec);
        seq += 1;
    }
    Ok((consumed, head, seq))
}

impl Ledger {
    /// Atomically consume an approval id exactly once (design.md §7.2). The first caller for a
    /// given id appends a ledger entry (written and fsynced before returning) and returns it;
    /// every later caller for the same id gets AlreadyConsumed with no append. The mutex
    /// serialises concurrent callers, so under a race exactly one succeeds.
    pub fn consume(&self, approval_id: &[u8], by: &str) -> Result<LedgerEntry, LedgerError> {
        let mut g = self.inner.lock().expect("ledger mutex");
        if g.consumed.contains_key(approval_id) {
            return Err(LedgerError::Cose(err_already_consumed()));
        }
        let e = LedgerEntry {
            seq: g.seq,
            prev: g.head.clone(),
            approval_id: approval_id.to_vec(),
            by: by.to_string(),
        };
        let rec = e.bytes();
        g.f.seek(SeekFrom::End(0)).map_err(LedgerError::Io)?;
        g.f.write_all(&(rec.len() as u32).to_be_bytes()).map_err(LedgerError::Io)?;
        g.f.write_all(&rec).map_err(LedgerError::Io)?;
        g.f.sync_all().map_err(LedgerError::Io)?; // persist-before-ack (R-7.2 durability)
        g.consumed.insert(approval_id.to_vec(), e.seq);
        g.head = chain_next(&rec);
        g.seq += 1;
        Ok(e)
    }

    pub fn is_consumed(&self, approval_id: &[u8]) -> bool {
        self.inner.lock().expect("ledger mutex").consumed.contains_key(approval_id)
    }

    pub fn head(&self) -> Vec<u8> {
        self.inner.lock().expect("ledger mutex").head.clone()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("ledger mutex").consumed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseVerifier; // bring verify_raw into method scope
    use serde_json::Value as J;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    const VECTOR_PATH: &str = "../../vectors/approval/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn tmp_wal(tag: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "naalp_appr_{}_{}_{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn rec_of(c: &J, name: &str) -> ApprovalRecord {
        for a in c["approvals"].as_array().unwrap() {
            if a["name"].as_str().unwrap() == name {
                return ApprovalRecord {
                    approves: hexd(a["approves_hex"].as_str().unwrap()),
                    approver: a["approver"].as_str().unwrap().to_string(),
                    grant: a["grant"].as_u64().unwrap(),
                    nonce: hexd(a["nonce_hex"].as_str().unwrap()),
                    not_after: a["not_after"].as_u64().unwrap(),
                };
            }
        }
        panic!("no approval {}", name);
    }

    fn keypair(seed: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk))
    }

    #[test]
    fn approval_bytes_match_oracle() {
        let c = load();
        let approvals = c["approvals"].as_array().unwrap();
        assert!(!approvals.is_empty());
        for a in approvals {
            let rec = rec_of(&c, a["name"].as_str().unwrap());
            assert_eq!(hex::encode(rec.bytes()), a["record_hex"].as_str().unwrap());
            assert_eq!(hex::encode(rec.id()), a["approval_id_hex"].as_str().unwrap());
        }
    }

    #[test]
    fn ledger_scenario_matches_oracle() {
        let c = load();
        let l = open_ledger(&tmp_wal("scenario")).unwrap();
        assert_eq!(hex::encode(l.head()), c["ledger"]["genesis_head_hex"].as_str().unwrap());
        for cons in c["ledger"]["consumes"].as_array().unwrap() {
            let id = hexd(cons["approval_id_hex"].as_str().unwrap());
            let by = cons["by"].as_str().unwrap();
            match cons["expect"].as_str().unwrap() {
                "ok" => {
                    let e = l.consume(&id, by).expect("consume ok");
                    assert_eq!(e.seq, cons["seq"].as_u64().unwrap());
                    assert_eq!(hex::encode(e.bytes()), cons["entry_hex"].as_str().unwrap());
                    assert_eq!(hex::encode(l.head()), cons["head_after_hex"].as_str().unwrap());
                }
                "AlreadyConsumed" => {
                    let err = l.consume(&id, by).unwrap_err();
                    assert_eq!(err.cose_kind(), Some("AlreadyConsumed"));
                }
                other => panic!("unknown expect {}", other),
            }
        }
        assert_eq!(hex::encode(l.head()), c["ledger"]["final_head_hex"].as_str().unwrap());
    }

    #[test]
    fn durability_across_reopen() {
        let c = load();
        let path = tmp_wal("durable");
        let id_a = hexd(c["approvals"][0]["approval_id_hex"].as_str().unwrap());
        let head_before;
        {
            let l = open_ledger(&path).unwrap();
            l.consume(&id_a, "c1").unwrap();
            head_before = hex::encode(l.head());
        } // drop closes the WAL — simulates process exit after the fsync'd consume
        let l2 = open_ledger(&path).unwrap();
        assert!(l2.is_consumed(&id_a), "consume did not survive reopen");
        assert_eq!(hex::encode(l2.head()), head_before);
        assert_eq!(l2.consume(&id_a, "c2").unwrap_err().cose_kind(), Some("AlreadyConsumed"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn exactly_once_under_threads() {
        let c = load();
        let l = Arc::new(open_ledger(&tmp_wal("race")).unwrap());
        let id_a = Arc::new(hexd(c["approvals"][0]["approval_id_hex"].as_str().unwrap()));
        const NTHREADS: usize = 64;
        let barrier = Arc::new(Barrier::new(NTHREADS));
        let wins = Arc::new(AtomicU64::new(0));
        let already = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..NTHREADS {
            let (l, id, b, w, a) =
                (l.clone(), id_a.clone(), barrier.clone(), wins.clone(), already.clone());
            handles.push(std::thread::spawn(move || {
                b.wait(); // release all threads together to maximise contention
                match l.consume(&id, "consumer") {
                    Ok(_) => {
                        w.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) if e.cose_kind() == Some("AlreadyConsumed") => {
                        a.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("unexpected error: {:?}", e),
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(wins.load(Ordering::SeqCst), 1, "exactly-once violated");
        assert_eq!(already.load(Ordering::SeqCst), (NTHREADS - 1) as u64);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn approval_verify() {
        let c = load();
        let (v, s) = keypair(11);
        let rec = rec_of(&c, "A");
        let args_id = hexd(c["args"]["content_id_hex"].as_str().unwrap());
        let sig = sign_approval(&rec, &s);

        verify_approval(&rec, &v, &sig, &args_id, c["expiry"]["valid_at"].as_u64().unwrap())
            .expect("valid approval");
        // R-7.1: mutated args -> content id no longer matches.
        let wrong = hexd(c["mismatch"]["wrong_args_id_hex"].as_str().unwrap());
        assert_eq!(
            verify_approval(&rec, &v, &sig, &wrong, c["expiry"]["valid_at"].as_u64().unwrap())
                .unwrap_err()
                .kind,
            "ApprovalMismatch"
        );
        // R-7.3: expired after not_after.
        assert_eq!(
            verify_approval(&rec, &v, &sig, &args_id, c["expiry"]["expired_at"].as_u64().unwrap())
                .unwrap_err()
                .kind,
            "ApprovalExpired"
        );
        // tampered signature -> BadSignature.
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            verify_approval(&rec, &v, &bad, &args_id, c["expiry"]["valid_at"].as_u64().unwrap())
                .unwrap_err()
                .kind,
            "BadSignature"
        );
    }

    #[test]
    fn held_result_signed() {
        let c = load();
        let (v, s) = keypair(12);
        let h = HeldResult {
            approves: hexd(c["args"]["content_id_hex"].as_str().unwrap()),
            reason: "awaiting approver".into(),
        };
        let sig = sign_held(&h, &s);
        assert!(v.verify_raw(&h.bytes(), &sig));
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(!v.verify_raw(&h.bytes(), &bad));
    }

    #[test]
    fn ledger_corrupt_detected() {
        let c = load();
        let path = tmp_wal("corrupt");
        let id_a = hexd(c["approvals"][0]["approval_id_hex"].as_str().unwrap());
        let id_b = hexd(c["approvals"][1]["approval_id_hex"].as_str().unwrap());
        let genesis = vec![0u8; HEAD_SIZE];
        let e0 = LedgerEntry { seq: 0, prev: genesis.clone(), approval_id: id_a, by: "c1".into() };
        // e1's prev is left at genesis instead of SHA-384(e0) — a broken link.
        let e1_bad = LedgerEntry { seq: 1, prev: genesis, approval_id: id_b, by: "c1".into() };
        {
            let mut f = File::create(&path).unwrap();
            for rec in [e0.bytes(), e1_bad.bytes()] {
                f.write_all(&(rec.len() as u32).to_be_bytes()).unwrap();
                f.write_all(&rec).unwrap();
            }
        }
        let err = match open_ledger(&path) {
            Err(e) => e,
            Ok(_) => panic!("corrupt (broken-link) ledger opened without error"),
        };
        assert_eq!(err.cose_kind(), Some("LedgerCorrupt"));
        let _ = std::fs::remove_file(&path);
    }
}
