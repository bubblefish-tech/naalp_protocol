// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C8 — delivery as four signed monotonic stages, persist-before-acknowledge, the live
//! full-duplex switchboard, and the content-free relay (design.md §9; R-9.1..9.4).
//!
//! Delivery is four separately-observable stages, each a signed delivery.update naming the
//! object's content id and the stage reached (§9.1): persisted_origin -> accepted_relay ->
//! persisted_target -> presented. A stage advances only after the object is durably persisted
//! (WAL fsync), so a crash right after an acknowledgment loses nothing (§9.2). A stage earlier
//! than the one already reached is StageOutOfOrder (§9.4). The switchboard holds two connections
//! open and relays both directions concurrently (§9.3); a content-free relay writes an audit
//! trail over content ids while retaining no payload (§9.4, R-9.4).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

use sha2::{Digest, Sha384};

use crate::audit;
use crate::cbor::{self, Value};
use crate::cose;

/// Delivery stages (design.md §9.1), monotonic in this order.
pub const STAGE_PERSISTED_ORIGIN: u64 = 0;
pub const STAGE_ACCEPTED_RELAY: u64 = 1;
pub const STAGE_PERSISTED_TARGET: u64 = 2;
pub const STAGE_PRESENTED: u64 = 3;

const STAGE_NAMES: [&str; 4] =
    ["persisted_origin", "accepted_relay", "persisted_target", "presented"];

/// Name of a stage value (0..3), or "unknown".
pub fn stage_name(stage: u64) -> &'static str {
    if (stage as usize) < STAGE_NAMES.len() {
        STAGE_NAMES[stage as usize]
    } else {
        "unknown"
    }
}

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_stage_out_of_order() -> cose::Error {
    err("StageOutOfOrder", "a delivery stage regressed to an earlier stage")
}
fn err_malformed() -> cose::Error {
    err("Malformed", "malformed delivery update")
}

/// Errors from tracker operations: a protocol-level `Cose` error (StageOutOfOrder / Malformed)
/// or an underlying `Io` failure of the write-ahead log.
#[derive(Debug)]
pub enum DeliveryError {
    Io(std::io::Error),
    Cose(cose::Error),
}

impl DeliveryError {
    pub fn cose_kind(&self) -> Option<&str> {
        match self {
            DeliveryError::Cose(c) => Some(c.kind),
            DeliveryError::Io(_) => None,
        }
    }
}

/// Content id with the T1 framing: multihash(0x20, SHA-384(bytes)).
pub fn content_id(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 48);
    out.push(0x20);
    out.push(0x30);
    out.extend_from_slice(&Sha384::digest(b));
    out
}

/// One signed delivery-stage notification (design.md §9.1).
#[derive(Debug)]
pub struct DeliveryUpdate {
    pub obj: Vec<u8>,
    pub stage: u64,
    pub at: u64,
}

impl DeliveryUpdate {
    /// Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.obj.clone())),
            (Value::Uint(2), Value::Uint(self.stage)),
            (Value::Uint(3), Value::Uint(self.at)),
        ]))
        .expect("encode delivery update")
    }
}

/// Sign a delivery.update with the observer's key.
pub fn sign_update(d: &DeliveryUpdate, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    signer.sign(&d.bytes())
}

fn parse_update(rec: &[u8]) -> Result<DeliveryUpdate, cose::Error> {
    let v = cbor::decode(rec).map_err(|_| err_malformed())?;
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_malformed()),
    };
    let (mut obj, mut stage, mut at) = (None, None, None);
    for (k, val) in m {
        let key = match k {
            Value::Uint(n) => n,
            _ => return Err(err_malformed()),
        };
        match (key, val) {
            (1, Value::Bstr(b)) => obj = Some(b),
            (2, Value::Uint(u)) => stage = Some(u),
            (3, Value::Uint(u)) => at = Some(u),
            _ => return Err(err_malformed()),
        }
    }
    match (obj, stage, at) {
        (Some(obj), Some(stage), Some(at)) => Ok(DeliveryUpdate { obj, stage, at }),
        _ => Err(err_malformed()),
    }
}

/// A durable, per-object delivery-stage tracker enforcing monotonic stages and
/// persist-before-acknowledge. Each `advance` persists to the WAL and fsyncs before returning
/// the acknowledging update, so a crash after the ack loses nothing (§9.2).
pub struct Tracker {
    f: File,
    current: HashMap<Vec<u8>, u64>,
}

/// Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable
/// stage for every object.
pub fn open_tracker(path: &std::path::Path) -> Result<Tracker, DeliveryError> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(DeliveryError::Io)?;
    let current = replay(&mut f)?;
    Ok(Tracker { f, current })
}

fn replay(f: &mut File) -> Result<HashMap<Vec<u8>, u64>, DeliveryError> {
    f.seek(SeekFrom::Start(0)).map_err(DeliveryError::Io)?;
    let mut current = HashMap::new();
    loop {
        let mut len_buf = [0u8; 4];
        match f.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(DeliveryError::Io(e)),
        }
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut rec = vec![0u8; n];
        f.read_exact(&mut rec).map_err(DeliveryError::Io)?;
        let u = parse_update(&rec).map_err(DeliveryError::Cose)?;
        current.insert(u.obj, u.stage); // last durable stage wins
    }
    Ok(current)
}

impl Tracker {
    /// Record that `obj` reached `stage` at time `at` and return the acknowledging update. A
    /// stage earlier than the one already reached is StageOutOfOrder (no state change);
    /// re-reporting the current stage is an idempotent no-op; a later stage is persisted (WAL
    /// fsync) before the update is returned. Skipping ahead is permitted; only regression errs.
    pub fn advance(&mut self, obj: &[u8], stage: u64, at: u64) -> Result<DeliveryUpdate, DeliveryError> {
        if let Some(&cur) = self.current.get(obj) {
            if stage < cur {
                return Err(DeliveryError::Cose(err_stage_out_of_order()));
            }
            if stage == cur {
                return Ok(DeliveryUpdate { obj: obj.to_vec(), stage, at });
            }
        }
        let u = DeliveryUpdate { obj: obj.to_vec(), stage, at };
        let rec = u.bytes();
        self.f.seek(SeekFrom::End(0)).map_err(DeliveryError::Io)?;
        self.f.write_all(&(rec.len() as u32).to_be_bytes()).map_err(DeliveryError::Io)?;
        self.f.write_all(&rec).map_err(DeliveryError::Io)?;
        self.f.sync_all().map_err(DeliveryError::Io)?; // persist-before-ack (R-9.2)
        self.current.insert(obj.to_vec(), stage);
        Ok(u)
    }

    /// The highest stage reached for `obj`, if seen.
    pub fn stage(&self, obj: &[u8]) -> Option<u64> {
        self.current.get(obj).copied()
    }
}

/// One side of a switchboard connection.
pub struct Endpoint {
    tx: SyncSender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl Endpoint {
    /// Submit an object toward the peer (blocks when the direction's buffer is full).
    pub fn send(&self, obj: Vec<u8>) {
        self.tx.send(obj).expect("switchboard peer gone");
    }
    /// Receive the next object relayed from the peer.
    pub fn recv(&self) -> Vec<u8> {
        self.rx.recv().expect("switchboard peer gone")
    }
    /// Split into the raw sender/receiver halves (so a sender thread and a receiver thread can
    /// each own one half of the same endpoint).
    pub fn into_parts(self) -> (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) {
        (self.tx, self.rx)
    }
}

/// Holds the two forwarding-pump threads of a live full-duplex switchboard (design.md §9.3).
pub struct Switchboard {
    pumps: Vec<JoinHandle<()>>,
}

impl Switchboard {
    /// Join both pumps (they exit once the endpoints feeding them are dropped).
    pub fn join(self) {
        for h in self.pumps {
            let _ = h.join();
        }
    }
}

/// Create a switchboard with per-direction buffering `capacity`. Returns the two endpoints and
/// the switchboard handle. Two pump threads forward left->right and right->left concurrently;
/// each pump retains nothing in transit.
pub fn new_switchboard(capacity: usize) -> (Endpoint, Endpoint, Switchboard) {
    let (la_tx, la_rx) = sync_channel::<Vec<u8>>(capacity); // left submits
    let (rb_tx, rb_rx) = sync_channel::<Vec<u8>>(capacity); // right receives
    let (ra_tx, ra_rx) = sync_channel::<Vec<u8>>(capacity); // right submits
    let (lb_tx, lb_rx) = sync_channel::<Vec<u8>>(capacity); // left receives

    let pump_l2r = thread::spawn(move || {
        while let Ok(obj) = la_rx.recv() {
            if rb_tx.send(obj).is_err() {
                break;
            }
        }
    });
    let pump_r2l = thread::spawn(move || {
        while let Ok(obj) = ra_rx.recv() {
            if lb_tx.send(obj).is_err() {
                break;
            }
        }
    });

    let left = Endpoint { tx: la_tx, rx: lb_rx };
    let right = Endpoint { tx: ra_tx, rx: rb_rx };
    (left, right, Switchboard { pumps: vec![pump_l2r, pump_r2l] })
}

/// Routes objects while retaining no payload at rest: for each routed object it appends an audit
/// receipt (§8) over the object's content id and returns the object for forwarding, keeping only
/// the receipt chain (content ids), never the payload (§9.4, R-9.4).
pub struct ContentFreeRelay {
    auth: audit::Authority,
    receipts: Vec<audit::Receipt>,
    sigs: Vec<Vec<u8>>,
}

impl Default for ContentFreeRelay {
    fn default() -> Self {
        ContentFreeRelay { auth: audit::Authority::new(), receipts: Vec::new(), sigs: Vec::new() }
    }
}

impl ContentFreeRelay {
    pub fn new() -> Self {
        ContentFreeRelay::default()
    }

    /// Record an audit receipt over `obj`'s content id (signed by `signer`) and return `obj` for
    /// forwarding. The relay keeps the receipt only; it does not store `obj`.
    pub fn route(&mut self, signer: &dyn cose::CoseSigner, obj: &[u8], at: u64) -> Vec<u8> {
        let (rec, sig) = self.auth.append(signer, &content_id(obj), at);
        self.receipts.push(rec);
        self.sigs.push(sig);
        obj.to_vec()
    }

    /// The retained receipts and signatures (the relay's only persistent state).
    pub fn audit_trail(&self) -> (&[audit::Receipt], &[Vec<u8>]) {
        (&self.receipts, &self.sigs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;
    use std::sync::atomic::{AtomicU64, Ordering};

    const VECTOR_PATH: &str = "../../vectors/delivery/cases.json";

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
            "naalp_deliv_{}_{}_{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn update_bytes_match_oracle() {
        let c = load();
        let obj = hexd(c["obj_content_id_hex"].as_str().unwrap());
        for s in c["stages"].as_array().unwrap() {
            assert_eq!(stage_name(s["value"].as_u64().unwrap()), s["name"].as_str().unwrap());
        }
        for u in c["updates"].as_array().unwrap() {
            let du = DeliveryUpdate {
                obj: obj.clone(),
                stage: u["stage"].as_u64().unwrap(),
                at: u["at"].as_u64().unwrap(),
            };
            assert_eq!(hex::encode(du.bytes()), u["body_hex"].as_str().unwrap());
        }
    }

    #[test]
    fn stage_monotonic_and_regression() {
        let c = load();
        let obj = hexd(c["obj_content_id_hex"].as_str().unwrap());
        let mut tr = open_tracker(&tmp_wal("mono")).unwrap();
        for s in [STAGE_PERSISTED_ORIGIN, STAGE_ACCEPTED_RELAY, STAGE_PERSISTED_TARGET] {
            tr.advance(&obj, s, 100 + s).expect("advance");
        }
        tr.advance(&obj, STAGE_PERSISTED_TARGET, 999).expect("idempotent re-report"); // == current
        assert_eq!(
            tr.advance(&obj, STAGE_ACCEPTED_RELAY, 999).unwrap_err().cose_kind(),
            Some("StageOutOfOrder")
        );
        tr.advance(&obj, STAGE_PRESENTED, 104).expect("advance to presented");
        assert_eq!(tr.stage(&obj), Some(STAGE_PRESENTED));
    }

    #[test]
    fn persist_before_ack_crash_recovery() {
        let c = load();
        let obj = hexd(c["obj_content_id_hex"].as_str().unwrap());
        let path = tmp_wal("crash");
        let acked;
        {
            let mut tr = open_tracker(&path).unwrap();
            tr.advance(&obj, STAGE_PERSISTED_ORIGIN, 100).unwrap();
            let ack = tr.advance(&obj, STAGE_PERSISTED_TARGET, 102).unwrap();
            acked = ack.stage;
        } // drop closes the WAL — simulates a crash right after the ack
        let mut tr2 = open_tracker(&path).unwrap();
        assert_eq!(tr2.stage(&obj), Some(acked), "acked stage did not survive crash");
        assert_eq!(
            tr2.advance(&obj, STAGE_PERSISTED_ORIGIN, 200).unwrap_err().cose_kind(),
            Some("StageOutOfOrder")
        );
        tr2.advance(&obj, STAGE_PRESENTED, 203).expect("advance after recovery");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn switchboard_full_duplex() {
        const N: usize = 200;
        let (left, right, sb) = new_switchboard(1);
        let (la_tx, lb_rx) = left.into_parts(); // A sends via la_tx, receives via lb_rx
        let (ra_tx, rb_rx) = right.into_parts(); // B sends via ra_tx, receives via rb_rx

        let h_as = thread::spawn(move || {
            for i in 0..N {
                la_tx.send(vec![(i % 251) as u8, 0xAB]).unwrap();
            }
        });
        let h_br = thread::spawn(move || {
            (0..N).map(|_| rb_rx.recv().unwrap()).collect::<Vec<_>>()
        });
        let h_bs = thread::spawn(move || {
            for i in 0..N {
                ra_tx.send(vec![(i % 251) as u8, 0xBA]).unwrap();
            }
        });
        let h_ar = thread::spawn(move || {
            (0..N).map(|_| lb_rx.recv().unwrap()).collect::<Vec<_>>()
        });

        h_as.join().unwrap();
        h_bs.join().unwrap();
        let got_ab = h_br.join().unwrap();
        let got_ba = h_ar.join().unwrap();
        sb.join();

        assert_eq!(got_ab.len(), N);
        assert_eq!(got_ba.len(), N);
        for i in 0..N {
            assert_eq!(got_ab[i], vec![(i % 251) as u8, 0xAB], "A->B order/content at {}", i);
            assert_eq!(got_ba[i], vec![(i % 251) as u8, 0xBA], "B->A order/content at {}", i);
        }
    }

    #[test]
    fn content_free_relay() {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[50; 32]);
        let v = cose::MlDsa65Verifier(pk);
        let s = cose::MlDsa65Signer(sk);
        let mut relay = ContentFreeRelay::new();
        let payloads: Vec<&[u8]> = vec![b"object one", b"object two", b"object three"];
        for (i, p) in payloads.iter().enumerate() {
            let out = relay.route(&s, p, 100 + i as u64);
            assert_eq!(out, p.to_vec(), "relay altered the forwarded object");
        }
        let (receipts, sigs) = relay.audit_trail();
        assert_eq!(receipts.len(), payloads.len());
        audit::verify_chain(receipts, sigs, &v).expect("relay audit trail verifies");
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!(receipts[i].obj, content_id(p), "receipt {} content id", i);
            // the receipt carries the content id, not the payload bytes.
            assert!(!receipts[i].obj.windows(p.len()).any(|w| w == *p), "payload retained at rest");
        }
    }
}
