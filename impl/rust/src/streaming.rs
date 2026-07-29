// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C9 — native streaming with a single signed per-stream commitment (design.md §10;
//! R-10.1..10.6).
//!
//! A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the
//! stream's identity, effect, and (where it causes an effect) its approval binding, refusing a
//! stream whose effect is not authorized before any chunk (§10.2, R-10.3); chunks are raw data
//! frames the transport AEAD already authenticates, so N-AALP does NOT sign them individually
//! (R-10.2); StreamCommit carries a rolling SHA-384 over the chunks in absolute-offset order,
//! making the whole stream non-repudiable with one signature (§10.2). Optional StreamCheckpoints
//! confirm a prefix without the end. Altering any delivered byte invalidates the commitment
//! (StreamDigestMismatch). Native streaming is channel 0x000C, distinct from foreign carriage
//! (§13, 0x000D); this module never carries a foreign protocol (R-10.6).

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;
use crate::policy;

/// The N-PAMP Stream channel native streams run on; foreign carriage uses 0x000D (R-10.6).
pub const STREAM_CHANNEL: u64 = 0x000C;

pub fn err_stream_digest_mismatch() -> cose::Error {
    cose::Error {
        kind: "StreamDigestMismatch",
        msg: "stream commitment digest does not match the recomputed rolling digest",
    }
}

/// One absolute-offset-positioned data frame of a stream (unsigned).
#[derive(Clone)]
pub struct Chunk {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// The rolling SHA-384 commitment accumulator (design.md §10.2).
pub struct StreamDigest {
    h: Sha384,
}

impl Default for StreamDigest {
    fn default() -> Self {
        StreamDigest { h: Sha384::new() }
    }
}

impl StreamDigest {
    pub fn new() -> Self {
        StreamDigest::default()
    }
    /// Feed the next chunk's data.
    pub fn update(&mut self, chunk: &[u8]) {
        self.h.update(chunk);
    }
    /// SHA-384 of everything fed so far, without ending the stream (a checkpoint's digest_so_far).
    pub fn digest_so_far(&self) -> Vec<u8> {
        self.h.clone().finalize().to_vec()
    }
}

/// Rolling SHA-384 over the chunks in absolute-offset order.
pub fn commit_digest(chunks: &[Chunk]) -> Vec<u8> {
    let mut sorted: Vec<&Chunk> = chunks.iter().collect();
    sorted.sort_by_key(|c| c.offset);
    let mut sd = StreamDigest::new();
    for c in sorted {
        sd.update(&c.data);
    }
    sd.digest_so_far()
}

/// Establishes a stream's identity, effect, optional approval binding, and sub-stream id
/// (design.md §10.2). Signed.
pub struct StreamOpen {
    pub stream_id: Vec<u8>,
    pub effect: u64,
    pub approval: Option<Vec<u8>>, // content id of the approval binding; None if no effect
    pub substream: u64,
}

impl StreamOpen {
    /// Deterministic-CBOR {1: stream_id, 2: effect, 3: approval?, 4: substream}; field 3 present
    /// only when an approval binding exists.
    pub fn bytes(&self) -> Vec<u8> {
        let mut m = vec![
            (Value::Uint(1), Value::Bstr(self.stream_id.clone())),
            (Value::Uint(2), Value::Uint(self.effect)),
            (Value::Uint(4), Value::Uint(self.substream)),
        ];
        if let Some(a) = &self.approval {
            m.push((Value::Uint(3), Value::Bstr(a.clone())));
        }
        cbor::encode(&Value::Map(m)).expect("encode stream open")
    }
}

/// Carries the completed stream's rolling-SHA-384 commitment (design.md §10.2).
pub struct StreamCommit {
    pub stream_id: Vec<u8>,
    pub digest: Vec<u8>,
}

impl StreamCommit {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.stream_id.clone())),
            (Value::Uint(2), Value::Bstr(self.digest.clone())),
        ]))
        .expect("encode stream commit")
    }
}

/// Carries a mid-stream commitment over the prefix through `through_offset` (design.md §10.2).
pub struct StreamCheckpoint {
    pub stream_id: Vec<u8>,
    pub through_offset: u64,
    pub digest_so_far: Vec<u8>,
}

impl StreamCheckpoint {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.stream_id.clone())),
            (Value::Uint(2), Value::Uint(self.through_offset)),
            (Value::Uint(3), Value::Bstr(self.digest_so_far.clone())),
        ]))
        .expect("encode stream checkpoint")
    }
}

pub fn sign_open(o: &StreamOpen, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    signer.sign(&o.bytes())
}
pub fn sign_commit(c: &StreamCommit, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    signer.sign(&c.bytes())
}
pub fn sign_checkpoint(c: &StreamCheckpoint, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    signer.sign(&c.bytes())
}

/// Authorize a StreamOpen against the granted effect ceiling, refusing a stream whose effect
/// exceeds it BEFORE any chunk (R-10.3). An unrecognized effect fails closed to destructive.
pub fn open_stream(o: &StreamOpen, granted_max: u8) -> Result<(), cose::Error> {
    if !policy::authorizes(granted_max, policy::normalize_effect(o.effect)) {
        return Err(policy::err_effect_not_authorized());
    }
    Ok(())
}

/// Recompute the rolling digest over the delivered chunks and compare it to the commitment; any
/// altered or reordered byte yields StreamDigestMismatch (R-10.2).
pub fn verify_commit(commit: &StreamCommit, chunks: &[Chunk]) -> Result<(), cose::Error> {
    if commit.digest != commit_digest(chunks) {
        return Err(err_stream_digest_mismatch());
    }
    Ok(())
}

/// Confirm a prefix without the end: the prefix chunks must be contiguous from offset 0 and total
/// exactly `through_offset` bytes, and their rolling digest must equal `digest_so_far`.
pub fn verify_checkpoint(cp: &StreamCheckpoint, prefix: &[Chunk]) -> Result<(), cose::Error> {
    let mut sorted: Vec<&Chunk> = prefix.iter().collect();
    sorted.sort_by_key(|c| c.offset);
    let mut total: u64 = 0;
    for c in &sorted {
        if c.offset != total {
            return Err(err_stream_digest_mismatch());
        }
        total += c.data.len() as u64;
    }
    if total != cp.through_offset {
        return Err(err_stream_digest_mismatch());
    }
    if cp.digest_so_far != commit_digest(prefix) {
        return Err(err_stream_digest_mismatch());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseVerifier; // bring verify_raw into method scope
    use serde_json::Value as J;
    use std::thread;

    const VECTOR_PATH: &str = "../../vectors/stream/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn chunks_of(c: &J) -> Vec<Chunk> {
        c["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ch| Chunk { offset: ch["offset"].as_u64().unwrap(), data: hexd(ch["data_hex"].as_str().unwrap()) })
            .collect()
    }

    #[test]
    fn digest_and_bodies_match_oracle() {
        let c = load();
        let stream_id = hexd(c["stream_id_hex"].as_str().unwrap());
        let chunks = chunks_of(&c);
        assert_eq!(hex::encode(commit_digest(&chunks)), c["final_digest_hex"].as_str().unwrap());

        let mut sd = StreamDigest::new();
        let cps = c["checkpoints"].as_array().unwrap();
        for (i, ch) in chunks.iter().enumerate() {
            sd.update(&ch.data);
            if i < cps.len() {
                assert_eq!(hex::encode(sd.digest_so_far()), cps[i]["digest_so_far_hex"].as_str().unwrap());
            }
        }
        assert_eq!(hex::encode(sd.digest_so_far()), c["final_digest_hex"].as_str().unwrap());

        let open = StreamOpen {
            stream_id: stream_id.clone(),
            effect: c["effect"].as_u64().unwrap(),
            approval: Some(hexd(c["approval_hex"].as_str().unwrap())),
            substream: c["substream"].as_u64().unwrap(),
        };
        assert_eq!(hex::encode(open.bytes()), c["open_body_hex"].as_str().unwrap());
        let commit = StreamCommit { stream_id: stream_id.clone(), digest: hexd(c["final_digest_hex"].as_str().unwrap()) };
        assert_eq!(hex::encode(commit.bytes()), c["commit_body_hex"].as_str().unwrap());
        let cp = StreamCheckpoint {
            stream_id,
            through_offset: cps[0]["through_offset"].as_u64().unwrap(),
            digest_so_far: hexd(cps[0]["digest_so_far_hex"].as_str().unwrap()),
        };
        assert_eq!(hex::encode(cp.bytes()), c["checkpoint_body_hex"].as_str().unwrap());
    }

    #[test]
    fn tamper_invalidates_commit() {
        let c = load();
        let commit = StreamCommit {
            stream_id: hexd(c["stream_id_hex"].as_str().unwrap()),
            digest: hexd(c["final_digest_hex"].as_str().unwrap()),
        };
        verify_commit(&commit, &chunks_of(&c)).expect("valid stream");
        let mut tampered = chunks_of(&c);
        let idx = c["tamper"]["chunk_index"].as_u64().unwrap() as usize;
        tampered[idx].data = hexd(c["tamper"]["flipped_data_hex"].as_str().unwrap());
        assert_eq!(verify_commit(&commit, &tampered).unwrap_err().kind, "StreamDigestMismatch");
    }

    #[test]
    fn checkpoint_verifies_prefix() {
        let c = load();
        let stream_id = hexd(c["stream_id_hex"].as_str().unwrap());
        let all = chunks_of(&c);
        for (i, cpj) in c["checkpoints"].as_array().unwrap().iter().enumerate() {
            let cp = StreamCheckpoint {
                stream_id: stream_id.clone(),
                through_offset: cpj["through_offset"].as_u64().unwrap(),
                digest_so_far: hexd(cpj["digest_so_far_hex"].as_str().unwrap()),
            };
            verify_checkpoint(&cp, &all[..=i]).expect("valid prefix"); // without the end
        }
        let cp0 = StreamCheckpoint {
            stream_id,
            through_offset: c["checkpoints"][0]["through_offset"].as_u64().unwrap(),
            digest_so_far: hexd(c["checkpoints"][0]["digest_so_far_hex"].as_str().unwrap()),
        };
        assert!(verify_checkpoint(&cp0, &all).is_err(), "wrong-length prefix accepted");
    }

    #[test]
    fn effect_refused_before_chunk() {
        let c = load();
        let stream_id = hexd(c["stream_id_hex"].as_str().unwrap());
        let destructive = StreamOpen { stream_id: stream_id.clone(), effect: policy::DESTRUCTIVE as u64, approval: None, substream: 1 };
        assert_eq!(open_stream(&destructive, policy::READ_ONLY).unwrap_err().kind, "EffectNotAuthorized");
        let ok = StreamOpen {
            stream_id: stream_id.clone(),
            effect: c["effect"].as_u64().unwrap(),
            approval: Some(hexd(c["approval_hex"].as_str().unwrap())),
            substream: c["substream"].as_u64().unwrap(),
        };
        open_stream(&ok, policy::IDEMPOTENT_WRITE).expect("authorized stream");
        let unknown = StreamOpen { stream_id, effect: 99, approval: None, substream: 1 };
        assert!(open_stream(&unknown, policy::NON_IDEMPOTENT_WRITE).is_err(), "unknown effect authorized");
    }

    #[test]
    fn signed_commitment() {
        let c = load();
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[60; 32]);
        let v = cose::MlDsa65Verifier(pk);
        let s = cose::MlDsa65Signer(sk);
        let commit = StreamCommit {
            stream_id: hexd(c["stream_id_hex"].as_str().unwrap()),
            digest: hexd(c["final_digest_hex"].as_str().unwrap()),
        };
        let sig = sign_commit(&commit, &s);
        assert!(v.verify_raw(&commit.bytes(), &sig));
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(!v.verify_raw(&commit.bytes(), &bad));
    }

    #[test]
    fn full_duplex_concurrent() {
        fn mk(seed: u8, n: usize) -> (Vec<Chunk>, StreamCommit) {
            let mut chunks = Vec::new();
            let mut off = 0u64;
            for i in 0..n {
                let data = vec![seed, i as u8, (i * 7) as u8];
                off += data.len() as u64;
                chunks.push(Chunk { offset: off - data.len() as u64, data });
            }
            let digest = commit_digest(&chunks);
            (chunks, StreamCommit { stream_id: vec![seed], digest })
        }
        let (chunks_a, commit_a) = mk(0xA1, 300);
        let (chunks_b, commit_b) = mk(0xB2, 300);
        let da = commit_a.digest.clone();
        let db = commit_b.digest.clone();

        let ha = thread::spawn(move || verify_commit(&commit_a, &chunks_a));
        let hb = thread::spawn(move || verify_commit(&commit_b, &chunks_b));
        ha.join().unwrap().expect("stream A");
        hb.join().unwrap().expect("stream B");
        assert_ne!(da, db, "distinct streams produced the same commitment");
    }

    #[test]
    fn offset_order_matters() {
        let c = load();
        let chunks = chunks_of(&c);
        let mut reversed = chunks.clone();
        reversed.reverse();
        assert_eq!(commit_digest(&chunks), commit_digest(&reversed), "input order must not matter");
        // Swap only the data at the first two offsets: same bytes, different positions.
        let mut swapped = chunks_of(&c);
        let d0 = swapped[0].data.clone();
        swapped[0].data = swapped[1].data.clone();
        swapped[1].data = d0;
        assert_ne!(hex::encode(commit_digest(&swapped)), c["final_digest_hex"].as_str().unwrap());
    }
}
