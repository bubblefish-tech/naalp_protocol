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

use std::collections::HashMap;
use std::sync::Mutex;

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

/// Returned when a stream presents more chunks than the maximum (design.md §3.4, R7):
/// the stream chunk-count bound, a memory/verification-cost DoS guard.
pub fn err_too_many_chunks() -> cose::Error {
    cose::Error {
        kind: "TooManyChunks",
        msg: "stream chunk count exceeds the maximum (§3.4, R7)",
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
    if chunks.len() > crate::envelope::MAX_STREAM_CHUNKS as usize {
        return Err(err_too_many_chunks()); // stream chunk-count bound (§3.4, R7)
    }
    if commit.digest != commit_digest(chunks) {
        return Err(err_stream_digest_mismatch());
    }
    Ok(())
}

/// Confirm a prefix without the end: the prefix chunks must be contiguous from offset 0 and total
/// exactly `through_offset` bytes, and their rolling digest must equal `digest_so_far`.
pub fn verify_checkpoint(cp: &StreamCheckpoint, prefix: &[Chunk]) -> Result<(), cose::Error> {
    if prefix.len() > crate::envelope::MAX_STREAM_CHUNKS as usize {
        return Err(err_too_many_chunks()); // stream chunk-count bound (§3.4, R7)
    }
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

/// A stream's lifecycle state (design.md §10, the stream state table): `Idle` (no stream open for
/// this stream id), `Open`, `Committed`, or `Abandoned` (the terminal state an open stream enters
/// when its idle/commit timer expires, § Timers — like `Committed`, it admits no further event and
/// its stream id is never re-admitted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Idle,
    Open,
    Committed,
    Abandoned,
}

impl State {
    /// Names a State ("idle", "open", "committed", "abandoned").
    pub fn name(self) -> &'static str {
        match self {
            State::Idle => "idle",
            State::Open => "open",
            State::Committed => "committed",
            State::Abandoned => "abandoned",
        }
    }
}

/// Returned when a stream event arrives for a state the stream state table does not admit: a second
/// StreamOpen on an already-open stream, any chunk, StreamCheckpoint, or StreamCommit after the
/// stream has committed or been abandoned, or any of those (including a StreamOpen reusing the id)
/// on a stream that was never opened. Registered as naalp-error code 49 (design.md §10 state table).
pub fn err_stream_state_error() -> cose::Error {
    cose::Error {
        kind: "StreamStateError",
        msg: "stream event is illegal for the current stream state (§10 state table)",
    }
}

/// Enforces the stream state machine across concurrently open streams, keyed by stream id. Tracks
/// only the current lifecycle state (idle/open/committed/abandoned), never chunk data, and rejects
/// an event the state table does not admit for the stream's current state before any state change —
/// a rejected event leaves the state exactly as it was (fail-closed, no partial transition). It
/// holds no clock: the idle/commit timer (§ Timers) lives in the caller, which calls `expire` when
/// a stream's interval elapses; the interval is a deployment policy, not a protocol constant.
///
/// A Guard is per-connection: the caller drops it when the connection closes, freeing the map with
/// the connection. There is no eviction of terminal (committed / abandoned) entries — evicting one
/// would re-admit a replayed signed StreamOpen reusing that id as a fresh idle -> open, the exact
/// replay the terminal states exist to refuse. Retained entries are bounded by the number of
/// streams the connection actually opened (each of which cost the peer a full StreamOpen signature,
/// and the transport's concurrent sub-stream limit further caps them at any instant, §10.1), so
/// retention is bounded by work the peer already performed rather than an amplification surface.
pub struct Guard {
    states: Mutex<HashMap<Vec<u8>, State>>,
}

impl Default for Guard {
    fn default() -> Self {
        Guard {
            states: Mutex::new(HashMap::new()),
        }
    }
}

impl Guard {
    /// A stream-state guard with no streams open yet.
    pub fn new() -> Self {
        Guard::default()
    }

    fn state_in(states: &HashMap<Vec<u8>, State>, id: &[u8]) -> State {
        *states.get(id).unwrap_or(&State::Idle)
    }

    /// The current lifecycle state of `id`; an id never seen is idle (design.md §10).
    pub fn state(&self, id: &[u8]) -> State {
        let s = self.states.lock().unwrap();
        Self::state_in(&s, id)
    }

    /// Validate a StreamOpen against the state table: only idle admits StreamOpen, and then only
    /// when the effect is authorized (R-10.3). A stream already open, committed, or abandoned is
    /// rejected StreamStateError (a committed or abandoned id is never re-admitted). On
    /// EffectNotAuthorized the stream stays idle; on StreamStateError the state is untouched; only a
    /// successful open advances to open.
    pub fn open(&self, o: &StreamOpen, granted_max: u8) -> Result<(), cose::Error> {
        let mut s = self.states.lock().unwrap();
        if Self::state_in(&s, &o.stream_id) != State::Idle {
            return Err(err_stream_state_error());
        }
        open_stream(o, granted_max)?;
        s.insert(o.stream_id.clone(), State::Open);
        Ok(())
    }

    /// Validate a data chunk's arrival: only open admits a chunk; idle, committed, or abandoned
    /// reject it StreamStateError. A chunk never changes the stream's state.
    pub fn chunk(&self, id: &[u8]) -> Result<(), cose::Error> {
        let s = self.states.lock().unwrap();
        if Self::state_in(&s, id) != State::Open {
            return Err(err_stream_state_error());
        }
        Ok(())
    }

    /// Validate a StreamCheckpoint's arrival: only open admits it; idle, committed, or abandoned
    /// reject it StreamStateError. A checkpoint never changes the stream's state.
    pub fn checkpoint(&self, id: &[u8]) -> Result<(), cose::Error> {
        let s = self.states.lock().unwrap();
        if Self::state_in(&s, id) != State::Open {
            return Err(err_stream_state_error());
        }
        Ok(())
    }

    /// Validate a StreamCommit against the state table: only open admits it — idle, committed, or
    /// abandoned reject it StreamStateError before the digest is inspected. When open, the
    /// commitment is verified against the delivered chunks (R-10.2): a digest mismatch is rejected
    /// StreamDigestMismatch and leaves the stream open (a corrected commit may follow); a matching
    /// digest advances the stream to committed.
    pub fn commit(&self, commit: &StreamCommit, chunks: &[Chunk]) -> Result<(), cose::Error> {
        let mut s = self.states.lock().unwrap();
        if Self::state_in(&s, &commit.stream_id) != State::Open {
            return Err(err_stream_state_error());
        }
        verify_commit(commit, chunks)?;
        s.insert(commit.stream_id.clone(), State::Committed);
        Ok(())
    }

    /// Fire the idle/commit timer's expiry for `id` (§ Timers): an open stream that has not
    /// committed within its interval transitions "open -> abandoned", a terminal state that then
    /// rejects every event with StreamStateError — including a StreamOpen reusing the id, so an
    /// abandoned stream is never re-admitted. Only an open stream can be abandoned: the timer
    /// clears on StreamCommit, so a correct caller fires `expire` only while the stream is open;
    /// `expire` on an idle, committed, or already-abandoned stream is rejected StreamStateError with
    /// no state change (fail-closed). The Guard holds no clock — the caller decides when the
    /// interval has elapsed.
    pub fn expire(&self, id: &[u8]) -> Result<(), cose::Error> {
        let mut s = self.states.lock().unwrap();
        if Self::state_in(&s, id) != State::Open {
            return Err(err_stream_state_error());
        }
        s.insert(id.to_vec(), State::Abandoned);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseVerifier; // bring verify_raw into method scope

    // Stream chunk-count bound (design.md §3.4, R7): a commit/checkpoint over exactly
    // MAX_STREAM_CHUNKS chunks verifies, and one over MAX_STREAM_CHUNKS+1 is rejected
    // TooManyChunks. Both carry a matching digest so the count is the only reason to
    // reject (mutation-surviving); the count check fires before the digest check.
    #[test]
    fn bound_too_many_chunks() {
        let max = crate::envelope::MAX_STREAM_CHUNKS as usize;
        let over = vec![
            Chunk {
                offset: 0,
                data: vec![]
            };
            max + 1
        ];
        let at_limit = &over[..max];

        let ok = StreamCommit {
            stream_id: vec![],
            digest: commit_digest(at_limit),
        };
        verify_commit(&ok, at_limit).expect("commit at the chunk limit should verify");

        let over_commit = StreamCommit {
            stream_id: vec![],
            digest: commit_digest(&over),
        };
        match verify_commit(&over_commit, &over) {
            Err(e) => assert_eq!(e.kind, "TooManyChunks"),
            Ok(_) => panic!("commit over the chunk limit should be TooManyChunks"),
        }

        let cp = StreamCheckpoint {
            stream_id: vec![],
            through_offset: 0,
            digest_so_far: vec![],
        };
        match verify_checkpoint(&cp, &over) {
            Err(e) => assert_eq!(e.kind, "TooManyChunks"),
            Ok(_) => panic!("checkpoint over the chunk limit should be TooManyChunks"),
        }
    }
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
            .map(|ch| Chunk {
                offset: ch["offset"].as_u64().unwrap(),
                data: hexd(ch["data_hex"].as_str().unwrap()),
            })
            .collect()
    }

    #[test]
    fn digest_and_bodies_match_oracle() {
        let c = load();
        let stream_id = hexd(c["stream_id_hex"].as_str().unwrap());
        let chunks = chunks_of(&c);
        assert_eq!(
            hex::encode(commit_digest(&chunks)),
            c["final_digest_hex"].as_str().unwrap()
        );

        let mut sd = StreamDigest::new();
        let cps = c["checkpoints"].as_array().unwrap();
        for (i, ch) in chunks.iter().enumerate() {
            sd.update(&ch.data);
            if i < cps.len() {
                assert_eq!(
                    hex::encode(sd.digest_so_far()),
                    cps[i]["digest_so_far_hex"].as_str().unwrap()
                );
            }
        }
        assert_eq!(
            hex::encode(sd.digest_so_far()),
            c["final_digest_hex"].as_str().unwrap()
        );

        let open = StreamOpen {
            stream_id: stream_id.clone(),
            effect: c["effect"].as_u64().unwrap(),
            approval: Some(hexd(c["approval_hex"].as_str().unwrap())),
            substream: c["substream"].as_u64().unwrap(),
        };
        assert_eq!(
            hex::encode(open.bytes()),
            c["open_body_hex"].as_str().unwrap()
        );
        let commit = StreamCommit {
            stream_id: stream_id.clone(),
            digest: hexd(c["final_digest_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(commit.bytes()),
            c["commit_body_hex"].as_str().unwrap()
        );
        let cp = StreamCheckpoint {
            stream_id,
            through_offset: cps[0]["through_offset"].as_u64().unwrap(),
            digest_so_far: hexd(cps[0]["digest_so_far_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(cp.bytes()),
            c["checkpoint_body_hex"].as_str().unwrap()
        );
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
        assert_eq!(
            verify_commit(&commit, &tampered).unwrap_err().kind,
            "StreamDigestMismatch"
        );
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
        assert!(
            verify_checkpoint(&cp0, &all).is_err(),
            "wrong-length prefix accepted"
        );
    }

    #[test]
    fn effect_refused_before_chunk() {
        let c = load();
        let stream_id = hexd(c["stream_id_hex"].as_str().unwrap());
        let destructive = StreamOpen {
            stream_id: stream_id.clone(),
            effect: policy::DESTRUCTIVE as u64,
            approval: None,
            substream: 1,
        };
        assert_eq!(
            open_stream(&destructive, policy::READ_ONLY)
                .unwrap_err()
                .kind,
            "EffectNotAuthorized"
        );
        let ok = StreamOpen {
            stream_id: stream_id.clone(),
            effect: c["effect"].as_u64().unwrap(),
            approval: Some(hexd(c["approval_hex"].as_str().unwrap())),
            substream: c["substream"].as_u64().unwrap(),
        };
        open_stream(&ok, policy::IDEMPOTENT_WRITE).expect("authorized stream");
        let unknown = StreamOpen {
            stream_id,
            effect: 99,
            approval: None,
            substream: 1,
        };
        assert!(
            open_stream(&unknown, policy::NON_IDEMPOTENT_WRITE).is_err(),
            "unknown effect authorized"
        );
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
                chunks.push(Chunk {
                    offset: off - data.len() as u64,
                    data,
                });
            }
            let digest = commit_digest(&chunks);
            (
                chunks,
                StreamCommit {
                    stream_id: vec![seed],
                    digest,
                },
            )
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
        assert_eq!(
            commit_digest(&chunks),
            commit_digest(&reversed),
            "input order must not matter"
        );
        // Swap only the data at the first two offsets: same bytes, different positions.
        let mut swapped = chunks_of(&c);
        let d0 = swapped[0].data.clone();
        swapped[0].data = swapped[1].data.clone();
        swapped[1].data = d0;
        assert_ne!(
            hex::encode(commit_digest(&swapped)),
            c["final_digest_hex"].as_str().unwrap()
        );
    }
}

// Guard enforces the stream state table (design.md §10) with StreamStateError (code 49) and the
// idle/commit timer's expiry -> abandoned terminal state (§ Timers). Behavior parity with the Go
// reference guard (impl/go/streaming/state_guard_test.go).
#[cfg(test)]
mod guard_tests {
    use super::*;

    fn open_for(id: &[u8]) -> StreamOpen {
        StreamOpen {
            stream_id: id.to_vec(),
            effect: policy::IDEMPOTENT_WRITE as u64,
            approval: None,
            substream: 0,
        }
    }

    // Forbidden (state, event) pairs from the stream state table are each rejected StreamStateError
    // and leave the state unchanged: chunk/checkpoint/commit before open (idle), a double open, and
    // every event after commit (including a reopen).
    #[test]
    fn rejects_forbidden_transitions() {
        let id = b"stream-forbidden".to_vec();

        let g = Guard::new();
        assert_eq!(g.chunk(&id).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&id), State::Idle);

        let g = Guard::new();
        assert_eq!(g.checkpoint(&id).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&id), State::Idle);

        let g = Guard::new();
        let commit = StreamCommit {
            stream_id: id.clone(),
            digest: vec![],
        };
        assert_eq!(
            g.commit(&commit, &[]).unwrap_err().kind,
            "StreamStateError"
        );
        assert_eq!(g.state(&id), State::Idle);

        // open + StreamOpen -> reject (StreamStateError).
        let g = Guard::new();
        let o = open_for(&id);
        g.open(&o, policy::IDEMPOTENT_WRITE).expect("first open");
        assert_eq!(g.open(&o, policy::IDEMPOTENT_WRITE).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&id), State::Open);

        // committed + {chunk, checkpoint, commit, open} -> reject (StreamStateError).
        let g = Guard::new();
        let cid = b"stream-after-commit".to_vec();
        let oc = open_for(&cid);
        g.open(&oc, policy::IDEMPOTENT_WRITE).expect("open");
        let chunks = vec![Chunk {
            offset: 0,
            data: b"payload".to_vec(),
        }];
        let commit = StreamCommit {
            stream_id: cid.clone(),
            digest: commit_digest(&chunks),
        };
        g.commit(&commit, &chunks).expect("commit");
        assert_eq!(g.state(&cid), State::Committed);
        assert_eq!(g.chunk(&cid).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.checkpoint(&cid).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.commit(&commit, &chunks).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.open(&oc, policy::IDEMPOTENT_WRITE).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&cid), State::Committed);
    }

    // The false-positive check: an ordered open -> chunk -> checkpoint -> commit succeeds and drives
    // idle -> open -> committed.
    #[test]
    fn valid_sequence_succeeds() {
        let id = b"stream-valid".to_vec();
        let g = Guard::new();
        assert_eq!(g.state(&id), State::Idle);

        g.open(&open_for(&id), policy::IDEMPOTENT_WRITE).expect("open");
        assert_eq!(g.state(&id), State::Open);

        let chunks = vec![
            Chunk {
                offset: 0,
                data: b"hello ".to_vec(),
            },
            Chunk {
                offset: 6,
                data: b"world".to_vec(),
            },
        ];
        for _ in &chunks {
            g.chunk(&id).expect("chunk");
        }
        g.checkpoint(&id).expect("checkpoint");
        assert_eq!(g.state(&id), State::Open);

        let commit = StreamCommit {
            stream_id: id.clone(),
            digest: commit_digest(&chunks),
        };
        g.commit(&commit, &chunks).expect("commit");
        assert_eq!(g.state(&id), State::Committed);
    }

    // A digest-mismatched commit surfaces StreamDigestMismatch (not StreamStateError) and leaves the
    // stream open so a corrected commit still lands.
    #[test]
    fn digest_mismatch_is_not_state_error() {
        let id = b"stream-bad-digest".to_vec();
        let g = Guard::new();
        g.open(&open_for(&id), policy::IDEMPOTENT_WRITE).expect("open");
        let chunks = vec![Chunk {
            offset: 0,
            data: b"payload".to_vec(),
        }];
        let bad = StreamCommit {
            stream_id: id.clone(),
            digest: b"not-the-real-digest-not-the-real-digest".to_vec(),
        };
        assert_eq!(
            g.commit(&bad, &chunks).unwrap_err().kind,
            "StreamDigestMismatch"
        );
        assert_eq!(g.state(&id), State::Open);
        let good = StreamCommit {
            stream_id: id.clone(),
            digest: commit_digest(&chunks),
        };
        g.commit(&good, &chunks).expect("corrected commit");
        assert_eq!(g.state(&id), State::Committed);
    }

    // An unauthorized open surfaces EffectNotAuthorized (not StreamStateError) and leaves the stream
    // idle so a properly authorized open still succeeds (R-10.3).
    #[test]
    fn effect_not_authorized_leaves_idle() {
        let id = b"stream-unauthorized".to_vec();
        let g = Guard::new();
        let destructive = StreamOpen {
            stream_id: id.clone(),
            effect: policy::DESTRUCTIVE as u64,
            approval: None,
            substream: 0,
        };
        assert_eq!(
            g.open(&destructive, policy::READ_ONLY).unwrap_err().kind,
            "EffectNotAuthorized"
        );
        assert_eq!(g.state(&id), State::Idle);
        g.open(&open_for(&id), policy::IDEMPOTENT_WRITE)
            .expect("authorized open");
        assert_eq!(g.state(&id), State::Open);
    }

    // The guard is keyed by stream id, so one stream's state never leaks into another's.
    #[test]
    fn independent_streams_do_not_interfere() {
        let g = Guard::new();
        let a = b"stream-a".to_vec();
        let b = b"stream-b".to_vec();
        g.open(&open_for(&a), policy::IDEMPOTENT_WRITE).expect("open a");
        assert_eq!(g.chunk(&b).unwrap_err().kind, "StreamStateError");
        g.chunk(&a).expect("chunk on open stream a");
    }

    // Expire on an open stream transitions open -> abandoned, a terminal state that rejects every
    // event with StreamStateError — including a StreamOpen reusing the id (never re-admitted).
    #[test]
    fn expire_abandons_open_stream() {
        let id = b"stream-abandoned".to_vec();
        let g = Guard::new();
        let o = open_for(&id);
        g.open(&o, policy::IDEMPOTENT_WRITE).expect("open");
        g.expire(&id).expect("expire open stream");
        assert_eq!(g.state(&id), State::Abandoned);

        let chunks = vec![Chunk {
            offset: 0,
            data: b"payload".to_vec(),
        }];
        let commit = StreamCommit {
            stream_id: id.clone(),
            digest: commit_digest(&chunks),
        };
        assert_eq!(g.chunk(&id).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.checkpoint(&id).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.commit(&commit, &chunks).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.open(&o, policy::IDEMPOTENT_WRITE).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&id), State::Abandoned);
    }

    // Expire on a non-open stream (idle, committed, already-abandoned) is rejected StreamStateError
    // and leaves the state unchanged (fail-closed; the timer clears on commit).
    #[test]
    fn expire_on_non_open_is_state_error() {
        // idle
        let id = b"stream-expire-idle".to_vec();
        let g = Guard::new();
        assert_eq!(g.expire(&id).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&id), State::Idle);

        // committed
        let cid = b"stream-expire-committed".to_vec();
        let g = Guard::new();
        g.open(&open_for(&cid), policy::IDEMPOTENT_WRITE).expect("open");
        let chunks = vec![Chunk {
            offset: 0,
            data: b"payload".to_vec(),
        }];
        let commit = StreamCommit {
            stream_id: cid.clone(),
            digest: commit_digest(&chunks),
        };
        g.commit(&commit, &chunks).expect("commit");
        assert_eq!(g.expire(&cid).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&cid), State::Committed);

        // already abandoned
        let aid = b"stream-expire-twice".to_vec();
        let g = Guard::new();
        g.open(&open_for(&aid), policy::IDEMPOTENT_WRITE).expect("open");
        g.expire(&aid).expect("first expire");
        assert_eq!(g.expire(&aid).unwrap_err().kind, "StreamStateError");
        assert_eq!(g.state(&aid), State::Abandoned);
    }
}
