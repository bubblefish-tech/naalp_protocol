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
use crate::policy;

/// Width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.
pub const HEAD_SIZE: usize = 48;

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_approval_mismatch() -> cose::Error {
    err(
        "ApprovalMismatch",
        "approval does not bind these arguments' content id",
    )
}
pub fn err_approval_expired() -> cose::Error {
    err("ApprovalExpired", "approval is past its not_after")
}
pub fn err_already_consumed() -> cose::Error {
    err("AlreadyConsumed", "approval already consumed")
}
pub fn err_approval_required() -> cose::Error {
    err(
        "ApprovalRequired",
        "action requires an approval that is not present",
    )
}
pub fn err_ledger_corrupt() -> cose::Error {
    err("LedgerCorrupt", "consume ledger hash chain does not verify")
}
// T1.5 (NAALP-REQ-121) — the ledger-signed consume receipt with forward-only position.
pub fn err_ledger_unsigned() -> cose::Error {
    err("LedgerUnsigned", "ledger was not opened with a signing key")
}
pub fn err_consume_receipt_unsigned() -> cose::Error {
    err(
        "ConsumeReceiptUnsigned",
        "consume receipt is unnamed or its ledger signature does not verify",
    )
}
pub fn err_consume_fork_invalid() -> cose::Error {
    err(
        "ConsumeForkInvalid",
        "fork evidence does not prove a double spend",
    )
}
pub fn err_consume_fork() -> cose::Error {
    err(
        "ConsumeFork",
        "two ledger-signed receipts contradict on one approval id",
    )
}
// R-TDCS-4 (design.md §25, C22) — trust-decision closure sovereignty: the ordering authority
// that stamps freshness is structurally distinct from the authenticated party.
pub fn err_freshness_self_asserted() -> cose::Error {
    err(
        "FreshnessSelfAsserted",
        "the ordering authority that stamps freshness is the authenticated party itself",
    )
}
// R-TDCS-5 (design.md §25, C22) — an approval that names an audience is valid only in that
// context; presenting it at a different use context is rejected fail-closed, authorizing nothing.
pub fn err_audience_mismatch() -> cose::Error {
    err(
        "AudienceMismatch",
        "approval names an audience other than the use context",
    )
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
    /// OPTIONAL valid-context (R-TDCS-5); "" == absent (field 6 omitted, unrestricted).
    pub audience: String,
}

impl ApprovalRecord {
    /// Deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6 is OMITTED
    /// when `audience` is "" — an empty string is not a distinct value, so an approval that names
    /// no audience encodes byte-identically to a 5-field approval (R-TDCS-5, additive by design).
    pub fn bytes(&self) -> Vec<u8> {
        let mut pairs = vec![
            (Value::Uint(1), Value::Bstr(self.approves.clone())),
            (Value::Uint(2), Value::Tstr(self.approver.clone())),
            (Value::Uint(3), Value::Uint(self.grant)),
            (Value::Uint(4), Value::Bstr(self.nonce.clone())),
            (Value::Uint(5), Value::Uint(self.not_after)),
        ];
        if !self.audience.is_empty() {
            pairs.push((Value::Uint(6), Value::Tstr(self.audience.clone())));
        }
        cbor::encode(&Value::Map(pairs)).expect("encode approval body")
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

/// The composed, single-call consume choke point for the approval state machine (draft "## Approval
/// state machine"). It runs the table's precedence in ONE impl-owned place — the exact sequence that
/// `payment::authorize_charge` (and the mcp/agui/delegation callers) hand-assemble — so a caller (and
/// the conformance suite) drives one realization of the reactions rather than re-deriving the ordering:
///
///  1. `verify_approval` checks the signature, then the args-content-id binding (ApprovalMismatch,
///     which the draft says "takes precedence over every cell"), then expiry (ApprovalExpired) — all
///     BEFORE the ledger. So a request both past `not_after` AND already in the ledger is refused
///     ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume rule), leaving the
///     ledger untouched.
///  2. The granted effect must be a valid class (0..3) and must cover the action's required effect; a
///     grant outside the closed vocabulary, or below the required effect, authorizes nothing and is
///     refused ApprovalRequired (fail-closed; the grant-range guard is stricter than the raw callers).
///  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
///     second returns AlreadyConsumed, and neither a rejected step nor a losing race appends.
///
/// Every rejection is fail-closed and appends nothing; it consumes only when every check holds. It
/// does NOT enforce object audience — that is `Ledger::consume_object`'s binding (design.md §2.5.3).
#[allow(clippy::too_many_arguments)]
pub fn consume_approval(
    a: &ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    a_sig: &[u8],
    args_content_id: &[u8],
    pos_time: u64,
    required_effect: u8,
    ledger: &Ledger,
    by: &str,
) -> Result<LedgerEntry, LedgerError> {
    verify_approval(a, approver_v, a_sig, args_content_id, pos_time).map_err(LedgerError::Cose)?; // sig/mismatch/expiry, all before the ledger
    if a.grant > policy::DESTRUCTIVE as u64 {
        return Err(LedgerError::Cose(err_approval_required())); // a grant outside the closed 0..3 vocabulary authorizes nothing
    }
    if !policy::authorizes(a.grant as u8, required_effect) {
        return Err(LedgerError::Cose(err_approval_required())); // the approval's granted effect does not cover this action
    }
    ledger.consume(&a.id(), by)
}

/// (R-TDCS-5) Enforce the OPTIONAL audience binding. An approval that NAMES an audience
/// (`a.audience != ""`) is valid only in that context: a relying party checks it at use and
/// rejects AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted by
/// the issuer's explicit choice and passes for any use context — a deployment MAY require an
/// audience by local policy above this check. The check is mandatory WHEN a context is present,
/// never mandatory-presence (the JWT `aud` present-optional / check-mandatory shape).
pub fn verify_audience(a: &ApprovalRecord, use_context: &str) -> Result<(), cose::Error> {
    if !a.audience.is_empty() && a.audience != use_context {
        return Err(err_audience_mismatch());
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
    pub prev: Vec<u8>, // prior chain head (HEAD_SIZE bytes; genesis is all-zero)
    pub approval_id: Vec<u8>, // the approval content id being consumed
    pub by: String,    // consumer signer id
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
        (Some(seq), Some(prev), Some(approval_id), Some(by)) => Ok(LedgerEntry {
            seq,
            prev,
            approval_id,
            by,
        }),
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
///
/// T1.5 (NAALP-REQ-121): a ledger opened with `open_ledger_signed` also carries its own
/// ordering-authority identity (`ledger_id`) and signing key, so `consume_with_receipt` can mint a
/// ledger-signed consume receipt binding the approval id to the ledger's forward-only position. A
/// plain `open_ledger` leaves both unset and offers `consume` only.
pub struct Ledger {
    inner: Mutex<LedgerInner>,
    ledger_id: Vec<u8>, // this ledger's signer id (the ordering authority); empty if unsigned
    signer: Option<Box<dyn cose::CoseSigner + Send + Sync>>,
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
    Ok(Ledger {
        inner: Mutex::new(LedgerInner {
            f,
            consumed,
            head,
            seq,
        }),
        ledger_id: Vec::new(),
        signer: None,
    })
}

/// Open a WAL-backed ledger (as `open_ledger`) bound to its own ordering-authority identity
/// (`ledger_id`, the signer-id form of the ledger key) and signing key, so it can mint ledger-signed
/// consume receipts (T1.5, NAALP-REQ-121). A zero-length `ledger_id` is refused fail-closed (an
/// unnamed ordering authority cannot sign the anti-double-spend position).
pub fn open_ledger_signed(
    path: &std::path::Path,
    ledger_id: &[u8],
    signer: Box<dyn cose::CoseSigner + Send + Sync>,
) -> Result<Ledger, LedgerError> {
    if ledger_id.is_empty() {
        return Err(LedgerError::Cose(err_ledger_unsigned()));
    }
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(LedgerError::Io)?;
    let (consumed, head, seq) = replay(&mut f)?;
    Ok(Ledger {
        inner: Mutex::new(LedgerInner {
            f,
            consumed,
            head,
            seq,
        }),
        ledger_id: ledger_id.to_vec(),
        signer: Some(signer),
    })
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
        g.f.write_all(&(rec.len() as u32).to_be_bytes())
            .map_err(LedgerError::Io)?;
        g.f.write_all(&rec).map_err(LedgerError::Io)?;
        g.f.sync_all().map_err(LedgerError::Io)?; // persist-before-ack (R-7.2 durability)
        g.consumed.insert(approval_id.to_vec(), e.seq);
        g.head = chain_next(&rec);
        g.seq += 1;
        Ok(e)
    }

    /// Audience-checked consume choke point for a single-use object (design.md §2.5.3). Enforces the
    /// object's audience BEFORE the compare-and-set: a consume-once object MUST name THIS ordering
    /// authority (`ledger_id`) as its audience, or the consume is refused WrongAudience with NO ledger
    /// append (the federated double-consume guard). Requires a NAMED authority (open_ledger_signed);
    /// an unnamed ledger fails closed (LedgerUnsigned). The check runs at the point of use, never in
    /// `envelope::verify`. Byte-identical behaviour to impl/go.
    pub fn consume_object(
        &self,
        o: &crate::envelope::Object,
        approval_id: &[u8],
        by: &str,
    ) -> Result<LedgerEntry, LedgerError> {
        if self.ledger_id.is_empty() {
            return Err(LedgerError::Cose(err_ledger_unsigned()));
        }
        // Compare against the ledger's own authority id (matches Go's `o.Audience == string(l.ledgerID)`).
        let self_authority = String::from_utf8_lossy(&self.ledger_id);
        crate::envelope::check_audience(o, self_authority.as_ref(), true)
            .map_err(LedgerError::Cose)?;
        self.consume(approval_id, by)
    }

    /// Perform the first-append-wins compare-and-set (exactly as `consume`) AND, on the winning
    /// append, return a ledger-signed ConsumeReceipt binding the approval id to the entry's
    /// forward-only position (its ledger seq) (T1.5, NAALP-REQ-121). The ledger must have been opened
    /// with `open_ledger_signed`; a plain ledger returns LedgerUnsigned (fail-closed). A second
    /// consume of the same approval id returns AlreadyConsumed and mints nothing — the first receipt
    /// stands (first-append-wins). The mutex serialises concurrent callers, so under a race exactly
    /// one wins and exactly one receipt is minted.
    pub fn consume_with_receipt(
        &self,
        approval_id: &[u8],
        by: &str,
    ) -> Result<(LedgerEntry, ConsumeReceipt, Vec<u8>), LedgerError> {
        let signer = match &self.signer {
            Some(s) if !self.ledger_id.is_empty() => s,
            _ => return Err(LedgerError::Cose(err_ledger_unsigned())),
        };
        let mut g = self.inner.lock().expect("ledger mutex");
        if g.consumed.contains_key(approval_id) {
            return Err(LedgerError::Cose(err_already_consumed())); // first-append-wins: no second receipt
        }
        let e = LedgerEntry {
            seq: g.seq,
            prev: g.head.clone(),
            approval_id: approval_id.to_vec(),
            by: by.to_string(),
        };
        // The receipt binds the approval id to THIS consume's forward-only position (the entry seq),
        // signed by the ledger key (REQ-121).
        let receipt = ConsumeReceipt {
            ledger: self.ledger_id.clone(),
            approval_id: approval_id.to_vec(),
            position: e.seq,
        };
        let sig = signer.sign(&receipt.bytes());
        let rec = e.bytes();
        g.f.seek(SeekFrom::End(0)).map_err(LedgerError::Io)?;
        g.f.write_all(&(rec.len() as u32).to_be_bytes())
            .map_err(LedgerError::Io)?;
        g.f.write_all(&rec).map_err(LedgerError::Io)?;
        g.f.sync_all().map_err(LedgerError::Io)?; // persist-before-ack (R-7.2 durability)
        g.consumed.insert(approval_id.to_vec(), e.seq);
        g.head = chain_next(&rec);
        g.seq += 1;
        Ok((e, receipt, sig))
    }

    pub fn is_consumed(&self, approval_id: &[u8]) -> bool {
        self.inner
            .lock()
            .expect("ledger mutex")
            .consumed
            .contains_key(approval_id)
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

/// The draft-01 (T1.5, NAALP-REQ-121) ledger-signed evidence that a consuming ledger — the ORDERING
/// AUTHORITY — bound an approval content id to its own forward-only position. The anti-double-spend
/// counter (`position`) rides under the LEDGER's signature, never the requester's: the requester
/// cannot forge the ledger's position or its signature. A partition that spends one approval twice
/// leaves two ledger-signed receipts against one approval id, each carrying a position drawn from
/// forked state — a contradiction authored by neither the requester nor a thief, provable on
/// comparison (see ConsumeForkEvidence). It does not PREVENT the second spend; it makes the
/// double-spend detectable in bytes neither party could repudiate.
#[derive(Clone, Debug)]
pub struct ConsumeReceipt {
    pub ledger: Vec<u8>, // the consuming ledger's signer id (the ordering authority; REQ-121)
    pub approval_id: Vec<u8>, // the approval content id consumed (the compare-and-set key)
    pub position: u64,   // the ledger's forward-only position bound to this consume
}

impl ConsumeReceipt {
    /// Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position} —
    /// the exact bytes the ledger signs (T1.5).
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.ledger.clone())),
            (Value::Uint(2), Value::Bstr(self.approval_id.clone())),
            (Value::Uint(3), Value::Uint(self.position)),
        ]))
        .expect("encode consume receipt")
    }
}

/// Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is under the
/// ordering authority's signature). The signed input is the receipt `bytes()`.
pub fn sign_consume_receipt(r: &ConsumeReceipt, ledger_signer: &dyn cose::CoseSigner) -> Vec<u8> {
    ledger_signer.sign(&r.bytes())
}

/// Check that a consume receipt is a valid ledger-signed statement: the ledger id is present (an
/// unnamed ordering authority is not evidence) and the signature verifies under the ledger's key.
/// Fail-closed: either fault returns ConsumeReceiptUnsigned. `ledger_v` MUST be the verifier resolved
/// for `r.ledger`.
pub fn verify_consume_receipt(
    r: &ConsumeReceipt,
    ledger_v: &dyn cose::CoseVerifier,
    sig: &[u8],
) -> Result<(), cose::Error> {
    if r.ledger.is_empty() {
        return Err(err_consume_receipt_unsigned()); // an unnamed ordering authority is not evidence
    }
    if !ledger_v.verify_raw(&r.bytes(), sig) {
        return Err(err_consume_receipt_unsigned());
    }
    Ok(())
}

/// (R-TDCS-4, design.md §25) Judge an approval's present-moment validity using time drawn from an
/// ordering authority STRUCTURALLY DISTINCT from the party being authenticated. It is the named
/// realization of the §18.2 seam — "validity judged on the ordering position, never the signer's
/// clock" — composing the existing verifiers and adding the distinctness check a relying party runs
/// so a party can never be the source of the time against which its own credential's expiry is
/// judged. It (1) verifies the approval binds `args_content_id`, is signed by the approver, and is
/// unexpired at `pos_time`, where `pos_time` is the ORDERING AUTHORITY's forward-only position (never
/// a clock the approver supplies); (2) verifies the consume receipt is ledger-signed (the position
/// rides under the ordering authority's key, never the requester's); and (3) rejects
/// `FreshnessSelfAsserted` when the ordering authority `r.ledger` IS the authenticated party
/// `party_id`. Fail-closed: any fault returns its named error and authorizes nothing.
#[allow(clippy::too_many_arguments)]
pub fn verify_fresh_independent(
    a: &ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    a_sig: &[u8],
    args_content_id: &[u8],
    pos_time: u64,
    r: &ConsumeReceipt,
    ledger_v: &dyn cose::CoseVerifier,
    r_sig: &[u8],
    party_id: &[u8],
) -> Result<(), cose::Error> {
    verify_approval(a, approver_v, a_sig, args_content_id, pos_time)?;
    verify_consume_receipt(r, ledger_v, r_sig)?;
    if r.ledger == party_id {
        return Err(err_freshness_self_asserted());
    }
    Ok(())
}

/// The non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content id received TWO
/// conflicting ledger-signed consume receipts — a double spend made provable on comparison. It
/// carries both receipts and both ledger signatures; because a verifier checks each signature under
/// the key its receipt names, the contradiction is authored by neither the requester nor a thief.
#[derive(Clone, Debug)]
pub struct ConsumeForkEvidence {
    pub approval_id: Vec<u8>, // the one approval content id spent twice
    pub a: ConsumeReceipt,    // first receipt
    pub sig_a: Vec<u8>,       // ledger A's signature over a.bytes()
    pub b: ConsumeReceipt,    // second receipt (same approval id; different position and/or ledger)
    pub sig_b: Vec<u8>,       // ledger B's signature over b.bytes()
}

impl ConsumeForkEvidence {
    /// Check that this is a genuine fork: (1) the disputed approval id is present and BOTH receipts
    /// name it; (2) the two receipts actually conflict — they are NOT byte-identical (a byte-identical
    /// re-emission is a benign duplicate); and (3) BOTH ledger signatures verify — `va` for `a.ledger`
    /// and `vb` for `b.ledger` (same-ledger forks pass the one verifier as both). Any failure rejects
    /// the whole thing (fail-closed): a mismatched/absent approval id or a byte-identical pair is
    /// ConsumeForkInvalid, an unnamed ledger or a signature that does not verify is
    /// ConsumeReceiptUnsigned. On a clean pass the double spend is proven and non-repudiable.
    pub fn verify(
        &self,
        va: &dyn cose::CoseVerifier,
        vb: &dyn cose::CoseVerifier,
    ) -> Result<(), cose::Error> {
        if self.approval_id.is_empty() {
            return Err(err_consume_fork_invalid());
        }
        if self.a.approval_id != self.approval_id || self.b.approval_id != self.approval_id {
            return Err(err_consume_fork_invalid()); // both receipts must name the disputed approval id
        }
        if self.a.bytes() == self.b.bytes() {
            return Err(err_consume_fork_invalid()); // byte-identical receipts are a benign duplicate
        }
        if self.a.ledger.is_empty() || self.b.ledger.is_empty() {
            return Err(err_consume_receipt_unsigned());
        }
        if !va.verify_raw(&self.a.bytes(), &self.sig_a)
            || !vb.verify_raw(&self.b.bytes(), &self.sig_b)
        {
            return Err(err_consume_receipt_unsigned());
        }
        Ok(()) // a valid, non-repudiable double-spend proof
    }
}

/// A receipt the ReceiptSet has accepted, kept with its signature so a later conflict can be minted
/// into a ConsumeForkEvidence carrying BOTH ledger signatures.
#[derive(Clone)]
struct SeenConsumeReceipt {
    r: ConsumeReceipt,
    sig: Vec<u8>,
}

/// Observes ledger-signed consume receipts, keyed by approval content id, and detects a fork (a
/// double spend) from the signed receipts alone (T1.5, NAALP-REQ-121) — the consume-layer analogue of
/// the audit auditor's equivocation detection. Each `observe` call carries the verifier resolved for
/// that receipt's ledger (mirroring the audit `Auditor`); a receipt whose ledger signature does not
/// verify is rejected, and a conflicting second receipt for one approval id mints a non-repudiable
/// ConsumeForkEvidence.
#[derive(Default)]
pub struct ReceiptSet {
    seen: HashMap<Vec<u8>, SeenConsumeReceipt>, // approval-id -> first receipt seen
}

impl ReceiptSet {
    pub fn new() -> Self {
        ReceiptSet {
            seen: HashMap::new(),
        }
    }

    /// Record a ledger-signed consume receipt, verifying it under `v` (the verifier for r.ledger).
    /// Returns `(None, Err(ConsumeReceiptUnsigned))` if the ledger is unnamed or the signature does
    /// not verify; `(Some(evidence), Err(ConsumeFork))` when a previously-seen receipt for the same
    /// approval id conflicts (different position and/or ledger); and `(None, Ok(()))` otherwise
    /// (including a benign byte-identical duplicate).
    pub fn observe(
        &mut self,
        v: &dyn cose::CoseVerifier,
        r: &ConsumeReceipt,
        sig: &[u8],
    ) -> (Option<ConsumeForkEvidence>, Result<(), cose::Error>) {
        if r.ledger.is_empty() || !v.verify_raw(&r.bytes(), sig) {
            return (None, Err(err_consume_receipt_unsigned()));
        }
        if let Some(prev) = self.seen.get(&r.approval_id) {
            if prev.r.bytes() == r.bytes() {
                return (None, Ok(())); // benign byte-identical duplicate
            }
            let fe = ConsumeForkEvidence {
                approval_id: r.approval_id.clone(),
                a: prev.r.clone(),
                sig_a: prev.sig.clone(),
                b: r.clone(),
                sig_b: sig.to_vec(),
            };
            return (Some(fe), Err(err_consume_fork()));
        }
        self.seen.insert(
            r.approval_id.clone(),
            SeenConsumeReceipt {
                r: r.clone(),
                sig: sig.to_vec(),
            },
        );
        (None, Ok(()))
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
                    audience: String::new(),
                };
            }
        }
        panic!("no approval {}", name);
    }

    fn keypair(seed: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk))
    }

    // consume_approval runs the draft "## Approval state machine" precedence in one place. This test
    // exercises every reaction and the two precedence rules (mismatch over every cell; expiry over
    // AlreadyConsumed), plus the effect-ceiling / grant-range / bad-signature refusals, and asserts the
    // ledger length so a mutant that returns the right Kind but still appends is caught. Reactions are
    // the draft's, not read off the code.
    #[test]
    fn consume_approval_precedence() {
        let (v, s) = keypair(7);
        let args_cid = b"args-content-id-A".to_vec();
        let wrong_cid = b"args-content-id-B".to_vec();
        let mk = |grant: u64, not_after: u64| -> (ApprovalRecord, Vec<u8>) {
            let a = ApprovalRecord {
                approves: args_cid.clone(),
                approver: "approver-1".into(),
                grant,
                nonce: vec![0x01, 0x02],
                not_after,
                audience: String::new(),
            };
            let sig = sign_approval(&a, &s);
            (a, sig)
        };
        let kind = |r: &Result<LedgerEntry, LedgerError>| -> Option<String> {
            match r {
                Err(e) => e.cose_kind().map(|k| k.to_string()),
                Ok(_) => None,
            }
        };

        // approved + consume -> consumed (len 1); a second consume -> AlreadyConsumed (len stays 1).
        {
            let (a, sig) = mk(policy::DESTRUCTIVE as u64, 1000);
            let l = open_ledger(&tmp_wal("ca-consumed")).unwrap();
            consume_approval(&a, &v, &sig, &args_cid, 500, policy::READ_ONLY, &l, "by")
                .expect("valid consume");
            assert_eq!(l.len(), 1);
            let r = consume_approval(&a, &v, &sig, &args_cid, 500, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("AlreadyConsumed"));
            assert_eq!(l.len(), 1);
        }
        // expired + consume -> ApprovalExpired; nothing appended.
        {
            let (a, sig) = mk(policy::DESTRUCTIVE as u64, 1000);
            let l = open_ledger(&tmp_wal("ca-expired")).unwrap();
            let r = consume_approval(&a, &v, &sig, &args_cid, 2000, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("ApprovalExpired"));
            assert_eq!(l.len(), 0);
        }
        // expiry over consume: success, then a second past not_after -> ApprovalExpired (never
        // AlreadyConsumed), ledger untouched (len stays 1).
        {
            let (a, sig) = mk(policy::DESTRUCTIVE as u64, 1000);
            let l = open_ledger(&tmp_wal("ca-eoc")).unwrap();
            consume_approval(&a, &v, &sig, &args_cid, 500, policy::READ_ONLY, &l, "by").unwrap();
            let r = consume_approval(&a, &v, &sig, &args_cid, 2000, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("ApprovalExpired"));
            assert_eq!(l.len(), 1);
        }
        // mismatch over every cell (fresh, and over an also-expired approval); no append.
        {
            let (a, sig) = mk(policy::DESTRUCTIVE as u64, 1000);
            let l = open_ledger(&tmp_wal("ca-mismatch")).unwrap();
            let r = consume_approval(&a, &v, &sig, &wrong_cid, 500, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("ApprovalMismatch"));
            let r2 = consume_approval(&a, &v, &sig, &wrong_cid, 2000, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r2).as_deref(), Some("ApprovalMismatch")); // mismatch before expiry
            assert_eq!(l.len(), 0);
        }
        // a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
        {
            let (a, sig) = mk(policy::DESTRUCTIVE as u64, 1000);
            let l = open_ledger(&tmp_wal("ca-reject-then-valid")).unwrap();
            assert!(consume_approval(&a, &v, &sig, &wrong_cid, 500, policy::READ_ONLY, &l, "by").is_err());
            assert_eq!(l.len(), 0);
            consume_approval(&a, &v, &sig, &args_cid, 500, policy::READ_ONLY, &l, "by")
                .expect("valid after rejected mismatch");
            assert_eq!(l.len(), 1);
        }
        // effect ceiling: granted effect below the action's required effect -> ApprovalRequired.
        {
            let (a, sig) = mk(policy::READ_ONLY as u64, 1000);
            let l = open_ledger(&tmp_wal("ca-under-grant")).unwrap();
            let r = consume_approval(&a, &v, &sig, &args_cid, 500, policy::DESTRUCTIVE, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("ApprovalRequired"));
            assert_eq!(l.len(), 0);
        }
        // grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
        {
            let (a, sig) = mk(7, 1000);
            let l = open_ledger(&tmp_wal("ca-malformed-grant")).unwrap();
            let r = consume_approval(&a, &v, &sig, &args_cid, 500, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("ApprovalRequired"));
            assert_eq!(l.len(), 0);
        }
        // bad signature (checked first) -> BadSignature.
        {
            let (a, sig) = mk(policy::DESTRUCTIVE as u64, 1000);
            let mut bad = sig.clone();
            let n = bad.len();
            bad[n - 1] ^= 0x01;
            let l = open_ledger(&tmp_wal("ca-bad-sig")).unwrap();
            let r = consume_approval(&a, &v, &bad, &args_cid, 500, policy::READ_ONLY, &l, "by");
            assert_eq!(kind(&r).as_deref(), Some("BadSignature"));
            assert_eq!(l.len(), 0);
        }
    }

    #[test]
    fn approval_bytes_match_oracle() {
        let c = load();
        let approvals = c["approvals"].as_array().unwrap();
        assert!(!approvals.is_empty());
        for a in approvals {
            let rec = rec_of(&c, a["name"].as_str().unwrap());
            assert_eq!(hex::encode(rec.bytes()), a["record_hex"].as_str().unwrap());
            assert_eq!(
                hex::encode(rec.id()),
                a["approval_id_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn ledger_scenario_matches_oracle() {
        let c = load();
        let l = open_ledger(&tmp_wal("scenario")).unwrap();
        assert_eq!(
            hex::encode(l.head()),
            c["ledger"]["genesis_head_hex"].as_str().unwrap()
        );
        for cons in c["ledger"]["consumes"].as_array().unwrap() {
            let id = hexd(cons["approval_id_hex"].as_str().unwrap());
            let by = cons["by"].as_str().unwrap();
            match cons["expect"].as_str().unwrap() {
                "ok" => {
                    let e = l.consume(&id, by).expect("consume ok");
                    assert_eq!(e.seq, cons["seq"].as_u64().unwrap());
                    assert_eq!(hex::encode(e.bytes()), cons["entry_hex"].as_str().unwrap());
                    assert_eq!(
                        hex::encode(l.head()),
                        cons["head_after_hex"].as_str().unwrap()
                    );
                }
                "AlreadyConsumed" => {
                    let err = l.consume(&id, by).unwrap_err();
                    assert_eq!(err.cose_kind(), Some("AlreadyConsumed"));
                }
                other => panic!("unknown expect {}", other),
            }
        }
        assert_eq!(
            hex::encode(l.head()),
            c["ledger"]["final_head_hex"].as_str().unwrap()
        );
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
        assert_eq!(
            l2.consume(&id_a, "c2").unwrap_err().cose_kind(),
            Some("AlreadyConsumed")
        );
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
            let (l, id, b, w, a) = (
                l.clone(),
                id_a.clone(),
                barrier.clone(),
                wins.clone(),
                already.clone(),
            );
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

        verify_approval(
            &rec,
            &v,
            &sig,
            &args_id,
            c["expiry"]["valid_at"].as_u64().unwrap(),
        )
        .expect("valid approval");
        // R-7.1: mutated args -> content id no longer matches.
        let wrong = hexd(c["mismatch"]["wrong_args_id_hex"].as_str().unwrap());
        assert_eq!(
            verify_approval(
                &rec,
                &v,
                &sig,
                &wrong,
                c["expiry"]["valid_at"].as_u64().unwrap()
            )
            .unwrap_err()
            .kind,
            "ApprovalMismatch"
        );
        // R-7.3: expired after not_after.
        assert_eq!(
            verify_approval(
                &rec,
                &v,
                &sig,
                &args_id,
                c["expiry"]["expired_at"].as_u64().unwrap()
            )
            .unwrap_err()
            .kind,
            "ApprovalExpired"
        );
        // tampered signature -> BadSignature.
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            verify_approval(
                &rec,
                &v,
                &bad,
                &args_id,
                c["expiry"]["valid_at"].as_u64().unwrap()
            )
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
        let e0 = LedgerEntry {
            seq: 0,
            prev: genesis.clone(),
            approval_id: id_a,
            by: "c1".into(),
        };
        // e1's prev is left at genesis instead of SHA-384(e0) — a broken link.
        let e1_bad = LedgerEntry {
            seq: 1,
            prev: genesis,
            approval_id: id_b,
            by: "c1".into(),
        };
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

    // ---- T1.5 (NAALP-REQ-121): ledger-signed consume receipt with forward-only position --------

    const CR_VECTOR_PATH: &str = "../../vectors/consume_receipt/cases.json";

    fn load_cr() -> J {
        serde_json::from_str(&std::fs::read_to_string(CR_VECTOR_PATH).expect("read cr corpus"))
            .expect("parse cr corpus")
    }

    // R12 (NAALP-01-03): a 64-bit position carried as a JSON number OR (values above 2^53) a
    // decimal string, so a float64 decoder cannot round the low octets before this exact parse.
    fn u64_flex(v: &J) -> u64 {
        v.as_u64()
            .unwrap_or_else(|| v.as_str().expect("position number or string").parse().unwrap())
    }

    fn cr_receipt(j: &J) -> ConsumeReceipt {
        ConsumeReceipt {
            ledger: hexd(j["ledger_hex"].as_str().unwrap()),
            approval_id: hexd(j["approval_id_hex"].as_str().unwrap()),
            position: u64_flex(&j["position"]),
        }
    }

    // consume_receipt_bytes_match_oracle: every receipt body is byte-identical to the independent
    // oracle (⟹ Go == Rust, which grade the same file).
    #[test]
    fn consume_receipt_bytes_match_oracle() {
        let c = load_cr();
        let mut all = vec![c["base"].clone()];
        for s in c["sequence"].as_array().unwrap() {
            all.push(s.clone());
        }
        for f in c["forks"].as_array().unwrap() {
            all.push(f["a"].clone());
            all.push(f["b"].clone());
        }
        assert!(!all.is_empty());
        for rj in &all {
            let got = hex::encode(cr_receipt(rj).bytes());
            assert_eq!(
                got,
                rj["body_hex"].as_str().unwrap(),
                "receipt body mismatch"
            );
        }
    }

    // consume_receipt_sign_verify: a ledger-signed receipt verifies under the ledger key; an unnamed
    // ledger, a tampered signature, and the wrong ledger key are each rejected fail-closed.
    #[test]
    fn consume_receipt_sign_verify() {
        let c = load_cr();
        let (v, s) = keypair(0x51);
        let r = cr_receipt(&c["base"]);
        let sig = sign_consume_receipt(&r, &s);
        verify_consume_receipt(&r, &v, &sig).expect("valid ledger-signed receipt");

        let mut unnamed = r.clone();
        unnamed.ledger = Vec::new();
        assert_eq!(
            verify_consume_receipt(&unnamed, &v, &sig).unwrap_err().kind,
            "ConsumeReceiptUnsigned"
        );

        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            verify_consume_receipt(&r, &v, &bad).unwrap_err().kind,
            "ConsumeReceiptUnsigned"
        );

        let (other_v, _s2) = keypair(0x52);
        assert_eq!(
            verify_consume_receipt(&r, &other_v, &sig).unwrap_err().kind,
            "ConsumeReceiptUnsigned"
        );
    }

    // consume_fork_detected (case a): two ledger-signed receipts for the SAME approval id with
    // DIFFERENT positions are detected as a fork; the surfaced evidence carries BOTH positions and
    // verifies as a non-repudiable double-spend proof. A byte-identical re-emission is benign.
    #[test]
    fn consume_fork_detected() {
        let c = load_cr();
        let fk = c["forks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "same_ledger_diff_position")
            .expect("same_ledger_diff_position case");
        assert_eq!(fk["expect"], "fork");
        let (v, s) = keypair(0x41); // one ledger signs both conflicting positions (a partition)
        let ra = cr_receipt(&fk["a"]);
        let rb = cr_receipt(&fk["b"]);
        let sig_a = sign_consume_receipt(&ra, &s);
        let sig_b = sign_consume_receipt(&rb, &s);

        let mut rs = ReceiptSet::new();
        assert!(rs.observe(&v, &ra, &sig_a).0.is_none());
        let (fe, res) = rs.observe(&v, &rb, &sig_b);
        let fe = fe.expect("fork not detected on same approval id / different positions");
        assert_eq!(res.unwrap_err().kind, "ConsumeFork");
        assert_ne!(
            fe.a.position, fe.b.position,
            "fork evidence hides the position conflict"
        );
        fe.verify(&v, &v).expect("fork evidence must verify");

        // a byte-identical re-emission is a benign duplicate, never flagged.
        let mut rs2 = ReceiptSet::new();
        let _ = rs2.observe(&v, &ra, &sig_a);
        assert!(
            rs2.observe(&v, &ra, &sig_a).0.is_none(),
            "benign duplicate flagged"
        );
    }

    // consume_fork_cross_ledger (case b): two DIFFERENT ledgers each sign a receipt for the SAME
    // approval id (a single-use approval spent twice), run concurrently on independent ledgers;
    // comparing the two receipts surfaces the fork.
    #[test]
    fn consume_fork_cross_ledger() {
        let c = load_cr();
        let ledger_a_id = hexd(c["ledgers"]["a_hex"].as_str().unwrap());
        let ledger_b_id = hexd(c["ledgers"]["b_hex"].as_str().unwrap());
        let approval_x = hexd(c["approvals"]["x_hex"].as_str().unwrap());
        let (va, sa) = keypair(0x41);
        let (vb, sb) = keypair(0x42);

        let l_a =
            Arc::new(open_ledger_signed(&tmp_wal("cross_a"), &ledger_a_id, Box::new(sa)).unwrap());
        let l_b =
            Arc::new(open_ledger_signed(&tmp_wal("cross_b"), &ledger_b_id, Box::new(sb)).unwrap());

        // two independent ordering authorities, run concurrently; each consumes approval X locally
        // (the double spend is not prevented, only made provable on comparison).
        let mut handles = Vec::new();
        for l in [l_a.clone(), l_b.clone()] {
            let ax = approval_x.clone();
            handles.push(std::thread::spawn(move || {
                let (_e, r, sig) = l
                    .consume_with_receipt(&ax, "requester")
                    .expect("independent consume");
                (r, sig)
            }));
        }
        let results: Vec<(ConsumeReceipt, Vec<u8>)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // resolve each receipt's ledger verifier by its ledger id, feed both to the detector.
        let verifier_for = |id: &[u8]| -> &dyn cose::CoseVerifier {
            if id == ledger_a_id.as_slice() {
                &va
            } else {
                &vb
            }
        };
        let mut rs = ReceiptSet::new();
        let mut fork: Option<ConsumeForkEvidence> = None;
        for (r, sig) in &results {
            let (fe, err) = rs.observe(verifier_for(&r.ledger), r, sig);
            if let Some(fe) = fe {
                assert_eq!(err.unwrap_err().kind, "ConsumeFork");
                fork = Some(fe);
            }
        }
        let fork = fork.expect("cross-ledger double spend not detected");
        assert_ne!(
            fork.a.ledger, fork.b.ledger,
            "cross-ledger evidence names one ledger twice"
        );
        fork.verify(verifier_for(&fork.a.ledger), verifier_for(&fork.b.ledger))
            .expect("cross-ledger fork evidence must verify");
    }

    // consume_first_append_wins_cas (case c): the compare-and-set MUTATION anchor. On one honest
    // signed ledger, consuming the same approval id twice yields exactly ONE receipt at position 0;
    // the second returns AlreadyConsumed and mints nothing. If the CAS is mutated to always-succeed,
    // the second consume mints a SECOND receipt at position 1 and this test's assertions flip.
    #[test]
    fn consume_first_append_wins_cas() {
        let c = load_cr();
        let ledger_a_id = hexd(c["ledgers"]["a_hex"].as_str().unwrap());
        let approval_x = hexd(c["approvals"]["x_hex"].as_str().unwrap());
        let (_v, s) = keypair(0x41);
        let l = open_ledger_signed(&tmp_wal("cas"), &ledger_a_id, Box::new(s)).unwrap();

        let (e, r1, _sig1) = l
            .consume_with_receipt(&approval_x, "requester")
            .expect("first consume");
        assert_eq!(e.seq, 0);
        assert_eq!(r1.position, 0);

        let err = l
            .consume_with_receipt(&approval_x, "requester")
            .unwrap_err();
        assert_eq!(
            err.cose_kind(),
            Some("AlreadyConsumed"),
            "second consume must be first-append-wins"
        );
        assert_eq!(l.len(), 1, "ledger must have exactly one entry");
    }

    // consume_receipt_exactly_once_under_race: N threads consume the same approval id on one signed
    // ledger; exactly one wins and mints one receipt, the rest get AlreadyConsumed.
    #[test]
    fn consume_receipt_exactly_once_under_race() {
        let c = load_cr();
        let ledger_a_id = hexd(c["ledgers"]["a_hex"].as_str().unwrap());
        let approval_x = Arc::new(hexd(c["approvals"]["x_hex"].as_str().unwrap()));
        let (v, s) = keypair(0x41);
        let l = Arc::new(open_ledger_signed(&tmp_wal("race"), &ledger_a_id, Box::new(s)).unwrap());

        const NTHREADS: usize = 64;
        let barrier = Arc::new(Barrier::new(NTHREADS));
        let wins = Arc::new(AtomicU64::new(0));
        let already = Arc::new(AtomicU64::new(0));
        let winner: Arc<Mutex<Option<(ConsumeReceipt, Vec<u8>)>>> = Arc::new(Mutex::new(None));
        let mut handles = Vec::new();
        for _ in 0..NTHREADS {
            let (l, id, b, w, a, win) = (
                l.clone(),
                approval_x.clone(),
                barrier.clone(),
                wins.clone(),
                already.clone(),
                winner.clone(),
            );
            handles.push(std::thread::spawn(move || {
                b.wait();
                match l.consume_with_receipt(&id, "requester") {
                    Ok((_e, r, sig)) => {
                        w.fetch_add(1, Ordering::SeqCst);
                        *win.lock().unwrap() = Some((r, sig));
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
        // the single minted receipt is not a fork with itself.
        let w = winner.lock().unwrap().clone().expect("a winner");
        let mut rs = ReceiptSet::new();
        assert!(
            rs.observe(&v, &w.0, &w.1).0.is_none(),
            "sole winning receipt flagged"
        );
    }

    // consume_receipt_wire_cases: keys out of order (NonCanonical at the CBOR layer), a position too
    // large for a normal int (64-bit uint round-trip), and empty-value vs absent-value (empty !=
    // absent; empty ledger id is verify-rejected fail-closed).
    #[test]
    fn consume_receipt_wire_cases() {
        let c = load_cr();

        // keys out of order -> the strict decoder rejects NonCanonical.
        let noncanon = hexd(
            c["wire"]["keys_out_of_order"]["payload_hex"]
                .as_str()
                .unwrap(),
        );
        assert_eq!(cbor::decode(&noncanon).unwrap_err().kind, "NonCanonical");
        // the canonical variant decodes cleanly.
        let canon = hexd(
            c["wire"]["keys_out_of_order"]["canonical_payload_hex"]
                .as_str()
                .unwrap(),
        );
        cbor::decode(&canon).expect("canonical receipt body");

        // position too large: 64-bit uint round-trips (encode == oracle, decode == value).
        let ledger_x = hexd(c["base"]["ledger_hex"].as_str().unwrap());
        let approval_x = hexd(c["base"]["approval_id_hex"].as_str().unwrap());
        for big in c["wire"]["position_too_large"].as_array().unwrap() {
            let pos = u64_flex(&big["position"]);
            let r = ConsumeReceipt {
                ledger: ledger_x.clone(),
                approval_id: approval_x.clone(),
                position: pos,
            };
            assert_eq!(
                hex::encode(r.bytes()),
                big["body_hex"].as_str().unwrap(),
                "big position encode"
            );
            let v = cbor::decode(&hexd(big["body_hex"].as_str().unwrap()))
                .expect("decode big position");
            let m = match v {
                Value::Map(m) => m,
                _ => panic!("not a map"),
            };
            let got = m.iter().find_map(|(k, val)| match (k, val) {
                (Value::Uint(3), Value::Uint(p)) => Some(*p),
                _ => None,
            });
            assert_eq!(got, Some(pos), "position round-trip");
        }

        // empty-ledger receipt: matches the oracle bytes, is verify-rejected fail-closed, and its
        // bytes differ from the absent-ledger variant (empty != absent).
        let el = &c["wire"]["empty_ledger"];
        let empty = ConsumeReceipt {
            ledger: Vec::new(),
            approval_id: hexd(el["approval_id_hex"].as_str().unwrap()),
            position: u64_flex(&el["position"]),
        };
        assert_eq!(hex::encode(empty.bytes()), el["body_hex"].as_str().unwrap());
        let (v, _s) = keypair(0x41);
        assert_eq!(
            verify_consume_receipt(&empty, &v, &[]).unwrap_err().kind,
            "ConsumeReceiptUnsigned"
        );
        assert_ne!(
            el["body_hex"].as_str().unwrap(),
            c["wire"]["absent_ledger"]["body_hex"].as_str().unwrap(),
            "empty != absent"
        );
    }

    // ---- R-TDCS-4 / R-TDCS-2 (design.md §25, C22): trust-decision closure sovereignty --------
    //
    // Behavioral graders for two trust-decision closure-sovereignty requirements:
    //   - R-TDCS-4 (freshness independence): a credential's present-moment validity is judged
    //     against an ordering authority STRUCTURALLY DISTINCT from the party being authenticated; a
    //     party stamping its own freshness is rejected FreshnessSelfAsserted.
    //   - R-TDCS-2 (deterministic verification): verification is a pure function of (object, key,
    //     pos_time) — the same inputs yield the same verdict on every call, with no dependence on a
    //     clock, RNG, map order, or call count.
    //
    // Each is mutation-surviving: removing the R-TDCS-4 distinctness check flips
    // tdcs4_freshness_independence, and injecting nondeterminism into verify_approval flips
    // tdcs2_verification_determinism (recorded in .shippable/red-evidence).

    // fresh_scenario builds a valid signed approval and a ledger-signed consume receipt for it, with
    // the approver, the ordering-authority ledger, and (returned separately) an authenticated-party id
    // that the caller chooses distinct or self-referential. pos_time is set at the approval's
    // not_after (still valid). ledger_id is the ordering authority's id; approver_id is the
    // authenticated party's id.
    #[allow(clippy::type_complexity)]
    fn fresh_scenario() -> (
        ApprovalRecord,
        cose::MlDsa65Verifier,
        Vec<u8>,
        Vec<u8>,
        u64,
        ConsumeReceipt,
        cose::MlDsa65Verifier,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        let (approver_v, approver_s) = keypair(0x11); // the approver's key (the authenticated party)
        let (ledger_v, ledger_s) = keypair(0x22); // the ordering authority (ledger) — a DISTINCT key
        let args_id = b"the-exact-canonical-args-content-id".to_vec();
        let approver_id = b"approver-authenticated-party-id".to_vec();
        let ledger_id = b"ordering-authority-ledger-id".to_vec();
        let a = ApprovalRecord {
            approves: args_id.clone(),
            approver: "approver-authenticated-party-id".to_string(),
            grant: 1,
            nonce: b"anti-replay-nonce".to_vec(),
            not_after: 1000,
            audience: String::new(),
        };
        let sig = sign_approval(&a, &approver_s);
        let r = ConsumeReceipt {
            ledger: ledger_id.clone(),
            approval_id: a.id(),
            position: 7,
        };
        let r_sig = sign_consume_receipt(&r, &ledger_s);
        (
            a,
            approver_v,
            sig,
            args_id,
            1000,
            r,
            ledger_v,
            r_sig,
            ledger_id,
            approver_id,
        )
    }

    // tdcs4_freshness_independence: R-TDCS-4. When the ordering authority is distinct from the
    // authenticated party, an unexpired, correctly-signed approval with a valid ledger receipt
    // verifies. When the ordering authority IS the authenticated party (the party stamping its own
    // freshness), it is rejected FreshnessSelfAsserted — the load-bearing distinctness the closure
    // property requires.
    #[test]
    fn tdcs4_freshness_independence() {
        let (a, approver_v, a_sig, args_id, pos_time, r, ledger_v, r_sig, ledger_id, approver_id) =
            fresh_scenario();

        // Distinct ordering authority (party != ledger): verifies.
        verify_fresh_independent(
            &a,
            &approver_v,
            &a_sig,
            &args_id,
            pos_time,
            &r,
            &ledger_v,
            &r_sig,
            &approver_id,
        )
        .expect("distinct ordering authority should verify");

        // Self-asserted freshness (party == ledger): the party is the source of its own time —
        // rejected.
        match verify_fresh_independent(
            &a,
            &approver_v,
            &a_sig,
            &args_id,
            pos_time,
            &r,
            &ledger_v,
            &r_sig,
            &ledger_id,
        ) {
            Err(e) => assert_eq!(e.kind, "FreshnessSelfAsserted"),
            Ok(()) => panic!(
                "self-asserted freshness (party == ordering authority) must be rejected, got Ok"
            ),
        }

        // The distinctness check does not weaken the underlying checks: an expired approval still
        // fails closed (pos_time past not_after), and a distinct authority does not rescue it.
        match verify_fresh_independent(
            &a,
            &approver_v,
            &a_sig,
            &args_id,
            a.not_after + 1,
            &r,
            &ledger_v,
            &r_sig,
            &approver_id,
        ) {
            Err(e) => assert_eq!(e.kind, "ApprovalExpired"),
            Ok(()) => panic!("expired approval must still be rejected under a distinct authority"),
        }

        // A receipt with no named ordering authority is not evidence (unnamed authority), even when
        // the party id supplied is distinct.
        let (_, other_ledger_s) = keypair(0x33);
        let empty = ConsumeReceipt {
            ledger: Vec::new(),
            approval_id: a.id(),
            position: 7,
        };
        let empty_sig = sign_consume_receipt(&empty, &other_ledger_s);
        match verify_fresh_independent(
            &a,
            &approver_v,
            &a_sig,
            &args_id,
            pos_time,
            &empty,
            &ledger_v,
            &empty_sig,
            &approver_id,
        ) {
            Err(e) => assert_eq!(e.kind, "ConsumeReceiptUnsigned"),
            Ok(()) => {
                panic!("unnamed ordering authority must not be accepted as freshness evidence")
            }
        }
    }

    // tdcs2_verification_determinism: R-TDCS-2. verify_approval is a pure function of its inputs —
    // the same (approval, key, args, pos_time) yields the same verdict on every call. Calling it many
    // times, interleaving accept and reject inputs, must return the identical verdict each time,
    // proving the verify path depends on no clock, RNG, map iteration order, or call count. Injecting
    // nondeterminism into the verify path flips this (recorded red-evidence).
    #[test]
    fn tdcs2_verification_determinism() {
        let (approver_v, approver_s) = keypair(0x11);
        let args_id = b"the-exact-canonical-args-content-id".to_vec();
        let wrong = b"a-different-args-content-id-------".to_vec();
        let a = ApprovalRecord {
            approves: args_id.clone(),
            approver: "approver".to_string(),
            grant: 1,
            nonce: b"nonce".to_vec(),
            not_after: 1000,
            audience: String::new(),
        };
        let sig = sign_approval(&a, &approver_s);

        const ITERS: usize = 256;
        // Accept path: identical Ok verdict every time; and the signed body bytes are byte-stable.
        let want_body = a.bytes();
        for i in 0..ITERS {
            if let Err(e) = verify_approval(&a, &approver_v, &sig, &args_id, 500) {
                panic!(
                    "iter {i}: valid approval verdict changed to {e:?} (non-deterministic accept)"
                );
            }
            let got = a.bytes();
            assert_eq!(
                got, want_body,
                "iter {i}: encoding is not byte-stable (non-deterministic serialization)"
            );
            // Interleave a reject input to prove no cross-call state leaks between verdicts.
            match verify_approval(&a, &approver_v, &sig, &wrong, 500) {
                Ok(()) => {
                    panic!("iter {i}: wrong-args approval accepted (non-deterministic reject)")
                }
                Err(e) => assert_eq!(
                    e.kind, "ApprovalMismatch",
                    "iter {i}: reject verdict changed to {e:?} (non-deterministic reject)"
                ),
            }
        }
    }

    // ---- R-TDCS-5 (design.md §25, C22): the OPTIONAL audience field on ApprovalRecord ---------
    //
    // Graded against the independent oracle vectors/trust_decision/cases.json (built by
    // tools/trust_decision_oracle.py, non-circular per F3). Go and Rust grade the SAME file, so
    // Go == Rust == oracle bytes. verify_audience is mutation-surviving: removing the mismatch
    // check flips tdcs5_audience_byte_parity_and_check's mismatch assertion (recorded red-evidence).

    const TDCS_WIRE_PATH: &str = "../../vectors/trust_decision/cases.json";

    fn load_tdcs_wire() -> J {
        serde_json::from_str(
            &std::fs::read_to_string(TDCS_WIRE_PATH).expect("read tdcs wire corpus"),
        )
        .expect("parse tdcs wire corpus")
    }

    #[test]
    fn tdcs5_audience_byte_parity_and_check() {
        let c = load_tdcs_wire();
        let a = &c["audience"];
        let approves = hexd(a["approves_hex"].as_str().unwrap());
        let approver = a["approver"].as_str().unwrap().to_string();
        let grant = a["grant"].as_u64().unwrap();
        let nonce = hexd(a["nonce_hex"].as_str().unwrap());
        let not_after = a["not_after"].as_u64().unwrap();
        let use_context_match = a["use_context_match"].as_str().unwrap();
        let use_context_mismatch = a["use_context_mismatch"].as_str().unwrap();

        for tc in a["cases"].as_array().unwrap() {
            let rec = ApprovalRecord {
                approves: approves.clone(),
                approver: approver.clone(),
                grant,
                nonce: nonce.clone(),
                not_after,
                audience: tc["audience"].as_str().unwrap().to_string(), // "" for audience_absent
            };
            let name = tc["name"].as_str().unwrap();
            assert_eq!(
                hex::encode(rec.bytes()),
                tc["record_hex"].as_str().unwrap(),
                "{name}: approval bytes != oracle"
            );
            assert_eq!(
                hex::encode(rec.id()),
                tc["approval_id_hex"].as_str().unwrap(),
                "{name}: approval id != oracle"
            );
        }

        // A named audience must differ from the absent-audience bytes — naming a context changes
        // the signed bytes, so a verdict cannot be silently moved to another context.
        let present = ApprovalRecord {
            approves: approves.clone(),
            approver: approver.clone(),
            grant,
            nonce: nonce.clone(),
            not_after,
            audience: use_context_match.to_string(),
        };
        let absent = ApprovalRecord {
            approves: approves.clone(),
            approver: approver.clone(),
            grant,
            nonce: nonce.clone(),
            not_after,
            audience: String::new(),
        };
        assert_ne!(
            present.bytes(),
            absent.bytes(),
            "naming an audience must change the approval bytes"
        );

        // The check: named audience must match the use context; absent audience passes any context.
        verify_audience(&present, use_context_match).expect("matching audience should verify");
        assert_eq!(
            verify_audience(&present, use_context_mismatch)
                .unwrap_err()
                .kind,
            "AudienceMismatch",
            "mismatched audience must be rejected"
        );
        verify_audience(&absent, use_context_mismatch)
            .expect("an approval that names no audience must pass any context");
    }
}
