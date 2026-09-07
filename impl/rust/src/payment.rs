// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C21 task 5B.1 — NAALP-PAY payment import (design.md §24; R-PAY-1..6). The Rust half of the
//! two-implementation parity; byte-identical to impl/go/payment.
//!
//! NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol
//! delegated token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not
//! adoption) and turns it into a value-bearing charge N-AALP governs with its OWN added guarantees.
//! It introduces NO new envelope, encoding, signature, identity, effect, or ledger mechanism (R-11.3):
//! it reuses the closed C5 effect lattice (policy), the §7 approval object, and the §7 single-use
//! consume ledger (crate::approval) UNCHANGED. There is NO fifth effect and NO payment-specific ledger.
//!
//!   - `PaymentImport` {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} carries
//!     the imported payload octet-for-octet; `format` selects the imported FORMAT from the closed
//!     payment-format registry. An unknown format is rejected (UnknownPaymentFormat).
//!   - `ChargeBinding` {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign_id} names
//!     the exact value a §7 approval binds by content id (including the foreign payload's content id).
//!     A wrong amount/payee/currency or a substituted payload changes the content id — a prior approval
//!     no longer matches (ApprovalMismatch).
//!   - `authorize_charge` verifies the approval binds the exact charge, requires the grant to cover the
//!     charge's `CHARGE_EFFECT` (a non_idempotent_write), and consumes the approval SINGLE-USE through
//!     the §7 ledger — a replay is AlreadyConsumed.
//!
//! Every check is fail-closed (§15): a failing charge is rejected whole, returns its named error, and
//! causes no state change (no ledger append).

use sha2::{Digest, Sha384};

use crate::approval;
use crate::cbor::{self, Value};
use crate::cose;
use crate::policy;

/// Width of a head / content-id digest (SHA-384 = 48 bytes).
pub const HEAD_SIZE: usize = 48;

/// The C5 effect a payment spend carries: a non_idempotent_write (value-bearing, not safely
/// repeatable — hence spent single-use through the §7 ledger; the grant must cover this).
pub const CHARGE_EFFECT: u8 = policy::NON_IDEMPOTENT_WRITE;

/// Payment format codes (design.md §24; machine-readable payment-format registry). A code outside the
/// closed set is rejected (UnknownPaymentFormat).
pub const FORMAT_AP2_MANDATE: u64 = 1; // AP2 mandate
pub const FORMAT_ACP_TOKEN: u64 = 2; // Agentic Commerce Protocol delegated token
pub const FORMAT_X402: u64 = 3; // x402 payload

/// The registry name of a format code, or "unknown".
pub fn format_name(code: u64) -> &'static str {
    match code {
        FORMAT_AP2_MANDATE => "ap2-mandate",
        FORMAT_ACP_TOKEN => "acp-delegated-token",
        FORMAT_X402 => "x402-payload",
        _ => "unknown",
    }
}

/// Whether `code` is one of the closed payment formats.
pub fn is_registered_format(code: u64) -> bool {
    matches!(code, FORMAT_AP2_MANDATE | FORMAT_ACP_TOKEN | FORMAT_X402)
}

pub fn err_malformed() -> cose::Error {
    cose::Error {
        kind: "PayMalformed",
        msg: "object is not a well-formed N-AALP payment-import body",
    }
}
pub fn err_unknown_format() -> cose::Error {
    cose::Error {
        kind: "UnknownPaymentFormat",
        msg: "payment import selects a format outside the closed payment-format registry",
    }
}

/// T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0x20u8, 0x30u8];
    v.extend_from_slice(&Sha384::digest(b));
    v
}

/// SHA-384 over a body — a 48-octet digest.
fn head(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

/// The imported payload wrapper. `format` selects the imported format (closed registry);
/// amount/currency/payee/not_after are the bound charge terms; `foreign` is the imported payload
/// carried octet-for-octet (carriage, not adoption). The wrapper's OWN effect is the envelope field 7.
#[derive(Debug, Clone)]
pub struct PaymentImport {
    pub format: u64,
    pub amount: u64,
    pub currency: String,
    pub payee: Vec<u8>,
    pub not_after: u64,
    pub foreign: Vec<u8>,
}

impl PaymentImport {
    /// Deterministic-CBOR {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.format)),
            (Value::Uint(2), Value::Uint(self.amount)),
            (Value::Uint(3), Value::Tstr(self.currency.clone())),
            (Value::Uint(4), Value::Bstr(self.payee.clone())),
            (Value::Uint(5), Value::Uint(self.not_after)),
            (Value::Uint(6), Value::Bstr(self.foreign.clone())),
        ]))
        .expect("encode payment import")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// T1 content-id (50 octets).
    pub fn id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
    /// T1 content-id of the carried foreign payload (the carriage binding).
    pub fn foreign_id(&self) -> Vec<u8> {
        content_id(&self.foreign)
    }
    /// The exact charge value a §7 approval binds for this import.
    pub fn charge_binding(&self) -> ChargeBinding {
        ChargeBinding {
            format: self.format,
            amount: self.amount,
            currency: self.currency.clone(),
            payee: self.payee.clone(),
            not_after: self.not_after,
            foreign_id: self.foreign_id(),
        }
    }
}

/// Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
/// closed set (that is `verify_payment_import`'s job). Fail-closed on a malformed shape.
pub fn parse_payment_import(b: &[u8]) -> Result<PaymentImport, cose::Error> {
    let m = decode_map(b)?;
    let format = uint_field(&m, 1).ok_or_else(err_malformed)?;
    let amount = uint_field(&m, 2).ok_or_else(err_malformed)?;
    let currency = tstr_field(&m, 3).ok_or_else(err_malformed)?;
    let payee = bstr_field(&m, 4).ok_or_else(err_malformed)?;
    let not_after = uint_field(&m, 5).ok_or_else(err_malformed)?;
    let foreign = bstr_field(&m, 6).ok_or_else(err_malformed)?;
    Ok(PaymentImport {
        format,
        amount,
        currency,
        payee,
        not_after,
        foreign,
    })
}

/// Produce the tagged COSE_Sign1 object over the PaymentImport body.
pub fn sign_payment_import(p: &PaymentImport, signer: &dyn cose::CoseSigner) -> Vec<u8> {
    cose::sign1(signer, &p.bytes())
}

/// Verify the import's signature under the profile, reconstruct it, and validate the format against
/// the closed registry (UnknownPaymentFormat). A bad signature propagates (BadSignature). Fail-closed.
pub fn verify_payment_import(
    obj: &[u8],
    profile: u32,
    v: &dyn cose::CoseVerifier,
) -> Result<PaymentImport, cose::Error> {
    cose::verify1(profile, v, obj)?;
    let (_prot, payload, _sig) = cose::parse_sign1_raw(obj)?;
    let p = parse_payment_import(&payload)?;
    if !is_registered_format(p.format) {
        return Err(err_unknown_format());
    }
    Ok(p)
}

/// The exact charge value an approval binds by content id.
#[derive(Debug, Clone)]
pub struct ChargeBinding {
    pub format: u64,
    pub amount: u64,
    pub currency: String,
    pub payee: Vec<u8>,
    pub not_after: u64,
    pub foreign_id: Vec<u8>,
}

impl ChargeBinding {
    /// Deterministic-CBOR {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign_id}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(self.format)),
            (Value::Uint(2), Value::Uint(self.amount)),
            (Value::Uint(3), Value::Tstr(self.currency.clone())),
            (Value::Uint(4), Value::Bstr(self.payee.clone())),
            (Value::Uint(5), Value::Uint(self.not_after)),
            (Value::Uint(6), Value::Bstr(self.foreign_id.clone())),
        ]))
        .expect("encode charge binding")
    }
    /// SHA-384 head (48 octets).
    pub fn head(&self) -> Vec<u8> {
        head(&self.bytes())
    }
    /// The charge content id an approval binds: multihash(0x20, SHA-384(binding)).
    pub fn content_id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

/// Enforce the value-bearing rule for an imported payment, reusing the §7 approval and single-use
/// consume ledger UNCHANGED. The approval MUST bind the EXACT charge binding content id (a wrong
/// amount/payee/currency or a substituted foreign payload is ApprovalMismatch), its granted effect
/// must cover `CHARGE_EFFECT`, it must be unexpired at `now`, and it is consumed single-use by `by`
/// through the §7 ledger (AlreadyConsumed on replay). Fail-closed: any failure returns its named error
/// and causes no ledger append. LedgerError is surfaced as its cose Kind.
pub fn authorize_charge(
    p: &PaymentImport,
    appr: &approval::ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    appr_sig: &[u8],
    by: &str,
    now: u64,
    ledger: &approval::Ledger,
) -> Result<(), cose::Error> {
    if !is_registered_format(p.format) {
        return Err(err_unknown_format()); // an unknown imported format is not chargeable
    }
    let charge_cid = p.charge_binding().content_id();
    approval::verify_approval(appr, approver_v, appr_sig, &charge_cid, now)?; // ApprovalMismatch / Expired / BadSignature
    if !policy::authorizes(appr.grant as u8, CHARGE_EFFECT) {
        return Err(approval::err_approval_required()); // the approval's granted effect does not cover the charge
    }
    match ledger.consume(&appr.id(), by) {
        Ok(_) => Ok(()),
        Err(approval::LedgerError::Cose(c)) => Err(c), // AlreadyConsumed — single-use, no double-spend
        Err(approval::LedgerError::Io(_)) => Err(cose::Error {
            kind: "LedgerIo",
            msg: "consume ledger write failed",
        }),
    }
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
    use serde_json::Value as J;
    use std::sync::atomic::{AtomicU64, Ordering};

    const VECTOR_PATH: &str = "../../vectors/payment/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }
    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk))
    }
    fn tmp_wal(tag: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "naalp_pay_{}_{}_{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }
    fn import_from(iv: &J) -> PaymentImport {
        PaymentImport {
            format: iv["format"].as_u64().unwrap(),
            amount: iv["amount"].as_u64().unwrap(),
            currency: iv["currency"].as_str().unwrap().to_string(),
            payee: hexd(iv["payee_hex"].as_str().unwrap()),
            not_after: iv["not_after"].as_u64().unwrap(),
            foreign: hexd(iv["foreign_hex"].as_str().unwrap()),
        }
    }
    fn mk_approval(
        charge_cid: &[u8],
        grant: u8,
        nonce: u8,
        not_after: u64,
    ) -> approval::ApprovalRecord {
        approval::ApprovalRecord {
            approves: charge_cid.to_vec(),
            approver: "approver-A".into(),
            grant: grant as u64,
            nonce: vec![nonce; 16],
            not_after,
            audience: String::new(),
        }
    }

    // Byte-parity: Rust encoding == the non-circular Python oracle -> Rust == Go on every body/head/id.
    #[test]
    fn bodies_match_oracle() {
        let c = load();
        for k in ["ap2", "acp", "x402"] {
            let iv = &c["imports"][k];
            let p = import_from(iv);
            assert_eq!(
                hex::encode(p.bytes()),
                iv["body_hex"].as_str().unwrap(),
                "{k} body"
            );
            assert_eq!(
                hex::encode(p.head()),
                iv["head_hex"].as_str().unwrap(),
                "{k} head"
            );
            assert_eq!(
                hex::encode(p.id()),
                iv["id_hex"].as_str().unwrap(),
                "{k} id"
            );
            assert_eq!(
                hex::encode(p.foreign_id()),
                iv["foreign_id_hex"].as_str().unwrap(),
                "{k} foreign_id"
            );
            let cb = p.charge_binding();
            assert_eq!(
                hex::encode(cb.bytes()),
                iv["charge_binding"]["body_hex"].as_str().unwrap(),
                "{k} cb body"
            );
            assert_eq!(
                hex::encode(cb.content_id()),
                iv["charge_binding"]["id_hex"].as_str().unwrap(),
                "{k} cb id"
            );
        }
        for e in c["format_vocabulary"].as_array().unwrap() {
            let code = e["code"].as_u64().unwrap();
            assert!(is_registered_format(code));
            assert_eq!(format_name(code), e["name"].as_str().unwrap());
        }
        assert!(!is_registered_format(c["unknown_format"].as_u64().unwrap()));
        assert_eq!(CHARGE_EFFECT as u64, c["charge_effect"].as_u64().unwrap());
    }

    // The C21 payment checkpoint: single-use spend + exact charge binding.
    #[test]
    fn charge_single_use_and_binding() {
        let c = load();
        let (s, v) = key(0x11);
        let (_, foreign_v) = key(0x22);
        let pi = import_from(&c["imports"]["ap2"]);
        let charge_cid = pi.charge_binding().content_id();
        let appr = mk_approval(&charge_cid, CHARGE_EFFECT, 0x01, pi.not_after);
        let sig = approval::sign_approval(&appr, &s);

        let l = approval::open_ledger(&tmp_wal("charge")).unwrap();
        authorize_charge(&pi, &appr, &v, &sig, "payer-1", pi.not_after, &l).expect("first charge");
        // Replay -> AlreadyConsumed, no double-spend.
        assert_eq!(
            authorize_charge(&pi, &appr, &v, &sig, "payer-1", pi.not_after, &l)
                .unwrap_err()
                .kind,
            "AlreadyConsumed"
        );
        assert_eq!(l.len(), 1);

        // Wrong amount / wrong payee / substituted payload -> ApprovalMismatch (a different charge cid).
        let mut wrong_amount = pi.clone();
        wrong_amount.amount = pi.amount + 8000;
        assert_eq!(
            hex::encode(wrong_amount.charge_binding().content_id()),
            c["mismatch"]["wrong_amount_charge_id_hex"]
                .as_str()
                .unwrap()
        );
        let l2 = approval::open_ledger(&tmp_wal("wa")).unwrap();
        assert_eq!(
            authorize_charge(&wrong_amount, &appr, &v, &sig, "p", pi.not_after, &l2)
                .unwrap_err()
                .kind,
            "ApprovalMismatch"
        );

        let mut wrong_payee = pi.clone();
        wrong_payee.payee = b"merchant:evil-store".to_vec();
        assert_eq!(
            hex::encode(wrong_payee.charge_binding().content_id()),
            c["mismatch"]["wrong_payee_charge_id_hex"].as_str().unwrap()
        );
        let l3 = approval::open_ledger(&tmp_wal("wp")).unwrap();
        assert_eq!(
            authorize_charge(&wrong_payee, &appr, &v, &sig, "p", pi.not_after, &l3)
                .unwrap_err()
                .kind,
            "ApprovalMismatch"
        );

        let mut substituted = pi.clone();
        substituted.foreign = hexd(c["mismatch"]["substituted_foreign_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(substituted.foreign_id()),
            c["mismatch"]["substituted_foreign_id_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            hex::encode(substituted.charge_binding().content_id()),
            c["mismatch"]["substituted_charge_id_hex"].as_str().unwrap()
        );
        let l4 = approval::open_ledger(&tmp_wal("sub")).unwrap();
        assert_eq!(
            authorize_charge(&substituted, &appr, &v, &sig, "p", pi.not_after, &l4)
                .unwrap_err()
                .kind,
            "ApprovalMismatch"
        );

        // Foreign key -> BadSignature; expired -> ApprovalExpired; under-grant -> ApprovalRequired;
        // unknown format -> UnknownPaymentFormat.
        let l5 = approval::open_ledger(&tmp_wal("fk")).unwrap();
        assert_eq!(
            authorize_charge(&pi, &appr, &foreign_v, &sig, "p", pi.not_after, &l5)
                .unwrap_err()
                .kind,
            "BadSignature"
        );
        let l6 = approval::open_ledger(&tmp_wal("ex")).unwrap();
        assert_eq!(
            authorize_charge(&pi, &appr, &v, &sig, "p", pi.not_after + 1, &l6)
                .unwrap_err()
                .kind,
            "ApprovalExpired"
        );
        let under = mk_approval(&charge_cid, policy::READ_ONLY, 0x03, pi.not_after);
        let under_sig = approval::sign_approval(&under, &s);
        let l7 = approval::open_ledger(&tmp_wal("ug")).unwrap();
        assert_eq!(
            authorize_charge(&pi, &under, &v, &under_sig, "p", pi.not_after, &l7)
                .unwrap_err()
                .kind,
            "ApprovalRequired"
        );
        let mut unk = pi.clone();
        unk.format = c["unknown_format"].as_u64().unwrap();
        let l8 = approval::open_ledger(&tmp_wal("uf")).unwrap();
        assert_eq!(
            authorize_charge(&unk, &appr, &v, &sig, "p", pi.not_after, &l8)
                .unwrap_err()
                .kind,
            "UnknownPaymentFormat"
        );
    }

    // REQUIRED checkpoint mutation (a): an importer that treats a payment token as MULTI-USE fails the
    // replay case. The honest path consumes single-use through the ledger (replay -> AlreadyConsumed);
    // a MUTANT that verifies the binding but skips the ledger consume authorizes the replay again.
    #[test]
    fn payment_import_multi_use_mutation() {
        let c = load();
        let (s, v) = key(0x11);
        let pi = import_from(&c["imports"]["ap2"]);
        let charge_cid = pi.charge_binding().content_id();
        let appr = mk_approval(&charge_cid, CHARGE_EFFECT, 0x01, pi.not_after);
        let sig = approval::sign_approval(&appr, &s);

        let l = approval::open_ledger(&tmp_wal("honest")).unwrap();
        authorize_charge(&pi, &appr, &v, &sig, "p", pi.not_after, &l).expect("honest first");
        assert_eq!(
            authorize_charge(&pi, &appr, &v, &sig, "p", pi.not_after, &l)
                .unwrap_err()
                .kind,
            "AlreadyConsumed"
        );

        // MUTANT: multi-use (no ledger consume) — the replay is NOT rejected, proving ledger.consume is
        // the single-use guarantee.
        let mutant = |p: &PaymentImport| -> Result<(), cose::Error> {
            let cid = p.charge_binding().content_id();
            approval::verify_approval(&appr, &v, &sig, &cid, p.not_after) // no consume => multi-use
        };
        mutant(&pi).expect("mutant first");
        mutant(&pi).expect("mutant replay must reproduce the multi-use bug");
    }

    // Cross-language pin: the signed AP2 payment-import digest matches the value the Go test pins,
    // proving Go and Rust emit byte-identical signed payment-import objects (deterministic ML-DSA-65).
    #[test]
    fn cross_lang_signed_payment_pin() {
        const PIN: &str = "c9c7c30eed7bfaf5292bd99e8a892a86f563d8531ccff25d0504d81f3f535b02a8afbd7d41a5ff0f69031841a338bbe4";
        let c = load();
        let (_pk, sk) = cose::mldsa65_keypair_from_seed(&[0x11; 32]);
        let s = cose::MlDsa65Signer(sk);
        let pi = import_from(&c["imports"]["ap2"]);
        let obj = sign_payment_import(&pi, &s);
        assert_eq!(
            hex::encode(Sha384::digest(&obj)),
            PIN,
            "signed payment-import digest differs from the Go pin"
        );
    }

    // Malformed bodies are fail-closed.
    #[test]
    fn malformed_rejected() {
        assert_eq!(
            parse_payment_import(&[0x00]).unwrap_err().kind,
            "PayMalformed"
        );
    }

    // Phase 6 edge case #3 (the >2^53 discipline): a charge amount above 2^53 round-trips byte-exact
    // through the import body AND the charge-binding (u64, no float64). Carried as a JSON string.
    #[test]
    fn oversized_amount_round_trip() {
        let c = load();
        let amount: u64 = c["big_amount"]["amount_str"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(amount > (1 << 53));
        let p = PaymentImport {
            format: c["big_amount"]["format"].as_u64().unwrap(),
            amount,
            currency: c["big_amount"]["currency"].as_str().unwrap().to_string(),
            payee: hexd(c["big_amount"]["payee_hex"].as_str().unwrap()),
            not_after: c["big_amount"]["not_after"].as_u64().unwrap(),
            foreign: hexd(c["big_amount"]["foreign_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(p.bytes()),
            c["big_amount"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(p.charge_binding().bytes()),
            c["big_amount"]["charge_binding"]["body_hex"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            parse_payment_import(&p.bytes()).expect("parse").amount,
            amount,
            ">2^53 amount corrupted"
        );
    }

    // Phase 6 edge case #4: the smallest valid payment import encodes, reconstructs, and has a stable id.
    #[test]
    fn minimal_import() {
        let c = load();
        let p = PaymentImport {
            format: c["minimal"]["format"].as_u64().unwrap(),
            amount: c["minimal"]["amount"].as_u64().unwrap(),
            currency: c["minimal"]["currency"].as_str().unwrap().to_string(),
            payee: hexd(c["minimal"]["payee_hex"].as_str().unwrap()),
            not_after: c["minimal"]["not_after"].as_u64().unwrap(),
            foreign: hexd(c["minimal"]["foreign_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(p.bytes()),
            c["minimal"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(p.id()),
            c["minimal"]["id_hex"].as_str().unwrap()
        );
        parse_payment_import(&p.bytes()).expect("parse minimal");
    }

    // ---- standard wire-format edge cases (Part 1) --------------------------------------------

    // Edge case #1: an import body with top-level keys DESCENDING (6,5,4,3,2,1) is rejected NonCanonical
    // by the strict shared decoder parse_payment_import routes through; the canonical body parses.
    #[test]
    fn keys_out_of_order_rejected() {
        let c = load();
        let e = &c["edge_cases"]["keys_out_of_order"];
        let p = PaymentImport {
            format: e["format"].as_u64().unwrap(),
            amount: e["amount"].as_u64().unwrap(),
            currency: e["currency"].as_str().unwrap().to_string(),
            payee: hexd(e["payee_hex"].as_str().unwrap()),
            not_after: e["not_after"].as_u64().unwrap(),
            foreign: hexd(e["foreign_hex"].as_str().unwrap()),
        };
        assert_eq!(
            hex::encode(p.bytes()),
            e["canonical_body_hex"].as_str().unwrap(),
            "canonical import body"
        );
        let canon = hexd(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = hexd(e["noncanonical_body_hex"].as_str().unwrap());
        cbor::decode(&canon).expect("canonical body should decode");
        parse_payment_import(&canon).expect("canonical body should parse");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key import body decoded (want NonCanonical)"),
        }
        assert_eq!(
            parse_payment_import(&noncanon).unwrap_err().kind,
            "PayMalformed"
        );
    }

    // Edge case #2 (foreign payload): an empty foreign payload is present and valid with its own
    // foreign_id (the carriage binding), distinct from a populated one; both differ from a body whose
    // foreign field is ABSENT (rejected PayMalformed — field 6 is mandatory).
    #[test]
    fn empty_vs_absent_foreign() {
        let c = load();
        let base = &c["edge_cases"]["keys_out_of_order"]; // same base fields
        let ea = &c["edge_cases"]["empty_vs_absent"];
        let mk = |foreign: Vec<u8>| PaymentImport {
            format: base["format"].as_u64().unwrap(),
            amount: base["amount"].as_u64().unwrap(),
            currency: base["currency"].as_str().unwrap().to_string(),
            payee: hexd(base["payee_hex"].as_str().unwrap()),
            not_after: base["not_after"].as_u64().unwrap(),
            foreign,
        };
        let empty = mk(vec![]);
        let populated = mk(hexd(
            ea["populated_foreign"]["foreign_hex"].as_str().unwrap(),
        ));
        assert_eq!(
            hex::encode(empty.bytes()),
            ea["empty_foreign"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(populated.bytes()),
            ea["populated_foreign"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(empty.foreign_id()),
            ea["empty_foreign"]["foreign_id_hex"].as_str().unwrap()
        );
        assert_ne!(
            empty.foreign_id(),
            populated.foreign_id(),
            "empty vs populated foreign must differ by foreign_id"
        );
        assert_ne!(
            empty.id(),
            populated.id(),
            "empty vs populated import must differ by content-id"
        );
        parse_payment_import(&empty.bytes()).expect("empty foreign parses");
        parse_payment_import(&populated.bytes()).expect("populated foreign parses");
        assert_eq!(
            parse_payment_import(&hexd(ea["absent_field"]["body_hex"].as_str().unwrap()))
                .unwrap_err()
                .kind,
            "PayMalformed"
        );
    }

    // Edge case #5: payment-import and charge-binding share one 6-field shape, so the look-alike is a
    // near-miss with a wrong field-3 (currency) type — a bstr where a tstr is required, rejected
    // PayMalformed.
    #[test]
    fn look_alike_rejected() {
        let c = load();
        let body = hexd(c["edge_cases"]["look_alike"]["body_hex"].as_str().unwrap());
        assert_eq!(
            parse_payment_import(&body).unwrap_err().kind,
            "PayMalformed"
        );
    }
}
