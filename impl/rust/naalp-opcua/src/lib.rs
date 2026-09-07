// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `naalp-opcua` — the OPC UA carriage binding (Manufacturing Add-ons Component B).
//!
//! N-AALP already defines a universal OPAQUE carriage class (design.md §13,
//! `impl/rust/src/carriage.rs`) that carries any foreign protocol's message octet-for-octet
//! in a signed N-AALP object, on an experimental protocol id with no registration required
//! (R-18.6). This crate is a *binding*, not a new wire kind: it decides how an OPC UA
//! message maps onto that existing carriage body's generic fields, and adds no CDDL, no new
//! crypto, and no new encoding of its own — every signature, hash, and CBOR encoding call
//! delegates to `naalp::naalpcore` / `naalp::cbor` / `naalp::carriage` unchanged.
//!
//! Two binding modes:
//! - **Inline** (`bind_inline`): the OPC UA message octets travel verbatim inside the
//!   carriage object's `foreign` field (R-14.4 — never re-serialized, canonicalized, or
//!   rewritten), alongside an explicit content-id hash of those same octets for a binding
//!   check independent of the envelope's own signature.
//! - **By reference** (`bind_by_reference`): for a message over the channel's size budget
//!   (the wire's whole-object bound, `naalp::envelope::MAX_OBJECT_SIZE`), only a content-id
//!   hash and a locator travel on the wire. `verify_binding` reports such an object as
//!   `BindingStatus::Unresolved` — signature-valid, but the OPC UA binding itself is
//!   UNVERIFIABLE until a caller fetches the referent out of band and calls
//!   `verify_referent`. A missing referent can never read as valid; there is no code path
//!   that produces `BindingStatus::Resolved` without a byte-exact content-id match.
//!
//! **The verify path never parses OPC UA.** `verify_binding` treats the carried `foreign`
//! bytes as an opaque octet string for hashing and passthrough only — it never decodes them
//! as OPC UA binary or XML. Decoding the referenced OPC UA message (if a consumer needs its
//! contents) is entirely out of this crate's scope, by design, per the Manufacturing
//! Add-ons Component B contract.
//!
//! An optional companion-node identity (a robotics/CNC OPC UA companion-object-model node
//! id, e.g. an OPC 40001 Robotics NodeId string) may ride alongside the binding; it is
//! carried as an opaque, unparsed string — this crate does not validate OPC UA NodeId
//! syntax, consistent with never parsing OPC UA.

use naalp::carriage::{self, CarriageBody, CLASS_OPAQUE};
use naalp::cbor::{self, Value};
use naalp::cose;
use naalp::envelope;
use naalp::naalpcore;
use naalp::policy;

/// The Bridge channel / Carriage kind (`impl/rust/src/channels.rs`, channel 0x000D, kind 0;
/// design.md §13) — the SAME registry entry every carriage-class binding signs under. This
/// crate introduces no new channel or kind. The Carriage kind's effect is VARIABLE in the
/// registry (`channels::lookup(0x000D, 0).variable == true`) — a carriage object's effect
/// depends on what it actually carries, so it is caller-declared per binding (`effect`
/// below) and signed via `easy::Signer::sign_with_effect`, never a registry default.
pub const CHANNEL_BRIDGE: u64 = 0x000D;
pub const KIND_CARRIAGE: u64 = 0;

/// An experimental (unregistered) protocol id for OPC UA (design.md §13.4 range
/// 0x10-0x7F; R-18.6 — an undefined protocol is carriable immediately on an experimental id
/// with no registration). This is NOT an entry in `vectors/registry/protocols.csv` (that
/// registry lists only the assigned "standards" range 0x01-0x0F) — this crate defines its
/// own experimental id for OPC UA, exactly as R-18.6 permits.
pub const PROTOCOL_ID_OPCUA: u64 = 0x20;

/// `content_type` values this binding defines over the carriage body's generic
/// `content_type` field (a per-binding-defined u64, the same slot every other carriage
/// class already assigns its own meaning to): encoding (binary/XML) crossed with binding
/// mode (inline/by-reference).
pub const CONTENT_TYPE_INLINE_BINARY: u64 = 0;
pub const CONTENT_TYPE_INLINE_XML: u64 = 1;
pub const CONTENT_TYPE_REFERENCE_BINARY: u64 = 2;
pub const CONTENT_TYPE_REFERENCE_XML: u64 = 3;

/// Reserved headroom (envelope fields, COSE header, ML-DSA-65 signature + public key,
/// carriage-body CBOR framing) subtracted from the wire's whole-object bound when deciding
/// whether an OPC UA message fits inline. Conservative on purpose: `fits_inline` must never
/// pass a message that would then fail the real `TooLarge` check once actually signed.
const INLINE_OVERHEAD_RESERVE: u64 = 16 * 1024;

/// A binding-layer failure, carrying a stable `kind` — the same `{kind, msg}` shape as
/// `naalp::cbor::Error` / `naalp::cose::Error`, which this type wraps and extends with a
/// few binding-specific reasons (`ExceedsBudget`, `MalformedContentId`, `MissingLocator`,
/// `WrongCarriage`, `ProtocolUnsupported`, `ContentIdMismatch`, `ReferentMismatch`).
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: &'static str,
    pub msg: &'static str,
}

impl From<cbor::Error> for Error {
    fn from(e: cbor::Error) -> Self {
        Error {
            kind: e.kind,
            msg: e.msg,
        }
    }
}

impl From<cose::Error> for Error {
    fn from(e: cose::Error) -> Self {
        Error {
            kind: e.kind,
            msg: e.msg,
        }
    }
}

fn err(kind: &'static str, msg: &'static str) -> Error {
    Error { kind, msg }
}

/// OPC UA's own on-wire message encoding — this binding carries either verbatim, never
/// interpreting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Binary,
    Xml,
}

/// What actually rides in the carriage object's `foreign` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// The OPC UA message octets, carried verbatim.
    Inline(Vec<u8>),
    /// A locator naming where to fetch the referent out of band; the message octets do not
    /// travel on the wire.
    ByReference(String),
}

/// An OPC UA message bound for N-AALP carriage: a content-id hash of the message, an
/// optional companion-node identity, its OPC UA encoding, and the payload (inline bytes or
/// a by-reference locator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcUaBinding {
    /// The 50-byte content-id (`0x20 0x30` || 48-byte SHA-384 digest) of the OPC UA message
    /// octets — the SAME multihash primitive N-AALP object content-ids use
    /// (`naalp::cbor::content_id`, design.md §2.3), applied unchanged to a non-object value.
    pub content_id: Vec<u8>,
    pub companion_node_id: Option<String>,
    pub encoding: Encoding,
    pub payload: Payload,
    /// The N-AALP effect (`naalp::policy::{READ_ONLY, IDEMPOTENT_WRITE,
    /// NON_IDEMPOTENT_WRITE, DESTRUCTIVE}`) of the OPC UA operation this message actually
    /// carries — e.g. a variable read is `READ_ONLY`, a method call actuating equipment is
    /// typically `DESTRUCTIVE`. Always normalized (`naalp::policy::normalize_effect`, S-5):
    /// an out-of-lattice caller value is coerced to `DESTRUCTIVE`, never accepted as-is or
    /// defaulted to benign (R-6.2, fail-closed).
    pub effect: u8,
}

/// The content-id of a raw OPC UA message: `multihash(0x20, SHA-384(canonical CBOR bstr
/// encoding of the message octets)))` — 50 bytes. This is `naalp::cbor::content_id` applied,
/// unchanged, to the message wrapped as a CBOR byte string (`Value::Bstr`); this crate adds
/// no new hash function, no new encoding, and no new multihash convention of its own.
pub fn content_id_of_message(message: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(cbor::content_id(&Value::Bstr(message.to_vec()))?)
}

/// Whether an OPC UA message of `message_len` bytes fits inline under the wire's whole-
/// object bound (`naalp::envelope::MAX_OBJECT_SIZE`, design.md §3.4), after reserving
/// headroom for envelope/COSE/carriage-body overhead.
pub fn fits_inline(message_len: usize) -> bool {
    (message_len as u64).saturating_add(INLINE_OVERHEAD_RESERVE) <= envelope::MAX_OBJECT_SIZE
}

fn validate_content_id(id: &[u8]) -> Result<(), Error> {
    if id.len() != 50 || id[0] != 0x20 || id[1] != 0x30 {
        return Err(err(
            "MalformedContentId",
            "content-id is not a 50-byte multihash(0x20, SHA-384)",
        ));
    }
    Ok(())
}

/// Bind an OPC UA message inline: the message octets are carried verbatim in the carriage
/// object's `foreign` field (R-14.4), and its content-id is computed and carried alongside
/// as an explicit binding hash. Fails closed (`ExceedsBudget`) rather than silently
/// embedding a message that would not fit the channel's size budget — the caller MUST use
/// `bind_by_reference` for an oversized message; there is no truncation path.
pub fn bind_inline(
    encoding: Encoding,
    message: Vec<u8>,
    companion_node_id: Option<String>,
    effect: u64,
) -> Result<OpcUaBinding, Error> {
    if !fits_inline(message.len()) {
        return Err(err(
            "ExceedsBudget",
            "OPC UA message exceeds the inline size budget; bind by reference instead",
        ));
    }
    let content_id = content_id_of_message(&message)?;
    Ok(OpcUaBinding {
        content_id,
        companion_node_id,
        encoding,
        payload: Payload::Inline(message),
        effect: policy::normalize_effect(effect),
    })
}

/// Bind an OPC UA message by reference: only its content-id hash and a locator travel on
/// the wire, never the message bytes (for a message over the channel's size budget). The
/// caller supplies the content-id of the actual referent — typically via
/// `content_id_of_message` over the real bytes before they are set aside, or an
/// independently computed equivalent — never a fabricated placeholder: a malformed
/// content-id (wrong length or multihash prefix) or an empty locator is rejected fail-closed
/// before any object is signed.
pub fn bind_by_reference(
    encoding: Encoding,
    content_id: Vec<u8>,
    locator: String,
    companion_node_id: Option<String>,
    effect: u64,
) -> Result<OpcUaBinding, Error> {
    validate_content_id(&content_id)?;
    if locator.is_empty() {
        return Err(err(
            "MissingLocator",
            "a by-reference binding requires a non-empty locator",
        ));
    }
    Ok(OpcUaBinding {
        content_id,
        companion_node_id,
        encoding,
        payload: Payload::ByReference(locator),
        effect: policy::normalize_effect(effect),
    })
}

fn content_type_for(encoding: Encoding, by_reference: bool) -> u64 {
    match (encoding, by_reference) {
        (Encoding::Binary, false) => CONTENT_TYPE_INLINE_BINARY,
        (Encoding::Xml, false) => CONTENT_TYPE_INLINE_XML,
        (Encoding::Binary, true) => CONTENT_TYPE_REFERENCE_BINARY,
        (Encoding::Xml, true) => CONTENT_TYPE_REFERENCE_XML,
    }
}

/// Map a binding onto the existing generic `CarriageBody` (`impl/rust/src/carriage.rs`):
/// `correlation` carries the content-id (a 50-byte bstr, the same field's existing bstr
/// type, just this binding's own semantic choice); `method` carries the optional
/// companion-node identity (empty string when absent, the existing "absent" convention the
/// carriage module's own OPAQUE test fixture already uses); `foreign` carries the message
/// octets inline or the locator's UTF-8 bytes by reference. No new CarriageBody field is
/// added or reinterpreted at the CBOR layer — this is purely which existing generic field
/// this binding chooses to populate with what, exactly what every carriage-class binding
/// document does.
fn to_carriage_body(binding: &OpcUaBinding) -> CarriageBody {
    let (content_type, foreign) = match &binding.payload {
        Payload::Inline(bytes) => (content_type_for(binding.encoding, false), bytes.clone()),
        Payload::ByReference(locator) => (
            content_type_for(binding.encoding, true),
            locator.as_bytes().to_vec(),
        ),
    };
    CarriageBody {
        protocol_id: PROTOCOL_ID_OPCUA,
        class: CLASS_OPAQUE,
        content_type,
        correlation: binding.content_id.clone(),
        method: binding.companion_node_id.clone().unwrap_or_default(),
        foreign,
    }
}

/// Sign an OPC UA binding as an N-AALP Bridge/Carriage object (channel 0x000D, kind 0). The
/// `channel`/`kind` pair is mandatory and explicit, per the reconciled `naalpcore` facade
/// contract (the facade-seam design S-1); the signing profile is derived
/// from the registry entry, never supplied here. Because the Carriage kind's effect is
/// variable (not fixed by the registry), this calls the real underlying
/// `easy::Signer::sign_with_effect` with the binding's own declared, normalized effect —
/// `naalpcore::sign` only covers the fixed-effect happy path and cannot be used for this
/// kind (it returns `EffectRequired`).
pub fn sign_binding(signer: &naalpcore::Signer, binding: &OpcUaBinding) -> Result<Vec<u8>, Error> {
    let body = to_carriage_body(binding).to_value();
    Ok(signer.sign_with_effect(CHANNEL_BRIDGE, KIND_CARRIAGE, binding.effect, body)?)
}

/// The verified state of an OPC UA binding after `verify_binding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingStatus {
    /// The message octets travelled inline and their content-id has been confirmed to
    /// match — a fully resolved binding.
    Resolved(Vec<u8>),
    /// Only a content-id and locator travelled on the wire; the referent was never fetched
    /// during this verification, so the OPC UA binding itself is UNVERIFIABLE — not valid,
    /// not invalid. `verify_referent` is the only function that can resolve it.
    Unresolved { content_id: Vec<u8>, locator: String },
}

/// The result of a successful `verify_binding` call: the envelope/signature check passed,
/// this object is scoped to the OPC UA binding (Bridge/Carriage, OPAQUE class, the OPC UA
/// protocol id), and its companion-node identity plus resolution status are extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBinding {
    pub companion_node_id: Option<String>,
    pub encoding: Encoding,
    pub status: BindingStatus,
    /// The signed object's declared effect (design.md §6.1), read directly off the
    /// verified envelope — the caller applies policy authorization on this value as a
    /// SEPARATE layer after verification succeeds (the facade-seam design
    /// S-2: verification is not authorization).
    pub effect: u8,
}

/// Verify a signed OPC UA carriage object: first the full envelope/signature check
/// (`naalpcore::verify` — fail-closed on any tamper, unknown key, or malformed object),
/// then this binding's own scoping (Bridge/Carriage channel+kind, OPAQUE class, the OPC UA
/// protocol id) and its content-id binding.
///
/// **This function never parses, decodes, or otherwise interprets the OPC UA message
/// bytes as OPC UA.** It treats the carried `foreign` octets as an opaque byte string for
/// hashing and passthrough only, per the Manufacturing Add-ons Component B contract.
pub fn verify_binding(pub_key: &[u8], obj: &[u8]) -> Result<VerifiedBinding, Error> {
    let object = naalpcore::verify(pub_key, obj)?;
    // envelope::verify already rejects effect > 3 as a field-range violation (R7) before
    // this point, so `object.effect` is always in the closed 0..=3 lattice here.
    let effect = object.effect as u8;
    if object.channel != CHANNEL_BRIDGE || object.kind != KIND_CARRIAGE {
        return Err(err(
            "WrongCarriage",
            "object is not a Bridge/Carriage object",
        ));
    }
    let cb = carriage::carriage_from_value(&object.body)?;
    if cb.class != CLASS_OPAQUE || cb.protocol_id != PROTOCOL_ID_OPCUA {
        return Err(err(
            "ProtocolUnsupported",
            "carriage body is not an OPC UA opaque binding",
        ));
    }
    validate_content_id(&cb.correlation)?;
    let companion_node_id = if cb.method.is_empty() {
        None
    } else {
        Some(cb.method.clone())
    };
    let encoding = match cb.content_type {
        CONTENT_TYPE_INLINE_BINARY | CONTENT_TYPE_REFERENCE_BINARY => Encoding::Binary,
        CONTENT_TYPE_INLINE_XML | CONTENT_TYPE_REFERENCE_XML => Encoding::Xml,
        _ => return Err(err("Malformed", "unknown OPC UA content_type")),
    };
    let by_reference = matches!(
        cb.content_type,
        CONTENT_TYPE_REFERENCE_BINARY | CONTENT_TYPE_REFERENCE_XML
    );
    let status = if by_reference {
        let locator = String::from_utf8(cb.foreign.clone())
            .map_err(|_| err("Malformed", "by-reference locator is not valid UTF-8"))?;
        BindingStatus::Unresolved {
            content_id: cb.correlation.clone(),
            locator,
        }
    } else {
        let recomputed = content_id_of_message(&cb.foreign)?;
        if recomputed != cb.correlation {
            return Err(err(
                "ContentIdMismatch",
                "inline OPC UA message does not match its carried content-id",
            ));
        }
        BindingStatus::Resolved(cb.foreign.clone())
    };
    Ok(VerifiedBinding {
        companion_node_id,
        encoding,
        status,
        effect,
    })
}

/// Resolve an `Unresolved` by-reference binding once the referent has been fetched out of
/// band (a plant historian, an OPC UA file transfer, a locator's target system — all
/// outside N-AALP's scope). A referent that is never fetched stays `Unresolved` forever;
/// this is the ONLY function able to turn it into a confirmed match, and it never trusts
/// unchecked input — a byte mismatch is a named, fail-closed error, never a silent pass. A
/// missing referent is unverifiable, never valid: no code path in this crate marks a
/// by-reference binding `Resolved` without this check succeeding.
pub fn verify_referent(content_id: &[u8], referent: &[u8]) -> Result<(), Error> {
    validate_content_id(content_id)?;
    let recomputed = content_id_of_message(referent)?;
    if recomputed != content_id {
        return Err(err(
            "ReferentMismatch",
            "fetched referent does not match its pinned content-id",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    fn signer() -> naalpcore::Signer {
        naalpcore::new_signer(&[0x42; 32])
    }

    // F3 non-circular oracle: hand-construct the RFC 8949 canonical CBOR encoding of a
    // definite-length byte string (major type 2, head byte 0x40|len for len<24) and hash it
    // with the `sha2` crate directly here in the test — independent of
    // naalp::cbor::encode/content_id, the code under test.
    #[test]
    fn content_id_oracle_independent_construction() {
        let message = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]; // 7 bytes, len < 24
        let mut enc = vec![0x40u8 | (message.len() as u8)];
        enc.extend_from_slice(&message);
        let digest = Sha384::digest(&enc);
        let mut want = vec![0x20u8, 0x30u8];
        want.extend_from_slice(&digest);
        let got = content_id_of_message(&message).expect("content_id_of_message");
        assert_eq!(got, want, "content-id must match an independently constructed RFC 8949 encoding + SHA-384");
        assert_eq!(got.len(), 50);
    }

    #[test]
    fn bind_inline_sign_verify_round_trip() {
        let s = signer();
        let message = br#"<OpcUaMessage>tag-actuation</OpcUaMessage>"#.to_vec();
        let binding = bind_inline(
            Encoding::Xml,
            message.clone(),
            Some("ns=2;s=Robot.Joint1".into()),
            policy::DESTRUCTIVE as u64,
        )
        .expect("bind_inline");
        let obj = sign_binding(&s, &binding).expect("sign_binding");
        let verified = verify_binding(s.public_key(), &obj).expect("verify_binding");
        assert_eq!(
            verified.companion_node_id.as_deref(),
            Some("ns=2;s=Robot.Joint1")
        );
        assert_eq!(verified.encoding, Encoding::Xml);
        assert_eq!(verified.effect, policy::DESTRUCTIVE);
        match verified.status {
            BindingStatus::Resolved(bytes) => assert_eq!(bytes, message),
            BindingStatus::Unresolved { .. } => panic!("an inline binding must resolve"),
        }
    }

    #[test]
    fn no_companion_node_id_round_trips_as_none() {
        let s = signer();
        let binding =
            bind_inline(Encoding::Binary, vec![1, 2, 3], None, policy::READ_ONLY as u64).unwrap();
        let obj = sign_binding(&s, &binding).unwrap();
        let verified = verify_binding(s.public_key(), &obj).unwrap();
        assert_eq!(verified.companion_node_id, None);
    }

    // MUTATION ANCHOR (fail-closed on tamper): a one-byte flip anywhere in the signed
    // bytes must be rejected before this crate's own scoping/content-id checks ever run.
    #[test]
    fn verify_rejects_tampered_object() {
        let s = signer();
        let binding =
            bind_inline(Encoding::Binary, vec![9, 9, 9], None, policy::READ_ONLY as u64).unwrap();
        let mut obj = sign_binding(&s, &binding).unwrap();
        let last = obj.len() - 1;
        obj[last] ^= 0x01;
        assert!(verify_binding(s.public_key(), &obj).is_err());
    }

    #[test]
    fn wrong_signer_key_rejected() {
        let s1 = signer();
        let s2 = naalpcore::new_signer(&[0x99; 32]);
        let binding =
            bind_inline(Encoding::Binary, vec![1], None, policy::READ_ONLY as u64).unwrap();
        let obj = sign_binding(&s1, &binding).unwrap();
        assert!(verify_binding(s2.public_key(), &obj).is_err());
    }

    // MUTATION ANCHOR (fail-closed on budget): an oversized message must not silently
    // embed; the caller is forced onto the by-reference path.
    #[test]
    fn oversized_message_refused_inline_must_use_by_reference() {
        let big = vec![0u8; envelope::MAX_OBJECT_SIZE as usize];
        match bind_inline(Encoding::Binary, big, None, policy::READ_ONLY as u64) {
            Err(e) => assert_eq!(e.kind, "ExceedsBudget"),
            Ok(_) => panic!("an oversized message must not bind inline"),
        }
    }

    #[test]
    fn by_reference_binding_is_unresolved_until_referent_verified() {
        let s = signer();
        let referent = b"a very large opc ua binary blob (represented small here)".to_vec();
        let cid = content_id_of_message(&referent).unwrap();
        let binding = bind_by_reference(
            Encoding::Binary,
            cid.clone(),
            "opc.tcp://historian.example.plant/blob/12345".into(),
            Some("ns=2;s=CNC.Spindle".into()),
            policy::NON_IDEMPOTENT_WRITE as u64,
        )
        .unwrap();
        let obj = sign_binding(&s, &binding).unwrap();
        let verified = verify_binding(s.public_key(), &obj).unwrap();
        assert_eq!(
            verified.companion_node_id.as_deref(),
            Some("ns=2;s=CNC.Spindle")
        );
        match &verified.status {
            BindingStatus::Unresolved { content_id, locator } => {
                assert_eq!(content_id, &cid);
                assert_eq!(locator, "opc.tcp://historian.example.plant/blob/12345");
            }
            BindingStatus::Resolved(_) => {
                panic!("a by-reference binding must not resolve on its own")
            }
        }
        if let BindingStatus::Unresolved { content_id, .. } = &verified.status {
            verify_referent(content_id, &referent).expect("the matching referent must resolve");
            assert!(
                verify_referent(content_id, b"a tampered referent entirely").is_err(),
                "a mismatched referent must never resolve as valid"
            );
        }
    }

    #[test]
    fn malformed_content_id_rejected() {
        let bad = vec![0u8; 10]; // wrong length
        assert!(bind_by_reference(
            Encoding::Binary,
            bad,
            "loc".into(),
            None,
            policy::READ_ONLY as u64
        )
        .is_err());
    }

    #[test]
    fn empty_locator_rejected() {
        let good = content_id_of_message(b"x").unwrap();
        assert!(bind_by_reference(
            Encoding::Binary,
            good,
            String::new(),
            None,
            policy::READ_ONLY as u64
        )
        .is_err());
    }

    #[test]
    fn wrong_carriage_channel_rejected() {
        // Sign a legitimate N-AALP object under a DIFFERENT (channel, kind) — not
        // Bridge/Carriage — and confirm verify_binding refuses it even though the
        // envelope signature itself is fully valid.
        let s = signer();
        let obj = naalpcore::sign(
            &s,
            0x000F, // Interaction
            1,      // Respond
            Value::Tstr("not a carriage object".into()),
        )
        .unwrap();
        assert_eq!(
            verify_binding(s.public_key(), &obj).unwrap_err().kind,
            "WrongCarriage"
        );
    }

    #[test]
    fn wrong_protocol_id_rejected() {
        // A Bridge/Carriage object legitimately built via the shared `carriage` module but
        // under a DIFFERENT protocol id and class (MCP=0x01, JSONRPC) must be refused by
        // this OPC UA-specific verifier.
        let s = signer();
        let cb = carriage::carry(
            0x01,
            carriage::CLASS_JSONRPC,
            0,
            vec![],
            "tools/call".into(),
            b"{}".to_vec(),
        )
        .unwrap();
        let obj = s
            .sign_with_effect(CHANNEL_BRIDGE, KIND_CARRIAGE, policy::READ_ONLY, cb.to_value())
            .unwrap();
        assert_eq!(
            verify_binding(s.public_key(), &obj).unwrap_err().kind,
            "ProtocolUnsupported"
        );
    }

    // MUTATION ANCHOR (content-id binding, defense-in-depth atop the envelope signature):
    // if the carried inline foreign bytes are edited so the CarriageBody re-encodes to a
    // DIFFERENT signed byte stream than what was actually signed, envelope verification
    // itself already fails first. This test instead proves the binding-layer check fires
    // on its own terms by constructing a self-consistent-but-wrong object directly: a
    // signed carriage body whose carried content-id does not match its carried foreign
    // bytes (both legitimately signed, so the envelope signature is valid).
    #[test]
    fn content_id_mismatch_rejected_even_with_valid_signature() {
        let s = signer();
        let real_message = b"authentic OPC UA payload".to_vec();
        let wrong_content_id = content_id_of_message(b"a different message entirely").unwrap();
        let cb = CarriageBody {
            protocol_id: PROTOCOL_ID_OPCUA,
            class: CLASS_OPAQUE,
            content_type: CONTENT_TYPE_INLINE_BINARY,
            correlation: wrong_content_id,
            method: String::new(),
            foreign: real_message,
        };
        let obj = s
            .sign_with_effect(CHANNEL_BRIDGE, KIND_CARRIAGE, policy::READ_ONLY, cb.to_value())
            .unwrap();
        assert_eq!(
            verify_binding(s.public_key(), &obj).unwrap_err().kind,
            "ContentIdMismatch"
        );
    }

    #[test]
    fn fits_inline_budget_boundary() {
        assert!(fits_inline(1024));
        assert!(!fits_inline(envelope::MAX_OBJECT_SIZE as usize));
    }
}
