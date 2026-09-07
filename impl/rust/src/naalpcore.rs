// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `naalpcore` is a stable, generic facade over N-AALP's real, module-scoped core
//! surface. It exists to reconcile a naming mismatch surfaced by two external integration
//! specs: the Agent Governance Kit's K0 neutral binding and the Manufacturing Add-ons'
//! naalp-ffi Component A both assume one generic top-level core API — sign / verify /
//! content_id / signer_id — but the real reference implementation exposes per-module
//! functions instead ([`easy::Signer::sign`], [`easy::verify`], [`cbor::content_id`],
//! [`identity::signer_id`]), each with its own signature.
//!
//! `naalpcore` reimplements no cryptography, no encoding, and no protocol logic: every
//! exported function below is a thin delegation to the real underlying function, named to
//! match what the external specs assume so a generic caller (a framework binding, an FFI
//! shim) has one small, stable surface to call through. The `naalp-ffi` C-ABI layer builds
//! on this facade.
//!
//! This mirrors `impl/go/naalpcore/naalpcore.go`. The two facades are NOT byte-identical in
//! parameter shape because the real Go and Rust convenience layers ([`crate::easy`] here;
//! `impl/go/naalp` there) are themselves not identical — `naalpcore` on each side picks that
//! side's own canonical happy-path function rather than inventing a shared shape neither
//! language actually has. See the delegation-differences note in the build-plan doc.
//!
//! This module is purely additive. It does not touch the wire format, the CDDL, any
//! conformance vector, or any existing `impl/rust` file — it only imports and calls them.

use crate::cbor::{self, Value};
use crate::cose;
use crate::easy;
use crate::envelope::Object;
use crate::identity;

/// Re-exports the COSE algorithm identifier for ML-DSA-65 a caller passes to
/// [`signer_id`] (design.md §4.1, RFC 9964). `naalpcore` introduces no new algorithm
/// identifier — this is the same constant [`crate::cose`] and [`crate::identity`] already
/// use.
pub const ALG_MLDSA65: i64 = cose::ALG_MLDSA65;

/// Re-exports the COSE algorithm identifier for ML-DSA-87 a caller passes to
/// [`signer_id`] (design.md §4.1, RFC 9964). See [`ALG_MLDSA65`].
pub const ALG_MLDSA87: i64 = cose::ALG_MLDSA87;

/// A deterministic ML-DSA-65 signing identity. It is a direct alias of [`easy::Signer`]
/// (`impl/rust/src/easy.rs`) — `naalpcore` adds no key-management logic of its own; a
/// `Signer` signs under the Public profile (`cose::PROFILE_PUBLIC`).
pub type Signer = easy::Signer;

/// Delegates to [`easy::Signer::from_seed`]: it derives a `Signer` from a 32-byte FIPS 204
/// ML-DSA-65 key-generation seed. The same seed always yields the same identity.
///
/// Unlike the Go facade's `NewSigner`/`GenerateSigner` pair, this facade exposes only the
/// seed-derived constructor: [`easy::Signer`] has no random-generation convenience to
/// delegate to, and adding one here would be new logic, not a thin delegation — so it is
/// deliberately not built (recorded as open work, not invented).
pub fn new_signer(seed: &[u8; 32]) -> Signer {
    easy::Signer::from_seed(seed)
}

/// Delegates to [`easy::Signer::sign`] — the canonical happy-path object-signing call. The
/// caller supplies the `(channel, kind)` a captured action belongs to (per the frozen
/// registry in [`crate::channels`]) and the CBOR body; the object's declared effect and
/// signing profile are derived from the registry entry for `(channel, kind)`, never
/// supplied by the caller, and the `created` timestamp is the current wall clock (the same
/// canonical happy path the Go facade's `Sign` takes an explicit `created` for — Rust's own
/// canonical happy-path signer does not take one; a caller needing an explicit `created`
/// should call [`easy::Signer::sign_at`] directly). An unregistered `(channel, kind)` is
/// rejected (`UnknownKind`) before any signing work. Returns the tagged, deterministic-CBOR
/// COSE_Sign1 envelope bytes.
pub fn sign(s: &Signer, channel: u64, kind: u64, body: Value) -> Result<Vec<u8>, cose::Error> {
    s.sign(channel, kind, body)
}

/// Delegates to [`easy::verifier_from_public_key`] then [`easy::verify`] — the canonical
/// happy-path verification call, taking raw public-key bytes directly (mirroring the Go
/// facade's `Verify(pub, obj)` shape) rather than requiring the caller to construct a
/// verifier first. It runs the full envelope check (content id, field ranges,
/// header/body copies, critical extensions, `(channel, kind)` admission against the frozen
/// registry, profile floor, and the COSE signature), then additionally enforces the
/// registry's effect binding for the kind. Any failure is fail-closed with the SDK's named
/// [`cose::Error`] and no partial result.
pub fn verify(pub_key: &[u8], obj: &[u8]) -> Result<Object, cose::Error> {
    let verifier = easy::verifier_from_public_key(pub_key)?;
    easy::verify(&verifier, obj)
}

/// Delegates to [`cbor::content_id`]: the object content-id of a body value with field 1
/// (the id itself) omitted — multihash(0x20, SHA-384(canonical-encoding(body))), a 50-byte
/// value (`0x20 0x30` || 48-byte digest; design.md §2.3). `content_id` is a pure function of
/// the body bytes: the same body always produces the same id, and a changed body always
/// produces a different id.
pub fn content_id(body_without_id: &Value) -> Result<Vec<u8>, cbor::Error> {
    cbor::content_id(body_without_id)
}

/// Delegates to [`identity::signer_id`]: the self-certifying signer id derived from
/// `(alg, pubkey)` alone (design.md §5.1) — a pure function of the public key, computed
/// with no external registry lookup. `alg` must be [`ALG_MLDSA65`] or [`ALG_MLDSA87`]; any
/// other value is rejected before any digest is computed.
pub fn signer_id(alg: i64, pubkey: &[u8]) -> Result<String, cose::Error> {
    identity::signer_id(alg, pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Interaction surface (channel 0x000F=15): Respond (kind 1) has the registry's
    // declared effect idempotent_write (1). Same fixture `easy`'s own tests use.
    const INTERACTION: u64 = 0x000F;
    const RESPOND: u64 = 1;

    fn text(o: &Object) -> Option<String> {
        match &o.body {
            Value::Tstr(s) => Some(s.clone()),
            _ => None,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let s = new_signer(&[0x0c; 32]);
        let obj_bytes = sign(&s, INTERACTION, RESPOND, Value::Tstr("hello from naalpcore".into()))
            .expect("sign a registered kind");
        let got = verify(s.public_key(), &obj_bytes).expect("valid object verifies offline");
        assert_eq!((got.channel, got.kind, got.effect), (INTERACTION, RESPOND, 1));
        assert_eq!(text(&got).as_deref(), Some("hello from naalpcore"));
        assert_eq!(std::str::from_utf8(&got.signer).unwrap(), s.id());
    }

    // MUTATION ANCHOR (fail-closed on tamper): a one-bit change anywhere in the signed
    // bytes must be rejected. If `verify` were bypassed (returned Ok unconditionally), this
    // assertion flips pass->fail.
    #[test]
    fn verify_rejects_tamper() {
        let s = new_signer(&[0x0d; 32]);
        let obj_bytes = sign(&s, INTERACTION, RESPOND, Value::Tstr("x".into())).unwrap();
        verify(s.public_key(), &obj_bytes).expect("untouched object verifies");
        for i in 0..obj_bytes.len() {
            let mut tampered = obj_bytes.clone();
            tampered[i] ^= 0x01;
            assert!(
                verify(s.public_key(), &tampered).is_err(),
                "byte {i} flip must be rejected"
            );
        }
    }

    // MUTATION ANCHOR (registry gate at sign): an unregistered (channel, kind) must not sign.
    #[test]
    fn sign_rejects_unknown_kind() {
        let s = new_signer(&[0x0e; 32]);
        match sign(&s, INTERACTION, 99, Value::Tstr("x".into())) {
            Err(e) => assert_eq!(e.kind, "UnknownKind"),
            Ok(_) => panic!("an unregistered kind was signed"),
        }
    }

    #[test]
    fn content_id_deterministic_and_unique() {
        let a = Value::Map(vec![(Value::Uint(1), Value::Tstr("alpha".into()))]);
        let b = Value::Map(vec![(Value::Uint(1), Value::Tstr("beta".into()))]);
        let id_a1 = content_id(&a).expect("content_id of a");
        let id_a2 = content_id(&a).expect("content_id of a again");
        let id_b = content_id(&b).expect("content_id of b");
        assert_eq!(id_a1, id_a2, "same body must produce the same id");
        assert_ne!(id_a1, id_b, "different bodies must produce different ids");
        assert_eq!(id_a1.len(), 50, "multihash(0x20, SHA-384) is 50 bytes");
        assert_eq!(&id_a1[0..2], &[0x20, 0x30], "multihash sha2-384/48 prefix");
    }

    // MUTATION ANCHOR: `SignerID(alg, pubkey)` must agree with the id a Signer was
    // constructed with, cross-checked directly against `identity::signer_id`, and two
    // different keys must produce two different ids.
    #[test]
    fn signer_id_extraction_cross_check() {
        let s1 = new_signer(&[0x01; 32]);
        let s2 = new_signer(&[0x02; 32]);
        let id1 = signer_id(ALG_MLDSA65, s1.public_key()).expect("signer_id for key 1");
        let id2 = signer_id(ALG_MLDSA65, s2.public_key()).expect("signer_id for key 2");
        assert_eq!(id1, s1.id(), "facade signer_id must agree with the Signer's own id");
        assert_ne!(id1, id2, "different keys must produce different signer ids");
        // Direct cross-check against the underlying module the facade delegates to.
        assert_eq!(
            id1,
            identity::signer_id(cose::ALG_MLDSA65, s1.public_key()).unwrap()
        );
    }

    #[test]
    fn signer_id_rejects_unknown_alg() {
        let s = new_signer(&[0x03; 32]);
        match signer_id(-1, s.public_key()) {
            Err(_) => {}
            Ok(_) => panic!("an unregistered algorithm id was accepted"),
        }
    }
}
