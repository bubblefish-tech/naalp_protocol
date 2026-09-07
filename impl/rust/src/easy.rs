// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Ergonomic sign/verify convenience layer over the raw N-AALP SDK.
//!
//! This module adds NO new cryptography and NO second encoding. It is a thin,
//! well-named facade that collapses the common paths — derive a signer, build and
//! sign one object, verify one object offline — into a minimal call each, delegating
//! every byte-producing step to the same primitives the conformance corpus grades:
//! [`crate::cose`] (COSE_Sign1 + deterministic ML-DSA-65), [`crate::identity`]
//! (the self-certifying signer id), [`crate::envelope`] (`sign` / `verify`), and
//! [`crate::channels`] (the frozen twenty-channel registry). Every failure surfaces
//! the SDK's own named, fail-closed [`cose::Error`].

use crate::cbor::Value;
use crate::channels;
use crate::cose::{self, CoseVerifier};
use crate::envelope::{self, Object};
use crate::identity;
use fips204::traits::SerDes as _;

/// A deterministic ML-DSA-65 signer bound to its self-certifying N-AALP signer id.
///
/// Constructing one derives the keypair from a seed and computes the signer id once;
/// every object it signs carries that id in field 5 and in the protected-header copy,
/// so a verifier can confirm the id is a pure function of the key that signed.
pub struct Signer {
    id: String,
    public_key: Vec<u8>,
    secret: fips204::ml_dsa_65::PrivateKey,
    public: fips204::ml_dsa_65::PublicKey,
}

impl Signer {
    /// Derives a deterministic ML-DSA-65 signer from a 32-byte FIPS 204 key-generation
    /// seed (ξ) and computes its self-certifying signer id. The seed maps to exactly one
    /// keypair (the FIPS 204 deterministic keygen path), so the same seed always yields
    /// the same identity.
    pub fn from_seed(seed: &[u8; 32]) -> Signer {
        let (public, secret) = cose::mldsa65_keypair_from_seed(seed);
        let public_key = public.clone().into_bytes().to_vec();
        // ML-DSA-65 is a registered algorithm, so signer_id never fails here.
        let id = identity::signer_id(cose::ALG_MLDSA65, &public_key)
            .expect("ML-DSA-65 is a registered algorithm");
        Signer {
            id,
            public_key,
            secret,
            public,
        }
    }

    /// Returns this signer's self-certifying signer id (the multibase/multihash string
    /// bound into every object it produces).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the raw ML-DSA-65 public-key bytes a verifying peer needs. Hand these to a
    /// counterparty (over any channel); the peer reconstructs a verifier with
    /// [`verifier_from_public_key`].
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns a verifier for this signer's key, for an in-process counterparty. A
    /// cross-process peer that received only [`Signer::public_key`] bytes should call
    /// [`verifier_from_public_key`] instead.
    pub fn verifier(&self) -> cose::MlDsa65Verifier {
        cose::MlDsa65Verifier(self.public.clone())
    }

    /// Signs `body` as a `(channel, kind)` object under the Public profile, using the
    /// effect the frozen channel registry declares for that kind. Returns the signed,
    /// deterministic-CBOR envelope bytes.
    ///
    /// Fail-closed: an unregistered `(channel, kind)` returns `UnknownKind`, and a kind
    /// whose effect is variable (it is not fixed by the registry) returns `EffectRequired`
    /// — such a kind must be signed with [`Signer::sign_with_effect`].
    pub fn sign(&self, channel: u64, kind: u64, body: Value) -> Result<Vec<u8>, cose::Error> {
        let spec = channels::lookup(channel, kind).ok_or_else(channels::err_unknown_kind)?;
        if spec.variable {
            return Err(cose::Error {
                kind: "EffectRequired",
                msg: "this kind has a variable effect; use sign_with_effect",
            });
        }
        Ok(self.build_and_sign(channel, kind, spec.effect, now_millis(), body))
    }

    /// Signs `body` as a `(channel, kind)` object under the Public profile with an explicit
    /// `effect`. Returns the signed envelope bytes.
    ///
    /// Fail-closed: the effect is validated against the frozen registry's binding for the
    /// kind ([`channels::check_effect`]) before anything is signed — an unregistered
    /// `(channel, kind)` returns `UnknownKind`, and an effect a fixed-effect kind does not
    /// declare returns `EffectDeclarationMismatch`.
    pub fn sign_with_effect(
        &self,
        channel: u64,
        kind: u64,
        effect: u8,
        body: Value,
    ) -> Result<Vec<u8>, cose::Error> {
        channels::check_effect(channel, kind, effect as u64)?;
        Ok(self.build_and_sign(channel, kind, effect, now_millis(), body))
    }

    /// Signs `body` with an explicit `effect` and an explicit `created` position, for a
    /// reproducible envelope (no wall-clock). The effect is registry-validated exactly as
    /// in [`Signer::sign_with_effect`].
    pub fn sign_at(
        &self,
        channel: u64,
        kind: u64,
        effect: u8,
        created: u64,
        body: Value,
    ) -> Result<Vec<u8>, cose::Error> {
        channels::check_effect(channel, kind, effect as u64)?;
        Ok(self.build_and_sign(channel, kind, effect, created, body))
    }

    // Assembles the C3 object and delegates the content-id binding + COSE_Sign1 to
    // envelope::sign — the same construction the conformance corpus grades.
    fn build_and_sign(
        &self,
        channel: u64,
        kind: u64,
        effect: u8,
        created: u64,
        body: Value,
    ) -> Vec<u8> {
        let mut o = Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind,
            channel,
            tier: 0,
            signer: self.id.clone().into_bytes(),
            created,
            effect: effect as u64,
            causes: vec![],
            profile: cose::PROFILE_PUBLIC as u64,
            body,
            ext: None,
            cext: None,
        };
        envelope::sign(&mut o, &cose::MlDsa65Signer(self.secret.clone()))
    }
}

/// Reconstructs an ML-DSA-65 verifier from raw public-key bytes — the cross-process peer's
/// path, where only [`Signer::public_key`] bytes were received.
///
/// Fail-closed: a byte string that is not a valid ML-DSA-65 public key (wrong length or bad
/// encoding) returns `Malformed`.
pub fn verifier_from_public_key(public_key: &[u8]) -> Result<cose::MlDsa65Verifier, cose::Error> {
    let arr: [u8; fips204::ml_dsa_65::PK_LEN] = public_key.try_into().map_err(|_| cose::Error {
        kind: "Malformed",
        msg: "ML-DSA-65 public key must be exactly 1952 bytes",
    })?;
    let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(arr).map_err(|_| cose::Error {
        kind: "Malformed",
        msg: "not a valid ML-DSA-65 public key encoding",
    })?;
    Ok(cose::MlDsa65Verifier(pk))
}

/// Verifies a signed N-AALP object offline under the Public profile and returns the decoded
/// object. Delegates the whole check chain to [`envelope::verify`] against the frozen
/// twenty-channel registry ([`channels::kind_validator`]), then additionally enforces the
/// registry's effect binding ([`channels::check_effect`]) — a check the bare envelope leaves
/// to the caller. Every failure is the SDK's named, fail-closed [`cose::Error`].
pub fn verify(verifier: &dyn CoseVerifier, envelope_bytes: &[u8]) -> Result<Object, cose::Error> {
    verify_with_profile(cose::PROFILE_PUBLIC, verifier, envelope_bytes)
}

/// Like [`verify`], under a caller-chosen crypto profile (`cose::PROFILE_PUBLIC` /
/// `PROFILE_ENTERPRISE` / `PROFILE_SOVEREIGN`).
pub fn verify_with_profile(
    profile: u32,
    verifier: &dyn CoseVerifier,
    envelope_bytes: &[u8],
) -> Result<Object, cose::Error> {
    let kind_ok = |ch: u64, k: u64| channels::kind_validator(ch, k);
    let obj = envelope::verify(profile, verifier, &kind_ok, &[], envelope_bytes)?;
    channels::check_effect(obj.channel, obj.kind, obj.effect)?;
    Ok(obj)
}

/// The current Unix time in milliseconds, or 0 if the clock is before the epoch.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Interaction surface (channel 0x000F=15): Respond (kind 1) has the registry's
    // declared effect idempotent_write (1). Used as the running "message post" example.
    const INTERACTION: u64 = 0x000F;
    const RESPOND: u64 = 1;

    fn text(o: &Object) -> Option<String> {
        match &o.body {
            Value::Tstr(s) => Some(s.clone()),
            _ => None,
        }
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let a = Signer::from_seed(&[0x0a; 32]);
        let envelope = a
            .sign(INTERACTION, RESPOND, Value::Tstr("hello from A".into()))
            .expect("sign a registered kind");
        // The peer reconstructs a verifier from the raw public key bytes (cross-process path).
        let v = verifier_from_public_key(a.public_key()).expect("reconstruct verifier");
        let got = verify(&v, &envelope).expect("valid object verifies offline");
        assert_eq!(
            (got.channel, got.kind, got.effect),
            (INTERACTION, RESPOND, 1)
        );
        assert_eq!(text(&got).as_deref(), Some("hello from A"));
        // The signer id inside the object is self-certifying for A's key.
        identity::check_signer(
            std::str::from_utf8(&got.signer).unwrap(),
            cose::ALG_MLDSA65,
            a.public_key(),
        )
        .expect("object signer id is bound to the signing key");
        assert_eq!(std::str::from_utf8(&got.signer).unwrap(), a.id());
    }

    // MUTATION ANCHOR (fail-closed on tamper): a one-bit change anywhere in the signed
    // bytes must be rejected. If verify were bypassed (returned Ok unconditionally), this
    // assertion flips pass->fail.
    #[test]
    fn tamper_is_rejected() {
        let a = Signer::from_seed(&[0x0a; 32]);
        let envelope = a
            .sign(INTERACTION, RESPOND, Value::Tstr("hello from A".into()))
            .unwrap();
        let v = a.verifier();
        verify(&v, &envelope).expect("the untouched object verifies");
        let mut tampered = envelope.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        assert!(
            verify(&v, &tampered).is_err(),
            "a tampered object must be rejected (fail-closed)"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = Signer::from_seed(&[0x0a; 32]);
        let b = Signer::from_seed(&[0x0b; 32]);
        let envelope = a
            .sign(INTERACTION, RESPOND, Value::Tstr("hello".into()))
            .unwrap();
        match verify(&b.verifier(), &envelope) {
            Err(e) => assert_eq!(e.kind, "BadSignature"),
            Ok(_) => panic!("an object verified under the wrong key"),
        }
    }

    // MUTATION ANCHOR (registry gate at sign): an unregistered (channel, kind) must not sign.
    #[test]
    fn unknown_kind_rejected_at_sign() {
        let a = Signer::from_seed(&[0x0a; 32]);
        match a.sign(INTERACTION, 99, Value::Tstr("x".into())) {
            Err(e) => assert_eq!(e.kind, "UnknownKind"),
            Ok(_) => panic!("an unregistered kind was signed"),
        }
    }

    // A variable-effect kind (Stream StreamOpen, channel 0x000C kind 0) cannot be signed via
    // the effect-deriving `sign`; `sign_with_effect` accepts an explicit valid effect.
    #[test]
    fn variable_effect_kind_requires_explicit_effect() {
        let a = Signer::from_seed(&[0x0a; 32]);
        match a.sign(0x000C, 0, Value::Uint(0)) {
            Err(e) => assert_eq!(e.kind, "EffectRequired"),
            Ok(_) => panic!("a variable-effect kind was signed without an effect"),
        }
        let env = a
            .sign_with_effect(0x000C, 0, crate::policy::READ_ONLY, Value::Uint(0))
            .expect("explicit valid effect on a variable kind");
        let v = a.verifier();
        verify(&v, &env).expect("variable-effect object verifies");
    }

    // MUTATION ANCHOR (effect binding at verify): an object whose effect contradicts the
    // registry's declared effect for its kind passes the bare envelope check but is rejected
    // by easy::verify. Removing the check_effect line in verify_with_profile flips this
    // pass->fail.
    #[test]
    fn effect_binding_enforced_on_verify() {
        let a = Signer::from_seed(&[0x0a; 32]);
        // Respond declares idempotent_write(1); sign it with destructive(3), which the bare
        // envelope range-check permits but the registry binding forbids.
        let env = a
            .sign_at(
                INTERACTION,
                RESPOND,
                crate::policy::DESTRUCTIVE,
                1,
                Value::Uint(0),
            )
            .expect_err("sign_with_effect/at must reject a registry-inconsistent effect");
        assert_eq!(env.kind, "EffectDeclarationMismatch");

        // Build the same registry-inconsistent object with the RAW envelope (which does not
        // enforce the binding) and confirm easy::verify rejects it.
        let mut o = Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind: RESPOND,
            channel: INTERACTION,
            tier: 0,
            signer: a.id().as_bytes().to_vec(),
            created: 1,
            effect: crate::policy::DESTRUCTIVE as u64,
            causes: vec![],
            profile: cose::PROFILE_PUBLIC as u64,
            body: Value::Uint(0),
            ext: None,
            cext: None,
        };
        // The child test module can reach Signer's private key to drive the RAW envelope path.
        let raw = envelope::sign(&mut o, &cose::MlDsa65Signer(a.secret.clone()));
        match verify(&a.verifier(), &raw) {
            Err(e) => assert_eq!(e.kind, "EffectDeclarationMismatch"),
            Ok(_) => panic!("a registry-inconsistent effect verified"),
        }
    }

    #[test]
    fn malformed_public_key_rejected() {
        match verifier_from_public_key(&[0u8; 10]) {
            Err(e) => assert_eq!(e.kind, "Malformed"),
            Ok(_) => panic!("a too-short public key produced a verifier"),
        }
    }
}
