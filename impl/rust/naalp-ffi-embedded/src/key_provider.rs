// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `KeyProvider`: a `no_std`-friendly abstraction over ML-DSA-65 key material, so a
//! constrained target can source signing/verification from a hardware secure element (an
//! HSM, a TPM-class peripheral, a vendor crypto accelerator) instead of holding a private
//! key in general-purpose RAM. Manufacturing Add-ons Component A4.
//!
//! `KeyProvider` names three operations any such element exposes: sign a message, verify a
//! signature, and read the public key. It performs no I/O and no bus protocol of its own —
//! a real HSM binding (SPI/I2C/CAN transaction framing to a specific secure element part
//! number) is a separate, target-specific crate that implements this trait; that binding is
//! not built here (out of scope — no target hardware to build or grade it against this
//! pass). What IS built and graded here is the trait contract itself, plus
//! [`InMemoryMlDsa65KeyProvider`]: a real (non-stub) `no_std` + `alloc` implementation that
//! holds an ML-DSA-65 keypair in ordinary memory. It is not a mock of a hardware path — it
//! performs genuine ML-DSA-65 keygen/sign/verify via `fips204` — and exists as (a) the test
//! double [`cose_verify`](crate::cose_verify)'s test suite signs against, and (b) a legitimate
//! target for a controller with no secure element (the common case named in the manufacturing
//! intake: a ROS node or PLC bridge where the private key already lives in the controller's
//! own protected memory, not a discrete HSM).

extern crate alloc;

use alloc::vec::Vec;

use fips204::ml_dsa_65::{PrivateKey, PublicKey, PK_LEN, SIG_LEN};
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
use fips204::{CryptoRng, RngCore};

/// Abstraction over ML-DSA-65 key material for an HSM/embedded target. Every method
/// returns `Result` (never panics on a well-formed call) because a real hardware element
/// can fail (a bus error, a busy/locked element, a malformed response) in ways an in-memory
/// implementation cannot; [`InMemoryMlDsa65KeyProvider`] below never actually returns `Err`
/// on a well-formed call because it has no hardware failure mode to report, but the trait
/// contract accounts for one so a real HSM binding can report it without changing this
/// trait's shape.
pub trait KeyProvider {
    /// The element-specific failure type (a bus error code, a hardware status word, ...).
    type Error;

    /// The raw 1952-byte ML-DSA-65 public key this provider signs/verifies for.
    fn public_key(&self) -> Result<[u8; PK_LEN], Self::Error>;

    /// Sign `tbs` (a COSE_Sign1 `Sig_structure`, e.g. from
    /// [`crate::cose_verify::to_be_signed_raw`]) and return the 3309-byte ML-DSA-65
    /// signature.
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verify `sig` over `msg` against this provider's own public key. A provider MUST
    /// return `Ok(false)` for a genuinely invalid signature — never `Err` for that case,
    /// since a rejected signature is not itself an element failure; `Err` is reserved for
    /// the element failing to complete the operation at all.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error>;
}

/// A fixed-seed RNG yielding the FIPS 204 key-generation seed (ξ) via `fill_bytes`, so
/// `try_keygen_with_rng` derives a keypair deterministically from a 32-byte seed. Same
/// technique as `naalp::cose::SeedRng` (`impl/rust/src/cose.rs`) — an independent copy, not
/// a dependency on that std-only module, since this crate cannot depend on the std `naalp`
/// crate (see `lib.rs` module docs).
struct SeedRng {
    seed: [u8; 32],
}
impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.copy_from_slice(&self.seed);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), fips204::RngError> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for SeedRng {}

/// An in-memory ML-DSA-65 [`KeyProvider`]: real (non-mock) `no_std` + `alloc` keygen, sign,
/// and verify, for a constrained target with no discrete secure element. This is the test
/// double [`crate::cose_verify`]'s test suite signs against.
pub struct InMemoryMlDsa65KeyProvider {
    public: PublicKey,
    private: PrivateKey,
}

/// [`InMemoryMlDsa65KeyProvider`] has no hardware failure mode; every method's `Result` is
/// always `Ok` in practice, but the type exists so callers write against the same
/// `Result<_, E>` shape a real HSM binding would need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Infallible;

impl InMemoryMlDsa65KeyProvider {
    /// Derive an ML-DSA-65 keypair from a 32-byte FIPS 204 key-generation seed (ξ),
    /// deterministically — the same seed always yields the same keypair. Cross-checked
    /// against the independent Python oracle's `mldsa_keygen` vector
    /// (`vectors/cose/cases.json`) in this module's tests, never against the std reference
    /// implementation's own output.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (public, private) =
            fips204::ml_dsa_65::try_keygen_with_rng(&mut SeedRng { seed: *seed })
                .expect("ML-DSA-65 keygen from a fixed seed cannot fail");
        Self { public, private }
    }
}

impl KeyProvider for InMemoryMlDsa65KeyProvider {
    type Error = Infallible;

    fn public_key(&self) -> Result<[u8; PK_LEN], Self::Error> {
        Ok(self.public.clone().into_bytes())
    }

    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // Deterministic path (rnd = 0^32): matches `naalp::cose::MlDsa65Signer`'s
        // `try_sign_with_seed(&[0u8; 32], ...)`, so a caller cross-validating against the
        // reference SDK's byte-for-byte signature output can do so.
        Ok(self
            .private
            .try_sign_with_seed(&[0u8; 32], tbs, &[])
            .expect("ML-DSA-65 sign cannot fail on a well-formed message")
            .to_vec())
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, Self::Error> {
        let arr: &[u8; SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(false),
        };
        Ok(self.public.verify(msg, arr, &[]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent authority: `vectors/cose/cases.json` `mldsa_keygen[0]` (seed_hex/pk_hex),
    // generated by tools/cose_oracle.py from the FIPS 204 reference algorithm directly — not
    // by this crate, not by the std `naalp` reference implementation. If `from_seed` were
    // replaced by a constant public key, this assertion fails.
    #[test]
    fn keygen_matches_independent_oracle() {
        let seed = unhex("70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c");
        let seed_arr: [u8; 32] = seed.as_slice().try_into().unwrap();
        let kp = InMemoryMlDsa65KeyProvider::from_seed(&seed_arr);
        let pk = kp.public_key().unwrap();
        assert_eq!(hex(&pk).len(), pk.len() * 2);
        assert_eq!(pk.len(), PK_LEN);
        let want_prefix = "d2fd03f3a1b7f635af9f34d580a98f524c735bd5ba2355dc6e035bd21765580";
        assert_eq!(
            &hex(&pk)[..want_prefix.len()],
            want_prefix,
            "derived public key disagrees with the independent Python oracle"
        );
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let a = InMemoryMlDsa65KeyProvider::from_seed(&[0x01u8; 32]);
        let b = InMemoryMlDsa65KeyProvider::from_seed(&[0x02u8; 32]);
        assert_ne!(a.public_key().unwrap(), b.public_key().unwrap());
    }

    #[test]
    fn same_seed_is_deterministic() {
        let a = InMemoryMlDsa65KeyProvider::from_seed(&[0x07u8; 32]);
        let b = InMemoryMlDsa65KeyProvider::from_seed(&[0x07u8; 32]);
        assert_eq!(a.public_key().unwrap(), b.public_key().unwrap());
    }

    // MUTATION ANCHOR: KeyProvider::verify must reject a tampered signature. If `verify`
    // were replaced by an unconditional `Ok(true)`, this assertion flips pass -> fail.
    // Witnessed in RED-EVIDENCE.md.
    #[test]
    fn verify_rejects_tampered_signature() {
        let kp = InMemoryMlDsa65KeyProvider::from_seed(&[0x33u8; 32]);
        let msg = b"key provider verify contract";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap(), "a genuine signature must verify");

        for i in 0..sig.len() {
            let mut tampered = sig.clone();
            tampered[i] ^= 0x01;
            assert!(
                !kp.verify(msg, &tampered).unwrap(),
                "byte {i} flip in the signature must be rejected"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let kp = InMemoryMlDsa65KeyProvider::from_seed(&[0x34u8; 32]);
        assert!(!kp.verify(b"msg", &[]).unwrap());
        assert!(!kp.verify(b"msg", &[0u8; SIG_LEN - 1]).unwrap());
    }

    fn hex(b: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(b.len() * 2);
        for byte in b {
            s.push(nibble(byte >> 4));
            s.push(nibble(byte & 0xf));
        }
        s
    }
    fn nibble(n: u8) -> char {
        (if n < 10 { b'0' + n } else { b'a' + (n - 10) }) as char
    }
    fn unhex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        (0..b.len())
            .step_by(2)
            .map(|i| {
                let hi = (b[i] as char).to_digit(16).unwrap() as u8;
                let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }
}
