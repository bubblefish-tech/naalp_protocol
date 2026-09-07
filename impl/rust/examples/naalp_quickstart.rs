// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Two-agent N-AALP quickstart: the core loop end-to-end with no hand-rolled crypto.
//!
//! Agent A derives an identity, builds and signs a real N-AALP object (a message posted on
//! the Interaction surface), and Agent B — given only the object bytes and Agent A's public
//! key — verifies it OFFLINE, reads it, and confirms Agent A's id is bound to the signing
//! key. Then a one-bit tamper is shown to be rejected, fail-closed. Every crypto step goes
//! through the real SDK's ergonomic layer (`naalp::easy`), which delegates to the same
//! COSE_Sign1 + deterministic ML-DSA-65 primitives the conformance corpus grades.
//!
//! Run it:
//!
//!   cargo run --example naalp_quickstart
//!
//! The program exits non-zero if any step differs from the expected outcome, so it doubles
//! as a self-checking smoke test: if verification were bypassed, the tamper step would not
//! reject and the program would fail.

use naalp::cbor::Value;
use naalp::channels;
use naalp::cose;
use naalp::easy;
use naalp::envelope::Object;
use naalp::identity;
use naalp::policy;

// The Interaction surface (channel 0x000F): Respond (kind 1) is a message posted back to a
// peer; the frozen registry declares its effect as idempotent_write.
const INTERACTION: u64 = 0x000F;
const RESPOND: u64 = 1;

fn main() {
    println!("N-AALP two-agent quickstart\n");

    // --- Agent A: derive an identity ------------------------------------------------------
    // A 32-byte seed maps to exactly one ML-DSA-65 keypair (deterministic FIPS 204 keygen).
    // In production this seed is generated once from a secure RNG and kept secret.
    let alice = easy::Signer::from_seed(&[0x0a; 32]);
    println!("[Agent A] generated identity");
    println!("          signer id : {}", alice.id());
    println!(
        "          public key: {} bytes (ML-DSA-65)\n",
        alice.public_key().len()
    );

    // --- Agent A: build + sign a message on the Interaction surface -----------------------
    let body = Value::Tstr("hello from Agent A".to_string());
    let envelope = match alice.sign(INTERACTION, RESPOND, body) {
        Ok(bytes) => bytes,
        Err(e) => fail(&format!("Agent A could not sign: {:?}", e)),
    };
    println!(
        "[Agent A] signed a {} object on channel {} ({}), effect {}",
        kind_name(INTERACTION, RESPOND),
        INTERACTION,
        channel_name(INTERACTION),
        effect_name(INTERACTION, RESPOND),
    );
    println!(
        "          envelope  : {} bytes (deterministic CBOR + COSE_Sign1)",
        envelope.len()
    );
    println!("          --> sends the envelope bytes + its public key to Agent B\n");

    // --- Agent B: verify offline from bytes + public key alone ---------------------------
    // Agent B holds ONLY what crossed the wire: the envelope bytes and Agent A's public key.
    // It rebuilds a verifier from those bytes (no private material, no network callback).
    let alice_public_key = alice.public_key(); // received out-of-band in a real deployment
    let verifier = match easy::verifier_from_public_key(alice_public_key) {
        Ok(v) => v,
        Err(e) => fail(&format!(
            "Agent B could not read Agent A's public key: {:?}",
            e
        )),
    };

    let object = match easy::verify(&verifier, &envelope) {
        Ok(o) => o,
        Err(e) => fail(&format!("Agent B rejected a valid object: {:?}", e)),
    };
    println!("[Agent B] VERIFIED offline (no network, no issuer callback)");
    println!(
        "          channel {} ({}), kind {} ({}), effect {}",
        object.channel,
        channel_name(object.channel),
        object.kind,
        kind_name(object.channel, object.kind),
        effect_name(object.channel, object.kind),
    );
    println!("          message   : {}", body_text(&object));

    // The signer id carried in the object is a pure function of the verifying key: recompute
    // and compare, so Agent B knows exactly which key authored the message.
    let claimed_id = match std::str::from_utf8(&object.signer) {
        Ok(s) => s,
        Err(_) => fail("Agent B: object signer id is not valid UTF-8"),
    };
    match identity::check_signer(claimed_id, cose::ALG_MLDSA65, alice_public_key) {
        Ok(()) => println!(
            "          signer id : {} (self-certifying: bound to the key)\n",
            claimed_id
        ),
        Err(e) => fail(&format!(
            "Agent B: signer id is not bound to the key: {:?}",
            e
        )),
    }

    // --- Tamper: a single flipped bit must be rejected, fail-closed ----------------------
    let mut tampered = envelope.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    match easy::verify(&verifier, &tampered) {
        Ok(_) => fail("a tampered object VERIFIED — verification is not fail-closed"),
        Err(e) => println!("[Agent B] REJECTED a tampered object, fail-closed: {:?}", e),
    }

    println!("\nOK: signed, verified offline, and rejected tampering — using the real SDK.");
}

/// The message body as text, or a placeholder for a non-text body.
fn body_text(o: &Object) -> String {
    match &o.body {
        Value::Tstr(s) => s.clone(),
        other => format!("<non-text body: {:?}>", other),
    }
}

/// The registry name for a channel id (e.g. 15 -> "Interaction").
fn channel_name(channel: u64) -> String {
    channels::table()
        .into_iter()
        .find(|c| c.id == channel)
        .map(|c| c.name.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The registry name for a (channel, kind) (e.g. (15,1) -> "Respond").
fn kind_name(channel: u64, kind: u64) -> String {
    channels::lookup(channel, kind)
        .map(|k| k.name.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The N-PAMP SafetyLabel name for a (channel, kind)'s declared effect.
fn effect_name(channel: u64, kind: u64) -> String {
    channels::lookup(channel, kind)
        .map(|k| policy::safety_label_name(k.effect).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn fail(msg: &str) -> ! {
    eprintln!("naalp_quickstart: {}", msg);
    std::process::exit(1);
}
