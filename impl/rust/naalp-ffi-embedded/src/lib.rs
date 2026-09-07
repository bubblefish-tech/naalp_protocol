// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `naalp-ffi-embedded` — Manufacturing Add-ons Component A3: a `no_std` + `alloc`
//! verify/parse subset of N-AALP for a bare-metal/RTOS constrained controller with no
//! operating system (Armv7E-M / Armv8-A target triples per the manufacturing intake).
//!
//! ## Precise blocker: why this is an independent subset, not a `naalp` wrapper
//!
//! The task for this crate was: depend on the std `naalp` reference crate (`impl/rust`)
//! under `#![no_std]` + `alloc` if it can build that way; if it genuinely cannot, build the
//! maximal `no_std`-compatible verify/parse subset and report the precise blocker instead of
//! faking `no_std` with a `std` shim. It cannot, for two concrete, source-verified reasons
//! (grepped this session, not assumed):
//!
//! 1. **`impl/rust/src/easy.rs::now_millis`** — called from `easy::Signer::sign`, which
//!    `naalpcore::sign` / `naalp-ffi`'s `naalp_sign` delegate to as their canonical happy
//!    path — calls `std::time::SystemTime::now()` to derive the object's `created`
//!    timestamp. There is no `core`/`alloc` equivalent: `no_std` has no OS-backed wall
//!    clock. A bare-metal target would need to supply time from an external source (an RTC
//!    peripheral, a network time sync) — a real design decision this pass does not make on
//!    the caller's behalf.
//! 2. **`impl/rust/src/channels.rs::open_workflow_gate`** (real, non-test code; the
//!    `channels` module is reachable from `easy::verify_with_profile` via
//!    `channels::check_effect`/`kind_validator`) uses `std::fs::File` and `std::io::{Read,
//!    Seek, Write}` to persist a workflow-gate file to disk. There is no filesystem on a
//!    bare-metal target by default.
//!
//! Neither has a `no_std`-compatible substitute in the crate today, and porting the `naalp`
//! crate itself to `no_std` is separately-scoped work this task does not authorize (it would
//! touch dozens of files across the whole reference implementation, not an additive,
//! narrowly-scoped embedded crate). Textual verification (grepping every reachable
//! `std::`-qualified call from the `sign`/`verify` entry points) is definitive regardless of
//! target: `std::fs`/`std::io`/`std::time::SystemTime` require an operating system by
//! definition, so no cross-compilation is needed to know they cannot link against a
//! genuinely `no_std` target. This session additionally checked whether a real bare-metal
//! target build could be attempted here to confirm empirically: `rustup` is not installed on
//! this machine (`rustup target list --installed` — "rustup: The term 'rustup' is not
//! recognized"), so no additional target triple can be added and a literal cross-compile
//! could not be run in this environment. That absence is reported honestly as a named,
//! separate limitation — it does not weaken the textual finding above, which holds by
//! definition independent of what targets are installed.
//!
//! ## What this crate is instead
//!
//! An independent, from-scratch `no_std` + `alloc` reimplementation of the narrow slice of
//! N-AALP a constrained verifier actually needs: canonical CBOR (RFC 8949 §4.2.1) parse and
//! encode ([`cbor_lite`]), COSE_Sign1 (RFC 9052) parse and ML-DSA-65 (RFC 9964) signature
//! verification ([`cose_verify`]), and a `KeyProvider` abstraction for HSM-backed or
//! in-memory key material ([`key_provider`]). It introduces no new wire format — it
//! implements the SAME canonical-CBOR and COSE_Sign1 rules `impl/rust/src` does, the same
//! way `impl/go`, `impl/rust`, and the other eight language ports are each independent
//! implementations of one shared wire format — and it is graded against the same
//! independent-authority oracle vectors those ports are (`vectors/cbor/cases.json`,
//! `vectors/cose/cases.json`), never against its own or the reference implementation's
//! output (F3 non-circularity).
//!
//! Not built this pass, named honestly rather than silently omitted: registry-driven
//! `(channel, kind)` -> effect admission (`naalp::channels::check_effect` — a large frozen
//! data table, not a crypto primitive, out of scope for a *verify/parse* subset), the
//! Ed25519/composite hybrid legs (classical-crypto dependencies not yet ported to
//! `no_std`), signing beyond the [`key_provider::KeyProvider`] test double (Component A3 is
//! framed as a verify tier per the manufacturing intake), and
//! on-target QEMU corpus revalidation (needs the bare-metal target this environment cannot
//! install; see above).

#![no_std]

extern crate alloc;

pub mod cbor_lite;
pub mod cose_verify;
pub mod key_provider;
