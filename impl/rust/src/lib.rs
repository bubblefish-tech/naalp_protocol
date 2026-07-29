// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP reference implementation (draft-bubblefish-naalp-00).
//!
//! Modules are added per the build plan in `tasks.md`, spine first
//! (deterministic CBOR, COSE signing, envelope, identity, effect, approval,
//! audit, delivery, streaming), then the twenty channel surfaces and carriage.
//! Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

pub mod approval;
pub mod audit;
pub mod carriage;
pub mod cbor;
pub mod channels;
pub mod cose;
pub mod delivery;
pub mod envelope;
pub mod federation;
pub mod identity;
pub mod policy;
pub mod streaming;
pub mod transport;
