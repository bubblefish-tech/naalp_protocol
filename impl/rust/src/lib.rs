// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! N-AALP reference implementation (draft-bubblefish-naalp-01).
//!
//! Modules are added per the build plan in `tasks.md`, spine first
//! (deterministic CBOR, COSE signing, envelope, identity, effect, approval,
//! audit, delivery, streaming), then the twenty channel surfaces and carriage.
//! Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

pub mod agui;
pub mod approval;
pub mod audit;
pub mod carriage;
pub mod cbor;
pub mod channels;
pub mod continuation;
pub mod cose;
pub mod delegation;
pub mod delivery;
pub mod description;
pub mod easy;
pub mod envelope;
pub mod evidence_record;
pub mod federation;
pub mod gateway;
pub mod identity;
pub mod mcp;
pub mod naalpcore;
pub mod naalperror;
pub mod naming;
pub mod negotiation;
pub mod payment;
pub mod policy;
pub mod refusal;
pub mod rooms;
pub mod streaming;
pub mod transport;
