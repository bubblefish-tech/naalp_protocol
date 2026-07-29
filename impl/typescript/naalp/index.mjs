// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP reference SDK (TypeScript/ESM) — barrel module re-exporting the spine surfaces.
//
// N-AALP makes the *object*, not the connection, the unit of security: every message is a
// deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
// content identity, its signer, a closed effect label, optional approval/audit bindings, and its
// causal derivation — verifiable offline, over any transport. The ergonomic surface is `envelope`
// (Object + sign + verify); the byte-level primitives live in the other submodules.

export * as cbor from './cbor.mjs';
export * as cose from './cose.mjs';
export * as identity from './identity.mjs';
export * as policy from './policy.mjs';
export * as records from './records.mjs';
export * as graph from './graph.mjs';
export * as channels from './channels.mjs';
export * as envelope from './envelope.mjs';

// the ergonomic surface, re-exported at the top level
export { Object_ as Object, sign, verify, EnvelopeError } from './envelope.mjs';
