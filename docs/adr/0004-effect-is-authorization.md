<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# 0004 — Effect is an authorization input, not a hint

- Status: accepted
- Date: 2026-07-27

## Context

The N-PAMP Bridge SafetyLabel "describes intent and does not replace authorization" — it is an
advisory hint. For autonomous agents taking consequential actions, an advisory label is
insufficient: nothing stops a destructive action labeled `read_only`, or an unrecognized label
being treated as safe.

## Decision

The N-AALP **effect** (a closed four-value set aligned 1:1 with the SafetyLabel) is an
**authorization input**. An endpoint grants a maximum effect (a capability) to an authenticated
signer id, and an object is authorized only if its effect does not exceed the grant
(`EffectNotAuthorized` otherwise). An unrecognized effect **fails closed to destructive** and is
never treated as safe. Authorization is never derived from transport metadata, a foreign header, or
a client-supplied name — only from the signature-verified signer id.

## Consequences

The gap a pure intent label leaves open is closed: the effect gates execution. The 1:1 alignment
with the SafetyLabel keeps carriage over the N-PAMP Bridge loss-free (no fifth effect class). A
value-bearing object carries its money semantics in a signed body field, not a new effect.
