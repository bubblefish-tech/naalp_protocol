<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Memory (`0x0001`)

Durable shared memory operations — composes with N-PAMP's native `NPAMP-MEMORY` frames when N-AALP
runs over N-PAMP. Like every channel surface, Memory adds only kind codes and their declared
effects over the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `MemoryOffer` | `idempotent_write` | |
| 1 | `MemoryAccept` | `idempotent_write` | |
| 2 | `MemoryWrite` | `non_idempotent_write` | |
| 3 | `MemoryRead` | `read_only` | |
| 4 | `MemoryExpire` | `destructive` | |
| 5 | `MemoryRevoke` | `destructive` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Memory](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L60-L61)),
cross-checked against an independent per-channel oracle.

## State model

An entry is `offered → accepted → live → (expired | revoked)`. A write persists before its
acknowledgment, per the spine's own persist-before-ack rule (the draft's Delivery, Idempotence, and
Backpressure section) — the same durability discipline the [Workflow channel](workflow.md)'s
crash-safe gate is built from.

## Fail-closed access to a revoked or quarantined entry

`AccessDenied` covers both a read of a revoked entry and a read of an entry that is unexpired but
governance-held (quarantined) — the two are deliberately given the same fail-closed treatment
rather than distinguished by a softer error, so a caller cannot infer quarantine state from error
granularity. `MemoryError` preserves a governance hold as a result distinct from an ordinary
failure.

## Failure modes

| Error kind | When |
|---|---|
| `AccessDenied` | a read of a revoked or governance-quarantined entry |
| `MemoryError` | a governance hold on the entry, preserved as a distinct result |

Every check is fail-closed (the draft's Security Considerations section): a failing operation is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Content-addressed dedup across sessions and memory derivation via `causes`** are named higher
  tiers, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md).
