<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Knowledge (`0x0012`)

Shared knowledge and enterprise-graph facts. Like every channel surface, Knowledge adds only kind
codes and their declared effects over the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Assert` | `non_idempotent_write` | a signed fact |
| 1 | `Retract` | `destructive` | |
| 2 | `KnowledgeQuery` | `read_only` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Knowledge](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L96-L97)),
cross-checked against an independent per-channel oracle.

## State model

Facts are append-only with signed retractions: `asserted → retracted`. A fact names its provenance
via `causes` — the same causal-graph edge mechanism the [Audit channel](audit.md) uses to prove one
object's derivation from another offline.

## Failure modes

| Error kind | When |
|---|---|
| `FactUnsigned` | an asserted fact's signature does not verify |
| `RetractUnknown` | a retraction names a fact that was never asserted |

Every check is fail-closed (the draft's Security Considerations section): a failing fact or
retraction is rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Signed inference chains** — a derived fact naming its premises by content id, so a conclusion
  is auditable to its axioms — are a named higher tier, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Audit channel](audit.md) for the `causes` provenance mechanism facts build on.
