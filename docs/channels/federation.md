<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Federation (`0x0006`)

Cross-authority operation. The baseline is frozen; deep federation is a named higher tier, not a
deferral (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `AuthorityAnnounce` | `read_only` | a signed statement of an ordering authority's identity and scope |
| 1 | `ScopeReceipt` | `non_idempotent_write` | an authority's signed receipt over its own scope (single-authority form) |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Federation](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L70-L71)),
cross-checked against an independent per-channel oracle.

## State model

`announced → ordering`. `AuthorityUnknown` and `ScopeOverlapConflict` are the baseline channel's
named errors — at baseline, two authorities ordering the same scope is an operator error.

## Higher tier: deterministic reconcile over the shared causal graph

The baseline tier is a single ordering authority's monotonic receipt chain (see
[Audit](audit.md)). The higher tier lets multiple independent authorities each order their own
scope and reconcile over the shared causal graph the baseline already produces — no envelope or
object change is required to move from single-authority to federated ordering, because reconcile
depends only on the causal partial order every authority already signs over.

`Reconcile` is a **deterministic linearization** of the union causal DAG: a topological sort whose
tie-break among causally-concurrent objects is the object's content id (bytewise ascending):

```go
// impl/go/federation/federation.go
// Reconcile deterministically merges the objects of a shared causal graph into one total order.
// It first verifies the graph is a valid partial order (acyclic, no future-cause), then
// linearizes it with Kahn's algorithm, breaking ties among ready nodes by content id
// (bytewise ascending).
```

([`federation.go:37-41`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/federation/federation.go#L37-L41)).
Because the tie-break rule is deterministic and depends only on the causal graph — never on how the
scopes happen to be split — any two authorities that split the same set of objects differently
reconcile to the **same** total order. `VerifyReconcileOrder` independently recomputes the
linearization from the causal graph alone and rejects a `Reconcile` record whose claimed order
disagrees (`ReconcileMismatch`) — the record is never trusted at face value.

## Failure modes

| Error kind | When |
|---|---|
| `AuthorityUnknown` | a receipt or announce names an authority not in the trusted set |
| `ScopeOverlapConflict` | (baseline) two authorities order the same scope — an operator error at tier 0, resolved at tier 1 |
| `ReconcileMismatch` | (tier 1) an independent recomputation of the deterministic linearization disagrees with a `Reconcile` record's claimed order |

Every check is fail-closed (the draft's Security Considerations section): a failing record is
rejected whole, returns its named error, and causes no state change.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Audit channel](audit.md) for the single-authority receipt chain and causal graph federated
reconcile builds on unchanged.
