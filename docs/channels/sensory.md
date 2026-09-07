<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Sensory (`0x0009`)

Bulk telemetry and typed observations — composes with N-PAMP's native `NPAMP-SENSORY` channel
(N-PAMP registers this channel at minimum profile High). Like every channel surface, Sensory adds
only kind codes and their declared effects over the one object model (the draft's Channel Surfaces
section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Observation` | `read_only` | batched |
| 1 | `Subscribe` | `idempotent_write` | |
| 2 | `Unsubscribe` | `idempotent_write` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Sensory](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L76-L77)),
cross-checked against an independent per-channel oracle.

## State model, and consumer-driven backpressure

A subscription is `active → cancelled`. Backpressure is consumer-driven credit, not a
sender-side throttle: `SubscriptionUnknown` is a named error, but a credit-exceeded condition is
handled by backpressure rather than surfaced as an error — the sender simply cannot exceed the
consumer's outstanding credit.

## Batched signatures amortize the spine cost

`Observation` is explicitly batched: a single signature covers many observations, amortizing the
spine's per-object signature-verify cost over the batch rather than paying it once per reading.
This is the same amortization pattern the [Spatial channel](spatial.md)'s `Pose`/`StateUpdate`
kinds use for physical-world state.

## Failure modes

| Error kind | When |
|---|---|
| `SubscriptionUnknown` | an operation names a subscription that does not exist |

Every check is fail-closed (the draft's Security Considerations section): a failing operation is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Signed observation provenance chains via `causes`** are a named higher tier, not part of the
  frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Spatial channel](spatial.md) for the same batched-observation pattern applied to physical-world
pose.
