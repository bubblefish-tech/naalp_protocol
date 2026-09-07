<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Commerce (`0x000E`)

Commercial transactions above settlement — offers, orders, and fulfilment. Like every channel
surface, Commerce adds only kind codes and their declared effects over the one object model (the
draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Offer` | `read_only` | |
| 1 | `Order` | `non_idempotent_write` | carries a `value_commitment` and an approval binding |
| 2 | `Fulfil` | `non_idempotent_write` | |
| 3 | `Cancel` | `destructive` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Commerce](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L86-L87)),
cross-checked against an independent per-channel oracle.

## State model

`offer → order → (fulfil | cancel)`; each object names its predecessor by content id — the same
content-id-chaining pattern used throughout the protocol rather than a separate order-tracking
field.

## Commerce vs. Settlement: a layering, not a duplication

Commerce sits **above** [Settlement](settlement.md): an `Order` carries the same signed
`value_commitment` mechanism Settlement uses for its `SettleIntent`, and an order's approval
binding follows the same Governance-channel approval workflow every effecting action uses. Commerce
does not invent a second value-transfer mechanism — it is a business-transaction wrapper (offer,
order, fulfilment, cancellation) over the one settlement primitive.

## Failure modes

| Error kind | When |
|---|---|
| `OfferExpired` | an order references an offer past its validity |
| `ApprovalRequired` | an order's value commitment has no covering approval |
| `OrderMismatch` | a fulfilment or cancellation does not match its order's content id |

Every check is fail-closed (the draft's Security Considerations section): a failing transaction is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Escrow and multi-leg orders via the derivation graph** are a named higher tier, not part of the
  frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Settlement channel](settlement.md) for the underlying value-commitment mechanism Commerce
builds on.
