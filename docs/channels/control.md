<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Control (`0x0000`)

Session and object-flow control at the application layer — distinct from the N-PAMP transport
handshake, which sits below N-AALP. Like every channel surface, Control adds only kind codes and
their declared effects over the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Hello` | `read_only` | a signed selector advertising the object kinds, channels, carriage classes, tiers, and profile an endpoint supports |
| 1 | `Bye` | `idempotent_write` | orderly close of an application session |
| 2 | `Ack` | `read_only` | the signed acknowledgment delivery uses |
| 3 | `Error` | `read_only` | the signed error object every failure mode returns |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Control](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L58-L59)),
cross-checked against an independent per-channel oracle.

## State model

A session is `open` after a mutual `Hello`, `closing` after `Bye`. `UnknownKind` and
`ProfileMismatch` (a `Hello` whose profile the peer refuses) are the baseline channel's named
errors.

## Why `Hello` is a signed object, not a bare capability list

Because every N-AALP object is signed, an endpoint's capability advertisement is itself
non-repudiable: a peer cannot later deny having offered a kind, channel, or profile it advertised.
`Ack` reuses the spine's own delivery acknowledgment shape (the draft's Delivery, Idempotence, and
Backpressure section), and `Error` is the one object every other channel's failure modes are
carried in — there is no separate, channel-specific error envelope anywhere in the protocol.

## Failure modes

| Error kind | When |
|---|---|
| `UnknownKind` | a `(channel, kind)` pair is not in the baseline registry |
| `ProfileMismatch` | a `Hello` names a crypto profile the peer refuses |

Every check is fail-closed (the draft's Security Considerations section): a failing object is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Higher-tier capability GREASE, negotiation extensions, and session resumption** are named
  escalations, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md).
