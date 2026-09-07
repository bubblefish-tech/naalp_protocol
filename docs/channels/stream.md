<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Stream (`0x000C`)

Native full-duplex streaming — fully specified in the draft's Native Streaming section. Chunks are
raw N-PAMP `NPAMP-STREAM` frames, not N-AALP objects, and are AEAD-authenticated by the transport;
this channel is kept distinct from foreign streamed carriage (see [Bridge](bridge.md), `0x000D`).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `StreamOpen` | variable | authorized per the stream's action before any chunk is admitted |
| 1 | `StreamCommit` | `read_only` | over the completed digest |
| 2 | `StreamCheckpoint` | `read_only` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Stream](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L82-L83)),
cross-checked against an independent per-channel oracle.

## One signature covers the whole stream, not one per chunk

`StreamOpen` establishes the stream's identity, effect, and — where it causes an effect — its
approval binding, refusing a stream whose effect is not authorized before any chunk is admitted.
The chunks themselves are unsigned: they are raw data frames the transport's own AEAD already
authenticates, so N-AALP deliberately does not re-sign them individually. `StreamCommit` instead
carries a rolling SHA-384 digest over the chunks in absolute-offset order, making the entire stream
non-repudiable with **one** signature rather than one per chunk. Altering any delivered byte
invalidates the commitment (`StreamDigestMismatch`). Optional signed `StreamCheckpoint`s let a
verifier confirm a prefix of the stream without waiting for the end.

## State model, enforced across concurrent streams

`idle → open → committed`, with `abandoned` as the terminal state a `StreamOpen` leaves on the
idle/commit timer's expiry:

```go
// impl/go/streaming/streaming.go
// Guard enforces the stream state table (idle -> open -> committed, with abandoned as the
// terminal state a StreamOpen leaves on the idle/commit timer's expiry) across concurrent
// streams, rejecting an event the table does not admit for the stream's current state with
// StreamStateError before any state change.
```

([`streaming.go:16-19`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/streaming/streaming.go#L16-L19)).

## Failure modes

| Error kind | When |
|---|---|
| `StreamDigestMismatch` | the completed stream's bytes do not hash to the committed digest |
| `FlowControlError` | a transport-level flow-control violation |
| `StreamStateError` | an event is not admitted by the stream's current state |

Every check is fail-closed (the draft's Security Considerations section): a failing stream is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Higher-tier signed checkpoint cadence policy and cross-transport stream continuation** are
  named escalations, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Bridge channel](bridge.md) for foreign streamed protocol carriage, which this channel is
deliberately kept distinct from.
