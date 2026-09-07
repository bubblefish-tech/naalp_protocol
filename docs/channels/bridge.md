<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Bridge (`0x000D`)

Foreign-protocol carriage by class. Fully specified in the draft's Foreign Carriage by Class
section; this page summarizes the wire-facing shape.

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Carriage` | variable | the carried operation's effect; absence on a state-mutating carried request is `destructive` |

The `Carriage` kind carries a `naalp-carriage-body` object in one of six carriage classes. This is
the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Bridge](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L84-L85)).

## Carry, never adopt: the wrap-not-rewrite rule

N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed
N-AALP carriage object whose effect, safety, identity, and audit apply — never by inventing a
bespoke per-protocol mapping. The carried field is verbatim and **must not** be re-serialized,
canonicalized, summarized, or rewritten; N-AALP metadata surrounds it, it never rewrites what is
inside it. The carriage object's signer remains the authorization identity — a foreign identity
embedded in the carried bytes never becomes an N-AALP authorization identity (the confused-deputy
rule every carriage-class implementation shares):

```go
// impl/go/carriage/carriage.go — the six carriage classes
const (
	ClassJSONRPC uint64 = 0
	ClassHTTP    uint64 = 1
	ClassMSG     uint64 = 2
	ClassSTREAM  uint64 = 3
	ClassDOC     uint64 = 4
	ClassOPAQUE  uint64 = 5
)
```

([`carriage.go:24-31`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/carriage/carriage.go#L24-L31)).
Five classes are structured (`JSONRPC`, `HTTP`, `MSG`, `STREAM`, `DOC`); the sixth, `OPAQUE`, is
universal — it makes any protocol, including one nobody has yet defined, carriable immediately on
an experimental protocol id with no registration required.

## State model

`carried` is the only state: a Bridge object is a single signed carriage event, not a session. Any
session-level state (an open connection, a streamed sequence) belongs to the carried protocol
itself and is opaque to N-AALP's own state machine.

## Failure modes

| Error kind | When |
|---|---|
| `EnvelopeMalformed` | the carriage body is not a well-formed `naalp-carriage-body` object |
| `ProtocolUnsupported` | the named protocol id is not one this endpoint carries |
| `MethodUnsupported` | the carried method/operation is not one this endpoint carries |
| `NotDelivered` | the carried request could not be delivered to the foreign protocol's real endpoint |
| `EffectNotAuthorized` | the carried operation's effect is not covered by any approval bound to it |

Every check is fail-closed (the draft's Security Considerations section): a failing carriage
object is rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **The registry of thin per-protocol mappings** (the two carry-and-map bridges N-AALP ships today
  — MCP and A2A — see [Protocol mappings](../mappings/mcp.md)) is a separate, versioned artifact
  from the six carriage classes themselves; new protocol-id registrations are additive registry
  entries, not envelope changes.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
[MCP mapping](../mappings/mcp.md), [A2A mapping](../mappings/a2a.md).
