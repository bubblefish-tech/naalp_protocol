<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Discovery (`0x0010`)

Which protocols, carriage classes, tools, and agents a peer offers — composing with N-PAMP's
native `NPAMP-DISC` / `NPAMP-DISC-SIGNED` substrate discovery when N-AALP runs over N-PAMP. Like
every channel surface, Discovery adds only kind codes and their declared effects over the one
object model (the draft's Channel Surfaces section).

This page covers the channel-surface (wire) view only. For the deeper signed-description and
directory mechanism this channel composes with — a service's full per-operation capability table,
signed directories, and equivocation detection — see the dedicated
[Discovery reference](../reference/discovery.md).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `DiscoveryRecord` | `read_only` | individually signed, offline-verifiable against a deployer trust anchor, `not_after` freshness |
| 1 | `DiscoveryQuery` | `read_only` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Discovery](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L90-L91)),
cross-checked against an independent per-channel oracle.

## State model

Records are self-contained and freshness-bounded: `fresh → stale`. A stale record (past
`not_after`) is ignored rather than trusted. `RecordExpired` and `TrustAnchorUnknown` are the
baseline channel's named errors.

## Same self-certifying-bytes property as every other surface

A `DiscoveryRecord`'s authority lives in the signature over its bytes, never in the connection or
host that served it — exactly the property the [Identity channel](identity.md)'s signer ids and
the deeper description mechanism both rely on. A cache, mirror, or unrelated relay conveys no
additional authority and loses none either.

## Failure modes

| Error kind | When |
|---|---|
| `RecordExpired` | a discovery record is past its `not_after` freshness bound |
| `TrustAnchorUnknown` | a record's claimed trust anchor is not one the verifier recognizes |

Every check is fail-closed (the draft's Security Considerations section): a failing record is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Signed capability catalogs carried as `DOC`-class Bridge objects** are a named higher tier, not
  part of the frozen baseline.
- **The full per-operation description/directory mechanism** (`naalp-description`) lives above this
  channel's baseline and is covered separately in the [Discovery reference](../reference/discovery.md).

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Discovery reference](../reference/discovery.md), the [Bridge channel](bridge.md) for the
`DOC`-class carriage the higher tier reuses.
