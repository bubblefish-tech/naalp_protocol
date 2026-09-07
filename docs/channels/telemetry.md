<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Telemetry (`0x000A`)

Operational metrics about the agent system itself — distinct from [Sensory](sensory.md)'s
world-observations, which describe the environment the agent operates in, not the agent's own
health. Like every channel surface, Telemetry adds only kind codes and their declared effects over
the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Metric` | `read_only` | batched |
| 1 | `HealthReport` | `read_only` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Telemetry](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L78-L79)),
cross-checked against an independent per-channel oracle.

## State model

Stateless emit: consumers aggregate metrics and health reports on their own side; the protocol
carries no subscription lifecycle here, unlike [Sensory](sensory.md)'s `Subscribe`/`Unsubscribe`.

## Failure modes

| Error kind | When |
|---|---|
| `MetricMalformed` | a metric batch is not a well-formed `Metric` body |

Every check is fail-closed (the draft's Security Considerations section): a failing metric object
is rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Signed SLA attestations** are a named higher tier, not part of the frozen baseline. Note the
  related but distinct primitive at [Governance](governance.md): a signed SLA attestation is
  operational-health evidence about the system, while `EgressAttestation` is evidence about a
  specific object's egress crossing — the two answer different questions and are not the same
  mechanism.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Sensory channel](sensory.md) for the parallel world-observation surface this channel is kept
distinct from.
