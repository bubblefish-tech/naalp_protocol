<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Immune (`0x0005`)

Anomaly reporting and defensive coordination — composes with N-PAMP's native `NPAMP-IMMUNE`
gossip. Like every channel surface, Immune adds only kind codes and their declared effects over
the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `AnomalyReport` | `read_only` | |
| 1 | `Quarantine` | `destructive` | marks a signer or object class untrusted |
| 2 | `QuarantineLift` | `non_idempotent_write` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Immune](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L68-L69)),
cross-checked against an independent per-channel oracle.

## State model

A subject is `normal → quarantined → (lifted | permanent)`.

## Fail-closed by default, including on future-dated revokes

Access to a quarantined subject is denied fail-closed — notably, this includes a **future-dated
revoke of a share**: the surface's design explicitly calls this out as denied, not fail-open, which
is the opposite of the common mistake of treating a not-yet-effective revocation as "not yet
denied." `AccessDenied` covers this case, matching the same error the [Memory channel](memory.md)
uses for a revoked or quarantined entry.

Report emission is rate-limited; the surface names the limit as a policy parameter rather than a
fixed protocol constant, so an operator can tune it without a wire change.

## Failure modes

| Error kind | When |
|---|---|
| `AccessDenied` | access to a quarantined subject, including one revoked with a future effective date |

Every check is fail-closed (the draft's Security Considerations section): a failing action is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Signed anti-entropy gossip with hop-bound convergence** (the `NPAMP-IMMUNE` propagation model)
  is a named higher tier at the federated level, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md).
