<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Compliance (`0x0008`)

Compliance evidence and multi-regulator reporting. Like every channel surface, Compliance adds
only kind codes and their declared effects over the one object model (the draft's Channel Surfaces
section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `ComplianceRecord` | `non_idempotent_write` | a signed, audit-chained evidence record |
| 1 | `ComplianceQuery` | `read_only` | |
| 2 | `ComplianceReport` | `read_only` | a signed report bound to a jurisdiction |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Compliance](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L74-L75)),
cross-checked against an independent per-channel oracle.

## State model

Records are append-only into the [Audit](audit.md) receipt chain — Compliance introduces no
second ledger; a compliance record's durability and tamper-evidence come entirely from the same
chain every other channel's evidence appends to.

## Failure modes

| Error kind | When |
|---|---|
| `RecordUnsigned` | a compliance record's signature does not verify |
| `JurisdictionUnknown` | a report names a jurisdiction the endpoint does not recognize |

Every check is fail-closed (the draft's Security Considerations section): a failing record is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Regulator-specific report schemas as critical extensions, and retention/legal-hold markers**
  are named higher tiers, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Audit channel](audit.md) for the receipt chain compliance records append to.
