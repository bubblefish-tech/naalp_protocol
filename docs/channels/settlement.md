<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Settlement (`0x0007`)

Agent-to-agent settlement — the public half of a value transfer, composing with N-PAMP's
`NPAMP-SETTLEMENT` when N-AALP runs over N-PAMP. Like every channel surface, Settlement adds
**only** kind codes and their declared effects over the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `SettleIntent` | `non_idempotent_write` | carries a signed `value_commitment` body field |
| 1 | `SettleReceipt` | `non_idempotent_write` | names its intent by content id |
| 2 | `SettleReject` | `idempotent_write` | |
| 3 | `PaymentImport` | `non_idempotent_write` | draft-01 addition — import a foreign payment payload (§ below) |
| 4 | `PaymentChargeBinding` | `non_idempotent_write` | draft-01 addition — the exact value a §7 approval binds |

This is the baseline+draft-01 registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Settlement](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L72-L73)).

## State model

`intent → (receipt | reject)`. A receipt names its intent by content id — there is no separate
settlement-status field; the graph of content-id references is the state.

## No fifth effect: `value_commitment`

Settlement is a value-bearing channel, and it deliberately does **not** get a fifth effect
class. Instead it carries its money semantics in a signed `value_commitment` body field under
the same signature and takes the effect that matches its actual state change — typically
`non_idempotent_write` (the draft's Effects and Authorization section):

> A fifth effect would break the 1:1 mapping to N-PAMP's Bridge `SafetyLabel` (which has four
> values) and force a lossy translation on every carried value message. A body-level
> `value_commitment` under the same signature is strictly more expressive and mapping-clean.

`ValueMismatch` and `SettleExpired` are the baseline channel's named errors.

## Draft-01 addition: payment import (`PaymentImport` / `PaymentChargeBinding`)

Settlement's two draft-01 kinds import a foreign payment instruction — an AP2 mandate, an
Agentic Commerce Protocol delegated token, or an x402 payload — and turn it into a governed,
single-use N-AALP charge (the draft's Channel Surfaces section). This is carriage, not adoption: the
foreign payload travels **octet-for-octet**, never re-serialized, canonicalized, or rewritten.

- **`PaymentImport`** `{1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign}` —
  the wrapper body. `format` selects from the closed payment-format registry
  (`vectors/registry/payment-format.csv`); an unknown code is rejected `UnknownPaymentFormat`.
- **`PaymentChargeBinding`** `{1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
  6: foreign_id}` — names the **exact** value being charged, including the imported payload's
  own content id (`foreign_id`). A §7 approval binds this binding's content id, so a wrong
  amount, wrong payee, wrong currency, or a substituted foreign payload yields a different
  content id and no longer matches a prior approval (`ApprovalMismatch`).

There is no fifth effect and no payment-specific ledger here either: a payment spend is a
`non_idempotent_write`, and `AuthorizeCharge` is `VerifyApproval` plus the grant check plus
`Ledger.Consume` — the same §7 approval-and-single-use-consume path the MCP profile's per-call
gate uses (the draft's Channel Surfaces section).

### Go reference implementation

`impl/go/payment/payment.go`:

```go
// ChargeEffect is the C5 effect a payment spend carries: a non_idempotent_write. A charge is
// value-bearing and not safely repeatable, which is exactly why it is spent single-use through
// the §7 ledger; the approval's grant must cover this effect.
const ChargeEffect = policy.NonIdempotentWrite
```

([`payment.go:47-50`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/payment/payment.go#L47-L50)).
[`AuthorizeCharge`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/payment/payment.go#L241)
verifies the bound approval, checks the granted effect covers `ChargeEffect`, and consumes the
approval single-use through the ledger — a replayed authorization is rejected `AlreadyConsumed`
with no state change, proven directly by
[`TestPaymentImportMultiUseMutation`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/payment/payment_test.go#L314-L387),
which constructs a deliberately mutant authorizer that skips the single-use check and confirms
the real one does not. The closed payment-format registry
([`FormatAP2Mandate` / `FormatACPToken` / `FormatX402`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/payment/payment.go#L55-L59))
names the three recognized foreign formats, and
[`VerifyPaymentImport`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/payment/payment.go#L175-L192)
rejects any other format code `UnknownPaymentFormat` before the import is ever trusted.

## Failure modes

| Error kind | When |
|---|---|
| `ValueMismatch` | (baseline) the settlement receipt disagrees with its intent's value commitment |
| `SettleExpired` | (baseline) the settlement is past its expiry |
| `UnknownPaymentFormat` | (draft-01) a payment format outside the closed registry |
| `ApprovalMismatch` | (draft-01) a charge whose amount/payee/currency/payload does not match its bound approval |
| `AlreadyConsumed` | (draft-01) a replayed payment authorization |
| `ApprovalExpired` | (draft-01) a charge past its approval's expiry |
| `ApprovalRequired` | (draft-01) an under-granting approval |
| `PayMalformed` | (draft-01) a body that is not a well-formed payment-import or charge-binding object |

Every check is fail-closed (the draft's Security Considerations section): a failing charge is rejected whole, returns its
named error, and causes no state change (no ledger append).

## What this surface does not decide

- **No settlement/clearing layer.** A payment is a `non_idempotent_write` spent through the §7
  ledger; whether and how a charge settles downstream (bank rails, a stablecoin transfer) is a
  deployment matter over the carried, bound, single-use approval — not a wire mechanism
  (the draft's Channel Surfaces section).
- **Non-Go/Rust SDK ports.** The payment-import primitives are graded on the Go+Rust
  two-implementation parity path against a non-circular oracle (`tools/payment_oracle.py`); the
  other eight reference SDKs port them in a later wave, tracked in the parity ledger.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Commerce channel](../spec/channels.md) for transactions above settlement (offers, orders,
fulfilment).
