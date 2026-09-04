<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Interaction (`0x000F`)

Human-in-the-loop and agent-to-user interaction: elicitation, response, and confirmation. Like
every channel surface, Interaction adds **only** kind codes and their declared effects over the
one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Elicit` | `read_only` | request input from a human |
| 1 | `Respond` | `idempotent_write` | |
| 2 | `Confirm` | `non_idempotent_write` | a human confirmation that can serve as an `Approval` approver (the draft's Approval section) |
| 3 | `UiEvent` | `non_idempotent_write` | draft-01 addition — a receipt-chained UI-consent event (§ below) |

This is the baseline+draft-01 registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Interaction](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L87-L88)).

## State model

`elicit → (respond | confirm | timeout)`. `InteractionTimeout` and `ElicitUnauthorized` are the
baseline channel's named errors.

## `Confirm` as an approver

Interaction's baseline tie into the rest of the protocol is that a `Confirm` object can itself
serve as the approver of a governed action: the human confirmation is an ordinary signed N-AALP
object, and it can satisfy the §7 approval requirement the same way any other approver's
signature does (the draft's Channel Surfaces section). This is what lets a human-in-the-loop UI act as the
approval authority for a `Governance` channel action without inventing a second approval
mechanism — Interaction never gets its own consume ledger or its own approval format.

## Draft-01 addition: UI-consent binding (`UiEvent`)

`UiEvent` is the wire kind behind **NAALP-AGUI** (the draft's Channel Surfaces section): binding a human's
approval, captured as a UI event stream (AG-UI-style tool-lifecycle events an agent shows a
user), to the **exact** action bytes shown, and receipt-chaining the shown events so the shown
sequence is provable offline. It introduces no new envelope, encoding, signature, identity, or
audit mechanism — a UI event is an ordinary signed N-AALP body reusing the C7 receipt-chain
construction (the draft's Audit, Causal Graph, and Ordering section) and the §7 approval binding, unchanged.

- **`naalp-ui-event`** `{1: session, 2: kind, 3: action, 4: seq, 5: prev}` — one shown
  tool-lifecycle event. `kind` is a closed set: `shown` / `args-shown` / `approved` / `rejected`.
  `action` is the content id of the exact action bytes shown to the user at this step. `seq` and
  `prev` chain the event to its predecessor exactly like an audit receipt: head =
  `SHA-384(body)`, genesis `prev` = 48 zero bytes, so editing or omitting an event breaks the
  next event's linkage.

Two load-bearing properties, each graded in both reference implementations:

- **Bound to the exact shown action.** A UI approval verifies **only** against the exact action
  shown: `VerifyConsent` walks the shown chain, takes the action content id from the
  shown-and-approved event, and requires the action actually executed to hash to that same
  content id — a substituted action after the click has a different content id and is rejected
  `ActionSubstituted` (the draft's Channel Surfaces section).
- **A removed or omitted event is detected with its position.** `WalkShown` enforces contiguity
  and returns `UIChainBroken` on a gap; `DetectHole` reports the first-broken position, the same
  way the §8.5 audit fork proof and the §22 name-history hole report a position.

### Go reference implementation

`impl/go/agui/agui.go` implements the closed event-kind vocabulary and the consent check:

```go
// UI event kinds — the closed AG-UI tool-lifecycle set transcribed to the spine. A kind outside
// the set is rejected (UnknownUIEventKind).
const (
	KindShown     uint64 = 0 // the action / tool call was shown (rendered) to the user
	KindArgsShown uint64 = 1 // the arguments were shown to the user
	KindApproved  uint64 = 2 // the user approved the shown action
	KindRejected  uint64 = 3 // the user rejected the shown action
)
```

([`agui.go:49-54`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/agui/agui.go#L49-L54)).
[`VerifyConsent`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/agui/agui.go#L281)
takes the shown-event chain, the actually-executed action's bytes, and the bound §7 approval, and
returns an error unless every one of the properties above holds. Every check is fail-closed: a
failing object is rejected whole, returns its named error, and causes no state change.

## Failure modes

| Error kind | When |
|---|---|
| `InteractionTimeout` | (baseline) an elicitation times out with no response |
| `ElicitUnauthorized` | (baseline) an elicitation is not authorized |
| `UIMalformed` | (draft-01) a UI-event body is not a well-formed `naalp-ui-event` object |
| `UnknownUIEventKind` | (draft-01) a UI event kind outside the closed `shown`/`args-shown`/`approved`/`rejected` set |
| `UIChainBroken` | (draft-01) a gap, reorder, or omitted shown-event |
| `ActionSubstituted` | (draft-01) the executed action is not the one shown and approved |
| `UINoConsent` | (draft-01) a shown chain with no `approved` event |
| `ApprovalMismatch` | (draft-01) the bound §7 approval does not match the shown-and-approved action |

Every check is fail-closed (the draft's Security Considerations section): a failing object is rejected whole, returns its
named error, and causes no state change.

## What this surface does not decide

- **No UI-rendering layer.** This binds a human approval to the exact action shown and makes
  the shown sequence provable; it deliberately does not define how a user interface renders an
  action or what a client displays — that is the client's concern (the draft's Channel Surfaces section).
- **Non-Go/Rust SDK ports.** The UI-consent primitives are graded on the Go+Rust
  two-implementation parity path against a non-circular oracle (`tools/agui_oracle.py`); the
  other eight reference SDKs port them in a later wave, tracked in the parity ledger.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Governance channel](../spec/channels.md) for the §7 approval workflow a `Confirm` or a
`UiEvent`-bound consent can satisfy.
