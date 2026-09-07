<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Governance (`0x0004`)

Policy and the approval workflow. Like every channel surface, Governance adds **only** kind codes
and their declared effects over the one object model — the approval mechanism itself lives in the
spine (the draft's Approval section); this surface is the workflow that reaches it (the draft's
Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `PolicyPublish` | `non_idempotent_write` | a signed policy naming, per effect class and capability, what is authorized |
| 1 | `Approval` | `non_idempotent_write` | the spine's approval object |
| 2 | `ApprovalHeld` | `read_only` | an action held pending approval |
| 3 | `Consume` | `non_idempotent_write` | the single-use ledger append |
| 4 | `GatewayDecision` | `non_idempotent_write` | portable, vendor-neutral enforcement-gateway evidence (§ below) |
| 5 | `DecisionRecord` | `non_idempotent_write` | the full governed-decision accountability record (§ below) |
| 6 | `EgressAttestation` | `non_idempotent_write` | signed egress-crossing evidence (§ below; wire-freeze pending) |
| 7 | `HazardAuthorization` | `non_idempotent_write` | physical-hazard authorization for manufacturing/robotics deployments (§ below) |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Governance](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L66-L67)),
cross-checked against an independent per-channel oracle so Go, Rust, and the oracle agree on every
kind code and effect.

## State model

An approvable action is `requested → (held | approved) → consumed | expired`. `Consume` is a
single-use ledger append (the draft's Approval section): a replayed authorization is rejected
`AlreadyConsumed` with no state change, never a second grant.

## Vendor-neutral, third-party-reverifiable evidence: `GatewayDecision`

`GatewayDecision` is a signed decision object an enforcement gateway of **any** vendor emits as
portable evidence that it decided about an action. Its load-bearing property is that authority
lives in the **signed bytes**, never in the connection or the host that served them:
`VerifyDecision` takes no serving-party or connection identity, so the identical signed decision
re-verifies when a party *other than* the gateway serves it (the third-party re-serve property).

```go
// impl/go/gateway/gateway.go — the closed decision outcome set
const (
	DecisionAllow uint64 = 0 // the gateway allows the action
	DecisionDeny  uint64 = 1 // the gateway denies the action
	DecisionHold  uint64 = 2 // the gateway holds the action pending a further step
)
```

([`gateway.go:42-45`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/gateway/gateway.go#L42-L45)).
`GatewayDecision {1: decision, 2: action, 3: policy, 4: effect}` defines the evidence format only,
never a policy language: `action` is the content id of the action decided about, `policy` is the
opaque identity of the deciding policy (a name, not a policy program), and `effect` is the C5
effect class of the action.

## The full accountability record: `DecisionRecord`

`DecisionRecord` is the signed record a governed decision point emits when it decides about an
action under a closed, uniquely-selected condition set. It carries a three-part accountability
claim (the draft's Channel Surfaces section): **unique selection** (the governing set, named in
the clear as content ids), **governed-at-decision-time** (the consume-receipt spent at decision
time), and **binding-fixed-by-decision-time** (established off-record by inclusion under a
witnessed checkpoint root — see [Audit](audit.md)). The record is deliberately **clock-free**: it
carries no self-asserted timestamp anywhere in its own body; both time properties are positional,
never claimed. `ParseDecisionRecord` and `ValidateDecisionRecord` follow the same
structural-parse/semantic-validate split `gateway.go` established for `GatewayDecision`
([`decision_record.go`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/gateway/decision_record.go)).

## Physical-hazard authorization: `HazardAuthorization`

`HazardAuthorization` is a manufacturing/robotics addition (design.md addendum) that authorizes an
action carrying physical danger. It is an orthogonal dimension from the C5 effect lattice: the
effect (envelope field 7) describes *data* reversibility, while a hazard claim describes *physical*
danger — a data-reversible action can still be a high physical hazard, and neither dimension
derives the other. `HazardClassFromCode` is the one fail-closed decode entry point: any missing or
out-of-range raw value normalizes to the **highest** hazard class, `MotionInSharedSpace`, never a
weaker one — mirroring the effect lattice's own unknown-to-destructive rule
([`hazard.go`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/hazard/hazard.go)).
`HazardAuthorization`'s wire shape was frozen 2026-09-01 with the maintainer's approval; it is
graded byte-identical against the shared, non-circular `vectors/hazard` corpus in both Go and Rust,
with the remaining eight-port propagation tracked in the parity ledger.

## Named, honest gap: `EgressAttestation`'s wire freeze

`EgressAttestation`'s Go implementation is built and tested, but — unlike `HazardAuthorization` —
its CDDL production, top-level object-choice registration, parity-baseline entry, and
conformance-corpus operation have **not yet landed in a maintainer-approved wire-freeze commit**
as of this writing. It is documented here for completeness of the current code, not as a claim
that its wire bytes are final; see the [Audit](audit.md) page and the draft itself for the
authoritative, frozen wire shape once that freeze lands.

## Failure modes

| Error kind | When |
|---|---|
| `ApprovalRequired` | an effecting action has no covering approval |
| `ApprovalMismatch` | a bound approval does not match the action's content id |
| `AlreadyConsumed` | a replayed single-use approval |
| `EffectNotAuthorized` | the approval's granted effect does not cover the action's effect |

Every check is fail-closed (the draft's Security Considerations section): a failing action is
rejected whole, returns its named error, and causes no state change.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Audit channel](audit.md) for the checkpoint-root anchor a `DecisionRecord` binds to.
