<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Workflow (`0x0011`)

Task and workflow orchestration across agents. Like every channel surface, Workflow adds only kind
codes and their declared effects over the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `TaskCreate` | `non_idempotent_write` | seq-keyed non-terminal status, so a crash cannot bypass the input/approval gate |
| 1 | `TaskInput` | `non_idempotent_write` | |
| 2 | `TaskCancel` | `destructive` | |
| 3 | `TaskResult` | `non_idempotent_write` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Workflow](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L92-L95)),
cross-checked against an independent per-channel oracle.

## State model

A task is `created → (awaiting-input | awaiting-approval) → running → (result | cancelled)`. The
load-bearing guarantee is that **a crash recovers to the last durable status and can never
manufacture a bypass of the input/approval gate** — reaching `running` requires an explicit input
or approval step a crash cannot fabricate.

## The input/approval gate: a durable, WAL-backed guarantee, not a convention

`WorkflowGate` persists every status transition to a write-ahead log **before** acknowledging it
(the spine's persist-before-ack rule): a task lands in `awaiting-input` or `awaiting-approval` on
creation, never directly in `running`, and `Run` refuses a task still sitting at either gate:

```go
// impl/go/channels/channels.go
func (g *WorkflowGate) Run(task string) error {
	switch g.status[task] {
	case "input-supplied", "approved":
		return g.persist(task, "running")
	case "awaiting-input", "awaiting-approval":
		return ErrInputGateBypass
	default:
		return ErrTaskStateError
	}
}
```

([`channels.go:391-402`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L391-L402)).
Each WAL record carries a length prefix and a CRC32 checksum over its payload, so replay can tell a
genuinely durable record from one that was only partially written when a crash lands mid-write: on
the first unreadable or corrupt record, replay stops, keeps every record read so far, and truncates
the file at that exact offset — a torn write never silently discards durable history, and it never
lets a partial write masquerade as a real status either
([`channels.go:259-331`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L259-L331)).
This is a crash test, not a design intention: `InputGateBypass` is a named error precisely because
the guarantee is proven, not assumed.

## Failure modes

| Error kind | When |
|---|---|
| `TaskStateError` | a transition is requested from a status that does not permit it |
| `InputGateBypass` | a task attempts to run without first passing its input or approval gate — forbidden, and proven unreachable by a crash test |
| `ApprovalRequired` | a task requiring approval has none bound |

Every check is fail-closed (the draft's Security Considerations section): a failing transition is
rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **No DAG orchestration yet.** The baseline models a single task's linear lifecycle; DAG
  workflows over the `causes` graph and compensation/rollback are a named higher tier, not part of
  the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Audit channel](audit.md) for how a task's causal history is proven offline via `causes`.
