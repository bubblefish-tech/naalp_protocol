<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Spatial (`0x0013`)

High-frequency physical-world state for robotics and IoT — composes with N-PAMP's native
`NPAMP-SPATIAL` channel (N-PAMP registers this channel at minimum profile High), and follows the
ROS REP-103/105 frame conventions. Like every channel surface, Spatial adds only kind codes and
their declared effects over the one object model (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `FrameDefine` | `idempotent_write` | defines a coordinate frame |
| 1 | `Pose` | `read_only` | batched observation |
| 2 | `StateUpdate` | `read_only` | batched observation |
| 3 | `SnapshotQuery` | `read_only` | |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Spatial](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L98-L99)),
cross-checked against an independent per-channel oracle.

## State model

Frames form a transform tree; poses are timestamped observations. `defined → observed`.

## The one structural check: `TransformCycle`

Coordinate frames form a parent/child tree in ROS convention (every frame has at most one parent,
and the tree must have no cycle). `CheckFrameTree` enforces this with a three-color depth-first
walk — a frame currently being visited (gray) reached again is a cycle:

```go
// impl/go/channels/channels.go
func CheckFrameTree(parent map[string]string) error {
	const (white = 0; gray = 1; black = 2)
	// ... a frame revisited while still gray (mid-traversal) is a TransformCycle
}
```

([`channels.go:192-224`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L192-L224)).
A frame mapping to an empty parent is treated as a root. This is the one Spatial-specific
structural check the surface defines; every other kind is a plain batched observation over the
spine.

## Bounds

Per-object performance bound is the spine cost — one signature verify plus one deterministic-CBOR
decode — except `Pose`/`StateUpdate`, which are explicitly **batched and amortized**, exactly like
[Sensory](sensory.md): a single signature covers many observations, because signing every
high-frequency pose individually would not meet real-time robotics rates. For hard-real-time
control loops, the surface's own design note is that safety-critical control runs *below* N-AALP —
N-AALP carries the signed setpoints and the audit trail, not the control loop itself.

## Failure modes

| Error kind | When |
|---|---|
| `FrameUnknown` | a pose or state update names a frame that was never defined |
| `TransformCycle` | the frame parent/child links form a cycle rather than a tree |

Every check is fail-closed (the draft's Security Considerations section): a failing frame
definition is rejected whole, returns its named error, and causes no state change.

## What this surface does not decide

- **Higher-tier multi-robot shared frames** (signed occupancy/mapping snapshots at the federated
  tier) are a named escalation, not part of the frozen baseline.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Sensory channel](sensory.md) for the same batched-observation amortization pattern applied to
general telemetry rather than physical-world pose.
