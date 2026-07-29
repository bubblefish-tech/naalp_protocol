<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# The twenty channel surfaces

A channel surface adds **only** kind codes and their declared effects over the one object model —
no channel-local encoding, signature, or identity. All twenty channels are frozen at the baseline
tier; higher tiers add capability under the frozen envelope through the tier field and
critical/non-critical extensions. The complete kind/effect table is the machine-readable registry
`vectors/registry/channels.csv` (65 kinds).

| Channel id | Name | Purpose (baseline) |
|---|---|---|
| 0x0000 | Control | session and object-flow control (Hello, Bye, Ack, Error) |
| 0x0001 | Memory | durable shared memory (offer/accept/write/read/expire/revoke) |
| 0x0002 | Capability | capability tokens (issue, delegate, revoke, lookup) |
| 0x0003 | Identity | rotation, revocation, foreign linkage, key announce |
| 0x0004 | Governance | policy + approval workflow (publish, approval, held, consume) |
| 0x0005 | Immune | anomaly reporting + quarantine |
| 0x0006 | Federation | authority announce, scope receipt (reconcile at tier 1) |
| 0x0007 | Settlement | agent-to-agent settlement (intent, receipt, reject) |
| 0x0008 | Compliance | compliance evidence + reporting |
| 0x0009 | Sensory | bulk telemetry / typed observations |
| 0x000A | Telemetry | operational metrics about the agent system |
| 0x000B | Audit | the receipt chain + auditor (receipt, query, fork-proof) |
| 0x000C | Stream | native full-duplex streaming (open, commit, checkpoint) |
| 0x000D | Bridge | foreign-protocol carriage by class |
| 0x000E | Commerce | offers, orders, fulfilment, cancel |
| 0x000F | Interaction | human-in-the-loop (elicit, respond, confirm) |
| 0x0010 | Discovery | which protocols/tools/agents a peer offers |
| 0x0011 | Workflow | task orchestration (create, input, cancel, result) |
| 0x0012 | Knowledge | shared knowledge / graph facts (assert, retract, query) |
| 0x0013 | Spatial | high-frequency physical-world state (frames, poses) |

## Effect binding

Each kind declares an effect (or is variable, e.g. Stream `StreamOpen` and Bridge `Carriage`). An
object on a registered kind must carry exactly the declared effect (`EffectDeclarationMismatch`
otherwise); an object on an unregistered (channel, kind) is `UnknownKind`.

## The input gate (Workflow)

The Workflow channel's task input/approval gate is durable (persist-before-acknowledge): a task
cannot reach `running` without passing the gate (`InputGateBypass`), and a crash recovers to the
pre-gate status — proven by a crash test in both implementations.
