# N-AALP adoption ecosystem

Ready-to-adopt integration packages built on the ten N-AALP reference SDKs. Each is a thin,
independently-tested adapter that gives an existing agent stack signed, deterministic,
post-quantum, offline-verifiable objects — identity, effect, approval, and audit — **without
re-architecting**. Every package is Apache-2.0 and ships its own examples and tests.

## Deploy as a governance sidecar / gateway

The bridges and hooks are designed to run as a **governance point** at the edge of an agent
system: put one in front of an MCP or A2A server (or attach it as an in-process framework hook),
and every tool call, agent message, and result is wrapped in a signed N-AALP envelope —
content-identified, effect-labelled, approval- and audit-bound — before it reaches the model or
the tool. The application is unchanged; governance moves to the edge. Transport-level ambient /
per-node deployment is the substrate's concern (see N-PAMP).

## Packages

### Framework hooks & agent patterns

| Package | What it does |
|---|---|
| [`naalp-mcp-hook`](naalp-mcp-hook/) | MCP framework-hook adapter — intercept MCP tool calls in-process |
| [`naalp-a2a-hook`](naalp-a2a-hook/) | A2A framework-hook adapter — intercept A2A agent messages in-process |
| [`naalp-adk-plugin`](naalp-adk-plugin/) | Agent Development Kit plugin — N-AALP governance for ADK apps |
| [`naalp-react`](naalp-react/) | ReAct bridge — sign and audit the reason/act loop |
| [`naalp-plan`](naalp-plan/) | Plan-and-Execute orchestrator with signed plan/step objects |
| [`naalp-multiagent`](naalp-multiagent/) | Multi-agent interaction shapes over governed objects |
| [`naalp-agent-go`](naalp-agent-go/) | Go agent-pattern SDK (ReAct, plan, multi-agent, mixed-mode) |

### Protocol bridges (sidecar / gateway)

| Package | What it does |
|---|---|
| [`naalp-mcp-bridge`](naalp-mcp-bridge/) | MCP tool-integration bridge — carry MCP octet-exact under a governed envelope |
| [`naalp-a2a-bridge`](naalp-a2a-bridge/) | A2A agent-coordination bridge — carry A2A octet-exact under a governed envelope |
| [`naalp-mixed-mode`](naalp-mixed-mode/) | Mixed-mode HTTP discrimination — accept legacy JSON and strict N-AALP on one endpoint, fail-closed to strict |

### Governance, policy and observability

| Package | What it does |
|---|---|
| [`naalp-opa-policy`](naalp-opa-policy/) | OPA / Rego policy-enforcement integration over N-AALP objects |
| [`naalp-otel`](naalp-otel/) | OpenTelemetry observability module for N-AALP flows |
| [`naalp-hitl`](naalp-hitl/) | Human-in-the-loop interceptor gating effecting actions on approval |
| [`naalp-governance-verify`](naalp-governance-verify/) | Offline mixed-kind receipt-chain verifier and replay |
| [`naalp-governance-portability`](naalp-governance-portability/) | Portability conformance corpus + harness verifying the framework adapters (ADK/A2A/MCP) agree |

### Verification and evidence primitives

| Package | What it does |
|---|---|
| [`naalp-verify-at-use`](naalp-verify-at-use/) | Verify-at-use guard — re-verify an object at the point of use |
| [`naalp-fingerprint-cache`](naalp-fingerprint-cache/) | Signer-id fingerprint cache for fast repeat verification |
| [`naalp-evidentiality`](naalp-evidentiality/) | Evidentiality primitive — bind supporting evidence to an object |
| [`naalp-bundle`](naalp-bundle/) | Offline proof bundle — package an object with its verification inputs |

### Developer tooling

| Package | What it does |
|---|---|
| [`naalp-codec`](naalp-codec/) | Deterministic-CBOR codec helpers |
| [`naalp-schemagen`](naalp-schemagen/) | Schema generation for N-AALP object kinds |
| [`naalp-validator`](naalp-validator/) | Object validator (structural and effect checks) |

## How they relate to the protocol

These packages **consume** the N-AALP reference SDKs (`impl/`) and the conformance corpus
(`vectors/`); they do not fork or re-specify the protocol. A bridged or hooked payload inherits
N-AALP's identity, effect, approval, and audit guarantees unchanged. The protocol itself — the
Internet-Draft, the CDDL wire authority, the ten SDKs, and the conformance corpus — is the
[repository root](../).

---

*N-AALP™ and BubbleFish™ are trademarks of BubbleFish Technologies, Inc. Apache-2.0.*
