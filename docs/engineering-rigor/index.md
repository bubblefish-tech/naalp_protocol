<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Engineering rigor: mutation-verified tests

A green test suite proves nothing by itself — a test that would pass even if the code it checks
were replaced with `return true` isn't testing anything. The check we hold every ecosystem module
to is a mutation test: introduce a real defect into the implementation, confirm the *specific*
test that should catch it actually fails, then restore the file and confirm the suite is green
again with the restored file's hash matched byte-for-byte against the pre-mutation baseline.

The pages below are the recorded evidence for the twenty modules in `ecosystem/` — the
integration points between the N-AALP core SDK and third-party agent frameworks (MCP, A2A, ADK,
OPA/Rego) and the higher-level patterns built on top of it (ReAct, Plan-and-Execute, multi-agent
fan-out, human-in-the-loop approval, verify-at-use guards, and more). Each page records, per
mutation: the exact code change, the named test(s) that flipped red and why, the file hash before
and after, and the full-suite re-run that confirms the revert was clean.

**Coverage:** 69 recorded mutations across the 20 modules below, each isolating one load-bearing
fail-closed property — an authorization check that must refuse, an audience gate that must not be
skipped, a clock that must be genuinely injected rather than hardcoded, a signature that must
actually be verified rather than assumed.

**What these pages are not:** a description of how the modules were built, planned, or scheduled.
They are strictly the record of what was mutated, what failed, and why — the same kind of
evidence a security review or an interoperability audit would ask for. Where a module's own test
suite depends on an independent, non-circular oracle (a value computed by a from-scratch
constructor that never imports the code under test), that provenance is documented on the page
alongside the mutations themselves.

## Modules

| Module | What it integrates | Mutations recorded |
|---|---|---|
| [naalp-a2a-bridge](naalp-a2a-bridge.md) | Agent2Agent (A2A) task-chain coordination | 3 |
| [naalp-a2a-hook](naalp-a2a-hook.md) | A2A framework-hook adapter | 1 |
| [naalp-adk-plugin](naalp-adk-plugin.md) | Google ADK reference framework adapter | 1 |
| [naalp-agent-go](naalp-agent-go.md) | Go agent-pattern SDK (ReAct, Plan, multi-agent, mixed-mode) | 7 |
| [naalp-bundle](naalp-bundle.md) | Offline proof bundle verification | 3 |
| [naalp-codec](naalp-codec.md) | Deterministic-CBOR codec binding | 3 |
| [naalp-evidentiality](naalp-evidentiality.md) | Evidentiality (basis-of-knowledge) primitive | 4 |
| [naalp-fingerprint-cache](naalp-fingerprint-cache.md) | Signer-id fingerprint pinning and rotation | 2 |
| [naalp-governance-verify](naalp-governance-verify.md) | Offline mixed-kind chain verifier and replay | 1 |
| [naalp-hitl](naalp-hitl.md) | Human-in-the-loop approval interceptor and audit log | 10 |
| [naalp-mcp-bridge](naalp-mcp-bridge.md) | Model Context Protocol (MCP) tool-integration bridge | 3 |
| [naalp-mcp-hook](naalp-mcp-hook.md) | MCP framework-hook adapter | 1 |
| [naalp-mixed-mode](naalp-mixed-mode.md) | Mixed-mode (legacy/strict) HTTP discrimination SDK | 4 |
| [naalp-multiagent](naalp-multiagent.md) | Multi-agent interaction shapes (pipeline, fan-out) | 3 |
| [naalp-opa-policy](naalp-opa-policy.md) | OPA/Rego policy-enforcement integration | 4 |
| [naalp-plan](naalp-plan.md) | Plan-and-Execute orchestrator | 3 |
| [naalp-react](naalp-react.md) | ReAct agent-pattern bridge | 4 |
| [naalp-schemagen](naalp-schemagen.md) | AI-native JSON-Schema to CDDL generator | 5 |
| [naalp-validator](naalp-validator.md) | Semantic validator and pre-send firewall | 3 |
| [naalp-verify-at-use](naalp-verify-at-use.md) | Verify-at-use (re-check at execution time) guard | 4 |

See also: [Conformance](../conformance.md) for the wire-level, cross-language grading this
mutation evidence complements.
