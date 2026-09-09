# naalp-mcp-guard

The N-AALP one-command guard for the Model Context Protocol (MCP). Packages the already-built
`naalp-mcp-bridge` (effect classification + signed carriage of a foreign tool call) and
`naalp-hitl` (pause / human-approval / D6 audit) behind two commands:

```
naalp-mcp-guard wrap <server-cmd...>     # stand the guard in front of a real MCP server
naalp-mcp-guard verify <receipt-file>    # offline-verify one receipt (no network, <1s)
```

`wrap` reuses (never re-implements) real cryptography and ledger logic from three already-built,
already-graded components: `naalp_mcp_bridge` (the annotation-to-effect mapping and the signed
McpToolCall carriage object), `naalp_hitl` (the pause/human-interface/audience-bound single-use
approval-consume/D6-audit interceptor), and this package's own new `EffectReceipt` primitive
(built from the same already-graded `naalp.cbor`/`naalp.cose` signing idiom `naalp.approval` and
`naalp_hitl.nonrepudiation` already use — no new cryptography).

## What `wrap` does, precisely

1. **Family-1 checks.** Every `tools/call` is carried into a real, signed N-AALP McpToolCall
   object under the guard's own ML-DSA key and immediately self-verified through the identical
   real-crypto path a remote verifier would use — an unauthenticated, malformed, or tool-name-
   mismatched call is refused before it can reach the wrapped server.
2. **The effect gate.** The tool's real annotations (learned from `tools/list` traffic) are
   mapped to the closed four-effect lattice; a call whose enforced effect is at or above
   `non_idempotent_write` is paused and routed to a local human-approval prompt (on the process's
   controlling terminal, never the JSON-RPC wire streams) bound to the EXACT
   `(tool_id, args_id)` this call classified to. Approval, consumption, and refusal auditing are
   the real `naalp_hitl.HITLInterceptor` — nothing here re-derives them.
3. **A PQ-signed, offline-verifiable receipt** is minted for every gated attempt, executed or
   denied, and written to `<state-dir>/receipts/`.

## Known limitations (stated honestly)

- **Headless hosts.** When this guard is launched with no controlling terminal (some MCP hosts do
  not allocate one for a subprocess), there is no side channel to ask a human for approval; every
  approval-requiring call is refused fail-closed (never a silent auto-approve). A host-integrated
  approval channel is compose-mode work (Task A.4, deferred — see below).
- **Single local operator.** The guard's own identity and the human approver's identity are each a
  raw 32-byte seed persisted locally (0600). This is not a KMS and not multi-operator; it is the
  deliberate "own the click" free-tier scope.
- **Standalone distribution.** `pip install -e .` (editable) works today because this package
  locates its `naalp` / `naalp_mcp_bridge` / `naalp_hitl` dependencies by walking up the source
  tree from its own file location; a non-editable wheel install does not, because none of the
  three is published on PyPI yet. Real `uvx naalp-mcp-guard` distribution needs them vendored or
  published alongside this package.
- **Deferred to Task A.3 (tool-definition hash-pin + rug-pull re-approval).** This build does NOT
  yet persist a hash of each tool's definition AT approval time and re-trigger approval when it
  later changes. What already exists, as a structural side effect of the approval binding to the
  full `(tool_id, args_id)` content id (Requirement 6.1), is that a tool description change
  produces a DIFFERENT `tool_id` and therefore a call binding no prior approval can satisfy — but
  the explicit hash-pin-at-approval-time store and the "re-trigger approval on a detected rug
  pull for an ALREADY-APPROVED-then-changed tool between calls" workflow is Task A.3's own
  deliverable, tracked as a follow-up, not built here.
- **Deferred to Task A.4 (own-the-click free tier + compose mode), `[GATE: #7/D7]`.** This build
  does not yet document or implement a compose mode for sitting behind an existing gateway, and
  does not yet bundle "commodity gateway checks" beyond what Family-1 above already performs.
  Tracked as a follow-up gated on D7, not built here.
- **Transport-level replay** on the client↔guard leg (as opposed to approval/effect replay, which
  is closed — see the coverage table) is not separately defended by this module; it rides on
  whatever transport security the deployment provides (e.g. TLS for a networked deployment; local
  stdio/loopback trust for the common case).
- **Server-initiated requests requiring a client reply** (e.g. `sampling/createMessage`,
  elicitation) are relayed upstream/downstream untouched — the guard gates the client's own
  `tools/call` path (Requirement 6.1's scope), not bidirectional MCP request types generally.

## Deployment preconditions (every claim below is void without BOTH)

1. **Sole ingress** — the guard is the only path to the effecting MCP server (network- or
   process-enforced: the server accepts connections only from the guard).
2. **Fail-closed effect classification** — a tool with no effect-class assignment defaults to
   approval-required (this build's `EffectGate.classify` enforces this structurally: an unknown or
   name-mismatched tool definition falls back to an EMPTY annotation set, which `naalp.mcp`'s own
   published mapping table collapses to `destructive`). If an operator otherwise misclassifies a
   consequential tool as read-only, the consequence-closed claim below is void for that tool.

## Honest per-concern coverage (verbatim from MCP-VERIFIED-01 §4 — do not weaken)

Coverage claims are scoped to checks the guard performs at its own enforcement point, fronting
**arbitrary, unmodified MCP clients and servers**: core MCP defines no signature verification
anywhere, so the guard's cryptography buys unilateral **evidence** (receipts signed by the
guard's key) and guard-side checks, not peer-enforced integrity.

| Concern | Verdict | What the guard actually does / does not do |
|---|---|---|
| F1.1 missing auth | **CLOSED** (at the boundary) | Guard requires an authenticated, effect-authorized request before anything reaches the server; unauthenticated ingress cannot occur through the guard. |
| F1.2a audience confusion / token passthrough | **CLOSED** (at the boundary) | Audience-bound authorization per spec MUSTs (RFC 8707-aligned); no client token is transited downstream. |
| F1.2b confused deputy (OAuth-proxy flow: static client ID + DCR + consent cookie) | **CONDITIONAL** | Closed only in deployments where the guard IS the OAuth proxy and implements the spec's per-client consent registry; if a separate OAuth proxy fronts the third-party AS, the guard is out of position for this flow. |
| F1.3 replay | **CLOSED for approval/effect replay; transport-dependent for wire replay** | Each args-bound approval is single-use, consumed atomically — a replayed effect request cannot re-execute; guard-issued sessions use non-deterministic, principal-bound IDs per spec MUSTs. Wire-level replay on the client↔guard leg rides on TLS (arbitrary clients do not sign requests). |
| F1.4 rug pull / definition change | **CLOSED** | Tool-definition hashing at approval time; any changed definition fails closed and re-triggers approval (the check CSA says "no mechanism exists" for in core MCP). *(Note: the explicit hash-pin-store + re-approval workflow named here is Task A.3, tracked as a follow-up — see "Known limitations" above; the structural CLOSED property already holds today because a changed tool description changes the call-binding content id, which no prior approval satisfies.)* |
| F1.5 audit trail | **CLOSED** | PQ-signed receipts per effect: parameters, principal, decision, result hash — the NSA logging recommendation made cryptographically evidenced. *(Internal note: receipts are non-repudiable only relative to the guard's key; when guard and server share one operator, receipts are self-attested — an independent anchor/witness is what upgrades that.)* |
| F1.6 message integrity | **PARTIAL — receipted, not peer-verified** | An arbitrary MCP server verifies no envelopes (core MCP has no signature verification). The guard unilaterally receipts exactly what it forwarded, signed with its own key, satisfying the *evidence* half of NSA's "sign and verify MCP messages"; the *verify-at-the-peer* half requires a signature-aware counterparty and is not claimed. Guard↔server transport integrity = stdio/loopback/TLS. |
| F2.1 tool poisoning | **CONSEQUENCE-CLOSED** | The poisoning trick itself is NOT prevented — a fooled agent still *attempts* the call. But the attempted consequential effect cannot execute without effect-class authorization + args-bound human approval; the attempt is receipted. Input-side detection is explicitly not claimed. |
| F2.2 prompt injection / XPIA | **CONSEQUENCE-CLOSED** | Same shape: injection is not detected or prevented; unauthorized consequential effects arising from it are blocked at the effect gate and evidenced by receipts. |
| F2.3 excessive agency | **CONSEQUENCE-CLOSED** | Agency is capped by the effect-class lattice + grants, not by trusting the model's judgment. |
| F2.4 approval fatigue (ASI09) | **PARTIAL** | Args-bound approvals mean a human approves *this call with these arguments* (not a blanket capability), and unapproved-effect execution is impossible. NOT closed: a fatigued or deceived human approving a bad args-bound call goes through — ASI09 is a human-cognition attack; the guard narrows the blast radius per approval and evidences it, nothing more. |
| F3.4 supply chain | **PARTIAL** | Definition hash-pinning detects observed drift; package provenance is out of scope. |
| F3.5 cross-tenant isolation | **PARTIAL** | Per-principal authorization and receipts at the boundary; intra-server data isolation is the server's job. |
| F3.1–F3.3, F3.6 | **NOT IN POSITION** | Client-side and local-host classes (client-side SSRF during OAuth metadata discovery; malicious authorization-URL XSS/RCE; local one-click install compromise / stdio-proxy privilege escalation; resource-exhaustion DoS). The guard must not appear in marketing claims for these — they are named here as explicitly OUT OF SCOPE. |

**Public-language rules for this table** (each anchored in MCP-VERIFIED-01 §4): (1) this guard
makes no claim of comprehensive MCP-security coverage of any kind — NSA itself cautions that
MCP-aware proxies "remain limited and are still maturing"; (2) "consequence-closed" always means
*the fooled agent still cannot execute a consequential effect; the input trick is not prevented*;
(3) every "closed" is
scoped to the sole-ingress + fail-closed-classification preconditions above and to the guard's own
checks; (4) the Family-3 out-of-position classes are named as explicitly out of scope; (5)
"consequential effect" means state-changing/irreversible effects **on the guarded server** — the
guard gates effects, not egress of read results: a poisoned agent that legitimately reads
permitted data can still exfiltrate it through some other channel, so read-class data
exfiltration through channels the guard does not front is never claimed closed.

## Running the tests

From `ecosystem/naalp-mcp-guard/`, with `PYTHONDONTWRITEBYTECODE=1` set and using the real Python
interpreter for this platform (not a Microsoft-Store `python`/`python3` execution-alias stub):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_receipt tests.test_effect_gate tests.test_proxy tests.test_cli tests.test_coverage_honesty
```

See `RED-EVIDENCE.md` for mutation-survival evidence on the three load-bearing functions:
`EffectGate.classify` (the fail-closed classifier), `EffectGate.authorize_and_execute` (the
effect gate), and `receipt.verify_receipt_bytes` (the offline verifier).
