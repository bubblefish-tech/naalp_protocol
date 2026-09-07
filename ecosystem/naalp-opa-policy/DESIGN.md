# naalp-opa-policy -- design notes

## What this package is

A defense-in-depth policy-enforcement integration: an administrator writes a Rego policy
inspecting an N-AALP object's authenticated `{effect, audience, kind, channel, signer}` plus
a caller-resolved `{grant}`, and this package consults a real OPA (Open Policy Agent) engine
to refuse the action before it executes if the policy denies. It is consulted BEFORE the
Part-1 SDK's own `naalp.policy.Grant.authorize_object` floor -- never a replacement for it
(design.md "Governance (R5)").

## Multi-language shape

The GRADED deliverable in this wave is the **Python** package (`naalp_opa_policy`), matching
where the rest of the ecosystem tier already lives. The integration shape is deliberately
NOT Python-specific, so the same checked-in `policies/naalp_authz.rego` (+ `data.json`)
serves every language port without change, per the governance-integration research:

- **Go**: OPA ships a first-party in-process Go SDK (`github.com/open-policy-agent/opa/v1/rego`
  -- `rego.New(Query, Module, Input)` -> `PrepareForEval` -> `Eval`). A future `impl/go`
  integration embeds the checked-in policy directly, with no subprocess and no sidecar --
  strictly less moving parts than this Python package's subprocess invocation, not more.
- **Every other port (Rust/TypeScript/C#/Java/Kotlin/PHP/Ruby/Swift):** OPA has no first-party
  SDK for any of these languages. The documented, standard integration shape is a co-located
  **OPA REST sidecar**: run `opa run --server` (or the equivalent bundle-serving mode) once
  per deployment, loaded with the SAME checked-in `policies/` directory this package ships,
  and have each port's `naalp_opa_policy`-equivalent module `POST` the identical JSON input
  document this package's `build_input()` produces to the sidecar's `/v1/data/naalp/authz/allow`
  endpoint, applying the SAME fail-closed rule this package's `OPAEngine.decide()` applies
  (an unreachable sidecar, a non-2xx response, or an absent/false `result` field in the JSON
  response body all deny). This Python package's `opa eval` subprocess invocation and a
  future REST-sidecar client are two transports over the SAME contract -- the input-document
  shape (`build_input`'s output) and the fail-closed decision rule (`decide`'s branches) are
  the stable, portable pieces; the transport is not.
- This package's own `subprocess`-based `opa eval` invocation is itself a THIRD valid shape
  (a local, in-process-adjacent evaluation with no server to run) -- appropriate for a
  single-process Python deployment; a production deployment with many short-lived Python
  workers would more likely run the same sidecar approach the other ports use, for the same
  reason (avoid re-loading/re-compiling the policy on every process).

## Why OPA (not Cedar) for this graded wave

The grounding research recommends OPA/Rego first for multi-language reach (a real, if thin,
SDK story across ecosystems) with Cedar as a future alternative given its currently
Rust/WASM/JS-only SDK breadth (a judgment call recorded in the research doc, not asserted by
either project). This package follows that recommendation; a `naalp-cedar-policy` sibling
package remains future, un-scoped work, tracked as such rather than silently implied.

## What is NOT in scope for this package

- Re-implementing Rego evaluation (this package invokes the real `opa` binary; see
  `opa_policy.py`'s module docstring and RED-EVIDENCE.md's engine-invocation notes).
- Replacing `naalp.policy.Grant.authorize_object` (Part-1's floor check remains mandatory and
  is unaffected; this package adds an earlier, additional gate).
- A REST-sidecar client, a bundle-server deployment, or any non-Python port's integration
  (multi-language shape above is design guidance for a future wave, not built here).
- Policy authoring tooling, a policy registry, or hot-reload of the checked-in policy
  directory -- `policies/naalp_authz.rego` is a WORKED EXAMPLE administrators are expected to
  adapt or replace outright by pointing `OPAEngine` at their own directory.
