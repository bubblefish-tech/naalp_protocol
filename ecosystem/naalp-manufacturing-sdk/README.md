# N-AALP Manufacturing / Physical-AI Evidence SDK

A named entry point over N-AALP's manufacturing and physical-AI components: a controller-tier
signer, an OPC UA carriage binding, and a physical-hazard authorization extension, composed to
produce a signed, offline-verifiable evidence object for a robotics, CNC, or industrial-controller
action. Each component is independently built, tested, and graded — this package is documentation
and a quickstart over the existing public surface, not a new implementation.

## Why this exists

A physical-AI or manufacturing deployment needs the same guarantees N-AALP gives any other
effecting action — post-quantum signature, content-identified binding, fail-closed verification —
applied to a controller that speaks OPC UA and to an action that carries physical risk, not merely
data risk. The three public components below give exactly that, and this SDK is where they are
named and documented together instead of sitting as an unlabeled set of packages.

## Components

| Component | Package | What it does |
|---|---|---|
| A — Controller-tier signer | [`naalp-ffi`](../../impl/rust/naalp-ffi/) | A stable `extern "C"` ABI (`naalp_sign` / `naalp_verify` / `naalp_content_id` / `naalp_signer_id` / `naalp_free`) over the N-AALP core, so a C/C++ or C-FFI-capable controller (ROS nodes, vendor motion-controller SDKs) can sign and verify N-AALP objects without a second protocol implementation. A `verify_only` build feature compiles the signing path out entirely for a verification-only deployment. |
| A — Embedded / bare-metal signer subset | [`naalp-ffi-embedded`](../../impl/rust/naalp-ffi-embedded/) | A `no_std` + `alloc` build profile for a bare-metal/RTOS controller with no operating system: verifies a COSE_Sign1 ML-DSA-65 object and recomputes its content id, using the same canonical-CBOR rules and the same independent oracle vectors as the standard-library implementation. |
| B — OPC UA carriage binding | [`naalp-opcua`](../../impl/rust/naalp-opcua/) | Wraps an OPC UA message as opaque octets under N-AALP's existing opaque-carriage class, binding it by content-id hash (with an optional companion-node identity for the robotics/CNC OPC UA companion object model). A message over the channel's size budget binds by reference — a content-id hash and a locator, never the message bytes; a missing referent is unverifiable, never valid. It never parses OPC UA on the verify path. |
| F — Physical-hazard authorization extension | [`naalp-hazard`](../../impl/rust/naalp-hazard/) | Adds `hazard`, a dimension orthogonal to the existing `effect` field: a closed, fail-closed 0–4 class describing *physical* danger (a data-reversible action can still be a high physical hazard). A hazard claim carries the class plus an envelope (spatial bounds, speed bound, time window); an authorization must fully cover the claim on every dimension — exact class match and full envelope containment — or the whole claim is denied. Wire-frozen 2026-09-01; graded byte-identical against the shared, non-circular `vectors/hazard` corpus across all ten reference ports. |
| Portable decision/audit evidence | [`gateway`](../../impl/go/gateway/) (per-language: `impl/*/gateway.*` across all ten reference SDKs) | `GatewayDecision` is a signed, vendor-neutral decision object any enforcement gateway can emit as portable evidence — authority lives in the signed bytes, never in the connection or the serving host, so the same signed decision re-verifies when served by a different party. `DecisionRecord` is the fuller governed-decision accountability record (unique selection, governed-at-decision-time, binding-fixed-by-decision-time). Neither defines a policy language; both define an evidence format. |

Two further manufacturing components — a device-identity/calibration binding and a runtime-assurance
actuator gate — are intentionally not part of this SDK yet, pending physical-hardware availability
for their integration; the verifier fails closed for them with a distinct, honest "check
unavailable" outcome rather than guessing, defaulting to a pass, or silently doing nothing. That
gap is visible by design, not silently dropped.

## Entry points

- Sign / verify (controller tier): `naalp-ffi`'s `naalp_sign` / `naalp_verify` C ABI, or the Rust
  `naalp::naalpcore::{new_signer, sign, verify}` facade the FFI crate delegates to.
- Carry an OPC UA message: `naalp-opcua`'s `bind_inline` / `bind_by_reference` (construct the
  binding) + `sign_binding` (sign it) + `verify_binding` (verify it end to end, without parsing OPC
  UA).
- Authorize a physical hazard: `naalp-hazard`'s `HazardClaim` / `HazardAuthorization` +
  `hazard_authorized` (exact-class-match, full-envelope-containment check) /
  `hazard_authorized_optional` (the case where no hazard claim was presented at all).
- Emit portable decision evidence: the `gateway` package's `GatewayDecision` (`SignDecision` /
  `VerifyDecision`) or `DecisionRecord` (`ParseDecisionRecord` / the governed-decision
  accountability record), available in every one of the ten reference SDKs.

## Quickstart (documented walkthrough)

The steps below name the real functions each component exports, in the language each component is
built in. They are a documentation walkthrough of the composed flow, not a new runnable script this
package ships — each step is exercised, isolated and graded, by the component's own test suite; see
"See it running" below for the exact tests.

**1. Sign the controller-tier object and carry an OPC UA message (Rust, Components A + B).**

```rust
// naalp = the N-AALP Rust reference SDK (impl/rust); naalp_opcua = Component B.
let seed: [u8; 32] = /* a 32-byte ML-DSA-65 key-generation seed */;
let signer = naalp::naalpcore::new_signer(&seed);

// The OPC UA message (e.g. a CNC/robotics measurement or command) is carried opaque —
// naalp-opcua never parses it — and bound by content-id hash.
let binding = naalp_opcua::bind_inline(
    naalp_opcua::Encoding::Binary,
    opc_ua_message_bytes,
    Some("ns=2;s=Controller.Axis1".to_string()), // companion-node identity, optional
    /* effect class */ 1,
)?;
let signed = naalp_opcua::sign_binding(&signer, &binding)?;
```

**2. Authorize the physical hazard the action carries (Rust, Component F).**

```rust
// A claim is what the acting controller declares; a grant is what was authorized in advance.
let claim = naalp_hazard::HazardClaim { class, envelope: claim_envelope };
let grant = naalp_hazard::HazardAuthorization { class, envelope: grant_envelope };
naalp_hazard::hazard_authorized(&claim, &grant)?; // exact class match + full envelope containment, or denied
```

**3. Record the decision as portable, vendor-neutral evidence (any reference SDK; Go shown).**

```go
// impl/go/gateway — the same object shape is available in every one of the ten reference SDKs.
d := gateway.GatewayDecision{Decision: gateway.DecisionAllow, Action: actionContentID, Policy: policyID, Effect: 1}
obj, err := gateway.SignDecision(d, gatewaySigner)
// A verifier resolves the gateway's key from the self-certifying signer id and checks the
// signature over the bytes — no connection or serving-host identity is required.
resolved, err := gateway.VerifyDecision(obj, profile, gatewayVerifier)
```

## See it running

Every step above is exercised in isolation, against real cryptography, by the component's own
tests:

- `naalp-opcua`: `bind_inline_sign_verify_round_trip` (`impl/rust/naalp-opcua/src/lib.rs`) —
  binds an inline OPC UA message, signs it, and verifies it end to end.
- `naalp-hazard`: the coverage tests in `impl/rust/naalp-hazard/src/lib.rs` and the shared
  `vectors/hazard/cases.json` corpus, graded byte-identical across all ten reference ports (with
  recorded mutation-test evidence in the parity ledger).
- `gateway`: `TestDecisionThirdPartyReServe` (`impl/go/gateway/gateway_test.go`) — proves the
  same signed decision re-verifies when served by a party other than the gateway that signed it.

## Related, not included here

- The offline auditor/verifier console and the QIF-to-signed-evidence attestor exist in this tree
  but are not part of this SDK's public surface yet.
- On-target-hardware conformance regeneration (running the shared corpus on the actual controller
  hardware, not only a host build) is a tracked follow-on, not a gap silently left out of this
  document.
- OPC UA's protocol registration inside N-AALP's Bridge carriage registry
  (`vectors/registry/protocols.csv`) is tracked separately from this SDK's packaging.

## How this relates to the protocol

Like every package in [`ecosystem/`](../), this SDK consumes the N-AALP reference SDKs (`impl/`)
and the conformance corpus (`vectors/`); it does not fork or re-specify the protocol, and it
introduces no new wire format, cryptography, or CBOR codec of its own. The protocol itself — the
Internet-Draft, the CDDL wire authority, the ten SDKs, and the conformance corpus — is the
[repository root](../../).

---

*N-AALP™ and BubbleFish™ are trademarks of BubbleFish Technologies, Inc. Apache-2.0.*
