<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Crypto agility and migration

N-AALP tracks four independent axes that a migration can confuse if it treats them as one. Each
changes on its own trigger, is carried by its own wire mechanism, and moving one never silently
moves another.

| Axis | Carrier | Current / default | Changes on |
|---|---|---|---|
| Envelope wire version | `naalp-version` (protected header + field 9) | `2` | A grammar-breaking change to the signed envelope shape |
| Signature suite | Field 14 (`suite`); absent = pure | pure ML-DSA (MTI); opt-in LAMPS composite | An operator's own opt-in decision, or a future default flip (§ below) |
| Profile (security posture) | Field 9 (protected header + body) | Public / Enterprise / Sovereign | An operator's own deployment choice |
| Signer identity | The self-certifying `signer` id (derived from the public key) | — | A key rotation or revocation |

## 1. Envelope wire version

The `naalp-version` field is the grammar-breaking axis: it changes only when the signed envelope's
own shape changes (a new required field, a changed field semantics), never for an algorithm swap or
a profile choice. It is checked and rejected fail-closed (`UnsupportedVersion`) on mismatch by every
reference SDK; the Go reference names it `envelope.NaalpVersion` (currently `2`). Algorithm agility
and profile choice are deliberately **decoupled** from this axis — adding the opt-in composite suite
and the `audience` field both landed as the same `naalp-version = 2` bump precisely because they
extend the grammar; a future algorithm change that does not touch the envelope shape would not need
a version bump at all.

## 2. Signature suite: pure ML-DSA (default) vs. the opt-in composite

The default and mandatory-to-implement (MTI) signature is **pure ML-DSA** (FIPS 204, deterministic,
`rnd = 0`) — no object pays for a classical leg unless a deployment opts in. Algorithm agility itself
is COSE's own `alg` header parameter (RFC 9052): changing the profile's signature algorithm changes
the `alg` value and the key type, with no change to the COSE_Sign1 construction or the envelope.

| Algorithm | COSE `alg` | Role |
|---|---:|---|
| ML-DSA-87 | -50 | PQ signature, level 5 (Sovereign default/mandate) |
| ML-DSA-65 | -49 | PQ signature, level 3 (Public/Enterprise default, MTI) |
| ML-DSA-44 | -48 | PQ signature, level 2 (optional edge/light tier only, never a silent downgrade) |
| Ed25519 | -19 | classical, **opt-in composite leg only** — never a standalone signature |

### The opt-in composite is one signature, not two

The optional hybrid is a **negotiable opt-in**, retained for a deployment bridging classical peers
and, for durability, as a pre-declared migration path should ML-DSA ever be weakened. It is **not**
two independent signatures: it is a single COSE_Sign1 whose signature value is the IETF LAMPS
composite of an ML-DSA and an Ed25519 signature over one domain-separated message representative —
verification is valid **iff both components validate**. A stripped object has no valid signature at
all, even to a non-strict verifier.

Which suite signed an object is itself a **signed field carried under the signature** (field 14,
`suite`) — absent for a pure object, `1` for the Public/Enterprise composite
(`COMPSIG-MLDSA65-Ed25519-SHA512`). Turning the composite on for a deployment, or flipping the
*default* suite later, is a suite-id change through this field — **not a wire break**.

```go
import "github.com/bubblefish-tech/naalp_protocol/impl/go/cose"

// Pure (default): no composite signer, field 14 absent.
signed, err := envelope.Sign(obj, cose.MLDSA65Signer{SK: sk})

// Opt-in composite: both an ML-DSA and an Ed25519 key. Sign() reads the composite alg off
// the signer and sets field 14 = SuiteMLDSA65Ed25519 automatically — a caller never sets
// the suite field by hand.
composite := cose.CompositeSigner{ML65: mlSK, Ed: edSK}
signed, err = envelope.Sign(obj, composite)
```

### Sovereign is never composite

The Sovereign profile signs with pure ML-DSA-87 and carries no classical leg — CNSA 2.0 mandates
ML-DSA-87 for national-security signatures. A Sovereign verifier **refuses** a composite object
(`CompositeRefused`); this is a hard profile rule, never a negotiable default.

### Migrating a deployment onto the composite

1. **Decide the trigger.** The composite exists for two reasons: bridging a classical-only peer
   during a transition, or a pre-declared response if ML-DSA is ever weakened. Do not enable it as a
   default performance or compatibility choice — it costs an extra signature verification per
   object for no security benefit when both peers already trust ML-DSA alone.
2. **Generate the Ed25519 leg** alongside the existing ML-DSA key for every signer that needs it.
   The ML-DSA leg's key and identity are unchanged; the composite adds a second key, it does not
   replace the first.
3. **Sign with the composite signer** — the SDK sets the signed suite field (14) automatically from
   the signer's algorithm; a caller never sets it by hand. A verifier that has not opted in to
   accepting composite objects will reject an unrecognized `alg` value (`UnknownAlg`) — coordinate
   rollout so verifiers are updated before signers start emitting composite objects.
4. **Never let Sovereign accept it.** If any signer in the deployment operates under the Sovereign
   profile, confirm the composite path is never reachable for that signer's keys — a Sovereign
   verifier rejects it regardless, but a Sovereign *signer* should never attempt it.
5. **Unforgeability note.** Pure ML-DSA is SUF-CMA (strongly unforgeable); the opt-in composite is
   EUF-CMA but not SUF-CMA. N-AALP never keys a security decision off raw signature bytes regardless
   — the single-use consume ledger binds the content id and receipt chain, not the signature — so
   this is a property to be aware of, not a load-bearing gap.

## 3. Profile: Public, Enterprise, Sovereign

Profile is a **separate axis** from the signature suite: it is the operator's own security-posture
choice, fixing the minimum signature level a verifier accepts and whether the composite is even
permitted.

| Property | Public (1) | Enterprise (2) | Sovereign (3) |
|---|---|---|---|
| Default signature | ML-DSA-65 | ML-DSA-65 | ML-DSA-87 |
| Minimum signature level | 3 | 3 | 5 (refuse below) |
| Opt-in composite | permitted | permitted | **refused** |
| Digest | SHA-384 | SHA-384 | SHA-384+ |

The profile is bound under the signature (field 9 + protected header), so stripping or downgrading
it invalidates the object. A Sovereign verifier refuses any object whose signature is below level 5.
No edition is a fork — one binding, one construction, one parameter row per profile on one codebase.

**Migrating a deployment's profile** (e.g. Public → Enterprise, or onboarding a Sovereign segment)
is an endpoint-configuration change: raise the accepted/emitted profile on the endpoints that need
it, and confirm no downstream verifier still pinned to the old profile silently accepts an
object it should now refuse at the higher floor. A profile can only ever be *raised* deliberately
by configuration — an object cannot claim a profile its own signature does not meet.

## 4. Key rotation and revocation

A signer's key is not permanent. Because the signer id is a pure function of the public key, a
rotation needs its own durable-identity mechanism so a receipt signed under an old key stays
attributable to the same identity after the key changes.

### Rotation: a co-signed statement, never a lone new-key claim

A **Rotation object** (Identity channel `0x0003`, kind `0`) is `{old: signer_old, new: signer_new,
not_before, prev_rotation?}`, carried as a tagged **COSE_Sign** (tag 98) with **exactly two**
`COSE_Signature` legs in fixed order — old key, then new key. A verifier requires **both** legs to
validate; a rotation presented as an ordinary single-signature COSE_Sign1 (tag 18) is rejected
`RotationUnauthorized` — closing the gap where a lone new-key signature would otherwise verify like
any other object with no old-key check at all. A substitution not co-signed by the old key is not a
rotation.

```go
signed, err := envelope.SignRotation(rotationObj, oldSigner, newSigner) // envelope/rotation.go
// A verifier holding a trusted old key and the object's new key:
obj, err := envelope.VerifyRotationObject(profile, oldVerifier, newVerifier, kindOK, nil, signed)
```

A chain of rotation objects gives a durable identity thread across arbitrarily many rotations: the
current signer is the last binding in a verified chain, and a receipt signed under any earlier key
in the chain stays attributable to the same durable identity. Composite legs are undecided inside a
rotation's old/new co-signature and are rejected fail-closed — rotate with pure ML-DSA (or pure
Ed25519) keys, not a composite signer.

**Old-leg profile floor.** By default, when a Sovereign/High verifier checks a rotation whose *old*
key is below the profile's signature floor, the floor applies to **both** legs (a below-floor old
key is rejected `ProfileDowngrade`). A deployment may explicitly relax this to the new (go-forward)
leg only — this is a deployment-configured toggle, not a wire choice.

### Revocation: distinct from rotation, and terminal

A **Revocation object** `{key: signer, not_after}`, signed by the key itself (or by a
deployer-configured recovery key), marks a key dead from `not_after`. It carries no `new` key and
does not continue the identity thread — where rotation *hands off* the thread, revocation *ends* it.
An object whose authoritative receipt position falls after `not_after` is rejected; objects fixed
before it stay valid. Absent any configured recovery key, only the revoked key may sign its own
revocation (`SignerMismatch` otherwise).

### Migrating (rotating) a live deployment's keys

1. **Generate the new key** for the signer while the old key is still valid and unrevoked.
2. **Build and co-sign the Rotation object** with both the old and new keys, setting `not_before` to
   when the new key becomes authoritative.
3. **Distribute the rotation object** to every counterparty that verifies this signer's objects
   before `not_before` arrives, so no verifier is surprised by a new signer id it cannot yet chain
   back to the old one.
4. **Confirm chain continuity**: a verifier walking the rotation chain should resolve the new signer
   id back to the original durable identity, and pre-rotation receipts signed under the old key
   should remain independently verifiable and attributable to the same identity thread.
5. **Only revoke** the old key if it is compromised or permanently retired — a clean rotation does
   not require revoking the old key at all; the old key simply stops being used going forward while
   remaining valid for verifying its own historical signatures.

## 5. Operational checklist

- [ ] Confirm every counterparty's SDK checks `naalp-version` and rejects an unsupported version
      fail-closed (`UnsupportedVersion`) rather than guessing at an unrecognized grammar.
- [ ] Decide the composite-suite trigger (classical-bridge or pre-declared ML-DSA-weakening
      response) before enabling it anywhere — it is not a default performance choice.
- [ ] If enabling the composite, roll out verifier support (accepting the `suite` field and the
      composite `alg`) before any signer starts emitting composite objects.
- [ ] Never enable the composite path for a Sovereign-profile signer; confirm a Sovereign verifier's
      refusal is exercised in the deployment's own test suite, not merely assumed from the spec.
- [ ] For a profile raise (Public → Enterprise, or onboarding Sovereign), confirm no downstream
      verifier is still pinned to the old, lower floor.
- [ ] For a key rotation, build and distribute the co-signed Rotation object before the new key's
      `not_before`, and confirm chain continuity resolves the new id back to the original identity.
- [ ] Revoke a key only on compromise or permanent retirement, never as a routine part of rotation.

## 6. Non-scope

This page does not cover: the eight non-Go/Rust SDK ports' own key-management or CLI tooling
(each language's own I/O and key-storage integration is that SDK's own concern; the wire mechanisms
above are identical across all ten); a general registry-of-registries for future signature
algorithms beyond the reserved SLH-DSA (FIPS 205) code points; and the N-PAMP transport's own
independent key-exchange rotation, which is a substrate concern that never lands on the N-AALP
object signature.

## 7. References

- [The object model](object-model.md) — the signed envelope this page's fields live in.
- [Design decision 0003](../adr/0003-post-quantum-first.md) — why ML-DSA is mandatory-to-implement.
- `vectors/registry/signatures.csv` — the authoritative COSE algorithm code-point registry.
- `impl/go/cose`, `impl/go/identity`, `impl/go/envelope/rotation.go` — the reference implementation
  this page's code snippets are drawn from.
