# N-AALP — Design (spine and cross-cutting)

**Protocol:** draft-bubblefish-naalp-00 — Native Agentic Application Layer Protocol
**Substrate:** N-PAMP `draft-bubblefish-npamp-01` (authoritative)
**Companions:** `PLAN.md`, `requirements.md`, `design-channels.md` (the twenty channel surfaces)
**Status:** Phase 2 deliverable. Requires Shawn's approval before Phase 3 build.

This document specifies the internal structure of every cross-cutting component to a
precision at which implementation is mechanical. Each section names the requirements it
satisfies, states the design, argues the alternatives with a recommendation where a
real choice exists, and lists the failure modes. The twenty channel surfaces are in
`design-channels.md`; every one of them inherits the spine defined here unchanged.

CDDL fragments below are the byte-level authority (R-3.2). They are the design's
normative core; the Phase-3 build assembles them into one validated module
`naalp-draft-00.cddl`.

---

## 1. Architecture

### 1.1 The one-object principle

Everything N-AALP does is one kind of thing on the wire: a **signed object**. A
message, an approval, a receipt, a delivery update, a stream commitment, a memory
operation, a carried foreign request — all are objects of the same envelope, differing
only in their `kind`, their `channel`, and their body. There is exactly one envelope,
one signing construction, one identity model, one effect model, and one audit model,
and every channel surface and every transport binding reuses them without variation
(R-2.1, R-11.3, R-12.1). This is the property that makes the protocol auditable as one
algebra rather than as twenty subsystems.

### 1.2 Layering

```
  application agent
      │  emits / consumes N-AALP objects
  ┌───────────────────────────────────────────────┐
  │ N-AALP object layer (this design)             │  signed, PQ, governed, audited
  │  envelope · identity · effect · approval ·    │  — identical on every transport
  │  audit · delivery · streaming · carriage      │
  └───────────────────────────────────────────────┘
      │  transport binding (§12)
  ┌─────────────┬─────────────┬──────────┬─────────┐
  │  N-PAMP     │  QUIC       │  WebSocket │  HTTP   │  confidentiality + channel auth
  └─────────────┴─────────────┴──────────┴─────────┘
```

Object-level security (integrity, identity, non-repudiation, audit) lives entirely in
the object layer and is present on all four transports (R-13.2). Confidentiality and
connection authentication are the transport's; N-PAMP is the reference that completes
the picture (R-13.3). The object layer never reads a guarantee from the transport that
it needs for its own correctness.

### 1.3 Component inventory (every component traces to requirements)

| # | Component | Requirements | design |
|---|---|---|---|
| C1 | Deterministic CBOR codec + CDDL | R-3.1..3.4 | §3 |
| C2 | COSE signing / crypto-agile profiles | R-4.1..4.8, R-2.2 | §4 |
| C3 | Object envelope + content-id | R-2.1..2.6 | §2 |
| C4 | Identity + key lifecycle | R-1.3, R-1.4, R-5.1..5.4 | §5 |
| C5 | Effect + safety vocabulary | R-6.1..6.5 | §6 |
| C6 | Approval + single-use consume ledger | R-7.1..7.4 | §7 |
| C7 | Audit chain + causal graph + ordering | R-8.1..8.6, R-12.2..12.3 | §8 |
| C8 | Delivery stages + switchboard | R-9.1..9.4 | §9 |
| C9 | Native streaming + commitment | R-10.1..10.6 | §10 |
| C10 | Channel surfaces (×20, tiered) | R-11.1..11.4, R-15A.1..3 | `design-channels.md` |
| C11 | Transport bindings (×4) | R-13.1..13.4 | §12 |
| C12 | Foreign carriage by class + registry | R-14.1..14.8 | §13 |
| C13 | Profiles + editions | R-15.1..15.5 | §4.4, §11 |
| C14 | Conformance corpus + oracles + parity | R-16.1..16.4, R-18.3..18.4 | §14 |

### 1.4 Build order (each depends only on components already built — R-16, no cycles)

C1 → C2 → C3 → C4 → C5 → C6 → C7 → C8 → C9 → C11 → C12 → C10 → C14.

C1–C9 are the spine and are built and graded in isolation before any channel surface
(C10) exists, because every channel surface is a thin body over the spine. C11
(transports) and C12 (carriage) precede C10 because a channel surface is demonstrated
end-to-end over a transport. C14 (conformance) grades each of the above as it lands;
it is not a final phase bolted on. There is no circular dependency: no component in
this order references a component later in it.

---

## 2. The object envelope (C3)

### 2.1 What an object is

An N-AALP object is a COSE_Sign1 structure (RFC 9052) whose payload is one
deterministically-encoded CBOR map — the **object body** — and whose protected header
binds the metadata that governs it. Signing one COSE_Sign1 over the whole body is the
single construction of R-2.1; there is no second encoding.

The signed payload (the COSE_Sign1 payload) is the object body map with these
integer-keyed fields:

```cddl
naalp-object = {
  1 : bstr,            ; id      — content id of this object (§2.3), self-referential-excluded (§2.3)
  2 : uint,            ; kind    — object kind code (per channel surface)
  3 : uint,            ; channel — N-PAMP channel id 0x0000..0x0013
  4 : uint,            ; tier    — channel capability tier (0 = baseline)
  5 : bstr,            ; signer  — signer identity id (§5.1)
  6 : uint,            ; created — signer's claimed creation time (§2.4), epoch ms
  7 : effect,          ; effect  — closed effect value (§6)
  8 : [* bstr],        ; causes  — content ids of causing objects (§8.2), may be empty
  9 : uint,            ; profile — 1 Public, 2 Enterprise, 3 Sovereign (§4.4)
  10 : any,            ; body    — kind-specific body (validated by the channel surface)
  ? 11 : { * uint => any }, ; ext — non-critical extensions (ignored if unknown, R-2.5)
  ? 12 : { * uint => any }, ; cext— critical extensions (reject if any unknown, R-2.5)
}
effect = 0 / 1 / 2 / 3   ; §6.1
```

The COSE_Sign1 protected header carries the signature algorithm id (COSE `alg`, §4.1)
and a copy of `signer` and `profile` for pre-parse routing; a verifier MUST reject an
object whose protected-header `signer`/`profile` disagree with the body's fields
(fail-closed). The COSE external_aad is empty; everything bound is inside the signed
structure so an object is self-contained and offline-verifiable (R-2.4).

### 2.2 What the signature binds

Because the entire body map (id, kind, channel, tier, signer, created, effect, causes,
profile, body, extensions) is the COSE_Sign1 payload, altering any field invalidates
the signature (R-2.3). A state-changing object with no valid COSE_Sign1 is rejected
before any effect (R-2.6). Two independent implementations produce byte-identical
signed input because the payload is deterministic CBOR (§3) and the COSE_Sign1
Sig_structure is constructed per RFC 9052 §4.4 with fixed context and empty aad
(R-2.2).

### 2.3 Content id

`id` (field 1) is the object's content id, computed as
`multihash(0x20, SHA-384(canonical-body-without-field-1))` — that is, the deterministic
CBOR encoding of the body map with field 1 omitted, hashed with SHA-384 (0x20 is the
multihash code for sha2-384), wrapped as a multihash so the hash algorithm is
self-described and agile.

- **Recommendation: content id, not random id.** A content id is self-certifying (any
  holder recomputes and checks it), makes deduplication free, and — decisively — makes
  a `causes` reference (§8.2) a verifiable pointer: naming a cause by its content id
  lets a verifier confirm the cause is exactly the object intended, with no separate
  integrity step. This is what makes the causal graph checkable offline (R-12.2).
- **Alternative rejected: random UUID id.** Needs a separate integrity binding for
  every causal edge and permits two different objects to claim one id. The only cost of
  content id — you cannot know the id until the body is fixed — is not a real cost here
  because the id is excluded from its own hash input and everything else is known at
  build time.

The signer computes `id` over the body-minus-field-1, writes it into field 1, then
signs the whole body (now including field 1). A verifier recomputes `id` from
body-minus-field-1 and rejects a mismatch, then verifies the COSE_Sign1.

### 2.4 Time

`created` (field 6) is the signer's own claim and MUST NOT be trusted as authoritative
for ordering or long-term proof (a signer can lie about its clock). The authoritative
temporal fact is an object's **position in the hash-chained audit log** (§8.1): the
receipt an ordering authority signs over the object fixes "this object existed no later
than receipt seq N," which a verifier checks independently of the signer's clock
(R-8.4). `created` is advisory and is used only for human display and for the
causal-consistency check of §8.3 (a cause's `created` must not exceed the effect's).

### 2.5 Versioning and extensions

The protected header carries `naalp-version` = 1. Field 12 (`cext`) is the critical
extension map: a verifier that does not recognize any key in `cext` MUST reject the
object. Field 11 (`ext`) is non-critical: unknown keys are ignored (R-2.5). This is the
one forward-compatibility rule; a channel surface adds capability by defining new
`kind` codes and, at a higher tier, new `ext`/`cext` keys, never by changing the
envelope.

### 2.6 Failure modes

| condition | detection | response |
|---|---|---|
| bad COSE_Sign1 signature | verify fails | reject; no effect (R-2.6) |
| `id` ≠ recomputed content id | recompute | reject (`ContentIdMismatch`) |
| header/body `signer` or `profile` disagree | compare | reject (`HeaderBodyMismatch`) |
| unknown `cext` key | map scan | reject (`UnknownCriticalExt`) |
| non-deterministic CBOR | codec (§3) | reject (`NonCanonical`) |
| unknown `kind`/`channel` for the surface | surface dispatch | reject (`UnknownKind`) |

---

## 3. Deterministic CBOR and CDDL (C1)

### 3.1 Encoding rules

All N-AALP CBOR is deterministic per RFC 8949 §4.2.1: integer keys in a map sorted
ascending by their encoded bytes; shortest-form integer and length encodings; no
indefinite-length items; no duplicate keys; finite floats only where a float is
permitted (N-AALP uses none in the spine). Text strings are UTF-8 and, where they name
an identity, resource, or approval scope, MUST be Unicode NFC; a non-NFC string in such
a field is rejected (R-3.3). This makes byte-for-byte reproducibility (R-2.2) a
property of the codec, not of each call site.

### 3.2 The CDDL module

`naalp-draft-00.cddl` is the byte-level authority (R-3.2). Prose and CDDL cannot
disagree; where they appear to, the CDDL governs. The build validates every positive
vector against it and confirms every negative vector fails it (R-16.1). The module is
assembled from the fragments in this document and `design-channels.md`.

### 3.3 Required edge cases (each gets a vector with a fixed outcome — R-3.3)

minimal object (only required fields); out-of-order map keys (reject `NonCanonical`);
non-NFC vs NFC in an identity/scope field (reject `NonNFC` vs accept); empty vs absent
optional field (absent ≠ empty; both defined); oversized integer beyond the field's
range (reject `RangeError`). A malformed object is rejected whole and never partially
applied (R-3.4).

---

## 4. Crypto: COSE signing and the profile table (C2, C13)

### 4.1 Signing container

N-AALP signs with **COSE_Sign1** (RFC 9052), one signer per object. Algorithm agility
is COSE's `alg` header parameter (R-4.1): changing the profile changes the `alg` value
and the key type, with no change to the COSE_Sign1 construction or the envelope. The
verified COSE algorithm code points are:

| algorithm | COSE alg | role | notes |
|---|---|---|---|
| ML-DSA-87 | -50 | PQ signature, level 5 | FIPS 204; Sovereign default/mandate |
| ML-DSA-65 | -49 | PQ signature, level 3 | FIPS 204; Public/Enterprise default |
| Ed25519 | -19 | classical, hybrid leg only | RFC 9053; fully-specified EdDSA |

- **Recommendation: COSE_Sign1 over a bespoke signature envelope.** COSE is a published
  IETF standard (R-4.8), is defined over deterministic CBOR, carries algorithm agility
  natively, and already has the ML-DSA code points assigned, so N-AALP invents no
  cryptography and no new algorithm registration (R-4.8). A bespoke container would
  duplicate COSE and forfeit its tooling.

### 4.2 Hybrid mode (transition)

The optional hybrid (R-4.4) is a COSE_Sign structure (multi-signature) with two
signatures over the identical payload: one Ed25519 (-19) and one ML-DSA (-49 or -50).
A hybrid object is accepted only if **both** verify. This is the one place COSE_Sign
(not Sign1) is used; a verifier selects the structure by the COSE tag. Hybrid is never
a default; it is selected explicitly for a deployment bridging classical peers.

### 4.3 Digests

Every digest in the spine (content id §2.3, stream commitment §10, receipt chain §8) is
SHA-384 or stronger (R-4.6), carried as a multihash so the algorithm is self-described
and can be raised without a wire change. No profile admits a hash below SHA-384.

### 4.4 The profile table (one wire, per-profile row — R-15.1)

| property | Public (1) | Enterprise (2) | Sovereign (3) |
|---|---|---|---|
| default signature | ML-DSA-65 (-49) | ML-DSA-65 (-49) | ML-DSA-87 (-50) |
| minimum signature level | 3 | 3 | 5 (refuse below) |
| hybrid Ed25519+ML-DSA | permitted | permitted | permitted |
| digest | SHA-384 | SHA-384 | SHA-384+ |
| composes with N-PAMP profile | Standard/High | High | Sovereign |

One binding, one construction, one parameter row per profile (R-15.1). The profile is
bound under the signature (field 9 + protected header, §2.1), so stripping or
downgrading it invalidates the object (R-15.2). A Sovereign verifier refuses any object
whose signature is below level 5 (R-15.3, R-4.3). Editions license rows and channel
tiers on one codebase; no edition is a fork (R-15.4). N-AALP's own object signature is
its only crypto weight — the heavy ML-KEM-1024 key exchange is N-PAMP's transport
concern and never lands on N-AALP.

- **Reserved for the future (R-4.5):** COSE alg ids for SLH-DSA (FIPS 205) are reserved
  in the N-AALP signature registry so a hash-based signature can be added as an
  alternative — hedging the lattice monoculture — with no envelope change.

### 4.5 Failure modes

signature-below-profile-minimum → reject (`ProfileDowngrade`); unknown `alg` →
reject (`UnknownAlg`); hybrid with one leg failing → reject (`HybridIncomplete`);
key/alg type mismatch → reject (`KeyAlgMismatch`).

---

## 5. Identity and key lifecycle (C4)

### 5.1 Signer identity

A signer is named by a self-certifying id derived from its public signing key exactly
as N-PAMP's PeerHandle (R-5.1, and identical to N-PAMP so the layers share one name):

```
  signer = multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))
  mc = 0x1212 for ML-DSA-87, the ML-DSA-65 multicodec for ML-DSA-65, 0xed for Ed25519
```

The full public key travels as an RFC 7250 SubjectPublicKeyInfo in the object's first
appearance from a signer (or is already known from the N-PAMP handshake, R-1.3). A
verifier recomputes `signer` from the key and rejects a mismatch (R-5.1). Over N-PAMP,
`signer` MUST equal the handshake-authenticated PeerHandle; a self-asserted `signer`
that the transport did not authenticate confers no authority (R-1.3, R-6.5).

### 5.2 Rotation continuity (the durable part N-PAMP leaves open — R-1.4, R-5.2)

Because the key-derived id changes when the key rotates, N-AALP defines a **Rotation
object** (Identity channel, `design-channels.md`) — a signed statement
`{ old: signer_old, new: signer_new, not_before, prev_rotation? }` signed by **both**
keys (a COSE_Sign with the old and new keys, both required). A verifier that trusts
`signer_old` thereby trusts `signer_new` from `not_before`. A chain of rotation objects
gives a durable identity thread across arbitrarily many rotations; a receipt signed
under an old key stays verifiable and remains attributable to the same durable identity
after rotation (R-1.4). A substitution not signed by the old key is not a rotation and
is rejected.

### 5.3 Revocation

A **Revocation object** `{ key: signer, not_after }` signed by the key (or by a
deployer-configured recovery key) marks a key dead from `not_after`. An object whose
authoritative receipt position (§8) is after `not_after` is rejected; objects fixed
before it stay valid (R-5.3). Revocation is distinguishable from rotation: rotation
carries a `new` key and continues the thread; revocation carries only `not_after` and
ends it.

### 5.4 Carried foreign identity

A foreign identity (a W3C DID, a foreign agent id) is linked only by a verified
cross-signature `{ controls: signer, foreign_id, not_after }` signed by the foreign
identity's key (R-5.4), the same construction N-PAMP's PeerHandle cross-signature uses.
It never overrides the key-derived N-AALP identity; absence of a link is not a failure.

### 5.5 Failure modes

signer ≠ recomputed id → reject (`SignerMismatch`); rotation not co-signed by old key →
reject (`RotationUnauthorized`); object after revocation `not_after` → reject
(`KeyRevoked`); foreign link expired or wrong key → link ignored, object still valid on
its own signature.

---

## 6. Effects and safety (C5)

### 6.1 The closed effect vocabulary

The effect field (envelope field 7) is one of a closed set aligned 1:1 with the N-PAMP
Bridge SafetyLabel so carriage maps without translation (R-6.1):

| effect | value | authorizes | denies |
|---|---|---|---|
| read_only | 0 | observation, no state change | any write |
| idempotent_write | 1 | a write safe to repeat | non-idempotent or destructive change |
| non_idempotent_write | 2 | a write not safe to repeat | destruction |
| destructive | 3 | irreversible change / deletion | nothing further (top of lattice) |

A value-bearing object (Settlement, Commerce) does **not** get a fifth effect class; it
carries its money semantics in a signed `value_commitment` body field and takes the
effect that matches its state change (typically `non_idempotent_write`). This keeps the
effect set aligned with N-PAMP and avoids a carriage mapping gap.
- **Recommendation over a 5th `value_transfer` effect:** a fifth effect would break the
  1:1 Bridge SafetyLabel mapping (N-PAMP has four) and force a lossy translation on
  every carried value message. A body-level `value_commitment` under the same signature
  is strictly more expressive and mapping-clean.

### 6.2 Fail-closed

An unrecognized effect value MUST be treated as `destructive` and MUST NOT fail open
(R-6.2) — identical to N-PAMP's rule that an absent SafetyLabel on a state-mutating
message is `destructive`.

### 6.3 Effect is an authorization input, not a hint

This is the exact hole N-PAMP names and leaves open ("the label describes intent and
does not replace authorization"). N-AALP closes it: §6.1 defines, per effect, what is
authorized and denied, and the endpoint's policy evaluates the object's effect against
its granted capability before any execution (R-6.3). An object whose effect exceeds
what its capability authorizes is denied (`EffectNotAuthorized`).

### 6.4 Safety label

The optional safety label is a signed `ext` field `{ risk, scope }`; it is
attributable to the signer and auditable, and the security considerations state plainly
that it is an accountable claim, not a guarantee the content is safe (R-6.4). No layer
authorizes from transport metadata, a foreign header, or a client-supplied name (R-6.5).

---

## 7. Approval and the single-use consume ledger (C6)

### 7.1 Approval binds exact arguments

An **Approval object** binds, under signature, the content id of the exact canonical
argument object it approves: `{ approves: <content-id-of-args>, approver: signer,
grant: effect, nonce: bstr, not_after }` (R-7.1). Because the args are named by content
id, approving one action cannot authorize a different one — any mutation of the args
changes their content id and the approval no longer matches.

### 7.2 The consume ledger

The consume ledger is a durable, hash-chained set keyed by approval content id. Consume
is an atomic compare-and-set: the first consumer that appends
`{ consumed: <approval-id>, by: signer, at_seq }` to the ledger wins; a second append
for the same approval id is rejected (`AlreadyConsumed`) (R-7.2). Atomicity is provided
by the store's write-ahead log and a single-writer-per-approval-id discipline;
concurrent consumers serialize through the ledger's compare-and-set and exactly one
succeeds.

### 7.3 No replay

An approval is bound to its `nonce`, its `not_after`, and (via the args' content id) its
exact action; it is not valid across sessions, contexts, or after expiry, and once
consumed it is dead (R-7.3). A held outcome — approval required but not yet granted — is
a distinct signed `ApprovalHeld` result object, never a silent success or denial
(R-7.4).

### 7.4 Failure modes

args mutated after approval → content-id mismatch → `ApprovalMismatch`; second consume
→ `AlreadyConsumed`; expired → `ApprovalExpired`; missing approval on an action that
requires one → `ApprovalRequired` (a held result, §7.3).

---

## 8. Audit, causal graph, and ordering (C7)

### 8.1 The receipt chain

An ordering authority records each accepted object by appending a signed **Receipt**:
`{ prev: <hash-of-prev-receipt>, obj: <object-content-id>, seq: uint, at: time }`,
signed by the authority (R-8.1). The chain is tamper-evident: any reordering, omission,
or substitution breaks a `prev` link or duplicates a `seq`, which a verifier detects.
The authority never mutates the origin object to order it — the object's own signature
stays valid; ordering is an outer signed layer (R-8.2).

### 8.2 The causal graph (the ordering foundation — R-8.5, R-12.2)

Every object may name its causes by content id in envelope field 8. This is a signed
partial order: an edge `A causes B` is proven by B's signature over A's content id, and
is checkable offline with no ordering authority present (R-8.5). The causal graph is the
authority-independent foundation; a total order is a policy layered on top of it, not a
property of the wire.

### 8.3 Causal consistency

An object MUST NOT name as a cause an object it could not have seen: a cause's authority
position (or, absent a receipt, its `created`) MUST NOT exceed the effect's, and the
graph MUST be acyclic (R-12.3). A cycle or future-cause is rejected (`CausalViolation`).

### 8.4 Tiered ordering authority (R-8.6, R-15A.3)

- **Baseline tier (frozen):** a single ordering authority per conversation issues the
  monotonic `seq` receipt chain of §8.1. Simple, strongly consistent, sufficient for
  the large majority of deployments.
- **Higher tier (federation):** multiple independent authorities each issue receipts
  over their own scope, and reconciliation is defined over the shared causal graph —
  the partial order from §8.2 is the common substrate every authority already signs
  over. Because both tiers order the identical signed objects, moving from single to
  federated ordering requires no envelope or object change (R-8.6). The reconciliation
  algorithm (a deterministic merge of per-authority receipt chains keyed by the causal
  graph) is specified at the federation tier of the Federation channel
  (`design-channels.md`); the baseline does not implement it and does not need it.

### 8.5 Independent auditor

An auditor detects **equivocation** — two receipts by one authority at one `seq` naming
different objects — from the signed receipts alone (R-8.3). The design states honestly
that the chain reveals equivocation and omission-of-known-events but cannot force an
authority to deliver events it chooses to withhold; that residual is a trust property of
the authority, not something the wire can remove.

### 8.6 Failure modes

broken `prev` link → `ChainBroken`; duplicate `seq` different obj → `Equivocation`;
cause after effect / cycle → `CausalViolation`; receipt signature invalid →
`ReceiptUnsigned`.

---

## 9. Delivery and the switchboard (C8)

### 9.1 Delivery as signed stages

Delivery is four distinct, monotonic, separately-observable stages, each a signed
`delivery.update` object naming the target object's content id and the stage reached
(R-9.1): `persisted_origin` → `accepted_relay` → `persisted_target` → `presented`.
There is no single "sent" boolean. A crash recovers to the last durable stage; the
sender learns exactly how far an object got.

### 9.2 Persist-before-acknowledge

An endpoint or relay MUST durably persist an object (store WAL fsync) before emitting
the acknowledgment that advances its stage (R-9.2). A crash immediately after an
acknowledgment therefore loses nothing acknowledged.

### 9.3 The live switchboard

The carrier interface holds two connections open and passes objects through in both
directions concurrently — a switchboard, not a one-object mailbox (R-9.3). A relay that
holds an object only in transit writes the audit receipt (§8) without retaining the
payload beyond routing, so a content-free relay still produces a valid audit trail
(R-9.4).

### 9.4 Failure modes

ack before persist (a conformance-forbidden implementation bug) → detected by the crash
test (R-9.2 vector); stage regression (a later stage observed before an earlier) →
`StageOutOfOrder`.

---

## 10. Native streaming (C9)

### 10.1 Over N-PAMP

A native stream runs on the N-PAMP Stream channel `0x000C`, reusing NPAMP-STREAM's
sub-streams, absolute-offset two-level flow control, half-close, and reset (R-10.1).
N-AALP does not reinvent stream framing; the transport already authenticates every
chunk to the peer with AEAD.

### 10.2 The three stream objects

- **StreamOpen** (signed): establishes the stream's identity, its `effect`, and — where
  it causes an effect — its approval binding (R-10.3). Carries the sub-stream id it
  will use.
- chunks: raw NPAMP-STREAM `STREAM_DATA` frames; **not** individually signed — the AEAD
  authenticates each chunk to the peer, and per-chunk ML-DSA signatures (≈3.3–4.6 KB
  each) would be ruinous and are unnecessary (R-10.2).
- **StreamCommit** (signed): at end-of-stream, carries the digest of the complete
  ordered stream — a rolling SHA-384 over the chunks in absolute-offset order — making
  the stream content non-repudiable and auditable with one signature, not N (R-10.2).
  For a long stream, optional signed **StreamCheckpoint** objects
  `{ stream_id, through_offset, digest_so_far }` let a verifier confirm a prefix
  without waiting for the end.

### 10.3 Over a non-N-PAMP transport

The same three objects map onto the transport's native streaming (QUIC streams,
WebSocket messages, HTTP chunked/event streams); the StreamCommit digest verifies
identically regardless of transport (R-10.4). Full-duplex is inherent: both peers open
and drive streams concurrently on independent sub-streams (R-10.5).

### 10.4 Separation from foreign streamed carriage

Native streaming (`0x000C`, this section) is distinct from foreign streamed-reply
carriage (§13, Bridge `0x000D`, NPAMP-CC-STREAM). N-AALP never carries a foreign
protocol on `0x000C` nor moves a native stream onto the Bridge (R-10.6).

### 10.5 Failure modes

chunk beyond granted flow-control credit → transport rejects (NPAMP-STREAM
`FlowControlError`); StreamCommit digest ≠ recomputed → `StreamDigestMismatch`;
effect not authorized at StreamOpen → stream refused before any chunk.

---

(Transports §12, foreign carriage §13, conformance §14, and the full traceability
matrix follow in the second half of this document.)

---

## 12. Transport bindings (C11)

### 12.1 The binding contract

A transport binding carries exactly one signed object as one message unit, with
identical object semantics across all four transports (R-13.1). The object is
self-secured (§2–§8); the binding adds only framing and, from the transport,
confidentiality and connection authentication (R-13.2, R-13.3). The N-AALP media type
is `application/naalp+cbor` (one object per representation), registered in the IANA plan.

### 12.2 The four bindings

| transport | one object = | confidentiality | connection auth | notes |
|---|---|---|---|---|
| N-PAMP | one frame body on the object's semantic channel `0x0000`–`0x0013`; carriage rides Bridge `0x000D` (§13) | PQ AEAD (all tiers) | PQ handshake (Sovereign) / PeerHandle | reference combination |
| QUIC | one object per QUIC stream (or datagram for small objects) | TLS 1.3 | TLS cert / raw public key | native full-duplex streams for §10 |
| WebSocket | one object per binary message | TLS (wss) | out of band | duplex message stream for §10 |
| HTTP | one object per request/response body, `application/naalp+cbor` | TLS (https) | out of band | streaming via chunked / event-stream for §10 |

### 12.3 The confidentiality boundary (normative)

The design states, per guarantee, which are object-level (always present: integrity,
identity, non-repudiation, effect, audit) and which are transport-provided
(conditional: confidentiality, forward secrecy, connection authentication), and names
N-PAMP as the reference confidential transport (R-13.3). An object whose payload is
marked sensitive MUST NOT be emitted in cleartext over a non-confidential transport;
the binding refuses it and directs the deployment to a confidential transport (R-13.4).
This is the enforced boundary that turns "N-AALP over plain HTTP leaks" from a footgun
into a refusal, and it is a pull toward N-PAMP for the sensitive cases.

### 12.4 Failure modes

sensitive object over cleartext transport → `ConfidentialTransportRequired` (refuse to
emit); transport auth absent where policy requires it → `PeerUnauthenticated`.

---

## 13. Foreign carriage by class (C12)

### 13.1 The principle (carriage by class, not by protocol — R-14.1)

N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a
signed N-AALP **carriage object** whose effect, safety, identity, and audit apply, and
whose foreign body is interpreted by a **carriage class**, not by a bespoke
per-protocol mapping. There are five structured classes plus a universal opaque class,
mirroring N-PAMP exactly so the two compose:

| class | carries | over N-PAMP reuses |
|---|---|---|
| JSONRPC | any JSON-RPC 2.0 protocol (MCP, A2A core) | NPAMP-CC-JSONRPC |
| HTTP | any HTTP-semantics protocol | NPAMP-CC-HTTP |
| MSG | any message-passing / performative protocol (FIPA-ACL family) | NPAMP-CC-MSG |
| STREAM | any event/streaming foreign reply | NPAMP-CC-STREAM |
| DOC | capability/schema documents (agent cards, tool catalogs) | NPAMP-CC-DOC |
| OPAQUE | any declared-content-type payload, incl. undefined protocols | NPAMP-CC-OPAQUE |

Adding a protocol is a registry entry plus an optional thin mapping, never a new
framework. The OPAQUE class makes any protocol — including one nobody has defined —
carriable immediately (R-14.1, R-18.6). This is the ease-of-adoption move.

### 13.2 The carriage object

```cddl
naalp-carriage-body = {
  1 : uint,        ; protocol_id — N-AALP registry (§13.4)
  2 : uint,        ; class       — 0 JSONRPC,1 HTTP,2 MSG,3 STREAM,4 DOC,5 OPAQUE
  3 : uint,        ; content_type— foreign encoding
  4 : bstr,        ; correlation — exchange correlation token
  5 : tstr,        ; method      — advisory routing key (foreign op name)
  6 : bstr,        ; foreign     — the foreign message, carried octet-for-octet
}
```

The carriage object is a normal N-AALP object (envelope §2): signed, effect-labeled,
identity-bound, audited (R-14.2). The `foreign` field is carried verbatim and MUST NOT
be re-serialized, canonicalized, summarized, or rewritten (R-14.4). N-AALP metadata is
carried around it, never inside it.

### 13.3 Composition with the N-PAMP Bridge (R-14.3)

When N-AALP runs over N-PAMP, the innermost raw `foreign` octets ride inside an N-PAMP
Bridge frame of the matching carriage class, byte-exact, reusing Bridge's octet-exact
carriage and correlation; N-AALP does not duplicate the raw byte transport Bridge
already provides. The N-AALP carriage object supplies the signed, governed, audited
wrapper that Bridge's SafetyLabel deliberately does not (Bridge "describes intent and
does not replace authorization"; N-AALP's effect authorizes, §6.3). Over a non-N-PAMP
transport, the same carriage object carries the same `foreign` octets directly, so the
governance is present everywhere, not only on N-PAMP.

### 13.4 The registry (R-14.5)

The N-AALP protocol registry partitions a one-octet `protocol_id`: standards `0x01`–
`0x0F` (Specification Required), experimental `0x10`–`0x7F` (no registration), private
`0x80`–`0xFF`. Assigned to match N-PAMP: MCP `0x01` (JSONRPC), A2A `0x02` (JSONRPC +
DOC for the AgentCard), HTTP `0x03` (HTTP), WebSocket `0x04` (STREAM). A developer
interoperates immediately on an experimental id with no registration (R-14.5, R-18.6).
The registry is machine-readable CSV, the source the prose is generated from (R-18.3).

### 13.5 Identity containment (R-14.6)

A foreign protocol's identity, header, or metadata MUST NOT become an N-AALP
authorization identity; the N-AALP carriage object's signer remains the authority. A
carried MCP request "from" some foreign principal is authorized by the N-AALP signer
who wrapped it, not by the foreign principal.

### 13.6 Round-trip and errors (R-14.7, R-14.8)

Each carriage class has octet-exactness vectors proving a carried-and-recovered foreign
message is byte-identical (R-14.7). A below-foreign failure uses a defined structured
error and never reports an undelivered message as delivered. An N-AALP semantic that a
foreign protocol cannot represent surfaces a typed mapping error, never a silent drop
(R-14.8).

---

## 14. Conformance, oracles, and two-implementation parity (C14)

### 14.1 Non-circular corpus

Every graded construction's expected values come from an independent authority — an RFC
or FIPS test vector, or a from-scratch byte constructor written independently of the
code under test — never from the implementation being graded (R-16.1). The oracle for
each construction is a standalone generator (the pattern N-PAMP uses: a Python
constructor cross-validated against the implementation).

### 14.2 Independent oracles by construction

| construction | independent authority |
|---|---|
| deterministic CBOR | RFC 8949 §4.2.1, an independent CBOR constructor |
| COSE_Sign1 Sig_structure | RFC 9052 §4.4, independent byte assembly |
| ML-DSA-65/87 sign/verify | FIPS 204 known-answer vectors |
| Ed25519 (hybrid leg) | RFC 8032 vectors |
| content id / stream digest | FIPS 180 SHA-384 vectors |
| PeerHandle-form signer id | multiformats + the N-PAMP PeerHandle vectors |
| carriage octet-exactness | the foreign protocol's own spec + round-trip identity |

### 14.3 Two-implementation byte parity

Every construction carrying a security or interoperability claim is demonstrated by two
independent implementations from different codebases producing byte-identical output
(R-16.2). Recommendation: **Go + Rust**, for maximum runtime and memory-model
independence in the parity proof; alternate Go + TypeScript to match N-PAMP's reference
pair. Beyond the parity pair, adoption (R-18.1) provides quickstart SDKs across more
languages.

### 14.4 Honest status and the completion gate

Each draft carries an RFC 7942 Implementation Status section that never labels a planned
feature working and never claims grading beyond what an independent oracle verified
(R-16.3). A feature is not "complete" until its negative tests, its failure-recovery
behavior, and an end-to-end demonstration all pass (R-16.4). A blocked construction is
built and graded under a provisional marker with a named blocker in the ledger, never
left as a stub and never labeled beyond its evidence.

---

## 15. Failure-mode index

Every component's failure modes are listed in its section (§2.6, §4.5, §5.5, §7.4, §8.6,
§9.4, §10.5, §12.4) and in each channel surface in `design-channels.md`. The invariant
across all of them: an object that fails any check is rejected whole, produces its named
error, and causes no state change (fail-closed). There is no partial application and no
fail-open path anywhere in the spine.

---

## 16. Traceability (design element ↔ requirement)

Forward — every requirement reaches a design element:

| req group | design |
|---|---|
| R-0 scope/naming | §1, §13.5, IANA plan |
| R-1 substrate | §1.2, §5.1, §13.3 |
| R-2 envelope | §2 |
| R-3 encoding/CDDL | §3 |
| R-4 crypto/profiles | §4 |
| R-5 identity | §5 |
| R-6 effects/safety | §6 |
| R-7 approval | §7 |
| R-8 audit/ordering | §8 |
| R-9 delivery | §9 |
| R-10 streaming | §10 |
| R-11 channels | `design-channels.md` |
| R-12 magnify/compound | §2.3, §6.3, §7, §8.2 |
| R-13 transports | §12 |
| R-14 carriage | §13 |
| R-15 profiles/editions | §4.4, §1.3 |
| R-15A channel tiers | `design-channels.md` §0, §8.4 |
| R-16 conformance | §14 |
| R-18 adoption | §13.1, §13.4, §14.3, docs/harness in Phase 3 |

Backward — every design element traces to a requirement: the component inventory (§1.3)
carries the requirement ids for each component; no component exists without one. Both
gap lists are empty at Phase 2 for the spine; `design-channels.md` closes the channel
rows.

---

## 17. What this design does NOT decide (deferred to build, not hidden)

- The exact per-channel body CDDL for higher tiers beyond baseline — the baseline body
  of every channel is fixed (`design-channels.md`); higher-tier bodies are fixed as
  each tier is built, under the frozen envelope, per R-2.5.
- The federation reconciliation algorithm's full pseudocode — the interface and the
  causal-graph substrate are fixed here (§8.4); the algorithm is specified at the
  Federation federated tier before that tier is built.
- The concrete two-implementation language pair (Go+Rust recommended) — confirmed at
  Phase 3 entry.

None of these is a spine gap; each is a bounded, named, higher-tier-or-build item under
a frozen envelope, effect model, identity model, and audit model.
