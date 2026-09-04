<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# The error-code registry

Every fail-closed rejection in N-AALP names a reason: the reason a verify or decode path returns
when it refuses an object whole (a fail-closed refusal, never a partial acceptance). Those names
are carried between parties by the **`naalp-error` object** — a **Control/Error** object (channel
`0x0000`, [kind](../spec/channels.md) 3; effect `read_only`, because an error report itself effects
nothing) whose body is:

```
naalp-error = { 1: code (uint), 2: name (tstr), ?3: detail (tstr), ?4: subject (bstr) }
```

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `code` (1) | `uint` | required | the numeric error code |
| `name` (2) | `tstr` | required | the code's registered name |
| `detail` (3) | `tstr` | optional | a non-normative human diagnostic; carries no security meaning |
| `subject` (4) | `bstr` | optional | the content id of the object the error is about, so one error object can refer to a specific rejected object without embedding it |

## Semantics

**Scope.** The registry is the complete set of protocol errors the specification defines as
fail-closed rejection reasons **returnable by a verify or decode path on peer-supplied input** — the
spine (encoding, object, bounds, crypto, identity, effect, approval, audit, delivery, streaming,
transport, carriage) and every channel surface. It excludes purely local errors that never travel to
a peer (the encoder-side `Unencodable`, and the key-generation input errors `SeedSize` /
`KeyMalformed`). `Malformed` is the generic fallback reason.

**Code assignment.** Codes are assigned sequentially from 1, in a documented subsystem order — the
spine subsystems first, then the channel surfaces in build order. Code `0` is reserved and MUST NOT
appear on the wire. The standards range is `1`–`0x7FFF` (registration policy RFC Required / First
Come First Served); `0x8000` and above is private-use, with no registration required. The order —
not any per-error choice — is the named source for every code, which is what makes the scheme
reproducible.

**Dual-carriage rules.** The `{code, name}` pair carries the same fact twice, so the grammar pins
which field wins:

- If a receiver recognizes `code`, it MUST require `name` to equal the registered name for that
  code; a code/name disagreement is rejected `Malformed`. The numeric code is authoritative — the
  name may never contradict it.
- A `code` outside the receiver's registry snapshot MUST NOT be treated as fatal. The registry is
  open (RFC Required lets it grow), so an unknown code is opaque: `name` is diagnostic only, no
  semantics are inferred, and the receiver stays interoperable with a peer emitting a
  later-registered code. This is why `code` is a bare `uint` in the CDDL, not the closed
  `naalp-error-code` enum — a future or private code still validates.

**Retryable.** `Retryable` is `yes` only when an unmodified retry of the *same* object can later
succeed because of a transient or environmental change, with no change to the object or the
receiver's configuration. Every deterministic verification or decode failure is therefore
non-retryable — retrying identical bytes fails identically, the fail-closed default. The only
registered transient is `NotDelivered`: a carriage delivery that did not complete may complete on a
later attempt.

## Registry

119 codes, in the order the CSV assigns them. Each subsystem occupies one contiguous block of
codes, per the code-assignment order above.

### Subsystems at a glance

| Subsystem | Codes | Count |
|---|---|---|
| encoding | 1-2 | 2 |
| object | 3-11 | 9 |
| bounds | 12-15 | 4 |
| crypto | 16-22 | 7 |
| identity | 23-25 | 3 |
| effect | 26-28 | 3 |
| approval | 29-39 | 11 |
| refusal | 40-41 | 2 |
| audit | 42-46 | 5 |
| delivery | 47 | 1 |
| streaming | 48-49 | 2 |
| transport | 50-51 | 2 |
| carriage | 52-53 | 2 |
| channels | 54-59 | 6 |
| federation | 60-61 | 2 |
| continuation | 62-67 | 6 |
| delegation | 68-73 | 6 |
| naming | 74-79 | 6 |
| description | 80-85 | 6 |
| negotiation | 86-94 | 9 |
| mcp | 95-98 | 4 |
| payment | 99-100 | 2 |
| gateway | 101-102 | 2 |
| agui | 103-107 | 5 |
| rooms | 108-119 | 12 |

### All codes

| Code | Name | Retryable | Subsystem | Description |
|---|---|---|---|---|
| 1 | `NonCanonical` | no | encoding | object or header is not the deterministic RFC 8949 §4.2.1 encoding (non-minimal, indefinite-length, unsorted or duplicate keys, a float, or the 0x41A0 empty header) |
| 2 | `DepthExceeded` | no | encoding | CBOR nesting depth exceeds the maximum (§3.4) |
| 3 | `Malformed` | no | object | structurally malformed object or COSE structure (the generic fallback rejection) |
| 4 | `ContentIdMismatch` | no | object | the recomputed content id does not equal the carried content id (§2.3) |
| 5 | `HeaderBodyMismatch` | no | object | a protected-header routing copy disagrees with the signed body (§2.6) |
| 6 | `UnsupportedVersion` | no | object | the protected-header naalp-version is not supported (§2.5.3) |
| 7 | `UnknownCriticalExt` | no | object | a critical-extension (cext) key is not understood (§2.5) |
| 8 | `UnknownKind` | no | object | the channel/kind code is not a registered surface (§3.2) |
| 9 | `RangeError` | no | object | a field value is outside its permitted range |
| 10 | `NonNFC` | no | object | a text field is not in Unicode Normalization Form C (§3.1) |
| 11 | `WrongAudience` | no | object | the signed audience is not the verifying party (§2.5.3, R1) |
| 12 | `TooLarge` | no | bounds | the object exceeds the maximum octet size (§3.4) |
| 13 | `TooManyCauses` | no | bounds | causes[] exceeds the maximum count (§3.4) |
| 14 | `TooManyExtensions` | no | bounds | the ext or cext map exceeds the maximum cardinality (§3.4) |
| 15 | `TooManyChunks` | no | bounds | a stream presents more chunks than the maximum (§3.4, §10) |
| 16 | `UnknownAlg` | no | crypto | the algorithm id is not in the N-AALP signature registry (§4) |
| 17 | `KeyAlgMismatch` | no | crypto | the key algorithm does not match the object header (§4.5) |
| 18 | `ProfileDowngrade` | no | crypto | the signature level is below the profile minimum (§4.5) |
| 19 | `HybridIncomplete` | no | crypto | a hybrid/composite object has a component signature that does not verify (§4.5) |
| 20 | `SuiteMismatch` | no | crypto | the signed suite declaration disagrees with the signature alg or structure (§4.5) |
| 21 | `CompositeRefused` | no | crypto | a Sovereign verifier refuses a composite (non-pure) object (§4.5) |
| 22 | `BadSignature` | no | crypto | signature verification failed (§4) |
| 23 | `SignerMismatch` | no | identity | the recomputed signer id does not equal the key, or a revocation signer is neither the key nor a configured recovery key (§5.1, §5.3, §5.5) |
| 24 | `RotationUnauthorized` | no | identity | a rotation object is not co-signed by both the old and new keys, or is presented as a single-signature object (§5.2) |
| 25 | `KeyRevoked` | no | identity | the signing key is revoked as of the object's authoritative receipt position (§5.3) |
| 26 | `EffectNotAuthorized` | no | effect | the declared effect is not authorized for the principal (§6) |
| 27 | `UnauthenticatedPrincipal` | no | effect | a self-asserted principal was not authenticated by the transport (§6.5, R1.3) |
| 28 | `MalformedSafetyLabel` | no | effect | the optional ext safety-label is structurally malformed (§6.4) |
| 29 | `ApprovalRequired` | no | approval | an effecting object requires an approval and none was presented (§7) |
| 30 | `ApprovalMismatch` | no | approval | the presented approval does not bind the object (§7) |
| 31 | `ApprovalExpired` | no | approval | the approval's validity window has passed (§7) |
| 32 | `AlreadyConsumed` | no | approval | a consume-once object was already consumed (§7) |
| 33 | `ConsumeFork` | no | approval | two consume receipts fork the single-consume ledger (§7) |
| 34 | `ConsumeForkInvalid` | no | approval | a presented consume-fork proof is not a valid fork (§7) |
| 35 | `ConsumeReceiptUnsigned` | no | approval | a consume receipt is not signed (§7) |
| 36 | `LedgerCorrupt` | no | approval | the consume ledger is structurally corrupt (§7) |
| 37 | `LedgerUnsigned` | no | approval | a consume-ledger record is not signed (§7) |
| 38 | `AudienceMismatch` | no | approval | a consume receipt's audience does not match the object (§7) |
| 39 | `FreshnessSelfAsserted` | no | approval | an approval's freshness is only self-asserted, not independently anchored (§7) |
| 40 | `UnknownRefusalOutcome` | no | refusal | a coarse-refusal object carries an unknown outcome value |
| 41 | `RefusalDetailLeak` | no | refusal | a coarse-refusal object discloses detail beyond the coarse vocabulary |
| 42 | `ChainBroken` | no | audit | an audit or hash-chain link does not verify (§8) |
| 43 | `Equivocation` | no | audit | two conflicting signed statements occupy one chain position (§8) |
| 44 | `CausalViolation` | no | audit | an object is applied before a declared cause (§8, §13) |
| 45 | `ReceiptUnsigned` | no | audit | an authoritative receipt is not signed (§8) |
| 46 | `ForkProofInvalid` | no | audit | an audit fork proof is not one signer over two conflicting objects (§8) |
| 47 | `StageOutOfOrder` | no | delivery | a delivery stage arrived out of its required order (§9) |
| 48 | `StreamDigestMismatch` | no | streaming | a stream commit digest does not equal the recomputed rolling digest (§10) |
| 49 | `StreamStateError` | no | streaming | a streaming event is illegal for the current stream state (§10 state table) |
| 50 | `ConfidentialTransportRequired` | no | transport | an object requiring a confidential transport was received without one (§12) |
| 51 | `PeerUnauthenticated` | no | transport | the transport peer is not authenticated (§12) |
| 52 | `NotDelivered` | yes | carriage | a carriage delivery did not complete; an unmodified retry may later succeed (§13) |
| 53 | `MappingError` | no | carriage | a foreign-carriage mapping could not be applied (§13) |
| 54 | `EffectDeclarationMismatch` | no | channels | a channel object's declared effect disagrees with its kind (§14) |
| 55 | `StateTransitionError` | no | channels | a channel state transition is not permitted (§14 state table) |
| 56 | `CapExceedsParent` | no | channels | a capability grant exceeds its parent's scope (§14) |
| 57 | `TransformCycle` | no | channels | a capability transform graph contains a cycle (§14) |
| 58 | `InputGateBypass` | no | channels | a workflow input gate was bypassed (§14) |
| 59 | `TaskStateError` | no | channels | a task state transition is not permitted (§14) |
| 60 | `ScopeOverlapConflict` | no | federation | two federated scopes overlap in conflict (§15) |
| 61 | `ReconcileMismatch` | no | federation | a federated reconcile verifier's independent recomputation disagrees with the presented linearization (§15) |
| 62 | `WrongFlow` | no | continuation | a continuation frame names the wrong flow |
| 63 | `SeqGap` | no | continuation | a continuation sequence has a gap |
| 64 | `AboveCeiling` | no | continuation | a continuation sequence exceeds its declared ceiling |
| 65 | `GapDetected` | no | continuation | a continuation commit detects a missing frame |
| 66 | `CommitMismatch` | no | continuation | a continuation commit digest does not match the frames |
| 67 | `ContMalformed` | no | continuation | a continuation frame is structurally malformed |
| 68 | `GrantExpired` | no | delegation | a delegation grant's validity window has passed |
| 69 | `GrantNotYetValid` | no | delegation | a delegation grant is not yet valid |
| 70 | `GrantRevoked` | no | delegation | a delegation grant is revoked |
| 71 | `UntrustedChainRoot` | no | delegation | a delegation chain does not root in a trusted grantor |
| 72 | `DelegationDepthExceeded` | no | delegation | the declared or realized delegation depth exceeds max_depth |
| 73 | `GrantMalformed` | no | delegation | a delegation grant object is structurally malformed |
| 74 | `NameMalformed` | no | naming | a naming object is structurally malformed |
| 75 | `NameChainBroken` | no | naming | a name-binding chain link does not verify |
| 76 | `NameForkProofInvalid` | no | naming | a name fork proof is not one signer over two conflicting bindings |
| 77 | `IllegalTransition` | no | naming | a naming state transition is not permitted |
| 78 | `TaskChainBroken` | no | naming | an A2A task chain link does not verify |
| 79 | `ForeignCard` | no | naming | a foreign agent-card reference is invalid |
| 80 | `DescMalformed` | no | description | a description object is structurally malformed |
| 81 | `MalformedApprovalFlag` | no | description | a description approval flag is malformed |
| 82 | `DirForkProofInvalid` | no | description | a directory fork proof is not one signer over two conflicting directory objects |
| 83 | `ImporterMismatch` | no | description | a description import's importer does not match |
| 84 | `UnknownDescriptionFormat` | no | description | a description carries an unregistered format code |
| 85 | `VerifierKeyMismatch` | no | description | a description import's verifier key does not match the declared alg/key |
| 86 | `NegMalformed` | no | negotiation | a negotiation object is structurally malformed |
| 87 | `UnknownRole` | no | negotiation | a negotiation role is unknown |
| 88 | `UnknownProfile` | no | negotiation | a negotiation profile is unknown |
| 89 | `NotDescended` | no | negotiation | a negotiation accept does not descend from the offer |
| 90 | `NotOffer` | no | negotiation | an object expected to be an offer is not one |
| 91 | `NotAccept` | no | negotiation | an object expected to be an accept is not one |
| 92 | `MalformedCriticalFlag` | no | negotiation | a negotiation critical flag is malformed |
| 93 | `UnknownCriticalRisk` | no | negotiation | a negotiation carries an unknown critical risk label |
| 94 | `ReferenceMismatch` | no | negotiation | a negotiation trust reference does not match |
| 95 | `MalformedAnnotation` | no | mcp | an MCP tool annotation is malformed |
| 96 | `EffectUnderDeclared` | no | mcp | an MCP annotation declares a lower effect than its mapping requires |
| 97 | `EffectOutsideLattice` | no | mcp | an MCP annotation maps to an effect outside the closed lattice |
| 98 | `ToolCallMalformed` | no | mcp | an MCP tool-call object is malformed |
| 99 | `PayMalformed` | no | payment | a payment object is structurally malformed |
| 100 | `UnknownPaymentFormat` | no | payment | a payment carries an unregistered format code |
| 101 | `GwMalformed` | no | gateway | a gateway object is structurally malformed |
| 102 | `UnknownGatewayDecision` | no | gateway | a gateway decision value is unknown |
| 103 | `UIMalformed` | no | agui | an AG-UI event object is malformed |
| 104 | `UIChainBroken` | no | agui | an AG-UI event chain link does not verify |
| 105 | `UnknownUIEventKind` | no | agui | an AG-UI event kind is unknown |
| 106 | `ActionSubstituted` | no | agui | an AG-UI action was substituted between render and confirm |
| 107 | `UINoConsent` | no | agui | an AG-UI effecting action lacks recorded user consent |
| 108 | `StaleEpoch` | no | rooms | a room operation names a stale membership epoch |
| 109 | `Unauthorized` | no | rooms | a room operation is not authorized for the principal |
| 110 | `OwnerImmutable` | no | rooms | a room owner cannot be changed by this operation |
| 111 | `MemberExists` | no | rooms | a room member add conflicts with an existing member |
| 112 | `MemberUnknown` | no | rooms | a room operation names an unknown member |
| 113 | `OwnerExists` | no | rooms | a room create conflicts with an existing owner |
| 114 | `RoleInvalid` | no | rooms | a room role value is invalid |
| 115 | `RoomOpMismatch` | no | rooms | a room operation kind does not match its payload |
| 116 | `OpUnknown` | no | rooms | a room operation kind is unknown |
| 117 | `PrincipalUnknown` | no | rooms | a room operation names an unknown principal |
| 118 | `PrincipalExists` | no | rooms | a room principal add conflicts with an existing principal |
| 119 | `RebindUnauthorized` | no | rooms | a room principal rebind is not authorized |

## Machine-readable authority

This page is a rendering of the CSV; if the two ever disagree, the CSV is authoritative.

- Registry (source of truth): `vectors/registry/error-codes.csv`
- CDDL enum (production `naalp-error-code`): `spec/naalp-draft-01.cddl`
