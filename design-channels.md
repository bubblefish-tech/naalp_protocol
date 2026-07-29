# N-AALP — Design: the twenty channel surfaces

**Protocol:** draft-bubblefish-naalp-00
**Companion:** `design.md` (the spine every surface below inherits unchanged)
**Status:** Phase 2 deliverable. Requires Shawn's approval before Phase 3 build.

Every channel surface here is a thin body over the one spine of `design.md`: the same
signed envelope (§2), encoding (§3), crypto (§4), identity (§5), effect vocabulary (§6),
approval (§7), audit (§8), and delivery (§9). A surface adds only `kind` codes and their
bodies; it introduces no channel-local encoding, signature, or identity (R-11.3). Each
surface below lists its baseline object kinds, each kind's effect, its state and error
notes, and what its higher tiers add. Per-object performance bound, unless noted, is
one signature verify plus one deterministic-CBOR decode (the spine cost); channels with
a heavier bound say so.

---

## 0. The channel-tier model (R-15A)

Channels are tiered exactly as the crypto profiles are (one definition, a per-tier row,
editions license the tier):

- **Baseline tier (tier 0), frozen for all twenty channels in draft-00.** Every channel
  has a complete baseline surface — object kinds, effects, state, errors — that no
  edition may omit. This is what R-11.1 and R-11.4 require: full coverage, nothing
  thinned.
- **Higher tiers (tier 1+),** named escalations that add capability under the frozen
  baseline envelope, effect vocabulary, identity model, and audit chain (R-15A.2). A
  baseline verifier accepts a higher-tier object's spine and ignores unknown higher-tier
  non-critical extensions (spine §2.5); a higher-tier capability it must honor is a
  critical extension it will reject if it cannot (fail-closed).
- **Editions license tiers,** the same axis as crypto profiles and orthogonal to them:
  an open edition may ship baseline surfaces only; enterprise and government editions
  license deeper tiers. One codebase (R-15.4).

`tier` is envelope field 4; `tier = 0` is baseline. The channel field (envelope field 3)
is the N-PAMP channel id.

---

## 1. Control — `0x0000`

**Purpose:** session and object-flow control at the application layer (distinct from the
N-PAMP transport handshake, which is below N-AALP).

**Baseline kinds:** `Hello` (read_only) — advertise the object kinds, channels, carriage
classes, tiers, and profile an endpoint supports, as a signed selector; `Bye`
(idempotent_write) — orderly close of an application session; `Ack` (read_only) — a
signed acknowledgment used by delivery (spine §9); `Error` (read_only) — the signed
error object every failure mode returns.
**State:** a session is `open` after a mutual `Hello`, `closing` after `Bye`.
**Errors:** `UnknownKind`, `ProfileMismatch` on a `Hello` whose profile the peer refuses.
**Tier 1+:** capability GREASE and negotiation extensions; session resumption.

## 2. Memory — `0x0001`

**Purpose:** durable shared memory operations (composes with N-PAMP's native
NPAMP-MEMORY frames when over N-PAMP).

**Baseline kinds:** `MemoryOffer` (idempotent_write), `MemoryAccept` (idempotent_write),
`MemoryWrite` (non_idempotent_write), `MemoryRead` (read_only), `MemoryExpire`
(destructive), `MemoryRevoke` (destructive).
**State:** an entry is `offered → accepted → live → (expired | revoked)`.
**Errors:** `AccessDenied` (a read of a revoked or unexpired-but-quarantined entry is
denied fail-closed), `MemoryError` preserving a governance-hold as a distinct result.
**Bounds:** a write persists before its ack (spine §9.2).
**Tier 1+:** content-addressed dedup across sessions; memory derivation via `causes`.

## 3. Capability — `0x0002`

**Purpose:** capability tokens — issuance, delegation, revocation, lookup (composes with
NPAMP-CAPABILITY).

**Baseline kinds:** `CapIssue` (non_idempotent_write), `CapDelegate` (non_idempotent_write),
`CapRevoke` (destructive), `CapLookup` (read_only).
**State:** a capability is `issued → (delegated…)* → (revoked | expired)`; delegation
forms a `causes` chain so a delegated capability names its parent by content id.
**Errors:** `CapExceedsParent` (a delegation may not grant more than its parent —
checked against the parent named in `causes`), `CapRevoked`.
**Tier 1+:** attenuation predicates; threshold/multi-party capabilities.

## 4. Identity — `0x0003`

**Purpose:** the durable identity layer (spine §5): rotation, revocation, foreign-identity
linkage.

**Baseline kinds:** `Rotation` (non_idempotent_write, co-signed old+new key, spine §5.2),
`Revocation` (destructive, spine §5.3), `ForeignLink` (idempotent_write, spine §5.4),
`KeyAnnounce` (read_only) — publish an RFC 7250 SPKI for a signer id.
**State:** an identity thread is a `causes`-linked chain of `Rotation`s ending at most in
one `Revocation`.
**Errors:** `RotationUnauthorized`, `KeyRevoked`, `SignerMismatch`.
**Tier 1+:** recovery-key quorum; cross-signed organizational identity roots.

## 5. Governance — `0x0004`

**Purpose:** policy and the approval workflow (spine §6–§7 are the mechanism; this
surface is the workflow).

**Baseline kinds:** `PolicyPublish` (non_idempotent_write) — a signed policy naming, per
effect class and capability, what is authorized; `Approval` (non_idempotent_write, spine
§7.1); `ApprovalHeld` (read_only, spine §7.4); `Consume` (non_idempotent_write, the
single-use ledger append, spine §7.2).
**State:** an approvable action is `requested → (held | approved) → consumed | expired`.
**Errors:** `ApprovalRequired`, `ApprovalMismatch`, `AlreadyConsumed`, `EffectNotAuthorized`.
**Tier 1+:** multi-approver quorum; time-boxed standing grants; policy inheritance.

## 6. Immune — `0x0005`

**Purpose:** anomaly reporting and defensive coordination (composes with NPAMP-IMMUNE
gossip).

**Baseline kinds:** `AnomalyReport` (read_only), `Quarantine` (destructive) — mark a
signer or object class untrusted, fail-closed on the quarantined set; `QuarantineLift`
(non_idempotent_write).
**State:** a subject is `normal → quarantined → (lifted | permanent)`.
**Errors:** access to a quarantined subject is denied fail-closed (a future-dated revoke
of a share is denied, not fail-open).
**Bounds:** report emission is rate-limited; the surface names the limit as policy.
**Tier 1+:** signed anti-entropy gossip with hop-bound convergence (the NPAMP-IMMUNE
propagation model) at the federated tier.

## 7. Federation — `0x0006`

**Purpose:** cross-authority operation. **Baseline** is frozen; **deep federation is a
named higher tier**, not a deferral (R-15A.3).

**Baseline kinds (tier 0):** `AuthorityAnnounce` (read_only) — a signed statement of an
ordering authority's identity and scope; `ScopeReceipt` (non_idempotent_write) — an
authority's signed receipt over its own scope (spine §8.1, single-authority form).
**Higher tier (tier 1, federated ordering):** `Reconcile` (non_idempotent_write) — the
deterministic merge of multiple authorities' receipt chains over the shared causal
graph (spine §8.4). The reconciliation algorithm is specified with this tier; it needs
no envelope change because it orders the identical signed objects the baseline already
produces.
**Errors:** `AuthorityUnknown`, `ScopeOverlapConflict` (resolved at tier 1 by the
causal-graph merge; at baseline, an overlap is an operator error).

## 8. Settlement — `0x0007`

**Purpose:** agent-to-agent settlement (public half; composes with NPAMP-SETTLEMENT).

**Baseline kinds:** `SettleIntent` (non_idempotent_write, carries a `value_commitment`
body field, spine §6.1), `SettleReceipt` (non_idempotent_write), `SettleReject`
(idempotent_write).
**State:** `intent → (receipt | reject)`; a receipt names its intent by content id.
**Errors:** `ValueMismatch`, `SettleExpired`. Settlement never invents a fifth effect;
it uses `non_idempotent_write` plus the signed `value_commitment` (spine §6.1).
**Tier 1+:** batch commitment; multi-party settlement.

## 9. Compliance — `0x0008`

**Purpose:** compliance evidence and multi-regulator reporting.

**Baseline kinds:** `ComplianceRecord` (non_idempotent_write) — a signed, audit-chained
evidence record; `ComplianceQuery` (read_only); `ComplianceReport` (read_only) — a signed
report bound to a jurisdiction.
**State:** records are append-only into the audit chain (spine §8).
**Errors:** `RecordUnsigned`, `JurisdictionUnknown`.
**Tier 1+:** regulator-specific report schemas as critical extensions; retention/legal-hold
markers.

## 10. Sensory — `0x0009`

**Purpose:** bulk telemetry / typed observations (composes with NPAMP-SENSORY; low
priority). Minimum profile note: N-PAMP registers this channel at min profile High.

**Baseline kinds:** `Observation` (read_only, batched), `Subscribe` (idempotent_write),
`Unsubscribe` (idempotent_write).
**State:** a subscription is `active → cancelled`; consumer-driven credit backpressure.
**Errors:** `SubscriptionUnknown`, credit-exceeded handled by backpressure not error.
**Bounds:** batched; per-batch signature amortizes the spine cost over many observations.
**Tier 1+:** signed observation provenance chains via `causes`.

## 11. Telemetry — `0x000A`

**Purpose:** operational metrics about the agent system itself (distinct from Sensory's
world-observations).

**Baseline kinds:** `Metric` (read_only, batched), `HealthReport` (read_only).
**State:** stateless emit; consumers aggregate.
**Errors:** `MetricMalformed`.
**Tier 1+:** signed SLA attestations.

## 12. Audit — `0x000B`

**Purpose:** the receipt chain and auditor (spine §8 is the mechanism; this surface is
the access to it).

**Baseline kinds:** `Receipt` (non_idempotent_write, spine §8.1), `AuditQuery` (read_only),
`ForkProof` (read_only) — a signed proof of equivocation an auditor emits (spine §8.5).
**State:** the chain is append-only; a `ForkProof` names the two conflicting receipts by
content id.
**Errors:** `ChainBroken`, `Equivocation`, `ReceiptUnsigned`.
**Bounds:** receipt append persists before ack (spine §9.2).
**Tier 1+:** Merkle-batched signed roots for cheap inclusion proofs at scale.

## 13. Stream — `0x000C`

**Purpose:** native full-duplex streaming. **Fully specified in `design.md` §10.**

**Baseline kinds:** `StreamOpen` (effect per the stream's action), `StreamCommit`
(read_only over the completed digest), `StreamCheckpoint` (read_only). Chunks are raw
NPAMP-STREAM frames, not N-AALP objects, and are AEAD-authenticated by the transport
(spine §10.2).
**Errors:** `StreamDigestMismatch`, `FlowControlError` (from the transport).
**Tier 1+:** signed checkpoint cadence policy; cross-transport stream continuation.

## 14. Bridge — `0x000D`

**Purpose:** foreign-protocol carriage by class. **Fully specified in `design.md` §13.**

**Baseline kinds:** the `naalp-carriage-body` object (spine §13.2) in its six classes
(JSONRPC, HTTP, MSG, STREAM, DOC, OPAQUE). Effect is the carried operation's effect;
absence on a state-mutating carried request is `destructive` (spine §6.2).
**Errors:** `EnvelopeMalformed`, `ProtocolUnsupported`, `MethodUnsupported`,
`NotDelivered`, `EffectNotAuthorized`.
**Tier 1+:** thin per-protocol mappings beyond the assigned four, added as registry
entries.

## 15. Commerce — `0x000E`

**Purpose:** commercial transactions above settlement (offers, orders, fulfilment).

**Baseline kinds:** `Offer` (read_only), `Order` (non_idempotent_write, `value_commitment`
+ an approval binding, spine §7), `Fulfil` (non_idempotent_write), `Cancel` (destructive).
**State:** `offer → order → (fulfil | cancel)`; each names its predecessor by content id.
**Errors:** `OfferExpired`, `ApprovalRequired`, `OrderMismatch`.
**Tier 1+:** escrow and multi-leg orders via the derivation graph.

## 16. Interaction — `0x000F`

**Purpose:** human-in-the-loop and agent-to-user interaction (elicitation, confirmation).

**Baseline kinds:** `Elicit` (read_only) — request input; `Respond` (idempotent_write);
`Confirm` (non_idempotent_write) — a human confirmation that can serve as an `Approval`
approver (spine §7).
**State:** `elicit → (respond | confirm | timeout)`.
**Errors:** `InteractionTimeout`, `ElicitUnauthorized`.
**Tier 1+:** signed consent records with retention.

## 17. Discovery — `0x0010`

**Purpose:** which protocols, carriage classes, tools, and agents a peer offers
(composes with NPAMP-DISC / NPAMP-DISC-SIGNED).

**Baseline kinds:** `DiscoveryRecord` (read_only, individually signed, offline-verifiable
against a deployer trust anchor, with `not_after` freshness), `DiscoveryQuery`
(read_only).
**State:** records are self-contained and freshness-bounded; a stale record is ignored.
**Errors:** `RecordExpired`, `TrustAnchorUnknown`.
**Tier 1+:** signed capability catalogs carried as DOC-class objects.

## 18. Workflow — `0x0011`

**Purpose:** task and workflow orchestration across agents.

**Baseline kinds:** `TaskCreate` (non_idempotent_write, seq-keyed non-terminal status so a
crash cannot bypass the input/approval gate), `TaskInput` (non_idempotent_write),
`TaskCancel` (destructive), `TaskResult` (non_idempotent_write).
**State:** a task is `created → (awaiting-input | awaiting-approval) → running →
(result | cancelled)`; a crash recovers to the last durable status (spine §9).
**Errors:** `TaskStateError`, `InputGateBypass` (forbidden; a crash test proves it cannot
occur), `ApprovalRequired`.
**Tier 1+:** DAG workflows over the `causes` graph; compensation/rollback.

## 19. Knowledge — `0x0012`

**Purpose:** shared knowledge / enterprise-graph facts.

**Baseline kinds:** `Assert` (non_idempotent_write) — a signed fact; `Retract`
(destructive); `KnowledgeQuery` (read_only).
**State:** facts are append-only with signed retractions; a fact names its provenance via
`causes`.
**Errors:** `FactUnsigned`, `RetractUnknown`.
**Tier 1+:** signed inference chains (a derived fact names its premises by content id, so
a conclusion is auditable to its axioms).

## 20. Spatial — `0x0013`

**Purpose:** high-frequency physical-world state for robotics and IoT (composes with
NPAMP-SPATIAL; N-PAMP registers min profile High; frame conventions ROS REP-103/105).

**Baseline kinds:** `FrameDefine` (idempotent_write) — a coordinate frame; `Pose`
(read_only, batched), `StateUpdate` (read_only, batched), `SnapshotQuery` (read_only).
**State:** frames form a transform tree; poses are timestamped observations.
**Errors:** `FrameUnknown`, `TransformCycle`.
**Bounds:** high-frequency; batched and amortized like Sensory. For hard-real-time paths,
the surface notes that per-object signing is amortized per batch, and safety-critical
control loops run below N-AALP with N-AALP carrying the signed setpoints and audit.
**Tier 1+:** signed occupancy/mapping snapshots; multi-robot shared frames at the
federated tier.

---

## Traceability (channels)

R-11.1 (all twenty defined, none deferred): sections 1–20 above. R-11.2 (each surface
complete — kinds, effects, state, errors, bounds): each section carries all five.
R-11.3 (inherit the one spine): stated in the header and enforced by the envelope.
R-11.4 / R-15A (tiered, baseline frozen, depth as named tiers): §0 plus each section's
"Tier 1+" line; Federation (§7) is the worked case of a frozen baseline with deep
federation as a named higher tier. Backward: every kind above maps to exactly one
channel and one effect; no kind exists without a channel and an effect. Both gap lists
empty.
