<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Audit (`0x000B`)

The receipt chain and the auditor. The mechanism — the signed hash-chained receipt, the
offline-checkable causal graph, and the equivocation auditor — lives in the spine (the draft's
Audit, Causal Graph, and Ordering section); this surface is the access to it (the draft's Channel
Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Receipt` | `non_idempotent_write` | one signed append to an ordering authority's chain |
| 1 | `AuditQuery` | `read_only` | |
| 2 | `ForkProof` | `read_only` | a signed proof of equivocation an auditor emits |
| 3 | `CheckpointRoot` | `non_idempotent_write` | a log operator's signed Merkle tree head (§ below) |
| 4 | `WitnessCosign` | `non_idempotent_write` | an independent countersignature over one checkpoint (§ below) |
| 5 | `InclusionProof` | `read_only` | proves one record was a leaf under a named checkpoint (§ below) |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Audit](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L80-L81)),
cross-checked against an independent per-channel oracle.

## The receipt chain

An ordering authority records each accepted object by appending a signed `Receipt {prev, obj, seq,
at}`: the chain is tamper-evident because reordering, omission, or substitution breaks a `prev`
link or a `seq`. The authority never mutates the origin object to order it — ordering is an outer
signed layer, and the object's own signature stays valid:

```go
// impl/go/audit/audit.go
type Receipt struct {
	Prev []byte // hash of the previous receipt body (48 bytes SHA-384; genesis is zero)
	Obj  []byte // content id of the accepted object (never the object itself)
	Seq  uint64 // monotonic sequence position within this authority's chain
	At   uint64 // the authority's time anchor, epoch ms (independent of the signer's clock)
}
```

([`audit.go:41-46`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/audit/audit.go#L41-L46)).
The causal graph is the authority-independent foundation underneath the chain: an edge "A causes
B" is proven by B's signature over A's content id and is checkable offline; a cause an effect could
not have seen — a later position, or a cycle — is rejected `CausalViolation`. An auditor detects
equivocation, two receipts by one authority at one `seq` naming different objects, from the signed
receipts alone.

## Merkle-batched checkpoints: `CheckpointRoot`, `WitnessCosign`, `InclusionProof`

Tree construction follows [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) §2.1 exactly,
SHA-384-profiled: leaf hash = `HASH(0x00 || leaf)`; interior node hash =
`HASH(0x01 || left || right)`; the inclusion-path recursion generates a leaf-to-root audit path,
and the inverse recursion recomputes the root from `(leaf, index, size, path)` and compares against
the named root, rejecting `InclusionProofInvalid` on any mismatch, fail-closed
([`gateway/checkpoint.go`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/gateway/checkpoint.go)
— Audit's Merkle-batching kinds are implemented in the `gateway` package alongside `GatewayDecision`,
since both are governed-decision evidence primitives that share the same signed-bytes-are-authority
property).

- **`CheckpointRoot`** — a log operator's signed Merkle tree head over a leaf set of record content
  ids, chaining by `prev` exactly as the baseline receipt chain does.
- **`WitnessCosign`** — the wire hook for an independent countersignature over one exact checkpoint
  by content id. Two witness-cosigned roots at one `(log, size)` carrying different root values are
  fork evidence — the log has signed two incompatible histories.
- **`InclusionProof`** — proves one record's content id was a leaf under a named checkpoint,
  verifiable without trusting the log operator further than the checkpoint's own signature.

This closes the gap the design's baseline text left as a named tier-1 escalation ("Merkle-batched
signed roots for cheap inclusion proofs at scale") — the current implementation registers it as a
baseline kind rather than deferring it.

## Failure modes

| Error kind | When |
|---|---|
| `ChainBroken` | a receipt's `prev`/`seq` does not chain to the previous receipt |
| `Equivocation` | two receipts at one `seq` name different objects |
| `ReceiptUnsigned` | a receipt's signature does not verify |
| `CausalViolation` | the causal graph has a cycle or a future cause |
| `ForkProofInvalid` | a fork proof does not actually prove equivocation |
| `CheckpointMalformed` | a checkpoint-root or witness-cosign body is not well-formed |
| `InclusionProofInvalid` | a recomputed Merkle root does not match the named checkpoint root |

Every check is fail-closed (the draft's Security Considerations section): a failing object is
rejected whole, returns its named error, and causes no state change — no ledger append, no
checkpoint update.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [Governance channel](governance.md) for the `DecisionRecord` that binds to a witnessed
checkpoint root, and the [Federation channel](federation.md) for the higher-tier reconcile that
merges multiple authorities' chains over this same causal graph.
