<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Discovery: signed descriptions, directories, and the Discovery channel

N-AALP does define a discovery mechanism, and it is deliberately **not** connection-based. Most
agent-discovery designs make a description's authority a property of who served it — the bytes
are trusted because of the authenticated session that carried them. N-AALP inverts that: every
N-AALP object is already self-certifying (its authority is the signature over its bytes,
independent of the connection that carried it, per the draft's Object Model section), and the discovery surfaces
below are exactly that property applied to "what does this peer offer." A signed description
verifies **offline** and re-verifies **byte-identically** no matter which host serves it — a
cache, a mirror, or an unrelated relay convey no additional authority, and none is lost either.

There are two layers, at two different depths, and they compose:

| Layer | What it answers | Where it lives |
|---|---|---|
| **Discovery channel** (`0x0010`, baseline tier) | Which protocols, carriage classes, tools, and agents a peer offers, as a lightweight signed record | the draft's Channel Surfaces section |
| **Signed description and directories** (C18, draft-01) | The full per-operation capability table of one service — its operations, each one's effect class, and whether it needs approval — plus signed collections and equivocation detection | the draft's Channel Surfaces section |

## The Discovery channel (baseline)

The baseline surface is deliberately thin — a channel adds only kind codes and effects over the
one spine (the draft's Object Model section):

| Kind | Effect | Notes |
|---|---|---|
| `DiscoveryRecord` | `read_only` | individually signed, offline-verifiable against a deployer trust anchor, carries a `not_after` freshness bound |
| `DiscoveryQuery` | `read_only` | a request for discovery records |

A record is self-contained and freshness-bounded; a stale record (past `not_after`) is ignored
rather than trusted. `RecordExpired` and `TrustAnchorUnknown` are the channel's named errors.
Higher tiers (`Tier 1+`) add signed capability catalogs carried as `DOC`-class Bridge objects
(the draft's Channel Surfaces section). This baseline layer composes with N-PAMP's own `NPAMP-DISC` /
`NPAMP-DISC-SIGNED` substrate discovery when N-AALP runs over N-PAMP — the channel is the
application-layer complement to a transport-level discovery record, not a replacement for it.

## Signed description and directories (the deeper mechanism)

The gap this closes: an agent needs to learn what a service offers — its operations, and at
what effect each one acts — **before** invoking it, and that knowledge needs to survive being
cached, mirrored, or relayed. The draft's Channel Surfaces section applies N-AALP's self-certifying-object
property to exactly that: a **Description**, a **Directory**, and a **description import** are
ordinary signed N-AALP objects. No new envelope, encoding, signature, identity, or audit
mechanism is introduced — this reuses the closed effect lattice (the draft's Effects and Authorization section) and the
T1 content-id framing (the draft's Object Model section) unchanged.

### The three wire objects

| Object | Body | Purpose |
|---|---|---|
| `naalp-description` | `{1: service (bstr), 2: [* operation]}` | a service's signed operation table; each `operation` is `{1: name, 2: effect, 3: requires_approval}` |
| `naalp-directory` | `{1: directory (bstr), 2: version (uint), 3: [* member-content-id]}` | a signed collection of content-ids, versioned so two versions can be compared for equivocation |
| `naalp-description-import` | `{1: importer (bstr), 2: format (uint), 3: foreign (bstr), 4: [* operation]}` | a foreign description format (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) carried octet-for-octet, attested by the importing signer |

`requires_approval` is the uint `1`/`0` — the N-AALP spine carries no CBOR boolean — and a value
outside `{0, 1}` is rejected `MalformedApprovalFlag`, never silently defaulted (the draft's Channel Surfaces section).

### Offline verifiability

`VerifyDescription` checks the object's full signature under the profile floor, then
reconstructs the entire operation table from the signed body bytes alone. Because authority is
the signature, not the host, the same signed bytes verify to the identical `Description`
whether fetched from the origin, replayed from a cache, or relayed by an unrelated peer. A
caller learns each operation's normalized effect class and its approval requirement with no
live fetch and no session state (the draft's Channel Surfaces section).

### Directories and fork detection

A Directory lists member content-ids under one signer and a monotonic `version`. `DetectFork`
compares two directory versions from the same signer and reports whether they **equivocate** —
same directory id and version, different members — and, when they do, the first-differing
member position, the same way the audit fork proof (the draft's Audit, Causal Graph, and Ordering section) reports an equivocation
position. `DirectoryForkProof` is self-contained and non-repudiable: it carries the accused
signer's own two signed directory objects, and `Verify` accepts only when both verify under one
key, share one directory id and version, and their member lists differ (the draft's Channel Surfaces section).

### Foreign import and confused-deputy containment

A description import carries a foreign capability description **octet-for-octet** (carriage,
not adoption) and binds two things under the importer's own signature: the foreign
bytes' content id, and an N-AALP effect mapping for the described operations. The
confused-deputy rule is enforced normatively: `VerifyImport` recomputes the self-certifying
signer id from the verifying key and requires the attestation's `importer` field to equal it
(`ImporterMismatch` otherwise). No field inside the carried foreign bytes — including any
identity the foreign format asserts about itself — can become the N-AALP authorization
identity; a signer can only ever import **as itself** (the draft's Channel Surfaces section).

### Go reference implementation

`impl/go/description/description.go` implements all three objects and their verification
paths:

- [`Description` / `ParseDescription` / `VerifyDescription`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/description/description.go#L183-L251)
- [`Directory` / `DetectFork` / `DirectoryForkProof.Verify`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/description/description.go#L253-L397)
- [`Import` / `VerifyImport`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/description/description.go#L399-L515)
- [`Operation.EffectClass` / `Operation.RequiresApprovalFlag`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/description/description.go#L109-L121) —
  the fail-closed normalization: an unrecognized effect value is treated as `destructive`
  (the draft's Effects and Authorization section), never the mildest default.

The Go and Rust implementations produce byte-identical bodies, heads, and content ids, and a
byte-identical deterministic ML-DSA-65 signature for a signed Description, graded against a
non-circular oracle (`tools/description_oracle.py`) that never reuses the code under test
(the draft's Channel Surfaces section).

## Failure modes

| Error kind | When |
|---|---|
| `DescMalformed` | the object is not a well-formed description/directory/import body |
| `MalformedApprovalFlag` | `requires_approval` is outside `{0, 1}` |
| `DirForkProofInvalid` | a directory fork proof is not one signer, not the same directory+version, or lists identical members |
| `ImporterMismatch` | the attested importer does not match the verifying key's self-certifying signer id |
| `BadSignature` | a signature that does not verify |
| `RecordExpired` / `TrustAnchorUnknown` | (Discovery channel) a stale record, or a record signed under an untrusted anchor |

Every check is fail-closed (the draft's Security Considerations section): a failing object is rejected whole, returns its
named error, and causes no state change. A baseline-only endpoint that validates only the
frozen kinds correctly rejects a C18 description object as `UnknownKind`.

## What this mechanism does not decide

- **The foreign format's internal schema.** A description import carries a foreign description
  octet-for-octet and binds its hash; parsing the foreign format's own fields is the importing
  application's concern — this is precisely what contains the confused deputy.
- **Directory reconciliation across signers.** Fork detection compares two versions from **one**
  signer; merging directories from multiple signers is the federated-ordering concern
  (the draft's Audit, Causal Graph, and Ordering section), layered over the same causal graph with no wire change.
- **Non-Go/Rust SDK ports.** The primitive is graded on the Go+Rust two-implementation parity
  path against a non-circular oracle; the other eight reference SDKs port it in a later wave,
  tracked honestly in the parity ledger.

See also: [the object model](../spec/object-model.md), [the twenty channels](../spec/channels.md),
[the A2A mapping](../mappings/a2a.md) for the sibling agent-coordination profile that names the
same Agent Card / task-lifecycle formats this mechanism can carry.
