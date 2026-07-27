---
title: "N-AALP: The Native Agentic Application Layer Protocol"
abbrev: N-AALP
docname: draft-bubblefish-naalp-00
category: info
ipr: trust200902
submissionType: independent
area: ART
date: 2026

keyword:
  - agents
  - agentic
  - application layer
  - post-quantum
  - CBOR
  - COSE

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: S. Sammartano
    name: Shawn Sammartano
    org: BubbleFish Technologies, Inc.
    # REQUIRED: a working, MONITORED email. ISE correspondence, the IESG conflict
    # review, and AUTH48 all go here. Confirm this address before submission.
    email: naalp-editor@bubblefish.sh

normative:
  RFC8949:   # CBOR (STD 94); deterministic encoding; the +cbor structured suffix
  RFC9052:   # COSE structures (COSE_Sign1, COSE_Sign)
  RFC9053:   # COSE initial algorithms
  RFC8032:   # EdDSA / Ed25519
  RFC9964:   # ML-DSA in COSE (algorithm identifiers)
  RFC9864:   # Ed25519 in COSE (as used in the hybrid leg)
  RFC8610:   # CDDL
  RFC6838:   # Media type registration procedures (BCP 13)
  RFC8126:   # IANA considerations guidelines (BCP 26)
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard (FIPS 204)"
    author:
      - org: National Institute of Standards and Technology
    date: 2024
  FIPS180:
    title: "Secure Hash Standard (SHS) (FIPS 180-4)"
    author:
      - org: National Institute of Standards and Technology
    date: 2015

informative:
  RFC7942:   # Implementation Status
  RFC6839:   # Additional media type structured syntax suffixes
  NPAMP:
    title: "N-PAMP: Native Post-Quantum Agent Messaging Protocol"
    author:
      - ins: S. Sammartano
        name: Shawn Sammartano
        org: BubbleFish Technologies, Inc.
    date: 2026
    seriesinfo:
      Internet-Draft: draft-bubblefish-npamp (work in progress)

--- abstract

The Native Agentic Application Layer Protocol (N-AALP) is an application-layer object
protocol for autonomous software agents. Every N-AALP object is a deterministically encoded
CBOR structure signed with COSE, carrying under one signature its content identity, its
originating signer, a closed effect label that is an authorization input rather than a hint,
optional approval and audit bindings, and its causal derivation. Objects are transport-
independent: the identical signed object is carried, with identical object-level guarantees,
over the N-PAMP substrate, QUIC, WebSocket, or HTTP. N-AALP defines a frozen envelope, a
post-quantum signature profile (ML-DSA with an optional Ed25519 hybrid), a self-certifying
identity with key rotation, a single-use approval ledger, a hash-chained audit and causal-
ordering model with a federated higher tier, native streaming with a single per-stream
commitment, foreign-protocol carriage by class, and twenty tiered channel surfaces. This
document is an Independent Submission and does not represent IETF consensus.

--- middle

# Introduction

Autonomous agents increasingly exchange consequential messages — tool invocations, memory
writes, capability delegations, settlements — across trust and organizational boundaries.
Existing agent protocols secure the transport connection but leave the individual message
un-signed, its effect on the world undeclared, and its authorization implicit. N-AALP makes
the object, not the connection, the unit of security and governance.

N-AALP is the application layer above the N-PAMP substrate
{{NPAMP}}: N-PAMP provides the post-quantum secure channel, channel identifiers,
and foreign-protocol Bridge; N-AALP provides the signed, effect-labeled, audited object that
rides any transport. The two compose but N-AALP does not require N-PAMP: the same object is
valid over QUIC, WebSocket, or HTTP.

## Scope

This document specifies: the object envelope and its deterministic CBOR encoding (# Object
Model); the COSE signing constructions and crypto-agile profiles (# Cryptographic
Constructions); self-certifying identity and key lifecycle (# Identity); the closed effect
vocabulary and effect-to-authorization rule (# Effects and Authorization); the approval object
and single-use consume ledger (# Approval); the audit receipt chain, causal graph, and tiered
ordering (# Audit, Causal Graph, and Ordering); delivery stages (# Delivery); native streaming
(# Streaming); the four transport bindings and the confidentiality boundary (# Transport
Bindings); foreign carriage by class (# Foreign Carriage by Class); and the twenty tiered
channel surfaces (# Channel Surfaces).

## Non-Goals

N-AALP does not define a transport handshake, key exchange, or record layer; those are the
substrate's (N-PAMP's, or the underlying TLS/QUIC's). It does not define agent reasoning,
planning, or model behavior. It does not replace the foreign protocols it carries; it wraps
them.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

The following terms are used:

Object:
: a deterministically encoded CBOR map, signed with COSE, that is the unit of N-AALP security
  and governance.

Content id:
: the multihash of the SHA-384 of an object's canonical body excluding its own id field; it
  binds the object's bytes.

Signer id:
: a self-certifying identifier derived from a public signing key (# Identity); no certificate
  authority is involved.

Effect:
: one closed value stating what an object does to the world, aligned with the N-PAMP Bridge
  SafetyLabel and used as an authorization input (# Effects and Authorization).

Channel:
: one of twenty application surfaces, identified by an N-PAMP channel id (# Channel Surfaces).

Carriage:
: wrapping a foreign protocol's message octet-for-octet inside a signed N-AALP object
  (# Foreign Carriage by Class).

# Architecture

N-AALP separates three layers that MUST NOT be conflated:

1. The object (this document): self-secured, transport-independent.
2. The transport: provides confidentiality, connection authentication, and framing; N-PAMP is
   the reference confidential transport, but QUIC, WebSocket, and HTTP are equally valid
   carriers of the identical object.
3. The application: the twenty channel surfaces, each a thin body over the one object model.

Object-level guarantees (integrity, identity, non-repudiation, effect, audit) are always
present regardless of transport. Confidentiality, forward secrecy, and connection
authentication are transport-provided and conditional (# Transport Bindings).

# Object Model {#objmodel}

## Deterministic encoding

All N-AALP structures are encoded as deterministic CBOR per {{RFC8949}} Section 4.2.1:
shortest-form integer and length encoding, major-type map keys sorted in bytewise-lexicographic
order of their encoded form, no indefinite-length items, and no duplicate keys. A non-canonical
encoding of any structure defined here MUST be rejected.

## The object body

The signed payload is the object body, a CBOR map, expressed here in CDDL {{RFC8610}}:

~~~ cddl
naalp-object = {
  1 : bstr,      ; id: multihash(0x20, SHA-384(body-without-1))
  2 : uint,      ; kind (per channel surface)
  3 : 0..19,     ; channel id
  4 : uint,      ; tier (0 = baseline)
  5 : bstr,      ; signer: self-certifying signer id
  6 : uint,      ; created: epoch ms (advisory)
  7 : effect,    ; closed effect value
  8 : [* bstr],  ; causes: content ids; may be empty
  9 : profile,   ; crypto profile
  10 : any,      ; body: kind-specific, validated by the surface
  ? 11 : { * uint => any },  ; ext: non-critical; unknown ignored
  ? 12 : { * uint => any },  ; cext: critical; unknown => reject
}
effect = &( read_only:0, idempotent_write:1,
            non_idempotent_write:2, destructive:3 )
profile = &( public:1, enterprise:2, sovereign:3 )
~~~

## Content identity

The id (field 1) is `multihash(0x20, SHA-384(C))` where C is the deterministic CBOR encoding of
the body with field 1 removed, and 0x20 is the multiformats code for SHA-384. A verifier
recomputes the content id and MUST reject a mismatch (ContentIdMismatch). Because the id binds
the exact bytes, altering any field changes the id.

## Extensions and versioning

Field 11 (ext) carries non-critical extensions a verifier that does not recognize them MUST
ignore. Field 12 (cext) carries critical extensions a verifier that cannot honor them MUST
reject the whole object (fail-closed). Higher channel tiers add capability solely through these
fields and the tier field; the envelope does not change across versions or tiers.

# Cryptographic Constructions {#crypto}

## Signing

An object is signed with COSE_Sign1 {{RFC9052}} over the deterministic-CBOR object body as the
payload. The protected header carries the COSE algorithm and a pre-parse routing copy of the
signer, profile, and protocol version under a text-string label. A verifier MUST reject an
object whose header signer/profile copies disagree with body fields 5 and 9
(HeaderBodyMismatch). On the wire the object is a tagged COSE_Sign1 (CBOR tag 18); the optional
hybrid uses tagged COSE_Sign (tag 98) and is accepted only if all its signatures verify.

## Algorithms and profiles

The mandatory-to-implement signature algorithm is ML-DSA {{FIPS204}} using the deterministic
variant (rnd = 0) so two implementations produce byte-identical signatures. The classical hybrid
leg is Ed25519 {{RFC8032}}. Within the COSE algorithm framework {{RFC9053}}, the algorithm
identifiers are those registered for ML-DSA {{RFC9964}} and Ed25519 {{RFC9864}}; N-AALP does not
define new COSE algorithm code points and reuses the existing IANA COSE Algorithms registry.
Three profiles select a signature floor:

| profile | value | signature floor |
|---|---|---|
| public | 1 | ML-DSA-65 (NIST level 3) |
| enterprise | 2 | ML-DSA-65 (NIST level 3) |
| sovereign | 3 | ML-DSA-87 (NIST level 5) |

A verifier for a profile MUST reject a signature below the profile's floor (ProfileDowngrade)
and an unknown algorithm (UnknownAlg). The optional Ed25519+ML-DSA hybrid (COSE_Sign) is
accepted only when both legs verify (HybridIncomplete otherwise). Digests use SHA-384
{{FIPS180}}.

# Identity {#identity}

The signer id (object field 5) is self-certifying: `multibase(base32,
multihash(0x12, SHA-256(multicodec(mc, pubkey))))`, identical in form to the N-PAMP PeerHandle,
where mc is the multiformats key-type code (0xed ed25519-pub, 0x1211 mldsa-65-pub, 0x1212
mldsa-87-pub). A verifier recomputes the id from the key and MUST reject a mismatch
(SignerMismatch). No certificate authority is involved.

Key lifecycle records are signed with the same COSE crypto: a Rotation is co-signed by both the
old and new key; a Revocation is signed by the revoked key or a recovery key; a foreign-identity
link is cross-signed by the foreign identity's key. Identity strings that carry human text MUST
be Unicode NFC (NonNFC otherwise). A receipt signed under a superseded key remains attributable
to the durable identity thread across rotations.

# Effects and Authorization {#effects}

Every object carries, under signature, one value from a closed four-value effect vocabulary
aligned 1:1 with the N-PAMP Bridge SafetyLabel: read_only (0), idempotent_write (1),
non_idempotent_write (2), destructive (3). The values form a lattice with destructive at the
top.

An unrecognized effect value MUST be treated as destructive and MUST NOT fail open. Unlike a
SafetyLabel that "describes intent and does not replace authorization", the N-AALP effect IS an
authorization input: an endpoint grants a maximum effect (a capability) to an authenticated
signer id, and an object is authorized only if its effect does not exceed the grant
(EffectNotAuthorized otherwise). No layer MUST treat transport metadata, a foreign header, or a
client-supplied name as an authorization identity; the authorizing principal is the object's
signature-verified signer id.

An object MAY carry an optional signed safety label (a non-critical ext) `{ risk, scope }`; it
is an accountable claim attributable to the signer, not a guarantee that the content is safe.

# Approval {#approval}

An Approval object binds, under signature, the content id of the exact canonical argument object
it approves, so approving one action cannot authorize another (ApprovalMismatch if the args are
mutated). It carries the approver signer id, the granted effect, an anti-replay nonce, and an
expiry.

The consume ledger is a durable, hash-chained set keyed by approval content id. Consume is an
atomic compare-and-set: the first consumer appends a ledger entry and wins; a second consume for
the same approval id is rejected (AlreadyConsumed). Atomicity is provided by a write-ahead log
written before the acknowledgment and a single-writer-per-approval-id discipline; under
concurrency exactly one consumer succeeds. An approval past its expiry is rejected
(ApprovalExpired). An approval-required-but-not-granted outcome is a distinct signed non-success
result, never a silent success or denial.

# Audit, Causal Graph, and Ordering {#audit}

An ordering authority records each accepted object by appending a signed Receipt
`{ prev, obj, seq, at }` where prev is the SHA-384 of the previous receipt body (genesis is
zero) and obj is the object content id. The chain is tamper-evident: reordering, omission, or
substitution breaks a prev link or a seq (ChainBroken). The authority MUST NOT mutate the origin
object to order it; ordering is an outer signed layer.

Every object MAY name its causes by content id (field 8). This is a signed partial order: an
edge "A causes B" is proven by B's signature over A's content id, checkable offline with no
ordering authority present. An object MUST NOT name a cause it could not have seen (a cause whose
ordering position exceeds the effect's, or a cycle), which is rejected (CausalViolation). A total
order is a policy layered over this partial order.

An independent auditor detects equivocation — two receipts by one authority at one seq naming
different objects — from the signed receipts alone (Equivocation). A receipt whose signature does
not verify is rejected (ReceiptUnsigned).

Ordering is tiered. The baseline tier is a single authority's monotonic receipt chain. The higher
tier is federated: multiple independent authorities each order their own scope and reconcile
deterministically over the shared causal graph (a topological linearization tie-broken by content
id). Because the merge depends only on the causal graph, both tiers order the identical signed
objects and moving to federated ordering requires no envelope change.

# Delivery {#delivery}

Delivery is four distinct, monotonic, separately-observable stages, each a signed delivery update
naming the object content id and the stage reached: persisted_origin (0), accepted_relay (1),
persisted_target (2), presented (3). There is no single "sent" flag. An endpoint MUST durably
persist an object before emitting the acknowledgment that advances its stage
(persist-before-acknowledge), so a crash immediately after an acknowledgment loses nothing. A
stage earlier than the one already reached is rejected (StageOutOfOrder). A relay that holds an
object only in transit MAY write an audit trail over content ids while retaining no payload.

# Streaming {#streaming}

A native stream is three signed objects plus unsigned chunks. StreamOpen binds the stream
identity, effect, and (where it causes an effect) approval; a stream whose effect is not
authorized is refused before any chunk. Chunks are raw data frames the transport authenticates;
they are not individually signed. StreamCommit carries a single rolling SHA-384 over the chunks
in absolute-offset order, making the whole stream non-repudiable with one signature; altering any
delivered byte invalidates it (StreamDigestMismatch). Optional signed StreamCheckpoints let a
verifier confirm a prefix without the end. The same three objects map onto QUIC streams,
WebSocket messages, and HTTP chunked/event streams; the commitment verifies identically across
transports.

# Transport Bindings {#transport}

A binding carries exactly one signed object as one message unit, with identical object semantics
over N-PAMP, QUIC, WebSocket, and HTTP. The object is self-secured; the binding adds only framing
and, from the transport, confidentiality and connection authentication. The media type is
`application/naalp+cbor` (one object per representation).

The confidentiality boundary is normative: an object marked sensitive MUST NOT be emitted in
cleartext over a non-confidential transport; the binding refuses it
(ConfidentialTransportRequired) and directs the deployment to a confidential transport. A
transport lacking peer authentication where policy requires it is refused (PeerUnauthenticated).

# Foreign Carriage by Class {#carriage}

N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed
carriage object interpreted by a carriage class:

~~~ cddl
naalp-carriage-body = {
  1 : uint,      ; protocol_id (N-AALP protocol registry)
  2 : carriage-class,   ; 0 JSONRPC .. 5 OPAQUE
  3 : uint,      ; content_type (foreign encoding)
  4 : bstr,      ; correlation token
  5 : tstr,      ; method (advisory routing key)
  6 : bstr,      ; foreign message, carried octet-for-octet
}
carriage-class = &( jsonrpc:0, http:1, msg:2,
                    stream:3, doc:4, opaque:5 )
~~~

The foreign field is carried verbatim and MUST NOT be re-serialized, canonicalized, summarized,
or rewritten. The carriage object's signer remains the authority: a foreign protocol's identity,
header, or metadata MUST NOT become an N-AALP authorization identity. The OPAQUE class carries
any protocol, including an undefined one, on an experimental protocol id with no registration. A
below-foreign failure uses a defined structured error and MUST NOT report an undelivered message
as delivered; an N-AALP semantic a foreign protocol cannot represent surfaces a typed mapping
error, never a silent drop.

# Channel Surfaces {#channels}

N-AALP defines twenty channel surfaces (channel ids 0x0000..0x0013): Control, Memory, Capability,
Identity, Governance, Immune, Federation, Settlement, Compliance, Sensory, Telemetry, Audit,
Stream, Bridge, Commerce, Interaction, Discovery, Workflow, Knowledge, and Spatial. Each surface
adds only object kind codes and their declared effects over the one object model; it introduces
no channel-local encoding, signature, or identity. Every channel has a complete frozen baseline
surface. Higher tiers add capability under the frozen envelope through the tier field and
critical/non-critical extensions. The complete kind/effect table is the N-AALP Channel and Object
Kind registries (# IANA Considerations).

# Security Considerations {#security}

Mandatory-to-implement algorithms and post-quantum rationale: N-AALP signs with ML-DSA
{{FIPS204}}, a post-quantum signature, because N-AALP objects (receipts, approvals, audit chains)
are long-lived non-repudiable records subject to store-now-verify-later forgery risk from a
future cryptographically relevant quantum computer; a classical-only signature on such records
would be a latent forgery exposure. An optional Ed25519 hybrid provides defense-in-depth during
the transition and is accepted only when both legs verify.

Downgrade and negotiation: algorithm agility is expressed by the COSE algorithm identifier bound
under the signature and checked against the profile floor; a signature below the floor is
rejected, so agility cannot become a downgrade.

Replay and reordering: approvals bind a nonce and expiry and are single-use through the consume
ledger; the audit receipt chain binds each object into a hash chain so reordering, omission, and
substitution are detectable; delivery stages are monotonic.

Identity and trust: the signer id is a pure function of the public key, so a forged id cannot
recompute; there is no certificate authority to compromise. Compromise of a signing key is
bounded by rotation and revocation, and attribution survives rotation. A non-injective or
forgeable identity function would collapse this property; the SHA-256 multihash over the
multicodec-tagged key provides collision and second-preimage resistance.

Effect and authorization: the effect is an authorization input, not a hint; an unrecognized
effect fails closed to destructive; authorization is never derived from transport metadata or a
foreign principal. This closes the gap a pure intent label leaves open.

Denial of service: an object requires one signature verification and one deterministic decode;
verification is fail-closed and performed before any state change or effect. Streaming amortizes
one signature over many chunks. Implementations SHOULD bound object and stream sizes by policy.

Confidentiality: object-level guarantees do not include confidentiality; a sensitive object MUST
use a confidential transport (# Transport Bindings), enforced by refusal.

What N-AALP does NOT defend against: it does not provide confidentiality by itself (that is the
transport's); it cannot force an ordering authority to deliver events it chooses to withhold (a
chain reveals equivocation and omission-of-known-events but cannot compel delivery); it does not
police the semantic correctness of a carried foreign message beyond octet-exact carriage; and it
does not defend against a signer that is itself authorized and malicious (it makes that signer's
actions attributable and auditable, not impossible).

# IANA Considerations {#iana}

This document is an Independent Submission. All registries requested below use registration
policies that do not require IETF Review or Standards Action, consistent with the Independent
stream: media-type registration under {{RFC6838}}, and per-registry Specification Required with a
Designated Expert per {{RFC8126}}. Numeric values shown are the values this specification
defines; where IANA assignment is requested the placeholder TBD is used.

## Media type application/naalp+cbor

IANA is requested to register the following media type in the standards tree per {{RFC6838}},
using the +cbor structured syntax suffix defined in {{RFC8949}} and registered in the IANA
Structured Syntax Suffixes registry (whose mechanism is established by {{RFC6838}} and populated
by {{RFC6839}}):

- Type name: application
- Subtype name: naalp+cbor
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary (CBOR per {{RFC8949}})
- Security considerations: see (# Security Considerations) of this document
- Interoperability considerations: objects are deterministic CBOR; see (# Object Model)
- Published specification: this document
- Applications that use this media type: autonomous-agent application-layer messaging
- Fragment identifier considerations: as specified for application/cbor
- Additional information: Magic number(s): none; File extension(s): .naalp; Macintosh file type
  code(s): none
- Person & email address to contact for further information: the author (front matter)
- Intended usage: COMMON
- Restrictions on usage: none
- Author: S. Sammartano
- Change controller: the author (BubbleFish Technologies, Inc.)

## N-AALP Channel registry

IANA is requested to create the "N-AALP Channels" registry. Registration policy: Specification
Required (a Designated Expert confirms a stable public specification and non-collision).
Columns: Channel Id (uint 0..19), Name, Reference. Initial contents: the twenty channels of
(# Channel Surfaces), ids 0x0000..0x0013, this document.

## N-AALP Object Kind registries

IANA is requested to create, per channel, an "N-AALP Object Kinds (channel N)" registry.
Registration policy: Specification Required. Columns: Kind Code (uint), Name, Effect (one of the
four closed effect names, or "variable"), Reference. Initial contents: the sixty-five baseline
kinds of this document.

## N-AALP Effect registry

IANA is requested to create the "N-AALP Effects" registry. Registration policy: Specification
Required (this closed set is not expected to grow; additions require a stable specification and
MUST preserve the fail-closed lattice). Columns: Value (0..3), Name, Reference. Initial contents:
read_only 0, idempotent_write 1, non_idempotent_write 2, destructive 3, this document.

## N-AALP Carriage Protocol Id registry

IANA is requested to create the "N-AALP Carriage Protocol Ids" registry, a one-octet space
partitioned: standards 0x01-0x0F (Specification Required), experimental 0x10-0x7F (no
registration), private 0x80-0xFF (no registration). Columns: Protocol Id, Name, Carriage Class,
Reference. Initial standards-range contents: 0x01 MCP (JSONRPC), 0x02 A2A (JSONRPC), 0x03 HTTP
(HTTP), 0x04 WebSocket (STREAM), this document.

## N-AALP Error Code registry

IANA is requested to create the "N-AALP Error Codes" registry. Registration policy: Specification
Required. Columns: Name, Retryable, Reference. Initial contents: the named errors of this
document (ContentIdMismatch, HeaderBodyMismatch, UnknownCriticalExt, UnknownKind, RangeError,
NonCanonical, NonNFC, ProfileDowngrade, UnknownAlg, HybridIncomplete, BadSignature,
SignerMismatch, RotationUnauthorized, KeyRevoked, EffectNotAuthorized, UnauthenticatedPrincipal,
ApprovalMismatch, ApprovalExpired, AlreadyConsumed, ApprovalRequired, ChainBroken, Equivocation,
CausalViolation, ReceiptUnsigned, StageOutOfOrder, StreamDigestMismatch,
ConfidentialTransportRequired, PeerUnauthenticated, NotDelivered, MappingError,
ScopeOverlapConflict, CapExceedsParent, TransformCycle, InputGateBypass).

## COSE algorithms

N-AALP reuses the existing IANA COSE Algorithms registry for ML-DSA {{RFC9964}} and Ed25519
{{RFC9864}} and requests no new COSE code points.

## Designated Expert guidance

For each Specification-Required registry the Designated Expert confirms: (1) a stable, publicly
available specification documents the value; (2) the value does not collide with an existing
entry; (3) the name is protocol-neutral and carries no vendor product name; and (4) for object
kinds, the declared effect is one of the closed set and preserves the fail-closed model.

# Implementation Status

RFC-Editor: please remove this section and the reference to {{RFC7942}} before publication.

This section records the status of known implementations at the time of posting, per
{{RFC7942}}. Listing here does not imply endorsement.

Two independent reference implementations exist, in Go and in Rust, from a single codebase but
separate language runtimes. For every construction carrying a security or interoperability claim
(deterministic CBOR and content id; COSE_Sign1 and the ML-DSA/Ed25519 profiles; the object
envelope; signer id; effect authorization; approval and the consume ledger; audit chain, causal
graph, and federated reconcile; delivery; streaming; transport bindings; foreign carriage; and
the twenty channel surfaces), the two implementations produce byte-identical output and are
cross-validated against an independent oracle whose expected values come from the relevant RFC,
FIPS, or NIST vector or a from-scratch constructor, never from the implementation under test. A
runnable conformance harness grades every construction and validates the CDDL module against the
committed vectors. Coverage and known gaps are tracked in the project's parity ledger.

# Conformance {#conformance}

A conforming implementation MUST implement the object model, the signing constructions, identity,
effects and authorization, and the baseline surfaces of every channel, and MUST reject a
non-conforming object whole with its named error and no state change (fail-closed). Conformance
is demonstrated against the machine-gradable vector corpus and the CDDL module (Appendix A). This
specification recommends, but does not require for Independent-stream publication, two independent
interoperating implementations; two exist (# Implementation Status).

# Specification License

This specification may be implemented by anyone, royalty-free. This right to implement is granted
independently of the license of any reference implementation (the reference code is licensed
separately). Contributions to this document are subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents.

--- back

# Collected CDDL {#cddl}

The complete, machine-validated CDDL module is maintained with the reference implementation as
`spec/naalp-draft-00.cddl` and is normative for the byte-level wire format. It is validated for
well-formedness and against the conformance vectors by the project's conformance harness. The
object body, effect, and profile productions of (# Object Model) and the carriage body of
(# Foreign Carriage by Class) are reproduced there in full, together with the COSE wrapper,
protected header, identity records, safety label, approval and consume records, receipt, delivery
update, stream objects, and the federated reconcile record.

# Acknowledgments

N-AALP builds on the N-PAMP substrate.
