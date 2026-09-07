---
title: "N-AALP: The Native Agentic Application Layer Protocol"
abbrev: N-AALP
docname: draft-bubblefish-naalp-01
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
  BCP14:
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
  RFC9943:   # Trustworthy/transparent digital supply chains (Transparency Service; Sec. 9.1/9.2)
  RFC9162:   # Certificate Transparency Version 2.0 (Merkle tree construction; the checkpoint-root primitive)
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
post-quantum signature profile (pure ML-DSA by default, with an optional Ed25519+ML-DSA composite), a self-certifying
identity with key rotation, a single-use approval ledger, a hash-chained audit and causal-
ordering model with a federated higher tier, native streaming with a single per-stream
commitment, foreign-protocol carriage by class, and twenty tiered channel surfaces. This
document is an Independent Submission and does not represent IETF consensus.

--- middle

# Introduction

Autonomous agents increasingly exchange consequential messages -- tool invocations, memory
writes, capability delegations, settlements -- across trust and organizational boundaries.
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
Bindings); foreign carriage by class (# Foreign Carriage by Class); the twenty tiered
channel surfaces (# Channel Surfaces); and the higher-tier additive object families -- rooms
membership, multi-hop delegation, MCP tool-call binding, description and directory, name bindings
and A2A task transitions, governed negotiation, advisory risk labels, flow continuations, governed-
decision records and transparency log primitives, portable egress evidence, and manufacturing
physical-hazard claims (# Additive Object Families). The document classifies these surfaces by status
(# Conformance): the spine and each channel's frozen baseline surface are normative and required for
conformance, while the higher tiers are experimental and OPTIONAL. The classification is editorial
and does not narrow implementation coverage.

## Non-Goals

N-AALP does not define a transport handshake, key exchange, or record layer; those are the
substrate's (N-PAMP's, or the underlying TLS/QUIC's). It does not define agent reasoning,
planning, or model behavior. It does not replace the foreign protocols it carries; it wraps
them.

# Conventions and Terminology

{::boilerplate bcp14-tagged-bcp14}

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

Every top-level wire structure this document defines -- the object body below, its COSE signature
wrapper, the identity, approval, audit, delivery, streaming, flow-continuation, carriage, and
additive-family records (# Additive Object Families) -- is collected as a single reachable root,
`naalp-artifact`, in the CDDL module (Appendix A). The union exists only so a CDDL validator sees
every production as reachable from one entry point; it carries no independent wire meaning of its
own, and a concrete instance is always validated against the specific production for its kind, not
against the union.

## Deterministic encoding

All N-AALP structures are encoded as deterministic CBOR per {{RFC8949}} Section 4.2.1:
shortest-form integer and length encoding, major-type map keys sorted in bytewise-lexicographic
order of their encoded form, no indefinite-length items, and no duplicate keys. A non-canonical
encoding of any structure defined here MUST be rejected.

{{RFC8949}} Section 4.2.2 leaves the integer/float question, and {{RFC9052}} Section 3 the empty
protected header, to the protocol; N-AALP resolves each as a MUST-reject so that one logical object
has exactly one encoding. A CBOR float (major type 7) MUST NOT appear in any object body field,
`ext` value, or `cext` value, and a decoder MUST reject a major-type-7 item as non-canonical. An
empty COSE protected header MUST be the zero-length byte string `0x40`; the redundant `0x41A0`
form (a byte string wrapping an empty map) MUST be rejected as non-canonical, before the header is
interpreted. A map with duplicate keys MUST be rejected at the decoder ({{RFC8949}} Section 5.6).

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
  ? 13 : tstr,   ; audience: consuming-authority binding;
                 ; omitted when empty (see below)
  ? 14 : uint,   ; suite: signed signature-suite selector;
                 ; present iff composite alg (see below)
}
effect = &( read_only:0, idempotent_write:1,
            non_idempotent_write:2, destructive:3 )
profile = &( public:1, enterprise:2, sovereign:3 )
~~~

Fields 4 (`tier`) and 9 (`profile`) are independent axes with distinct meanings and MUST NOT be
conflated. `profile` selects the cryptographic signature floor (# Cryptographic Constructions)
that bounds which signature strength a verifier accepts for the object. `tier` selects the
channel's capability depth (0 = baseline; higher values are named per channel, # Channel
Surfaces) under the one frozen envelope. The two are set independently: a higher channel tier
does not raise the signature floor, and a higher crypto profile does not unlock channel
capability.

## Content identity

The id (field 1) is `multihash(0x20, SHA-384(C))` where C is the deterministic CBOR encoding of
the body with field 1 removed, and 0x20 is the multiformats code for SHA-384. A verifier
recomputes the content id and MUST reject a mismatch (ContentIdMismatch). Because the id binds
the exact bytes, altering any field changes the id.

### Multihash length-octet worked example

A multihash is `unsigned-varint(code) || unsigned-varint(digest-length) || digest`, per the
multiformats multihash and unsigned-varint specifications. unsigned-varint is a base-128
(LEB128-style) encoding: a value under 128 encodes as exactly one octet equal to that value.
Both integers a content id ever carries are under 128 (32 and 48), so both octets are
single-byte:

~~~
octet 0        : 0x20  -- unsigned-varint(32); sha2-384 multicodec code
octet 1        : 0x30  -- unsigned-varint(48); a 48-octet SHA-384 digest
octets 2..49   : the 48-octet SHA-384 digest
~~~

Using the FIPS 180-4 SHA-384 known-answer digest for the ASCII input `"abc"` (shown below),
the 50-octet content id is:

~~~
SHA-384("abc"):
  cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163
  1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7

content id:
  2030cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1
  631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
~~~

The two prefix octets are derived from the unsigned-varint algorithm applied to 32 and 48,
not asserted as a fixed literal; the same algorithm produces a two-octet encoding
(`0xac 0x02`) for a value at or above 128 (e.g. 300), which is how a future digest algorithm
with a multicodec code or digest length at or above 128 would be carried without changing
this framing. A conformance oracle and grading gate for this construction, cross-checked
against the multiformats spec and NIST FIPS 180-4 SHA-384 known-answer values independent of
any N-AALP encoder, ship with the reference implementation (`tools/multihash_oracle.py`,
`scripts/gates/gate_multihash.py`).

## Extensions and versioning

The protected header carries `naalp-version`, which tracks the **envelope object grammar** -- the
top-level numbered fields of `naalp-object`. The rule is mechanical: adding or changing a
top-level envelope field moves the version; adding an `ext`/`cext` key (a key inside the
field-11 or field-12 maps) never does. `naalp-version` 1 was the previous version, which lacked
the `audience` and `suite` fields; this document specifies **`naalp-version` 2**, anchored by two
envelope additions -- the top-level `audience` field (field 13) and the `suite` field (field 14). A
verifier MUST reject an object whose `naalp-version` it does not support (`UnsupportedVersion`).

`audience` (field 13, a text string) names the one endpoint or channel-scope identity an object
is bound to. It is omitted when empty, so a no-audience object encodes byte-identically to a
`naalp-version` 1 object and its content id is unchanged. A *consume-once* kind -- one whose
acceptance spends a single-use ledger resource (the consume ledger, see Approval) -- MUST carry
an `audience` naming its one consuming authority. The audience is checked by that consuming
authority at the moment it would spend the object, before the single-use compare-and-set and
outside core object verification, so that an in-transit relay, ordering authority, or auditor
can still verify an object addressed to someone else. An object whose `audience` is not the
checking authority -- or a consume-once object that omits it -- is rejected `WrongAudience`, with
no ledger entry and no state change (fail-closed).

`suite` (field 14, a `uint`) is the signed selector for the object's signature suite. It is PRESENT
if and only if the object is signed with the opt-in composite algorithm (the composite COSE alg id
in the private-use range, see Signing) and ABSENT for a pure ML-DSA object, so a pure object encodes
byte-identically to a `naalp-version` 1 object carrying neither field 13 nor field 14 and its content
id is unchanged. Value 1 selects the `COMPSIG-MLDSA65-Ed25519-SHA512` composite suite
(Public/Enterprise); value 2 is RESERVED for the ML-DSA-44 edge suite. Because `suite` is a signed
body field it cannot be stripped or altered without invalidating the signature; a `suite` value that
disagrees with the COSE algorithm is rejected (`SuiteMismatch`). Turning the composite on, or
changing the default suite in a later profile, is a suite-registry change, not a wire break.

Field 11 (`ext`) carries non-critical extensions a verifier that does not recognize them MUST
ignore. Field 12 (`cext`) carries critical extensions a verifier that cannot honor them MUST
reject the whole object (fail-closed). Three extension keys are defined in this revision and ride
this mechanism without moving the version. Key 13 (a key inside the `ext`/`cext` maps -- a
distinct namespace from the top-level `audience` field 13), `recheck`, names by id the procedure
a verifier runs to re-check the body claim, from a closed set -- 1 recompute-content-id, 2
verify-cose-sign1, 3 walk-causes, 4 replay-consume-check; carried in `ext` an unrecognized id is
ignored, in `cext` it is rejected fail-closed (`UnknownCriticalExt`). Key 14, `signer-counter`,
is an OPTIONAL forward-only per-signer position carried only in the non-critical `ext` map; it is
a duplication-*detection* aid, never a verification gate, and because `ext` is part of the signed
payload it is covered by the signer's own signature. Key 15, `producing-boundary`, is an OPTIONAL
per-object disclosure of the trust boundary that produced the object and whether that boundary
observed the described event first-hand or is relaying a report of it: a small map of `boundary` (a
party identifier in the same `bstr` form as the object `signer`), `kind` (a closed enum -- 1
observed, 2 reported), and an OPTIONAL `reporting-boundary` (`bstr`) present only when `kind` is
reported and absent under observed. It rides the non-critical `ext` map, so a verifier that does not
recognize it -- or reads a malformed value (no `boundary`, a `kind` outside the enum, or a
`reporting-boundary` under observed) -- ignores the entry and the object still verifies; placing it
in `cext` is an unrecognized critical key rejected fail-closed (`UnknownCriticalExt`). Because `ext`
is part of the signed payload the disclosure is covered by the signer's own signature: it is a claim
the signer makes about itself, naming whose observational domain the object rests on and whether
first-hand or relayed, and does not by itself establish that the named boundary is honest or that
its clock is authoritative outside its own domain (# Security Considerations). Higher channel tiers
add capability by defining new `kind` codes and, at higher tiers, new `ext`/`cext` keys; the
envelope grammar itself changes only with the version.

# Cryptographic Constructions {#crypto}

## Signing

An object is signed with COSE_Sign1 {{RFC9052}} over the deterministic-CBOR object body as the
payload. The protected header carries the COSE algorithm and a pre-parse routing copy of the
signer, profile, and protocol version under a text-string label. A verifier MUST reject an
object whose header signer/profile copies disagree with body fields 5 and 9
(HeaderBodyMismatch). On the wire the object is a tagged COSE_Sign1 (CBOR tag 18). The default and
mandatory-to-implement signature is pure ML-DSA; a deployment MAY opt in to a hybrid, which is a
single COSE_Sign1 (tag 18) whose signature value is one non-separable IETF LAMPS composite of an
ML-DSA and an Ed25519 signature -- not two separate signatures -- selected by the signed suite field
(field 14, below).

An N-AALP object's signature wrapper (`naalp-signed-object`) is therefore one of exactly two
tagged COSE structures: the `COSE_Sign1` (tag 18) form above, or `COSE_Sign` (tag 98), a
multi-signature form this revision uses for exactly two cases -- the OPTIONAL legacy two-signature
Ed25519+ML-DSA hybrid (not required by the Standard profile; (# Security Considerations) discusses
why the single-`COSE_Sign1` composite above is preferred to it), and
the Rotation object's co-signature (# Identity). A `COSE_Sign` carries the same `protected`,
`unprotected`, and `payload` positions as `COSE_Sign1` plus a `signatures` array of two or more
`COSE_Signature` elements, each an independent `[protected, unprotected, signature]` triple with
its own per-signer protected header `{1 => cose-alg}`; this per-element header is distinct from the
`COSE_Sign` body's own protected header. The `unprotected` header position in both structures is
the generic COSE header map ({{RFC9052}} Section 3); this revision defines no N-AALP-specific
unprotected-header parameter.

## Algorithms and profiles

The mandatory-to-implement signature algorithm is pure ML-DSA {{FIPS204}} using the deterministic
variant (rnd = 0) so two implementations produce byte-identical signatures. This determinism is a
producer and cross-implementation-parity property, not a security requirement: {{FIPS204}} permits
either the deterministic or the hedged (randomized) signing variant, and a production signer MAY
use the hedged variant. A conforming verifier MUST accept any signature that is valid under the
object's declared algorithm and profile floor regardless of whether it was produced
deterministically or with per-signature randomness; the deterministic variant is required only for
generating the conformance corpus and its byte-identical cross-implementation vectors
(# Conformance). The composite's classical leg is Ed25519 {{RFC8032}} {{RFC9864}}. Within the COSE algorithm framework {{RFC9053}},
the pure ML-DSA and Ed25519 suites reuse the code points registered for ML-DSA {{RFC9964}} and
Ed25519 {{RFC9864}}; the opt-in composite is named by a single COSE algorithm id in the COSE
private-use range (integers < -65536), which N-AALP owns provisionally until IANA assigns a public
composite code point, so adopting the eventual public id is a registry swap rather than a wire
break. Three profiles select a signature floor:

| profile | value | signature floor |
|---|---|---|
| public | 1 | ML-DSA-65 (NIST level 3) |
| enterprise | 2 | ML-DSA-65 (NIST level 3) |
| sovereign | 3 | ML-DSA-87 (NIST level 5) |

The closed `cose-alg` identifiers this revision defines are: `ml-dsa-44` (-48, NIST level 2,
reserved for an optional edge/light tier and never a Public/Enterprise/Sovereign default),
`ml-dsa-65` (-49, NIST level 3, the Public/Enterprise floor), `ml-dsa-87` (-50, NIST level 5, the
Sovereign floor), `ed25519` (-19, classical, an opt-in composite leg only), `compsig-mldsa65-ed25519`
(-65537, the opt-in Public/Enterprise LAMPS composite above), and `compsig-mldsa44-ed25519` (-65538,
an edge composite suite that is registered but not implemented in this revision). An unrecognized
algorithm identifier is rejected `UnknownAlg`.

A verifier for a profile MUST reject a signature below the profile's floor (ProfileDowngrade)
and an unknown algorithm (UnknownAlg). The opt-in Ed25519+ML-DSA composite is a single COSE_Sign1
whose LAMPS composite value is valid only when both components verify against the shared
message representative; because the two components are bound into one non-separable value, a
stripped-leg object has no valid signature at all (the strongest level of the LAMPS composite
non-separability spectrum: strong non-separability with simultaneous verification). A signed suite
field (field 14) that disagrees with the signature algorithm is rejected
(SuiteMismatch), and a Sovereign verifier refuses a composite object outright (CompositeRefused),
since Sovereign signs with pure ML-DSA-87 and carries no classical leg. Digests use SHA-384
{{FIPS180}}.

The public and enterprise profiles carry an identical object-signature floor: both require ML-DSA-65
(NIST level 3), both permit the opt-in composite, and both use SHA-384 digests. They are not
distinguished by object cryptography. The distinction is one of deployment policy -- the confidential
transport an object composes with: an enterprise deployment mandates the higher N-PAMP transport
profile, while a public deployment MAY compose with either the Standard or the higher profile. A
verifier applies the same object-signature-floor check to both; the profile value records the
deployment posture, not a different object-crypto strength.

# Identity {#identity}

The signer id (object field 5) is self-certifying: `multibase(base32,
multihash(0x12, SHA-256(multicodec(mc, pubkey))))`, identical in form to the N-PAMP PeerHandle,
where mc is the key-type code: 0xed (ed25519-pub), 0x1211 (mldsa-65-pub), 0x1212 (mldsa-87-pub).
These three values are N-AALP's own normative constants for signer-id derivation (sourced from the
multiformats table, 2026-08-19); a verifier MUST derive `mc` from exactly these three values,
independent of the live upstream multiformats table (# Security Considerations). A verifier
recomputes the id from the key and MUST reject a mismatch (SignerMismatch). No certificate
authority is involved.

Key lifecycle records are signed with the same COSE crypto: a Rotation is co-signed by both the
old and new key -- carried as a `COSE_Sign` (tag 98) structure whose two `COSE_Signature` elements
are the old-key and new-key signatures (# Cryptographic Constructions); a Rotation encoded as a
single-signature `COSE_Sign1` (tag 18) is rejected `RotationUnauthorized`. A Revocation is signed
by the revoked key or a deployer-configured recovery key (a Revocation signed by neither is
rejected, fail-closed); a foreign-identity link is cross-signed by the foreign identity's key. Identity strings that carry human text MUST
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

The consume ledger is on the path for a single-use approval spend only, not for every object. An
object that consumes no approval -- a read-only object, or any object that is verified but not
spent -- is checked from its own signed bytes with no ledger access, so ordinary verification stays
available under partition. Only the spend of an approval reaches the ledger; a partition that makes
the ledger unreachable denies that spend fail-closed (# Security Considerations) and denies nothing
else. Placing the ledger on every object's path would make the protocol unavailable under partition
for read-only and other non-spending objects, which this design specifically avoids.

At the baseline tier, an executor that cannot reach the consume ledger SHALL deny the spend
(fail-closed): local spend-and-reconcile-later is not a baseline behavior, and a consumer that
spends locally while the ledger is unreachable is non-conforming. Federated ordering over
identical signed objects, which relaxes this at a bounded and stated cost, is a named higher
tier only (# Audit, Causal Graph, and Ordering); see (# Security Considerations) for the
exposure model that governs the higher tier.

Each consume is recorded as a hash-chained ledger entry: `{ seq, prev, approval_id, by }`, where
`prev` is the SHA-384 of the previous entry (the genesis `prev` is 48 zero bytes) and `by` is the
consuming signer id; the head after an entry is SHA-384(entry), so editing any entry breaks the
next entry's linkage and is detectable on replay (LedgerCorrupt). This chaining format is what the
single-writer-per-approval-id property above rests on as a mechanism, not merely an operational
discipline: the write-ahead log persists an entry before acknowledging it, and the first-append-wins
compare-and-set is what makes exactly one consumer's entry extend the chain for a given approval id,
with every later append for that id rejected (AlreadyConsumed) rather than merely discouraged.

Each consume also mints a **consume receipt** (`naalp-consume-receipt`), a wire object distinct
from the ledger entry above: `{ ledger, approval_id, position }`, signed by the consuming ledger's
own key over exactly those bytes, and minted by the same first-append-wins compare-and-set -- the
first consume of an approval id assigns exactly one position and mints exactly one receipt; a
second consume mints nothing (AlreadyConsumed). Because the position is under the ledger's own
signature rather than the requester's, the requester cannot forge it, and the receipt is the
normative, independently-verifiable artifact by which a third party detects a double spend without
trusting either party to the spend.

At the federated tier, cross-authority single-consume is specified by issuance-time audience
binding, not by a mandated cross-authority consensus protocol: a consensus mechanism between
ordering authorities is explicitly out of scope for this specification. A consume-once object -- one
whose acceptance spends this ledger -- MUST carry a signed `audience` naming its one consuming
authority (# Object Model); any authority other than the named one rejects it WrongAudience before
consume logic runs, so an object addressed elsewhere can never reach this ledger's compare-and-set.
The residual case a partitioned federation still allows is the named authority's own ledger state
forking -- two ledger-signed receipts issued against one approval id from divergent state. Two such
receipts contradict on comparison by any third party holding both, since neither party to the spend
could have produced the other's ledger signature; this contradiction is ConsumeFork, the detected
double spend, bounded in exposure by the spent approval's own expiry (# Security Considerations).

The delivery guarantee this ledger provides therefore has a scope boundary, stated here explicitly.
On a single reachable authority the guarantee is prevention: exactly-once, by the compare-and-set
above. Across a federation the guarantee is weaker and is stated as such: a double consume remains a
verifiable wire violation -- prevented before the fact by WrongAudience for any misdirected object,
and detected after the fact by ConsumeFork for the residual same-authority fork -- never a
consensus-based exactly-once guarantee, because this specification fixes invariants over signed
bytes and does not mandate any cross-authority consensus topology.

The approval object's full state machine -- pending, approved, consumed, expired, its timer, and the
clock-skew rule governing not_after -- is specified normatively in (# Object State Machines).

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

A receiver applies the causal graph, not merely stores it: a receiver SHALL NOT apply an object's
effect before it has applied the effects of that object's already-received causes (the causes named
by content id in field 8). An object naming a cause the receiver has not yet received is held
**pending** -- a state distinct from CausalViolation -- for a bounded interval: the receiver neither
applies nor rejects it. It is resolved when the named cause is applied, which lifts the hold, or by
timeout once the bounded interval elapses, which rejects the object. Pending and CausalViolation
answer different questions: CausalViolation is a cause the object could not have seen -- a
future-cause or a cycle -- and is rejected outright and immediately; pending is a cause the receiver
has simply not received yet, which gives the receiver no basis to reject the object, so an object is
never rejected merely for arriving before a cause that is itself still in flight. The bound on the
hold interval is a timer value, fixed normatively by this document's per-object-kind timer
specification.

An independent auditor detects equivocation -- two receipts by one authority at one seq naming
different objects -- from the signed receipts alone (Equivocation) and expresses the finding as a
non-repudiable ForkProof carrying the accused authority's own two signatures over the two
conflicting receipt bodies, plus an external counter binding the proof against replay or reorder.
A verifier accepts a ForkProof only when the signer is named, the two receipts share one seq, name
different objects, and both signatures verify under the accused key, and rejects it whole otherwise
(ForkProofInvalid, or ReceiptUnsigned for a signature that does not verify). This is a draft-01
change (it supersedes draft-00's signatureless fork proof, which an accused could repudiate). A
receipt whose signature does not verify is rejected (ReceiptUnsigned).

Ordering is tiered. The baseline tier is a single authority's monotonic receipt chain. The higher
tier is federated: multiple independent authorities each order their own scope, and a signed
Reconcile object records their deterministic merge. Because both tiers order the identical signed
objects, moving to federated ordering requires no envelope change.

The federated merge SHALL produce a deterministic total order: a topological linearization of the
union of the per-authority causal graphs above (the signed partial order over field 8), with ties --
pairs the causal graph does not order relative to each other -- broken by object content id in
bytewise ascending order. The tie-break is fixed by this document, not left to an implementation's
choice: because the linearization depends only on the union causal graph and this fixed tie-break,
and not on which authority reconciles first or the order the objects arrived in, two conforming
reconcilers reconciling the identical set of objects SHALL produce the identical total order.

The receive-side pending-cause hold introduced above, the federated reconcile machine, and their
timers are specified normatively in (# Object State Machines).

# Delivery {#delivery}

Delivery is four distinct, monotonic, separately-observable stages, each a signed delivery update
naming the object content id and the stage reached: persisted_origin (0), accepted_relay (1),
persisted_target (2), presented (3). There is no single "sent" flag. An endpoint MUST durably
persist an object before emitting the acknowledgment that advances its stage
(persist-before-acknowledge), so a crash immediately after an acknowledgment loses nothing. A
stage earlier than the one already reached is rejected (StageOutOfOrder). A relay that holds an
object only in transit MAY write an audit trail over content ids while retaining no payload.

The full delivery state machine, including the idempotent-repeat and legal-skip cases and its
stage-advance timer, is specified normatively in (# Object State Machines).

# Streaming {#streaming}

A native stream is three signed objects plus unsigned chunks. StreamOpen binds the stream
identity, effect, and (where it causes an effect) approval; a stream whose effect is not
authorized is refused before any chunk. Chunks are raw data frames; they are not individually
signed. Per-chunk authentication before StreamCommit is a property of the specific transport in
use, not of the N-AALP object: over N-PAMP, the Stream channel's AEAD authenticates every chunk to
the peer (# Transport Bindings); over a transport without an equivalent per-frame guarantee, a
chunk consumed before StreamCommit is unauthenticated at the object layer. StreamCommit carries a
single rolling SHA-384 over the chunks in absolute-offset order, making the whole stream
non-repudiable with one signature; altering any delivered byte invalidates it
(StreamDigestMismatch). This rolling digest, together with any optional signed StreamCheckpoint,
is the object-level mechanism that binds the chunk sequence, transport-independent and identical
across N-PAMP and non-N-PAMP transports. A StreamCheckpoint confirms only a contiguous prefix
through its stated offset, never the stream's end. The same three objects map onto QUIC streams,
WebSocket messages, and HTTP chunked/event streams; the commitment verifies identically across
transports.

The full stream state machine, including the illegal-reuse cases after StreamCommit, is specified
normatively in (# Object State Machines).

# Object State Machines {#statemachines}

This section collects the normative event x state tables governing the four N-AALP objects whose
correct handling depends on accumulated history rather than being decidable from one signed object
in isolation: delivery (# Delivery), streaming (# Streaming), approval (# Approval), and the
reconcile record (# Audit, Causal Graph, and Ordering). Each table is total: every (state, event)
pair a conforming implementation can encounter resolves to exactly one Reaction, either a
transition to a next state (`-> NextState`) or a rejection under a named error
(`reject (ErrorName)`). A (state, event) pair not listed in a table is rejected under that table's
stated default error, so no combination is left undefined. Every rejection under these machines is
fail-closed: the triggering object is refused whole, its named error is returned, and no state
change occurs. Every transition below presupposes the triggering object has already passed the
envelope-layer checks -- signature verification and content-id recomputation (# Cryptographic
Constructions, # Object Model) -- before this table is consulted; an envelope-layer failure
(BadSignature, ContentIdMismatch) is rejected there and never reaches these tables.

## Delivery state machine

The delivery machine (# Delivery) has states `persisted_origin`, `accepted_relay`,
`persisted_target`, and `presented`, ordered 0 through 3. Its one event is a delivery update
reporting a stage S'; relative to the machine's current state (the highest stage already reached
for the object), the update is classified `advance(S')` when S' is strictly greater than the
current stage, `repeat(S')` when S' equals it, and `regress(S')` when S' is strictly less than it.
`advance(S')` transitions directly to S', not merely to the next stage in sequence: a stage MAY be
skipped (for example a relay-less delivery path observing `persisted_origin` followed directly by
`persisted_target`, with no `accepted_relay` in between), because skipping a stage is not a
regression -- only `regress(S')` is. `repeat(S')` -- the same stage reported a second time, such as a
redelivered acknowledgment -- is accepted idempotently and leaves the state unchanged; it is not an
error and produces no new observable state.

| State | Event | Reaction |
|---|---|---|
| persisted_origin | advance(S') | -> S' |
| persisted_origin | repeat(S') | -> persisted_origin |
| accepted_relay | advance(S') | -> S' |
| accepted_relay | repeat(S') | -> accepted_relay |
| accepted_relay | regress(S') | reject (StageOutOfOrder) |
| persisted_target | advance(S') | -> presented |
| persisted_target | repeat(S') | -> persisted_target |
| persisted_target | regress(S') | reject (StageOutOfOrder) |
| presented | repeat(S') | -> presented |
| presented | regress(S') | reject (StageOutOfOrder) |

The machine's initial state for an object is established by that object's first delivery update:
the first update records the stage it reports and cannot regress, because no earlier stage has yet
been reached for that object; the table above governs every update after the first.

Any (state, event) pair not listed above is rejected with `StageOutOfOrder`.

## Stream state machine

The stream machine (# Streaming) has states `idle` (no stream open for this stream id), `open`,
`committed`, and `abandoned` (a terminal state an `open` stream enters when its idle/commit timer
expires; see # Timers), and events `StreamOpen`, `chunk`, `StreamCheckpoint`, and `StreamCommit`.

| State | Event | Reaction |
|---|---|---|
| idle | StreamOpen (effect authorized) | -> open |
| idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized) |
| open | chunk | -> open |
| open | StreamCheckpoint | -> open |
| open | StreamCommit (digest matches) | -> committed |
| open | StreamCommit (digest mismatch) | reject (StreamDigestMismatch) |
| open | StreamOpen | reject (StreamStateError) |
| committed | chunk | reject (StreamStateError) |
| committed | StreamCheckpoint | reject (StreamStateError) |
| committed | StreamCommit | reject (StreamStateError) |
| abandoned | StreamOpen | reject (StreamStateError) |
| abandoned | chunk | reject (StreamStateError) |
| abandoned | StreamCheckpoint | reject (StreamStateError) |
| abandoned | StreamCommit | reject (StreamStateError) |

Any (state, event) pair not listed above is rejected with `StreamStateError`, which names a
stream-state violation: an object arriving for a stream whose current state does not admit it -- a
second `StreamOpen` on an already-open stream, or any `chunk`, `StreamCheckpoint`, or `StreamCommit`
after the stream has committed or been abandoned. A `committed` or `abandoned` stream id is
terminal: it is never re-admitted, so a `StreamOpen` naming it is rejected `StreamStateError`
rather than opening a fresh stream. A chunk that exceeds its granted
flow-control credit is refused at the transport, not the object, layer (NPAMP-STREAM
`FlowControlError`, # Transport Bindings): that rejection is a property of the specific transport in
use and is distinct from the state-machine violations in this table, which apply uniformly across
every transport binding.

## Approval state machine

The approval machine (# Approval) has states `pending`, `approved`, `consumed`, and `expired`, and
events `approve`, `consume`, and `expiry` (the passing of `not_after`; see Clock skew and validity
windows, below). `ApprovalHeld` is not a fifth state: it is the distinct signed non-success result
an action requiring this approval receives while the machine is in `pending`, never a silent success
or denial. An action requiring an approval for which no Approval object naming its exact args has
ever been signed is refused `ApprovalRequired` at the point of use, independent of this table.

| State | Event | Reaction |
|---|---|---|
| pending | approve | -> approved |
| approved | consume | -> consumed |
| approved | expiry | -> expired |
| consumed | consume | reject (AlreadyConsumed) |
| expired | consume | reject (ApprovalExpired) |

An args-content-id mismatch -- the presented args do not hash to the content id the Approval object
binds -- is rejected `ApprovalMismatch` regardless of state and takes precedence over every cell in
this table, because content binding is checked before any state-dependent reaction is evaluated.
Where an approval is both past `not_after` and already present in the consume ledger, expiry takes
precedence over consumption: a consume request MUST be checked against `not_after` before the
ledger is consulted, so such a request is rejected `ApprovalExpired`, never `AlreadyConsumed`, and
the ledger is left untouched by the rejected request.

Any (state, event) pair not listed above is rejected with `ApprovalRequired`.

## Reconcile state machine

The reconcile machine (# Audit, Causal Graph, and Ordering) governs the production of one federated
Reconcile record. States: `collecting` (per-authority receipt chains are being gathered),
`linearized` (the deterministic total order has been computed), `verified`. Events: `add-chain` (a
per-authority receipt chain is added to the merge), `linearize` (the deterministic linearization is
computed over the accumulated chains), `verify` (an independent recomputation is compared against a
claimed total order).

| State | Event | Reaction |
|---|---|---|
| collecting | add-chain (valid link, no equivocation) | -> collecting |
| collecting | add-chain (broken prev/seq link) | reject (ChainBroken) |
| collecting | add-chain (two receipts, one seq, different objects) | reject (Equivocation) |
| collecting | add-chain (receipt signature does not verify) | reject (ReceiptUnsigned) |
| collecting | linearize (union causal graph acyclic, no future-cause) | -> linearized |
| collecting | linearize (cycle or future-cause in the merged graph) | reject (CausalViolation) |
| linearized | verify (independent recomputation agrees) | -> verified |
| linearized | verify (independent recomputation disagrees) | reject (ReconcileMismatch) |

`ReconcileMismatch` is the one new error name this section introduces: a verifier that
independently re-runs the deterministic linearization (# Audit, Causal Graph, and Ordering) over
the identical set of objects and obtains a total order different from the one the Reconcile record
claims has found a violation of the fixed determinism property that section states, and rejects the
record whole.

Any (state, event) pair not listed above is rejected: a fault in an individual per-authority receipt
chain is rejected under its own already-registered name (`ChainBroken`, `Equivocation`, or
`ReceiptUnsigned`), a cycle or future-cause in the merged causal graph is rejected
`CausalViolation`, and a disagreeing linearization is rejected `ReconcileMismatch`.

## Timers

Every timer named in this section has a name, a start condition, a clear condition, and a named
reaction on expiry. This document specifies each timer's behavior but not its duration: the
interval a timer runs for is a deployment and local-policy parameter, and no timer in this section
carries a protocol-mandated default duration. The hard numeric bounds this document does impose on
the wire -- the per-stream chunk-count limit (`TooManyChunks`, # Streaming) and the decoder resource
limits in the CDDL (# Collected CDDL) -- are stated where they are enforced, not here.

Delivery stage-advance timer:
: starts when a delivery update advances an object's state to any stage before `presented`; clears
  when a later update reports `presented` (or, per the Delivery table above, a `repeat` or a further
  `advance`) for the same object; on expiry, the stalled delivery is reported to the sender as
  undelivered (`NotDelivered`) without changing the object's last durably-recorded stage -- expiry
  ends the wait, not the recorded progress.

Stream idle/commit timer:
: starts when a `StreamOpen` transitions the stream machine to `open`; clears when a `StreamCommit`
  transitions it to `committed`; on expiry, the stream transitions `open -> abandoned` and is
  rejected `StreamStateError`. `abandoned` is terminal (# Object State Machines): no later `chunk`,
  `StreamCheckpoint`, or `StreamCommit` for the stream is admitted, and its stream id MUST NOT be
  reopened -- a `StreamOpen` naming an abandoned id is rejected `StreamStateError`, never re-admitted
  as a fresh stream. No chunk delivered without an eventual `StreamCommit` is non-repudiable
  (# Streaming), so an abandoned stream commits nothing.

Approval not_after timer:
: starts when an Approval object is signed; clears when the approval is consumed (# Approval) while
  still valid; on expiry, the approval transitions `approved -> expired` per the Approval table
  above, and any further `consume` is rejected `ApprovalExpired`.

Pending-cause hold timer:
: starts when an object is received naming a cause (# Audit, Causal Graph, and Ordering) the
  receiver has not yet received, putting the object into the held `pending` state described there;
  clears when the named cause is applied, which lifts the hold and allows the held object's own
  effect to be applied; on expiry, the held object is rejected and its effect is never applied. This
  timer is the bounded interval that section states the pending-cause hold is "resolved ... by
  timeout once the bounded interval elapses."

## Clock skew and validity windows

An Approval's `not_after` (# Approval) is judged against the action's authoritative ordering
position -- its receipt seq/at where a receipt exists (# Audit, Causal Graph, and Ordering) -- and,
only where no receipt yet exists for the action, its advisory `created` timestamp stands in as the
best available position for this one purpose (# Object Model); this narrow fallback does not make
`created` reliable ordering evidence for any other purpose (# Security Considerations). In neither
case is validity judged against any participant's own wall clock: there is exactly one clock in
this check -- the authoritative ordering position -- so wall-clock skew between the approver, the
consumer, and any relay never enters the determination of whether `not_after` has passed. This
document does not define a numeric clock-skew tolerance: a validity check is a single deterministic
comparison against one authoritative position, not a comparison between two participants' clocks,
so no tolerance is required by this design, and none is introduced.

## Cancel

A cancel object -- `TaskCancel` (0x0011/2), `Cancel` (0x000E/3), or a channel-specific cancel object
elsewhere in (# Channel Surfaces) -- MUST propagate a real abort to the work it names: an
implementation that flips a status field to a canceled state without actually stopping the
underlying work has not canceled it, and reporting the canceled status in that condition is a false
report and is non-conforming. Once an object's status has reached a terminal canceled state, no
later transition MAY leave it: a terminal-absorbing guard MUST ensure that a status update
completing the same work after cancellation (for example a late `completed` transition arriving
after `canceled`) is dropped, not applied, so a race between an abort and an in-flight completion
can never overwrite the canceled outcome. This is the general terminal-state rule already stated
elsewhere for an imported task lifecycle -- a terminal state has no out-edge and no transition may
leave it -- applied here to cancellation specifically; it is not a new rule.

## Deadline

Effecting objects are time-bounded today by their required approval's `not_after`, judged at the
action's authoritative ordering position as stated above (# Approval). A distinct, per-object signed
deadline field is out of scope for this revision and is noted here for a future revision.

# Transport Bindings {#transport}

A binding carries exactly one signed object as one message unit, with identical object semantics
over N-PAMP, QUIC, WebSocket, and HTTP. The object is self-secured; the binding adds only framing
and, from the transport, confidentiality and connection authentication. The media type is
`application/vnd.bubblefish.naalp+cbor` (one object per representation).

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
or rewritten. For every carriage class, N-AALP treats the foreign message as opaque octets: it
never decodes or parses the foreign payload, and it binds those octets by hash under the carriage
object's content id and signature. A verifier checks the payload by recomputing that content id
over the carried bytes, never by interpreting the foreign format, so a tampered payload is rejected
on the content-id check before any foreign parser could run. This rule is normative for every
carriage class -- each foreign binding is carriage by class, so no binding adds a foreign-format
parser to the verify path. The carriage object's signer remains the authority: a foreign protocol's identity,
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

# Additive Object Families {#additive}

This section documents the higher-tier (tier 1+) object families this revision adds. None of them
introduces a new envelope field, encoding, signature form, identity mechanism, or effect value: each
family reuses the frozen `naalp-object` envelope (# Object Model), the closed effect lattice
(# Effects and Authorization), the content-id framing (# Object Model), and, where a family is
receipt-chained, the audit receipt chain construction unchanged (# Audit, Causal Graph, and
Ordering). A baseline verifier that has not licensed a family's tier rejects its kind as `UnknownKind`
(# Object Model), consistent with the tier model (# Object Model, # Channel Surfaces). Every
capability in this section carries experimental status under the tiering rule of (# Conformance): it
is OPTIONAL, and an implementation that omits it is still conforming.

## Collaboration and Rooms Membership

A room's membership is a first-class signed object, not implicit connection state. A membership
change is carried as a `naalp-room-op` -- a `naalp-object` whose body (field 10) is `{ room, op,
epoch, subject, role }` -- on the Governance channel (0x0004). `op` selects one of the closed
`room-op-code` operations: create (0), add_member (1), remove_member (2), change_role (3), or
add_owner (4). `subject` (the affected member's signer id) MUST be Unicode NFC (`NonNFC` otherwise).
`role` is one of the closed `member-role` values: member (0), admin (1), or owner (2).

A room-op object is CURSOR-OCCUPYING and RECEIPT-CHAINED: each accepted op is ordered at a cursor by
an ordering authority's `naalp-receipt` over the op's content id, weaving membership into the
append-only audit chain (# Audit, Causal Graph, and Ordering) the same way any other object is
ordered. It is EPOCH-BUMPING: `epoch` carries the membership epoch the op is built against, and each
accepted op increments the room's epoch; an op built against a superseded epoch is rejected
`StaleEpoch`. Ownership is multi-owner and ADD-ONLY: `add_owner` adds an owner, but an owner is never
removed (`remove_member` naming an owner is rejected `OwnerImmutable`) and never demoted
(`change_role` refusing to lower an owner's role is rejected `RoleInvalid`), so a room's owner count
is monotonically at least one and a room can never become ownerless. `remove_member` naming an
unknown member, or `add_member`/`change_role` naming an already-present or already-absent member as
the operation requires, is rejected `MemberExists` or `MemberUnknown` as appropriate; an op whose
fields do not match its declared `op` code is `RoomOpMismatch`; an `op` value outside the closed set
is `OpUnknown`.

A `naalp-principal-binding` maps a stable semantic principal id to a durable Handle (a signer id): `{
principal, handle, epoch, prev }`. `principal` MUST be Unicode NFC. It is kept as a per-principal
SHA-384 hash chain -- `prev` carries the prior binding's head (48 bytes; genesis is 48 zero bytes) --
the same chaining shape as the audit receipt chain and the consume ledger, so an omitted or
substituted binding is detectable the same way. A delivery addresses the semantic principal id and
resolves it to the Handle at send time: a durable naming layer above a connection-scoped peer handle.
A rebind (a new binding for an already-bound principal) is authorized only by a verified rotation
from the current Handle to the new one; a rebind naming an unrelated key is rejected
`RebindUnauthorized`. Binding a principal id already bound is `PrincipalExists`; resolving an unbound
principal is `PrincipalUnknown`. The membership op-authorization, epoch guard, owner-immutability, and
rebind-continuity rules above are endpoint behaviors graded against the non-circular oracle, not wire
productions in their own right.

## Multi-Hop Delegation Grant

A `naalp-delegation-grant` is a normal `naalp-object` -- an independent `COSE_Sign1` whose issuer is
the verified envelope signer (field 5), never a body field -- carried as Capability-channel (0x0002)
kind DelegationGrant (kind 4), tier 1. The object's own envelope effect (field 7) is
`non_idempotent_write` (issuing a grant); the body's `effect_cap` field is a SEPARATE ceiling the
grant confers on its subject, never the object's own effect. The body is `{ subject, effect_cap,
max_depth, not_before, not_after, ?scope }`: `subject` (the delegatee's signer id) MUST be Unicode
NFC; `effect_cap` (the closed effect lattice) MUST NOT exceed the parent grant's own ceiling, else
`CapExceedsParent`; `max_depth` bounds how many FURTHER delegation hops are permitted below this
grant (0 means the subject may act but not re-delegate); `not_before`/`not_after` bound the grant's
validity window (`GrantNotYetValid` / `GrantExpired`); the OPTIONAL `scope` (Unicode NFC when
present) narrows the grant to a resource scope that a child grant's scope MUST be contained within,
else `CapExceedsParent`.

A DelegationGrant reuses the existing Capability-channel delegation substrate rather than a parallel
mechanism: its delegation parent is named by content id in the envelope's `causes` field (# Object
Model) as the UNIQUE cause resolving to a Capability authority object (CapIssue, CapDelegate, or
another DelegationGrant) whose subject/holder equals this grant's issuer. A root grant -- one whose
issuer is in the verifier's trust-anchor set -- names no such cause; a grant naming two or more is
rejected `ChainBroken`. A malformed grant body is `GrantMalformed`; a grant whose chain of authority
does not terminate at a trusted root is `UntrustedChainRoot`; a chain exceeding the accumulated
`max_depth` bound is `DelegationDepthExceeded`; a revoked grant is `GrantRevoked`. The invariant that
delegated authority only ever shrinks across every hop -- on effect, scope, and depth -- is stated as a
closure-sovereignty property in (# Security Considerations).

## MCP Tool-Call Binding

An MCP (Model Context Protocol) tool call is CARRIED, not adopted: its bytes are unchanged, and its
unenforced, untrusted annotation hints are mapped to the closed four-value effect lattice by a
published table for which the wrapping signer is accountable -- a false declaration is attributable
to that key. The wrapper (`naalp-mcp-tool-call`) is a Bridge-channel (0x000D) tier-1 kind McpToolCall
(kind 1), a named escalation over the frozen baseline Carriage kind (0, # Foreign Carriage by Class)
under the unchanged envelope. Its body is `{ tool, args, annotations }`: `tool` and `args` carry the
MCP tool definition and call-argument bytes octet-for-octet (never re-serialized); `annotations`
(`naalp-mcp-annotations`) is the wrapping signer's transcription of the tool's MCP `ToolAnnotations`.

The object's own envelope effect (field 7) is the wrapping signer's DECLARED effect. A verifier
independently recomputes the annotation-derived effect from the carried annotations and enforces the
MORE SEVERE of the two values -- an unknown or disagreeing input collapses UP, never down. A declared
effect below the annotation-derived effect is rejected `EffectUnderDeclared`; an annotation set that
maps outside the closed lattice is rejected `MalformedAnnotation`, never defaulted to benign. Each
annotation field (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) is an OPTIONAL
`mcp-hint` -- the uint 1 (true) or 0 (false); a value outside `{0,1}` transcribes no boolean and is
rejected. MCP is boolean-typed in JSON but the N-AALP spine carries no CBOR boolean, so an ABSENT hint
takes the MCP-documented default: `readOnlyHint` false, `destructiveHint` TRUE (the fail-closed
default, matching the "absent effect on a state-changing object defaults to destructive" rule),
`idempotentHint` false, `openWorldHint` true. A present `0` and an absent hint therefore encode to
DIFFERENT bytes even where they resolve to the same effect. `openWorldHint` is carried for
accountability only -- it is an ADVISORY risk signal that never enters the effect lattice.

`naalp-mcp-call-binding` (`{ tool_id, args_id }`) is the value an approval binds: `tool_id` and
`args_id` are the content ids of the tool and argument bytes respectively. Because the binding names
BOTH the tool description and the arguments by content id, a changed tool description or a changed
argument set yields a different call content id, invalidating a prior approval bound to the old one.
A malformed tool-call body is `ToolCallMalformed`.

## Description and Directory

A signed, OFFLINE-VERIFIABLE description and discovery layer, carried on N-AALP's own signed object:
the authority is the SIGNATURE OVER THE BYTES, never the connection or host that served them, so a
signed description re-verifies byte-identically when an unrelated host serves the same bytes (a
bearer credential, not a fetched document). A `naalp-description` (`{ service, operations }`) lists a
service's operations, each a `naalp-description-operation` (`{ name, effect, requires_approval }`)
carrying its effect (the closed lattice) and an approval declaration: `requires_approval`
(`desc-approval-flag`, the uint 1/0 -- the spine carries no CBOR boolean) outside `{0,1}` is rejected
`MalformedApprovalFlag`.

A `naalp-directory` (`{ directory, version, members }`) is a signed collection whose members are
content ids (the same list-of-content-ids shape the causal partial order uses), carrying a monotonic
per-signer `version` so two versions can be compared. Two conflicting versions from ONE signer -- the
SAME directory and version but DIFFERENT members -- are a FORK, detected at the FIRST-DIFFERING member
position and reported `DirForkProofInvalid`, the same way the audit ForkProof reports the position of
an equivocation (# Audit, Causal Graph, and Ordering).

A `naalp-description-import` (`{ importer, format, foreign, operations }`) carries a FOREIGN
description format -- an A2A Agent Card, an ANP Agent Description, or an AGNTCY Agent Badge, selected
from the closed `naalp-description-format` registry (a2a-agent-card 1, anp-agent-description 2,
agntcy-agent-badge 3; an unrecognized value is `UnknownDescriptionFormat`) -- octet-for-octet in
`foreign` (carriage, not adoption: the foreign bytes MUST NOT be re-serialized, canonicalized, or
rewritten) as a signed attestation binding the foreign bytes' content id AND an N-AALP effect mapping
(`operations`) for the described operations. `importer` is the wrapping signer id and is the SOLE
authorization identity: a verifier recomputes the self-certifying signer id from the verifying key
and requires `importer` to equal it (`ImporterMismatch` otherwise), so a foreign identity embedded in
`foreign` NEVER becomes an N-AALP authorization identity -- the confused-deputy rule the MCP profile
above also applies. A malformed description body is `DescMalformed`.

## Name Bindings and A2A Task Transitions

Two receipt-CHAINED, OFFLINE-WALKABLE surfaces reusing the audit receipt-chain construction
unchanged: the head of each object is SHA-384(body), the genesis `prev` is 48 zero bytes, `seq` is
monotonic, and the body carries the prior head in `prev`, so editing or omitting a record breaks the
next record's linkage.

A `naalp-name-binding` (`{ name, signer, seq, prev }`) maps a durable, human-readable `name` to a
signer id and chains onto the prior binding for that name. A key ROTATION for a name is a NEW binding
at the next `seq` naming the new signer; a binding is dated by its chain position (`seq`), not by the
envelope's advisory `created` field. A name's history is walkable offline; a deleted or omitted
binding leaves a detectable HOLE at the first-broken position, reported `NameChainBroken`; two
bindings by ONE authority at the SAME `(name, seq)` naming DIFFERENT signers are a FORK, reported
`NameForkProofInvalid` at that `seq`. A malformed binding is `NameMalformed`; a binding signed under a
key that does not match the claimed signer is `VerifierKeyMismatch`.

A `naalp-task-transition` (`{ task, card, from, to, seq, prev }`) is one signed, receipt-chained A2A
(Agent2Agent) task-lifecycle state transition. The `task-state` set -- submitted (0), working (1),
input-required (2), auth-required (3), completed (4), canceled (5), failed (6), rejected (7) -- is an
IMPORTED vocabulary (carriage, not adoption): the A2A specification Section 4.1.3 defines these eight
states and their terminal/interrupted categories NORMATIVELY (start = submitted; terminal =
{completed, canceled, failed, rejected}; interrupted = {input-required, auth-required}), and N-AALP's
legal-edge table is DERIVED from those documented category rules and enforced by the endpoint, not by
this wire production, which carries only the `from`/`to` state values. `card` is the content id of the
A2A Agent Card attestation (a `naalp-description-import` with format a2a-agent-card) binding the task
profile to an agent/operation; a transition carrying a `card` other than the profile's bound card is
rejected `ForeignCard`. An illegal edge, a non-contiguous `from`, a transition out of a terminal
state, or a gap or reorder in the chain is rejected fail-closed `IllegalTransition` or
`TaskChainBroken`, with the violating position reported.

## Governed Negotiation

Three signed surfaces reusing the closed effect lattice, the content-id framing, and the causal
partial order (`causes`) unchanged: offer, counter, and accept are SIGNED, CAUSALLY-LINKED messages,
each naming its predecessor(s) by content id in `causes` (the same shape the causal partial order
uses). Each SELECTS a profile from the CLOSED, PRE-REGISTERED `negotiation-profile` set -- baseline
(0), streaming (1), or batch (2) -- never a free-form capability string and never a runtime-generated
handler; an unknown profile is rejected `UnknownProfile`.

The three productions -- `naalp-negotiation-offer` (`{ negotiation, role, profile, causes }`),
`naalp-negotiation-counter`, and `naalp-negotiation-accept` -- are distinguished by a fixed `role`
literal from the closed `negotiation-role` set (offer 0, counter 1, accept 2), so an offer body never
validates against the accept production and vice versa; a role value outside the set, or a body whose
fixed-literal field disagrees with its production, is rejected `UnknownRole` (`NotOffer`/`NotAccept`
name the specific offer/accept-shape mismatch). An offer is the root of the exchange and carries no
`causes`; a counter chains onto the offer or a prior counter; an accept MUST DESCEND from its offer
along the `causes` DAG, enforced by the endpoint (`NotDescended` otherwise). A malformed negotiation
body is `NegMalformed`.

## Advisory Risk Labels

A `naalp-risk-label` (`{ code, critical }`) carries one label: `code` (`risk-code`, an open uint -- a
closed standard vocabulary plus a private/experimental extensible range, enforced by the endpoint and
a registry the same way the per-signer counter's value space is open, # Object Model) and `critical`
(`risk-critical`, the per-carriage must-understand flag: 1 critical, 0 advisory -- the spine carries no
CBOR boolean). A `naalp-labeled-object` (`{ effect, labels }`) carries an object's effect together
with a set of risk labels. The critical-extension rule (# Object Model) applies to labels the same way
it applies to `ext`/`cext`: an unknown CRITICAL label is rejected `UnknownCriticalRisk`, and an
unknown non-critical one is ignored; a critical flag outside `{0,1}` is `MalformedCriticalFlag`.
LOAD-BEARING INVARIANT: a risk label is an ADVISORY dimension, NEVER a fifth effect -- carrying a
label never changes the object's effect class, and the closed four-value effect lattice
(# Effects and Authorization) is untouched by this family.

## Flow Continuations

A long-running flow costs exactly two full ML-DSA signatures -- `FlowOpen` and `FlowCommit` --
regardless of the number of intermediate steps, generalizing native streaming (# Streaming) from a
byte stream to a flow of typed steps. `naalp-flow-open` (`{ flow_id, effect_ceiling, approvals }`) is
a fully signed `naalp-object` that fixes the flow's effect ceiling and its approval bindings; its
authority is reconstructable from its own bytes alone. Its head (SHA-384 of the body) anchors the
chain, and its content id is carried by every child object as `flow_open_id`; a continuation naming a
different `flow_open_id` than the one it chains from is rejected `WrongFlow`.

A `naalp-continuation` (`{ flow_open_id, seq, effect, payload_id, prev }`) is a cheap, UNSIGNED
hash-chain link: its head is SHA-384(body), and `prev` is the previous link's head (the FlowOpen's own
head for `seq` 0). Its `effect` MUST NOT exceed the FlowOpen's `effect_ceiling`, else `AboveCeiling`.
`payload_id` is the content id of that step's payload, carried separately so the continuation itself
stays small. A `naalp-flow-checkpoint` (`{ flow_open_id, through_seq, head }`) confirms a contiguous
prefix of the chain through `through_seq`; a dropped or reordered link short of that prefix is
`GapDetected`. `naalp-flow-commit` (`{ flow_open_id, final_head }`) binds the FINAL chain head under
the second full signature, closing the flow; a missing or altered link relative to the committed
`final_head` is `CommitMismatch`. The four body shapes (3, 5, 3, and 2 fields respectively) are
structurally distinct, so domain separation between them needs no additional tag.

## Governed-Decision Records and Transparency Log Primitives

This family carries the accountability triple natively -- UNIQUE SELECTION, GOVERNED-AT-T, and
BINDING-FIXED-BY-T -- as three signed, additive sibling productions; none moves `naalp-version`.

An `ordering-disclosure` (`{ basis, ?boundary, ?mechanism, ?relation }`) states what, if anything,
establishes a record's order relative to the event it concerns, and from which observational domain,
via the closed `ordering-basis` set: correspondence-only (0) -- the weakest claim, ON PURPOSE, meaning
a record that says nothing about ordering, and an existing record whose ordering field is ABSENT, are
BOTH read as correspondence-only (a verifier MUST NEVER infer a stronger ordering claim from silence);
single-boundary (1) -- one covering boundary (`boundary`, a signer id) attests the order; or
external-mechanism (2) -- `mechanism` names an external sequencing mechanism and OPTIONAL `relation`
binds this record under it (for example, the content id of a `naalp-checkpoint-root` the record is
included under). Field presence is fail-closed and native: correspondence-only requires keys 2-4
absent; single-boundary requires key 2 present and 3-4 absent; external-mechanism requires key 3
present (4 optional) and 2 absent; any other combination is `OrderingDisclosureMalformed`. Whether an
external mechanism's operator is genuinely distinct from both parties is a structural deployment fact
checkable in substance later, not a claim the wire itself can close. A `term-disposition` (`{ kind,
?source }`) reuses the producing-boundary kind codes (1 observed, 2 reported; # Object Model) to state
whether one term of a record was observed first-hand or is relayed from `source`; a `code` outside
`{1,2}` or a `source` present under `observed` is malformed. `enforcement-disposition` is a closed pair:
enforced (1) or advised (2).

A `naalp-decision-record` (`{ action, governing, ?consume, outcome, ordering, ?terms, ?enforcement }`)
is the SIGNED record a governed decision point emits stating that it decided about `action` under a
CLOSED, uniquely selected condition set. `governing` names that set in the clear as content ids -- may
be empty when the decision is governed by standing policy alone, naming that policy object's content
id instead (UNIQUE SELECTION: identification and availability together). The OPTIONAL `consume` names
the `naalp-consume-receipt` that spent the governing authority at decision time (GOVERNED-AT-T): it is
PRESENT for an allow that consumed a single-use authority and MUST be ABSENT for deny/hold, since a
refusal consumes nothing (a deny/hold body carrying a `consume` reference is `DecisionMalformed`).
`outcome` reuses the closed `gw-decision` set (# Security Considerations). `ordering` is MANDATORY --
the record states its ordering basis or states correspondence-only; there is no silent default, and an
unrecognized basis value is `UnknownOrderingBasis`. The OPTIONAL `terms` map keys per-term dispositions
by THIS record's own field numbers 1..5 (a key outside that set is `TermDispositionMalformed`), and the
OPTIONAL `enforcement` states whether the producer enforces the outcome or only advises it -- the
producer's own unverifiable self-account. The record is deliberately CLOCK-FREE: it carries no claimed
time, and both time properties above are POSITIONAL, never a self-asserted timestamp; the signature
binds THE DECISION, not a retrieval of it.

A `naalp-checkpoint-root` (`{ log, size, root, prev, at }`, an RFC 9162-style construction) is a log
operator's SIGNED Merkle tree head over a leaf set of record content ids -- the NEITHER-PARTY ANCHOR
PRIMITIVE (BINDING-FIXED-BY-T). Tree construction follows {{RFC9162}} Section 2.1: leaf hash =
HASH(0x00 || leaf), interior node = HASH(0x01 || left || right), instantiated with SHA-384 (48-byte
heads); the 0x00/0x01 prefixes supply leaf/node domain separation. Checkpoints chain by `prev`
(genesis 48 zero bytes), so a withheld or reordered checkpoint breaks a link, reported
`CheckpointMalformed` on a structurally invalid checkpoint. A `naalp-witness-cosign` (`{ witness, root,
at }`) COUNTERSIGNS one exact checkpoint by content id; the wire carries the cosignature, while
whether the witness's observational domain is genuinely distinct from both parties is a structural
deployment fact a later verifier checks in substance -- the wire hook for the neither-party property,
stated honestly as a hook rather than a guarantee. A cosignature naming a root that does not match the
checkpoint it purports to cover is `WitnessRootMismatch`.

A `naalp-inclusion-proof` (`{ root, leaf, index, path }`) proves that a leaf existed in the tree a
named `naalp-checkpoint-root` commits to (RFC 9162 Section 2.1.3.1 path recomputation, SHA-384
profiled): recording a content id as a leaf under a witnessed checkpoint establishes
existed-no-later-than-the-checkpoint, closing the BINDING-FIXED-BY-T leg. Verification recomputes the
path bottom-up from `leaf` at position `index` using the sibling hashes in `path` and compares the
result against `root`, fail-closed `InclusionProofInvalid` on any mismatch.

## Portable Egress Evidence

A `naalp-egress-attestation` (`{ binding, digest, effect, audience, at, ?ordering }`) is a SIGNED
attestation a gateway or sidecar emits that an object of a given effect class, bound to a given
audience, crossed an egress boundary at a given time -- third-party re-serve, payload-free. `binding`
selects one of the closed `egress-binding` values: content-bound (0), where `digest` is the crossed
object's own content id, or content-free (1), where `digest` is a hiding commitment
SHA-384(content_id || salt), openable later only by the gateway revealing the content id and salt out
of band. `effect` is the crossed object's effect class and `audience` is its bound destination
(empty-permitted). The OPTIONAL `ordering` (an `ordering-disclosure` above) states the attestation's
ordering basis; its absence is read correspondence-only, never a stronger claim. A malformed
attestation is `EgMalformed`; an unrecognized `binding` value is `UnknownEgressBinding`.

## Manufacturing Physical-Hazard Claims and Authorizations

`hazard` is a dimension ORTHOGONAL to `effect`: `effect` (# Effects and Authorization) is DATA
reversibility (can the state change be undone); `hazard` is PHYSICAL danger -- a data-reversible
action may still be a high physical hazard (for example, a tool re-approaching a work envelope). The
two are never merged, and neither is derived from the other. A hazard CLAIM (`naalp-hazard-claim`)
rides as the critical `cext` key 16 on the acting object (# Object Model); a hazard AUTHORIZATION
(`naalp-hazard-authorization`) is a standalone Governance-channel (0x0004) kind 7 object, referenced by
the acting object's `causes`. All numeric bounds in this family are fixed-point integers (signed
millimeters for position, unsigned millimeters-per-second for speed) -- no floats, per the spine's
deterministic-CBOR subset (# Object Model) -- and map keys are 1-based.

`hazard-class` is a CLOSED 0..4 enum: none (0), tool-actuation (1), thermal (2), energy-release (3),
motion-in-shared-space (4). This closed set carries a DECODE-TIME rule mirroring `effect`'s
unknown-value handling: an absent or unrecognized raw hazard value MUST normalize to the HIGHEST class
(4), never to none or a weaker value, so a missing declaration fails safe (`HazardUnknown` when no
claim exists at all; else `HazardNotCovered` against a lower-class grant) -- a rule CDDL cannot itself
express, since it governs the absence or invalidity of a raw wire value, so it is stated here as a
MUST on the decoder. `spatial-bounds` (`{ frame, axes }`) names a coordinate frame (`frame`, which MUST
be Unicode NFC, `NonNFC` otherwise) plus a signed axis-aligned bounding region in that frame: `axes`
MUST be non-empty and every `[min, max]` entry MUST satisfy `min <= max`, else `HazardMalformed`. The
frame id is integrator-defined; N-AALP requires only that a claim's frame id equal the authorization's
for containment to be checkable. `hazard-window` (`{ not_before, not_after }`) is a validity window in
the spine's epoch-ms convention. `hazard-envelope` (`{ spatial, speed_bound, window }`) is the full
physical envelope a claim or authorization bounds itself by; all three fields are MANDATORY -- a
silently absent axis, speed, or window is a MALFORMED envelope (`HazardMalformed`), never treated as
"unconstrained," which would fail OPEN in a physical-safety context.

`naalp-hazard-claim` (`{ class, envelope }`) and `naalp-hazard-authorization` (`{ class, envelope }`)
share the identical `{ hazard-class, hazard-envelope }` shape; both fields are mandatory in each, else
`HazardMalformed`. Coverage of a claim by an authorization requires an EXACT class match AND full
containment of the claim's envelope in the authorization's: the frame id equal; the same axis count
and order; every claim axis inside the matching authorization axis; the claim's `speed_bound` no
greater than the authorization's; and the claim's window a sub-interval of the authorization's window.
Any single failing dimension denies the WHOLE claim (`HazardNotCovered`) -- there is no partial
authorization.

# Security Considerations {#security}

Mandatory-to-implement algorithms and post-quantum rationale: N-AALP signs with ML-DSA
{{FIPS204}}, a post-quantum signature, because N-AALP objects (receipts, approvals, audit chains)
are long-lived non-repudiable records subject to store-now-verify-later forgery risk from a
future cryptographically relevant quantum computer; a classical-only signature on such records
would be a latent forgery exposure. An optional Ed25519+ML-DSA composite provides defense-in-depth
during the transition; it is a single non-separable LAMPS composite, so it is accepted only when
both components verify and a stripped object has no valid signature at all. Pure ML-DSA is SUF-CMA;
the opt-in composite is EUF-CMA but not SUF-CMA, which is not load-bearing because N-AALP never
keys a security decision off raw signature bytes.

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

External code-point stability: the key-type codes 0xed, 0x1211, and 0x1212 that signer-id
derivation uses (# Identity) originate in the external multiformats table, a registry N-AALP does
not govern. If that upstream table ever reassigned one of these three codes to a different meaning,
an implementation that resolved `mc` by looking the key type up in the live table would derive a
different signer id than an implementation that used the value current when it was built, silently
splitting the identity space. N-AALP closes this dependency by pinning all three values as its own
normative constants (# Identity) rather than by indirection through the upstream table, so
signer-id derivation stays fixed under this specification regardless of any later upstream
reassignment.

Effect and authorization: the effect is an authorization input, not a hint; an unrecognized
effect fails closed to destructive; authorization is never derived from transport metadata or a
foreign principal. This closes the gap a pure intent label leaves open.

Effect inflation as an availability risk (accepted and stated): the effect lattice has an abuse
direction. A malicious wrapping signer can mark ordinary actions destructive so that everything
demands an approval and throughput collapses, and attribution identifies who did it only after the
fact. N-AALP does not prevent this on the wire and does not pretend the lattice has no abuse
direction; it is an accepted risk, mitigated operationally by attribution -- every object binds to a
signer id -- together with per-signer rate limiting applied by the deployment. Rate limiting is a
deployment control rather than a wire field, stated here as an operational obligation, not a format
guarantee.

Continuation compromise, honest limit: a node compromised inside an open flow can keep emitting
continuations up to the ceiling. The ceiling bounds the damage. It does not prevent it. The flow's
effect ceiling caps the severity any continuation can reach, so the damage is bounded to actions
within that ceiling; but until the flow is closed or the compromised key is revoked, the
compromised node keeps acting within it. This limit is stated plainly here rather than left for a
reviewer to infer.

Denial of service: an object requires one signature verification and one deterministic decode;
verification is fail-closed and performed before any state change or effect. Streaming amortizes
one signature over many chunks. Implementations SHOULD bound object and stream sizes by policy.

Cost-ordered verification (cheapest checks first): a verifier SHALL perform its checks in
increasing order of cost and reject on the cheapest failing check before it performs the signature
verification. The cheap checks -- deterministic decode, content-id recomputation, field-range
checks, protected-header/body agreement and version, critical-extension recognition, and
kind/channel dispatch -- all run before the ML-DSA signature verification, which is the most
expensive step and is therefore last. Because the expensive step is last, a flood of mismatched or
malformed objects is rejected on a cheap check and cannot force a signature verification on
attacker-controlled bytes; the cost of rejecting garbage is bounded by the cheap checks, not by the
post-quantum signature.

Confidentiality: object-level guarantees do not include confidentiality; a sensitive object MUST
use a confidential transport (# Transport Bindings), enforced by refusal.

Offline verification proves validity-at-issue, not current unspent-ness: a signature verified
offline proves an approval was well-formed and authorized when it was issued; it does NOT prove
the approval is still unspent. Spent-or-unspent is state held at the consume ledger
(# Approval), not a property of the object's bytes. A verifier that treats a syntactically valid,
unexpired approval as spendable without consulting the ledger has confused attributability at the
moment of issue with current spendability.

Exposure and reconciliation cadence: a relying party that accepts a consume receipt during a
network partition, before that receipt has been compared against the receipt sets held by other
parties, is exposed to a conflicting spend it cannot yet see. Its exposure is a function of its
own reconciliation cadence -- the window between accepting a receipt and next comparing its
receipt set against the others -- multiplied by the value at risk in that window (the rate, in
value per unit time, at which double-spendable value is being accepted). N-AALP makes no liveness
promise here: the format does not bound how quickly a conflicting spend elsewhere becomes
visible, and it is the relying party, not the format, that lowers its exposure by reconciling
more often. Cadence is a parameter the exposed party sets, not a guarantee the format provides.

Worked exposure example: a party reconciles on a 3,600-second (one hour) cadence and, within one
such window, accepts approvals whose combined double-spendable value arrives at a value at risk
of $5,000 per second. Its worst-case exposure across one unreconciled window is
(value at risk) x (window length) = $5,000/s x 3,600 s = $18,000,000 that could be double-spent
before the next comparison detects the conflict. Cutting the reconciliation cadence to 60 seconds
cuts the window length, and the exposure with it, by 60x, to $300,000. The exposure figure is set
entirely by the party's own cadence and value at risk; the object bytes do not change, and the
protocol computes none of it.

Baseline consume under an unreachable ledger: at the baseline tier, an executor that cannot reach
the consume ledger SHALL deny the spend (this is the normative rule of (# Approval), restated
here for its security weight). Local spend-and-reconcile-later is not a baseline behavior; a
consumer that spends locally while the ledger is unreachable is non-conforming. This is the
fail-closed choice -- under partition the baseline refuses rather than risk an undetected double
spend -- and federated ordering over identical signed objects, which trades this refusal for the
bounded exposure modeled above, is a named higher tier only.

Attributable versus checkable: a signature makes a statement attributable to a signer -- it binds
the bytes to a key -- but attributability is not the same as checkability. A statement is
checkable only if a stranger who trusts no one can re-derive the claim for themselves. A checkable
claim (a) says what it is about, (b) carries the evidence it rests on, directly or by content id,
and (c) names the procedure that re-checks it. N-AALP already delivers (a) and (b) for its
structural claims: the content id recomputes from the bytes, so anyone can confirm the id names
these exact bytes, and the causes field is a signed partial order a stranger can walk offline. An
object that carries a body claim without naming the procedure that re-checks it is attributable
only, and this specification says so plainly: absent (c), a relying party has the signer's word,
not an independent re-derivation.

The per-signer forward-only counter is detection, not prevention: N-AALP MAY define a forward-only
per-signer counter that a signer increments on each object. Its purpose is detection, not
prevention: it exists to detect key duplication, not to stop it. A counter a signer writes about
itself proves nothing on its own, because once a key is duplicated both the legitimate holder and
the thief emit locally consistent, monotonic sequences, and neither sequence contradicts the other
in isolation. The duplication becomes provable only when two conflicting sequences bearing the same
signer id physically meet somewhere the attacker cannot suppress; until that meeting the counter
has detected nothing. The counter's value is therefore contingent on a reachability property the
wire cannot guarantee -- that the conflicting evidence reaches a common observer -- and this
specification states that dependency rather than implying the counter prevents duplication. The
sharper contradiction, authored by neither the requester nor a thief, is carried by the
ledger-signed consume receipt (# Approval), not by the self-authored
counter.

Correspondence is not precedence: the causal graph (# Audit, Causal Graph, and Ordering) and
parent-by-content-id let a stranger establish record order offline -- an object that names another
as a cause existed no later than its effect, within the two-party construction that produced them.
That is not cross-trust-boundary event precedence. Each boundary's observational domain is
authoritative only within itself, so ordering two boundaries' events against each other requires an
ordering authority whose observational domain is neither party; the baseline single-authority
ordering (# Audit, Causal Graph, and Ordering) does not guarantee an authority that is neither party,
so cross-boundary precedence is a higher-tier or deployment property, not a baseline guarantee. The
OPTIONAL `producing-boundary` disclosure (`ext` key 15, # Object Model) makes the one fact an object
can honestly assert explicit -- whose domain observed the event, and whether first-hand or relayed --
and a relying party that needs precedence across a boundary composes it with an independent ordering
authority. One such construction is a Transparency Service as defined in {{RFC9943}}, whose own
Section 9.1 (Ordering of Signed Statements) states that a relying party cannot assume the
registration order matches the issuance order unless the service's registration policy advertises
it, and whose Section 9.2 (Accuracy of Statements) states that registering a statement only proves
it was produced, not that it is accurate -- the same limit, stated by an independent standard.

Custody continuity and rotation dating: a valid signature proves the signer held the private seed
at signing time and nothing more; it does not prove continuous custody. draft-01 does not solve
rotation-continuity, because a successor (rotation) statement signed by an old key can be forged by
a thief who holds that old key, and the forged handoff verifies. What the design provides instead
is dating after the fact. The created timestamp (field 6) is advisory only and MUST NOT be relied
on as ordering evidence; the receipt-chain position is the record of when a statement happened
(# Audit, Causal Graph, and Ordering). A rotation statement is dated by where it lands in the
receipt chain, the same as any other object. On discovery of a theft there is a specific receipt
position to cut at -- a cut position -- before which the history is still provable from the original
signatures. Because the mandatory signatures are post-quantum (ML-DSA), the pre-cut history stays
checkable for years after the compromised keys are gone.

Worked custody timeline: at receipt position 100 a key K is used legitimately. At position 140 the
key is stolen and the thief immediately signs a rotation from K to the thief's own key K'. At
position 200 the theft is discovered. The relying party sets the cut position at 140 -- the earliest
position it can attribute to the thief, or, where that is uncertain, the last position it can vouch
for. Every object at receipt position below 140 remains verifiable from its original ML-DSA
signature and its receipt-chain position, independent of K's later compromise; objects at position
140 and after, including the forged rotation, fall outside the cut and are not trusted on K's
authority. The forged handoff still verified as bytes -- dating does not prevent it -- but the
receipt-chain position gives the relying party a defined cut position and a pre-cut history it can
still stand on.

The never-signs-again case: if the legitimate holder never signs again after a theft, the case is
undecidable from the signer's own bytes: as far as the signer's own signatures can prove, the
thief is that identity from the moment of theft onward, because every subsequent signature verifies
under the stolen key and there is no later legitimate signature to contradict it. Anything that
resolves this works from statements other parties make -- counterparty acknowledgments, obligations
that settled, an observer outside the thief's reach -- and N-AALP carries exactly those as checkable
signed objects. The weighing of that outside evidence is left to the relying party, to whoever
decides to transact, and is not a property the wire computes. N-AALP does not pick a trust graph:
this revision deliberately encodes no trust-weighting scheme into the object, keeping the line
between what the protocol carries -- checkable evidence, and refusal when required evidence is
missing -- and what the deployment decides -- who to believe -- where it belongs.

Third-party trust statements are carriage, not adjudication: N-AALP carries third-party trust
statements -- attestations, reputation assertions, and external-registry references such as an
ERC-8004-style identity or reputation registry record -- as checkable signed objects, each naming its
subject and carrying the external record it references by content id, so a relying party re-derives
the reference for itself rather than trusting the connection that delivered it. The wire carries
these statements and weighs none of them: no wire field scores a trust statement, ranks two
conflicting attestations, or selects among registries, because the protocol takes no position on
which trust statement outranks which. A carried reputation or registry reference therefore verifies --
its content-id recomputes and its signature checks -- without the protocol computing any score from it;
which statement to believe remains a decision for the deployment, not one the wire performs.

Payment import, user-interface consent, and portable gateway evidence add guarantees around imported
and human-in-the-loop actions without introducing a new effect, ledger, or policy mechanism. A payment
instruction issued in a foreign format -- an AP2 mandate, an Agentic Commerce Protocol delegated token,
an x402 payload -- is carried octet-for-octet and imported as a single-use approval: imported payment
instructions become single-use approvals bound to the amount, currency, payee, and the carried
payload's content id, so a wrong amount or payee no longer matches the approval and a replayed payment
authorization is rejected by the consume ledger. The imported format (`naalp-payment-format`) is one
of a closed, registered set -- an AP2 mandate, an Agentic Commerce Protocol delegated token, or an
x402 payload -- and an unrecognized format is rejected `UnknownPaymentFormat`; the value an approval
binds (`naalp-payment-charge-binding`) carries the same fields as the import (`naalp-payment-import`)
with the foreign payload replaced by its content id, so the binding names the exact value approved
without re-embedding the foreign bytes. A user-interface approval binds the exact action
shown by content id, with the shown tool-lifecycle events (`naalp-ui-event`) receipt-chained so the
shown sequence is provable and an omitted event is detected at its position; an action other than the
one shown and approved has a different content id and is refused. The shown-event stream is one of a
closed vocabulary -- shown, args-shown, approved, or rejected (`ui-event-kind`) -- and an event outside
that set is rejected `UnknownUIEventKind`; a malformed event body is `UIMalformed` and a broken
receipt chain is `UIChainBroken`. A gateway decision (`naalp-gateway-decision`) is portable evidence whose
authority is the signature over its bytes, not the connection that delivered it, so it re-verifies
identically when a party other than the gateway serves it; it carries the decision, the action it is
about, and the deciding policy's identity as an opaque name, and defines no policy language. The
decision is one of a closed vocabulary -- allow, deny, or hold (`gw-decision`); an unrecognized value
is rejected `UnknownGatewayDecision`, and a malformed body is `GwMalformed`. A gateway decision MAY
additionally carry an ordering disclosure (# Additive Object Families) and, where the decision was
made over foreign-protocol evidence, a `naalp-foreign-profile-pin` naming the foreign evidence
profile's identifier and the specific revision pinned at decision time, so a later revision of that
foreign profile cannot be silently substituted for the one the decision actually evaluated.

Signing outside the page context (browser and WebMCP bindings): where N-AALP signing is exposed
to a web page -- for example a WebMCP-style in-browser binding -- the signing operation MUST be
performed outside the page script context, in an isolated signer (a browser-extension background
context, a distinct origin, or a platform key store) that the page cannot script. The page MAY
request a signature over a named object but never holds the signing key or the signing routine, so
a compromised or malicious page can request but never forge a signature and cannot exfiltrate the
key. A binding that signs inside the page script context is non-conforming.

What N-AALP does NOT defend against: it does not provide confidentiality by itself (that is the
transport's); it cannot force an ordering authority to deliver events it chooses to withhold (a
chain reveals equivocation and omission-of-known-events but cannot compel delivery); it does not
provide cross-trust-boundary event precedence at the baseline tier (the causal graph proves record
order, not event precedence across trust boundaries -- see the correspondence-is-not-precedence
discussion above); it does not police the semantic correctness of a carried foreign message beyond
octet-exact carriage; it does
not prove an offline-verified approval is still unspent (that is consume-ledger state, bounded by
the reconciliation cadence and exposure model above); it does not make a self-authored per-signer
counter proof of anything until two conflicting sequences meet where the attacker cannot suppress
them; it does not solve rotation-continuity or the never-signs-again theft from the signer's own
bytes (it provides dating and a cut position, not prevention); and it does not defend against a
signer that is itself authorized and malicious (it makes that signer's actions attributable and
auditable, not impossible).

## Trust-decision closure sovereignty {#closure}

A relying party's decision to act on an authenticated party's object is trustworthy only when that
decision depends only on inputs outside the authenticated party's influence -- transitively, so that an
input's own inputs are inputs. Where the authenticated party does influence an input, that influence
MUST take one of exactly three safe shapes: verifiable, attenuating, or committed. A verifiable
influence is a fixed function of bytes the party cannot forge and is recomputed by the relying party; an
attenuating influence can only reduce the party's own authority; a committed influence is mixed with an
independent contribution the party cannot bias. An input safe in none of the three, and not otherwise
checkable, is treated as unverified and MUST fail closed. This property is already enforced across
N-AALP's identity, encoding, conformance, delegation, approval, and negotiation requirements; the
paragraphs below close the remaining inputs.

Verification MUST be deterministic: an implementation performs verification as deterministic code whose
control flow does not depend on unverified content, and no part of an object under verification reaches
a model or inference component before it is deterministically accepted. This keeps an agent-native
relying party -- one whose evaluator is itself a model -- from having its trust decision steered by the
very bytes it is judging.

A refusal or deny outcome is a signed, attributable, fail-closed record, and a refusal returns only a
coarse outcome to the authenticated party -- a single value from a closed vocabulary together with the
content id of the signed record, and nothing more. Discriminating detail is carried only in the signed
record an auditor reads, so that repeated refusals cannot serve an adaptive party as an oracle. A
party-visible outcome that carries discriminating detail, or omits the record content id, is a refusal
detail leak.

A standalone judgment that a credential is in force at the present moment rests on time the party cannot
supply. A credential's present-moment freshness is judged against a clock the authenticated party does
not provide, and the ordering authority is structurally distinct from the party being authenticated, so
the party whose credential would expire is never itself the source of the time against which expiry is
judged.

Where a verdict or approval travels beyond the context that produced it, a portable verdict names the
context in which it is valid, and a relying party checks that named context at use, so a verdict sound
for one context cannot be replayed into another the party chose. Naming a context is optional -- an
approval that names no context is unrestricted by the issuer's choice, and a deployment MAY require one
by local policy -- but the check is mandatory when a context is present.

Delegated authority only ever shrinks: derived authority is non-increasing across every hop of a
delegation chain, on effect, scope, and depth, whether the chain is read leaf-to-root or root-to-leaf; a
hop that would raise authority denies the whole chain.

# Privacy Considerations {#privacy}

N-AALP objects are signed and content-addressed, and are often long-lived, which creates two
privacy tensions the format addresses explicitly: correlation of identical content, and erasure of
personal data from records that are immutable by design.

Salted body option: because the content id is a deterministic hash of the body, two objects with
identical logical content produce an identical content id and are trivially correlatable across
contexts. N-AALP therefore offers an optional body salt so that identical logical content does not
yield a correlatable content id; a signer that must avoid cross-context linkage includes a fresh
random salt in the body, carried under the signature like any other field.

Hash-only personal data: an object that must reference a person SHOULD NOT carry the personal data
in the clear. Personal data is carried only as a salted one-way hash of the datum, so the object
binds to the person without disclosing the identifier; the plaintext and its salt are held off the
record by the party that needs them.

Erasure resolution against immutable records: a signed, hash-chained record cannot have bytes
removed without breaking the chain, which appears to conflict with an erasure
(right-to-be-forgotten) obligation. N-AALP resolves this without mutating the signed record:
because personal data is present only as a salted hash, erasure is resolved by destroying the
off-chain preimage and its salt, leaving the signed record intact but its hashed personal data
unlinkable to any person. The signature and the audit chain stay valid; what is destroyed is the
ability to reverse the hash to a person, which is exactly the property erasure requires.

# IANA Considerations {#iana}

This document is an Independent Submission. All registries requested below use registration
policies permitted on the Independent stream, requiring no IETF Review or Standards Action: the
media type registers into the existing IANA Media Types registry under {{RFC6838}} (that
registry's Expert Review), and each new registry this document creates uses RFC Required (First
Come First Served in the standards range) per {{RFC8126}} -- an ISE-permissible policy. Numeric
values shown are the values this specification defines; where IANA assignment is requested the
placeholder TBD is used.

## Media type application/vnd.bubblefish.naalp+cbor

IANA is requested to register the following media type in the vendor tree ({{RFC6838}} Section 3.2),
using the +cbor structured syntax suffix defined in {{RFC8949}} and registered in the IANA
Structured Syntax Suffixes registry (whose mechanism is established by {{RFC6838}} and populated
by {{RFC6839}}). The `vnd.bubblefish.` facet designates BubbleFish Technologies, Inc. as the
producing organization; a vendor-tree registration is submitted directly to IANA and undergoes
Expert Review ({{RFC6838}} Section 3.2), requiring no IESG approval or IETF standards action:

- Type name: application
- Subtype name: vnd.bubblefish.naalp+cbor
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

IANA is requested to create the "N-AALP Channels" registry. Registration policy: RFC Required
(First Come First Served in the standards range) -- an ISE-permissible policy; a successor RFC
provides the stable public specification and a non-colliding Channel Id.
Columns: Channel Id (uint 0..19), Name, Reference. Initial contents: the twenty channels of
(# Channel Surfaces), ids 0x0000..0x0013, this document.

## N-AALP Object Kind registries

IANA is requested to create, per channel, an "N-AALP Object Kinds (channel N)" registry.
Registration policy: RFC Required (First Come First Served in the standards range) -- an
ISE-permissible policy. Columns: Kind Code (uint), Name, Effect (one of the
four closed effect names, or "variable"), Reference. The initial contents are the sixty-five
baseline kinds below, enumerated here (channel, code, kind, effect) so an implementer building
from only this document has the complete set:

| Channel | Code | Kind | Effect |
|---------|-----:|------|--------|
| 0x0000 Control | 0 | Hello | read_only |
| 0x0000 Control | 1 | Bye | idempotent_write |
| 0x0000 Control | 2 | Ack | read_only |
| 0x0000 Control | 3 | Error | read_only |
| 0x0001 Memory | 0 | MemoryOffer | idempotent_write |
| 0x0001 Memory | 1 | MemoryAccept | idempotent_write |
| 0x0001 Memory | 2 | MemoryWrite | non_idempotent_write |
| 0x0001 Memory | 3 | MemoryRead | read_only |
| 0x0001 Memory | 4 | MemoryExpire | destructive |
| 0x0001 Memory | 5 | MemoryRevoke | destructive |
| 0x0002 Capability | 0 | CapIssue | non_idempotent_write |
| 0x0002 Capability | 1 | CapDelegate | non_idempotent_write |
| 0x0002 Capability | 2 | CapRevoke | destructive |
| 0x0002 Capability | 3 | CapLookup | read_only |
| 0x0003 Identity | 0 | Rotation | non_idempotent_write |
| 0x0003 Identity | 1 | Revocation | destructive |
| 0x0003 Identity | 2 | ForeignLink | idempotent_write |
| 0x0003 Identity | 3 | KeyAnnounce | read_only |
| 0x0004 Governance | 0 | PolicyPublish | non_idempotent_write |
| 0x0004 Governance | 1 | Approval | non_idempotent_write |
| 0x0004 Governance | 2 | ApprovalHeld | read_only |
| 0x0004 Governance | 3 | Consume | non_idempotent_write |
| 0x0005 Immune | 0 | AnomalyReport | read_only |
| 0x0005 Immune | 1 | Quarantine | destructive |
| 0x0005 Immune | 2 | QuarantineLift | non_idempotent_write |
| 0x0006 Federation | 0 | AuthorityAnnounce | read_only |
| 0x0006 Federation | 1 | ScopeReceipt | non_idempotent_write |
| 0x0007 Settlement | 0 | SettleIntent | non_idempotent_write |
| 0x0007 Settlement | 1 | SettleReceipt | non_idempotent_write |
| 0x0007 Settlement | 2 | SettleReject | idempotent_write |
| 0x0008 Compliance | 0 | ComplianceRecord | non_idempotent_write |
| 0x0008 Compliance | 1 | ComplianceQuery | read_only |
| 0x0008 Compliance | 2 | ComplianceReport | read_only |
| 0x0009 Sensory | 0 | Observation | read_only |
| 0x0009 Sensory | 1 | Subscribe | idempotent_write |
| 0x0009 Sensory | 2 | Unsubscribe | idempotent_write |
| 0x000A Telemetry | 0 | Metric | read_only |
| 0x000A Telemetry | 1 | HealthReport | read_only |
| 0x000B Audit | 0 | Receipt | non_idempotent_write |
| 0x000B Audit | 1 | AuditQuery | read_only |
| 0x000B Audit | 2 | ForkProof | read_only |
| 0x000C Stream | 0 | StreamOpen | variable |
| 0x000C Stream | 1 | StreamCommit | read_only |
| 0x000C Stream | 2 | StreamCheckpoint | read_only |
| 0x000D Bridge | 0 | Carriage | variable |
| 0x000E Commerce | 0 | Offer | read_only |
| 0x000E Commerce | 1 | Order | non_idempotent_write |
| 0x000E Commerce | 2 | Fulfil | non_idempotent_write |
| 0x000E Commerce | 3 | Cancel | destructive |
| 0x000F Interaction | 0 | Elicit | read_only |
| 0x000F Interaction | 1 | Respond | idempotent_write |
| 0x000F Interaction | 2 | Confirm | non_idempotent_write |
| 0x0010 Discovery | 0 | DiscoveryRecord | read_only |
| 0x0010 Discovery | 1 | DiscoveryQuery | read_only |
| 0x0011 Workflow | 0 | TaskCreate | non_idempotent_write |
| 0x0011 Workflow | 1 | TaskInput | non_idempotent_write |
| 0x0011 Workflow | 2 | TaskCancel | destructive |
| 0x0011 Workflow | 3 | TaskResult | non_idempotent_write |
| 0x0012 Knowledge | 0 | Assert | non_idempotent_write |
| 0x0012 Knowledge | 1 | Retract | destructive |
| 0x0012 Knowledge | 2 | KnowledgeQuery | read_only |
| 0x0013 Spatial | 0 | FrameDefine | idempotent_write |
| 0x0013 Spatial | 1 | Pose | read_only |
| 0x0013 Spatial | 2 | StateUpdate | read_only |
| 0x0013 Spatial | 3 | SnapshotQuery | read_only |

## N-AALP Effect registry

IANA is requested to create the "N-AALP Effects" registry. Registration policy: RFC Required -- an
ISE-permissible policy; this closed set is not expected to grow, and any addition (via a successor
RFC) MUST preserve the fail-closed lattice. Columns: Value (0..3), Name, Reference. Initial
contents:
read_only 0, idempotent_write 1, non_idempotent_write 2, destructive 3, this document.

## N-AALP Carriage Protocol Id registry

IANA is requested to create the "N-AALP Carriage Protocol Ids" registry, a one-octet space
partitioned: standards 0x01-0x0F (RFC Required / First Come First Served -- an ISE-permissible
policy), experimental 0x10-0x7F (no registration), private 0x80-0xFF (no registration). Columns:
Protocol Id, Name, Carriage Class,
Reference. Initial standards-range contents: 0x01 MCP (JSONRPC), 0x02 A2A (JSONRPC), 0x03 HTTP
(HTTP), 0x04 WebSocket (STREAM), this document.

## N-AALP Error Code registry

A fail-closed rejection reason is carried on the wire by a **`naalp-error` object** -- a
Control/Error object (channel `0x0000`, kind 3, effect `read_only`; an error report effects
nothing) whose body is the map `{ 1: code (uint), 2: name (tstr), ?3: detail (tstr), ?4: subject
(bstr content id) }` (Appendix A). `code` is the numeric error code; `name` is its registered name;
optional `detail` is a non-normative human diagnostic with no security meaning; optional `subject`
is the content id (Section 2.3) of the object the error is about.

Two dual-carriage rules make the `code`/`name` pair unambiguous and forward-compatible:

- A receiver that recognizes `code` MUST require `name` to equal the registered name for that code;
  a code/name disagreement is rejected `Malformed`. (This is the strengthening direction: the
  numeric code is authoritative and the name cannot contradict it.)
- A `code` outside the receiver's registry snapshot MUST NOT be fatal: it is opaque (the `name` is
  diagnostic only and no semantics are inferred), so a receiver interoperates with a peer that
  emits a later-registered code.

IANA is requested to create the "N-AALP Error Codes" registry. Registration policy: **RFC Required**
(First Come First Served in the standards range) -- an ISE-permissible policy. The value space is a
uint: **1-0x7FFF** is the standards range (RFC Required / FCFS), **>=0x8000** is private-use (no
registration), and **0 is reserved** and MUST NOT appear on the wire. Columns: Code, Name,
Retryable, Reference. `Retryable` is `yes` only when an unmodified retry of the same object can
later succeed because of a transient or environmental change (with no object or configuration
change); every deterministic verification or decode failure is therefore non-retryable (the
fail-closed default), and the only registered transient is `NotDelivered`. The reference for every
initial value is this document.

Initial contents (assigned sequentially in the order below; the same order is the `naalp-error-code`
production of Appendix A):

| Code | Name | Retryable |
| ---: | --- | :---: |
| 1 | `NonCanonical` | no |
| 2 | `DepthExceeded` | no |
| 3 | `Malformed` | no |
| 4 | `ContentIdMismatch` | no |
| 5 | `HeaderBodyMismatch` | no |
| 6 | `UnsupportedVersion` | no |
| 7 | `UnknownCriticalExt` | no |
| 8 | `UnknownKind` | no |
| 9 | `RangeError` | no |
| 10 | `NonNFC` | no |
| 11 | `WrongAudience` | no |
| 12 | `TooLarge` | no |
| 13 | `TooManyCauses` | no |
| 14 | `TooManyExtensions` | no |
| 15 | `TooManyChunks` | no |
| 16 | `UnknownAlg` | no |
| 17 | `KeyAlgMismatch` | no |
| 18 | `ProfileDowngrade` | no |
| 19 | `HybridIncomplete` | no |
| 20 | `SuiteMismatch` | no |
| 21 | `CompositeRefused` | no |
| 22 | `BadSignature` | no |
| 23 | `SignerMismatch` | no |
| 24 | `RotationUnauthorized` | no |
| 25 | `KeyRevoked` | no |
| 26 | `EffectNotAuthorized` | no |
| 27 | `UnauthenticatedPrincipal` | no |
| 28 | `MalformedSafetyLabel` | no |
| 29 | `ApprovalRequired` | no |
| 30 | `ApprovalMismatch` | no |
| 31 | `ApprovalExpired` | no |
| 32 | `AlreadyConsumed` | no |
| 33 | `ConsumeFork` | no |
| 34 | `ConsumeForkInvalid` | no |
| 35 | `ConsumeReceiptUnsigned` | no |
| 36 | `LedgerCorrupt` | no |
| 37 | `LedgerUnsigned` | no |
| 38 | `AudienceMismatch` | no |
| 39 | `FreshnessSelfAsserted` | no |
| 40 | `UnknownRefusalOutcome` | no |
| 41 | `RefusalDetailLeak` | no |
| 42 | `ChainBroken` | no |
| 43 | `Equivocation` | no |
| 44 | `CausalViolation` | no |
| 45 | `ReceiptUnsigned` | no |
| 46 | `ForkProofInvalid` | no |
| 47 | `StageOutOfOrder` | no |
| 48 | `StreamDigestMismatch` | no |
| 49 | `StreamStateError` | no |
| 50 | `ConfidentialTransportRequired` | no |
| 51 | `PeerUnauthenticated` | no |
| 52 | `NotDelivered` | yes |
| 53 | `MappingError` | no |
| 54 | `EffectDeclarationMismatch` | no |
| 55 | `StateTransitionError` | no |
| 56 | `CapExceedsParent` | no |
| 57 | `TransformCycle` | no |
| 58 | `InputGateBypass` | no |
| 59 | `TaskStateError` | no |
| 60 | `ScopeOverlapConflict` | no |
| 61 | `ReconcileMismatch` | no |
| 62 | `WrongFlow` | no |
| 63 | `SeqGap` | no |
| 64 | `AboveCeiling` | no |
| 65 | `GapDetected` | no |
| 66 | `CommitMismatch` | no |
| 67 | `ContMalformed` | no |
| 68 | `GrantExpired` | no |
| 69 | `GrantNotYetValid` | no |
| 70 | `GrantRevoked` | no |
| 71 | `UntrustedChainRoot` | no |
| 72 | `DelegationDepthExceeded` | no |
| 73 | `GrantMalformed` | no |
| 74 | `NameMalformed` | no |
| 75 | `NameChainBroken` | no |
| 76 | `NameForkProofInvalid` | no |
| 77 | `IllegalTransition` | no |
| 78 | `TaskChainBroken` | no |
| 79 | `ForeignCard` | no |
| 80 | `DescMalformed` | no |
| 81 | `MalformedApprovalFlag` | no |
| 82 | `DirForkProofInvalid` | no |
| 83 | `ImporterMismatch` | no |
| 84 | `UnknownDescriptionFormat` | no |
| 85 | `VerifierKeyMismatch` | no |
| 86 | `NegMalformed` | no |
| 87 | `UnknownRole` | no |
| 88 | `UnknownProfile` | no |
| 89 | `NotDescended` | no |
| 90 | `NotOffer` | no |
| 91 | `NotAccept` | no |
| 92 | `MalformedCriticalFlag` | no |
| 93 | `UnknownCriticalRisk` | no |
| 94 | `ReferenceMismatch` | no |
| 95 | `MalformedAnnotation` | no |
| 96 | `EffectUnderDeclared` | no |
| 97 | `EffectOutsideLattice` | no |
| 98 | `ToolCallMalformed` | no |
| 99 | `PayMalformed` | no |
| 100 | `UnknownPaymentFormat` | no |
| 101 | `GwMalformed` | no |
| 102 | `UnknownGatewayDecision` | no |
| 103 | `UIMalformed` | no |
| 104 | `UIChainBroken` | no |
| 105 | `UnknownUIEventKind` | no |
| 106 | `ActionSubstituted` | no |
| 107 | `UINoConsent` | no |
| 108 | `StaleEpoch` | no |
| 109 | `Unauthorized` | no |
| 110 | `OwnerImmutable` | no |
| 111 | `MemberExists` | no |
| 112 | `MemberUnknown` | no |
| 113 | `OwnerExists` | no |
| 114 | `RoleInvalid` | no |
| 115 | `RoomOpMismatch` | no |
| 116 | `OpUnknown` | no |
| 117 | `PrincipalUnknown` | no |
| 118 | `PrincipalExists` | no |
| 119 | `RebindUnauthorized` | no |

## N-AALP Extension Key registry

IANA is requested to create the "N-AALP Extension Keys" registry, the shared key namespace for the
non-critical `ext` (object field 11) and critical `cext` (field 12) maps, so two independent
extensions cannot collide on a key. Registration policy: RFC Required (First Come First Served in
the standards range) -- an ISE-permissible policy. Columns: Key (uint), Name, Maps (`ext` or
`ext|cext`), Reference. Initial contents:

| Key | Name | Maps | Reference |
|----:|------|------|-----------|
| 1 | `safety-label` | `ext` | this document |
| 13 | `recheck` | `ext\|cext` | this document |
| 14 | `signer-counter` | `ext` | this document |
| 15 | `producing-boundary` | `ext` | this document |
| 16 | `naalp-hazard-claim` | `cext` | this document |

## N-AALP Carriage Content Type registry

IANA is requested to create the "N-AALP Carriage Content Types" registry for the `content_type`
field (naalp-carriage-body field 3), the foreign encoding an OPAQUE-class object carries. It is a
one-octet space partitioned: standards 0x00-0x0F (RFC Required / First Come First Served -- an
ISE-permissible policy), experimental 0x10-0x7F (no registration), private 0x80-0xFF (no
registration). Columns: Content Type (uint), Name, Reference. Initial standards-range contents:

| Content Type | Name | Reference |
|-------------:|------|-----------|
| 0 | `json` | this document |
| 1 | `octet-stream` | this document |
| 2 | `text` | this document |

## N-AALP Trust-Decision Input Class registry

IANA is requested to create the "N-AALP Trust-Decision Input Classes" registry, the closed set of
input classes a relying party's decision to act may key on, each classified by the safe shape its
influence must take -- verifiable, attenuating, or committed -- so that a party cannot influence a
decision except through one of those shapes, or the decision fails closed (see the
trust-decision-closure-sovereignty subsection of the Security Considerations). Registration policy:
RFC Required (First Come First Served in the standards range) -- an ISE-permissible policy. Columns:
Class (uint), Name, Safe shape, Reference. Initial contents:

| Class | Name | Safe shape | Reference |
|------:|------|------------|-----------|
| 1 | `identifier` | verifiable | this document |
| 2 | `object-parse` | verifiable | this document |
| 3 | `object-identity` | verifiable | this document |
| 4 | `conformance-expectation` | verifiable | this document |
| 5 | `verification-procedure` | verifiable | this document |
| 6 | `delegated-authority` | attenuating | this document |
| 7 | `approved-action` | committed | this document |
| 8 | `negotiated-parameters` | committed | this document |
| 9 | `validity-clock` | committed | this document |
| 10 | `use-context` | committed | this document |

## COSE algorithms

N-AALP reuses the existing IANA COSE Algorithms registry for ML-DSA {{RFC9964}} and Ed25519
{{RFC9864}} and requests no new COSE code points.

## Registration criteria for the RFC-Required registries

The Independent stream appoints no Designated Expert, so the RFC-Required registries above are
self-administered: a registration is made by a successor RFC (or by First Come First Served in the
standards range) and MUST satisfy the same four criteria a reviewer would otherwise confirm: (1) a
stable, publicly available specification documents the value; (2) the value does not collide with
an existing entry; (3) the name is protocol-neutral and carries no vendor product name; and (4)
for object kinds, the declared effect is one of the closed set and preserves the fail-closed model.

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

This specification tiers its surfaces by editorial status, so a first conforming implementation is
not asked to build the whole surface at once. The normative surface required for conformance is the
spine -- the object model, the signing constructions, identity, effects and authorization, approval
and the single-use consume ledger, the baseline audit receipt chain, delivery, the per-stream
commitment, the transport bindings, and the carriage-never-decodes rule -- together with the frozen
baseline surface (tier 0) of every channel. Every capability an object gains above tier 0, including
the federated higher tier of ordering and any higher channel tier carried through the tier field and
critical or non-critical extensions, has experimental status: it is OPTIONAL, it MAY change in a
later revision, and an implementation that omits it is still conforming. An implementation that does
provide such a capability MUST provide it exactly as specified, and a verifier that does not
recognize a critical extension MUST reject the object fail-closed (# Object Model). This tiering is
editorial: it bounds what conformance requires, not what the reference implementations provide, which
is the full surface across all ten reference languages (# Implementation Status).

# Specification License

This specification may be implemented by anyone, royalty-free. This right to implement is granted
independently of the license of any reference implementation (the reference code is licensed
separately). Contributions to this document are subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents.

--- back

# Collected CDDL {#cddl}

This appendix is the complete and normative CDDL module for the N-AALP byte-level wire format.
It defines the object body, effect, and profile productions of (# Object Model) and the
carriage body of (# Foreign Carriage by Class), together with the COSE wrapper, protected
header, identity records, safety label, approval and consume records, receipt, delivery update,
stream objects, and the federated reconcile record. A byte-identical copy is maintained with
the reference implementation and machine-validated against the conformance vectors. Where a
CDDL excerpt elsewhere in this document differs from this appendix, this appendix is
authoritative.

~~~ cddl
; draft-bubblefish-naalp-01 -- Native Agentic Application Layer
; Protocol: the complete CDDL wire-format module (RFC 8610). The copy
; in Appendix A of the Internet-Draft is normative; the copy
; maintained with the reference implementation is a byte-identical
; mirror, machine-validated for well-formedness and against the
; conformance vector corpus.
;
; This module is complete: the object body, the effect, profile, and
; channel vocabularies, the COSE_Sign1 / COSE_Sign wrapper (RFC 9052
; Section 4), the protected header, the identity records, the safety
; label, the approval and consume records, the receipt and ForkProof,
; the delivery update, the stream objects, the carriage body, the
; channel-registry note, the federated reconcile record, and the
; collaboration/rooms membership records (room op + principal
; binding) -- all reachable from the `naalp-artifact` root.
;
; All instances are deterministic CBOR per RFC 8949 Section 4.2.1
; (shortest heads, map keys ascending by encoded bytes, no indefinite
; lengths, no duplicate keys). A non-canonical encoding of any
; production here is rejected.

; ---- Collected root -----------------------------------------------
; The set of top-level N-AALP artifacts this module defines, as a
; single reachable root so a CDDL tool sees no unreferenced rule.
; Each concrete instance is validated against the specific production
; for its kind (the conformance harness targets the rule per
; construction), not against this union; the union exists only for
; reachability.
naalp-artifact = naalp-object
  / naalp-signed-object / naalp-protected-header
  / naalp-rotation / naalp-revocation / naalp-foreign-link
  / naalp-safety-label
  / naalp-approval / naalp-approval-held / naalp-consume-entry
  / naalp-consume-receipt
  / naalp-receipt / naalp-fork-proof / naalp-delivery-update
  / naalp-stream-open / naalp-stream-commit / naalp-stream-checkpoint
  / naalp-carriage-body / naalp-reconcile
  / naalp-room-op / naalp-principal-binding
  / naalp-delegation-grant
  / recheck-procedure / signer-counter
  / naalp-mcp-tool-call / naalp-mcp-annotations
  / naalp-mcp-call-binding / mcp-hint
  / naalp-flow-open / naalp-continuation / naalp-flow-checkpoint
  / naalp-flow-commit
  / naalp-description / naalp-directory / naalp-description-import
  / naalp-name-binding / naalp-task-transition
  / naalp-negotiation-offer / naalp-negotiation-counter
  / naalp-negotiation-accept
  / negotiation-role
  / naalp-risk-label / naalp-labeled-object / naalp-trust-ref
  / naalp-payment-import / naalp-payment-charge-binding
  / naalp-payment-format
  / naalp-ui-event / ui-event-kind
  / naalp-gateway-decision / gw-decision
  / naalp-refusal / refusal-outcome
  / naalp-error / naalp-error-code
  / trust-decision-input-class
  / naalp-decision-record / ordering-basis
  / naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof
  / naalp-egress-attestation / egress-binding
  / naalp-foreign-profile-pin
  / naalp-hazard-claim / naalp-hazard-authorization
  / hazard-class / hazard-envelope / spatial-bounds / hazard-window

; Decoder resource bounds -- CDDL cannot express element counts,
; nesting depth, or octet size (RFC 8610 restricts none of these), so
; these are MUST-level limits every decoder enforces fail-closed, not
; this schema: object octet size <= 1 MiB (TooLarge, on raw bytes
; before parse); |causes| (field 8) <= 1024 (TooManyCauses); |ext|
; (11) and |cext| (12) <= 64 each (TooManyExtensions); CBOR nesting
; depth <= 16 with the outermost item at depth 1 (DepthExceeded);
; stream chunk count <= 2^20 (TooManyChunks, native streaming below).
; The maxima are wire constants, projected identically into all ten
; ports so one port cannot accept what another refuses. The object
; body -- the map that is signed as the COSE_Sign1 payload.
naalp-object = {
  1 : bstr,
  ; id -- content id: multihash(0x20, SHA-384(body-without-1))
  2 : uint,
  ; kind -- object kind code (per channel surface)
  3 : channel-id,
  ; channel -- N-PAMP channel id
  4 : uint,
  ; tier -- channel capability tier (0 = baseline)
  5 : bstr,
  ; signer -- self-certifying signer id
  6 : uint,
  ; created -- signer's claimed creation time, epoch ms (advisory)
  7 : effect,
  ; effect -- closed effect value
  8 : [* bstr],
  ; causes -- content ids of causing objects; may be empty
  9 : profile,
  ; profile -- crypto profile
  10 : any,
  ; body -- kind-specific body, validated by the channel surface
  ? 11 : { * uint => any },
  ; ext -- non-critical extensions; unknown keys ignored
  ? 12 : { * uint => any },
  ; cext -- critical extensions; any unknown key => reject
  ? 13 : tstr,
  ; audience -- endpoint/channel-scope id the object is bound to.
  ; OMITTED when empty -- a no-audience object encodes byte-
  ; identically to a draft-00 object. MANDATORY for consume-once
  ; kinds (enforced by channel-surface validation, not this
  ; cardinality). A verifier rejects an object whose audience is not
  ; itself: WrongAudience. This is object-map FIELD 13 (a top-level
  ; envelope field) -- the genuine draft-01 envelope addition that
  ; anchors naalp-version 2. DISTINCT namespace from ext/cext KEY 13
  ; (recheck) below, which is a key INSIDE the field-11/12 maps, not
  ; a top-level object field.
  ? 14 : uint,
  ; suite -- signed suite declaration: PRESENT iff the object's alg
  ; is the composite id -65537; ABSENT (byte-identical to a pure
  ; object) for a pure ML-DSA object. Value 1 = COMPSIG-MLDSA65-
  ; Ed25519-SHA512. Top-level object FIELD 14 -- DISTINCT namespace
  ; from ext key 14 (signer-counter) INSIDE the field-11/12 maps
  ; below.
  ; The ext (11) / cext (12) extension-KEY namespace is a single
  ; registry (RFC Required / FCFS) so two implementers assigning keys
  ; cannot COLLIDE -- a critical-ext collision is a denial; the
  ; registry_drift gate asserts key uniqueness + agreement with the
  ; per-capability registries. The currently-registered keys are 1
  ; safety-label (ext), 13 recheck (ext/cext), 14 signer-counter
  ; (ext), 15 producing-boundary (ext), 16 naalp-hazard-claim
  ; (cext): ext/cext key 13 = recheck: it
  ; names the body claim's re-check procedure by id
  ; (recheck-procedure below). In ext (11) it is may-ignore (an
  ; unknown id ignored); in cext (12) it is must-understand (an
  ; unknown id => UnknownCriticalExt, the same rule).
  ; ext key 14 = signer-counter: an OPTIONAL forward-only per-signer
  ; position (signer-counter below). It rides the NON-CRITICAL ext
  ; map (11)
  ; ONLY -- a detection aid, not a verification gate -- so it is
  ; may-ignore; placing it in cext (12) is an unrecognized critical
  ; key => UnknownCriticalExt (the same rule). It is covered by the
  ; SIGNER's own COSE_Sign1 signature (ext is part of the signed
  ; body). Detection, not prevention (# Security Considerations). ext
  ; key 15 = producing-boundary: an OPTIONAL per-object disclosure
  ; (naalp-producing-boundary below). of the trust boundary that
  ; emitted the object and whether that boundary OBSERVED the event
  ; first-hand or RELAYED a report of it. It rides the NON-CRITICAL
  ; ext map (11) ONLY -- a disclosure, not a verification gate -- so
  ; it is may-ignore (a verifier that does not understand it, or
  ; reads a malformed value, ignores the entry and the object still
  ; verifies); placing it in cext (12) is an unrecognized critical
  ; key => UnknownCriticalExt (the same rule). It is covered by the
  ; SIGNER's own COSE_Sign1 signature (ext is part of the signed
  ; body), so it is SELF-ASSERTED; it establishes record-order /
  ; observational domain, NOT cross-boundary event precedence (#
  ; Security Considerations).
  ; cext key 16 = naalp-hazard-claim: an OPTIONAL critical
  ; must-understand physical-hazard claim (naalp-hazard-claim below) --
  ; the hazard dimension orthogonal to effect (physical danger, not
  ; data reversibility). It rides the CRITICAL cext map (12) ONLY: a
  ; safety gate, so a verifier that has not implemented Component F
  ; rejects the WHOLE object (UnknownCriticalExt) rather than letting a
  ; hazardous action through unchecked -- the fail-closed direction,
  ; the OPPOSITE of producing-boundary's may-ignore ext placement. It
  ; is covered by the SIGNER's own COSE_Sign1 signature (cext is part
  ; of the signed body).
}

; Closed effect vocabulary, aligned 1:1 with the N-PAMP Bridge
; SafetyLabel. An unrecognized effect is treated as destructive,
; never fail-open.
effect = &(
  read_only:            0,
  idempotent_write:     1,
  non_idempotent_write: 2,
  destructive:          3,
)

; Crypto profiles -- one wire, per-profile row.
profile = &(
  public:     1,
  enterprise: 2,
  sovereign:  3,
)

; N-PAMP channel ids 0x0000..0x0013 -- the twenty channels.
channel-id = 0..19

; ---- COSE signing wrapper (RFC 9052) ------------------------------
; On the wire, an N-AALP object is a tagged COSE structure whose
; payload is the deterministic-CBOR `naalp-object` body above. A
; single signature uses COSE_Sign1 (tag 18) -- either a pure ML-DSA
; signature (per profile) or the opt-in classical-bridge signature: a
; single COSE_Sign1 under the private-use composite alg id -65537
; whose signature value is the IETF LAMPS composite mldsaSig(3309) ||
; tradSig(64). COSE_Sign (tag 98, multiple signatures) carries two
; roles: the legacy two-signature Ed25519+ML-DSA hybrid (OPTIONAL;
; not required by the Standard profile), and the Rotation object
; co-signature (channel 3 / kind 0; old-key then new-key legs, both
; required); a channel-3/kind-0 object MUST be tag 98, and a tag-18
; single-signature rotation is rejected RotationUnauthorized. Signing
; is the FIPS 204 deterministic variant (rnd = 0) so two
; implementations produce byte-identical signatures.
;

naalp-signed-object = COSE_Sign1_Tagged / COSE_Sign_Tagged

COSE_Sign1_Tagged = #6.18(COSE_Sign1)
COSE_Sign1 = [
  protected   : bstr,
  ; serialized protected header {1 => cose-alg}; empty => zero-length
  ; bstr 0x40 (reject the 0x41A0 bstr-wrapped-empty-map form)
  unprotected : cose-header,
  payload     : bstr,
  ; the deterministic-CBOR naalp-object body (the signed payload)
  signature   : bstr,
]

COSE_Sign_Tagged = #6.98(COSE_Sign)
; optional hybrid (Ed25519 + ML-DSA)
COSE_Sign = [
  protected   : bstr,
  ; body protected header: empty for the legacy hybrid; for a
  ; Rotation object (channel 3/kind 0) the enriched naalp header {1:
  ; newKeyAlg, "naalp": {...}}
  unprotected : cose-header,
  payload     : bstr,
  signatures  : [+ COSE_Signature],
]
COSE_Signature = [
  protected   : bstr,
  ; serialized per-signer header {1 => cose-alg}
  unprotected : cose-header,
  signature   : bstr,
]

cose-header = { * (int / tstr) => any }

; COSE algorithm ids. ML-DSA from RFC 9964; Ed25519 from RFC 9864.
; SLH-DSA (FIPS 205) is reserved, addable with no envelope change
; once its COSE code point is assigned.
cose-alg = &(
  ml-dsa-44: -48,
  ; NIST level 2 -- optional edge/light tier only, never a
  ; Public/Enterprise/Sovereign default
  ml-dsa-65: -49,
  ; NIST level 3 -- Public / Enterprise default (MTI)
  ml-dsa-87: -50,
  ; NIST level 5 -- Sovereign default / mandate
  ed25519:   -19,
  ; classical, opt-in composite leg only
  compsig-mldsa65-ed25519: -65537,
  ; opt-in LAMPS composite (Public/Enterprise) -- COSE private-use,
  ; N-AALP provisional
  compsig-mldsa44-ed25519: -65538,
  ; edge composite suite -- RESERVED (registered, not implemented
  ; this wave)
)

; ---- object envelope protected header -----------------------------
; A COSE_Sign1 over an N-AALP object uses this protected header: the
; COSE `alg` plus a pre-parse routing copy of the signer, profile,
; and naalp-version, carried under a text-string label ("naalp"). A
; tstr label cannot collide with any integer-labeled standard COSE
; header parameter (RFC 9052 Section 3.1). A verifier MUST reject an
; object whose header signer/profile copies disagree with the body's
; field 5 / field 9 (HeaderBodyMismatch). An empty protected header
; is a zero-length bstr (RFC 9052 Section 3); the N-AALP object
; header is never empty (it always carries alg + "naalp"). Per this
; disposition, the redundant 0x41A0 encoding of an empty protected
; header (a bstr wrapping an empty map) MUST be rejected as
; NonCanonical, at every protected-header parse site, before the
; header is interpreted.
naalp-protected-header = {
  1 : cose-alg,
  ; COSE algorithm id
  "naalp" : naalp-header-meta,
}
naalp-header-meta = {
  1 : bstr,
  ; signer -- copy of object body field 5
  2 : profile,
  ; profile -- copy of object body field 9
  3 : uint,
  ; naalp-version (draft-01: 2; draft-00 was 1 -- anchored by the
  ; audience envelope field)
}

; ---- identity + key lifecycle -------------------------------------
; The signer id (envelope field 5) is a self-certifying multibase
; string, identical in form to the N-PAMP PeerHandle: signer =
; multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))
; mc is a multiformats key-type code: 0xed (ed25519-pub), 0x1211
; (mldsa-65-pub), 0x1212 (mldsa-87-pub) -- all draft status; 0x12
; (sha2-256) is permanent. base32 is RFC 4648 lowercase without
; padding (multibase prefix "b"). A verifier recomputes the id from
; the key and rejects a mismatch (SignerMismatch); no CA.
;
; Identity-channel (0x0003) lifecycle record bodies (carried in
; envelope field 10 by the channel surface):
naalp-rotation = {
; co-signed by BOTH the old and new key
  1 : tstr,
  ; old -- prior signer id
  2 : tstr,
  ; new -- successor signer id
  3 : uint,
  ; not_before (epoch ms)
}
naalp-revocation = {
; signed by the key it revokes (or a recovery key)
  1 : tstr,
  ; key -- the signer id being revoked
  2 : uint,
  ; not_after (epoch ms)
}
naalp-foreign-link = {
; cross-signed by the FOREIGN identity's key
  1 : tstr,
  ; controls -- the N-AALP signer id
  2 : tstr,
  ; foreign_id -- foreign identifier; MUST be NFC (else NonNFC)
  3 : uint,
  ; not_after (epoch ms)
}

; ---- effect authorization + safety label --------------------------
; The effect (object body field 7) is the closed four-value set
; defined above
; (read_only/idempotent_write/non_idempotent_write/destructive),
; aligned 1:1 with the N-PAMP Bridge SafetyLabel u8 (NPAMP draft-01
; 10_bridge_framework Section 7): 0x00..0x03, an identity map, so
; carriage over the Bridge is loss-free. The values form a LATTICE
; with destructive at the top.
;
; The effect is an AUTHORIZATION INPUT, not a hint -- closing the gap
; N-PAMP names and leaves open ("describes intent and does not
; replace authorization"). An endpoint grants a maximum effect (a
; capability) to an AUTHENTICATED signer id, and an object is
; authorized iff effect <= granted (the lattice); otherwise it is
; denied (EffectNotAuthorized). An effect value the evaluator does
; not recognize is treated as destructive and MUST NOT fail open. No
; layer authorizes from transport metadata, a foreign header, or a
; client-supplied name (UnauthenticatedPrincipal). This is endpoint
; policy, not a wire production: the wire carries only the effect
; value (field 7).
;
; The OPTIONAL safety label is a signed, non-critical ext entry under
; ext key 1 (object body field 11). It is attributable to the
; object's signer and auditable; it is an ACCOUNTABLE CLAIM, NOT a
; guarantee that the content is safe.
naalp-safety-label = {
; ext[1]
  1 : tstr,
  ; risk -- an accountable risk claim (e.g. "elevated")
  2 : tstr,
  ; scope -- what the object affects (e.g. "billing-records")
}

; ---- approval + single-use consume ledger -------------------------
; An Approval binds, UNDER SIGNATURE, the content id of the exact
; canonical argument object it approves. Because the args are named
; by content id, mutating any argument changes that id and the
; approval no longer matches (ApprovalMismatch). The approval is not
; valid across sessions/contexts (it carries a nonce) nor after
; not_after (ApprovalExpired), and once consumed it is dead. These
; record bodies are signed with the crypto over deterministic CBOR;
; wrapping them as Governance-channel (0x0004) objects.
naalp-approval = {
  1 : bstr,
  ; approves -- content id of the exact args object
  2 : tstr,
  ; approver -- approver signer id
  3 : effect,
  ; grant -- the granted effect class
  4 : bstr,
  ; nonce -- anti-replay nonce
  5 : uint,
  ; not_after -- expiry, epoch ms
  ? 6 : tstr,
  ; audience -- OPTIONAL valid-context; field omitted = unrestricted
  ; by the issuer's explicit choice; when present, a relying party
  ; checks it at use and rejects AudienceMismatch on mismatch. An
  ; empty string is not a distinct value -- omit field 6 to mean
  ; absent.
}
; A held outcome -- approval required but not yet granted -- is a
; DISTINCT signed non-success result, never a silent success or
; denial.
naalp-approval-held = {
  1 : bstr,
  ; approves -- content id of the args whose approval is pending
  2 : tstr,
  ; reason -- accountable explanation
}
; PARTY-VISIBLE COARSE REFUSAL. A refusal returned to the
; authenticated party carries ONLY a single value from a closed
; vocabulary and the content id of the full signed record -- a
; reference, not the reason. Every discriminating detail lives only
; in that full signed record (a naalp-approval-held, a
; naalp-gateway-decision, or an audit event), resolvable by a party
; authorized to read it, so repeated refusals cannot serve an
; adaptive party as an oracle. A party-visible refusal that carries
; discriminating detail, or omits the record content id, is a
; RefusalDetailLeak. An outcome outside the closed set is
; UnknownRefusalOutcome.
refusal-outcome = &(
  denied:       0,
  ; the action is refused
  held:         1,
  ; the action requires a further step not yet taken
  unverifiable: 2,
  ; required evidence did not verify
)
naalp-refusal = {
  1 : refusal-outcome,
  ; outcome -- the coarse, party-visible outcome (closed set)
  2 : bstr,
  ; record -- content id of the full signed record carrying the
  ; detail
}
; N-AALP ERROR OBJECT (Control/Error surface: channel 0x0000, kind
; 3). The body of a Control/Error object. It reports one fail-closed
; rejection reason as BOTH a numeric `code` (field 1) and its
; registered `name` (field 2), plus an OPTIONAL free-text `detail`
; (field 3) and an OPTIONAL `subject` content id (field 4, the object
; the error is about). The Control/Error kind has effect read_only
; (kind table) -- an error report effects nothing. Field 1 is `code :
; uint`, deliberately NOT the naalp-error-code enum below, so a code
; from a LATER-registered or private-use point still validates
; against this grammar (the open, RFC-Required registry).
; DUAL-CARRIAGE: a receiver that KNOWS `code` MUST find `name` equal
; to the registered name for that code, else it rejects `Malformed`
; (the strengthening direction); a `code` it does NOT know is opaque
; and non-fatal (name diagnostic only, no semantics inferred), for
; forward compatibility. The authoritative name<->code taxonomy is
; the naalp-error-code enum below.
naalp-error = {
  1 : uint,
  ; code -- registered error code (standards 1..0x7FFF; private
  ; >=0x8000)
  2 : tstr,
  ; name -- the registered name for `code` (MUST agree; else
  ; Malformed)
  ? 3 : tstr,
  ; detail -- OPTIONAL non-normative human diagnostic (no security
  ; meaning)
  ? 4 : bstr,
  ; subject -- OPTIONAL content id of the object the error is about
}
; N-AALP ERROR CODES registry (# IANA). Registration policy RFC
; Required / FCFS in the standards range 1..0x7FFF; >=0x8000 is
; private-use, no registration; 0 is reserved and MUST NOT appear on
; the wire. The naalp-error body above binds `code` as a bare uint,
; NOT this enum, so the registry can grow without breaking CDDL
; validation of a future or private code. This enum is the
; authoritative error-code taxonomy.
;
naalp-error-code = &(
  NonCanonical: 1,
  DepthExceeded: 2,
  Malformed: 3,
  ContentIdMismatch: 4,
  HeaderBodyMismatch: 5,
  UnsupportedVersion: 6,
  UnknownCriticalExt: 7,
  UnknownKind: 8,
  RangeError: 9,
  NonNFC: 10,
  WrongAudience: 11,
  TooLarge: 12,
  TooManyCauses: 13,
  TooManyExtensions: 14,
  TooManyChunks: 15,
  UnknownAlg: 16,
  KeyAlgMismatch: 17,
  ProfileDowngrade: 18,
  HybridIncomplete: 19,
  SuiteMismatch: 20,
  CompositeRefused: 21,
  BadSignature: 22,
  SignerMismatch: 23,
  RotationUnauthorized: 24,
  KeyRevoked: 25,
  EffectNotAuthorized: 26,
  UnauthenticatedPrincipal: 27,
  MalformedSafetyLabel: 28,
  ApprovalRequired: 29,
  ApprovalMismatch: 30,
  ApprovalExpired: 31,
  AlreadyConsumed: 32,
  ConsumeFork: 33,
  ConsumeForkInvalid: 34,
  ConsumeReceiptUnsigned: 35,
  LedgerCorrupt: 36,
  LedgerUnsigned: 37,
  AudienceMismatch: 38,
  FreshnessSelfAsserted: 39,
  UnknownRefusalOutcome: 40,
  RefusalDetailLeak: 41,
  ChainBroken: 42,
  Equivocation: 43,
  CausalViolation: 44,
  ReceiptUnsigned: 45,
  ForkProofInvalid: 46,
  StageOutOfOrder: 47,
  StreamDigestMismatch: 48,
  StreamStateError: 49,
  ConfidentialTransportRequired: 50,
  PeerUnauthenticated: 51,
  NotDelivered: 52,
  MappingError: 53,
  EffectDeclarationMismatch: 54,
  StateTransitionError: 55,
  CapExceedsParent: 56,
  TransformCycle: 57,
  InputGateBypass: 58,
  TaskStateError: 59,
  ScopeOverlapConflict: 60,
  ReconcileMismatch: 61,
  WrongFlow: 62,
  SeqGap: 63,
  AboveCeiling: 64,
  GapDetected: 65,
  CommitMismatch: 66,
  ContMalformed: 67,
  GrantExpired: 68,
  GrantNotYetValid: 69,
  GrantRevoked: 70,
  UntrustedChainRoot: 71,
  DelegationDepthExceeded: 72,
  GrantMalformed: 73,
  NameMalformed: 74,
  NameChainBroken: 75,
  NameForkProofInvalid: 76,
  IllegalTransition: 77,
  TaskChainBroken: 78,
  ForeignCard: 79,
  DescMalformed: 80,
  MalformedApprovalFlag: 81,
  DirForkProofInvalid: 82,
  ImporterMismatch: 83,
  UnknownDescriptionFormat: 84,
  VerifierKeyMismatch: 85,
  NegMalformed: 86,
  UnknownRole: 87,
  UnknownProfile: 88,
  NotDescended: 89,
  NotOffer: 90,
  NotAccept: 91,
  MalformedCriticalFlag: 92,
  UnknownCriticalRisk: 93,
  ReferenceMismatch: 94,
  MalformedAnnotation: 95,
  EffectUnderDeclared: 96,
  EffectOutsideLattice: 97,
  ToolCallMalformed: 98,
  PayMalformed: 99,
  UnknownPaymentFormat: 100,
  GwMalformed: 101,
  UnknownGatewayDecision: 102,
  UIMalformed: 103,
  UIChainBroken: 104,
  UnknownUIEventKind: 105,
  ActionSubstituted: 106,
  UINoConsent: 107,
  StaleEpoch: 108,
  Unauthorized: 109,
  OwnerImmutable: 110,
  MemberExists: 111,
  MemberUnknown: 112,
  OwnerExists: 113,
  RoleInvalid: 114,
  RoomOpMismatch: 115,
  OpUnknown: 116,
  PrincipalUnknown: 117,
  PrincipalExists: 118,
  RebindUnauthorized: 119,
  EgMalformed: 120,
  UnknownEgressBinding: 121,
  DecisionMalformed: 122,
  UnknownOrderingBasis: 123,
  OrderingDisclosureMalformed: 124,
  TermDispositionMalformed: 125,
  CheckpointMalformed: 126,
  WitnessRootMismatch: 127,
  InclusionProofInvalid: 128,
  ForeignProfileMalformed: 129,
  HazardMalformed: 130,
  HazardNotCovered: 131,
  HazardUnknown: 132,
)
; TRUST-DECISION INPUT-CLASS REGISTRY. The open,
; RFC Required / FCFS registry of the decision inputs the closure
; property governs, each classified by its safe shape (verifiable /
; attenuating / committed). It grows input-by-input as new
; architectures mint new inputs, without reopening the property.
;
trust-decision-input-class = &(
  identifier:               1,
  ; the identifier a decision keys on (verifiable)
  object-parse:             2,
  ; the object bytes and their parse (verifiable)
  object-identity:          3,
  ; the object content id (verifiable)
  conformance-expectation:  4,
  ; the expected conformance value (verifiable)
  verification-procedure:   5,
  ; the evaluator's own procedure (verifiable)
  delegated-authority:      6,
  ; authority derived across a delegation hop (attenuating)
  approved-action:          7,
  ; which action an approval authorizes (committed)
  negotiated-parameters:    8,
  ; the negotiated profile and parameters (committed)
  validity-clock:           9,
  ; when a credential's validity is judged (committed)
  use-context:              10,
  ; the context a portable verdict is valid in (committed)
)
; The consume ledger is a durable, hash-chained set keyed by the
; approval content id. Consume is an atomic compare-and-set: the
; first append for an approval id wins; a second is rejected
; (AlreadyConsumed). The head after an entry is SHA-384(entry); the
; entry carries the prior head in field 2, so editing any entry
; breaks the next entry's linkage (LedgerCorrupt on replay). The
; genesis head is 48 zero bytes. Atomicity = the store's write-ahead
; log (persist-before-acknowledge) + a single-writer-per-approval-id
; discipline.
naalp-consume-entry = {
  1 : uint,
  ; seq -- ledger sequence position
  2 : bstr,
  ; prev -- prior chain head (48 bytes; genesis = zero)
  3 : bstr,
  ; approval_id -- the approval content id being consumed
  4 : tstr,
  ; by -- consumer signer id
}

; The ledger-signed consume receipt -- draft-01 addition. It moves
; the anti-double-spend counter OFF the requester and ONTO the
; consuming ledger (the ordering authority): the receipt binds the
; approval content id to the LEDGER's own forward-only position and
; is SIGNED BY THE LEDGER KEY over these exact bytes. The requester
; cannot forge the ledger's position or signature, so a partition
; that spends one approval twice leaves TWO ledger-signed receipts
; against ONE approval id, each carrying a position drawn from forked
; state -- a contradiction authored by neither the requester nor a
; thief, provable on comparison (ConsumeFork; the surfaced evidence
; carries both receipts and both ledger signatures). It does not
; PREVENT the second spend; it makes the double-spend detectable in
; bytes neither party could repudiate, and the approval's expiry
; bounds the exposure window. Keyed by approval content id,
; first-append-wins: on one reachable ledger the first consume
; assigns exactly one position and one receipt; a byte-identical
; re-emission is a benign duplicate, and a second receipt with a
; DIFFERENT position (or a DIFFERENT ledger) is a detected fork.
; Wrapping receipts as Audit-channel (0x000B) objects. This does not
; alter naalp-consume-entry (the ledger's internal hash-chained
; entry, above).
naalp-consume-receipt = {
  1 : bstr,
  ; ledger -- the consuming ledger's signer id (the ordering
  ; authority)
  2 : bstr,
  ; approval_id -- the approval content id consumed (the
  ; compare-and-set key)
  3 : uint,
  ; position -- the ledger's forward-only position bound to this
  ; consume
}

; ---- audit chain + causal graph + tiered ordering -----------------
; An ordering authority records each accepted object by appending a
; signed Receipt, signed by the authority with the crypto over the
; deterministic-CBOR body. The chain is tamper-evident: the head
; after a receipt is SHA-384(receipt body), the genesis prev is 48
; zero bytes, and the body carries the prior head in field 1 -- so
; any reorder, omission, or substitution breaks a `prev` link
; (ChainBroken) or duplicates a `seq`. The authority NEVER mutates
; the origin object to order it; ordering is an outer signed layer
; and the object's own signature stays valid. `at` is the authority's
; time anchor, evidence a verifier checks independently of the
; signer's clock. An independent auditor detects equivocation -- two
; receipts by one authority at one `seq` naming different objects --
; from the signed receipts alone and mints a non-repudiable
; naalp-fork-proof (below, draft-01) carrying both of the accused's
; signatures. Wrapping receipts as Audit-channel (0x000B) objects;
; the federation (higher) tier that reconciles multiple authorities
; over the shared causal graph -- both tiers order the identical
; signed objects, so federation needs no wire change.
naalp-receipt = {
  1 : bstr,
  ; prev -- hash of the previous receipt body (48 bytes; genesis =
  ; zero)
  2 : bstr,
  ; obj -- content id of the accepted object (never the object
  ; itself)
  3 : uint,
  ; seq -- monotonic sequence position within this authority's chain
  4 : uint,
  ; at -- authority time anchor, epoch ms
}

; ForkProof -- the auditor's NON-REPUDIABLE equivocation proof.
; CHANGED IN draft-01 (SUPERSEDES draft-00's ForkProof): draft-00's
; fork proof named the two conflicting receipts but carried NEITHER
; conflicting signature, so an accused signer could deny the fork.
; draft-01's ForkProof carries the accused authority's OWN two
; signatures -- sig-a over body-a and sig-b over body-b, two
; validly-signed receipts by ONE authority at ONE seq naming
; DIFFERENT objects -- making the proof self-contained and
; non-repudiable: any third party verifies both signatures against
; the accused key with no further evidence. `ext-counter` is an
; external monotonic counter bound into the proof so a replayed or
; reordered proof is detectable. The two embedded bodies are
; naalp-receipt encodings (the exact bytes each signature covers).
; Verify accepts iff signer is present, the two bodies share one seq,
; name different objects, and BOTH signatures verify under the
; accused key; it is rejected whole (fail-closed) otherwise.
naalp-fork-proof = {
  1 : bstr,
  ; signer -- accused authority signer id (envelope field-5 form)
  2 : uint,
  ; ext-counter -- external monotonic counter bound into the proof
  3 : bstr,
  ; body-a -- receipt A body (naalp-receipt det-CBOR); sig-a's input
  4 : bstr,
  ; sig-a -- the accused authority's signature over body-a
  5 : bstr,
  ; body-b -- receipt B body (naalp-receipt det-CBOR); obj !=
  ; body-a's
  6 : bstr,
  ; sig-b -- the accused authority's signature over body-b
}

; The causal graph is not a distinct wire object: an edge "A causes
; B" is carried by B's object body field 8 (`causes`, an array of
; content ids) and proven by B's own signature. It is a signed
; partial order, checkable offline with no ordering authority
; present; a total order is a policy layered over it. A cause an
; effect could not have seen -- a present cause at a later ordering
; position, or a cycle -- is rejected (CausalViolation).

; ---- delivery stages + persist-before-ack + switchboard -----------
; Delivery is four distinct, monotonic, separately-observable stages
; -- there is no single "sent" boolean. Each stage is a signed
; delivery.update naming the target object's content id and the stage
; reached. Stages advance in order; observing a stage earlier than
; the one already reached is StageOutOfOrder. An endpoint MUST
; durably persist an object (write-ahead log fsync) BEFORE emitting
; the acknowledgment that advances its stage, so a crash immediately
; after an acknowledgment loses nothing (persist-before-ack). The
; live switchboard (two connections held open, objects passed through
; both directions concurrently) and the content-free relay (a relay
; holding objects only in transit still writes a valid audit trail
; over content ids) are behavioural properties of an endpoint/relay,
; not additional wire objects. Wrapping delivery.update as a
; Delivery-channel object.
delivery-stage = &(
  persisted_origin: 0,
  ; object durably persisted at the origin
  accepted_relay:   1,
  ; accepted by a relay in transit
  persisted_target: 2,
  ; durably persisted at the target
  presented:        3,
  ; presented to the target application
)
naalp-delivery-update = {
  1 : bstr,
  ; obj -- content id of the object whose delivery this reports
  2 : delivery-stage,
  ; stage -- the stage reached (0..3)
  3 : uint,
  ; at -- observer time, epoch ms
}

; ---- native streaming + per-stream commitment ---------------------
; A native stream runs on the N-PAMP Stream channel 0x000C, distinct
; from foreign streamed carriage (0x000D) -- N-AALP never carries a
; foreign protocol on 0x000C. The chunks are raw data frames the
; transport AEAD already authenticates; they are NOT signed
; individually (per-chunk ML-DSA would be ruinous). Instead three
; signed objects govern the stream. StreamOpen binds the stream's
; identity, effect, and -- where it causes an effect -- its approval;
; a stream whose effect is not authorized is refused BEFORE any
; chunk. StreamCommit carries a single rolling SHA-384 over the
; chunks in absolute-offset order (a bare 48-octet digest), making
; the whole stream non-repudiable with one signature, not N; altering
; any delivered byte invalidates it (StreamDigestMismatch). Optional
; StreamCheckpoints let a verifier confirm a prefix (digest_so_far =
; SHA-384 of the prefix through that offset) without waiting for the
; end. The same three objects map onto QUIC / WS / HTTP native
; streaming and the commitment verifies identically. Full-duplex is
; inherent Wrapping these as Stream-channel objects.
naalp-stream-open = {
  1 : bstr,
  ; stream_id
  2 : effect,
  ; effect -- the stream's effect class
  ? 3 : bstr,
  ; approval -- content id of the approval binding (present iff
  ; effecting)
  4 : uint,
  ; substream -- NPAMP-STREAM sub-stream id
}
naalp-stream-commit = {
  1 : bstr,
  ; stream_id
  2 : bstr,
  ; digest -- rolling SHA-384 over the complete ordered stream (48
  ; octets)
}
naalp-stream-checkpoint = {
  1 : bstr,
  ; stream_id
  2 : uint,
  ; through_offset -- absolute offset the prefix ends at
  3 : bstr,
  ; digest_so_far -- SHA-384 over the prefix through_offset (48
  ; octets)
}

; ---- N-AALP-CONT flow continuation --------------------------------
; A long-running flow costs two full ML-DSA signatures (FlowOpen +
; FlowCommit) regardless of the number of continuations, generalizing
; native streaming from a byte stream to a flow of typed steps.
; FlowOpen fixes the effect ceiling + approval bindings and is a
; signed N-AALP object whose authority is reconstructable from its
; bytes alone; its head = SHA-384(body) anchors the chain and its
; content-id (multihash(0x20, SHA-384(body))) is carried by every
; child object. A Continuation is a cheap UNSIGNED hash-chain link
; (head = SHA-384(body); prev = the previous head, the FlowOpen head
; for seq 0) whose effect MUST be <= the ceiling (AboveCeiling
; otherwise). A Checkpoint confirms a contiguous prefix (a
; dropped/reordered link is GapDetected). FlowCommit binds the final
; chain head under the second full signature (CommitMismatch on a
; missing/altered link). Domain separation is structural: the four
; body shapes (3 / 5 / 3 / 2 fields) are distinct.
naalp-flow-open = {
  1 : bstr,
  ; flow_id
  2 : effect,
  ; effect_ceiling -- the max effect any continuation may cause
  3 : [* bstr],
  ; approvals -- content-ids of the approvals authorizing the flow
}
naalp-continuation = {
  1 : bstr,
  ; flow_open_id -- content-id of the FlowOpen (WrongFlow if
  ; mismatched)
  2 : uint,
  ; seq -- 0-based position in the chain
  3 : effect,
  ; effect -- this step's effect; MUST be <= the FlowOpen ceiling
  4 : bstr,
  ; payload_id -- content-id of this step's payload
  5 : bstr,
  ; prev -- the previous link head (FlowOpen head for seq 0) (48
  ; octets)
}
naalp-flow-checkpoint = {
  1 : bstr,
  ; flow_open_id
  2 : uint,
  ; through_seq -- the contiguous prefix ends at this seq
  3 : bstr,
  ; head -- chain head after the prefix (48 octets)
}
naalp-flow-commit = {
  1 : bstr,
  ; flow_open_id
  2 : bstr,
  ; final_head -- chain head over the whole ordered sequence (48
  ; octets)
}

; ---- transport bindings -------------------------------------------
; A transport binding adds NO new wire object: it carries exactly one
; signed N-AALP object (any production above) as one message unit,
; byte-for-byte, over N-PAMP / QUIC / WebSocket / HTTP, with
; identical object semantics. The media type is
; `application/vnd.bubblefish.naalp+cbor` (one object per
; representation), registered in the IANA Considerations. The object
; is self-secured; the binding adds only framing and, from the
; transport, confidentiality and connection authentication. The
; confidentiality boundary is NORMATIVE: an object marked sensitive
; MUST NOT be emitted in cleartext over a non-confidential transport
; -- the binding refuses it (ConfidentialTransportRequired) and
; directs the deployment to a confidential transport (N-PAMP is the
; reference confidential transport). A transport lacking peer
; authentication where policy requires it is refused
; (PeerUnauthenticated). These are endpoint behaviours, not wire
; productions.

; ---- foreign carriage by class ------------------------------------
; N-AALP carries a foreign protocol by wrapping its message,
; octet-for-octet, in a signed N-AALP carriage object interpreted by
; a carriage CLASS. The carriage body is a normal N-AALP object body
; (envelope field 10): signed, effect-labeled, identity-bound,
; audited. The `foreign` field is carried VERBATIM and MUST NOT be
; re-serialized, canonicalized, summarized, or rewritten; N-AALP
; metadata is carried around it, never inside it. The carriage
; object's signer remains the authority -- a foreign identity NEVER
; becomes an N-AALP authorization identity. The OPAQUE class carries
; any protocol, including an undefined one, on an experimental
; protocol id with no registration. protocol_id ranges: standards
; 0x01-0x0F (RFC Required / FCFS), experimental 0x10-0x7F (no
; registration), private 0x80-0xFF. content_type (field 3) is the
; foreign ENCODING, an OPEN registry ("N-AALP Carriage Content
; Types"): standard encodings 0x00-0x0F (RFC Required / FCFS),
; experimental 0x10-0x7F and private 0x80-0xFF take no registration
; (0 json, 1 octet-stream, 2 text). Over N-PAMP the raw `foreign`
; octets ride an N-PAMP Bridge frame of the matching class
; byte-exact.
naalp-carriage-class = &(
  jsonrpc: 0,
  ; any JSON-RPC 2.0 protocol (MCP, A2A core)
  http:    1,
  ; any HTTP-semantics protocol
  msg:     2,
  ; any message-passing / performative protocol
  stream:  3,
  ; any event/streaming foreign reply
  doc:     4,
  ; capability/schema documents (agent cards, tool catalogs)
  opaque:  5,
  ; any declared-content-type payload, incl. undefined protocols
)
naalp-carriage-body = {
  1 : uint,
  ; protocol_id -- N-AALP registry
  2 : naalp-carriage-class,
  ; class -- 0 JSONRPC .. 5 OPAQUE
  3 : uint,
  ; content_type -- foreign encoding (open registry)
  4 : bstr,
  ; correlation -- exchange correlation token
  5 : tstr,
  ; method -- advisory routing key (foreign op name)
  6 : bstr,
  ; foreign -- the foreign message, carried octet-for-octet
}

; ---- the twenty channel surfaces, baseline tier -------------------
; A channel surface adds NO new encoding, signature, or identity: it
; only assigns `kind` codes (object body field 2), each scoped by the
; `channel` id (field 3), and binds each kind to a declared `effect`
; (field 7). All twenty channels (0x0000..0x0013) and their baseline
; kinds are enumerated in the machine-readable registry (65 kinds). A
; fixed-effect kind's object MUST carry exactly its declared effect
; (EffectDeclarationMismatch otherwise); a variable-effect kind
; (Stream StreamOpen, Bridge Carriage) takes the carried/stream
; action's effect, authorized at run time by the effect lattice. An
; object on an unregistered (channel, kind) is rejected
; (UnknownKind). Each channel's baseline body is a spine production
; already defined above -- Identity rotation/
; revocation/foreign-link, Governance approval/held/consume, Audit
; receipt/fork-proof, delivery-update, Stream open/commit/checkpoint,
; Bridge carriage -- or a thin channel-specific body carried in
; object body field 10; the surface introduces no new wire
; production, only the kind/effect/state vocabulary. Higher tiers
; (tier 1+) are the higher-tier surfaces below.

; ---- Higher tiers: federated ordering + the tier model ------------
; The channel tier is envelope field 4; tier = 0 is the frozen
; baseline (all twenty channels). A higher tier (tier 1+) adds
; capability WITHOUT changing the baseline envelope, effect
; vocabulary, identity model, or audit chain: a baseline-tier
; verifier accepts a higher-tier object's spine and IGNORES an
; unknown higher-tier NON-critical extension (field 11), while an
; unknown CRITICAL extension (field 12) it cannot honor is rejected
; fail-closed (UnknownCriticalExt) -- the same field-11/field-12
; mechanism defined in the protected header. No new wire field is
; introduced for tiering.
;
; Federated ordering (the Federation channel higher tier, tier 1):
; multiple independent authorities each issue baseline receipts over
; their own scope, and a signed Reconcile object records a
; DETERMINISTIC merge of their receipt chains over the shared causal
; graph -- a topological linearization of the union causal DAG
; tie-broken by object content id (bytewise ascending). Because the
; order depends only on the causal graph, any split of the same
; objects across authorities reconciles to the same order, so moving
; from single-authority to federated ordering requires NO envelope or
; object change. ScopeOverlapConflict (an object claimed by two
; authorities) is an operator error at baseline and is resolved by
; the merge at tier 1 (the object is ordered once).
naalp-reconcile = {
  1 : [+ tstr],
  ; authorities -- the ordering authorities' signer ids reconciled
  2 : [+ bstr],
  ; order -- the deterministic total order, object content ids
}

; ---- Collaboration / rooms membership (higher tier, tier 1) -------
; A Phase-3 ADDITIVE higher-tier surface over the frozen baseline
; envelope, effect vocabulary, identity model, and audit chain -- it
; introduces NO new wire mechanism, only tier-1 kinds on the
; Governance channel (0x0004; membership ops) and the Identity
; channel (0x0003; the principal registry), so it reuses the
; naalp-object envelope, the naalp-receipt chain, and the identity
; records unchanged. A baseline verifier that has not licensed the
; tier rejects a room kind as UnknownKind (fail-closed), consistent
; with the tier model above. It builds three recorded decisions: #4a
; Membership carriage -- a membership change is a first-class SIGNED
; naalp-object whose body (field 10) is a naalp-room-op. It is
; CURSOR-OCCUPYING and RECEIPT-CHAINED: each accepted op is ordered
; at a cursor by an ordering authority's naalp-receipt over the op's
; content id (multihash(0x20, SHA-384(op body))), weaving membership
; into the append-only audit chain. It is EPOCH-BUMPING: the op
; carries the membership epoch it is built against (field 3); each
; accepted op increments the room's epoch, so a superseded-epoch op
; is rejected (StaleEpoch). Ops:
; create/add_member/remove_member/change_role/add_owner. #4b O2
; ownership -- multi-owner, ADD-ONLY: add_owner adds an owner; an
; owner is never removed (remove_member refuses an owner) nor demoted
; (change_role refuses to lower an owner), so the owner count is
; monotonically >= 1 (a room can never become ownerless). #3 Delivery
; Model B -- a naalp-principal-binding maps a stable semantic
; principal id to a durable Handle (a signer id), kept as a
; per-principal SHA-384 chain (head = SHA-384(body), prior head in
; field 4, genesis = 48 zero bytes). A delivery addresses the
; semantic id and resolves it to the Handle at send time -- a durable
; naming layer above the connection-scoped N-PAMP PeerHandle. A
; rebind is authorised only by a verified rotation from the current
; handle to the new handle; a rebind to an unrelated key is refused.
; The membership op-authorisation, epoch guard, owner-immutability,
; and rebind continuity are endpoint behaviours (graded by two
; implementations against the non-circular oracle), not wire
; productions.
naalp-room-op = {
  1 : bstr,
  ; room -- room id
  2 : room-op-code,
  ; op -- membership operation
  3 : uint,
  ; epoch -- membership epoch this op is built against (bumps on
  ; accept)
  4 : tstr,
  ; subject -- affected member signer id (the creator, for create);
  ; NFC
  5 : member-role,
  ; role -- the role assigned to the subject
}
room-op-code = &(
  create:        0,
  add_member:    1,
  remove_member: 2,
  change_role:   3,
  add_owner:     4,
)
member-role = &(
  member: 0,
  admin:  1,
  owner:  2,
)
naalp-principal-binding = {
  1 : tstr,
  ; principal -- the stable semantic principal id (MUST be NFC)
  2 : tstr,
  ; handle -- the current durable Handle (a signer id) it resolves to
  3 : uint,
  ; epoch -- monotonic per-principal binding epoch (0 for first bind)
  4 : bstr,
  ; prev -- prior per-principal chain head (48 bytes; genesis = zero)
}

; ---- multi-hop agent-delegation grant -- draft-01 addition --------
; A DelegationGrant is a NORMAL N-AALP object (envelope): an
; independent COSE_Sign1 whose ISSUER is the verified envelope signer
; (field 5), NEVER a body field. It is a Capability-channel (0x0002)
; kind DelegationGrant (kind 4), tier 1 -- a named escalation adding
; MULTI-HOP capability under the frozen baseline envelope; a verifier
; that has not licensed the tier rejects the kind as UnknownKind
; (fail-closed). The object's OWN effect (envelope field 7) is
; non_idempotent_write (issuing a grant); effect_cap below is the
; SEPARATE ceiling it confers on the subject. It REUSES the
; CapDelegate substrate -- parent-by-content-id in `causes` and
; CapExceedsParent attenuation -- rather than a parallel mechanism
; (D5). The delegation PARENT (the grant or CapIssue that authorised
; THIS grant's issuer) is named by content id in envelope field 8
; (`causes`): the UNIQUE cause resolving to a Capability authority
; object (CapIssue kind 0, CapDelegate kind 1, DelegationGrant kind
; 4) whose subject/holder == this grant's issuer; a root grant
; (issuer in the verifier's trust-anchor set) has none, two-or-more
; is ChainBroken. scope is OPTIONAL: an absent field 6 is
; unconstrained (an empty scope is not a distinct value).
naalp-delegation-grant = {
  1 : tstr,
  ; subject -- delegatee agent id (agent B), signer-id form; MUST be
  ; NFC
  2 : effect,
  ; effect_cap -- MAX effect conveyed (the lattice); child <= parent
  ; else CapExceedsParent
  3 : uint,
  ; max_depth -- max FURTHER delegation hops below this grant (0 =
  ; act, not re-delegate)
  4 : uint,
  ; not_before -- validity-window start, epoch ms (GrantNotYetValid
  ; before)
  5 : uint,
  ; not_after -- validity-window end, epoch ms (GrantExpired after)
  ? 6 : tstr,
  ; scope -- OPTIONAL NFC resource scope; child scope MUST be
  ; contained else CapExceedsParent
}

; ---- The checkable minimum: recheck procedure (draft-01 addition) -
; A signature makes a body claim ATTRIBUTABLE; a claim is CHECKABLE
; only if a stranger can re-derive it without trusting the speaker,
; which requires the object to NAME the procedure a verifier runs to
; re-check it. That naming is carried as extension key 13 (see
; naalp-object above): the VALUE is a recheck-procedure id into this
; CLOSED registry. In the non-critical ext map (field 11) it is
; may-ignore (an unknown id ignored); in the critical cext map (field
; 12) it is must-understand and an unknown id is rejected
; (UnknownCriticalExt, the critical-extension rule reaching the
; procedure it names). A known id verifies in either map. There is no
; boolean on the wire -- placement (ext vs cext) is the criticality
; signal (the N-AALP spine carries no CBOR booleans). recheck is an
; ext-key (key 13) and does NOT move naalp-version -- the version is
; anchored by the top-level audience envelope field.
;
recheck-procedure = &(
  recompute-content-id: 1,
  ; recompute the content id from the body and compare
  verify-cose-sign1:    2,
  ; verify the COSE_Sign1 signature under the signer key
  walk-causes:          3,
  ; walk the signed causal partial order offline
  replay-consume-check: 4,
  ; replay the single-use consume ledger for the approval
)

; ---- The per-signer forward-only counter (draft-01 addition) ------
; A signer MAY carry a forward-only counter it increments on each
; object, to DETECT key duplication -- NOT to prevent it. It is
; carried as extension key 14 in the object's NON-CRITICAL ext map
; (field 11, may-ignore), covered by the SIGNER's own COSE_Sign1
; signature -- the deliberate contrast with the LEDGER-signed
; naalp-consume-receipt position. The value is a bare forward-only
; position; ANY 64-bit uint is valid (a large value is not an error,
; it must decode as a 64-bit unsigned position without rounding). The
; field is OPTIONAL: an absent counter is valid. It is
; DETECTION-only: a single self-authored sequence proves nothing;
; duplication is flagged only when two conflicting sequences bearing
; ONE signer id physically meet where the attacker cannot suppress
; one (# Security Considerations). Placing the counter in the
; critical cext map is an unrecognized critical key
; (UnknownCriticalExt). No wire-version bump: this reuses the ext
; mechanism (a new ext-key assignment, not a change to an existing
; object body), so naalp-version stays at 2.
signer-counter = uint

; ---- The NAALP-MCP binding profile (draft-01 addition) ------------
; An MCP tool call is CARRIED (its bytes unchanged -- carriage, not
; adoption), its unenforced, untrusted annotation hints are mapped to
; the closed four-effect lattice by a PUBLISHED table, and the
; WRAPPING SIGNER is accountable for that mapping (a false
; declaration is attributable to that key). The wrapper is a
; Bridge-channel (0x000D) tier-1 kind McpToolCall (kind 1) -- a named
; escalation over the frozen baseline Carriage kind (0), under the
; frozen envelope; a baseline verifier that has not licensed the tier
; rejects it as UnknownKind (fail-closed). Its OWN envelope effect
; (field 7) is the wrapping signer's DECLARED effect; a verifier
; independently recomputes the annotation-derived effect from the
; carried annotations and enforces the MORE SEVERE of the two (the
; good-regulator attenuator -- an unknown or disagreeing input
; collapses UP, never down). A declared effect BELOW the
; annotation-derived effect is rejected (EffectUnderDeclared); an
; annotation set that maps outside the lattice is rejected
; (MalformedAnnotation), never defaulted to benign.
;
;
; The MCP ToolAnnotations are booleans in JSON, but the N-AALP spine
; carries NO CBOR boolean Each hint is transcribed as the uint 1
; (true) / 0 (false); an ABSENT hint is the MCP documented default,
; applied by the mapping (readOnlyHint default false, destructiveHint
; default true, idempotentHint default false, openWorldHint default
; true). destructiveHint's default of TRUE is why an un-annotated
; write maps to destructive -- the same fail-closed rule as N-AALP's
; "absent effect on a state-changing object => destructive". A
; present 0 and an absent hint encode to DIFFERENT bytes (empty !=
; absent) though they may resolve to the same effect. A hint value
; outside {0,1} is rejected (it transcribes no boolean).
; openWorldHint (key 4) is carried for accountability but is an
; ADVISORY risk signal ONLY -- it never enters the effect lattice
; (risk dimensions ride as advisory labels, not effects).
mcp-hint = 0..1
; a JSON boolean hint transcribed to the spine: 1 = true, 0 = false
naalp-mcp-annotations = {
; the wrapping signer's transcription of the tool's MCP annotations
  ? 1 : mcp-hint,
  ; readOnlyHint (absent => MCP default false)
  ? 2 : mcp-hint,
  ; destructiveHint (absent => MCP default true; the fail-closed
  ; default)
  ? 3 : mcp-hint,
  ; idempotentHint (absent => MCP default false)
  ? 4 : mcp-hint,
  ; openWorldHint (absent => MCP default true; ADVISORY, not an
  ; effect)
}
naalp-mcp-tool-call = {
; the wrapper body (envelope field 10); its OWN effect is field 7
  1 : bstr,
  ; tool -- the MCP tool definition bytes, carried octet-for-octet
  2 : bstr,
  ; args -- the MCP tool-call argument bytes, carried octet-for-octet
  3 : naalp-mcp-annotations,
  ; annotations -- the signer's transcription; the mapping is over
  ; these
}
; The approval binds the content id of this call binding. Because it
; names BOTH the tool id and the args id by content id, a changed
; tool DESCRIPTION (new tool_id) OR changed ARGUMENTS (new args_id)
; yields a new call content id, invalidating a prior approval bound
; to the old one.
naalp-mcp-call-binding = {
  1 : bstr,
  ; tool_id -- content id of the tool bytes: multihash(0x20,
  ; SHA-384(tool))
  2 : bstr,
  ; args_id -- content id of the args bytes: multihash(0x20,
  ; SHA-384(args))
}

; ---- signed description / directory primitive (draft-01 addition) -
; A signed, OFFLINE-VERIFIABLE description and discovery layer
; carried on N-AALP's own signed object: the authority is the
; SIGNATURE OVER THE BYTES, never the connection or host that served
; them, so a signed description re-verifies byte-identically when an
; unrelated host serves the same bytes (a bearer credential, not a
; fetched document). It introduces NO new envelope, encoding,
; signature, identity, or audit mechanism: each object below is an
; ordinary COSE_Sign1 over a deterministic-CBOR body, reusing the
; closed effect lattice and the content-id framing. The head of each
; object is SHA-384(body); its content-id is multihash(0x20,
; SHA-384(body)).
;
; A naalp-description lists a service's operations, each a
; naalp-description-operation carrying its effect (lattice) and an
; approval declaration. requires_approval is the uint 1/0 -- the
; N-AALP spine carries no CBOR boolean; a value outside {0,1} is
; rejected (MalformedApprovalFlag), never defaulted. A
; naalp-directory is a signed collection whose members are
; content-ids (the same list-of-content-ids shape the causal partial
; order uses); it carries a monotonic per-signer version so two
; versions can be compared. Two conflicting versions from ONE signer
; -- the SAME directory and version but DIFFERENT members -- are a
; FORK, detected at the FIRST-DIFFERING member position, the same way
; the audit fork proof reports the position of an equivocation.
;
; A naalp-description-import carries a FOREIGN description format (an
; A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge)
; octet-for-octet in `foreign` (carriage, not adoption -- the foreign
; bytes MUST NOT be re-serialized, canonicalized, or rewritten) as a
; signed attestation that binds the foreign bytes' content-id
; (multihash(0x20, SHA-384(foreign))) AND an N-AALP effect mapping
; (`operations`) for the described operations. The `importer` is the
; wrapping signer id and is the SOLE authorization identity: a
; verifier recomputes the self-certifying signer id from the
; verifying key and requires `importer` to equal it (ImporterMismatch
; otherwise), so a foreign identity embedded in `foreign` NEVER
; becomes an N-AALP authorization identity -- the confused-deputy
; rule of the MCP profile and foreign carriage.
;
naalp-description-operation = {
  1 : tstr,
  ; name -- operation name (advisory routing key)
  2 : effect,
  ; effect -- the operation's effect class (lattice)
  3 : desc-approval-flag,
  ; requires_approval -- 1 requires an approval, 0 otherwise (no CBOR
  ; bool)
}
desc-approval-flag = 0..1
; a boolean transcribed to the spine: 1 = requires approval, 0 = not
naalp-description = {
  1 : bstr,
  ; service -- opaque service id
  2 : [* naalp-description-operation],
  ; operations -- the listed operations
}
naalp-description-format = &(
  a2a-agent-card:        1,
  ; A2A Agent Card
  anp-agent-description: 2,
  ; ANP Agent Description
  agntcy-agent-badge:    3,
  ; AGNTCY Agent Badge
)
naalp-directory = {
  1 : bstr,
  ; directory -- opaque directory id
  2 : uint,
  ; version -- monotonic per-signer version
  3 : [* bstr],
  ; members -- content-ids of the member objects (the causal-order
  ; shape)
}
naalp-description-import = {
  1 : bstr,
  ; importer -- the wrapping signer id; the SOLE authorization
  ; identity
  2 : naalp-description-format,
  ; format -- the foreign description format code
  3 : bstr,
  ; foreign -- the foreign description bytes, carried octet-for-octet
  4 : [* naalp-description-operation],
  ; operations -- the N-AALP effect mapping the importer attests
}

; ---- name bindings + the signed A2A task-state profile (draft-01 ad
; Two receipt-CHAINED, OFFLINE-WALKABLE surfaces reusing the audit
; receipt chain unchanged: the head of each object is SHA-384(body),
; the genesis prev is 48 zero bytes, seq is monotonic, and the body
; carries the prior head in `prev`, so editing or omitting a record
; breaks the next record's linkage. They add NO new envelope,
; encoding, signature, identity, or audit mechanism: each object is
; an ordinary COSE_Sign1 over a deterministic-CBOR body, reusing the
; content-id framing.
;
; A naalp-name-binding maps a name to a signer id and CHAINS onto the
; prior binding for that name. A key ROTATION is a NEW binding at the
; next seq naming the new signer. A binding is DATED BY ITS CHAIN
; POSITION (seq); the envelope's `created` field (naalp-object field
; 6) is advisory only. A name's history is WALKABLE offline (the
; signer succession); a deleted/omitted binding leaves a detectable
; HOLE at the first-broken position (gap-evident, as the audit chain
; / directory fork report position); two bindings by ONE authority at
; the SAME (name, seq) naming DIFFERENT signers are a FORK, reported
; at that seq (the same way the audit fork proof reports an
; equivocation position).
naalp-name-binding = {
  1 : tstr,
  ; name -- the name being bound (a durable, human-readable name)
  2 : bstr,
  ; signer -- the signer id the name maps to at this position
  ; (signer-id form)
  3 : uint,
  ; seq -- monotonic per-name chain position; seq 0 is the genesis
  ; binding
  4 : bstr,
  ; prev -- the prior binding's head (48 bytes; genesis = 48 zero
  ; bytes)
}

; A naalp-task-transition is one signed, receipt-CHAINED A2A
; (Agent2Agent) task-lifecycle state transition. The A2A TaskState
; set is an IMPORTED vocabulary (carriage, not adoption): the A2A
; specification (Section 4.1.3) defines the eight states and the
; terminal/interrupted categories NORMATIVELY (start = submitted;
; terminal = {completed, canceled, failed, rejected}; interrupted =
; {input- required, auth-required}) and leaves the exact legal edges
; to implementations; N-AALP's legal-edge table is DERIVED from those
; documented category rules and is enforced by the endpoint, not by
; this wire production (the wire carries only the from/to state
; values). `card` is the content-id of the A2A Agent Card attestation
; (a naalp-description-import with format a2a-agent-card) that binds
; the task profile to an agent/operation; a transition carrying a
; card other than the profile's bound card is rejected (ForeignCard).
; An illegal edge, a non-contiguous `from`, a transition out of a
; terminal state, or a gap/reorder in the chain is detected
; fail-closed (IllegalTransition / TaskChainBroken), position
; reported.
;
task-state = &(
  submitted:      0,
  ; acknowledged, not yet started (the start state)
  working:        1,
  ; actively processed
  input-required: 2,
  ; interrupted, awaiting client input
  auth-required:  3,
  ; interrupted, awaiting authentication
  completed:      4,
  ; terminal success
  canceled:       5,
  ; terminal, canceled before completion
  failed:         6,
  ; terminal, finished with an error
  rejected:       7,
  ; terminal, the agent declined the task
)
naalp-task-transition = {
  1 : bstr,
  ; task -- the task id (opaque)
  2 : bstr,
  ; card -- content-id of the bound A2A Agent Card attestation
  3 : task-state,
  ; from -- the source state
  4 : task-state,
  ; to -- the target state
  5 : uint,
  ; seq -- monotonic per-task chain position; seq 0's from =
  ; submitted
  6 : bstr,
  ; prev -- the prior transition's head (48 bytes; genesis = zero)
}

; ---- governed negotiation, advisory risk labels, and trust (draft-0
; Three signed surfaces reusing the closed effect lattice, the
; content-id framing, and the causal partial order (`causes`)
; UNCHANGED: each object is an ordinary COSE_Sign1 over a
; deterministic-CBOR body. head = SHA-384(body); content-id =
; multihash(0x20, SHA-384(body)).
;
; GOVERNED NEGOTIATION. offer / counter / accept are SIGNED,
; CAUSALLY-LINKED messages: each names its predecessor(s) by
; content-id in `causes` (the same list-of-content-ids shape the
; causal partial order uses). Each SELECTS a profile from the CLOSED,
; PRE-REGISTERED negotiation-profile set -- the negotiation selects a
; pre-registered profile, never a free-form capability string and
; never a runtime-generated handler. The three productions are
; distinguished by a fixed `role` literal (0/1/2), so an offer body
; never validates against the accept production and vice-versa. An
; accept MUST DESCEND from its offer along the `causes` DAG (enforced
; by the endpoint, NotDescended otherwise); an unknown profile
; (UnknownProfile) or role is rejected fail-closed. The
; machine-readable role/profile source is the negotiation-role /
; negotiation-profile enums below.
negotiation-role = &(
  offer:   0,
  ; the initiating offer (the root; no causes)
  counter: 1,
  ; a counter chaining onto the offer or a prior counter
  accept:  2,
  ; the accept; it MUST descend from its offer
)
negotiation-profile = &(
  baseline:  0,
  ; the baseline capability profile
  streaming: 1,
  ; the native-streaming capability profile
  batch:     2,
  ; the batched-delivery capability profile
)
naalp-negotiation-offer = {
  1 : bstr,
  ; negotiation -- opaque negotiation id (ties the exchange together)
  2 : 0,
  ; role -- offer (fixed literal 0)
  3 : negotiation-profile,
  ; profile -- the selected pre-registered profile (closed set)
  4 : [* bstr],
  ; causes -- content-ids of predecessors (empty for an offer)
}
naalp-negotiation-counter = {
  1 : bstr,
  ; negotiation
  2 : 1,
  ; role -- counter (fixed literal 1)
  3 : negotiation-profile,
  ; profile
  4 : [* bstr],
  ; causes -- names the offer or a prior counter
}
naalp-negotiation-accept = {
  1 : bstr,
  ; negotiation
  2 : 2,
  ; role -- accept (fixed literal 2)
  3 : negotiation-profile,
  ; profile -- the AGREED pre-registered profile
  4 : [* bstr],
  ; causes -- descends from the offer along this chain
}

; ADVISORY RISK LABELS. A naalp-risk-label is one carried label
; {code, critical}; a naalp-labeled-object carries an effect (the
; lattice) together with a set of risk labels. The vocabulary is a
; closed standard set -- sensitive/egress (gating), reversible
; (informing) -- plus a private/experimental extensible range, so
; `code` is an open uint and the known set is enforced by the
; endpoint + registry (as the signer-counter is an open uint).
; `critical` is the per-carriage must-understand flag (uint 1/0 --
; the spine carries no CBOR boolean); the critical-extension rule
; rejects an unknown CRITICAL label (UnknownCriticalRisk) and ignores
; an unknown non-critical one. LOAD-BEARING INVARIANT: a risk label
; is an ADVISORY dimension, NEVER a fifth effect -- carrying a label
; does not change the object's effect class (the closed effect
; lattice is untouched).
risk-code = uint
; a risk-label code (standard set + private/experimental extensible
; range)
risk-critical = 0..1
; per-carriage must-understand flag: 1 = critical, 0 = advisory (no
; CBOR bool)
naalp-risk-label = {
  1 : risk-code,
  ; code -- the risk-label code
  2 : risk-critical,
  ; critical -- the must-understand flag
}
naalp-labeled-object = {
  1 : effect,
  ; effect -- the effect class (field 7); the effect class derives
  ; from this ALONE -- risk labels never alter it
  2 : [* naalp-risk-label],
  ; labels -- the advisory risk labels carried on the object
}

; TRUST. A naalp-trust-ref carries a THIRD-PARTY trust statement as a
; CHECKABLE signed object: `reference` is the content-id of an
; EXTERNAL registry record (an ERC-8004-style reputation/identity
; registry record). A verifier CONFIRMS the reference by recomputing
; that content-id over the external bytes; the signature checks. But
; NO wire field WEIGHS the statement -- there is no score, rank, or
; ordering on the wire; the protocol carries trust statements and
; does not weigh them, and which to believe is left to the relying
; party.
naalp-trust-ref = {
  1 : bstr,
  ; registry -- opaque external-registry identifier (e.g.
  ; "erc-8004:reputation")
  2 : bstr,
  ; reference -- content-id of the referenced external record
  3 : bstr,
  ; subject -- the subject the statement is about (opaque id)
}

; ---- payment import, UI consent, and portable gateway evidence (dra
; Three signed surfaces reusing the closed effect lattice, the
; content-id framing, the approval + single-use consume ledger, and
; the receipt chain UNCHANGED: each object is an ordinary COSE_Sign1
; over a deterministic-CBOR body. head = SHA-384(body); content-id =
; multihash(0x20, SHA-384(body)). These are NEW productions, not
; changes to an existing object body, so naalp-version stays at 2.
;
; PAYMENT IMPORT. A naalp-payment-import carries a foreign payment
; payload -- an AP2 mandate, an Agentic Commerce Protocol delegated
; token, an x402 payload -- octet-for-octet in `foreign` (carriage,
; not adoption; the foreign bytes MUST NOT be re-serialized,
; canonicalized, or rewritten), and turns it into a value-bearing
; charge N-AALP governs with its OWN added guarantees. `format`
; selects the imported FORMAT from the closed naalp-payment-format
; registry; an unknown format is rejected (UnknownPaymentFormat). The
; naalp-payment-charge-binding names the exact value an approval
; binds by content-id -- including the foreign payload's content-id
; (`foreign_id`, the carriage binding) -- so a wrong
; amount/payee/currency OR a substituted foreign payload yields a
; different content-id and no longer matches the approval
; (ApprovalMismatch). A payment spend is a non_idempotent_write spent
; SINGLE-USE through the consume ledger (AlreadyConsumed on replay).
; There is NO fifth effect and NO payment-specific ledger. There is
; no boolean on the wire.
naalp-payment-format = &(
  ap2-mandate:         1,
  ; AP2 mandate
  acp-delegated-token: 2,
  ; Agentic Commerce Protocol delegated token
  x402-payload:        3,
  ; x402 payload
)
naalp-payment-import = {
  1 : naalp-payment-format,
  ; format -- the imported payment format (closed registry)
  2 : uint,
  ; amount -- the charge amount in minor units
  3 : tstr,
  ; currency -- the charge currency code (e.g. "USD")
  4 : bstr,
  ; payee -- the payee id (opaque)
  5 : uint,
  ; not_after -- the charge expiry, epoch ms
  6 : bstr,
  ; foreign -- the imported payment payload, carried octet-for-octet
}
; The charge-binding is the payment-import's fields with `foreign`
; replaced by its content-id (`foreign_id`); it shares the import's
; 6-field shape by design and is distinguished by position and
; semantics (the value an approval binds), not by CDDL structure. It
; is a hashing input, not itself an on-wire signed object (only
; naalp-payment-import is signed as an envelope body).
naalp-payment-charge-binding = {
; the exact value an approval binds by content-id
  1 : naalp-payment-format,
  ; format
  2 : uint,
  ; amount
  3 : tstr,
  ; currency
  4 : bstr,
  ; payee
  5 : uint,
  ; not_after
  6 : bstr,
  ; foreign_id -- content-id of the foreign payload: multihash(0x20,
  ; SHA-384(foreign))
}

; UI CONSENT BINDING. A naalp-ui-event is one shown tool-lifecycle
; event (AG-UI style) in a user- interface event stream,
; receipt-CHAINED by the chain construction: head = SHA-384(body),
; genesis prev = 48 zero bytes, monotonic seq, prior head carried in
; `prev`, so editing or omitting an event breaks the next event's
; linkage (a detectable hole with position). `kind` is the closed
; ui-event-kind set; `action` is the content-id of the exact action
; bytes shown to the user. A human approval (a naalp-approval) binds
; the shown-and-approved action's content-id, and the action actually
; executed MUST hash to that same content-id -- a SUBSTITUTED action
; has a different content-id and is rejected (ActionSubstituted).
; There is no boolean on the wire.
ui-event-kind = &(
  shown:      0,
  ; the action / tool call was shown (rendered) to the user
  args-shown: 1,
  ; the arguments were shown to the user
  approved:   2,
  ; the user approved the shown action
  rejected:   3,
  ; the user rejected the shown action
)
naalp-ui-event = {
  1 : bstr,
  ; session -- UI session id (ties the stream together)
  2 : ui-event-kind,
  ; kind -- the event kind (closed set)
  3 : bstr,
  ; action -- content-id of the exact action bytes shown at this step
  4 : uint,
  ; seq -- monotonic per-session chain position; seq 0 is the genesis
  ; event
  5 : bstr,
  ; prev -- the prior event's head (48 bytes; genesis = zero)
}

; PORTABLE GATEWAY EVIDENCE. A naalp-gateway-decision is a SIGNED
; decision object an enforcement gateway of ANY vendor emits as
; portable evidence. Its authority is the SIGNATURE OVER THE BYTES,
; never the connection or host that served them, so it verifies
; offline and RE-VERIFIES IDENTICALLY when served by a party OTHER
; than the gateway (the third-party re-serve property). This is the
; EVIDENCE FORMAT ONLY -- it defines NO policy language. `decision`
; is the closed gw-decision set; `action` is the content-id of the
; action decided about; `policy` is the opaque identity of the
; deciding policy (a name, not a program); `effect` is the effect
; class of the action. An unknown decision code is rejected
; (UnknownGatewayDecision). The gateway is the SIGNER (envelope field
; 5); a verifier resolves its key offline from the self-certifying
; signer id and checks the signature over the bytes.
gw-decision = &(
  allow: 0,
  ; the gateway allows the action
  deny:  1,
  ; the gateway denies the action
  hold:  2,
  ; the gateway holds the action pending a further step
)
naalp-gateway-decision = {
  1 : gw-decision,
  ; decision -- the decision outcome (closed set)
  2 : bstr,
  ; action -- content-id of the action decided about
  3 : bstr,
  ; policy -- the deciding policy's opaque identity (NOT a policy
  ; language)
  4 : effect,
  ; effect -- the effect class of the action
  ? 5 : ordering-disclosure,
  ; ordering (R1) -- OPTIONAL. ABSENT is read correspondence-only,
  ; never a stronger claim. The mandatory fields 1-4 are validated
  ; FIRST: a body failing a mandatory-field check is GwMalformed
  ; regardless of any optional 5/6, so a look-alike whose field 1 is
  ; not the gw-decision uint stays GwMalformed.
  ? 6 : naalp-foreign-profile-pin,
  ; foreign-profile (R8) -- OPTIONAL; present iff the decision was over
  ; foreign-protocol evidence. Pins the foreign evidence profile's
  ; identifier AND revision at decision time (bind the reference, not
  ; just the class).
}
naalp-foreign-profile-pin = {
  1 : tstr,
  ; id -- the foreign evidence profile identifier, an ABSOLUTE URI
  ; (opaque per-protocol ids drift at the mapping)
  2 : tstr,
  ; revision -- the profile revision pinned at decision time
}

; ===== EVIDENCE-RECORD FAMILY (R1 ordering + S1 DecisionRecord +
; S3 CheckpointRoot). All additive sibling productions; naalp-version
; stays 2. The accountability triple, carried natively:
; unique-selection + governed-at-T + binding-fixed-by-T. =====

; ORDERING BASIS (R1): what, if anything, establishes
; decision->effect / record->event ORDER, and from which
; observational domain. The weakest claim is the ZERO value ON
; PURPOSE: a record that says nothing, and an existing record whose
; optional ordering field is ABSENT, are both read as
; correspondence-only -- a verifier MUST NEVER infer a stronger
; ordering claim from silence (fail-closed reading direction).
; external-mechanism NAMES the mechanism; whether its operator is
; genuinely distinct from both parties is a structural deployment fact
; checkable in substance at T+n, not a claim the wire can close.
ordering-basis = &(
  correspondence-only: 0,
  single-boundary:     1,
  external-mechanism:  2,
)
ordering-disclosure = {
  1 : ordering-basis,
  ? 2 : bstr,
  ; boundary -- the single covering boundary (signer-id form); present
  ; iff basis = single-boundary
  ? 3 : bstr,
  ; mechanism -- the external sequencing mechanism's identity; present
  ; iff basis = external-mechanism
  ? 4 : bstr,
  ; relation -- the log relation binding this record under the
  ; mechanism (e.g. the content id of the naalp-checkpoint-root the
  ; record is included under); present only when basis =
  ; external-mechanism
}
; Well-formedness (fail-closed, native): correspondence-only -> keys
; 2/3/4 absent; single-boundary -> key 2 present, 3/4 absent;
; external-mechanism -> key 3 present (4 optional), 2 absent. Any
; violation is OrderingDisclosureMalformed on the whole record.

term-disposition = {
  1 : uint,
  ; kind -- 1 observed / 2 reported (reuses the producing-boundary
  ; kind codes)
  ? 2 : bstr,
  ; source -- the boundary the term was received from; present iff
  ; kind = reported
}

enforcement-disposition = &(
  enforced: 1,
  advised:  2,
)

; THE GOVERNED-DECISION RECORD (S1). A naalp-decision-record is the
; SIGNED record a governed decision point emits that it decided about
; an action under a CLOSED, uniquely-selected condition set. It is the
; carrier for the T/T+n accountability triple: UNIQUE SELECTION (field
; 2, the governing set in the clear as content ids -- identification
; AND availability); GOVERNED-AT-T (field 3, the consume-receipt spent
; at decision time -- decision-time consumption, not
; identity-to-the-act); BINDING-FIXED-BY-T (established off-record by
; inclusion under a witnessed naalp-checkpoint-root). The record is
; deliberately CLOCK-FREE: it carries no claimed time; both time
; properties are POSITIONAL, never a self-asserted timestamp. The
; signature binds THE DECISION, not a retrieval of it.
naalp-decision-record = {
  1 : bstr,
  ; action -- content id of the action decided about
  2 : [* bstr],
  ; governing -- the CLOSED governing condition set, content ids, in
  ; the clear; may be empty (a decision governed by standing policy
  ; alone names that policy object's cid here)
  ? 3 : bstr,
  ; consume -- content id of the naalp-consume-receipt that spent the
  ; governing authority at decision time. PRESENT for an allow that
  ; consumed a single-use authority; ABSENT for deny/hold (a refusal
  ; consumes nothing). A deny/hold body carrying a consume ref is
  ; rejected DecisionMalformed -- nothing was consumed.
  4 : gw-decision,
  ; outcome -- allow / deny / hold (reuses the closed gw-decision set)
  5 : ordering-disclosure,
  ; ordering -- MANDATORY (R1 folded in from the start): the record
  ; states its ordering basis or states correspondence-only; there is
  ; no silent default
  ? 6 : { * uint => term-disposition },
  ; terms -- OPTIONAL per-term observed-vs-reported dispositions, keyed
  ; by THIS record's own field numbers (1..5). A key outside the field
  ; set is TermDispositionMalformed (fail-closed).
  ? 7 : enforcement-disposition,
  ; enforcement -- OPTIONAL: whether the producer ENFORCES the outcome
  ; or only ADVISES it (the producer's own unverifiable self-account).
}

; THE NEITHER-PARTY ANCHOR PRIMITIVE (S3, RFC 9162-style). A
; naalp-checkpoint-root is a log operator's SIGNED Merkle tree head
; over a leaf set of record content ids. Tree construction follows RFC
; 9162 Section 2.1: leaf hash = HASH(0x00 || leaf), interior node =
; HASH(0x01 || left || right), instantiated with the profile hash
; SHA-384 (48-byte heads), the 0x00/0x01 prefixes supplying leaf/node
; domain separation. Checkpoints chain by prev (genesis = 48 zero
; bytes) so a withheld or reordered checkpoint breaks a link.
naalp-checkpoint-root = {
  1 : bstr,
  ; log -- the log operator's signer id
  2 : uint,
  ; size -- leaf count at this checkpoint
  3 : bstr,
  ; root -- the Merkle tree head over the leaf set (48 bytes)
  4 : bstr,
  ; prev -- the prior checkpoint root value (48 bytes; genesis zero)
  5 : uint,
  ; at -- the log's time anchor, epoch ms (advisory)
}

; A witness COUNTERSIGNS one exact checkpoint by content id. The wire
; carries the cosignature; whether the witness's observational domain
; is genuinely distinct from both parties is a structural deployment
; fact a T+n verifier checks in substance -- the wire hook for the
; neither-party property, stated honestly as a hook.
naalp-witness-cosign = {
  1 : bstr,
  ; witness -- the witness's signer id
  2 : bstr,
  ; root -- content id of the exact naalp-checkpoint-root cosigned
  3 : uint,
  ; at -- the witness's own time anchor, epoch ms (advisory)
}

; Inclusion proof: a leaf existed in the tree the root commits to (RFC
; 9162 Section 2.1.3.1 path recomputation, SHA-384-profiled). Record
; cid as a leaf under a witnessed checkpoint = existed-no-later-than
; the checkpoint (the binding-fixed-by-T leg). Verification recomputes
; the path bottom-up and compares against the named root, fail-closed
; (InclusionProofInvalid).
naalp-inclusion-proof = {
  1 : bstr,
  ; root -- content id of the naalp-checkpoint-root proven against
  2 : bstr,
  ; leaf -- the included record's content id (the leaf value)
  3 : uint,
  ; index -- the leaf's 0-based position in the tree
  4 : [* bstr],
  ; path -- the audit path, leaf-to-root sibling hashes (48 bytes each)
}

; PORTABLE EGRESS EVIDENCE (E6.3). A naalp-egress-attestation is a
; SIGNED attestation a gateway/sidecar emits that an object of a given
; effect class, bound to a given audience, crossed an egress boundary
; at a given time -- third-party re-serve, payload-free. content_bound:
; digest is the crossed object's T1 content id. content_free: digest is
; a hiding commitment SHA-384(content_id || salt), openable later by
; the gateway revealing (content_id, salt).
egress-binding = &(
  content-bound: 0,
  content-free:  1,
)
naalp-egress-attestation = {
  1 : egress-binding,
  ; binding -- content_bound vs content_free (closed set)
  2 : bstr,
  ; digest -- content id (content-bound) or commitment (content-free)
  3 : effect,
  ; effect -- the effect class of the crossed object
  4 : bstr,
  ; audience -- the bound destination (empty-permitted)
  5 : uint,
  ; at -- the gateway's egress timestamp, epoch ms
  ? 6 : ordering-disclosure,
  ; ordering -- OPTIONAL (R1); ABSENT is read correspondence-only
}

; MANUFACTURING PHYSICAL-HAZARD (Mfg-F). `hazard` is a dimension
; ORTHOGONAL to `effect`: effect (field 7) is DATA reversibility (can
; the state change be undone); hazard is PHYSICAL danger -- a
; data-reversible action may still be a high physical hazard (e.g. a
; tool re-approaching a work envelope). The two are never merged and
; neither is derived from the other. A hazard CLAIM rides as the
; critical cext key 16 (naalp-hazard-claim) on the acting object; a
; hazard AUTHORIZATION is a standalone Governance (0x0004) kind 7
; object (naalp-hazard-authorization), referenced by the acting
; object's `causes`. Coverage: EXACT class match AND full containment
; of the claim envelope in the grant envelope (frame id equal; same
; axis count and order; every claim axis inside the matching grant
; axis; claim speed_bound <= grant speed_bound; claim window a
; sub-interval of the grant window); any single failing dimension
; denies the whole claim (HazardNotCovered). All numeric bounds are
; fixed-point integers (signed mm; unsigned mm/s) -- no floats, per the
; spine's deterministic-CBOR subset. Map keys are 1-based.
;
; hazard-class is a CLOSED 0..4 enum. A DECODE-TIME rule (like effect's
; unknown->destructive): an absent or unrecognized raw hazard value
; MUST normalize to the HIGHEST class (4, motion-in-shared-space) --
; never to none(0) or a weaker value -- so a missing declaration fails
; safe (HazardUnknown when no claim exists; else HazardNotCovered
; against a lower-class grant). CDDL cannot see the absence or
; invalidity of a raw wire value, so this is a MUST on the decoder, not
; this grammar.
hazard-class = &(
  none:                   0,
  tool-actuation:         1,
  thermal:                2,
  energy-release:         3,
  motion-in-shared-space: 4,
)

; A named coordinate frame plus a signed axis-aligned bounding region
; in that frame, integer millimeters. `axes` MUST be non-empty and
; every entry MUST satisfy min <= max (HazardMalformed otherwise). The
; frame id is integrator-defined; N-AALP requires only that a claim's
; frame id equal the grant's for containment to be checkable.
spatial-bounds = {
  1 : tstr,                        ; frame -- MUST be Unicode NFC
                                    ; (NonNFC else)
  2 : [ + [min: int, max: int] ],  ; axes -- per-axis [min,max], mm,
                                    ; signed
}

; A validity window in the epoch-ms convention of the spine.
hazard-window = {
  1 : uint,   ; not_before -- epoch ms
  2 : uint,   ; not_after  -- epoch ms
}

; The full physical envelope a hazard claim or authorization bounds
; itself by. All three fields MANDATORY: a silently-absent axis, speed,
; or window is a MALFORMED envelope (HazardMalformed), never
; "unconstrained" (which would fail OPEN in a physical-safety context).
hazard-envelope = {
  1 : spatial-bounds,   ; spatial
  2 : uint,             ; speed_bound -- max instantaneous speed, mm/s
  3 : hazard-window,    ; window
}

; A signed physical-hazard claim, carried as cext key 16 on the acting
; object. `class` and `envelope` are BOTH mandatory (HazardMalformed
; otherwise).
naalp-hazard-claim = {
  1 : hazard-class,     ; class    -- the declared hazard class
  2 : hazard-envelope,  ; envelope -- the bounds this claim asserts
}

; A signed physical-hazard authorization (a grant): a standalone
; Governance (0x0004) kind 7 object. Same {class, envelope} shape as
; the claim; coverage is the exact-class-match + full-containment rule
; above (any failing dimension => HazardNotCovered).
naalp-hazard-authorization = {
  1 : hazard-class,     ; class    -- the class this authorization covers
  2 : hazard-envelope,  ; envelope -- the bounds this authorization covers
}
~~~

# Acknowledgments

N-AALP builds on the N-PAMP substrate.
