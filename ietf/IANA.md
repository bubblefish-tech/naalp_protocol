<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — IANA registration package

This document collects the IANA actions N-AALP requires, in submission form, so they can be
tracked independently of the Internet-Draft's rendered IANA Considerations (which contains the
same requests). Every registry below uses a policy an **Independent Submission** can carry: the
ISE requires the author to assert that **no IANA allocation in the document requires "IETF
Review" or "Standards Action"** (per the ISE checklist). This package is built to satisfy that
assertion — all policies are Media-Type registration (RFC 6838), Specification Required, Expert
Review, First Come First Served, or Private/Experimental Use (all RFC 8126).

> Process facts below were grounded in primary sources on 2026-07-27; see `SUBMISSION.md` for the
> WITNESSED/RELAYED citation log. Do not treat any RFC number or policy name as verified beyond
> what that log records.

---

## Part A — Media type: `application/naalp+cbor`

Register in the **standards tree** per **RFC 6838** (BCP 13), using the **`+cbor`** structured
syntax suffix, which is **already registered by RFC 8949** in the IANA "Structured Syntax
Suffixes" registry — N-AALP does **not** register `+cbor`, it references it.

Registration path for an Independent Submission (not the IETF stream): the media type is
registered under **Specification Required / Expert Review** citing this stable published
specification, via the completed template in the I-D's IANA Considerations (RFC 6838 §4.12
suggests incorporating the form into the specification) with a review note to
`media-types@iana.org`.

Template (RFC 6838 §5.6), all fields:

| field | value |
|---|---|
| Type name | `application` |
| Subtype name | `naalp+cbor` |
| Required parameters | none |
| Optional parameters | none |
| Encoding considerations | binary (CBOR per RFC 8949) |
| Security considerations | see the Security Considerations of draft-bubblefish-naalp-00 |
| Interoperability considerations | objects are deterministic CBOR (RFC 8949 §4.2.1) |
| Published specification | draft-bubblefish-naalp-00 (this specification) |
| Applications that use this media type | autonomous-agent application-layer messaging |
| Fragment identifier considerations | as specified for `application/cbor` |
| Additional information — Deprecated alias names | none |
| Additional information — Magic number(s) | none |
| Additional information — File extension(s) | `.naalp` |
| Additional information — Macintosh file type code(s) | none |
| Person & email address to contact | S. Sammartano, naalp-editor@bubblefish.sh |
| Intended usage | COMMON |
| Restrictions on usage | none |
| Author | S. Sammartano |
| Change controller | BubbleFish Technologies, Inc. |
| Provisional registration? | No (this specification is stable) |

---

## Part B — New N-AALP registries

For each registry: **name**, **registration procedure** (RFC 8126), **columns**, **initial
contents**, and **change controller** = BubbleFish Technologies, Inc. Where IANA assigns a value,
the placeholder `TBDn` is used; N-AALP's own code points below are fixed by the specification and
are requested as-is.

### B.1 N-AALP Channels

- Procedure: **Specification Required** (RFC 8126 §4.6). Designated Expert confirms a stable
  public spec, non-collision, and a protocol-neutral (no product name) channel name.
- Columns: `Channel Id` (0..19), `Name`, `Reference`.
- Initial contents (from `vectors/registry/channels.csv`): 0x0000 Control, 0x0001 Memory, 0x0002
  Capability, 0x0003 Identity, 0x0004 Governance, 0x0005 Immune, 0x0006 Federation, 0x0007
  Settlement, 0x0008 Compliance, 0x0009 Sensory, 0x000A Telemetry, 0x000B Audit, 0x000C Stream,
  0x000D Bridge, 0x000E Commerce, 0x000F Interaction, 0x0010 Discovery, 0x0011 Workflow, 0x0012
  Knowledge, 0x0013 Spatial — Reference: this document.

### B.2 N-AALP Object Kinds (per channel)

- Procedure: **Specification Required**. Expert additionally checks the declared effect is one of
  the closed set and preserves the fail-closed model.
- Columns: `Kind Code` (uint), `Name`, `Effect` (one of the four effect names or `variable`),
  `Reference`.
- Initial contents: the 65 baseline kinds of `vectors/registry/channels.csv`, this document.

### B.3 N-AALP Effects

- Procedure: **Specification Required** (closed set; additions MUST preserve the fail-closed
  lattice with `destructive` at top).
- Columns: `Value` (0..3), `Name`, `Reference`.
- Initial contents: 0 read_only, 1 idempotent_write, 2 non_idempotent_write, 3 destructive — this
  document.

### B.4 N-AALP Carriage Protocol Ids

- One-octet space, partitioned by procedure:
  - `0x01-0x0F` **Specification Required** (standards range);
  - `0x10-0x7F` **Experimental Use** (RFC 8126 §4.2; no registration);
  - `0x80-0xFF` **Private Use** (RFC 8126 §4.1; no registration).
- Columns: `Protocol Id`, `Name`, `Carriage Class`, `Reference`.
- Initial standards-range contents (from `vectors/registry/protocols.csv`): 0x01 MCP (JSONRPC),
  0x02 A2A (JSONRPC), 0x03 HTTP (HTTP), 0x04 WebSocket (STREAM) — this document.

### B.5 N-AALP Error Codes

- Procedure: **Specification Required**.
- Columns: `Name`, `Retryable`, `Reference`.
- Initial contents: the named errors of draft-bubblefish-naalp-00 (34 codes: ContentIdMismatch,
  HeaderBodyMismatch, UnknownCriticalExt, UnknownKind, RangeError, NonCanonical, NonNFC,
  ProfileDowngrade, UnknownAlg, HybridIncomplete, BadSignature, SignerMismatch,
  RotationUnauthorized, KeyRevoked, EffectNotAuthorized, UnauthenticatedPrincipal,
  ApprovalMismatch, ApprovalExpired, AlreadyConsumed, ApprovalRequired, ChainBroken, Equivocation,
  CausalViolation, ReceiptUnsigned, StageOutOfOrder, StreamDigestMismatch,
  ConfidentialTransportRequired, PeerUnauthenticated, NotDelivered, MappingError,
  ScopeOverlapConflict, CapExceedsParent, TransformCycle, InputGateBypass).

---

## Part C — Registries N-AALP reuses (does NOT create)

- **COSE Algorithms** (existing IANA registry): ML-DSA identifiers per RFC 9964, Ed25519 per RFC
  9864. N-AALP requests **no new COSE code points**.
- **Multicodec** (multiformats registry, not IANA): `ed25519-pub` 0xed, `mldsa-65-pub` 0x1211,
  `mldsa-87-pub` 0x1212, `sha2-256` 0x12, `sha2-384` 0x20. These are multiformats code points,
  referenced not forked (`vectors/registry/multicodec.csv`).
- **Structured Syntax Suffixes** (existing IANA registry): `+cbor` = RFC 8949. Referenced, not
  registered.

---

## Part D — Designated Expert guidance (all Specification-Required registries)

The Designated Expert confirms, for each requested value:

1. a stable, publicly available specification documents the value;
2. the value does not collide with an existing entry;
3. the name is protocol-neutral and carries **no vendor product name**;
4. for object kinds, the declared effect is one of the closed four (or `variable`) and preserves
   the fail-closed model.

---

## Part E — The ISE assertion (verbatim, for the submission email)

> No IANA allocation requested in draft-bubblefish-naalp-00 requires "IETF Review" or "Standards
> Action." The media type is registered under RFC 6838; all N-AALP registries use Specification
> Required, Experimental Use, or Private Use (RFC 8126). The `+cbor` suffix and the COSE
> algorithms are referenced from existing registries, not created.

This assertion is required by the ISE checklist for an Independent submission; it holds because
every policy above is one the ISE / Designated Expert can approve without IETF-stream gatekeeping.
