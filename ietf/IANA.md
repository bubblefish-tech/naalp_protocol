<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP — IANA registration package

This document collects the IANA actions N-AALP requires, in submission form, so they can be
tracked independently of the Internet-Draft's rendered IANA Considerations (which contains the
same requests). Every registry below uses a policy an **Independent Submission** can carry: the
ISE requires the author to assert that **no IANA allocation in the document requires "IETF
Review" or "Standards Action"** (per the ISE checklist). On the Independent Submission stream the
ISE appoints no Designated Expert (RFC 8726), so no registry this document *creates* may use
**Specification Required** or **Expert Review** (RFC 8126 §4.6, §4.5) — every new N-AALP registry
below instead uses **RFC Required** (RFC 8126 §4.7), optionally **First Come First Served** (RFC
8126 §4.4) within a standards range, or an **Experimental Use**/**Private Use** range (RFC 8126
§4.2, §4.1). The one exception is Part A: the media type is registered *into* the existing IANA
"Media Types" registry, whose vendor-tree process (RFC 6838 §3.2) is that registry's own
established Expert Review — not a Designated Expert this document appoints — and RFC 6838
registration on the Independent Submission stream is explicitly permitted.

> Process facts below were grounded in primary sources on 2026-07-27; see `SUBMISSION.md` for the
> WITNESSED/RELAYED citation log. The registration-policy guidance was subsequently corrected
> against RFC 8726 and RFC 7120 — no registry a document *creates* on the Independent Submission
> stream may use Specification Required or Expert Review, and RFC 7120 early allocation is not
> available on this stream. The RFC 8126 §4.1-§4.7 section numbers cited throughout this document
> were independently re-verified against the current published RFC on 2026-08-24. Do not treat
> any RFC number or policy name as verified beyond what is recorded here or in `SUBMISSION.md`.

---

## Part A — Media type: `application/vnd.bubblefish.naalp+cbor`

Register in the **vendor tree** per **RFC 6838 §3.2** (BCP 13), using the **`+cbor`** structured
syntax suffix, which is **already registered by RFC 8949** in the IANA "Structured Syntax
Suffixes" registry — N-AALP does **not** register `+cbor`, it references it. The `vnd.bubblefish.`
facet is the vendor-tree designation for BubbleFish Technologies, Inc. as the producing
organization (RFC 6838 §3.2); the change controller is BubbleFish Technologies, Inc.

Registration path for an Independent Submission (not the IETF stream): a vendor-tree registration
is submitted directly to IANA and undergoes **Expert Review** (RFC 6838 §3.2, §5.2) — it requires
**no IESG approval and no IETF standards action**, which is exactly what the Independent Submission
stream requires. The completed template below is carried in the I-D's IANA Considerations (RFC 6838
§5.6); posting to `media-types@iana.org` for review before submission is encouraged (RFC 6838 §5.2).

Template (RFC 6838 §5.6), all fields:

| field | value |
|---|---|
| Type name | `application` |
| Subtype name | `vnd.bubblefish.naalp+cbor` |
| Required parameters | none |
| Optional parameters | none |
| Encoding considerations | binary (CBOR per RFC 8949) |
| Security considerations | see the Security Considerations of draft-bubblefish-naalp-01 |
| Interoperability considerations | objects are deterministic CBOR (RFC 8949 §4.2.1) |
| Published specification | draft-bubblefish-naalp-01 (this specification) |
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

- Procedure: **RFC Required** (RFC 8126 §4.7; First Come First Served among successor documents)
  — an ISE-permissible policy. A registration into this registry, made via a successor RFC to this
  document, additionally must be documented by a stable public specification, must not collide
  with an existing entry, and must use a protocol-neutral name that carries no vendor product name
  (Part D).
- Columns: `Channel Id` (0..19), `Name`, `Reference`.
- Initial contents (from `vectors/registry/channels.csv`): 0x0000 Control, 0x0001 Memory, 0x0002
  Capability, 0x0003 Identity, 0x0004 Governance, 0x0005 Immune, 0x0006 Federation, 0x0007
  Settlement, 0x0008 Compliance, 0x0009 Sensory, 0x000A Telemetry, 0x000B Audit, 0x000C Stream,
  0x000D Bridge, 0x000E Commerce, 0x000F Interaction, 0x0010 Discovery, 0x0011 Workflow, 0x0012
  Knowledge, 0x0013 Spatial — Reference: this document.

### B.2 N-AALP Object Kinds (per channel)

- Procedure: **RFC Required** (RFC 8126 §4.7; First Come First Served among successor documents)
  — an ISE-permissible policy. A registration into this registry, made via a successor RFC,
  additionally must declare an effect that is one of the closed four (or `variable`) and must
  preserve the fail-closed model (Part D).
- Columns: `Kind Code` (uint), `Name`, `Effect` (one of the four effect names or `variable`),
  `Reference`.
- Initial contents: the 65 baseline kinds of `vectors/registry/channels.csv`, this document.

### B.3 N-AALP Effects

- Procedure: **RFC Required** (RFC 8126 §4.7) — an ISE-permissible policy. This is a closed set
  not expected to grow; an addition, via a successor RFC, must preserve the fail-closed lattice
  with `destructive` at top.
- Columns: `Value` (0..3), `Name`, `Reference`.
- Initial contents: 0 read_only, 1 idempotent_write, 2 non_idempotent_write, 3 destructive — this
  document.

### B.4 N-AALP Carriage Protocol Ids

- One-octet space, partitioned by procedure:
  - `0x01-0x0F` **RFC Required** (RFC 8126 §4.7; First Come First Served in the standards range)
    — an ISE-permissible policy;
  - `0x10-0x7F` **Experimental Use** (RFC 8126 §4.2; no registration);
  - `0x80-0xFF` **Private Use** (RFC 8126 §4.1; no registration).
- Columns: `Protocol Id`, `Name`, `Carriage Class`, `Reference`.
- Initial standards-range contents (from `vectors/registry/protocols.csv`): 0x01 MCP (JSONRPC),
  0x02 A2A (JSONRPC), 0x03 HTTP (HTTP), 0x04 WebSocket (STREAM) — this document.

### B.5 N-AALP Error Codes

- Procedure: **RFC Required** (RFC 8126 §4.7; First Come First Served in the standards range) —
  an ISE-permissible policy.
- Value space: a uint, partitioned `1-0x7FFF` standards range (RFC Required / FCFS), `>=0x8000`
  Private Use (RFC 8126 §4.1; no registration); `0` is reserved and does not appear on the wire.
- Columns: `Code`, `Name`, `Retryable`, `Reference`.
- Initial contents: the named errors of draft-bubblefish-naalp-01, this document. This package
  lists 34 representative codes below as of its last synchronization pass with the draft; the
  draft's own IANA Considerations carries the complete, currently authoritative numbered set and
  governs on any disagreement between the two. ContentIdMismatch,
  HeaderBodyMismatch, UnknownCriticalExt, UnknownKind, RangeError, NonCanonical, NonNFC,
  ProfileDowngrade, UnknownAlg, HybridIncomplete, BadSignature, SignerMismatch,
  RotationUnauthorized, KeyRevoked, EffectNotAuthorized, UnauthenticatedPrincipal,
  ApprovalMismatch, ApprovalExpired, AlreadyConsumed, ApprovalRequired, ChainBroken, Equivocation,
  CausalViolation, ReceiptUnsigned, StageOutOfOrder, StreamDigestMismatch,
  ConfidentialTransportRequired, PeerUnauthenticated, NotDelivered, MappingError,
  ScopeOverlapConflict, CapExceedsParent, TransformCycle, InputGateBypass.

### B.6 N-AALP Extension Keys

- Procedure: **RFC Required** (RFC 8126 §4.7; First Come First Served) — an ISE-permissible
  policy. The `ext` (non-critical, object field 11) and `cext` (critical, object field 12)
  extension-key namespace is a single registry, so two independent extension assignments cannot
  collide. A registration into this registry, made via a successor RFC, additionally must be
  documented by a stable public specification and must not collide with an existing entry
  (Part D).
- Columns: `Ext/Cext Key` (uint), `Name`, `Maps` (`ext` | `ext, cext`), `Reference`.
- Initial contents (from `vectors/registry/extension-keys.csv`):

  | Key | Name | Maps | Reference |
  |----:|------|------|-----------|
  | 1 | `safety-label` | `ext` | this document |
  | 13 | `recheck` | `ext, cext` | this document |
  | 14 | `signer-counter` | `ext` | this document |
  | 15 | `producing-boundary` | `ext` | this document |
  | 16 | `naalp-hazard-claim` | `cext` | this document |

  `safety-label` carries an OPTIONAL signed safety label attributable to the object's signer.
  `recheck` names a re-check procedure by id; in the non-critical map an unrecognized id is
  ignored, and in the critical map an unrecognized id is rejected. `signer-counter` is an OPTIONAL
  forward-only per-signer position used to detect duplication; it is covered by the signer's own
  signature. `producing-boundary` is an OPTIONAL, self-asserted disclosure of the emitting trust
  boundary and whether the content was observed or relayed; it is covered by the signer's own
  signature.

### B.7 N-AALP Carriage Content Types

- One-octet space, partitioned by procedure:
  - `0x00-0x0F` **RFC Required** (RFC 8126 §4.7; First Come First Served in the standards range)
    — an ISE-permissible policy;
  - `0x10-0x7F` **Experimental Use** (RFC 8126 §4.2; no registration);
  - `0x80-0xFF` **Private Use** (RFC 8126 §4.1; no registration).
- Columns: `Content Type`, `Name`, `Reference`.
- Initial standards-range contents (from `vectors/registry/carriage-content-types.csv`): 0x00
  `json` (UTF-8 JSON or JSON-RPC text), 0x01 `octet-stream` (an opaque binary payload with no
  declared text or JSON structure), 0x02 `text` (UTF-8 text that is not JSON, such as a
  line/token/event protocol) — this document.

---

### B.8 N-AALP Trust-Decision Input Classes

- Closed set of input classes a relying-party decision may key on, each classified by the safe
  shape its influence must take (verifiable / attenuating / committed), so a party cannot influence
  a decision except through one of those shapes or the decision fails closed.
- Policy: **RFC Required** (RFC 8126 §4.7; First Come First Served in the standards range) — an
  ISE-permissible policy.
- Columns: `Class`, `Name`, `Safe shape`, `Reference`.
- Initial contents (from `vectors/registry/trust-decision-input-classes.csv`): 1 `identifier`, 2
  `object-parse`, 3 `object-identity`, 4 `conformance-expectation`, 5 `verification-procedure`
  (verifiable); 6 `delegated-authority` (attenuating); 7 `approved-action`, 8
  `negotiated-parameters`, 9 `validity-clock`, 10 `use-context` (committed) — this document.

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

## Part D — Registration criteria for the RFC-Required registries

The Independent Submission stream appoints no Designated Expert, so none of the registries in
Part B is gated by expert review; each uses **RFC Required** (RFC 8126 §4.7) instead, meaning a
value is assigned only once it appears in a published RFC — this document for the initial
contents, or a successor RFC for any addition. A successor RFC adding a value to one of these
registries must satisfy, for each value it adds:

1. the value is documented by a stable, publicly available specification;
2. the value does not collide with an existing entry;
3. the name is protocol-neutral and carries **no vendor product name**;
4. for object kinds, the declared effect is one of the closed four (or `variable`) and preserves
   the fail-closed model.

These criteria are self-administered by the RFC-Required registration procedure itself — checked
by the authors and reviewers of the successor RFC before submission — and are not verified by an
IANA-appointed reviewer; IANA records the value once the RFC that defines it is published.

---

## Part E — The ISE assertion (verbatim, for the submission email)

> No IANA allocation requested in draft-bubblefish-naalp-01 requires "IETF Review" or "Standards
> Action." The media type is registered into the existing IANA Media Types registry, under RFC 6838
> (§3.2, vendor tree, that registry's own Expert Review); every registry N-AALP creates (Part B)
> uses RFC Required, First Come First Served, Experimental Use, or Private Use (RFC 8126) — never
> Specification Required or Expert Review, consistent with the restriction on new registries
> created by an Independent Submission. The `+cbor` suffix and the COSE algorithms are referenced
> from existing registries, not created.

This assertion is required by the ISE checklist for an Independent submission; it holds because
every policy above is one the ISE can accept without appointing a Designated Expert and without
IETF-stream gatekeeping.
