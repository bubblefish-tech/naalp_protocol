<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Registries

The machine-readable registries under `vectors/registry/*.csv` are the source the prose and CDDL
are generated from; a drift check (`scripts/registry_drift.py`) keeps them consistent with the
graded conformance vectors, and the IANA considerations (in the Internet-Draft) request
each as an IANA registry.

| registry | file | policy (IANA) | contents |
|---|---|---|---|
| Channels | `channels.csv` | RFC Required / FCFS | 20 channels (0x0000–0x0013) |
| Object Kinds | `channels.csv` | RFC Required / FCFS | 65 baseline kinds + effects |
| Signatures (COSE algs) | `signatures.csv` | reuse IANA COSE registry | ML-DSA-65/-87, Ed25519, SLH-DSA (reserved) |
| Multicodec (signer-id keys) | `multicodec.csv` | multiformats (referenced) | ed25519-pub, mldsa-65/87-pub, sha2-256/384 |
| Carriage Protocol Ids | `protocols.csv` | RFC Required / FCFS / Experimental / Private | MCP, A2A, HTTP, WebSocket + ranges |
| Carriage Content Types | `carriage-content-types.csv` | RFC Required / FCFS (standards); no-reg (exp + private) | 0 json, 1 octet-stream, 2 text + ranges |
| Extension Keys | `extension-keys.csv` | RFC Required / FCFS | ext (field 11) / cext (field 12) map keys: 1 safety-label, 13 recheck, 14 signer-counter, 15 producing-boundary |
| Effects | (in the draft) | RFC Required / FCFS | read_only, idempotent_write, non_idempotent_write, destructive |
| Error Codes | `error-codes.csv` | RFC Required / FCFS (standards 1–0x7FFF); no-reg (private ≥0x8000) | 119 numeric error codes carried by the `naalp-error` object (Control/Error, channel 0/kind 3); `code`+`name` dual-carriage, unknown code opaque |
| Trust-Decision Input Classes | `trust-decision-input-classes.csv` | RFC Required / FCFS | 10 decision-input classes, each classified by safe shape (verifiable / attenuating / committed) |

## Protocol-id ranges (carriage)

- `0x01–0x0F` — **standards** (RFC Required / FCFS); assigned: 0x01 MCP, 0x02 A2A, 0x03 HTTP,
  0x04 WebSocket.
- `0x10–0x7F` — **experimental** (no registration).
- `0x80–0xFF` — **private** (no registration).

## Content-type ranges (carriage)

- `0x00–0x0F` — **standards** (RFC Required / First Come First Served);
  assigned: 0 json, 1 octet-stream, 2 text.
- `0x10–0x7F` — **experimental** (no registration).
- `0x80–0xFF` — **private** (no registration).

## Reused, not forked

The COSE algorithm identifiers (ML-DSA per RFC 9964, Ed25519 per RFC 9864) and the `+cbor`
structured syntax suffix (RFC 8949) come from existing IANA registries; N-AALP references them and
does **not** create competing registries.
