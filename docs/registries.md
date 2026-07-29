<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Registries

The machine-readable registries under `vectors/registry/*.csv` are the source the prose and CDDL
are generated from; a drift check (`scripts/registry_drift.py`) keeps them consistent with the
graded conformance vectors, and the IANA considerations (see the [Internet-Draft](ietf.md)) request
each as an IANA registry.

| registry | file | policy (IANA) | contents |
|---|---|---|---|
| Channels | `channels.csv` | Specification Required | 20 channels (0x0000–0x0013) |
| Object Kinds | `channels.csv` | Specification Required | 65 baseline kinds + effects |
| Signatures (COSE algs) | `signatures.csv` | reuse IANA COSE registry | ML-DSA-65/-87, Ed25519, SLH-DSA (reserved) |
| Multicodec (signer-id keys) | `multicodec.csv` | multiformats (referenced) | ed25519-pub, mldsa-65/87-pub, sha2-256/384 |
| Carriage Protocol Ids | `protocols.csv` | Spec Required / Experimental / Private | MCP, A2A, HTTP, WebSocket + ranges |
| Effects | (in the draft) | Specification Required | read_only, idempotent_write, non_idempotent_write, destructive |
| Error Codes | (in the draft) | Specification Required | the 34 named errors |

## Protocol-id ranges (carriage)

- `0x01–0x0F` — **standards** (Specification Required); assigned: 0x01 MCP, 0x02 A2A, 0x03 HTTP,
  0x04 WebSocket.
- `0x10–0x7F` — **experimental** (no registration).
- `0x80–0xFF` — **private** (no registration).

## Reused, not forked

The COSE algorithm identifiers (ML-DSA per RFC 9964, Ed25519 per RFC 9864) and the `+cbor`
structured syntax suffix (RFC 8949) come from existing IANA registries; N-AALP references them and
does **not** create competing registries.
