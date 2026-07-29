<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# 0005 — Foreign carriage by class, not by protocol

- Status: accepted
- Date: 2026-07-27

## Context

Agents speak many protocols (MCP, A2A, HTTP, FIPA-ACL, event streams, agent cards, …). A bespoke
per-protocol mapping for each is a combinatorial burden and a permanent source of drift; an
undefined protocol would be uncarriable until someone wrote a mapping.

## Decision

N-AALP carries a foreign protocol by wrapping its message **octet-for-octet** in a signed carriage
object interpreted by a **carriage class** — five structured classes (JSONRPC, HTTP, MSG, STREAM,
DOC) plus a universal **OPAQUE** class. Adding a protocol is a registry entry plus an optional thin
mapping, never a new framework. The OPAQUE class makes any protocol — including one nobody has
defined — carriable immediately on an experimental protocol id with no registration.

## Consequences

The foreign message MUST NOT be re-serialized, canonicalized, summarized, or rewritten; N-AALP
metadata is carried around it, never inside it. The carriage object's signer remains the
authority: a foreign identity never becomes an N-AALP authorization identity. Round-trip
octet-exactness is a conformance requirement per class.
