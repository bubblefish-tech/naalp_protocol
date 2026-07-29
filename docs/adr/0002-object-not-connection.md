<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# 0002 — The object, not the connection, is the unit of security

- Status: accepted
- Date: 2026-07-27

## Context

Existing agent protocols secure the transport connection (TLS/QUIC) but leave the individual
message un-signed, its effect undeclared, and its authorization implicit. A message that crosses a
relay, is stored, or is replayed loses all its guarantees the moment it leaves the connection.

## Decision

The **object** is the unit of security and governance. Each object is self-secured: signed,
content-identified, effect-labeled, identity-bound, and auditable, independently of any transport.
The same signed object carries identical object-level guarantees over N-PAMP, QUIC, WebSocket, or
HTTP.

## Consequences

Object-level guarantees (integrity, identity, non-repudiation, effect, audit) survive relays,
storage, and replay. Confidentiality, forward secrecy, and connection authentication remain the
transport's job (conditional guarantees), and a sensitive object is refused over a cleartext
transport. Transports become interchangeable carriers; the binding adds only framing.
