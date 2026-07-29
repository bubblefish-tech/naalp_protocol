# Security Policy

This repository contains a protocol **specification**, not a deployed service.
N-AALP is the application layer (identity, effect, approval, audit over signed,
deterministic, offline-verifiable objects) carried by N-PAMP. "Security issues"
here means weaknesses in the N-AALP protocol design or its description, or vulns
in the reference implementations.

Protocol-design weaknesses include, for example:

- a **downgrade** path (for example, an object accepted with a weaker or
  classical-only signature where a post-quantum one was required);
- a **missing authentication binding** — a field, effect, or approval that is
  not covered by the signed input, or a signer-id that is not bound to the object
  it signs;
- a **replay or nonce-reuse** hazard in the audit/ordering or approval surfaces;
- **effect mislabeling** — an object whose declared effect does not match the
  action it authorizes, or an effect that under-states its authority;
- a **carriage** hazard — a foreign protocol (MCP, A2A, or another) carried in a
  way that escapes the governed signed envelope or is not octet-exact for its
  carriage class; or
- a **specification ambiguity** that would lead independent implementers to build
  something insecure or non-interoperable.

Reference-implementation vulnerabilities (in `impl/`) are also in scope: for
example a non-canonical CBOR path that verifies, a fail-open acceptance of an
object that failed a check, or a signature-verification bypass.

## Reporting a vulnerability

Please report suspected security issues **privately** by email to:

    naalp-editor@bubblefish.sh

Use a clear subject line (for example, `N-AALP security: <short summary>`) and
include:

- the section of the draft or the CDDL involved (and the draft revision, e.g.
  `-00`), or the implementation file and language;
- a description of the weakness and the assumptions it requires;
- an attack scenario or proof-of-concept, if you have one; and
- any suggested mitigation.

Please do **not** open a public issue for an unfixed security weakness.

## What to expect

- Acknowledgement of your report within a reasonable time.
- Coordinated handling: we will work with you on an assessment and, where a
  specification change is warranted, a revised draft; where an implementation
  change is warranted, a fix. We ask for a coordinated disclosure window
  (target: up to 90 days) before public discussion of an unmitigated weakness.
- Credit in the document's acknowledgements if you wish.

## Scope

In scope: the N-AALP object encoding, the identity / effect / approval /
audit-and-ordering surfaces, the delivery and streaming surfaces, the carriage
classes and foreign-protocol carriage, the twenty channel surfaces, and the five
IANA registries as specified in the Internet-Draft and the CDDL in this
repository; and the reference implementations under `impl/`.

Out of scope: the N-PAMP substrate itself — its transport, handshake, key
schedule, and cryptographic-suite negotiation are N-PAMP transport-layer
concerns; report those against the N-PAMP project. Also out of scope:
third-party implementations, deployments, or services that use N-AALP. Report
those to their respective maintainers.
