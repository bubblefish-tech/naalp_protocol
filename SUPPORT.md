<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Support

N-AALP is a pre-1.0 reference protocol and SDK set. Support is best-effort while the specification
is in the Internet-Draft stage.

## Where to go

| I want to… | Go to |
|---|---|
| Report a bug in an SDK | Open a **Bug report** issue (`.github/ISSUE_TEMPLATE/bug_report.yml`) |
| Report a conformance failure | Open a **Conformance failure** issue (`.github/ISSUE_TEMPLATE/conformance_failure.yml`) — include the `naalp-conform` output |
| Request carriage of a foreign protocol | Open a **Mapping request** issue |
| Raise a specification question or ambiguity | Open a **Specification issue** |
| Report a security vulnerability | **Do not open a public issue** — follow [`SECURITY.md`](SECURITY.md) |
| Ask "how do I…" | Check the per-SDK `QUICKSTART.md`, [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md), and the docs site |

## Before opening an issue

1. Confirm you are on a tagged release (`git describe --tags`) and read the SDK's `QUICKSTART.md`.
2. Check [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — most first-contact problems (ML-DSA
   availability, PHP extensions, Ruby OpenSSL version, the Go module path) are covered there.
3. For a conformance failure, include: the language + SDK version, the failing op/case id from the
   `naalp-conform` runner, and the exact bytes if a byte-parity mismatch.

## Scope

This repository is the **open** reference surface: the object spine, the baseline of all twenty
channel surfaces, the public draft registry code points, the conformance corpus, and the reference
implementations. Transport concerns (handshake, key establishment, AEAD) belong to the substrate
(N-PAMP) or the underlying QUIC/WebSocket/HTTP and are out of scope here.

## Response expectations

Best-effort, community-driven, no SLA at this stage. Security reports follow the timeline in
`SECURITY.md`.
