<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP two-agent quickstart (Go)

A runnable demonstration of the N-AALP core loop between two agents, with **no hand-rolled
crypto**. Agent A generates an identity, signs a real N-AALP object (an Interaction-surface
message), and agent B verifies it offline and reads it — then rejects a tampered copy.

Everything runs through the reference SDK via the `naalp` convenience layer, which delegates to
the `cose` / `envelope` / `identity` / `channels` spine packages. The signature is a real
post-quantum ML-DSA-65 (FIPS 204) signature over the deterministic CBOR object body.

## Prerequisites

- Go 1.25 or newer (`go version`).
- The module dependencies (fetched automatically on first build): Cloudflare CIRCL for ML-DSA-65.

## Run

From the Go SDK root (`impl/go`):

```sh
GOWORK=off go run ./cmd/naalp-quickstart
```

## Expected output

The signer id and byte counts change every run (agent A draws a **fresh** random identity), but
the shape is fixed:

```text
[1] agent A generated an identity
    signer id : bciq...            (self-certifying id, derived from the public key)
    public key: 1952 bytes (ML-DSA-65)
[2] agent A signed an object
    channel   : 0x000F (Interaction)  kind: 0 (Elicit)  effect: read_only
    body      : "hello from agent A"
    signed obj: 3548 bytes (deterministic CBOR + COSE_Sign1 ML-DSA-65)
[3] over the wire to agent B: 3548 object bytes + 1952 public-key bytes
[4] agent B VERIFIED the object offline (no network)
    from      : bciq...
    read      : "hello from agent A"
[5] agent B REJECTED a tampered copy, fail-closed: BadSignature: signature verification failed
OK: two-agent sign -> verify -> read succeeded and tamper was rejected
```

The program is **self-checking**: it exits non-zero if the genuine object fails to verify, if
the round-tripped body differs, or if the tampered object is *not* rejected. A `0` exit with the
final `OK:` line is the proof the whole loop held.

## What it shows

- **Identity is a pure function of the key.** The signer id is derived from agent A's public key
  (`identity.SignerID`); agent B recomputes it and rejects any object whose claimed id does not
  bind to the key the signature was checked against.
- **Verification is offline.** Agent B needs only the object bytes, agent A's public key, and the
  spec — no network call, no issuer callback.
- **Failure is fail-closed.** A one-byte change anywhere in the signed object is rejected whole,
  with a named error and no partial read.

## Tests

```sh
GOWORK=off go test -race -count=1 ./cmd/naalp-quickstart
```

`TestTamperedEnvelopeRejected` flips every byte of a genuine object in turn and asserts each one
is rejected — the mutation-surviving guard for the loop's security claim.
