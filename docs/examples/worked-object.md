<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Worked example: a complete signed object, byte by byte

Every byte on this page is **produced by the reference implementation** (not hand-typed) from a
fixed 32-byte seed (`0x2a` repeated), so it is deterministic and reproducible, and it **verifies
end-to-end** (graded by `impl/go/cmd/naalp-worked-example`'s test). Regenerate it with:

```console
$ cd impl/go && GOWORK=off go run ./cmd/naalp-worked-example
```

The full JSON breakdown is committed at `vectors/worked/example.json`.

## The object

A **Governance Approval** object (channel `0x0004`, kind 1), effect `non_idempotent_write` (2), on
the **Public** profile. Its body is an approval that binds the exact arguments by content id.

| field | value |
|---|---|
| kind | 1 (Approval) |
| channel | 0x0004 (Governance) |
| tier | 0 (baseline) |
| effect | 2 (non_idempotent_write) |
| profile | 1 (public) |
| signer id | `bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua` |

## Derived bytes

| what | value |
|---|---|
| content id | `2030192922f9be80623bea1c689ddfe9…` (50 bytes: `0x20 0x30` ‖ SHA-384) |
| protected header | `a2013830656e61616c70a30158386263…` ({1: alg −49, "naalp": {signer, profile, version}}) |
| signed payload (body) | 271 bytes of deterministic CBOR |
| signature (ML-DSA-65) | 3309 bytes |
| full signed object (tagged COSE_Sign1) | 3665 bytes |

## Why it verifies

1. The **content id** recomputes from the body (fields 2–12) as `multihash(0x20, SHA-384)` — a
   mismatch would be `ContentIdMismatch`.
2. The **protected header** copies of signer and profile match body fields 5 and 9 — a
   disagreement would be `HeaderBodyMismatch`.
3. The **effect** (2) is within the channel-surface declaration for a Governance Approval.
4. The **ML-DSA-65 signature** verifies over the COSE `Signature1` structure — a single tampered
   byte anywhere would be `BadSignature`.

The Go and Rust implementations produce this object byte-for-byte identically; the byte-parity of
the general envelope is checked on every run by `scripts/verify.sh`.
