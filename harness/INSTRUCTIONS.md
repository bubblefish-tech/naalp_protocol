<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP conformance adapter contract

This is the contract every N-AALP reference SDK implements to be **graded** against the shared
conformance corpus. It is byte-compatible with the mechanism the sibling protocol N-PAMP uses, so
an implementer who has written one can write the other.

The `naalp-conform` runner (`harness/runner/`) drives the corpus
(`vectors/conformance/corpus.json`, assembled by `tools/conformance_corpus.py` from the per-family
non-circular oracles) through **one adapter at a time**, launched as a child process, and grades
each answer against the corpus's committed expected value. **No adapter is ever compared to another
for the deterministic ops** — every expected byte traces to an RFC / FIPS / NIST vector or a
from-scratch constructor (F3, non-circular). The single exception, the deterministic ML-DSA
signature, is graded by the separate cross-language consensus gate (`tools/crypto_consensus.py`).

## Target languages (10)

| language   | adapter dir                         | status  |
|------------|-------------------------------------|---------|
| Go         | `harness/adapters/go/`              | wired   |
| Rust       | `harness/adapters/rust/`            | wired   |
| Python     | `harness/adapters/python/`          | planned |
| TypeScript | `harness/adapters/typescript/`      | planned |
| C#         | `harness/adapters/csharp/`          | planned |
| Java       | `harness/adapters/java/`            | planned |
| Kotlin     | `harness/adapters/kotlin/`          | planned |
| PHP        | `harness/adapters/php/`             | planned |
| Ruby       | `harness/adapters/ruby/`            | planned |
| Swift      | `harness/adapters/swift/`           | planned |

`wired` = the adapter exists, builds, and passes the corpus in CI. `planned` = the adapter and its
SDK are built and graded under task #20. The authoritative `{language -> build + launch}` table is
`harness/adapters.json` (and, for CI, the matrix in `.github/workflows/conformance.yml`).

## Wire protocol

Framing, both directions, over the child's stdin/stdout:

```
4-byte little-endian uint32 length N, then N bytes of UTF-8 JSON. Repeat until stdin closes.
```

The adapter **must flush stdout after every response** (line-buffered stdout desyncs the pipe on
some platforms).

**Request** (runner -> adapter):

```json
{ "op": "<operation>", "in": { ...fields... } }
```

**Response** (adapter -> runner) — exactly one of these three keys:

```json
{ "out": { ...fields... } }      // success: the produced value(s)
{ "error": "<reason>" }          // the input was rejected, or processing failed
{ "skipped": "<why>" }           // this op is not implemented by this SDK
```

**Encoding rules**

- Every byte-valued field is a **lowercase hex string** (`bytes_hex`, `pk_hex`, `id_hex`, ...).
  The runner compares hex case-insensitively, but emit lowercase.
- 64-bit counters (`seq`, `at`, `not_after`, `through_offset`, `offset`, ...) may be a JSON number
  or a decimal **string**; adapters must parse either. Emit them however is natural for the value's
  magnitude (all current corpus values are < 2^53, so a JSON number is safe).
- `skipped` vs `error` is load-bearing: return **`skipped`** when the SDK *cannot do* the op (e.g.
  no deterministic ML-DSA library), and **`error`** when the input *should be rejected* (a
  MUST-reject case) or processing genuinely failed. Grading treats them oppositely (below).

## Grading (per case, from the corpus `result`)

| `result`      | Pass when…                                                     |
|---------------|---------------------------------------------------------------|
| `valid`       | adapter returns `out` and every key in `expected` matches      |
| `invalid`     | adapter returns `error` (a MUST-reject case)                   |
| `acceptable`  | the call succeeds (either `out` or `error` is fine)            |
| any           | `skipped` -> **Unimplemented** (tracked, does **not** fail CI) |

`matchExpected` is a **subset** match: only keys present in `expected` are checked; extra keys in
`out` are ignored. Strings compare case-insensitively; numbers, bools, arrays (element-wise), and
nested maps compare structurally. A transport/pipe failure is a hard Fail and aborts the run. Exit
code is **1 iff any case Failed**, else 0.

## The op set (31 ops)

Byte fields are hex. `->` shows `in` fields then `out` fields. Ops group by spine construction.

### Pure (every language; SHA-256/384 + canonical CBOR only)

| op                      | in -> out                                                              |
|-------------------------|-----------------------------------------------------------------------|
| `sha384`                | `msg_hex` -> `digest_hex` (FIPS 180-4 KAT anchor)                      |
| `cbor.encode`           | `value` (tagged) -> `bytes_hex` (deterministic CBOR, RFC 8949)         |
| `cbor.decode`           | `bytes_hex` -> `{}` or **error** (reject non-canonical)                |
| `content.id`            | `body_hex` -> `id_hex` (`multihash(0x20,0x30, SHA-384(body))`)         |
| `cose.tbs`              | `protected_hex`,`payload_hex` -> `tobesigned_hex` (RFC 9052 Sig_structure) |
| `signerid`             | `alg`,`pubkey_hex` -> `signer_id` (multiformats PeerHandle form)        |
| `nfc.check`             | `utf8_hex` -> `{ok:true}` or **error** (reject non-NFC)                |
| `effect.normalize`      | `value` -> `effect` (0..3; unknown -> 3 destructive)                   |
| `effect.authorize`      | `granted`,`effect` -> `allow` (bool; the §6.1 lattice)                 |
| `effect.safety_label`   | `risk`,`scope` -> `cbor_hex` (safety-label map bytes)                  |
| `approval.body`         | `approves_hex`,`approver`,`grant`,`nonce_hex`,`not_after` -> `body_hex`|
| `approval.id`           | (same in) -> `id_hex` (content id of the approval body)               |
| `ledger.entry`          | `seq`,`prev_hex`,`approval_id_hex`,`by` -> `body_hex`                  |
| `receipt.body`          | `prev_hex`,`obj_hex`,`seq`,`at` -> `body_hex`                          |
| `receipt.head`          | `body_hex` -> `head_hex` (SHA-384 of the receipt body)                 |
| `causal.verify`         | `nodes:[{id_hex,causes_hex,position?}]` -> `{valid:true}` or **error** |
| `delivery.update`       | `obj_hex`,`stage`,`at` -> `body_hex`                                   |
| `stream.digest`         | `chunks:[{offset,data_hex}]` -> `digest_hex` (rolling SHA-384, offset order) |
| `stream.open`           | `stream_id_hex`,`effect`,`approval_hex?`,`substream` -> `body_hex`     |
| `stream.commit`         | `stream_id_hex`,`digest_hex` -> `body_hex`                             |
| `stream.checkpoint`     | `stream_id_hex`,`through_offset`,`digest_so_far_hex` -> `body_hex`     |
| `transport.emit`        | `transport`,`sensitive`,`require_peer_auth` -> `result` (`ok` / error kind) |
| `carriage.body`         | `protocol_id`,`class`,`content_type`,`correlation_hex`,`method`,`foreign_hex` -> `body_hex` |
| `channels.lookup`       | `channel`,`kind` -> `name`,`effect`,`variable` or **error** (UnknownKind) |
| `channels.effect_check` | `channel`,`kind`,`effect` -> `{ok:true}` or **error**                  |
| `federation.reconcile`  | `nodes:[{id_hex,causes_hex}]` -> `order:[id_hex,…]` (deterministic merge) |
| `federation.record`     | `authorities:[str]`,`order:[id_hex]` -> `body_hex`                     |

### Crypto (skippable where no deterministic FIPS 204 / Ed25519 library exists)

| op                | in -> out                                                                    |
|-------------------|------------------------------------------------------------------------------|
| `mldsa.keygen`    | `param`(`ML-DSA-65`/`-87`),`seed_hex` -> `pk_hex` (NIST ACVP seed->pk KAT)    |
| `ed25519.sign`    | `sk_hex`(32-byte seed),`msg_hex` -> `sig_hex` (RFC 8032 KAT)                  |
| `cose.sign1`      | `alg`,`seed_hex`,`protected_hex`,`payload_hex` -> `obj_hex` (consensus-graded)|
| `cose.verify1`    | `alg`,`pubkey_hex`,`obj_hex` -> `valid` (bool)                                |

`mldsa.keygen` is the **ML-DSA-availability probe**: an SDK whose language has no deterministic
FIPS 204 library returns `skipped` here, and its `cose.sign1`/`cose.verify1` too. The runner records
those as Unimplemented (never a false green); the SDK is still fully graded on all the pure ops. Its
ML-DSA gap is tracked per language in `harness/adapters.json`.

### The tagged-value form (`cbor.encode` input)

A logical CBOR value is a two-element array `[tag, payload]`, so the **encoder under test** — not
the corpus author's language — produces the bytes:

| tag     | payload                          | CBOR                        |
|---------|----------------------------------|-----------------------------|
| `"u"`   | a non-negative integer           | unsigned int (major 0)      |
| `"b"`   | lowercase hex string             | byte string (major 2)       |
| `"s"`   | a UTF-8 string                   | text string (major 3)       |
| `"arr"` | `[value, …]`                     | array (major 4)             |
| `"map"` | `[[key, value], …]`              | map (major 5), canonical    |

A conforming encoder emits map keys in canonical (bytewise-ascending) order regardless of input
order.

## Running

Build the two reference adapters, then grade each:

```sh
# runner
( cd harness/runner && GOWORK=off go build -o naalp-conform ./ )
# go adapter
( cd harness/adapters/go && GOWORK=off go build -o naalp-adapter-go ./ )
# rust adapter
( cd harness/adapters/rust && cargo build --release )

./harness/runner/naalp-conform run --testee "./harness/adapters/go/naalp-adapter-go"
./harness/runner/naalp-conform run --testee "./harness/adapters/rust/target/release/naalp-adapter-rust"

# cross-language deterministic ML-DSA byte-parity
python tools/crypto_consensus.py \
  go=./harness/adapters/go/naalp-adapter-go \
  rust=./harness/adapters/rust/target/release/naalp-adapter-rust
```

`bash harness/run.sh` runs the whole conformance suite (two-implementation parity + CDDL + registry
drift + this cross-language gate) and is what CI runs. `naalp-conform vectors` dumps the embedded
corpus.

## Adding a new-language adapter

1. Build the SDK for the language (the spine: deterministic CBOR, content-id, COSE ToBeSigned,
   signer-id, effect, approval, audit, delivery, streaming, carriage, channels, federation; plus
   ML-DSA/Ed25519 where a conformant library exists).
2. Write `harness/adapters/<lang>/` implementing this protocol — read the 4-byte-LE request loop,
   dispatch on `op`, call the SDK, write the framed response, flush.
3. Return `skipped` for any op the SDK genuinely cannot do (record the reason in
   `harness/adapters.json`); implement every pure op.
4. Add the `{build, launch}` entry to `harness/adapters.json` and the CI matrix.
5. `naalp-conform run --testee "<launch>"` must pass every `valid`/`invalid` case (skips allowed
   only for the crypto ops when the language lacks a library); the consensus gate must agree on
   `cose.sign1` where implemented.
