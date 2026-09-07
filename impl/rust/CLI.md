<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# `naalp` — command-line tool

A small command-line front end to the N-AALP Rust SDK. Two subcommands:

- **`sign`** — build and sign a real N-AALP object from a seed + payload, emit the envelope.
- **`verify`** — check a signed object offline against a public key; exit `0` on success,
  non-zero on any failure.

Both delegate to the real SDK (`naalp::easy`) — no hand-rolled crypto and no second
encoding — and are **fail-closed** on bad input.

## Build / run

From `impl/rust/`:

```sh
cargo run --bin naalp -- <command> [flags]      # during development
# or build once and call the binary directly:
cargo build --bin naalp
./target/debug/naalp <command> [flags]
```

## `naalp sign`

```
naalp sign --seed <hex32> --channel <n> --kind <n> [--effect <0..3>]
           [--message <text> | --body-file <path>] [--created <ms>]
           [--out <path>] [--pubkey-out <path>]
```

| Flag | Meaning |
|---|---|
| `--seed <hex32>` | 32-byte (64 hex char) FIPS 204 key-generation seed → the ML-DSA-65 identity. **Required.** |
| `--channel <n>` | channel id (decimal or `0x..`). **Required.** |
| `--kind <n>` | kind code within the channel. **Required.** |
| `--effect <0..3>` | `0`=read_only `1`=idempotent_write `2`=non_idempotent_write `3`=destructive. Optional: for a fixed-effect kind it defaults to the value the frozen registry declares; a **variable-effect** kind (e.g. Stream `StreamOpen`) requires it. |
| `--message <text>` | the message body as text. |
| `--body-file <path>` | the message body read from a file (as text). |
| `--created <ms>` | the object's created position in ms (default: now). Pass a fixed value for a reproducible envelope. |
| `--out <path>` | write the envelope hex here (default: stdout). |
| `--pubkey-out <path>` | write the public-key hex here (default: a labeled line on stderr). |

`sign` writes the **envelope hex to stdout** (or `--out`) and the **signer id + public-key
hex to stderr** (or the public key to `--pubkey-out`). If no `--message`/`--body-file` is
given, the payload text is read from stdin.

## `naalp verify`

```
naalp verify (--pubkey <hex> | --pubkey-file <path>)
             (--envelope <hex> | --envelope-file <path>)   # or envelope hex on stdin
```

On success it prints the verified object and exits `0`. On any failure — bad signature,
wrong key, unknown/registry-inconsistent kind or effect, malformed input — it prints the
named error to stderr and exits `1`.

## A real round-trip

```sh
cd impl/rust
cargo build --bin naalp
BIN=./target/debug/naalp
SEED=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a

# 1) sign a message on the Interaction surface (channel 15, kind 1 = Respond)
$BIN sign --seed $SEED --channel 15 --kind 1 --message "hello from A via CLI" \
          --created 1785000000000 --pubkey-out pk.hex --out env.hex
#   stderr:
#   public-key: 1952 bytes -> pk.hex
#   signer-id : bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua
#   envelope  : 3550 bytes -> env.hex

# 2) verify it (exit 0)
$BIN verify --pubkey-file pk.hex --envelope-file env.hex ; echo "exit=$?"
#   VERIFIED
#     channel : 15 (Interaction)
#     kind    : 1 (Respond)
#     effect  : 1 (idempotent_write)
#     signer  : bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua
#     id      : 203092acd7f37a6926888b9fd291e91aaf90cf0c...
#     message : hello from A via CLI
#   exit=0

# 3) tamper one hex nibble in env.hex, verify again (exit 1, fail-closed)
$BIN verify --pubkey-file pk.hex --envelope-file env.hex ; echo "exit=$?"
#   REJECTED: BadSignature (signature verification failed)
#   exit=1
```

Piping also works — `sign`'s stdout envelope hex feeds `verify`'s stdin:

```sh
$BIN sign --seed $SEED --channel 15 --kind 1 --message "hi" --created 1 --pubkey-out pk.hex \
  | $BIN verify --pubkey-file pk.hex          # VERIFIED, exit 0
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success (`sign` produced an envelope, or `verify` accepted the object) |
| `1` | a run-time failure: verification rejected, or bad/malformed input (fail-closed) |
| `2` | usage error (missing or unknown command) |

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`.
