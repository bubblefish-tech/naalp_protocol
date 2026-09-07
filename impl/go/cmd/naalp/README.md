<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# `naalp` — N-AALP command-line tool (Go)

A small command-line tool for the N-AALP core loop: generate an identity, sign an object, and
verify an object **offline**. It is a thin front end over the `naalp` convenience layer (which
delegates to the `cose` / `envelope` / `identity` / `channels` spine packages); it performs no
cryptography of its own. Every bad input is fail-closed.

## Prerequisites

- Go 1.25 or newer.

## Install / build

From the Go SDK root (`impl/go`):

```sh
GOWORK=off go build -o naalp ./cmd/naalp
# or run without building:
GOWORK=off go run ./cmd/naalp <subcommand> ...
```

## Usage

```text
naalp keygen [-seed <hex32>]
naalp sign   -seed <hex32> -channel <n> -kind <n> -text <msg> -created <ms>
naalp verify -pubkey <hex> [-env <hex>]        (envelope hex read from stdin if -env omitted)
```

Exit codes: **0** success · **1** verification rejected (fail-closed) · **2** bad arguments.

### `keygen` — mint an ML-DSA-65 identity

```sh
$ naalp keygen
seed_hex   1c9f...            # 32-byte seed — SECRET signing key material
pubkey_hex b1f7a2c6...        # 1952-byte packed public key (share this)
signer_id  bciqo2gx...        # self-certifying id, derived from the public key
```

Pass `-seed <hex32>` to derive the same key deterministically. The `seed_hex` line is **secret**
key material — treat it like a private key (do not commit it or paste it into shared logs).

### `sign` — sign an object

Signs an N-AALP object carrying a UTF-8 message on `(channel, kind)`. The object's effect is
taken from the kind's declared effect in the frozen channel registry; an unregistered
`(channel, kind)` is rejected. Prints the signed object as hex to stdout.

```sh
$ naalp sign -seed 1111...1111 -channel 15 -kind 0 -text "hello from the CLI" -created 1785000000000
d284584aa2013830656e61616c70a3015838...      # tagged COSE_Sign1 object, hex
```

`-channel 15 -kind 0` is the Interaction surface's `Elicit` message (`read_only`). `-created` is
the object timestamp in unix milliseconds and is required so the object is reproducible.

### `verify` — verify an object offline

Reads the signed object as hex (from `-env`, or from stdin) and verifies it under the public key.
On success prints the decoded object and exits `0`; on any failure prints the named error and
exits `1`.

```sh
$ naalp verify -pubkey b1f7a2c6... -env d284584a...
VERIFIED
  signer   bciqo2gx...
  channel  0x000F (Interaction)
  kind     0 (Elicit)
  effect   0 (read_only)
  body     "hello from the CLI"
```

## Round-trip (sign → verify over a pipe)

```sh
SEED=1111111111111111111111111111111111111111111111111111111111111111
PUB=$(naalp keygen -seed "$SEED" | awk '$1=="pubkey_hex"{print $2}')
naalp sign -seed "$SEED" -channel 15 -kind 0 -text "hello from the CLI" -created 1785000000000 \
  | naalp verify -pubkey "$PUB"
# -> VERIFIED ... ; exit 0
```

## Fail-closed behavior

| Input                                   | Result                                             | Exit |
|-----------------------------------------|----------------------------------------------------|------|
| Genuine object, correct key             | `VERIFIED` + decoded object                         | 0    |
| Object verified under the wrong key     | `REJECTED: BadSignature`                            | 1    |
| Tampered object (any byte changed)      | `REJECTED: BadSignature`                            | 1    |
| Malformed public key (wrong length)     | `REJECTED: KeyMalformed`                            | 1    |
| Unregistered `(channel, kind)` on sign  | `sign: UnknownKind ...`                             | 2    |
| Missing required flag                   | `sign: -text is required` (etc.)                    | 2    |

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`.
