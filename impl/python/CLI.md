<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# `naalp` — command-line tool

A small CLI over the N-AALP Python SDK for signing and verifying objects from the shell. It adds
no cryptography or encoding of its own — every step calls the reference primitives
(`naalp.cose` ML-DSA, `naalp.envelope` sign/verify, `naalp.cbor` deterministic CBOR) through the
ergonomic `naalp.ez` surface.

## Install

```sh
cd impl/python
pip install -e .          # exposes the `naalp` command
```

Without installing, invoke it as a module from the SDK checkout: `python -m naalp.cli ...`.

## Commands

| Command | What it does |
|---|---|
| `naalp keygen`  | Derive (or randomly generate) a 32-byte seed and print its public key + self-certifying signer id. |
| `naalp sign`    | Build a message body `{1: TEXT}`, sign a full N-AALP object on `(channel, kind)`, emit the object bytes. |
| `naalp verify`  | Verify a signed object offline; exit `0` on success, non-zero on any failure (fail-closed). |

### `naalp keygen`

```
naalp keygen [--alg ml-dsa-65|ml-dsa-87] [--seed-hex HEX]
```

`--seed-hex` is a 32-byte seed as hex; omit it to draw a random seed from the OS CSPRNG.

### `naalp sign`

```
naalp sign --seed-hex HEX --channel N --kind N --message TEXT
           [--alg ml-dsa-65|ml-dsa-87] [--effect 0..3] [--profile 1..3] [--out FILE]
```

`--channel`/`--kind` name a surface in the twenty-channel registry; the declared effect is taken
from the registry automatically (a variable-effect kind, e.g. Stream `StreamOpen`, requires
`--effect`). Object bytes go to `--out`, or to stdout if omitted.

### `naalp verify`

```
naalp verify --pubkey-hex HEX [--profile 1..3] [--in FILE]
```

Reads object bytes from `--in` (or stdin), runs the full offline check (canonical decode →
content-id rebind → field ranges → header/body agreement → critical extensions → kind dispatch →
profile floor → ML-DSA signature), and prints the decoded object. Any failure exits non-zero.

## A real round-trip

```
$ SEED=2a2a...2a          # 32 bytes of hex

$ naalp keygen --seed-hex $SEED
alg       ml-dsa-65
seed      2a2a2a2a...2a2a
pubkey    f5408337d0fee65c...   (1952-byte ML-DSA-65 public key)
signer-id bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua

$ naalp sign --seed-hex $SEED --channel 15 --kind 1 --message "hello from the CLI" --out obj.bin
naalp: signed 3550 bytes -> obj.bin  (signer bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua)

$ naalp verify --pubkey-hex $PUBKEY --in obj.bin ; echo "exit=$?"
verify OK
  channel   0x000f Interaction
  kind      1 Respond
  effect    1
  profile   1
  signer    bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua
  id        20309e9652971829bab5cbb2ca35a776260ab48594a2cb4aaeb6bf115eda970d8049a18926a56db06afe02de3ea7eb3d44ce
  message   hello from the CLI
exit=0
```

### Fail-closed behavior (non-zero exit)

```
$ naalp verify --pubkey-hex $PUBKEY --in tampered.bin ; echo "exit=$?"   # one flipped byte
naalp: verify FAILED: BadSignature
exit=2

$ naalp verify --pubkey-hex $WRONG_KEY --in obj.bin ; echo "exit=$?"
naalp: verify FAILED: BadSignature
exit=2

$ naalp sign --seed-hex $SEED --channel 99 --kind 0 --message x ; echo "exit=$?"
naalp: unknown channel/kind: channel 0x0063 not registered
exit=2
```
