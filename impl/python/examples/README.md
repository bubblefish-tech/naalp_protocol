<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Python examples

Runnable, dependency-light demonstrations of the N-AALP core loop with the reference SDK. No
hand-rolled cryptography: every signature and check goes through `naalp` (deterministic CBOR,
COSE_Sign1, ML-DSA-65).

## Prerequisites

- Python ≥ 3.9
- The SDK's runtime dependencies: `dilithium-py` (deterministic ML-DSA, FIPS 204) and
  `cryptography` (Ed25519, RFC 8032).

```sh
cd impl/python
pip install -e .        # installs naalp + its dependencies (and the `naalp` CLI)
```

The examples also run straight from a source checkout without installing (they add the SDK to
`sys.path` themselves) as long as `dilithium-py` and `cryptography` are importable.

## `two_agent_quickstart.py` — the core loop, end to end

Agent A generates a post-quantum identity, builds a message on the **Interaction** surface
(channel `0x000F`, kind `1` = *Respond*), and signs it into one self-describing N-AALP object.
Only the object bytes plus Agent A's public key cross to Agent B. Agent B verifies the object
**offline** — real ML-DSA signature, content-id rebind, channel-registry dispatch, profile floor —
and reads the message. A single flipped byte is then shown to be rejected (fail-closed).

```sh
python examples/two_agent_quickstart.py
```

Expected output (the signer id, public-key prefix, and byte counts vary because Agent A generates
a fresh random identity each run; the verify result, message, and tamper rejection are stable):

```
[A] generated ML-DSA-65 identity
    signer id : bciq...
    public key: 1a2b3c4d..1952 bytes
[A] signed a Respond object on channel 0x000f (Interaction), effect=1
    object    : 3593 bytes, d284584a...
[.] transmitted 3593 object bytes to Agent B (any transport)
[B] verified OK: channel 0x000f kind 1 (Respond), signer bciqxxxxxxxx..
[B] read message: "Hello Agent B - this object is signed, not the connection."
[B] tamper rejected: BadSignature

OK - signed by A, verified by B, tamper rejected.
```

The tamper step is a hard assertion: if a modified object ever verified, the script exits non-zero.

## `sign_object.py` — a single full object, low-level

`sign_object.py` uses the raw `envelope` API directly (build an `Object`, `envelope.sign`,
`envelope.verify`) to sign and verify a Governance Approval object, then reject a tampered copy.
It shows the layer the ergonomic `naalp.ez` surface sits on top of.

```sh
python examples/sign_object.py
```

## The `naalp` command-line tool

The same primitives are available from the shell (see `../naalp/cli.py`):

```sh
# derive a key + its self-certifying signer id
naalp keygen --seed-hex 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a

# sign a message object on the Interaction / Respond surface
naalp sign --seed-hex 2a...2a --channel 15 --kind 1 --message "hello" --out obj.bin

# verify it (exit 0 on success, non-zero on any failure)
naalp verify --pubkey-hex <PUBKEY_HEX> --in obj.bin
```
