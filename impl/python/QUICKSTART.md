<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Python SDK

The Python reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents. Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `envelope.Object` + `envelope.sign` / `envelope.verify`: build,
  content-id-bind, deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519
  (RFC 8032), in COSE_Sign1 (`cose`).
- **The byte-level primitives** — deterministic CBOR + content id (`cbor`), self-certifying
  signer id (`identity`), the effect lattice + authorization (`policy`), the spine record bodies
  — approval, receipt, delivery, stream, carriage, transport boundary (`records`), causal verify
  + federation reconcile (`graph`), and the twenty-channel registry (`channels`).

Every construction is **graded byte-for-byte** against the shared conformance corpus
(== Go == Rust); the reference worked object is reproduced exactly (`tests/test_worked_example.py`).

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `records.transport_emit`.
- Production key management. `dilithium-py` is a correct but **non-constant-time** ML-DSA
  implementation — ideal for reference/interop, not for production key handling; swap in a
  constant-time FIPS 204 provider for production while keeping the same object bytes.

## Install

```sh
pip install naalp        # from PyPI  (or: pip install -e .  from this directory)
```

Dependencies: `dilithium-py>=1.4.0` (deterministic ML-DSA) and `cryptography>=42` (Ed25519).
The CBOR / content-id / identity / effect / record / graph / channel code is pure standard library.

## Sign and verify an object

```python
from naalp import cose, identity, envelope
from naalp.cbor import U, B, T, M

seed = bytes(32)                                   # a real 32-byte key seed in production
alg  = cose.ALG_MLDSA65
pk   = cose.mldsa_keygen("ML-DSA-65", seed)
sid  = identity.signer_id(alg, pk)

body   = M([(U(1), T("hello"))])
obj    = envelope.Object(kind=1, channel=4, signer=sid.encode(),
                         created=1785000000000, effect=2, profile=cose.PROFILE_PUBLIC, body=body)
signed = envelope.sign(obj, alg, seed)             # a self-describing signed object (bytes)
got    = envelope.verify(cose.PROFILE_PUBLIC, alg, pk, lambda c, k: (c, k) == (4, 1), signed)
```

## Run the example

```sh
python examples/sign_object.py
# signer   bciq...
# signed   <N> bytes, verifies=True
# tampered rejected: BadSignature
```

## Run the tests

```sh
python -m unittest discover -s tests -v
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
./harness/runner/naalp-conform run --testee "python harness/adapters/python/adapter.py"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
