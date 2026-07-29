<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Go SDK

The Go reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — and the primary
reference against which every other SDK is byte-compared. Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `envelope.Object` + `envelope.Sign` / `envelope.Verify`: build,
  content-id-bind, deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519, in
  COSE_Sign1 (`cose`), via Cloudflare CIRCL.
- **The byte-level primitives** — deterministic CBOR + content id (`cbor`), self-certifying
  identity (`identity`), effect + authorization (`policy`), the spine record bodies (`approval`,
  `audit`, `delivery`, `streaming`, `carriage`), causal + federation ordering (`audit`,
  `federation`), the transport boundary (`transport`), and the twenty-channel registry (`channels`).

Every construction is graded byte-for-byte against the shared conformance corpus (Go is the
reference: Go == Rust == oracle), and the reference worked object is reproduced exactly.

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `transport.Emit`.

## Install

```sh
go get github.com/bubblefish-tech/naalp_protocol/impl/go
```

## Sign and verify an object

```go
package main

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	var seed [32]byte // a real 32-byte key seed in production
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	sid, _ := identity.SignerID(cose.AlgMLDSA65, pk.Bytes())

	o := &envelope.Object{
		Kind: 1, Channel: 4, Signer: []byte(sid), Created: 1785000000000,
		Effect: 2, Profile: cose.ProfilePublic,
		Body: cbor.Map{{K: cbor.Uint(1), V: cbor.Tstr("hello")}},
	}
	signed, _ := envelope.Sign(o, cose.MLDSA65Signer{SK: sk})

	kindOK := func(ch, k uint64) bool { return ch == 4 && k == 1 }
	obj, err := envelope.Verify(cose.ProfilePublic, cose.MLDSA65Verifier{PK: pk}, kindOK, nil, signed)
	_ = obj
	_ = err
}
```

## Run the example and tests

```sh
cd impl/go
go run ./cmd/naalp-worked-example        # generates the byte-exact worked object
GOWORK=off go test -race -count=1 ./...   # unit + KAT + oracle cross-validation tests
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
./harness/runner/naalp-conform run --testee "./harness/adapters/go/naalp-adapter-go"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
