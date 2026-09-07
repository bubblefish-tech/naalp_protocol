<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Identity (`0x0003`)

The durable identity layer: rotation, revocation, and foreign-identity linkage. The signer-id
construction and its verification are part of the spine (the draft's Identity section); this
surface is the workflow around it (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `Rotation` | `non_idempotent_write` | co-signed old+new key |
| 1 | `Revocation` | `destructive` | |
| 2 | `ForeignLink` | `idempotent_write` | binds a foreign identity to an N-AALP signer id (§ below) |
| 3 | `KeyAnnounce` | `read_only` | publish an RFC 7250 SPKI for a signer id |

This is the current registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Identity](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L64-L65)),
cross-checked against an independent per-channel oracle.

## Self-certifying signer ids, no CA

N-AALP's identity model is "no CA," self-certifying, offline-verifiable: a signer id is a hash of
the multicodec-tagged public key, never a value a third party issues.

```go
// impl/go/identity/identity.go
// signer = multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))
// where mc is the multiformats multicodec key-type code (ed25519-pub 0xed, mldsa-65-pub ...)
func SignerID(alg int, pubkey []byte) (string, error)
```

([`identity.go:75`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L75)).
Because a signer id is a one-way hash, it cannot be inverted back into a public key by itself —
every verify path recomputes the hash from a presented key (`CheckSigner`) rather than trusting the
id as a lookup key.

## State model

An identity thread is a `causes`-linked chain of `Rotation`s ending at most in one `Revocation`.
`RotationUnauthorized`, `KeyRevoked`, and `SignerMismatch` are the baseline channel's named errors.

## Rotation and revocation, co-signed

`SignRotation` requires both the old and the new signing key to co-sign the rotation record — a
compromised new key alone cannot rotate an identity, and a stolen old key alone cannot either:

```go
func SignRotation(r RotationRecord, oldSigner, newSigner cose.Signer) (oldSig, newSig []byte, err error)
func VerifyRotation(r RotationRecord, oldV, newV cose.Verifier, oldPub, newPub, oldSig, newSig []byte) error
```

([`identity.go:155`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L155),
[`identity.go:171`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L171)).
`VerifyRevocation` additionally accepts a recovery-key quorum (`recoveryIDs`) so a lost signing key
does not permanently strand an identity's revocation path.

## Portable identity: `ForeignLink` and the did:jwk bridge

`ForeignLink` is the linkage primitive the ecosystem's DID/VC bridge (`ecosystem/naalp-did`, Go)
builds on — a cross-signed record `{controls, foreign_id, not_after}` binding a foreign identity
(for example, a W3C DID) to an N-AALP signer id, signed by the foreign identity's own key:

```go
type ForeignLinkRecord struct {
	Controls  string // the N-AALP signer id this record binds
	ForeignID string // the foreign identity string (e.g. a did:jwk URI)
	NotAfter  uint64 // the link's validity horizon
}
func VerifyForeignLink(r ForeignLinkRecord, foreignV cose.Verifier, foreignPub, sig []byte, now uint64) (linked bool, err error)
```

([`identity.go:233`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L233),
[`identity.go:252`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L252)).
`VerifyForeignLink` requires `ForeignID` to be Unicode NFC (`RequireNFC`), rejects an expired link
(`NotAfter` in the past), and rejects a link whose signature does not verify under the foreign
identity's own claimed key — a link is only real when the foreign identity itself signed it, never
when the N-AALP side merely asserts the binding. The `ecosystem/naalp-did` package (Go) is the
concrete production caller: it bridges an N-AALP signer id to a `did:jwk` URI carrying an
[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) `kty:"AKP"` JWK for the agent's actual
ML-DSA-65/87 (or an RFC 8037 OKP JWK for Ed25519) public key, and calls `LinkSignerToDID` to build
and sign the `ForeignLinkRecord` this mechanism already defines — no new linkage primitive, only a
deterministic encoder for the DID string.

## Failure modes

| Error kind | When |
|---|---|
| `RotationUnauthorized` | a rotation record is missing the required old-or-new co-signature |
| `KeyRevoked` | a signature verifies under a key whose revocation record predates it |
| `SignerMismatch` | the presented key does not hash to the claimed signer id |

Every check is fail-closed (the draft's Security Considerations section): a failing action is
rejected whole, returns its named error, and causes no state change.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md),
the [discovery reference](../reference/discovery.md) for the Discovery-channel and signed-description
mechanisms `ForeignLink` composes with at the identity layer.
