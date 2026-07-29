<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# The object model

## Deterministic CBOR

All N-AALP structures are deterministic CBOR per RFC 8949 §4.2.1: shortest-form integers and
lengths, map keys sorted bytewise-lexicographically by their encoded form, no indefinite-length
items, no duplicate keys. A non-canonical encoding is rejected (`NonCanonical`).

## The object body

```cddl
naalp-object = {
  1 : bstr,      ; id: multihash(0x20, SHA-384(body-without-1))
  2 : uint,      ; kind (per channel surface)
  3 : 0..19,     ; channel id
  4 : uint,      ; tier (0 = baseline)
  5 : bstr,      ; signer: self-certifying signer id
  6 : uint,      ; created: epoch ms (advisory)
  7 : effect,    ; closed effect value (0..3)
  8 : [* bstr],  ; causes: content ids; may be empty
  9 : profile,   ; crypto profile (1 public, 2 enterprise, 3 sovereign)
  10 : any,      ; body: kind-specific, validated by the surface
  ? 11 : { * uint => any },  ; ext: non-critical; unknown ignored
  ? 12 : { * uint => any },  ; cext: critical; unknown => reject
}
```

## Content identity

The `id` binds the exact bytes: `multihash(0x20, SHA-384(C))`, where `C` is the deterministic
encoding of the body with field 1 removed. A verifier recomputes it and rejects a mismatch
(`ContentIdMismatch`). Any field change changes the id.

## Signing

The object is signed with COSE_Sign1 (RFC 9052) over the object body as the payload. The protected
header carries the COSE algorithm plus a pre-parse routing copy of the signer, profile, and
version; a header/body disagreement is `HeaderBodyMismatch`. On the wire the object is a tagged
COSE_Sign1 (tag 18); the optional hybrid is a tagged COSE_Sign (tag 98), accepted only if all
legs verify.

## Fail-closed verification

Verification proceeds decode → content-id → field ranges → header/body copies + version →
critical extensions → kind/channel dispatch → profile floor → signature. An object that fails any
check is **rejected whole**, returns its named error, and causes no state change. There is no
partial application and no fail-open path.

## Identity

The signer id (field 5) is `multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))`
— a pure function of the public key, recomputed by the verifier (`SignerMismatch` on a mismatch);
no certificate authority. Keys rotate (co-signed old+new), revoke, and cross-sign foreign
identities, and attribution survives rotation.
