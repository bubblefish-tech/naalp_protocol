// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naalpcore is a stable, generic facade over N-AALP's real, module-scoped core
// surface. It exists to reconcile a naming mismatch surfaced by two external integration
// specs: the Agent Governance Kit's K0 neutral binding and the Manufacturing Add-ons'
// naalp-ffi Component A both assume one generic top-level core API — sign / verify /
// content_id / signer_id — but the real reference implementation exposes per-module
// functions instead (naalp.Signer.Sign, naalp.Verify, cbor.ContentID, identity.SignerID),
// each with its own signature.
//
// naalpcore reimplements no cryptography, no encoding, and no protocol logic: every
// exported function below is a thin, one-line delegation to the real underlying function,
// named to match what the external specs assume so a generic caller (a framework binding,
// an FFI shim) has one small, stable surface to call through. The companion facade lives
// in impl/rust/src/naalpcore.rs, with the C-ABI layer in impl/rust/naalp-ffi.
//
// This package is purely additive. It does not touch the wire format, the CDDL, any
// conformance vector, or any existing impl/go file — it only imports and calls them.
package naalpcore

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalp"
)

// AlgMLDSA65 and AlgMLDSA87 re-export the COSE algorithm identifiers a caller passes to
// SignerID (cose.AlgMLDSA65 = -49, cose.AlgMLDSA87 = -50; design.md §4.1, RFC 9964).
// naalpcore introduces no new algorithm identifier — these are the same constants
// envelope, cose, and identity already use.
const (
	AlgMLDSA65 = cose.AlgMLDSA65
	AlgMLDSA87 = cose.AlgMLDSA87
)

// Signer is a deterministic ML-DSA-65 signing identity. It is a direct alias of
// naalp.Signer (impl/go/naalp/naalp.go) — naalpcore adds no key-management logic of its
// own; a Signer signs at naalp.DefaultProfile (cose.ProfilePublic).
type Signer = naalp.Signer

// NewSigner delegates to naalp.NewSigner: it derives a Signer from a 32-byte ML-DSA-65
// seed and rejects any other length with naalp.ErrSeedSize before any key is created.
func NewSigner(seed []byte) (*Signer, error) { return naalp.NewSigner(seed) }

// GenerateSigner delegates to naalp.GenerateSigner: it draws a fresh, cryptographically
// random 32-byte seed from crypto/rand and derives a Signer from it.
func GenerateSigner() (*Signer, error) { return naalp.GenerateSigner() }

// Sign delegates to (*naalp.Signer).Sign — the canonical happy-path object-signing call.
// The caller supplies the (channel, kind) a captured action belongs to (per the frozen
// registry in package channels), the created timestamp (Unix milliseconds), and the CBOR
// body; the object's declared effect and signing profile are derived from the registry
// entry for (channel, kind), never supplied by the caller. An unregistered (channel,
// kind) is rejected (envelope.ErrUnknownKind) before any signing work. It returns the
// tagged COSE_Sign1 object bytes.
func Sign(s *Signer, channel, kind, created uint64, payload cbor.Value) ([]byte, error) {
	return s.Sign(channel, kind, created, payload)
}

// Verify delegates to naalp.Verify — the canonical happy-path verification call. It runs
// the full envelope check (content id, field ranges, header/body copies, critical
// extensions, (channel, kind) admission against the frozen registry, profile floor, and
// the COSE signature), then rebinds the object's self-certifying signer id to the public
// key the signature was actually checked against, then confirms the object's effect
// equals the kind's declared effect. Any failure is fail-closed with the spine's named
// error and no partial result.
func Verify(pub, obj []byte) (*envelope.Object, error) {
	return naalp.Verify(pub, obj)
}

// ContentID delegates to cbor.ContentID: the object content-id of a body map with field 1
// (the id itself) omitted — multihash(0x20, SHA-384(canonical-encoding(body))), a 50-byte
// value (0x20 0x30 || 48-byte digest; design.md §2.3). ContentID is a pure function of the
// body bytes: the same body always produces the same id, and a changed body always
// produces a different id.
func ContentID(bodyWithoutID cbor.Map) ([]byte, error) {
	return cbor.ContentID(bodyWithoutID)
}

// SignerID delegates to identity.SignerID: the self-certifying signer id derived from
// (alg, pubkey) alone (design.md §5.1) — a pure function of the public key, computed with
// no external registry lookup. alg must be AlgMLDSA65 or AlgMLDSA87; any other value is
// rejected before any digest is computed.
func SignerID(alg int, pubkey []byte) (string, error) {
	return identity.SignerID(alg, pubkey)
}
