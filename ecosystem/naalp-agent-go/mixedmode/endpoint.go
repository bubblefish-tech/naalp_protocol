// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package mixedmode implements N-AALP's mixed-mode / gradual-typing HTTP endpoint SDK
// (design.md Sec.13.8: the mixed-mode discrimination design). A mixed-mode endpoint accepts EITHER a strict
// N-AALP CBOR/COSE envelope OR a legacy NPAMP-CC-HTTP JSON body on the same channel,
// tags each request with its origin, and enforces the one non-negotiable rule the design
// settles before any SDK code: the legacy path gains NO authority the strict checks
// (effect-class, audience, signature) would deny -- it is read-only-equivalent unless the
// caller upgrades to a signed strict object.
//
// This package performs NO cryptography, NO CBOR encoding, and NO carriage-body
// re-serialization of its own: strict-path verification is the real Part-1
// impl/go/envelope.Verify, effect authorization is the real Part-1
// impl/go/policy.Grant.AuthorizeObject, and a legacy body is wrapped octet-for-octet by
// the real Part-1 impl/go/carriage.Carry under ClassHTTP/content_type=json (Sec.13.7) --
// never parsed, never canonicalized, never re-serialized (R-14.4 applies to the legacy
// fallback exactly as it applies to every other carried foreign message). This package's
// own code is only the discrimination order (Sec.13.8(a): try strict first, fall back to
// legacy only on parse failure and only when explicitly enabled) and the ONE
// authorization choke point (Sec.13.8(b)) that caps a legacy-origin record at read_only
// regardless of anything the legacy JSON body itself claims -- an attacker-crafted
// {"effect":3,...} inside an unsigned legacy body is never consulted for authorization;
// Authorize below never even inspects Record.Carriage.Foreign.
package mixedmode

import (
	"github.com/bubblefish-tech/naalp_protocol/impl/go/carriage"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// ContentTypeJSON is content_type = 0 (design.md Sec.13.7, the "json" row) -- the
// encoding tag a legacy NPAMP-CC-HTTP body carries when wrapped as a carriage payload.
const ContentTypeJSON uint64 = 0

// ProtocolIDHTTP is protocol_id = 0x03 (design.md Sec.13.4, vectors/registry/protocols.csv
// row 4, "HTTP") -- the registered N-AALP protocol id for HTTP-class carriage, used to
// wrap an accepted legacy body when Endpoint.ProtocolID is left zero.
const ProtocolIDHTTP uint64 = 0x03

// Origin tags a discriminated Record's provenance (Requirement 11 AC2: "a unified typed
// interface that tags each object's origin (legacy vs strict)").
type Origin int

const (
	OriginStrict Origin = iota
	OriginLegacy
)

// String names the origin ("strict" / "legacy").
func (o Origin) String() string {
	if o == OriginStrict {
		return "strict"
	}
	return "legacy"
}

// Error is a named, fail-closed mixedmode error (the same stable-Kind-plus-Msg shape
// every sibling ecosystem package's own glue-layer error type uses, e.g. react.Error).
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

// Errors this package's own code can produce. A strict-path verification failure
// propagates as ITS OWN error type (typically *cose.Error), never wrapped into this
// type -- only this package's two glue-layer decisions get a named Error here.
var (
	// ErrLegacyDisabled is returned when the strict parse fails and AllowLegacy is
	// false (AC4: strict is the default; a caller MUST opt in before any legacy
	// fallback is even attempted -- there is no implicit fallback).
	ErrLegacyDisabled = &Error{"LegacyDisabled",
		"endpoint is strict-only; AllowLegacy was not explicitly enabled, so a strict-parse " +
			"failure is refused rather than silently retried as legacy"}

	// ErrLegacyEffectNotAuthorized is the D15 refusal: a legacy-origin record requested
	// an effect above read_only. It is returned unconditionally -- independent of any
	// Grant -- because a legacy record carries no signature-derived principal for a
	// Grant to check against in the first place (design.md Sec.13.8(b)).
	ErrLegacyEffectNotAuthorized = &Error{"LegacyEffectNotAuthorized",
		"a legacy-origin record MUST NOT gain effecting authority above read_only; upgrade " +
			"to a signed strict N-AALP object to request a higher effect (design.md Sec.13.8(b), D15)"}
)

// Record is the unified typed interface Requirement 11 AC2 requires: every
// discriminated request, strict or legacy, decodes into this ONE type, tagged by Origin.
type Record struct {
	// Origin is OriginStrict or OriginLegacy.
	Origin Origin
	// Object is the verified strict N-AALP object -- non-nil iff Origin == OriginStrict.
	Object *envelope.Object
	// Carriage is the legacy body, wrapped octet-for-octet under
	// ClassHTTP/content_type=json (Sec.13.8(a)) -- valid iff Origin == OriginLegacy.
	// Carriage.Foreign holds the raw legacy bytes VERBATIM (R-14.4); this package
	// never parses them, and Authorize never reads this field.
	Carriage carriage.CarriageBody
}

// Endpoint is a mixed-mode N-AALP HTTP endpoint (Requirement 11 AC2-4). The zero value
// is strict-only (AllowLegacy defaults false) -- a caller must set AllowLegacy=true
// explicitly before Handle will ever attempt the legacy fallback (AC4: fail-closed
// opt-in, the legacy path is the wider attack surface).
type Endpoint struct {
	// Profile, Verifier, KindValidator, and KnownCext are passed straight through to
	// the real Part-1 envelope.Verify for the strict-path parse; see
	// impl/go/envelope.Verify's own doc for their meaning.
	Profile       int
	Verifier      cose.Verifier
	KindValidator envelope.KindValidator
	KnownCext     map[uint64]bool

	// AllowLegacy must be set true explicitly for Handle to ever attempt the legacy
	// fallback (AC4).
	AllowLegacy bool

	// ProtocolID is the carriage protocol_id used to wrap an accepted legacy body
	// (design.md Sec.13.4). Zero means ProtocolIDHTTP (0x03).
	ProtocolID uint64

	// SelfAuthority is this endpoint's own consuming-authority id, passed to the real
	// Part-1 envelope.CheckAudience (Sec.2.5.3) for every (channel,kind) registered in
	// ConsumeOnceKinds, on BOTH the strict and legacy legs of Authorize -- mirrors
	// naalp_mixed_mode.MixedModeEndpoint.self_authority in the Python sibling SDK.
	SelfAuthority string

	// ConsumeOnceKinds is the set of (channel, kind) pairs this endpoint treats as
	// single-use/audience-bound (Sec.2.5.3), checked in Authorize on BOTH legs (closes
	// the Fable-identified cross-SDK parity finding, design.md Sec.13.8/D15: this Go
	// mixed-mode SDK previously lacked the audience binding its Python mirror already
	// carried). A strict-origin record targeting one of these pairs MUST additionally
	// pass envelope.CheckAudience against its VERIFIED audience field. A legacy-origin
	// record claiming one of these pairs (named explicitly via Authorize's legacyTarget
	// argument, since Handle never parses the untrusted foreign body) MUST ALSO be
	// refused -- an unsigned legacy record can never present a real audience, so it can
	// never satisfy a consume-once binding (mirrors the Python _handle_legacy surrogate).
	ConsumeOnceKinds map[ConsumeOnceKey]bool
}

// ConsumeOnceKey identifies a (channel, kind) pair by its two wire-registered numeric
// ids (design.md Sec.2.5.3) -- the map key type for Endpoint.ConsumeOnceKinds and the
// explicit legacy-leg target argument to Authorize.
type ConsumeOnceKey struct {
	Channel uint64
	Kind    uint64
}

// Handle discriminates rawBody per design.md Sec.13.8(a): it FIRST attempts to parse
// and verify rawBody as a strict N-AALP envelope (the real Part-1 envelope.Verify, so
// the signature, content id, and every structural check are the genuine ones, never a
// mixedmode-local reimplementation). If and only if that parse fails does Handle
// consider the legacy fallback -- and only when e.AllowLegacy is true; otherwise the
// request is refused ErrLegacyDisabled (AC4 -- no implicit fallback). A legacy body is
// wrapped octet-for-octet as a ClassHTTP/content_type=json carriage payload via the
// real Part-1 carriage.Carry and returned tagged OriginLegacy; it is never parsed as
// JSON by this package (this package makes no assumption about the legacy body's
// structure beyond "it is bytes").
func (e *Endpoint) Handle(rawBody []byte) (*Record, error) {
	obj, err := envelope.Verify(e.Profile, e.Verifier, e.KindValidator, e.KnownCext, rawBody)
	if err == nil {
		return &Record{Origin: OriginStrict, Object: obj}, nil
	}
	if !e.AllowLegacy {
		return nil, ErrLegacyDisabled
	}
	protocolID := e.ProtocolID
	if protocolID == 0 {
		protocolID = ProtocolIDHTTP
	}
	body, cerr := carriage.Carry(protocolID, carriage.ClassHTTP, ContentTypeJSON, nil, "", rawBody)
	if cerr != nil {
		return nil, cerr
	}
	return &Record{Origin: OriginLegacy, Carriage: body}, nil
}

// Authorize is the ONE choke point through which every discriminated Record's
// effecting authority is decided (design.md Sec.13.8(b), D15; requirements.md
// Requirement 11 AC1). It implements the CRITICAL AUTHZ rule: a legacy-origin
// record's effect ceiling is UNCONDITIONALLY read_only, decided by this function
// alone and never derived from anything the legacy body itself contains -- Authorize
// never reads r.Carriage.Foreign, so an attacker-crafted legacy JSON claiming a
// higher effect or a forged audience has nothing here to influence. A strict-origin
// record delegates to the real Part-1 policy.Grant.AuthorizeObject against its
// VERIFIED signer (the exact check every other N-AALP effecting object passes
// through, Sec.6.3) -- no code path in this package routes a legacy-origin record
// around this gate or the channels.CheckEffect choke point on the theory that "it
// isn't really an N-AALP object" (the request-smuggling shape design.md explicitly
// forecloses).
//
// legacyTarget is an OPTIONAL variadic argument (at most its first element is used):
// on the legacy leg it names the (channel, kind) the caller believes this legacy
// record is claiming, since Handle never parses the untrusted foreign body itself
// and a Record's legacy leg therefore carries no channel/kind of its own. Omitting
// it (the zero-arg call every pre-existing caller already makes) is equivalent to a
// legacy claim that never targets a consume-once pair -- no new refusal fires, and
// the D15 read_only ceiling below is unchanged. It is ignored on the strict leg,
// where the (channel, kind) is instead read directly off the VERIFIED r.Object.
func (e *Endpoint) Authorize(r *Record, grant policy.Grant, requestedEffect policy.Effect, legacyTarget ...ConsumeOnceKey) error {
	if r.Origin == OriginLegacy {
		if requestedEffect > policy.ReadOnly {
			return ErrLegacyEffectNotAuthorized
		}
		// (3) the Sec.2.5.3 single-use consume binding, mirrored onto the legacy leg
		// (Python's _handle_legacy surrogate, closing the Fable parity finding). A legacy
		// record has no signature-derived audience -- Handle never parses the foreign
		// body -- so a caller naming a consume-once target here gets a surrogate whose
		// Audience field is left at its Go zero value "" and is NEVER populated from the
		// untrusted foreign bytes (there is no self-asserted-audience field to even read).
		// envelope.CheckAudience's own absent-audience-on-consume-once branch then refuses
		// it unconditionally (ErrWrongAudience): a legacy record can never satisfy a
		// consume-once binding, no matter what (channel, kind) is named.
		if len(legacyTarget) > 0 && e.ConsumeOnceKinds[legacyTarget[0]] {
			surrogate := &envelope.Object{Channel: legacyTarget[0].Channel, Kind: legacyTarget[0].Kind}
			if err := envelope.CheckAudience(surrogate, e.SelfAuthority, true); err != nil {
				return err
			}
		}
		return nil
	}
	// (1) C10 effect-vs-kind admission (design.md Sec.3.2): the object's DECLARED effect must
	// match the effect its kind declares -- the SAME channels.CheckEffect the Python mirror's
	// _authorize_strict runs as its first strict step. A strict object whose declared effect is
	// not the one its kind declares is refused here, before the grant is even consulted; this is
	// the choke point the package doc names, now enforced in-package (not merely delegated).
	if err := channels.CheckEffect(r.Object.Channel, r.Object.Kind, r.Object.Effect); err != nil {
		return err
	}
	// (2) the C5 effect-authorization gate against the VERIFIED signer's registered grant.
	if err := grant.AuthorizeObject(policy.SourceSignature, string(r.Object.Signer), uint64(requestedEffect)); err != nil {
		return err
	}
	// (3) the Sec.2.5.3 single-use consume binding, for a (channel, kind) this endpoint
	// has registered as consume-once -- reuses the real Part-1 envelope.CheckAudience
	// against the VERIFIED strict object and this endpoint's own SelfAuthority (never
	// reimplemented here); closes the Fable-identified parity finding against the
	// Python mirror's _authorize_strict step 3.
	if e.ConsumeOnceKinds[ConsumeOnceKey{Channel: r.Object.Channel, Kind: r.Object.Kind}] {
		if err := envelope.CheckAudience(r.Object, e.SelfAuthority, true); err != nil {
			return err
		}
	}
	return nil
}
