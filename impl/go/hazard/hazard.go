// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package hazard implements Manufacturing Add-ons Component F, the physical-hazard
// authorization extension (design.md addendum; requirements F1-F5; wire authority
// spec/naalp-draft-01.cddl, the frozen MANUFACTURING PHYSICAL-HAZARD productions).
//
// STATUS: FROZEN 2026-09-01 (Shawn-approved wire bytes). The naalp-hazard-claim
// (critical cext key 16) and naalp-hazard-authorization (Governance 0x0004 kind 7)
// productions are merged into the normative spec/naalp-draft-01.cddl naalp-artifact
// reachability root; the channel kind is registered in vectors/registry/channels.csv,
// the ext key in extension-keys.csv, and the three error codes (130/131/132) in
// error-codes.csv. This package is the Go port of the frozen Rust reference
// impl/rust/naalp-hazard, graded byte-identical against the shared vectors/hazard
// corpus (the non-circular oracle produced by tools/hazard_oracle.py); the remaining
// eight-port propagation is tracked separately.
//
// effect (envelope field 7, naalp/policy) describes DATA reversibility. hazard is a
// new, ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may
// still be a high physical hazard. The two dimensions are never merged and neither
// derives the other.
//
// This package adds no new cryptography and no new CBOR codec of its own: every
// encode call delegates to cbor.Encode / cbor.ContentID, exactly as every other
// spine/extension package builds on the shared codec.
//
// The fail-closed rules (F2, F3):
//   - HazardClassFromCode is the ONE fail-closed decode entry point: any missing or
//     out-of-range raw value normalizes to HazardClassMotionInSharedSpace -- the
//     highest class -- never to a weaker class. This mirrors the effect lattice's
//     unknown-to-destructive rule, extended to a domain-distinct closed set.
//   - HazardAuthorized requires an EXACT class match (not a "<=" ceiling the way the
//     effect lattice's authorization works) AND full containment of the claim's
//     envelope inside the grant's, on every axis, the speed bound, and the time
//     window. Any single failing dimension denies the WHOLE claim -- there is no
//     partial authorization.
//   - HazardAuthorizedOptional additionally covers the case where an action carries
//     NO hazard claim at all: there is no envelope to check containment against, so
//     it denies immediately with a distinct error (ErrHazardUnknown) rather than
//     fabricating a sentinel envelope and running the ordinary coverage check.
package hazard

import (
	"math"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
)

// Named errors, mirroring impl/rust/naalp-hazard's err_hazard_* constructors
// byte-for-byte in Kind and Msg (cose.Error{Kind,Msg} is the shared error shape
// every N-AALP port uses).
var (
	// ErrHazardMalformed: a hazard-claim/hazard-authorization/envelope body is not
	// the CDDL shape (spec/naalp-draft-01.cddl), a spatial-bounds axis has min > max,
	// axes is empty, or frame is not Unicode NFC.
	ErrHazardMalformed = &cose.Error{
		Kind: "HazardMalformed",
		Msg:  "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid",
	}
	// ErrHazardNotCovered (design's E_HAZARD_UNCOV): a well-formed claim's class or
	// envelope is not fully covered by the presented authorization.
	ErrHazardNotCovered = &cose.Error{
		Kind: "HazardNotCovered",
		Msg:  "declared hazard class or envelope is not fully covered by the authorization",
	}
	// ErrHazardUnknown (design's E_HAZARD_UNKNOWN): the hazard value for an action
	// requiring one is unrecognized or absent, and -- for the fully-absent case -- no
	// envelope exists to check coverage against at all.
	ErrHazardUnknown = &cose.Error{
		Kind: "HazardUnknown",
		Msg:  "hazard value unrecognized or absent; no claim to check coverage against",
	}
)

// ---- hazard-class (F2: closed, fail-closed to the highest class) -------------------------

// HazardClass is the closed five-value hazard-class vocabulary (spec/naalp-draft-01.cddl).
// HazardClassMotionInSharedSpace is BOTH a named class (4) and the fail-closed default
// for an unrecognized or absent raw value (F2) -- the assumption that "the producer did
// not tell us" is at least as dangerous as the worst named class.
type HazardClass uint8

const (
	HazardClassNone HazardClass = iota
	HazardClassToolActuation
	HazardClassThermal
	HazardClassEnergyRelease
	HazardClassMotionInSharedSpace
)

// Code returns the CDDL wire code (0..4).
func (c HazardClass) Code() uint8 { return uint8(c) }

// HazardClassFromCode is the fail-closed decode (F2). A nil code (the raw value was
// absent) or any value outside 0..=4 (unrecognized) normalizes to
// HazardClassMotionInSharedSpace -- never to a weaker class, and never a decode
// failure (there is no "invalid hazard" outcome; there is only "the worst case we
// must assume"). The pointer parameter mirrors the Rust reference's Option<u64> so a
// malformed wire value outside even the byte range still normalizes correctly rather
// than failing to parse.
func HazardClassFromCode(code *uint64) HazardClass {
	if code == nil {
		return HazardClassMotionInSharedSpace // F2: absent -> highest class
	}
	switch *code {
	case 0:
		return HazardClassNone
	case 1:
		return HazardClassToolActuation
	case 2:
		return HazardClassThermal
	case 3:
		return HazardClassEnergyRelease
	case 4:
		return HazardClassMotionInSharedSpace
	default:
		return HazardClassMotionInSharedSpace // F2: unknown -> highest class
	}
}

func (c HazardClass) toValue() cbor.Value { return cbor.Uint(uint64(c.Code())) }

// ---- spatial-bounds ------------------------------------------------------------------

// SpatialBounds is a named coordinate frame plus a signed axis-aligned bounding
// region in that frame, integer millimeters (spec/naalp-draft-01.cddl
// spatial-bounds). Fixed-point: the N-AALP CBOR subset (impl/go/cbor.Value) carries
// no floats, so a hazard envelope stays inside the same deterministic-CBOR
// discipline as every other production.
type SpatialBounds struct {
	Frame string
	// Axes holds per-axis [min, max], millimeters, signed. MUST be non-empty; every
	// entry MUST satisfy min <= max.
	Axes [][2]int64
}

func intValue(v int64) cbor.Value {
	if v >= 0 {
		return cbor.Uint(uint64(v))
	}
	return cbor.Nint(v)
}

func intFromValue(v cbor.Value) (int64, bool) {
	switch t := v.(type) {
	case cbor.Uint:
		if uint64(t) > uint64(math.MaxInt64) {
			return 0, false
		}
		return int64(t), true
	case cbor.Nint:
		return int64(t), true
	default:
		return 0, false
	}
}

// IsWellFormed checks structural validity (spec/naalp-draft-01.cddl): non-empty axes,
// every min <= max, frame non-empty and Unicode NFC.
func (s SpatialBounds) IsWellFormed() bool {
	if len(s.Axes) == 0 {
		return false
	}
	for _, a := range s.Axes {
		if a[0] > a[1] {
			return false
		}
	}
	if s.Frame == "" {
		return false
	}
	return identity.RequireNFC(s.Frame) == nil
}

func (s SpatialBounds) toValue() cbor.Map {
	axes := make(cbor.Arr, 0, len(s.Axes))
	for _, a := range s.Axes {
		axes = append(axes, cbor.Arr{intValue(a[0]), intValue(a[1])})
	}
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(s.Frame)},
		{K: cbor.Uint(2), V: axes},
	}
}

// Bytes returns the deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input
// still encodes (encoding is not the validity gate); callers MUST check
// IsWellFormed before treating a SpatialBounds as authoritative, exactly as
// SpatialBoundsFromValue does on decode.
func (s SpatialBounds) Bytes() []byte {
	b, _ := cbor.Encode(s.toValue())
	return b
}

// SpatialBoundsFromValue parses a spatial-bounds map. It rejects a non-map, an
// out-of-range/wrong-typed key or value, a missing key, empty axes, an axis with
// min > max, or a non-NFC/empty frame -- fail-closed (ErrHazardMalformed), never a
// partially-valid result.
func SpatialBoundsFromValue(v cbor.Value) (SpatialBounds, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return SpatialBounds{}, ErrHazardMalformed
	}
	var frame *string
	var axes *[][2]int64
	for _, p := range m {
		key, ok := p.K.(cbor.Uint)
		if !ok {
			return SpatialBounds{}, ErrHazardMalformed
		}
		switch uint64(key) {
		case 1:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return SpatialBounds{}, ErrHazardMalformed
			}
			str := string(s)
			frame = &str
		case 2:
			items, ok := p.V.(cbor.Arr)
			if !ok || len(items) == 0 {
				return SpatialBounds{}, ErrHazardMalformed
			}
			out := make([][2]int64, 0, len(items))
			for _, it := range items {
				pair, ok := it.(cbor.Arr)
				if !ok || len(pair) != 2 {
					return SpatialBounds{}, ErrHazardMalformed
				}
				min, okMin := intFromValue(pair[0])
				max, okMax := intFromValue(pair[1])
				if !okMin || !okMax {
					return SpatialBounds{}, ErrHazardMalformed
				}
				if min > max {
					return SpatialBounds{}, ErrHazardMalformed
				}
				out = append(out, [2]int64{min, max})
			}
			axes = &out
		default:
			return SpatialBounds{}, ErrHazardMalformed
		}
	}
	if frame == nil || axes == nil {
		return SpatialBounds{}, ErrHazardMalformed
	}
	sb := SpatialBounds{Frame: *frame, Axes: *axes}
	if !sb.IsWellFormed() {
		return SpatialBounds{}, ErrHazardMalformed
	}
	return sb, nil
}

// SpatialContained is full containment (F3): same frame id (a bound in one frame
// says nothing about a bound in a different, unrelated frame), the SAME axis count
// in the SAME order, and every claim axis's [min,max] a subset of the matching
// grant axis's [min,max].
func SpatialContained(claim, grant SpatialBounds) bool {
	if claim.Frame != grant.Frame {
		return false
	}
	if len(claim.Axes) != len(grant.Axes) {
		return false
	}
	for i := range claim.Axes {
		cmin, cmax := claim.Axes[i][0], claim.Axes[i][1]
		gmin, gmax := grant.Axes[i][0], grant.Axes[i][1]
		if cmin < gmin || cmax > gmax {
			return false
		}
	}
	return true
}

// ---- hazard-window ---------------------------------------------------------------------

// HazardWindow is a validity window, epoch ms, the same convention as naalp-object
// field 6 (created) and naalp-delegation-grant fields 4/5.
type HazardWindow struct {
	NotBefore uint64
	NotAfter  uint64
}

func (w HazardWindow) toValue() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(w.NotBefore)},
		{K: cbor.Uint(2), V: cbor.Uint(w.NotAfter)},
	}
}

func hazardWindowFromValue(v cbor.Value) (HazardWindow, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return HazardWindow{}, ErrHazardMalformed
	}
	var notBefore, notAfter *uint64
	for _, p := range m {
		key, ok := p.K.(cbor.Uint)
		if !ok {
			return HazardWindow{}, ErrHazardMalformed
		}
		n, ok := p.V.(cbor.Uint)
		if !ok {
			return HazardWindow{}, ErrHazardMalformed
		}
		nv := uint64(n)
		switch uint64(key) {
		case 1:
			notBefore = &nv
		case 2:
			notAfter = &nv
		default:
			return HazardWindow{}, ErrHazardMalformed
		}
	}
	if notBefore == nil || notAfter == nil {
		return HazardWindow{}, ErrHazardMalformed
	}
	return HazardWindow{NotBefore: *notBefore, NotAfter: *notAfter}, nil
}

// ---- hazard-envelope --------------------------------------------------------------------

// HazardEnvelope is the full physical envelope a claim or an authorization bounds
// itself by. All three fields are MANDATORY on the wire (spec/naalp-draft-01.cddl) --
// a silently-absent axis would be fail-OPEN in a physical-safety context, so an
// issuer that means "unbounded" states so explicitly with wide numeric bounds; the
// wire never infers permissiveness from silence here (deliberate contrast with
// naalp-delegation-grant's optional scope).
type HazardEnvelope struct {
	Spatial SpatialBounds
	// SpeedBoundMmS is the max instantaneous speed, millimeters per second.
	SpeedBoundMmS uint64
	Window        HazardWindow
}

func (e HazardEnvelope) toValue() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: e.Spatial.toValue()},
		{K: cbor.Uint(2), V: cbor.Uint(e.SpeedBoundMmS)},
		{K: cbor.Uint(3), V: e.Window.toValue()},
	}
}

// Bytes returns the deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}.
func (e HazardEnvelope) Bytes() []byte {
	b, _ := cbor.Encode(e.toValue())
	return b
}

// ContentID returns the envelope's content id (T1 framing, cbor.ContentID): a pure
// function of the bytes above.
func (e HazardEnvelope) ContentID() ([]byte, error) {
	return cbor.ContentID(e.toValue())
}

// HazardEnvelopeFromValue parses a hazard-envelope map; fail-closed on any
// missing/malformed field.
func HazardEnvelopeFromValue(v cbor.Value) (HazardEnvelope, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return HazardEnvelope{}, ErrHazardMalformed
	}
	var spatial *SpatialBounds
	var speed *uint64
	var window *HazardWindow
	for _, p := range m {
		key, ok := p.K.(cbor.Uint)
		if !ok {
			return HazardEnvelope{}, ErrHazardMalformed
		}
		switch uint64(key) {
		case 1:
			sb, err := SpatialBoundsFromValue(p.V)
			if err != nil {
				return HazardEnvelope{}, err
			}
			spatial = &sb
		case 2:
			n, ok := p.V.(cbor.Uint)
			if !ok {
				return HazardEnvelope{}, ErrHazardMalformed
			}
			nv := uint64(n)
			speed = &nv
		case 3:
			w, err := hazardWindowFromValue(p.V)
			if err != nil {
				return HazardEnvelope{}, err
			}
			window = &w
		default:
			return HazardEnvelope{}, ErrHazardMalformed
		}
	}
	if spatial == nil || speed == nil || window == nil {
		return HazardEnvelope{}, ErrHazardMalformed
	}
	return HazardEnvelope{Spatial: *spatial, SpeedBoundMmS: *speed, Window: *window}, nil
}

// EnvelopeContained is full containment (F3): SpatialContained AND
// claim.SpeedBoundMmS <= grant.SpeedBoundMmS AND the claim's window is a
// sub-interval of the grant's (grant.NotBefore <= claim.NotBefore and
// claim.NotAfter <= grant.NotAfter).
func EnvelopeContained(claim, grant HazardEnvelope) bool {
	return SpatialContained(claim.Spatial, grant.Spatial) &&
		claim.SpeedBoundMmS <= grant.SpeedBoundMmS &&
		grant.Window.NotBefore <= claim.Window.NotBefore &&
		claim.Window.NotAfter <= grant.Window.NotAfter
}

// ---- naalp-hazard-claim / naalp-hazard-authorization -------------------------------------

// HazardClaim is a signed physical-hazard claim (spec/naalp-draft-01.cddl
// naalp-hazard-claim). Carriage (the object it accompanies and how) is a
// wire-impact decision, not this package's concern.
type HazardClaim struct {
	Class    HazardClass
	Envelope HazardEnvelope
}

// HazardAuthorization is a signed physical-hazard authorization ("a grant" in
// requirements F3's language; spec/naalp-draft-01.cddl naalp-hazard-authorization).
// Same shape as HazardClaim deliberately: one envelope shape for both sides keeps
// the containment check symmetric.
type HazardAuthorization struct {
	Class    HazardClass
	Envelope HazardEnvelope
}

func hazardBodyToValue(class HazardClass, envelope HazardEnvelope) cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: class.toValue()},
		{K: cbor.Uint(2), V: envelope.toValue()},
	}
}

func hazardBodyFromValue(v cbor.Value) (HazardClass, HazardEnvelope, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return 0, HazardEnvelope{}, ErrHazardMalformed
	}
	var classCode *uint64
	var envelope *HazardEnvelope
	for _, p := range m {
		key, ok := p.K.(cbor.Uint)
		if !ok {
			return 0, HazardEnvelope{}, ErrHazardMalformed
		}
		switch uint64(key) {
		case 1:
			n, ok := p.V.(cbor.Uint)
			// An out-of-range class ON THE WIRE (not merely "absent") is a malformed
			// body, not a normalize-to-4 input: F2's fail-closed normalization is for
			// the DECODE step that produces a class from a less-structured source (see
			// HazardClassFromCode), not for a CDDL-invalid hazard-class value already
			// claiming to be well-formed.
			if !ok || uint64(n) > 4 {
				return 0, HazardEnvelope{}, ErrHazardMalformed
			}
			nv := uint64(n)
			classCode = &nv
		case 2:
			e, err := HazardEnvelopeFromValue(p.V)
			if err != nil {
				return 0, HazardEnvelope{}, err
			}
			envelope = &e
		default:
			return 0, HazardEnvelope{}, ErrHazardMalformed
		}
	}
	if classCode == nil || envelope == nil {
		return 0, HazardEnvelope{}, ErrHazardMalformed
	}
	return HazardClassFromCode(classCode), *envelope, nil
}

func (c HazardClaim) toValue() cbor.Map { return hazardBodyToValue(c.Class, c.Envelope) }

// Bytes returns the deterministic-CBOR encoding of {1:class,2:envelope}.
func (c HazardClaim) Bytes() []byte {
	b, _ := cbor.Encode(c.toValue())
	return b
}

// ContentID returns the claim's content id (T1 framing).
func (c HazardClaim) ContentID() ([]byte, error) {
	return cbor.ContentID(c.toValue())
}

// HazardClaimFromValue parses a naalp-hazard-claim body. Both class and envelope
// are mandatory -- a claim declaring one and omitting the other is
// ErrHazardMalformed, not partially valid.
func HazardClaimFromValue(v cbor.Value) (HazardClaim, error) {
	class, envelope, err := hazardBodyFromValue(v)
	if err != nil {
		return HazardClaim{}, err
	}
	return HazardClaim{Class: class, Envelope: envelope}, nil
}

func (a HazardAuthorization) toValue() cbor.Map { return hazardBodyToValue(a.Class, a.Envelope) }

// Bytes returns the deterministic-CBOR encoding of {1:class,2:envelope}.
func (a HazardAuthorization) Bytes() []byte {
	b, _ := cbor.Encode(a.toValue())
	return b
}

// ContentID returns the authorization's content id (T1 framing).
func (a HazardAuthorization) ContentID() ([]byte, error) {
	return cbor.ContentID(a.toValue())
}

// HazardAuthorizationFromValue parses a naalp-hazard-authorization body.
func HazardAuthorizationFromValue(v cbor.Value) (HazardAuthorization, error) {
	class, envelope, err := hazardBodyFromValue(v)
	if err != nil {
		return HazardAuthorization{}, err
	}
	return HazardAuthorization{Class: class, Envelope: envelope}, nil
}

// ---- F3: grant-coverage authorization -----------------------------------------------------

// HazardAuthorized authorizes a well-formed, present claim against an authorization
// (F3): EXACT class match (not a "<=" ceiling -- see the package doc) AND
// EnvelopeContained. Any single failing dimension denies the WHOLE claim
// (ErrHazardNotCovered) -- there is no partial authorization and no fail-open
// branch.
func HazardAuthorized(claim HazardClaim, grant HazardAuthorization) error {
	if claim.Class != grant.Class {
		return ErrHazardNotCovered
	}
	if !EnvelopeContained(claim.Envelope, grant.Envelope) {
		return ErrHazardNotCovered
	}
	return nil
}

// HazardAuthorizedOptional authorizes an OPTIONAL claim (F2's "absent" case at the
// object level, distinct from a present-but-unrecognized class byte inside a
// claim). A nil claim -- no hazard-claim object exists at all for an action that
// requires one -- denies immediately (ErrHazardUnknown) rather than fabricating a
// sentinel envelope and running the ordinary coverage check: there is no envelope
// to check containment against, so the honest outcome is a distinct error, not a
// coverage denial that implies an envelope was compared.
func HazardAuthorizedOptional(claim *HazardClaim, grant HazardAuthorization) error {
	if claim == nil {
		return ErrHazardUnknown
	}
	return HazardAuthorized(*claim, grant)
}
