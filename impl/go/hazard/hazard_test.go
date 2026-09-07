// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package hazard_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/hazard"
)

// vectorPath is the shared, from-scratch, independent oracle (tools/hazard_oracle.py)
// that grades both impl/rust/naalp-hazard and this port -- NEVER produced by the code
// under test (the non-circular-oracle rule, CLAUDE.md).
const vectorPath = "../../../vectors/hazard/cases.json"

// ---- corpus shapes ------------------------------------------------------------------------

type fromCodeVec struct {
	Code      json.RawMessage `json:"code"`
	Class     uint8           `json:"class"`
	ClassName string          `json:"class_name"`
}

type bodyVec struct {
	Name          string     `json:"name"`
	Class         uint64     `json:"class"`
	ClassName     string     `json:"class_name"`
	Frame         string     `json:"frame"`
	Axes          [][2]int64 `json:"axes"`
	SpeedBoundMmS uint64     `json:"speed_bound_mm_s"`
	NotBefore     uint64     `json:"not_before"`
	NotAfter      uint64     `json:"not_after"`
	BodyHex       string     `json:"body_hex"`
	ContentIDHex  string     `json:"content_id_hex"`
}

type envVec struct {
	Frame         string     `json:"frame"`
	Axes          [][2]int64 `json:"axes"`
	SpeedBoundMmS uint64     `json:"speed_bound_mm_s"`
	NotBefore     uint64     `json:"not_before"`
	NotAfter      uint64     `json:"not_after"`
}

type coverageVec struct {
	Name           string          `json:"name"`
	ClaimClassCode json.RawMessage `json:"claim_class_code"`
	GrantClassCode json.RawMessage `json:"grant_class_code"`
	ClaimEnvelope  envVec          `json:"claim_envelope"`
	GrantEnvelope  envVec          `json:"grant_envelope"`
	Authorized     bool            `json:"authorized"`
}

type corpus struct {
	FromCode []fromCodeVec `json:"from_code"`
	Bodies   []bodyVec     `json:"bodies"`
	Coverage []coverageVec `json:"coverage"`
}

func load(t *testing.T) corpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read hazard corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse hazard corpus: %v", err)
	}
	return c
}

// decodeCode turns a raw "code"/"*_class_code" JSON field into the *uint64 the
// HazardClassFromCode entry point expects: JSON null -> nil; a JSON number that
// fits u64 -> its value; a JSON string (the corpus's own convention for a 64-bit
// value that would silently lose precision as a bare JSON number, e.g. 2^63) or any
// other non-numeric encoding -> nil, matching serde_json's Value::as_u64() (which
// the Rust reference test uses) returning None for a string. Both the nil and the
// out-of-range-number branches converge on HazardClassMotionInSharedSpace, so the
// exact convention makes no behavioural difference -- it only has to be honest about
// what was actually decoded.
func decodeCode(raw json.RawMessage) *uint64 {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil
	}
	if strings.HasPrefix(s, "\"") {
		return nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func env(v envVec) hazard.HazardEnvelope {
	return hazard.HazardEnvelope{
		Spatial:       hazard.SpatialBounds{Frame: v.Frame, Axes: v.Axes},
		SpeedBoundMmS: v.SpeedBoundMmS,
		Window:        hazard.HazardWindow{NotBefore: v.NotBefore, NotAfter: v.NotAfter},
	}
}

// ---- F2: fail-closed class decode (mutation anchor: a constant HazardClassNone
// return would pass none of the non-zero cases; a constant
// HazardClassMotionInSharedSpace would fail the exact 0..3 cases). -------------------------
func TestHazardKat_FromCodeFailClosedMatchesOracle(t *testing.T) {
	c := load(t)
	for _, row := range c.FromCode {
		input := decodeCode(row.Code)
		got := hazard.HazardClassFromCode(input).Code()
		if got != row.Class {
			t.Errorf("HazardClassFromCode(%v) = %d, want %d (%s)", input, got, row.Class, row.ClassName)
		}
	}
	// Explicit oracle-independent assertions of the two named fail-closed cases (F2).
	if got := hazard.HazardClassFromCode(nil); got != hazard.HazardClassMotionInSharedSpace {
		t.Errorf("absent must normalize to the highest class, got %d", got.Code())
	}
	nine := uint64(9)
	if got := hazard.HazardClassFromCode(&nine); got != hazard.HazardClassMotionInSharedSpace {
		t.Errorf("unknown code must normalize to the highest class, got %d", got.Code())
	}
	huge := ^uint64(0)
	if got := hazard.HazardClassFromCode(&huge); got != hazard.HazardClassMotionInSharedSpace {
		t.Errorf("an out-of-range code must still normalize, not panic or wrap, got %d", got.Code())
	}
	// The five in-range codes decode to themselves, never collapsing to the default.
	for code := uint64(0); code <= 4; code++ {
		c := code
		if got := uint64(hazard.HazardClassFromCode(&c).Code()); got != code {
			t.Errorf("HazardClassFromCode(%d).Code() = %d, want %d", code, got, code)
		}
	}
}

// ---- byte-level: encode matches the independent oracle (Go == Rust once both
// build against the same vectors/hazard/cases.json). ----------------------------------------
func TestHazardKat_ClaimAndAuthorizationBytesMatchOracle(t *testing.T) {
	c := load(t)
	for _, row := range c.Bodies {
		code := row.Class
		class := hazard.HazardClassFromCode(&code)
		e := env(envVec{Frame: row.Frame, Axes: row.Axes, SpeedBoundMmS: row.SpeedBoundMmS,
			NotBefore: row.NotBefore, NotAfter: row.NotAfter})
		claim := hazard.HazardClaim{Class: class, Envelope: e}
		auth := hazard.HazardAuthorization{Class: class, Envelope: e}
		if got := hex.EncodeToString(claim.Bytes()); got != row.BodyHex {
			t.Errorf("claim %s bytes = %s, want %s", row.Name, got, row.BodyHex)
		}
		if got := hex.EncodeToString(auth.Bytes()); got != row.BodyHex {
			t.Errorf("authorization %s (same shape as claim) bytes = %s, want %s", row.Name, got, row.BodyHex)
		}
		cid, err := claim.ContentID()
		if err != nil {
			t.Fatalf("%s content-id: %v", row.Name, err)
		}
		if got := hex.EncodeToString(cid); got != row.ContentIDHex {
			t.Errorf("claim %s content-id = %s, want %s", row.Name, got, row.ContentIDHex)
		}
	}
}

// Round-trip: HazardClaimFromValue(claim.toValue()) == claim for every oracle body.
func TestHazardKat_RoundTripMatchesOracle(t *testing.T) {
	c := load(t)
	for _, row := range c.Bodies {
		code := row.Class
		class := hazard.HazardClassFromCode(&code)
		e := env(envVec{Frame: row.Frame, Axes: row.Axes, SpeedBoundMmS: row.SpeedBoundMmS,
			NotBefore: row.NotBefore, NotAfter: row.NotAfter})
		claim := hazard.HazardClaim{Class: class, Envelope: e}
		v, err := cbor.Decode(claim.Bytes())
		if err != nil {
			t.Fatalf("%s: decode: %v", row.Name, err)
		}
		got, err := hazard.HazardClaimFromValue(v)
		if err != nil {
			t.Fatalf("%s: HazardClaimFromValue: %v", row.Name, err)
		}
		if !reflect.DeepEqual(got, claim) {
			t.Errorf("round-trip %s: got %+v, want %+v", row.Name, got, claim)
		}
	}
}

// ---- F3: coverage matrix (mutation anchor: a constant nil return fails the deny
// rows; a constant ErrHazardNotCovered return fails the allow rows) --------------------------
func TestHazardKat_CoverageMatchesOracle(t *testing.T) {
	c := load(t)
	if len(c.Coverage) == 0 {
		t.Fatal("coverage matrix must not be empty")
	}
	var allows, denies int
	for _, row := range c.Coverage {
		claim := hazard.HazardClaim{
			Class:    hazard.HazardClassFromCode(decodeCode(row.ClaimClassCode)),
			Envelope: env(row.ClaimEnvelope),
		}
		grant := hazard.HazardAuthorization{
			Class:    hazard.HazardClassFromCode(decodeCode(row.GrantClassCode)),
			Envelope: env(row.GrantEnvelope),
		}
		err := hazard.HazardAuthorized(claim, grant)
		if row.Authorized {
			allows++
			if err != nil {
				t.Errorf("%s: want authorized, got %v", row.Name, err)
			}
		} else {
			denies++
			if err == nil {
				t.Errorf("%s: want denied, got authorized", row.Name)
			} else if err != hazard.ErrHazardNotCovered {
				t.Errorf("%s: want ErrHazardNotCovered, got %v", row.Name, err)
			}
		}
	}
	if allows == 0 || denies == 0 {
		t.Fatal("matrix needs both allows and denies")
	}
}

// F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at
// all): distinct from an in-range-but-mismatched class, and distinct from an
// unrecognized class byte inside a present claim (covered by
// TestHazardKat_CoverageMatchesOracle's normalized rows).
func TestHazardKat_AbsentClaimDeniesWithDistinctError(t *testing.T) {
	grant := hazard.HazardAuthorization{
		Class: hazard.HazardClassToolActuation,
		Envelope: env(envVec{Frame: "cell-7/world", Axes: [][2]int64{{0, 1000}, {0, 1000}, {0, 500}},
			SpeedBoundMmS: 500, NotBefore: 0, NotAfter: 1000}),
	}
	if err := hazard.HazardAuthorizedOptional(nil, grant); err != hazard.ErrHazardUnknown {
		t.Errorf("an absent claim must deny with ErrHazardUnknown, got %v", err)
	}
	// A present, well-covered claim still authorizes through the same entry point.
	claim := hazard.HazardClaim{
		Class: hazard.HazardClassToolActuation,
		Envelope: env(envVec{Frame: "cell-7/world", Axes: [][2]int64{{100, 200}, {100, 200}, {0, 100}},
			SpeedBoundMmS: 100, NotBefore: 10, NotAfter: 900}),
	}
	if err := hazard.HazardAuthorizedOptional(&claim, grant); err != nil {
		t.Errorf("a covered present claim must authorize, got %v", err)
	}
}

// ---- structural malformation (fail-closed, never partially valid) -------------------------
func TestHazardKat_MalformedBodiesRejected(t *testing.T) {
	// empty axes
	bad := hazard.SpatialBounds{Frame: "f", Axes: nil}
	if bad.IsWellFormed() {
		t.Fatal("empty axes must not be well-formed")
	}
	if _, err := hazard.SpatialBoundsFromValue(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr("f")},
		{K: cbor.Uint(2), V: cbor.Arr{}},
	}); err != hazard.ErrHazardMalformed {
		t.Errorf("empty axes: want ErrHazardMalformed, got %v", err)
	}

	// min > max
	bad2 := hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{10, -10}}}
	if bad2.IsWellFormed() {
		t.Fatal("min > max must not be well-formed")
	}

	// non-NFC frame ('e' + combining acute, NFD not NFC)
	bad3 := hazard.SpatialBounds{Frame: "é", Axes: [][2]int64{{0, 1}}}
	if bad3.IsWellFormed() {
		t.Fatal("non-NFC frame must not be well-formed")
	}

	// wrong shape entirely (not a map)
	if _, err := hazard.HazardClaimFromValue(cbor.Uint(0)); err != hazard.ErrHazardMalformed {
		t.Errorf("non-map body: want ErrHazardMalformed, got %v", err)
	}

	// class present, envelope missing
	partial := cbor.Map{{K: cbor.Uint(1), V: cbor.Uint(1)}}
	if _, err := hazard.HazardClaimFromValue(partial); err != hazard.ErrHazardMalformed {
		t.Errorf("missing envelope: want ErrHazardMalformed, got %v", err)
	}

	// an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not
	// silently normalized -- see hazardBodyFromValue's doc comment.
	goodEnv := hazard.HazardEnvelope{
		Spatial:       hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{0, 1}}},
		SpeedBoundMmS: 1,
		Window:        hazard.HazardWindow{NotBefore: 0, NotAfter: 1},
	}
	outOfRange := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(99)},
		{K: cbor.Uint(2), V: mustEnvValue(t, goodEnv)},
	}
	if _, err := hazard.HazardClaimFromValue(outOfRange); err != hazard.ErrHazardMalformed {
		t.Errorf("out-of-range wire class: want ErrHazardMalformed, got %v", err)
	}
}

// mustEnvValue round-trips a HazardEnvelope through its own encoder/decoder to
// obtain a cbor.Value usable as a map entry in a hand-built body (HazardEnvelope's
// internal toValue is unexported; Bytes()+cbor.Decode is the package's own public
// path to the same Value).
func mustEnvValue(t *testing.T, e hazard.HazardEnvelope) cbor.Value {
	t.Helper()
	v, err := cbor.Decode(e.Bytes())
	if err != nil {
		t.Fatalf("decode envelope fixture: %v", err)
	}
	return v
}

// ---- containment truth table (independent of the oracle file, direct assertions) ----------
func TestHazardKat_SpatialContainedTruthTable(t *testing.T) {
	grant := hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{0, 100}, {0, 100}}}
	// fully inside -> contained
	inside := hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{10, 90}, {10, 90}}}
	if !hazard.SpatialContained(inside, grant) {
		t.Error("fully-inside axes must be contained")
	}
	// equal bounds -> contained (closed interval)
	equal := hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{0, 100}, {0, 100}}}
	if !hazard.SpatialContained(equal, grant) {
		t.Error("equal bounds must be contained (closed interval)")
	}
	// one axis pokes outside -> not contained
	outside := hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{10, 90}, {10, 101}}}
	if hazard.SpatialContained(outside, grant) {
		t.Error("an axis poking outside must not be contained")
	}
	// different frame -> never contained regardless of numeric bounds
	wrongFrame := hazard.SpatialBounds{Frame: "g", Axes: [][2]int64{{10, 90}, {10, 90}}}
	if hazard.SpatialContained(wrongFrame, grant) {
		t.Error("a different frame must never be contained")
	}
	// fewer axes -> never contained
	fewer := hazard.SpatialBounds{Frame: "f", Axes: [][2]int64{{10, 90}}}
	if hazard.SpatialContained(fewer, grant) {
		t.Error("a mismatched axis count must never be contained")
	}
}

func TestHazardKat_EnvelopeContainedWindowAndSpeed(t *testing.T) {
	grant := env(envVec{Frame: "f", Axes: [][2]int64{{0, 100}}, SpeedBoundMmS: 500, NotBefore: 100, NotAfter: 900})
	ok := env(envVec{Frame: "f", Axes: [][2]int64{{0, 100}}, SpeedBoundMmS: 500, NotBefore: 100, NotAfter: 900})
	if !hazard.EnvelopeContained(ok, grant) {
		t.Error("exact edges (closed interval) must be contained")
	}
	speedOver := env(envVec{Frame: "f", Axes: [][2]int64{{0, 100}}, SpeedBoundMmS: 501, NotBefore: 100, NotAfter: 900})
	if hazard.EnvelopeContained(speedOver, grant) {
		t.Error("a speed bound exceeding the grant must not be contained")
	}
	startsEarly := env(envVec{Frame: "f", Axes: [][2]int64{{0, 100}}, SpeedBoundMmS: 500, NotBefore: 99, NotAfter: 900})
	if hazard.EnvelopeContained(startsEarly, grant) {
		t.Error("a window starting before the grant must not be contained")
	}
	endsLate := env(envVec{Frame: "f", Axes: [][2]int64{{0, 100}}, SpeedBoundMmS: 500, NotBefore: 100, NotAfter: 901})
	if hazard.EnvelopeContained(endsLate, grant) {
		t.Error("a window ending after the grant must not be contained")
	}
}
