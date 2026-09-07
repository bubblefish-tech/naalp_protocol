// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Migration path for a mixed-mode endpoint (Requirement 11 AC3): register an endpoint
// as mixed-mode, then tighten to strict-only, with a Deprecation/Sunset signal on the
// legacy path in between.
//
// The two header fields are two different IETF documents, cited precisely rather than
// both lumped under "RFC 8594" (B10 -- no rounding up a citation), verified against the
// RFC Editor text this session (E8):
//   - Sunset (RFC 8594 Sec.3): an HTTP-date value, IMF-fixdate per RFC 7231 Sec.7.1.1.1,
//     e.g. "Sat, 31 Dec 2018 23:59:59 GMT" -- exactly Go's net/http.TimeFormat layout.
//   - Deprecation (RFC 9745 Sec.2): a Structured-Field-Headers (RFC 9651) Item whose
//     value is a Date (RFC 9651 Sec.3.3.7), serialized as "@" followed by a Unix
//     timestamp, e.g. "Deprecation: @1688169599".
package mixedmode

import (
	"fmt"
	"net/http"
	"time"
)

// Stage is a migration endpoint's current tightening stage (AC3).
type Stage int

const (
	// StageMixed is the starting stage AC3 names ("register an endpoint as
	// mixed-mode"): legacy is accepted, no deprecation signal has been emitted yet.
	// It is the zero value, so a zero-value Migration starts here.
	StageMixed Stage = iota
	// StageDeprecated: legacy is still accepted, but every legacy-origin response
	// MUST carry the Deprecation/Sunset headers (DeprecationHeaders below).
	StageDeprecated
	// StageStrict: legacy is refused outright ("tighten to strict-only").
	StageStrict
)

// String names the stage.
func (s Stage) String() string {
	switch s {
	case StageMixed:
		return "mixed"
	case StageDeprecated:
		return "deprecated"
	case StageStrict:
		return "strict"
	default:
		return "unknown"
	}
}

// Migration tracks one endpoint's staged tightening from mixed-mode to strict-only
// (AC3: "register an endpoint as mixed-mode, then tighten to strict-only ... with a
// Deprecation/Sunset signal on the legacy path"). The zero value starts at StageMixed.
// Advance is monotonic and cannot be re-triggered or skipped: Deprecate is valid only
// from StageMixed, and -- the property this package's own mutation-tested capability
// enforces -- Tighten is valid ONLY from StageDeprecated, so an endpoint can never
// jump straight from accepting undeclared legacy traffic to refusing it without ever
// having emitted the Deprecation/Sunset signal callers were told to expect.
type Migration struct {
	// Clock returns the wall clock; time.Now if nil. Exposed for deterministic
	// tests, matching the Bridge.Clock convention in the sibling react package.
	Clock func() time.Time

	stage        Stage
	deprecatedAt time.Time
	sunset       time.Time
}

// Stage returns the current migration stage.
func (m *Migration) Stage() Stage { return m.stage }

// now returns m.Clock() if set, else the real wall clock.
func (m *Migration) now() time.Time {
	if m.Clock != nil {
		return m.Clock()
	}
	return time.Now()
}

// Deprecate advances StageMixed -> StageDeprecated and records the RFC 8594 Sunset
// instant -- the point in time after which the legacy path will stop being served.
// It is valid ONLY from StageMixed (returns InvalidMigrationTransition, unchanged
// otherwise) -- monotonic, no re-triggering.
func (m *Migration) Deprecate(sunset time.Time) error {
	if m.stage != StageMixed {
		return &Error{"InvalidMigrationTransition", "Deprecate is only valid from StageMixed, got " + m.stage.String()}
	}
	m.deprecatedAt = m.now()
	m.sunset = sunset
	m.stage = StageDeprecated
	return nil
}

// Tighten advances StageDeprecated -> StageStrict (AC3's endpoint: "tighten to
// strict-only"). It is valid ONLY from StageDeprecated -- an endpoint MUST pass
// through the deprecation signal before legacy is refused outright; there is no
// overnight cutover that skips telling legacy callers first.
func (m *Migration) Tighten() error {
	if m.stage != StageDeprecated {
		return &Error{"InvalidMigrationTransition", "Tighten is only valid from StageDeprecated, got " + m.stage.String()}
	}
	m.stage = StageStrict
	return nil
}

// AllowLegacy reports whether an Endpoint at this migration stage should still
// accept the legacy fallback (Mixed/Deprecated: yes; Strict: no) -- the value a
// caller assigns to Endpoint.AllowLegacy as the migration advances.
func (m *Migration) AllowLegacy() bool { return m.stage != StageStrict }

// DeprecationHeaders returns the two HTTP response headers a Deprecated-stage
// endpoint attaches to every legacy-origin response: Deprecation (RFC 9745 Sec.2,
// "@<unix-seconds>" of when deprecation began) and Sunset (RFC 8594 Sec.3, the
// IMF-fixdate instant legacy stops being served). It returns (nil, false) outside
// StageDeprecated -- a Mixed-stage endpoint carries no deprecation signal yet, and a
// Strict-stage endpoint no longer serves the legacy path at all, so neither header
// applies.
func (m *Migration) DeprecationHeaders() (map[string]string, bool) {
	if m.stage != StageDeprecated {
		return nil, false
	}
	return map[string]string{
		"Deprecation": fmt.Sprintf("@%d", m.deprecatedAt.Unix()),
		"Sunset":      m.sunset.UTC().Format(http.TimeFormat),
	}, true
}
