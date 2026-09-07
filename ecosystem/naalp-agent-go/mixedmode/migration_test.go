// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package mixedmode

import (
	"strconv"
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestMigration_ZeroValueStartsAtMixed_LegacyAllowed(t *testing.T) {
	var m Migration
	if got := m.Stage(); got != StageMixed {
		t.Fatalf("zero-value Migration stage = %s, want mixed", got)
	}
	if !m.AllowLegacy() {
		t.Fatal("expected AllowLegacy() true at StageMixed")
	}
	if _, ok := m.DeprecationHeaders(); ok {
		t.Fatal("expected no deprecation headers at StageMixed")
	}
}

func TestMigration_Deprecate_AdvancesStageAndKeepsLegacyAllowed(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	sunset := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	m := Migration{Clock: fixedClock(now)}

	if err := m.Deprecate(sunset); err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	if got := m.Stage(); got != StageDeprecated {
		t.Fatalf("stage after Deprecate = %s, want deprecated", got)
	}
	if !m.AllowLegacy() {
		t.Fatal("expected AllowLegacy() still true at StageDeprecated")
	}

	headers, ok := m.DeprecationHeaders()
	if !ok {
		t.Fatal("expected deprecation headers at StageDeprecated")
	}
	if want := "@" + strconv.FormatInt(now.Unix(), 10); headers["Deprecation"] != want {
		t.Fatalf("Deprecation header = %q, want %q (RFC 9745 Sec.2 Date item)", headers["Deprecation"], want)
	}
	if want := "Thu, 31 Dec 2026 23:59:59 GMT"; headers["Sunset"] != want {
		t.Fatalf("Sunset header = %q, want %q (RFC 8594 Sec.3 IMF-fixdate)", headers["Sunset"], want)
	}
}

func TestMigration_Deprecate_FromNonMixed_Refused(t *testing.T) {
	m := Migration{Clock: fixedClock(time.Unix(0, 0))}
	if err := m.Deprecate(time.Unix(1, 0)); err != nil {
		t.Fatalf("first Deprecate: %v", err)
	}
	if err := m.Deprecate(time.Unix(2, 0)); err == nil {
		t.Fatal("expected a second Deprecate call to be refused (monotonic, no re-trigger)")
	}
	if got := m.Stage(); got != StageDeprecated {
		t.Fatalf("stage after refused second Deprecate = %s, want unchanged deprecated", got)
	}
}

// TestMigration_Tighten_CannotSkipDeprecatedStage is this file's CRITICAL AC3 test:
// an endpoint must pass through StageDeprecated (emitting the Deprecation/Sunset
// signal) before it may tighten to strict-only. Calling Tighten directly from the
// zero-value (StageMixed) Migration MUST be refused and MUST NOT move the stage.
func TestMigration_Tighten_CannotSkipDeprecatedStage(t *testing.T) {
	var m Migration
	if err := m.Tighten(); err == nil {
		t.Fatal("expected Tighten from StageMixed to be refused (cannot skip the deprecation signal)")
	}
	if got := m.Stage(); got != StageMixed {
		t.Fatalf("stage after refused Tighten = %s, want unchanged mixed", got)
	}
	if !m.AllowLegacy() {
		t.Fatal("legacy must still be allowed: the refused Tighten must not have taken effect")
	}
}

func TestMigration_Tighten_FromDeprecated_AdvancesToStrict_LegacyRefused(t *testing.T) {
	m := Migration{Clock: fixedClock(time.Unix(0, 0))}
	if err := m.Deprecate(time.Unix(1, 0)); err != nil {
		t.Fatalf("Deprecate: %v", err)
	}
	if err := m.Tighten(); err != nil {
		t.Fatalf("Tighten: %v", err)
	}
	if got := m.Stage(); got != StageStrict {
		t.Fatalf("stage after Tighten = %s, want strict", got)
	}
	if m.AllowLegacy() {
		t.Fatal("expected AllowLegacy() false at StageStrict")
	}
	if _, ok := m.DeprecationHeaders(); ok {
		t.Fatal("expected no deprecation headers at StageStrict (legacy no longer served at all)")
	}
}
