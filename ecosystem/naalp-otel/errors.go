// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpotel

import "fmt"

// Error is a named, fail-closed naalp-otel error (E3.1/R5.1). A malformed Outcome input
// (an unresolvable channel/kind pair, or an error code absent from the naalperror
// registry) produces one of these and emits NO span and NO metric -- never a silent empty
// span, per the fail-closed discipline every N-AALP surface follows.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("naalpotel: %s: %s", e.Kind, e.Msg) }

var (
	// ErrUnknownSurface: the (channel, kind) pair does not resolve against the real
	// impl/go/channels.Table -- this package refuses to guess at a span name for a surface
	// it cannot identify.
	ErrUnknownSurface = &Error{Kind: "UnknownSurface", Msg: "channel/kind pair does not resolve in channels.Table"}

	// ErrUnknownErrorCode: Outcome.VerifyErrorCode or ApprovalOutcome.RefusalErrorCode is
	// nonzero but does not resolve via naalperror.NameForCode -- emitting error.type from an
	// unresolvable code would be a fabricated name.
	ErrUnknownErrorCode = &Error{Kind: "UnknownErrorCode", Msg: "error code does not resolve in the naalperror registry"}

	// ErrNilOutcome: EmitOperationSpan was called with a nil *Outcome.
	ErrNilOutcome = &Error{Kind: "NilOutcome", Msg: "Outcome must not be nil"}
)

// wrapf builds an *Error carrying additional detail without inventing a new Kind for every
// call site.
func wrapf(base *Error, format string, args ...any) *Error {
	return &Error{Kind: base.Kind, Msg: base.Msg + ": " + fmt.Sprintf(format, args...)}
}
