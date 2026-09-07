// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

// Error carries a stable Kind, matching the cose.Error / delegation error convention used
// throughout this tree (impl/go/cose.Error, impl/go/delegation's *cose.Error sentinels),
// so a GNAP-bridge failure is distinguishable and testable the same way every other
// N-AALP error is.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

var (
	// ErrKeyProofMismatch is returned by Verify when the RFC 9421 HTTP Message Signature
	// over a GNAP request does not verify under the presented key — a tampered
	// signature, a tampered covered-component value, or a signature produced by a
	// different key. Fail-closed: the caller MUST treat the request as unauthenticated.
	ErrKeyProofMismatch = &Error{"KeyProofMismatch", "RFC 9421 HTTP message signature does not verify"}

	// ErrAuthorityExport is returned by ExportDelegationEvidence when the caller asked
	// to export more authority (effect or scope) than the underlying, already-verified
	// DelegationGrant leaf actually confers, or names a subject the leaf does not
	// cover. This is the D15 fail-closed, export-only posture (design.md §18.1, §18.3):
	// the bridge NEVER lets an external GNAP AS mint new N-AALP authority.
	ErrAuthorityExport = &Error{"AuthorityExport", "requested export exceeds the DelegationGrant's attenuated ceiling"}

	// ErrMalformedRequest is returned when a Grant Request this package is asked to
	// encode is missing a field it requires to be safely sent (no requested access, or
	// a client key-proofing method other than the one this package implements).
	ErrMalformedRequest = &Error{"MalformedRequest", "GNAP grant request is missing a required field"}

	// ErrMalformedResponse is returned when a GNAP grant/continue response is not
	// well-formed JSON, or is missing a field this bridge requires to proceed safely.
	ErrMalformedResponse = &Error{"MalformedResponse", "GNAP response is not well-formed or is missing a required field"}

	// ErrContinuationMissing is returned when a grant/continuation response's
	// `continue` object (or a field within it this bridge needs to poll/finish) is
	// absent or incomplete.
	ErrContinuationMissing = &Error{"ContinuationMissing", "GNAP continue object is absent or incomplete"}

	// ErrUnknownComponent is returned when a covered-component identifier requested for
	// a signature base has no value supplied — signing/verifying over a silently-absent
	// component would be worse than refusing (fail-closed).
	ErrUnknownComponent = &Error{"UnknownComponent", "no value supplied for a covered signature component"}

	// ErrUnknownAlg mirrors cose.ErrUnknownAlg for the RFC 9421 `alg` signature-parameter
	// tag this bridge derives from a cose.Signer/Verifier's Alg().
	ErrUnknownAlg = &Error{"UnknownAlg", "no RFC 9421 alg tag for this COSE algorithm id"}
)
