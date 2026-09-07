// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package naalpgnap

import (
	"crypto/sha512"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// GNAPCoveredComponentsBase are the covered-component identifiers RFC 9635 §7.3.1 requires
// an "httpsig" (RFC 9421) proof to cover unconditionally: the HTTP method and the full
// request target. "content-digest" and "authorization" are added conditionally — see
// RequiredComponents.
var GNAPCoveredComponentsBase = []string{"@method", "@target-uri"}

// RequiredComponents returns the RFC 9635 §7.3.1 covered-component set for a request that
// does/does not carry a body and does/does not carry an Authorization header: always
// @method + @target-uri, plus content-digest when hasBody, plus authorization when
// hasAuthorization (a continuation request authenticated with the continuation bearer
// token, RFC 9635 §5, is the case that needs the latter).
func RequiredComponents(hasBody, hasAuthorization bool) []string {
	c := append([]string(nil), GNAPCoveredComponentsBase...)
	if hasBody {
		c = append(c, "content-digest")
	}
	if hasAuthorization {
		c = append(c, "authorization")
	}
	return c
}

// SignatureParams is the RFC 9421 §2.3 signature-parameters set: Created/Expires are Unix
// seconds (0 = omitted), KeyID/Alg/Tag/Nonce are optional string parameters.
type SignatureParams struct {
	Created int64
	Expires int64
	Nonce   string
	Alg     string
	KeyID   string
	Tag     string
}

// sfString serializes s as an RFC 8941 §4.1.6 sf-string: double-quoted, with '\' and '"'
// backslash-escaped. RFC 9421 component identifiers and string signature-parameter values
// are both sf-strings.
func sfString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// serializeParams serializes SignatureParams as the semicolon-prefixed parameter list that
// follows the covered-component inner list in both the "@signature-params" line (RFC 9421
// §2.3) and the Signature-Input header value: a fixed, deterministic order (created,
// expires, nonce, alg, keyid, tag) so a signer and a verifier of this package always agree
// on the exact signature-base bytes for the same logical parameters, regardless of the
// order fields were set in.
func serializeParams(p SignatureParams) string {
	var b strings.Builder
	if p.Created != 0 {
		b.WriteString(";created=")
		b.WriteString(strconv.FormatInt(p.Created, 10))
	}
	if p.Expires != 0 {
		b.WriteString(";expires=")
		b.WriteString(strconv.FormatInt(p.Expires, 10))
	}
	if p.Nonce != "" {
		b.WriteString(";nonce=")
		b.WriteString(sfString(p.Nonce))
	}
	if p.Alg != "" {
		b.WriteString(";alg=")
		b.WriteString(sfString(p.Alg))
	}
	if p.KeyID != "" {
		b.WriteString(";keyid=")
		b.WriteString(sfString(p.KeyID))
	}
	if p.Tag != "" {
		b.WriteString(";tag=")
		b.WriteString(sfString(p.Tag))
	}
	return b.String()
}

// serializeComponentList serializes an ordered list of covered-component identifiers as
// the RFC 8941 §3.1.1 Inner List of sf-strings: `("a" "b" ...)`.
func serializeComponentList(components []string) string {
	parts := make([]string, len(components))
	for i, c := range components {
		parts[i] = sfString(c)
	}
	return "(" + strings.Join(parts, " ") + ")"
}

// BuildSignatureBase constructs the RFC 9421 §2.5 signature base: one line per covered
// component (`"<component-id>": <value>`), in the caller's given order, followed by the
// final "@signature-params" line binding the exact ordered component list and parameters
// used. `values` MUST carry an entry (possibly an empty string) for every name in
// `components`; a missing entry is ErrUnknownComponent — signing/verifying over a
// silently-absent component would be worse than refusing (fail-closed).
func BuildSignatureBase(components []string, values map[string]string, params SignatureParams) ([]byte, error) {
	var b strings.Builder
	for _, c := range components {
		v, ok := values[c]
		if !ok {
			return nil, ErrUnknownComponent
		}
		b.WriteString(sfString(c))
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	b.WriteString(sfString("@signature-params"))
	b.WriteString(": ")
	b.WriteString(serializeComponentList(components))
	b.WriteString(serializeParams(params))
	return []byte(b.String()), nil
}

// AlgTag maps a cose.Signer/Verifier algorithm id to the RFC 9421 `alg` signature-parameter
// tag this bridge carries for local self-description. These three tags are NOT (as of this
// session) confirmed as registered values in IETF's "HTTP Signature Algorithms" registry —
// see doc.go's honest-gaps note. Verify never consults this string; the actual algorithm
// used is whatever the caller's cose.Verifier implements.
func AlgTag(alg int) (string, error) {
	switch alg {
	case cose.AlgMLDSA65:
		return "ml-dsa-65", nil
	case cose.AlgMLDSA87:
		return "ml-dsa-87", nil
	case cose.AlgEd25519:
		return "ed25519", nil
	default:
		return "", ErrUnknownAlg
	}
}

// ContentDigest computes an RFC 9530 "Content-Digest" header value over body using SHA-512
// (the Dictionary-of-byte-sequence form `sha-512=:<base64>:` — sha-512 chosen for
// consistency with this tree's existing SHA-384/512 use, e.g. impl/go/cose.go,
// impl/go/delegation.go).
func ContentDigest(body []byte) string {
	sum := sha512.Sum512(body)
	return "sha-512=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// Sign produces an RFC 9421 HTTP message signature over the given covered
// components/values using signer's Sign (the agent's existing N-AALP signer-id keypair,
// cose.Signer — no new key type is introduced by this package). It returns the raw
// signature-base bytes (useful for a caller building Signature-Input/Signature headers, or
// for logging/debugging) and the raw signature value.
func Sign(signer cose.Signer, components []string, values map[string]string, params SignatureParams) (sigBase, sig []byte, err error) {
	base, err := BuildSignatureBase(components, values, params)
	if err != nil {
		return nil, nil, err
	}
	sig, err = signer.Sign(base)
	if err != nil {
		return nil, nil, err
	}
	return base, sig, nil
}

// Verify recomputes the signature base from components/values/params and checks sig under
// verifier. It is FAIL-CLOSED: any base-construction error or signature mismatch returns a
// non-nil error and the caller MUST treat the request as unauthenticated — there is no
// partial-credit and no fail-open path.
func Verify(verifier cose.Verifier, components []string, values map[string]string, params SignatureParams, sig []byte) error {
	base, err := BuildSignatureBase(components, values, params)
	if err != nil {
		return err
	}
	if !verifier.VerifyRaw(base, sig) {
		return ErrKeyProofMismatch
	}
	return nil
}

// BuildSignatureInputHeader builds the "Signature-Input" header value (RFC 9421 §4.1): a
// Dictionary member `label` mapping to the same ordered component Inner List and
// parameters used to compute the signature base's "@signature-params" line.
func BuildSignatureInputHeader(label string, components []string, params SignatureParams) string {
	return label + "=" + serializeComponentList(components) + serializeParams(params)
}

// BuildSignatureHeader builds the "Signature" header value (RFC 9421 §4.2): a Dictionary
// member `label` mapping to the raw signature bytes as an RFC 8941 §4.1.7 sf-binary
// (base64, colon-delimited).
func BuildSignatureHeader(label string, sig []byte) string {
	return label + "=:" + base64.StdEncoding.EncodeToString(sig) + ":"
}
