// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "strings"

// GoModulePURL builds a Package URL (purl) for a Go module, per the purl-spec "golang"
// type definition (https://raw.githubusercontent.com/package-url/purl-spec/main/types/
// golang-definition.json, fetched this session): type "golang", namespace+name given
// together as the module path, both lowercased ("The namespace shall be lowercased" / "The
// name shall be lowercased" — the definition's own normative notes), version optional and
// appended with "@" when present. Examples from that same definition:
// "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c".
//
// path must not be empty (ErrEmptyModulePath). version may be empty, in which case the
// purl carries no "@version" suffix (the golang-definition.json note: "The version is
// often empty when a commit is not specified").
func GoModulePURL(path, version string) (string, error) {
	if path == "" {
		return "", ErrEmptyModulePath
	}
	lowerPath := strings.ToLower(path)
	purl := "pkg:golang/" + percentEncodePURLComponent(lowerPath)
	if version != "" {
		purl += "@" + percentEncodePURLComponent(version)
	}
	return purl, nil
}

// purlUnreserved is the set of ASCII characters a purl component (namespace/name/version
// segment) never needs to percent-encode: RFC 3986 unreserved characters plus '/', '.',
// '~', '+', '-', and '_', which are the characters that already appear unescaped in the
// purl-spec's own worked examples (module paths carry '.', '/', '-'; semver carries '.',
// '-', '+').
func isPURLSafeByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '/', b == '.', b == '~', b == '+', b == '-', b == '_':
		return true
	default:
		return false
	}
}

// percentEncodePURLComponent percent-encodes any byte not in the safe set. Go module
// paths/versions are almost always entirely composed of safe bytes; this exists so a
// path/version carrying an unusual byte (e.g. a '#', which purl reserves as the subpath
// separator, or a space) still produces a syntactically valid purl instead of an
// ambiguous or invalid one.
func percentEncodePURLComponent(s string) string {
	needsEscape := false
	for i := 0; i < len(s); i++ {
		if !isPURLSafeByte(s[i]) {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s
	}
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isPURLSafeByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}
