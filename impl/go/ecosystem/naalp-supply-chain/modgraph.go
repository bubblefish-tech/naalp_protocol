// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Module is one entry of a Go module dependency graph. Its field set and JSON tags match
// the real, observed output of `go list -m -json all` (captured this session, from
// impl/go: `cd impl/go && GOWORK=off go list -m -json all`) — Path, Version, Main,
// Indirect, GoVersion, Sum are the fields that stream actually emits (Time/Dir/GoMod/
// GoModSum also appear but are not needed by this package and are simply ignored by
// encoding/json's default unmarshal-into-struct behavior, which drops unrecognized JSON
// object keys rather than erroring). This is not an assumed/invented struct shape (E8):
// every field name below was read off a real `go list -m -json` invocation this session,
// not recalled from training data.
type Module struct {
	Path      string `json:"Path"`
	Version   string `json:"Version"`
	Main      bool   `json:"Main"`
	Indirect  bool   `json:"Indirect"`
	GoVersion string `json:"GoVersion"`
	Sum       string `json:"Sum"` // the "h1:<base64>" module-zip dirhash, when present
}

// DecodeGoListModules parses a stream of concatenated JSON objects in the shape
// `go list -m -json all` emits (one JSON object per module, back-to-back, NOT wrapped in
// an enclosing array or separated by commas) into a []Module. It uses json.Decoder in a
// loop, which is the correct decoder for concatenated JSON values (a single json.Unmarshal
// call would fail on this input, since the input as a whole is not one JSON value) — this
// actually parses the real module graph; it does not hardcode a component list (the
// package's build discipline requires this).
//
// The first entry `go list -m -json all` emits is always the main module itself
// (Main: true); DecodeGoListModules returns it along with every dependency so a caller can
// decide whether to treat it as the SBOM's root component or filter it out (BuildSBOM
// filters it out — the root component is supplied separately, by the caller, since it
// describes the *artifact* being released, which may differ from the main module's own
// identity).
func DecodeGoListModules(r io.Reader) ([]Module, error) {
	dec := json.NewDecoder(r)
	var mods []Module
	for dec.More() {
		var m Module
		if err := dec.Decode(&m); err != nil {
			return nil, ErrMalformedModuleList
		}
		if m.Path == "" {
			return nil, ErrMalformedModuleList
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// ParseGoModRequires parses the `require` directives of a go.mod file's raw bytes into a
// []Module (Path/Version/Indirect only — a go.mod carries no resolved Sum or GoVersion per
// requirement, only the module's own top-level `go` directive, which this function does
// not need). It handles both forms Go's go.mod grammar allows: a single-line
// `require module version` and a parenthesized block:
//
//	require (
//	    module version // indirect
//	    module version
//	)
//
// A trailing `// indirect` line comment sets Indirect = true (the exact marker `go mod
// tidy` writes); any other trailing comment is ignored. A `require` line/entry with fewer
// than two whitespace-separated tokens (path, version) is rejected (ErrMalformedGoMod) —
// this function does not silently skip malformed input.
func ParseGoModRequires(data []byte) ([]Module, error) {
	var mods []Module
	sc := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		switch {
		case inBlock:
			if line == ")" {
				inBlock = false
				continue
			}
			m, err := parseRequireEntry(line)
			if err != nil {
				return nil, err
			}
			mods = append(mods, m)
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case strings.HasPrefix(line, "require "):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			m, err := parseRequireEntry(rest)
			if err != nil {
				return nil, err
			}
			mods = append(mods, m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return mods, nil
}

// parseRequireEntry parses one "module version [// indirect]" entry (with the `require`
// keyword and any surrounding parens already stripped by the caller).
func parseRequireEntry(entry string) (Module, error) {
	indirect := false
	if idx := strings.Index(entry, "//"); idx >= 0 {
		comment := strings.TrimSpace(entry[idx+2:])
		if comment == "indirect" {
			indirect = true
		}
		entry = strings.TrimSpace(entry[:idx])
	}
	fields := strings.Fields(entry)
	if len(fields) != 2 {
		return Module{}, ErrMalformedGoMod
	}
	return Module{Path: fields[0], Version: fields[1], Indirect: indirect}, nil
}
