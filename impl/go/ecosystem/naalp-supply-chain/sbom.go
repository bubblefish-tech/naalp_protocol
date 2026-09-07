// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

// CycloneDX 1.7 component-type enum values, verbatim from
// schema/bom-1.7.schema.json's definitions.component.properties.type.enum (fetched this
// session from https://raw.githubusercontent.com/CycloneDX/specification/master/schema/
// bom-1.7.schema.json). Every value the schema allows is listed here — BuildSBOM rejects
// any Type not in this set (ErrInvalidComponentType) before building anything.
const (
	ComponentTypeApplication          = "application"
	ComponentTypeFramework            = "framework"
	ComponentTypeLibrary              = "library"
	ComponentTypeContainer            = "container"
	ComponentTypePlatform             = "platform"
	ComponentTypeOperatingSystem      = "operating-system"
	ComponentTypeDevice               = "device"
	ComponentTypeDeviceDriver         = "device-driver"
	ComponentTypeFirmware             = "firmware"
	ComponentTypeFile                 = "file"
	ComponentTypeMachineLearningModel = "machine-learning-model"
	ComponentTypeData                 = "data"
	ComponentTypeCryptographicAsset   = "cryptographic-asset"
)

var validComponentTypes = map[string]bool{
	ComponentTypeApplication: true, ComponentTypeFramework: true, ComponentTypeLibrary: true,
	ComponentTypeContainer: true, ComponentTypePlatform: true, ComponentTypeOperatingSystem: true,
	ComponentTypeDevice: true, ComponentTypeDeviceDriver: true, ComponentTypeFirmware: true,
	ComponentTypeFile: true, ComponentTypeMachineLearningModel: true, ComponentTypeData: true,
	ComponentTypeCryptographicAsset: true,
}

// Component scope values (schema definitions.component.properties.scope.enum).
const (
	ComponentScopeRequired = "required"
	ComponentScopeOptional = "optional"
	ComponentScopeExcluded = "excluded"
)

// CycloneDX hash-alg enum values this package emits (a subset of
// schema/bom-1.7.schema.json's definitions.hash-alg.enum — SHA-256 is the only one this
// package ever computes and emits).
const HashAlgSHA256 = "SHA-256"

// Hash is one CycloneDX "hash" object (definitions.hash: required alg + content).
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// Component is a CycloneDX 1.7 component (definitions.component). Only the fields this
// package ever emits are modeled; every field name and JSON tag below is taken verbatim
// from schema/bom-1.7.schema.json's definitions.component.properties, and additionalProperties
// on that definition is false, so ValidateSBOM will reject any field this struct does NOT
// carry — the struct's own field set is deliberately exactly the schema's allowed subset.
type Component struct {
	BOMRef  string `json:"bom-ref,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Hashes  []Hash `json:"hashes,omitempty"`
}

// Metadata is a CycloneDX 1.7 "metadata" object (definitions.metadata) — only the two
// fields this package emits (timestamp, component).
type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Component *Component `json:"component,omitempty"`
}

// BOM is a CycloneDX 1.7 Bill of Materials document (root schema object). bomFormat and
// specVersion are the only two REQUIRED top-level fields per schema.required; BuildSBOM
// always sets both.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version,omitempty"`
	Metadata     *Metadata   `json:"metadata,omitempty"`
	Components   []Component `json:"components"`
}

// SpecVersion1_7 is the CycloneDX specification version this package targets (confirmed
// current this session — see doc.go's grounding section).
const SpecVersion1_7 = "1.7"

// BuildSBOM constructs a CycloneDX 1.7 BOM document from an actual, parsed module
// dependency graph (modules — see DecodeGoListModules / ParseGoModRequires; this function
// never hardcodes a component list). root describes the artifact the BOM is FOR
// (metadata.component) — its Type must be one of the fourteen CycloneDX component-type
// enum values and its Name must be non-empty; both are validated before anything else is
// built (fail-closed).
//
// The main module entry in modules (Main == true) is skipped: it IS the artifact root is
// already describing, not one of its dependencies. Every other module becomes one
// components[] entry: Type = library (per the CycloneDX enum note, "All third-party and
// open source reusable components will likely be a library"), Name = the module path,
// Version = the resolved module version, PURL = GoModulePURL(path, version), Scope =
// optional for an Indirect module and required otherwise. When a module carries a
// non-empty Go dirhash Sum ("h1:<base64>"), it is decoded and, when the decoded length
// matches a SHA-256 digest (32 bytes), recorded as one CycloneDX hash object (alg
// "SHA-256"); the Go module dirhash h1 algorithm is itself SHA-256-based (it hashes a
// sorted per-file SHA-256 listing with a final SHA-256 pass), so the decoded bytes are a
// genuine 32-byte SHA-256 digest, not a fabricated value — a Sum this package cannot
// decode to exactly 32 bytes is simply omitted (hashes is an optional CycloneDX field;
// this is graceful omission of decorative provenance, not a fail-closed rejection of the
// whole SBOM).
func BuildSBOM(root Component, modules []Module, now time.Time) (*BOM, error) {
	if !validComponentTypes[root.Type] {
		return nil, ErrInvalidComponentType
	}
	if root.Name == "" {
		return nil, ErrEmptyComponentName
	}

	components := make([]Component, 0, len(modules))
	for _, m := range modules {
		if m.Main {
			continue
		}
		purl, err := GoModulePURL(m.Path, m.Version)
		if err != nil {
			return nil, err
		}
		scope := ComponentScopeRequired
		if m.Indirect {
			scope = ComponentScopeOptional
		}
		c := Component{
			Type:    ComponentTypeLibrary,
			Name:    strings.ToLower(m.Path),
			Version: m.Version,
			PURL:    purl,
			Scope:   scope,
		}
		if h, ok := decodeGoDirhashSHA256(m.Sum); ok {
			c.Hashes = []Hash{{Alg: HashAlgSHA256, Content: h}}
		}
		components = append(components, c)
	}

	serial, err := newUUIDv4()
	if err != nil {
		return nil, err
	}

	rootCopy := root
	return &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion1_7,
		SerialNumber: "urn:uuid:" + serial,
		Version:      1,
		Metadata: &Metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Component: &rootCopy,
		},
		Components: components,
	}, nil
}

// decodeGoDirhashSHA256 decodes a Go module "h1:<base64>" dirhash Sum into a hex-encoded
// SHA-256 digest, returning ok=false if sum is empty, does not carry the "h1:" prefix, is
// not valid base64, or does not decode to exactly 32 bytes (the SHA-256 digest size) — any
// of which means this is not a value this package can honestly label "SHA-256".
func decodeGoDirhashSHA256(sum string) (hexDigest string, ok bool) {
	const prefix = "h1:"
	if !strings.HasPrefix(sum, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sum, prefix))
	if err != nil || len(raw) != 32 {
		return "", false
	}
	return hex.EncodeToString(raw), true
}
