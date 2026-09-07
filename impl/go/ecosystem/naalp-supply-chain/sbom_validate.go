// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// cyclonedxSchemaBytes is the real CycloneDX 1.7 JSON Schema, embedded verbatim (no
// hand-editing) from schema/bom-1.7.schema.json — see doc.go's grounding section for the
// exact download URL and fetch date, and jsonschema_test.go for a check that this embedded
// copy still matches the on-disk file's SHA-256 (so a future edit to the schema file
// cannot silently drift from what the compiled binary embeds).
//
//go:embed schema/bom-1.7.schema.json
var cyclonedxSchemaBytes []byte

var (
	cyclonedxSchemaOnce sync.Once
	cyclonedxSchema     *Schema
	cyclonedxSchemaErr  error
)

func loadCycloneDXSchema() (*Schema, error) {
	cyclonedxSchemaOnce.Do(func() {
		cyclonedxSchema, cyclonedxSchemaErr = LoadSchema(cyclonedxSchemaBytes)
	})
	return cyclonedxSchema, cyclonedxSchemaErr
}

// SchemaValidationError wraps every disagreement ValidateSBOM found between a document
// and the vendored CycloneDX 1.7 JSON Schema.
type SchemaValidationError struct {
	Errors []*ValidationError
}

func (e *SchemaValidationError) Error() string {
	parts := make([]string, len(e.Errors))
	for i, ve := range e.Errors {
		parts[i] = ve.Error()
	}
	return fmt.Sprintf("CycloneDX 1.7 schema validation failed (%d error(s)): %s", len(e.Errors), strings.Join(parts, "; "))
}

func (e *SchemaValidationError) Unwrap() error { return ErrSchemaInvalid }

// ValidateSBOM schema-validates bomJSON (the marshaled bytes of a BOM, or any other
// CycloneDX 1.7 document) against the real, vendored CycloneDX 1.7 JSON Schema (an
// independent authority — F3/A7: this is not the code that produced bomJSON asserting its
// own correctness). A schema disagreement is returned as *SchemaValidationError (which
// wraps ErrSchemaInvalid, so errors.Is(err, ErrSchemaInvalid) works); malformed JSON or an
// internal schema-processing failure is returned as a plain error.
func ValidateSBOM(bomJSON []byte) error {
	schema, err := loadCycloneDXSchema()
	if err != nil {
		return fmt.Errorf("loading vendored CycloneDX schema: %w", err)
	}
	errs, err := schema.Validate(bomJSON)
	if err != nil {
		return fmt.Errorf("validating against CycloneDX schema: %w", err)
	}
	if len(errs) > 0 {
		return &SchemaValidationError{Errors: errs}
	}
	return nil
}

// MarshalAndValidateSBOM marshals bom to JSON and validates the result against the
// vendored CycloneDX 1.7 schema in one call, returning the JSON bytes on success.
func MarshalAndValidateSBOM(bom *BOM) ([]byte, error) {
	data, err := json.Marshal(bom)
	if err != nil {
		return nil, err
	}
	if err := ValidateSBOM(data); err != nil {
		return nil, err
	}
	return data, nil
}
