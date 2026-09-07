// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import "testing"

func mustLoadSchema(t *testing.T, src string) *Schema {
	t.Helper()
	s, err := LoadSchema([]byte(src))
	if err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return s
}

func TestSchemaRequiredCatchesMissingField(t *testing.T) {
	s := mustLoadSchema(t, `{
		"type": "object",
		"required": ["name"],
		"properties": {"name": {"type": "string"}}
	}`)
	errs, err := s.Validate([]byte(`{}`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1 (missing required 'name')", len(errs))
	}

	errs, err = s.Validate([]byte(`{"name":"ok"}`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("got %d errors for a valid document, want 0: %v", len(errs), errs)
	}
}

func TestSchemaTypeMismatch(t *testing.T) {
	s := mustLoadSchema(t, `{"type": "string"}`)
	errs, err := s.Validate([]byte(`42`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1 (number is not a string)", len(errs))
	}
}

func TestSchemaIntegerAcceptsWholeNumberFloat(t *testing.T) {
	s := mustLoadSchema(t, `{"type": "integer"}`)
	errs, err := s.Validate([]byte(`3`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("integer 3 should validate as type integer, got %v", errs)
	}
	errs, err = s.Validate([]byte(`3.5`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("3.5 should NOT validate as type integer, got %d errors", len(errs))
	}
}

func TestSchemaEnum(t *testing.T) {
	s := mustLoadSchema(t, `{"enum": ["a", "b", "c"]}`)
	if errs, _ := s.Validate([]byte(`"b"`)); len(errs) != 0 {
		t.Fatalf("\"b\" should be in enum, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`"z"`)); len(errs) != 1 {
		t.Fatalf("\"z\" should NOT be in enum, got %d errors", len(errs))
	}
}

func TestSchemaConst(t *testing.T) {
	s := mustLoadSchema(t, `{"const": "CycloneDX"}`)
	if errs, _ := s.Validate([]byte(`"CycloneDX"`)); len(errs) != 0 {
		t.Fatalf("matching const should validate, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`"SPDX"`)); len(errs) != 1 {
		t.Fatalf("non-matching const should fail, got %d errors", len(errs))
	}
}

func TestSchemaPattern(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"string","pattern":"^[0-9]{3}$"}`)
	if errs, _ := s.Validate([]byte(`"123"`)); len(errs) != 0 {
		t.Fatalf("\"123\" should match pattern, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`"abc"`)); len(errs) != 1 {
		t.Fatalf("\"abc\" should NOT match pattern, got %d errors", len(errs))
	}
}

func TestSchemaMinMaxLength(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"string","minLength":2,"maxLength":4}`)
	cases := map[string]int{"": 1, "a": 1, "ab": 0, "abcd": 0, "abcde": 1}
	for in, wantErrs := range cases {
		errs, err := s.Validate([]byte(`"` + in + `"`))
		if err != nil {
			t.Fatalf("Validate(%q): %v", in, err)
		}
		if len(errs) != wantErrs {
			t.Fatalf("Validate(%q) = %d errors, want %d", in, len(errs), wantErrs)
		}
	}
}

func TestSchemaMinMaxItemsAndUniqueItems(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string"}}`)
	if errs, _ := s.Validate([]byte(`[]`)); len(errs) != 1 {
		t.Fatalf("empty array should fail minItems, got %d errors", len(errs))
	}
	if errs, _ := s.Validate([]byte(`["a","b","c"]`)); len(errs) != 1 {
		t.Fatalf("3-item array should fail maxItems, got %d errors", len(errs))
	}
	if errs, _ := s.Validate([]byte(`["a","a"]`)); len(errs) != 1 {
		t.Fatalf("duplicate items should fail uniqueItems, got %d errors", len(errs))
	}
	if errs, _ := s.Validate([]byte(`["a","b"]`)); len(errs) != 0 {
		t.Fatalf("valid 2-item unique array should pass, got %v", errs)
	}
}

func TestSchemaMinMax(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"number","minimum":1,"maximum":10}`)
	for in, want := range map[string]int{"0": 1, "1": 0, "5": 0, "10": 0, "11": 1} {
		errs, err := s.Validate([]byte(in))
		if err != nil {
			t.Fatalf("Validate(%s): %v", in, err)
		}
		if len(errs) != want {
			t.Fatalf("Validate(%s) = %d errors, want %d", in, len(errs), want)
		}
	}
}

func TestSchemaAdditionalPropertiesFalse(t *testing.T) {
	s := mustLoadSchema(t, `{
		"type":"object",
		"additionalProperties": false,
		"properties": {"a": {"type":"string"}}
	}`)
	if errs, _ := s.Validate([]byte(`{"a":"x"}`)); len(errs) != 0 {
		t.Fatalf("declared property should pass, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`{"a":"x","b":"y"}`)); len(errs) != 1 {
		t.Fatalf("undeclared property 'b' should be rejected, got %d errors", len(errs))
	}
}

func TestSchemaRefResolution(t *testing.T) {
	s := mustLoadSchema(t, `{
		"type": "object",
		"required": ["thing"],
		"properties": {"thing": {"$ref": "#/definitions/named"}},
		"definitions": {
			"named": {"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}
		}
	}`)
	if errs, _ := s.Validate([]byte(`{"thing":{"name":"ok"}}`)); len(errs) != 0 {
		t.Fatalf("valid $ref'd document should pass, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`{"thing":{}}`)); len(errs) != 1 {
		t.Fatalf("missing required field inside a $ref'd schema should fail, got %d errors", len(errs))
	}
}

func TestSchemaOneOf(t *testing.T) {
	s := mustLoadSchema(t, `{"oneOf": [{"type":"string"},{"type":"number"}]}`)
	if errs, _ := s.Validate([]byte(`"x"`)); len(errs) != 0 {
		t.Fatalf("string should satisfy exactly one oneOf branch, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`42`)); len(errs) != 0 {
		t.Fatalf("number should satisfy exactly one oneOf branch, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`true`)); len(errs) != 1 {
		t.Fatalf("boolean matches neither branch, want 1 error, got %d", len(errs))
	}
}

func TestSchemaArrayItemsValidatedRecursively(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"array","items":{"type":"string","minLength":1}}`)
	if errs, _ := s.Validate([]byte(`["a","b"]`)); len(errs) != 0 {
		t.Fatalf("valid array should pass, got %v", errs)
	}
	if errs, _ := s.Validate([]byte(`["a",""]`)); len(errs) != 1 {
		t.Fatalf("array with one invalid element should fail exactly once, got %d errors", len(errs))
	}
}

// TestValidateRejectsMalformedJSON confirms a processing error (not a ValidationError
// slice) is returned for input that is not JSON at all.
func TestValidateRejectsMalformedJSON(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"string"}`)
	_, err := s.Validate([]byte(`{not json`))
	if err == nil {
		t.Fatal("Validate should return a processing error for malformed JSON")
	}
}

// TestSchemaRequiredMutationSurvives is the A4/A5 mutation-surviving test named
// explicitly for jsonschema.go's most load-bearing check: a validator whose "required"
// handling is stubbed out (never appends an error) passes every OTHER test above by
// accident on well-formed documents, but fails this one, which specifically exercises
// only the required-field check on an otherwise schema-conformant document.
func TestSchemaRequiredMutationSurvives(t *testing.T) {
	s := mustLoadSchema(t, `{"type":"object","required":["mustHave"]}`)
	errs, err := s.Validate([]byte(`{"somethingElse": 1}`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want exactly 1 (missing required field), errs=%v", len(errs), errs)
	}
	if errs[0].Msg == "" {
		t.Fatal("ValidationError.Msg must not be empty")
	}
}
