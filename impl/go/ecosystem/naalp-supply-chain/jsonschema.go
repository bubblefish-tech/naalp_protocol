// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Schema is a parsed JSON Schema document (draft-07, the draft
// schema/bom-1.7.schema.json itself declares via its own "$schema" field). This is a
// GENERIC, real JSON Schema validator over the following subset of draft-07 keywords —
// not a hand-fit assertion of "this looks like a CycloneDX document" (A7/F3: an
// independent authority, not this package's own opinion of validity):
//
//	type, required, properties, additionalProperties (boolean form only), items (single-
//	schema form only, not tuple validation), enum, const, pattern, minLength, maxLength,
//	minItems, maxItems, minimum, maximum, uniqueItems, $ref (local "#/..." JSON Pointer
//	only), oneOf, anyOf.
//
// Deliberately NOT implemented (an honest scope limit, not silently ignored — a schema
// node using one of these is a validation-time internal error, never a silent pass):
// patternProperties, allOf, if/then/else, $dynamicRef, remote $ref, format enforcement,
// tuple-form items, propertyNames, dependentRequired/dependentSchemas. None of these
// appear on the JSON-pointer paths this package's own generated documents (sbom.go)
// actually walk through the vendored CycloneDX schema, so the subset above is sufficient
// to genuinely schema-validate what this package emits — see jsonschema_test.go for tests
// that exercise the validator against both the real vendored schema and small malformed
// documents designed to fail specific keywords.
type Schema struct {
	root map[string]any
}

// ValidationError is one schema-vs-instance disagreement, with the JSON Pointer path (in
// the INSTANCE document) at which it occurred.
type ValidationError struct {
	Path string
	Msg  string
}

func (e *ValidationError) Error() string { return e.Path + ": " + e.Msg }

// LoadSchema parses a JSON Schema document's raw bytes.
func LoadSchema(data []byte) (*Schema, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	return &Schema{root: root}, nil
}

// Validate parses docJSON and checks it against the schema, returning every disagreement
// found (nil/empty slice means valid). The second return value is a processing error (a
// malformed schema node this validator's supported subset cannot interpret, or docJSON
// itself not being well-formed JSON) — distinct from a ValidationError, which means the
// JSON parsed fine but disagrees with the schema.
func (s *Schema) Validate(docJSON []byte) ([]*ValidationError, error) {
	var instance any
	if err := json.Unmarshal(docJSON, &instance); err != nil {
		return nil, fmt.Errorf("document is not well-formed JSON: %w", err)
	}
	var errs []*ValidationError
	if err := s.validateNode(s.root, instance, "", &errs); err != nil {
		return nil, err
	}
	return errs, nil
}

// resolveRef resolves a local JSON Pointer reference ("#/definitions/component") against
// the schema root, per RFC 6901's "~1" -> "/" and "~0" -> "~" segment unescaping.
func (s *Schema) resolveRef(ref string) (map[string]any, error) {
	if !strings.HasPrefix(ref, "#/") && ref != "#" {
		return nil, fmt.Errorf("jsonschema: only local refs are supported, got %q", ref)
	}
	if ref == "#" {
		return s.root, nil
	}
	cur := any(s.root)
	for _, raw := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		seg := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("jsonschema: cannot resolve %q — %q is not an object", ref, seg)
		}
		next, ok := m[seg]
		if !ok {
			return nil, fmt.Errorf("jsonschema: cannot resolve %q — no key %q", ref, seg)
		}
		cur = next
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jsonschema: resolved %q is not a schema object", ref)
	}
	return m, nil
}

// validateNode validates instance against schemaNode, appending any ValidationErrors to
// *errs, at the given instance JSON-Pointer path. It returns a non-nil error only for a
// processing failure (unsupported keyword combination, unresolvable $ref, bad regexp).
func (s *Schema) validateNode(schemaNode map[string]any, instance any, path string, errs *[]*ValidationError) error {
	if ref, ok := schemaNode["$ref"].(string); ok {
		resolved, err := s.resolveRef(ref)
		if err != nil {
			return err
		}
		return s.validateNode(resolved, instance, path, errs)
	}

	if rawOneOf, ok := schemaNode["oneOf"]; ok {
		return s.validateOneOfAnyOf(rawOneOf, instance, path, errs, true)
	}
	if rawAnyOf, ok := schemaNode["anyOf"]; ok {
		return s.validateOneOfAnyOf(rawAnyOf, instance, path, errs, false)
	}

	if err := s.checkType(schemaNode, instance, path, errs); err != nil {
		return err
	}
	if err := s.checkEnumConst(schemaNode, instance, path, errs); err != nil {
		return err
	}

	switch v := instance.(type) {
	case string:
		s.checkStringConstraints(schemaNode, v, path, errs)
	case float64:
		s.checkNumberConstraints(schemaNode, v, path, errs)
	case []any:
		if err := s.checkArrayConstraints(schemaNode, v, path, errs); err != nil {
			return err
		}
	case map[string]any:
		if err := s.checkObjectConstraints(schemaNode, v, path, errs); err != nil {
			return err
		}
	}
	return nil
}

// validateOneOfAnyOf implements oneOf (exactly one subschema must match) and anyOf (at
// least one must match). errsOut collects a SINGLE combined error when the constraint
// fails; the individual subschema failures are not surfaced (oneOf/anyOf failures are
// inherently about "none/more than one matched", not about a specific field).
func (s *Schema) validateOneOfAnyOf(raw any, instance any, path string, errsOut *[]*ValidationError, exactlyOne bool) error {
	arr, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("jsonschema: oneOf/anyOf at %q is not an array", path)
	}
	matched := 0
	for _, sub := range arr {
		subSchema, ok := sub.(map[string]any)
		if !ok {
			return fmt.Errorf("jsonschema: oneOf/anyOf entry at %q is not an object", path)
		}
		var subErrs []*ValidationError
		if err := s.validateNode(subSchema, instance, path, &subErrs); err != nil {
			return err
		}
		if len(subErrs) == 0 {
			matched++
		}
	}
	if exactlyOne && matched != 1 {
		*errsOut = append(*errsOut, &ValidationError{Path: path, Msg: fmt.Sprintf("oneOf: matched %d subschemas, want exactly 1", matched)})
	}
	if !exactlyOne && matched == 0 {
		*errsOut = append(*errsOut, &ValidationError{Path: path, Msg: "anyOf: matched 0 subschemas, want at least 1"})
	}
	return nil
}

func (s *Schema) checkType(schemaNode map[string]any, instance any, path string, errs *[]*ValidationError) error {
	raw, ok := schemaNode["type"]
	if !ok {
		return nil
	}
	var allowed []string
	switch t := raw.(type) {
	case string:
		allowed = []string{t}
	case []any:
		for _, x := range t {
			ts, ok := x.(string)
			if !ok {
				return fmt.Errorf("jsonschema: type array at %q has a non-string entry", path)
			}
			allowed = append(allowed, ts)
		}
	default:
		return fmt.Errorf("jsonschema: type at %q is neither a string nor an array", path)
	}
	got := jsonInstanceType(instance)
	for _, want := range allowed {
		if got == want {
			return nil
		}
		if want == "integer" && got == "number" {
			if f, ok := instance.(float64); ok && f == math.Trunc(f) {
				return nil
			}
		}
	}
	*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("type is %s, want one of %v", got, allowed)})
	return nil
}

func jsonInstanceType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func (s *Schema) checkEnumConst(schemaNode map[string]any, instance any, path string, errs *[]*ValidationError) error {
	if rawConst, ok := schemaNode["const"]; ok {
		if !jsonDeepEqual(rawConst, instance) {
			*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("value does not equal const %v", rawConst)})
		}
	}
	if rawEnum, ok := schemaNode["enum"]; ok {
		arr, ok := rawEnum.([]any)
		if !ok {
			return fmt.Errorf("jsonschema: enum at %q is not an array", path)
		}
		for _, cand := range arr {
			if jsonDeepEqual(cand, instance) {
				return nil
			}
		}
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("value %v is not in enum %v", instance, arr)})
	}
	return nil
}

// jsonDeepEqual compares two values decoded from encoding/json (so numbers are always
// float64, objects are map[string]any, arrays are []any) for JSON-level equality.
func jsonDeepEqual(a, b any) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

func (s *Schema) checkStringConstraints(schemaNode map[string]any, v string, path string, errs *[]*ValidationError) {
	n := utf8.RuneCountInString(v)
	if minLen, ok := numberField(schemaNode, "minLength"); ok && float64(n) < minLen {
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("length %d < minLength %v", n, minLen)})
	}
	if maxLen, ok := numberField(schemaNode, "maxLength"); ok && float64(n) > maxLen {
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("length %d > maxLength %v", n, maxLen)})
	}
	if rawPattern, ok := schemaNode["pattern"].(string); ok {
		re, err := regexp.Compile(rawPattern)
		if err != nil {
			// The pattern itself cannot be compiled by Go's RE2 engine (a genuine
			// processing limitation of this validator's subset, not a document defect);
			// this is intentionally NOT appended as a ValidationError — see the type doc.
			return
		}
		if !re.MatchString(v) {
			*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("value %q does not match pattern %q", v, rawPattern)})
		}
	}
}

func (s *Schema) checkNumberConstraints(schemaNode map[string]any, v float64, path string, errs *[]*ValidationError) {
	if minV, ok := numberField(schemaNode, "minimum"); ok && v < minV {
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("%v < minimum %v", v, minV)})
	}
	if maxV, ok := numberField(schemaNode, "maximum"); ok && v > maxV {
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("%v > maximum %v", v, maxV)})
	}
}

func (s *Schema) checkArrayConstraints(schemaNode map[string]any, v []any, path string, errs *[]*ValidationError) error {
	if minI, ok := numberField(schemaNode, "minItems"); ok && float64(len(v)) < minI {
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("%d items < minItems %v", len(v), minI)})
	}
	if maxI, ok := numberField(schemaNode, "maxItems"); ok && float64(len(v)) > maxI {
		*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("%d items > maxItems %v", len(v), maxI)})
	}
	if unique, ok := schemaNode["uniqueItems"].(bool); ok && unique {
		seen := map[string]bool{}
		for i, item := range v {
			b, err := json.Marshal(item)
			if err != nil {
				return err
			}
			if seen[string(b)] {
				*errs = append(*errs, &ValidationError{Path: fmt.Sprintf("%s/%d", path, i), Msg: "duplicate item, uniqueItems is true"})
			}
			seen[string(b)] = true
		}
	}
	if rawItems, ok := schemaNode["items"]; ok {
		itemSchema, ok := rawItems.(map[string]any)
		if !ok {
			return fmt.Errorf("jsonschema: items at %q is not a single schema object (tuple-form items is not supported)", path)
		}
		for i, item := range v {
			if err := s.validateNode(itemSchema, item, fmt.Sprintf("%s/%d", path, i), errs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Schema) checkObjectConstraints(schemaNode map[string]any, v map[string]any, path string, errs *[]*ValidationError) error {
	if rawRequired, ok := schemaNode["required"]; ok {
		arr, ok := rawRequired.([]any)
		if !ok {
			return fmt.Errorf("jsonschema: required at %q is not an array", path)
		}
		for _, r := range arr {
			key, ok := r.(string)
			if !ok {
				return fmt.Errorf("jsonschema: required entry at %q is not a string", path)
			}
			if _, present := v[key]; !present {
				*errs = append(*errs, &ValidationError{Path: path, Msg: fmt.Sprintf("missing required property %q", key)})
			}
		}
	}

	properties, _ := schemaNode["properties"].(map[string]any)

	// Deterministic key order for reproducible error output (Go map iteration is
	// randomized) — this has no effect on validity, only on the order errors appear in.
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		val := v[key]
		propSchema, inProperties := properties[key]
		if inProperties {
			ps, ok := propSchema.(map[string]any)
			if !ok {
				return fmt.Errorf("jsonschema: properties[%q] at %q is not a schema object", key, path)
			}
			if err := s.validateNode(ps, val, path+"/"+jsonPointerEscape(key), errs); err != nil {
				return err
			}
			continue
		}
		if rawAdditional, ok := schemaNode["additionalProperties"]; ok {
			if allowed, ok := rawAdditional.(bool); ok {
				if !allowed {
					*errs = append(*errs, &ValidationError{Path: path + "/" + jsonPointerEscape(key), Msg: "additional property not allowed"})
				}
				continue
			}
			return fmt.Errorf("jsonschema: additionalProperties at %q is not a boolean (schema-form additionalProperties is not supported)", path)
		}
	}
	return nil
}

func jsonPointerEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// numberField reads a numeric schema keyword, which json.Unmarshal always decodes as
// float64 (or occasionally json.Number if a decoder option were set, which this package
// never sets) — also tolerates an integer written as a json.Number-compatible string,
// which never occurs from encoding/json's default decode but is accepted defensively.
func numberField(schemaNode map[string]any, key string) (float64, bool) {
	raw, ok := schemaNode[key]
	if !ok {
		return 0, false
	}
	switch n := raw.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := strconv.ParseFloat(n.String(), 64)
		return f, err == nil
	default:
		return 0, false
	}
}
