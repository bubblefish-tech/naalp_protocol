# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
A hand-rolled JSON Schema (draft 2020-12) CORE-SUBSET instance validator.

A real implementation of `jsonschema` (python-jsonschema) is importable in some
environments this tool may run in, but this module does not call one: the schema-gen tool
must run wherever an N-AALP ecosystem SDK runs, without adding a new runtime dependency
this repository's ecosystem tier does not otherwise carry (`naalp-codec` and
`naalp-validator` both reuse only the Part-1 stdlib-only reference SDK). This module
implements, from the 2020-12 core vocabulary (https://json-schema.org/draft/2020-12),
exactly the keywords a body/object schema needs to describe an N-AALP-compatible
structure: `type` (a single name or a list, for a union), `properties` / `required` /
`additionalProperties`, `items` / `prefixItems` / `minItems` / `maxItems`, `minLength` /
`maxLength` / `pattern`, `minimum` / `maximum` / `exclusiveMinimum` / `exclusiveMaximum`,
`enum`, and `const`. Composition/reference keywords (`$ref`, `oneOf`, `anyOf`, `allOf`,
`not`, `if`/`then`/`else`, `patternProperties`, `dependentSchemas`) are recognized but
deliberately UNSUPPORTED here -- see `generator.py`'s UNMAPPABLE warning, which fires on
exactly these constructs when generating CDDL, rather than being silently ignored.

Design choice -- COLLECT, don't fail-fast, mirroring `naalp_validator.validate()`: a schema
author (or an LLM proposing a candidate object) benefits from seeing every violation in a
candidate instance at once, not one violation per round trip.
"""
import re

__all__ = ["SchemaError", "Violation", "ValidationOutcome", "validate_instance"]

_JSON_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})


class SchemaError(ValueError):
    """Raised for a structurally malformed SCHEMA (not an instance violation) -- e.g. a
    non-dict schema node, an unrecognized 'type' name, or a 'required' entry that is not a
    string. An instance that fails to CONFORM to a well-formed schema is never reported this
    way; it becomes a Violation inside a ValidationOutcome instead."""


class Violation:
    """One rejected aspect of a candidate instance. `path` is a JSON-Pointer-ish location
    string rooted at '$' (e.g. '$.tags[2]'), so a caller (human or LLM) can find exactly
    which part of the instance failed."""
    __slots__ = ("path", "message")

    def __init__(self, path, message):
        self.path = path
        self.message = message

    def __eq__(self, other):
        return isinstance(other, Violation) and self.path == other.path and self.message == other.message

    def __hash__(self):
        return hash((self.path, self.message))

    def __repr__(self):
        return "Violation(path=%r, message=%r)" % (self.path, self.message)


class ValidationOutcome:
    """The outcome of validate_instance(): `valid` is computed (True iff `violations` is
    empty), never stored independently -- mirrors naalp_validator.ValidationResult so there
    is exactly one place a mutation could break the verdict, and it is this property, not a
    second flag that could drift from the list."""
    __slots__ = ("violations",)

    def __init__(self, violations):
        self.violations = list(violations)

    @property
    def valid(self):
        return len(self.violations) == 0

    def __bool__(self):
        return self.valid

    def __repr__(self):
        return "ValidationOutcome(valid=%r, violations=%r)" % (self.valid, self.violations)


def _json_type_of(value):
    """The JSON Schema type name for a Python value built from (or destined for) JSON. `bool`
    is checked before `int` because Python's bool is an int subclass, but JSON Schema treats
    booleans and integers as distinct types."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    raise SchemaError("value %r is not a JSON-decodable Python type" % (value,))


def _allowed_types(schema):
    t = schema.get("type")
    if t is None:
        return None
    if isinstance(t, str):
        names = [t]
    elif isinstance(t, list):
        names = list(t)
    else:
        raise SchemaError("'type' must be a string or a list of strings, got %r" % (t,))
    for name in names:
        if name not in _JSON_TYPES:
            raise SchemaError("unrecognized JSON Schema type %r" % (name,))
    return names


def validate_instance(schema, instance, *, path="$"):
    """Validate `instance` against `schema` (a JSON-Schema 2020-12 core-subset dict). Returns
    a ValidationOutcome collecting every applicable violation (never fails fast)."""
    violations = []
    _walk_instance(schema, instance, path, violations)
    return ValidationOutcome(violations)


def _walk_instance(schema, instance, path, violations):
    if not isinstance(schema, dict):
        raise SchemaError("schema at %s must be a dict, got %r" % (path, type(schema).__name__))

    allowed = _allowed_types(schema)
    if allowed is not None:
        actual = _json_type_of(instance)
        if actual not in allowed:
            violations.append(Violation(
                path, "expected type %s, got %s" % (" or ".join(allowed), actual)))
            return  # the structural checks below assume the type already matched

    if "enum" in schema:
        options = schema["enum"]
        if instance not in options:
            violations.append(Violation(
                path, "value %r is not one of the enumerated options %r" % (instance, options)))

    if "const" in schema:
        if instance != schema["const"]:
            violations.append(Violation(
                path, "value %r does not equal the required const %r" % (instance, schema["const"])))

    kind = _json_type_of(instance)
    if kind == "object":
        _walk_object(schema, instance, path, violations)
    elif kind == "array":
        _walk_array(schema, instance, path, violations)
    elif kind == "string":
        _walk_string(schema, instance, path, violations)
    elif kind in ("integer", "number"):
        _walk_number(schema, instance, path, violations)


def _walk_object(schema, instance, path, violations):
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise SchemaError("'properties' at %s must be a dict, got %r" % (path, type(properties).__name__))
    required = schema.get("required", [])
    for name in required:
        if not isinstance(name, str):
            raise SchemaError("'required' entries must be strings, got %r" % (name,))
        if name not in instance:
            violations.append(Violation(path, "missing required property %r" % (name,)))
    additional = schema.get("additionalProperties", True)
    for key, value in instance.items():
        if key in properties:
            _walk_instance(properties[key], value, "%s.%s" % (path, key), violations)
        elif additional is False:
            violations.append(Violation(
                path, "unexpected additional property %r (additionalProperties is false)" % (key,)))
        elif isinstance(additional, dict):
            _walk_instance(additional, value, "%s.%s" % (path, key), violations)
        # additional is True (or absent, which JSON Schema 2020-12 also defaults to true):
        # any shape is accepted for a key not named in 'properties'.


def _walk_array(schema, instance, path, violations):
    min_items = schema.get("minItems")
    max_items = schema.get("maxItems")
    if min_items is not None and len(instance) < min_items:
        violations.append(Violation(
            path, "array has %d item(s), fewer than minItems=%d" % (len(instance), min_items)))
    if max_items is not None and len(instance) > max_items:
        violations.append(Violation(
            path, "array has %d item(s), more than maxItems=%d" % (len(instance), max_items)))
    prefix = schema.get("prefixItems")
    items_schema = schema.get("items")
    for i, item in enumerate(instance):
        item_path = "%s[%d]" % (path, i)
        if prefix is not None and i < len(prefix):
            _walk_instance(prefix[i], item, item_path, violations)
        elif items_schema is not None:
            if items_schema is False:
                violations.append(Violation(
                    item_path, "array item present but 'items' is false (no further items allowed)"))
            elif isinstance(items_schema, dict):
                _walk_instance(items_schema, item, item_path, violations)


def _walk_string(schema, instance, path, violations):
    min_len = schema.get("minLength")
    max_len = schema.get("maxLength")
    if min_len is not None and len(instance) < min_len:
        violations.append(Violation(
            path, "string length %d is less than minLength=%d" % (len(instance), min_len)))
    if max_len is not None and len(instance) > max_len:
        violations.append(Violation(
            path, "string length %d exceeds maxLength=%d" % (len(instance), max_len)))
    pattern = schema.get("pattern")
    if pattern is not None and re.search(pattern, instance) is None:
        violations.append(Violation(path, "string %r does not match pattern %r" % (instance, pattern)))


def _walk_number(schema, instance, path, violations):
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    ex_min = schema.get("exclusiveMinimum")
    ex_max = schema.get("exclusiveMaximum")
    if minimum is not None and instance < minimum:
        violations.append(Violation(path, "value %r is less than minimum=%r" % (instance, minimum)))
    if maximum is not None and instance > maximum:
        violations.append(Violation(path, "value %r exceeds maximum=%r" % (instance, maximum)))
    if ex_min is not None and instance <= ex_min:
        violations.append(Violation(
            path, "value %r is not greater than exclusiveMinimum=%r" % (instance, ex_min)))
    if ex_max is not None and instance >= ex_max:
        violations.append(Violation(
            path, "value %r is not less than exclusiveMaximum=%r" % (instance, ex_max)))
