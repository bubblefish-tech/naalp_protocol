# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
JSON-Schema (2020-12) -> N-AALP CDDL + validation-code generator (Part-2 ecosystem task
E1.5, requirement R10, "A+ item 3").

Given a JSON Schema describing an N-AALP object body (or a body sub-structure), this module:

  1. Emits a CDDL group definition compatible with the N-AALP object model and its
     deterministic-CBOR encoding profile (RFC 8949 sec.4.2.1: no floats, sorted map keys,
     bounded strings/arrays/integers) -- `generate_cddl()`.
  2. Produces a bound Python validation callable for the same schema -- `generate_validator()`,
     which returns a SchemaValidator wrapping the hand-rolled walker in jsonschema_core.py.

It warns (GenWarning), rather than silently drops, on three named unsafe/unmappable
schema constructs, and additionally on other JSON-Schema 2020-12 constructs this generator
does not map at all:

  - UNBOUNDED    -- an array/string/integer with no maxItems/maxLength/maximum
                    (design.md's R7 decoder-bounds discipline: every wire construct this
                    generator emits must have a fixed decode-time upper bound).
  - FLOAT_FORBIDDEN -- a 'number' type. naalp.cbor's value model (U/N/B/T/A/M/Tag) has no
                    floating-point wrapper at all (see naalp_codec.codec's own
                    `_reject_bare_float` docstring), so a float is not merely discouraged on
                    the N-AALP wire -- it has no encoding in this codec.
  - EFFECTING_WITHOUT_AUDIENCE -- a schema declaring `x-naalp-effect` as anything other than
                    `read_only` (an effecting kind) whose top-level `properties` do not
                    include `audience`. design.md sec.2.5.3 requires a consume-once kind's
                    object to carry an audience naming its consuming authority
                    (naalp_validator.CONSUME_ONCE_KINDS enforces this at the envelope level;
                    this warning catches the schema-authoring mistake before that check ever
                    runs).
  - UNMAPPABLE   -- `boolean`/`null` (CBOR major type 7 -- simple values/booleans/null -- is
                    not defined anywhere in naalp.cbor's value model, so these have no wire
                    representation at all, not merely an unsafe one), an untyped schema node,
                    an open (`additionalProperties: true`/unset) object body (a closed CDDL
                    map production cannot express an unbounded key set), and any JSON-Schema
                    composition/reference keyword ($ref, oneOf, anyOf, allOf, not, if/then/
                    else, patternProperties, dependentSchemas).

In `strict=True` mode, `generate_cddl()`/`generate_validator()` raise SchemaGenRefusal
instead of returning warnings: the schema is refused outright rather than accepted with an
advisory. `x-naalp-effect` is a vendor extension keyword (JSON Schema 2020-12 permits and
ignores unrecognized keywords in generic validators); only this generator interprets it.
"""
import re

from .jsonschema_core import SchemaError

__all__ = [
    "UNBOUNDED", "FLOAT_FORBIDDEN", "EFFECTING_WITHOUT_AUDIENCE", "UNMAPPABLE",
    "GenWarning", "GenResult", "SchemaGenRefusal", "SchemaValidator",
    "generate_cddl", "generate_validator",
]

UNBOUNDED = "Unbounded"
FLOAT_FORBIDDEN = "FloatForbidden"
EFFECTING_WITHOUT_AUDIENCE = "EffectingWithoutAudience"
UNMAPPABLE = "Unmappable"

_EFFECTING_VALUES = frozenset({"idempotent_write", "non_idempotent_write", "destructive"})
_KNOWN_EFFECT_VALUES = _EFFECTING_VALUES | {"read_only"}

_UNMAPPABLE_KEYWORDS = (
    "$ref", "oneOf", "anyOf", "allOf", "not", "if", "then", "else",
    "patternProperties", "dependentSchemas",
)

_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


class GenWarning:
    """One advisory raised while scanning a schema: `code` is one of the module-level
    constants above, `path` locates the offending schema node (rooted at '$'), `message`
    explains why it is unsafe or unmappable on the N-AALP wire."""
    __slots__ = ("code", "path", "message")

    def __init__(self, code, path, message):
        self.code = code
        self.path = path
        self.message = message

    def __eq__(self, other):
        return isinstance(other, GenWarning) and (self.code, self.path) == (other.code, other.path)

    def __hash__(self):
        return hash((self.code, self.path))

    def __repr__(self):
        return "GenWarning(code=%r, path=%r, message=%r)" % (self.code, self.path, self.message)


class SchemaGenRefusal(SchemaError):
    """Raised by generate_cddl()/generate_validator() in strict=True mode when scanning the
    schema collected one or more warnings. Carries the FULL list (`.warnings`), not just the
    first, so a caller can report every offending construct in one refusal."""

    def __init__(self, warnings):
        self.warnings = list(warnings)
        codes = ", ".join(sorted({w.code for w in self.warnings}))
        super().__init__(
            "strict mode refuses %d unsafe/unmappable construct(s): %s" % (len(self.warnings), codes))


class GenResult:
    """The outcome of generate_cddl(): `cddl` is the emitted CDDL group-definition text (a
    trailing newline, no leading/trailing warnings baked into the grammar itself -- those
    live in `.warnings`, never silently folded into the text as if they were a soft-pass)."""
    __slots__ = ("def_name", "cddl", "warnings")

    def __init__(self, def_name, cddl, warnings):
        self.def_name = def_name
        self.cddl = cddl
        self.warnings = list(warnings)

    def __repr__(self):
        return "GenResult(def_name=%r, warnings=%r)" % (self.def_name, self.warnings)


def _cddl_ident(name):
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise SchemaError(
            "not a valid CDDL rule identifier: %r (must match %s)" % (name, _IDENT_RE.pattern))
    return name


def _check_unmappable_keywords(schema, path, warnings):
    for kw in _UNMAPPABLE_KEYWORDS:
        if kw in schema:
            warnings.append(GenWarning(
                UNMAPPABLE, path,
                "the %r keyword is a JSON-Schema composition/reference construct with no CDDL "
                "group-definition mapping in this generator; a generated definition needs a "
                "single concrete structural shape per node" % (kw,)))


def _check_effecting_audience(schema, warnings):
    """Top-level-only: 'audience' is a naalp-object ENVELOPE field (field 13), never a body
    field, so this check inspects only the schema root, not every nested object node."""
    effect = schema.get("x-naalp-effect")
    if effect is None:
        return
    if effect not in _KNOWN_EFFECT_VALUES:
        raise SchemaError(
            "x-naalp-effect must be one of %s, got %r" % (sorted(_KNOWN_EFFECT_VALUES), effect))
    if effect in _EFFECTING_VALUES:
        properties = schema.get("properties", {})
        if not isinstance(properties, dict) or "audience" not in properties:
            warnings.append(GenWarning(
                EFFECTING_WITHOUT_AUDIENCE, "$",
                "x-naalp-effect=%r declares an effecting kind, but the schema's top-level "
                "properties do not include 'audience'; design.md sec.2.5.3 requires a "
                "consume-once kind's object to carry an audience naming its consuming "
                "authority" % (effect,)))


def _cddl_literal(value):
    if isinstance(value, bool):
        raise SchemaError("a boolean const/enum literal has no CDDL representation on the "
                           "N-AALP wire (no CBOR boolean in naalp.cbor's value model)")
    if isinstance(value, str):
        return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')
    if isinstance(value, int):
        return str(value)
    raise SchemaError("unsupported const/enum literal: %r" % (value,))


def _cddl_enum(values):
    return "(" + " / ".join(_cddl_literal(v) for v in values) + ")"


def _cddl_object(schema, path, warnings):
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise SchemaError("'properties' at %s must be a dict, got %r" % (path, type(properties).__name__))
    required = set(schema.get("required", []))
    fields = []
    for key, sub_schema in properties.items():
        sub_path = "%s.properties.%s" % (path, key)
        sub_cddl = _walk_and_collect(sub_schema, sub_path, warnings)
        marker = "" if key in required else "? "
        fields.append('  %s"%s" : %s,' % (marker, key, sub_cddl))

    additional = schema.get("additionalProperties")
    if additional is not False and not isinstance(additional, dict):
        # True, or unset (2020-12 default is true): an open key set has no closed CDDL map
        # production this generator can express exactly.
        warnings.append(GenWarning(
            UNMAPPABLE, path,
            "additionalProperties is true (or unset, defaulting to true); a closed CDDL map "
            "production cannot express an open-ended key set -- set additionalProperties: "
            "false for a generated definition to be exact"))

    return "{\n%s\n}" % "\n".join(fields) if fields else "{ }"


def _cddl_array(schema, path, warnings):
    items_schema = schema.get("items")
    min_items = schema.get("minItems", 0)
    max_items = schema.get("maxItems")
    item_cddl = _walk_and_collect(items_schema, path + "[]", warnings) \
        if isinstance(items_schema, dict) else "any"
    if max_items is None:
        warnings.append(GenWarning(
            UNBOUNDED, path,
            "array has no 'maxItems'; an unbounded array has no fixed CBOR decode-time "
            "element-count bound (design.md R7 decoder-bounds discipline)"))
        return "[* %s]" % item_cddl
    return "[%d*%d %s]" % (min_items, max_items, item_cddl)


def _cddl_string(schema, path, warnings):
    min_len = schema.get("minLength", 0)
    max_len = schema.get("maxLength")
    if "pattern" in schema:
        warnings.append(GenWarning(
            UNMAPPABLE, path,
            "'pattern' (regex) constraints have no CDDL representation in this generator; "
            "enforce it in the generated Python validator only, not in the emitted CDDL"))
    if max_len is None:
        warnings.append(GenWarning(
            UNBOUNDED, path,
            "string has no 'maxLength'; an unbounded text string has no fixed CBOR "
            "decode-time octet bound (design.md R7 decoder-bounds discipline)"))
        return "tstr"
    return "tstr .size (%d..%d)" % (min_len, max_len)


def _cddl_integer(schema, path, warnings):
    minimum = schema.get("minimum")
    ex_min = schema.get("exclusiveMinimum")
    maximum = schema.get("maximum")
    ex_max = schema.get("exclusiveMaximum")
    bounded_above = maximum is not None or ex_max is not None
    if not bounded_above:
        warnings.append(GenWarning(
            UNBOUNDED, path,
            "integer has no 'maximum' or 'exclusiveMaximum'; an unbounded integer has no "
            "fixed CBOR shortest-form-head upper bound (design.md R7 decoder-bounds discipline)"))
        lo = minimum if minimum is not None else (ex_min + 1 if ex_min is not None else 0)
        return "uint" if lo >= 0 else "int"
    lo = minimum if minimum is not None else (ex_min + 1 if ex_min is not None else 0)
    hi = maximum if maximum is not None else ex_max - 1
    return "%d..%d" % (lo, hi)


def _walk_and_collect(schema, path, warnings):
    """The single recursive CDDL-fragment builder AND warning-collector: both generate_cddl()
    and generate_validator() call this (the latter discards the returned text), so a schema
    is scanned for unsafe/unmappable constructs exactly once per entry point, never by two
    diverging code paths that could drift apart."""
    if not isinstance(schema, dict):
        raise SchemaError("schema at %s must be a dict, got %r" % (path, type(schema).__name__))

    _check_unmappable_keywords(schema, path, warnings)

    if "enum" in schema:
        return _cddl_enum(schema["enum"])
    if "const" in schema:
        return _cddl_literal(schema["const"])

    t = schema.get("type")
    if t is None:
        warnings.append(GenWarning(
            UNMAPPABLE, path, "schema node has no 'type' (and no enum/const); emitting 'any'"))
        return "any"

    if isinstance(t, list):
        branches = []
        for member in t:
            sub = dict(schema)
            sub["type"] = member
            branches.append(_walk_and_collect(sub, path, warnings))
        return "(" + " / ".join(branches) + ")"

    if t == "object":
        return _cddl_object(schema, path, warnings)
    if t == "array":
        return _cddl_array(schema, path, warnings)
    if t == "string":
        return _cddl_string(schema, path, warnings)
    if t == "integer":
        return _cddl_integer(schema, path, warnings)
    if t == "number":
        warnings.append(GenWarning(
            FLOAT_FORBIDDEN, path,
            "'number' allows non-integer values, which have no representation in the N-AALP "
            "deterministic-CBOR value model (RFC 8949 sec.4.2.1; naalp.cbor defines only "
            "U/N/B/T/A/M/Tag, no float wrapper) -- use 'integer' with explicit bounds instead"))
        return "float64  ; UNSAFE: forbidden on the N-AALP wire, see warnings"
    if t == "boolean":
        warnings.append(GenWarning(
            UNMAPPABLE, path,
            "'boolean' has no representation in the N-AALP CBOR value model (CBOR major type "
            "7 -- simple values -- is not defined in naalp.cbor); represent it as an integer "
            "0/1 with an explicit enum instead"))
        return "any  ; UNMAPPABLE: boolean, see warnings"
    if t == "null":
        warnings.append(GenWarning(
            UNMAPPABLE, path,
            "'null' has no representation in the N-AALP CBOR value model (CBOR major type 7 "
            "is not defined in naalp.cbor); omit the field instead of using an explicit null"))
        return "any  ; UNMAPPABLE: null, see warnings"

    raise SchemaError("unrecognized JSON Schema type %r at %s" % (t, path))


def generate_cddl(schema, def_name, *, strict=False):
    """Generate a CDDL group definition named `def_name` for `schema`. Returns a GenResult.
    Raises SchemaGenRefusal in strict mode if any warning was collected."""
    _cddl_ident(def_name)
    warnings = []
    body = _walk_and_collect(schema, "$", warnings)
    _check_effecting_audience(schema, warnings)
    if strict and warnings:
        raise SchemaGenRefusal(warnings)
    return GenResult(def_name=def_name, cddl="%s = %s\n" % (def_name, body), warnings=warnings)


class SchemaValidator:
    """A schema-bound validation callable produced by generate_validator(): holds the schema
    and the warnings collected while scanning it, and validates any instance against that
    exact schema via naalp_schemagen.jsonschema_core -- a real recursive JSON-Schema 2020-12
    core-subset walk, never a stub that ignores the schema or the instance."""
    __slots__ = ("schema", "warnings")

    def __init__(self, schema, warnings):
        self.schema = schema
        self.warnings = list(warnings)

    def validate(self, instance):
        from .jsonschema_core import validate_instance
        return validate_instance(self.schema, instance)

    def __call__(self, instance):
        return self.validate(instance)

    def __repr__(self):
        return "SchemaValidator(warnings=%r)" % (self.warnings,)


def generate_validator(schema, *, strict=False):
    """Scan `schema` for the same warnings generate_cddl() would collect, then return a
    SchemaValidator bound to it. Raises SchemaGenRefusal in strict mode if any warning was
    collected -- a schema too unsafe to emit CDDL for is also too unsafe to hand out a
    validator for, since both would be certifying the same non-conformant shape as legitimate."""
    warnings = []
    _walk_and_collect(schema, "$", warnings)
    _check_effecting_audience(schema, warnings)
    if strict and warnings:
        raise SchemaGenRefusal(warnings)
    return SchemaValidator(schema, warnings)
