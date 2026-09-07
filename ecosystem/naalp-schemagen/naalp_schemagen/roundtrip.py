# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
JSON-Schema -> N-AALP object round trip (Part-2 ecosystem task E1.5, requirement R10 item 3).

Converts an already schema-validated Python instance into the real deterministic-CBOR body
value naalp_codec/naalp.cbor use (U/N/B/T/A/M), builds a full naalp.envelope.Object around
it, and proves round-trip fidelity through the REAL Part-1/Part-2 machinery -- never a
second codec, never a second validator:

  1. naalp_codec.verify_roundtrip(body) -- the blessed E0.3 codec's own determinism proof
     (encode -> decode -> re-encode -> byte-identical).
  2. naalp_validator.validate(obj) -- the E0.2 semantic validator's full envelope-level check
     (kind registry, effect-class, R7 bounds, and the consume-once audience rule).

This module performs NO cryptography and adds NO new encoding rule; build_cbor_value below
is a real, schema-guided TRANSFORM (not a raw pass-through) from a JSON-decoded Python value
into the seven wrapper types naalp.cbor recognizes, and it refuses (NaalpUnrepresentable)
rather than silently coerces a JSON Schema type this codec's value model cannot represent at
all: naalp.cbor defines only U/N/B/T/A/M/Tag -- there is no boolean, null, or
floating-point wire representation in this value model (see naalp_codec.codec's own
`_reject_bare_float` docstring for the float case) -- so 'boolean', 'null', and 'number'
instances are refused here, matching generator.py's UNMAPPABLE/FLOAT_FORBIDDEN warnings for
the same schema constructs.

'audience' is handled specially: it is a naalp-object ENVELOPE field (field 13), never a
body field (spec/naalp-draft-01.cddl field 13; design.md sec.2.5.3), so a top-level schema
property literally named 'audience' is popped out of the instance before the body is built
and threaded through as the object's real `audience=` argument instead -- there is never a
redundant 'audience' key duplicated inside the CBOR body map.
"""
from . import _bootstrap  # noqa: F401  (side-effecting import: puts the ecosystem siblings on sys.path)

import naalp_codec
import naalp_validator
from naalp import cose, envelope

__all__ = [
    "NaalpUnrepresentable", "RoundTripResult",
    "build_cbor_value", "build_object", "round_trip",
]


class NaalpUnrepresentable(ValueError):
    """Raised when a JSON Schema type has genuinely no representation in the N-AALP
    deterministic-CBOR value model (boolean, null, or a non-integer number), or when an
    instance disagrees with its schema's declared type at build time -- never silently
    coerced into an invented encoding."""


def _infer_type(instance):
    if isinstance(instance, bool):
        return "boolean"
    if isinstance(instance, int):
        return "integer"
    if isinstance(instance, float):
        return "number"
    if isinstance(instance, str):
        return "string"
    if isinstance(instance, list):
        return "array"
    if isinstance(instance, dict):
        return "object"
    if instance is None:
        return "null"
    raise NaalpUnrepresentable("Python value %r has no JSON Schema type mapping" % (instance,))


def build_cbor_value(schema, instance):
    """Recursively construct the naalp_codec wrapper value for `instance`, guided by
    `schema`. Dispatches on schema['type'] (falling back to the instance's own inferred JSON
    type only when the schema node omits 'type', so a genuinely untyped node still converts
    something real). Changing either the schema or the instance changes the resulting CBOR
    value -- this is never a constant-output stub (A4)."""
    t = schema.get("type") if isinstance(schema, dict) else None
    if t is None:
        t = _infer_type(instance)
    if isinstance(t, list):
        actual = _infer_type(instance)
        if actual not in t:
            raise NaalpUnrepresentable(
                "instance type %r is not one of the declared union %r at this node" % (actual, t))
        t = actual

    if t == "object":
        if not isinstance(instance, dict):
            raise NaalpUnrepresentable("schema declares 'object' but instance is %r" % (type(instance).__name__,))
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        pairs = [(naalp_codec.T(key), build_cbor_value(properties.get(key, {}), value))
                 for key, value in instance.items()]
        return naalp_codec.M(pairs)
    if t == "array":
        if not isinstance(instance, list):
            raise NaalpUnrepresentable("schema declares 'array' but instance is %r" % (type(instance).__name__,))
        items_schema = schema.get("items", {}) if isinstance(schema, dict) else {}
        return naalp_codec.A([build_cbor_value(items_schema, item) for item in instance])
    if t == "string":
        if not isinstance(instance, str):
            raise NaalpUnrepresentable("schema declares 'string' but instance is %r" % (type(instance).__name__,))
        return naalp_codec.T(instance)
    if t == "integer":
        if isinstance(instance, bool) or not isinstance(instance, int):
            raise NaalpUnrepresentable("schema declares 'integer' but instance is %r" % (type(instance).__name__,))
        return naalp_codec.U(instance) if instance >= 0 else naalp_codec.N(instance)
    if t == "number":
        raise NaalpUnrepresentable(
            "'number' has no representation in the N-AALP CBOR value model (no float wrapper "
            "exists; naalp.cbor defines only U/N/B/T/A/M/Tag) -- use 'integer' instead")
    if t == "boolean":
        raise NaalpUnrepresentable(
            "'boolean' has no representation in the N-AALP CBOR value model (CBOR major type "
            "7 is not defined) -- represent it as an integer 0/1 instead")
    if t == "null":
        raise NaalpUnrepresentable(
            "'null' has no representation in the N-AALP CBOR value model (CBOR major type 7 "
            "is not defined) -- omit the field instead")
    raise NaalpUnrepresentable("unrecognized or unsupported JSON Schema type %r" % (t,))


def _split_reserved_audience(schema, instance):
    """If `schema` is an object schema whose top-level properties name 'audience', pop that
    key out of both schema and instance and return it separately -- 'audience' is envelope
    field 13, never a body field. Returns (body_schema, body_instance, audience_or_None)."""
    if not (isinstance(schema, dict) and schema.get("type", "object") == "object"
            and isinstance(instance, dict)
            and "audience" in schema.get("properties", {})):
        return schema, instance, None
    body_schema = dict(schema)
    props = dict(body_schema.get("properties", {}))
    props.pop("audience", None)
    body_schema["properties"] = props
    if "required" in body_schema:
        body_schema["required"] = [r for r in body_schema["required"] if r != "audience"]
    body_instance = dict(instance)
    audience_value = body_instance.pop("audience", None)
    return body_schema, body_instance, audience_value


def build_object(schema, instance, *, kind, channel, effect, signer, created,
                  profile=None, audience=None):
    """Build a full naalp.envelope.Object whose body is build_cbor_value(body_schema,
    body_instance), where body_schema/body_instance have any reserved top-level 'audience'
    key removed (see _split_reserved_audience). If `audience` is not explicitly passed and
    the schema/instance carry that reserved key, its instance value becomes the object's
    real audience (field 13); otherwise the object has no audience ("")."""
    body_schema, body_instance, inferred_audience = _split_reserved_audience(schema, instance)
    if audience is None:
        audience = inferred_audience if inferred_audience is not None else ""
    body = build_cbor_value(body_schema, body_instance)
    return envelope.Object(
        kind=kind, channel=channel, effect=effect, profile=profile or cose.PROFILE_PUBLIC,
        signer=signer, created=created, body=body, audience=audience,
    )


class RoundTripResult:
    """The outcome of round_trip(): every field is real evidence from an actual check, not a
    summary flag computed independently of what it reports -- `valid` is a property, never a
    stored bool that could drift from the two checks it combines."""
    __slots__ = ("object", "body_bytes", "byte_consistent", "validation")

    def __init__(self, object_, body_bytes, byte_consistent, validation):
        self.object = object_
        self.body_bytes = body_bytes
        self.byte_consistent = byte_consistent
        self.validation = validation

    @property
    def valid(self):
        return self.byte_consistent and self.validation.valid

    def __repr__(self):
        return "RoundTripResult(valid=%r, byte_consistent=%r, validation=%r)" % (
            self.valid, self.byte_consistent, self.validation)


def round_trip(schema, instance, *, kind, channel, effect, signer, created,
               profile=None, audience=None):
    """Build the object, prove its body round-trips byte-identically through the REAL E0.3
    codec, and validate the whole envelope through the REAL E0.2 semantic validator."""
    obj = build_object(schema, instance, kind=kind, channel=channel, effect=effect,
                        signer=signer, created=created, profile=profile, audience=audience)
    byte_consistent = naalp_codec.verify_roundtrip(obj.body)
    body_bytes = naalp_codec.encode(obj.body)
    validation = naalp_validator.validate(obj)
    return RoundTripResult(
        object_=obj, body_bytes=body_bytes, byte_consistent=byte_consistent, validation=validation)
