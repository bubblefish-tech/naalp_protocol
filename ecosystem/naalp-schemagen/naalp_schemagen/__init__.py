# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_schemagen -- the N-AALP AI-native JSON-Schema-to-N-AALP tool (Part-2 ecosystem E1.5, R10).

    from naalp_schemagen import generate_cddl, generate_validator, round_trip

    result = generate_cddl(schema, "naalp-body-my-kind")
    print(result.cddl)
    for w in result.warnings:
        print(w.code, w.path, w.message)

    validator = generate_validator(schema)
    outcome = validator.validate(instance)

    rt = round_trip(schema, instance, kind=0, channel=0x0000, effect=0,
                     signer=b"...", created=1785000000000)
    assert rt.valid

See `generator.py` for JSON-Schema(2020-12)->CDDL + warnings, `jsonschema_core.py` for the
hand-rolled 2020-12 core-subset instance validator, and `roundtrip.py` for the
schema->object->codec->validator proof. Reuses `naalp-codec` (E0.3) and `naalp-validator`
(E0.2) for every byte-level and semantic-envelope operation; defines no third codec or
validator. See `prompts.py` for the LLM prompt-template pack (item 5).
"""
from .generator import (  # noqa: F401
    EFFECTING_WITHOUT_AUDIENCE, FLOAT_FORBIDDEN, UNBOUNDED, UNMAPPABLE,
    GenResult, GenWarning, SchemaGenRefusal, SchemaValidator,
    generate_cddl, generate_validator,
)
from .jsonschema_core import SchemaError, ValidationOutcome, Violation, validate_instance  # noqa: F401
from .roundtrip import (  # noqa: F401
    NaalpUnrepresentable, RoundTripResult, build_cbor_value, build_object, round_trip,
)
from .prompts import list_prompts, load_prompt  # noqa: F401

__all__ = [
    "generate_cddl", "generate_validator", "GenResult", "GenWarning", "SchemaGenRefusal",
    "SchemaValidator", "UNBOUNDED", "FLOAT_FORBIDDEN", "EFFECTING_WITHOUT_AUDIENCE", "UNMAPPABLE",
    "validate_instance", "ValidationOutcome", "Violation", "SchemaError",
    "build_cbor_value", "build_object", "round_trip", "RoundTripResult", "NaalpUnrepresentable",
    "list_prompts", "load_prompt",
]

__version__ = "0.1.0"
