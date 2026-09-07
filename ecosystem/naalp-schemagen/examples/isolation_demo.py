# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for naalp_schemagen: concrete input -> concrete output,
independent of any other component -- just naalp_schemagen called directly on a JSON
Schema, an instance, and (for the round trip) a (kind, channel, effect) triple.

Run:  python examples/isolation_demo.py   (from ecosystem/naalp-schemagen/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import naalp_schemagen as ns  # noqa: E402  (puts the ecosystem siblings + impl/python on sys.path)

_SIGNER = bytes.fromhex("5349474e45525f41")
_CREATED = 1785000000000


def main():
    print("=== naalp-schemagen -- isolation demo ===\n")

    # 1. A bounded, read-only JSON Schema (2020-12) for an object body -> generate CDDL.
    schema = {
        "type": "object",
        "x-naalp-effect": "read_only",
        "properties": {
            "task_id": {"type": "string", "maxLength": 64},
            "priority": {"type": "integer", "minimum": 0, "maximum": 10},
            "tags": {
                "type": "array",
                "items": {"type": "string", "maxLength": 32},
                "maxItems": 8,
            },
        },
        "required": ["task_id", "priority"],
        "additionalProperties": False,
    }
    result = ns.generate_cddl(schema, "naalp-body-task-note")
    print("1. Generated CDDL for a bounded, read-only object-body schema:")
    print(result.cddl)
    print("   warnings:", result.warnings)
    assert result.warnings == []

    # 2. The generated Python validation function: a conforming instance passes.
    validator = ns.generate_validator(schema)
    good_instance = {"task_id": "abc123", "priority": 7, "tags": ["urgent", "review"]}
    outcome = validator.validate(good_instance)
    print("\n2. Validating a conforming instance:")
    print("   instance =", good_instance)
    print("   valid    =", outcome.valid)
    assert outcome.valid

    # 3. The same generated validator rejects a schema-violating instance.
    bad_instance = {"task_id": "abc123", "priority": 99}  # priority exceeds maximum=10
    bad_outcome = validator.validate(bad_instance)
    print("\n3. Validating a schema-violating instance:")
    print("   instance =", bad_instance)
    print("   valid    =", bad_outcome.valid)
    for v in bad_outcome.violations:
        print("   violation: path=%-10s %s" % (v.path, v.message))
    assert not bad_outcome.valid

    # 4. Round trip: schema + conforming instance -> real naalp.envelope.Object -> the real
    #    E0.3 codec (byte-consistency) -> the real E0.2 semantic validator (envelope checks).
    rt = ns.round_trip(
        schema, good_instance, kind=0, channel=0x0000, effect=0,
        signer=_SIGNER, created=_CREATED,
    )
    print("\n4. Round trip (Control/Hello, read-only, no audience needed):")
    print("   byte_consistent   =", rt.byte_consistent)
    print("   validation.valid  =", rt.validation.valid)
    print("   rt.valid          =", rt.valid)
    print("   body_bytes (hex)  =", rt.body_bytes.hex())
    assert rt.valid

    # 5. An EFFECTING schema warns if it forgets the reserved 'audience' property.
    unsafe_schema = {
        "type": "object",
        "x-naalp-effect": "non_idempotent_write",
        "properties": {"resource_id": {"type": "string", "maxLength": 64}},
        "required": ["resource_id"],
        "additionalProperties": False,
    }
    unsafe_result = ns.generate_cddl(unsafe_schema, "naalp-body-unsafe-consume")
    print("\n5. An effecting schema missing 'audience' -- generator warnings:")
    for w in unsafe_result.warnings:
        print("   warning: code=%-24s path=%-4s %s" % (w.code, w.path, w.message))
    assert {w.code for w in unsafe_result.warnings} == {ns.EFFECTING_WITHOUT_AUDIENCE}

    # 6. strict mode refuses the same schema outright instead of merely warning.
    try:
        ns.generate_cddl(unsafe_schema, "naalp-body-unsafe-consume", strict=True)
        raise AssertionError("strict mode should have refused")
    except ns.SchemaGenRefusal as e:
        print("\n6. strict=True refuses the same schema:")
        print("   refusal:", e)

    # 7. The FIXED schema (with a reserved 'audience' property) round-trips through the real
    #    consume-once kind (Governance/Consume, channel 0x0004 kind 3) with the audience
    #    correctly lifted into the object's real envelope field -- never duplicated in body.
    consume_schema = {
        "type": "object",
        "x-naalp-effect": "non_idempotent_write",
        "properties": {
            "audience": {"type": "string", "maxLength": 128},
            "resource_id": {"type": "string", "maxLength": 64},
            "quantity": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        "required": ["audience", "resource_id", "quantity"],
        "additionalProperties": False,
    }
    consume_instance = {"audience": "ledger-authority-7", "resource_id": "res-42", "quantity": 3}
    consume_rt = ns.round_trip(
        consume_schema, consume_instance, kind=3, channel=0x0004, effect=2,
        signer=_SIGNER, created=_CREATED,
    )
    print("\n7. Round trip for the fixed consume-once schema:")
    print("   object.audience =", repr(consume_rt.object.audience))
    body_keys = sorted(k.v for k, _ in consume_rt.object.body.pairs)
    print("   body keys       =", body_keys)
    print("   rt.valid        =", consume_rt.valid)
    assert consume_rt.valid
    assert consume_rt.object.audience == "ledger-authority-7"
    assert "audience" not in body_keys

    # 8. Defense in depth: even without the schema-authoring fix, the REAL E0.2 semantic
    #    validator independently rejects the resulting consume-once object at the envelope
    #    layer (WrongAudience) -- two independent gates, not one gate wearing two names.
    unsafe_instance = {"resource_id": "res-1", "quantity": 1}
    unsafe_rt = ns.round_trip(
        unsafe_schema, unsafe_instance, kind=3, channel=0x0004, effect=2,
        signer=_SIGNER, created=_CREATED,
    )
    print("\n8. Same missing-audience shape, forced through round_trip anyway:")
    print("   validation.valid =", unsafe_rt.validation.valid)
    print("   validation.errors =", unsafe_rt.validation.errors())
    assert unsafe_rt.validation.errors() == ["WrongAudience"]

    # 9. The LLM prompt pack is real, loadable content.
    print("\n9. Available LLM prompt templates:", ns.list_prompts())
    for name in ns.list_prompts():
        text = ns.load_prompt(name)
        print("   %-24s %d characters" % (name, len(text)))
        assert len(text) > 200

    print("\n=== all isolation assertions held ===")


if __name__ == "__main__":
    main()
