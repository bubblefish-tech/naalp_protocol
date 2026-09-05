<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red evidence — N-AALP AI-native schema generator (`ecosystem/naalp-schemagen/`)

Per the test-driven-development discipline: a test that has never been observed failing is
not known to be a test. This records five real mutations applied to this package's own
`naalp_schemagen/*.py` (never `impl/python/naalp/*`, never the sibling `naalp-codec`/
`naalp-validator` packages), each confirmed to flip a named test RED for the right reason,
then restored from a `.bak` copy (never `git checkout`) and re-confirmed GREEN with
`__pycache__` cleared and `PYTHONDONTWRITEBYTECODE=1` set (guarding against the interpreter
bytecode-cache staleness failure mode: a mutate-test-revert cycle completing within one
filesystem-second can leave a stale `.pyc` compiled from the mutant source, making a
byte-clean revert appear to still fail).

Baseline (post-hardening, pre-mutation) SHA-256, confirmed identical before mutation 1 and
after every restore in this document:

| File | SHA-256 |
|---|---|
| `naalp_schemagen/generator.py` | `96991e97789edcadbef0828aa2e63717a6c38a01319394e89e13aa26527af082` |
| `naalp_schemagen/jsonschema_core.py` | `84aeb96bbad636946390fc22a0ddc38425a237fa4d41cfff5a7b3144768937fc` |
| `naalp_schemagen/roundtrip.py` | `c6e8318069e1d6149c34db027e6001571f340489723f1ac0d5d93ad2452815f8` |

Run command for every RED/GREEN check in this document (from `ecosystem/naalp-schemagen/`,
with `PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` cleared before each re-run):

    <python> -m pytest -v tests/

(`<python>` = the real interpreter's own full path; a bare `python` resolves to a
zero-length Microsoft Store execution-alias stub on this checkout and hangs.)

Baseline (pre-mutation), full suite: **81 passed**.

---

## Mutation 1 — the generator ignores the schema, constant output (`generator.py`)

**File:** `naalp_schemagen/generator.py`, `_walk_and_collect()`.

**Baseline:**
```python
    if not isinstance(schema, dict):
        raise SchemaError("schema at %s must be a dict, got %r" % (path, type(schema).__name__))

    _check_unmappable_keywords(schema, path, warnings)
```

**Mutation applied:**
```python
    if not isinstance(schema, dict):
        raise SchemaError("schema at %s must be a dict, got %r" % (path, type(schema).__name__))

    return "any"  # MUTATION M1: generator ignores the schema, constant output

    _check_unmappable_keywords(schema, path, warnings)
```

**Procedure:** `cp naalp_schemagen/generator.py naalp_schemagen/generator.py.bak` → applied
the mutation → cleared `__pycache__` → ran `pytest -v tests/test_generator.py::BasicTypeMapping`
→ confirmed RED → `cp naalp_schemagen/generator.py.bak naalp_schemagen/generator.py` →
cleared `__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored
file's SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failure:**
```
tests/test_generator.py::BasicTypeMapping::test_array_with_max_items_produces_bounded_occurrence FAILED
tests/test_generator.py::BasicTypeMapping::test_const_produces_literal FAILED
tests/test_generator.py::BasicTypeMapping::test_different_schemas_produce_different_cddl FAILED
tests/test_generator.py::BasicTypeMapping::test_enum_produces_alternation FAILED
tests/test_generator.py::BasicTypeMapping::test_integer_type_produces_a_range FAILED
tests/test_generator.py::BasicTypeMapping::test_object_with_required_and_optional_fields FAILED
tests/test_generator.py::BasicTypeMapping::test_string_type_produces_tstr FAILED
tests/test_generator.py::BasicTypeMapping::test_union_type_produces_alternation_per_branch FAILED

    def test_string_type_produces_tstr(self):
        r = G.generate_cddl({"type": "string", "maxLength": 10}, "x")
>       self.assertIn("tstr", r.cddl)
E       AssertionError: 'tstr' not found in 'x = any\n'
```
All 8 tests in `BasicTypeMapping` failed, for the right reason: every schema -- object,
array, string, integer, enum, const, union -- produced the identical `"x = any\n"` output,
a textbook stub signature (output identical regardless of input).

**Post-restore:** full suite `81 passed`. `generator.py` SHA-256 matched the baseline
(`96991e97...`) exactly.

---

## Mutation 2 — the float-forbidden warning dropped (`generator.py`)

**File:** `naalp_schemagen/generator.py`, the `"number"` branch inside `_walk_and_collect()`.

**Baseline:**
```python
    if t == "number":
        warnings.append(GenWarning(
            FLOAT_FORBIDDEN, path,
            "'number' allows non-integer values, which have no representation in the N-AALP "
            "deterministic-CBOR value model (RFC 8949 sec.4.2.1; naalp.cbor defines only "
            "U/N/B/T/A/M/Tag, no float wrapper) -- use 'integer' with explicit bounds instead"))
        return "float64  ; UNSAFE: forbidden on the N-AALP wire, see warnings"
```

**Mutation applied:**
```python
    if t == "number":
        pass  # MUTATION M2: float-forbidden warning dropped, never appended
        return "float64  ; UNSAFE: forbidden on the N-AALP wire, see warnings"
```

**Procedure:** `cp naalp_schemagen/generator.py naalp_schemagen/generator.py.bak` → applied
the mutation → cleared `__pycache__` → ran
`pytest -v tests/test_generator.py::FloatWarning tests/test_generator.py::StrictModeRefusal::test_strict_refuses_float`
→ confirmed RED → `cp naalp_schemagen/generator.py.bak naalp_schemagen/generator.py` →
cleared `__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored
file's SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_generator.py::FloatWarning::test_number_type_warns_float_forbidden FAILED
    r = G.generate_cddl({"type": "number"}, "x")
>   self.assertIn(G.FLOAT_FORBIDDEN, {w.code for w in r.warnings})
E   AssertionError: 'FloatForbidden' not found in set()

tests/test_generator.py::StrictModeRefusal::test_strict_refuses_float FAILED
    with self.assertRaises(G.SchemaGenRefusal) as ctx:
E   AssertionError: SchemaGenRefusal not raised
```
2 tests failed, for the right reason: with the warning silently dropped, a `"number"` schema
(the wire-forbidden float type) produced zero warnings, so strict mode -- which only refuses
when warnings exist -- no longer refused it either. `FloatWarning::test_integer_type_does_not_warn_float_forbidden`
correctly stayed green (an integer never triggered this warning either way).

**Post-restore:** full suite `81 passed`. `generator.py` SHA-256 matched the baseline
(`96991e97...`) exactly.

---

## Mutation 3 — strict mode never refuses (`generator.py`)

**File:** `naalp_schemagen/generator.py`, `generate_cddl()`.

**Baseline:**
```python
    body = _walk_and_collect(schema, "$", warnings)
    _check_effecting_audience(schema, warnings)
    if strict and warnings:
        raise SchemaGenRefusal(warnings)
```

**Mutation applied:**
```python
    body = _walk_and_collect(schema, "$", warnings)
    _check_effecting_audience(schema, warnings)
    if strict and warnings and False:  # MUTATION M3: strict mode never refuses
        raise SchemaGenRefusal(warnings)
```

**Procedure:** `cp naalp_schemagen/generator.py naalp_schemagen/generator.py.bak` → applied
the mutation → cleared `__pycache__` → ran `pytest -v tests/test_generator.py::StrictModeRefusal`
→ confirmed RED → `cp naalp_schemagen/generator.py.bak naalp_schemagen/generator.py` →
cleared `__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored
file's SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_generator.py::StrictModeRefusal::test_strict_refuses_unbounded_array FAILED
tests/test_generator.py::StrictModeRefusal::test_strict_refuses_float FAILED
tests/test_generator.py::StrictModeRefusal::test_strict_refuses_effecting_without_audience FAILED
    with self.assertRaises(G.SchemaGenRefusal) as ctx:
E   AssertionError: SchemaGenRefusal not raised
```
3 of 6 tests in `StrictModeRefusal` failed, for the right reason: every schema that should
have been refused in strict mode (unbounded array, float, effecting-without-audience) was
instead silently accepted with warnings recorded but never enforced. The 3 that did NOT flip
are exactly the ones this mutation does not touch: `test_strict_does_not_refuse_a_clean_schema`
and `test_non_strict_does_not_refuse_unbounded_array` never expected a refusal in the first
place, and `test_strict_refusal_also_applies_to_generate_validator` asserts its refusal via
`generate_validator()`'s own (unmutated) strict check, not `generate_cddl()`'s.

**Post-restore:** full suite `81 passed`. `generator.py` SHA-256 matched the baseline
(`96991e97...`) exactly.

---

## Mutation 4 — the missing-required-property check neutralized (`jsonschema_core.py`)

**File:** `naalp_schemagen/jsonschema_core.py`, `_walk_object()`.

**Baseline:**
```python
    for name in required:
        if not isinstance(name, str):
            raise SchemaError("'required' entries must be strings, got %r" % (name,))
        if name not in instance:
            violations.append(Violation(path, "missing required property %r" % (name,)))
```

**Mutation applied:**
```python
    for name in required:
        if not isinstance(name, str):
            raise SchemaError("'required' entries must be strings, got %r" % (name,))
        if name not in instance and False:  # MUTATION M4: required-property check neutralized
            violations.append(Violation(path, "missing required property %r" % (name,)))
```

**Procedure:** `cp naalp_schemagen/jsonschema_core.py naalp_schemagen/jsonschema_core.py.bak`
→ applied the mutation → cleared `__pycache__` → ran
`pytest -v tests/test_jsonschema_core.py::RejectMissingRequired tests/test_jsonschema_core.py::CollectAllViolations`
→ confirmed RED → `cp naalp_schemagen/jsonschema_core.py.bak naalp_schemagen/jsonschema_core.py`
→ cleared `__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored
file's SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_jsonschema_core.py::RejectMissingRequired::test_missing_required_property_is_a_violation FAILED
    outcome = J.validate_instance(schema, {})
>   self.assertFalse(outcome.valid)
E   AssertionError: True is not false

tests/test_jsonschema_core.py::CollectAllViolations::test_multiple_violations_reported_together FAILED
    self.assertIn("missing required property 'c'", messages)
E   AssertionError: "missing required property 'c'" not found in
    "string length 7 exceeds maxLength=2 | value 99 exceeds maximum=5 | unexpected additional property 'd' (additionalProperties is false)"
```
A full-suite run under this mutation confirmed exactly `2 failed, 79 passed`: the missing
instance in `RejectMissingRequired` was silently accepted, and `CollectAllViolations`'s
combined case lost exactly the one violation the mutation neutralized, keeping its other
three (maxLength, maximum, additionalProperties) intact -- confirming the collect-all
mechanism itself was untouched by this mutation.

**Post-restore:** full suite `81 passed`. `jsonschema_core.py` SHA-256 matched the baseline
(`84aeb96bba...`) exactly.

---

## Mutation 5 — the round-trip builder ignores the instance, constant body (`roundtrip.py`)

**File:** `naalp_schemagen/roundtrip.py`, `build_cbor_value()`.

**Baseline:**
```python
    t = schema.get("type") if isinstance(schema, dict) else None
    if t is None:
        t = _infer_type(instance)
    if isinstance(t, list):
        ...
```

**Mutation applied:**
```python
    return naalp_codec.T("constant")  # MUTATION M5: instance ignored, constant CBOR value

    t = schema.get("type") if isinstance(schema, dict) else None
    if t is None:
        t = _infer_type(instance)
    if isinstance(t, list):
        ...
```

**Procedure:** `cp naalp_schemagen/roundtrip.py naalp_schemagen/roundtrip.py.bak` → applied
the mutation → cleared `__pycache__` → ran `pytest -v tests/test_roundtrip.py` → confirmed
RED → `cp naalp_schemagen/roundtrip.py.bak naalp_schemagen/roundtrip.py` → cleared
`__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored file's
SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_roundtrip.py::SchemaARoundTrip::test_a_second_conforming_instance_produces_different_bytes FAILED
tests/test_roundtrip.py::SchemaARoundTrip::test_body_actually_reflects_the_instance_not_a_constant FAILED
tests/test_roundtrip.py::SchemaBRoundTrip::test_audience_is_not_duplicated_inside_the_body FAILED
    keys = {k.v for k, _ in rt.object.body.pairs}
>   AttributeError: 'T' object has no attribute 'pairs'

tests/test_roundtrip.py::UnrepresentableTypesRefused::test_boolean_instance_refused FAILED
tests/test_roundtrip.py::UnrepresentableTypesRefused::test_null_instance_refused FAILED
tests/test_roundtrip.py::UnrepresentableTypesRefused::test_number_type_refused_even_for_a_whole_value FAILED
tests/test_roundtrip.py::UnrepresentableTypesRefused::test_type_mismatch_refused FAILED
    with self.assertRaises(R.NaalpUnrepresentable):
E   AssertionError: NaalpUnrepresentable not raised
```
7 of 12 tests in `test_roundtrip.py` failed, for the right reason: every call to
`build_cbor_value` -- regardless of schema type or instance shape -- returned the identical
`naalp_codec.T("constant")` value (a textbook stub signature). This broke structural
assertions expecting a `naalp_codec.M` map with real body keys (`AttributeError` on `.pairs`,
since a `T` has no such attribute), broke the byte-distinctness check between two different
instances, and silently accepted every JSON-Schema type this codec's value model cannot
represent (boolean/null/number/type-mismatch), since the constant-returning stub never
reaches the type-dispatch code that refuses them. The 5 unaffected tests in the same file
(`SchemaARoundTrip::test_conforming_instance_round_trips_byte_consistently_and_validates`,
`test_schema_violating_instance_is_rejected_by_the_generated_validator`, and the 3
`SchemaBRoundTrip` tests not listed above) either check the schema-level validator directly
(never touching `build_cbor_value`) or happen not to inspect body structure/type-refusal --
exactly the tests this mutation does not reach.

**Post-restore:** full suite `81 passed`. `roundtrip.py` SHA-256 matched the baseline
(`c6e8318069...`) exactly.

---

## Summary

| # | File | Function mutated | Named test(s) flipped RED | Restored SHA-256 == baseline |
|---|---|---|---|---|
| M1 | `generator.py` | `_walk_and_collect()` (constant `"any"` output) | 8 in `BasicTypeMapping` | yes |
| M2 | `generator.py` | `"number"` branch (float warning dropped) | `FloatWarning::test_number_type_warns_float_forbidden`, `StrictModeRefusal::test_strict_refuses_float` | yes |
| M3 | `generator.py` | `generate_cddl()` (strict mode never refuses) | 3 in `StrictModeRefusal` | yes |
| M4 | `jsonschema_core.py` | `_walk_object()` (required check neutralized) | `RejectMissingRequired::test_missing_required_property_is_a_violation`, `CollectAllViolations::test_multiple_violations_reported_together` | yes |
| M5 | `roundtrip.py` | `build_cbor_value()` (constant body, instance ignored) | 7 in `test_roundtrip.py` (structural + all 4 `UnrepresentableTypesRefused`) | yes |

All five mutations were applied only to `naalp_schemagen/*.py` (never `impl/python/naalp/*`
or the sibling `naalp-codec`/`naalp-validator` packages), restored via `cp` from a `.bak`
copy (never `git checkout`), and re-verified GREEN with `__pycache__` cleared and
`PYTHONDONTWRITEBYTECODE=1` set. No `.bak` file is committed.
