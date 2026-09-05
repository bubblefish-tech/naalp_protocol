<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red evidence — N-AALP blessed deterministic-CBOR codec binding (`ecosystem/naalp-codec/`)

Per the test-driven-development discipline: a test that has never been observed failing is
not known to be a test. This records three real mutations applied to the binding's own
`naalp_codec/codec.py` (never Part-1 `impl/python/naalp/*`), each confirmed to flip a
named test RED for the right reason, then restored from a `.bak` copy (never
`git checkout`) and re-confirmed GREEN with `__pycache__` cleared and
`PYTHONDONTWRITEBYTECODE=1` set (guarding against the interpreter bytecode-cache
staleness failure mode: a mutate-test-revert cycle completing within one filesystem-second
can leave a stale `.pyc` compiled from the mutant source, making a byte-clean revert
appear to still fail).

Baseline (post-hardening, pre-mutation) SHA-256, confirmed identical before mutation 1 and
after every restore in this document:

| File | SHA-256 |
|---|---|
| `naalp_codec/codec.py` | `cf816cada04d84ee410921cc6812679c3e0e176ac3c19454251d9f68dd780551` |

Run command for every RED/GREEN check in this document (from `ecosystem/naalp-codec/`,
with `PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` cleared before each re-run):

    <python> -m pytest -v tests/

(`<python>` = the real interpreter's own full path; a bare `python` resolves to a
zero-length Microsoft Store execution-alias stub on this checkout and hangs.)

Baseline (pre-mutation), full suite: **28 passed, 5 subtests passed**.

---

## Mutation 1 — the encode-side bare-float guard (`codec.py`, `encode()`)

**File:** `naalp_codec/codec.py`, `encode()`.

**Baseline:**
```python
def encode(value):
    _reject_bare_float(value)
    return cbor.encode(value)
```

**Mutation applied:**
```python
def encode(value):
    pass  # MUTATION M1: float guard neutralized (_reject_bare_float never called)
    return cbor.encode(value)
```

**Procedure:** `cp naalp_codec/codec.py naalp_codec/codec.py.bak` → applied the mutation →
cleared `__pycache__` → ran
`pytest -v tests/test_codec.py::EncodeSideFailClosed tests/test_codec.py::VerifyRoundtripRealWork::test_propagates_non_canonical_on_a_bare_float`
→ confirmed RED → `cp naalp_codec/codec.py.bak naalp_codec/codec.py` → cleared
`__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored file's
SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_codec.py::EncodeSideFailClosed::test_encode_raises_no_bytes_returned_on_float FAILED
tests/test_codec.py::EncodeSideFailClosed::test_encode_rejects_bare_float_at_top_level FAILED
tests/test_codec.py::EncodeSideFailClosed::test_encode_rejects_bare_float_inside_array FAILED
tests/test_codec.py::EncodeSideFailClosed::test_encode_rejects_bare_float_nested_in_body FAILED
tests/test_codec.py::VerifyRoundtripRealWork::test_propagates_non_canonical_on_a_bare_float FAILED

    def encode(v):
        ...
        if isinstance(v, Tag):
            return _head(6, v.n) + encode(v.content)
>       raise TypeError("not a cbor value: %r" % (v,))
E       TypeError: not a cbor value: 0.87
```
5 tests failed, for the right reason: with the guard bypassed, a bare float reaches
`naalp.cbor.encode` unchanged and that function's own final fallback raises a bare
`TypeError("not a cbor value: ...")` -- fail-closed (no bytes returned), but under the
WRONG name. Every test asserting the specific *registered* error (`NonCanonical`) failed
because a `TypeError` propagated instead; `assertRaises(NonCanonical, ...)` does not catch
an unrelated exception type, so each test failed with that `TypeError` as an unhandled
error, not merely a false assertion.

**Post-restore:** full suite `28 passed, 5 subtests passed`. `codec.py` SHA-256 matched
the baseline (`cf816cada0...`) exactly.

---

## Mutation 2 — `verify_roundtrip()` swallowing every failure into a blanket `True`

**File:** `naalp_codec/codec.py`, `verify_roundtrip()`.

**Baseline:**
```python
    first = encode(value)
    decoded = decode(first)
    second = encode(decoded)
    return first == second
```

**Mutation applied:**
```python
    try:  # MUTATION M2: every failure swallowed, blanket True returned
        first = encode(value)
        decoded = decode(first)
        second = encode(decoded)
        return first == second
    except Exception:
        return True
```

**Procedure:** `cp naalp_codec/codec.py naalp_codec/codec.py.bak` → applied the mutation →
cleared `__pycache__` → ran `pytest -v tests/test_codec.py::VerifyRoundtripRealWork` →
confirmed RED → `cp naalp_codec/codec.py.bak naalp_codec/codec.py` → cleared
`__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored file's
SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_codec.py::VerifyRoundtripRealWork::test_propagates_non_canonical_on_a_bare_float FAILED
tests/test_codec.py::VerifyRoundtripRealWork::test_true_on_a_valid_pinned_value PASSED
tests/test_codec.py::VerifyRoundtripRealWork::test_propagates_type_error_on_a_non_value_input FAILED

    def test_propagates_type_error_on_a_non_value_input(self):
        with self.assertRaises(TypeError):
>           codec.verify_roundtrip(5)
E       AssertionError: TypeError not raised

    def test_propagates_non_canonical_on_a_bare_float(self):
        with self.assertRaises(codec.NonCanonical):
>           codec.verify_roundtrip(codec.M([(codec.U(1), 9.9)]))
E       AssertionError: NonCanonical not raised
```
2 of 3 tests failed, for the right reason: with every exception swallowed and `True`
returned unconditionally, calling `verify_roundtrip` on a raw non-value input (`5`) or on
a value carrying a bare float no longer raises at all -- it reports the same blanket
"safe" verdict a correctly-round-tripping value would get. The one test that did NOT flip
(`test_true_on_a_valid_pinned_value`) is exactly the case where the real implementation and
the "always True" mutant genuinely agree, which is why the other two -- both feeding an
input the real implementation must reject -- are the tests that carry this mutation's
signal.

**Post-restore:** full suite `28 passed, 5 subtests passed`. `codec.py` SHA-256 matched
the baseline (`cf816cada0...`) exactly.

---

## Mutation 3 — `content_id()` stubbed to a constant, ignoring its input

**File:** `naalp_codec/codec.py`, `content_id()`.

**Baseline:**
```python
    if isinstance(value_or_bytes, (U, N, B, T, A, M, Tag)):
        value_or_bytes = encode(value_or_bytes)
    return cbor.content_id(value_or_bytes)
```

**Mutation applied:**
```python
    if isinstance(value_or_bytes, (U, N, B, T, A, M, Tag)):
        value_or_bytes = encode(value_or_bytes)
    return bytes([0x20, 0x30]) + b"\x00" * 48  # MUTATION M3: constant id, input ignored
```

**Procedure:** `cp naalp_codec/codec.py naalp_codec/codec.py.bak` → applied the mutation →
cleared `__pycache__` → ran
`pytest -v tests/test_codec.py::ContentIdVariesWithInput tests/test_codec.py::ByteIdentityAgainstPinnedCorpus`
→ confirmed RED → `cp naalp_codec/codec.py.bak naalp_codec/codec.py` → cleared
`__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored file's
SHA-256 matched the baseline exactly.

**Named tests that flipped, and the exact failures:**
```
tests/test_codec.py::ContentIdVariesWithInput::test_distinct_values_produce_distinct_ids FAILED
tests/test_codec.py::ContentIdVariesWithInput::test_id_is_48_byte_sha384_multihash_with_registered_prefix FAILED
tests/test_codec.py::ByteIdentityAgainstPinnedCorpus::test_content_id_matches_pinned_minimal FAILED
tests/test_codec.py::ByteIdentityAgainstPinnedCorpus::test_content_id_matches_pinned_nested FAILED
tests/test_codec.py::ByteIdentityAgainstPinnedCorpus::test_content_id_over_already_encoded_bytes_agrees_with_over_value FAILED

    def test_distinct_values_produce_distinct_ids(self):
        v1 = codec.M([(codec.U(2), codec.U(0))])
        v2 = codec.M([(codec.U(2), codec.U(1))])
>       self.assertNotEqual(codec.content_id(v1), codec.content_id(v2))
E       AssertionError: b' 0\x00\x00...\x00' == b' 0\x00\x00...\x00'

    def test_content_id_matches_pinned_minimal(self):
        ...
>       self.assertEqual(codec.content_id(value), bytes.fromhex(vec["id_hex"]))
E       AssertionError: b' 0\x00\x00\x00...\x00' != b' 0E\x0c\xec\xcc\x1dC\xb1\xc9\xbd...\xfc'
```
5 tests failed, for the right reason: the stubbed `content_id` returns the identical
50-byte constant regardless of its argument, so two logically different bodies produce the
"same" id (a stub signature -- output identical regardless of input), and the
constructed body no longer matches the pinned, independently-generated reference id at
all.

**Post-restore:** full suite `28 passed, 5 subtests passed`. `codec.py` SHA-256 matched
the baseline (`cf816cada0...`) exactly.

---

## Summary

| # | File | Function mutated | Named test(s) flipped RED | Restored SHA-256 == baseline |
|---|---|---|---|---|
| M1 | `codec.py` | `encode()` (bare-float guard bypassed) | 4 in `EncodeSideFailClosed` + `VerifyRoundtripRealWork::test_propagates_non_canonical_on_a_bare_float` | yes |
| M2 | `codec.py` | `verify_roundtrip()` (every failure swallowed to `True`) | `VerifyRoundtripRealWork::test_propagates_type_error_on_a_non_value_input`, `test_propagates_non_canonical_on_a_bare_float` | yes |
| M3 | `codec.py` | `content_id()` (constant, input ignored) | 2 in `ContentIdVariesWithInput` + 3 in `ByteIdentityAgainstPinnedCorpus` | yes |

All three mutations were applied only to `naalp_codec/codec.py` (never
`impl/python/naalp/*`), restored via `cp` from a `.bak` copy (never `git checkout`), and
re-verified GREEN with `__pycache__` cleared and `PYTHONDONTWRITEBYTECODE=1` set. No
`.bak` file is committed.
