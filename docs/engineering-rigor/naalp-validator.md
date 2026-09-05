<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red evidence — N-AALP semantic validator (`ecosystem/naalp-validator/`)

Per the test-driven-development discipline: a test that has never been observed failing is
not known to be a test. This records three real mutations applied to the validator's own
`naalp_validator/*.py` (never Part-1 `impl/python/naalp/*`), each confirmed to flip a named
test RED for the right reason, then restored from a `.bak` copy (never `git checkout`) and
re-confirmed GREEN with `__pycache__` cleared and `PYTHONDONTWRITEBYTECODE=1` set (guarding
against the interpreter bytecode-cache staleness failure mode: a mutate-test-revert cycle
completing within one filesystem-second can leave a stale `.pyc` compiled from the mutant
source, making a byte-clean revert appear to still fail).

Baseline (post-hardening, pre-mutation) SHA-256, confirmed identical before mutation 1 and
after every restore in this document:

| File | SHA-256 |
|---|---|
| `naalp_validator/validator.py` | `40fd14d36d9d452ade0d14d46b19c1329a5170be41d26f80220b9b8a50f77401` |
| `naalp_validator/firewall.py` | `c4ca6931b927e63b86b4b170adf90ac602add6e4de378d5ff26292439737074a` |

Run command for every RED/GREEN check in this document (from `ecosystem/naalp-validator/`,
with `PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` cleared before each re-run):

    <python> -m pytest -v tests/

(`<python>` = the real interpreter's own full path; a bare `python` resolves to a
zero-length Microsoft Store execution-alias stub on this checkout and hangs.)

---

## Mutation 1 — the `TooManyCauses` bounds check (`validator.py`)

**File:** `naalp_validator/validator.py`, the `causes[]` cardinality check inside `validate()`.

**Baseline:**
```python
    if causes_ok and len(obj.causes) > MAX_CAUSES:
        violations.append(Violation(
            "TooManyCauses", "causes[] exceeds the maximum count (%d)" % MAX_CAUSES, field="causes"))
```

**Mutation applied:**
```python
    if causes_ok and len(obj.causes) > MAX_CAUSES and False:  # MUTATION M1: bound check neutralized
        violations.append(Violation(
            "TooManyCauses", "causes[] exceeds the maximum count (%d)" % MAX_CAUSES, field="causes"))
```

**Procedure:** `cp naalp_validator/validator.py naalp_validator/validator.py.bak` →
applied the mutation → ran
`pytest -v tests/test_validator.py::RejectTooManyCauses tests/test_validator.py::MultipleViolationsCollected`
→ confirmed RED → `cp naalp_validator/validator.py.bak naalp_validator/validator.py` →
cleared `__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored
file's SHA-256 matched the baseline exactly.

**Named test that flipped, and the exact failure:**
```
tests/test_validator.py::RejectTooManyCauses::test_causes_over_boundary FAILED
    r = V.validate(_obj(0x0000, 0, 0, causes=[b"c"] * (V.MAX_CAUSES + 1)))
>   self.assertFalse(r.valid)
E   AssertionError: True is not false

tests/test_validator.py::MultipleViolationsCollected::test_unknown_kind_and_too_many_causes_both_reported FAILED
    r = V.validate(_obj(0x0000, 99, 0, causes=[b"c"] * (V.MAX_CAUSES + 1)))
    self.assertFalse(r.valid)
>   self.assertEqual(set(r.errors()), {"UnknownKind", "TooManyCauses"})
E   AssertionError: Items in the second set but not the first:
E   'TooManyCauses'
```
2 tests failed, for the right reason (the neutralized bound silently accepted an
over-boundary `causes[]`; the collect-both-violations test lost exactly the mutated
violation and nothing else).

**Post-restore:** full suite `46 passed, 4 subtests passed`. `validator.py` SHA-256
matched the baseline (`40fd14d3...`) exactly.

---

## Mutation 2 — the effect-class (`EffectDeclarationMismatch`) check (`validator.py`)

**File:** `naalp_validator/validator.py`, the fixed-effect-kind dispatch inside `validate()`.

**Baseline:**
```python
            if effect_in_range:
                try:
                    channels.check_effect(obj.channel, obj.kind, obj.effect)
                except channels.EffectDeclarationMismatch as e:
                    violations.append(Violation("EffectDeclarationMismatch", str(e), field="effect"))
```

**Mutation applied:**
```python
            if effect_in_range:
                try:
                    channels.check_effect(obj.channel, obj.kind, obj.effect)
                except channels.EffectDeclarationMismatch as e:
                    pass  # MUTATION M2: effect-class violation swallowed, never reported
```

**Procedure:** `cp naalp_validator/validator.py naalp_validator/validator.py.bak` →
applied the mutation → ran `pytest -v tests/test_validator.py::RejectEffectDeclarationMismatch`
→ confirmed RED → `cp naalp_validator/validator.py.bak naalp_validator/validator.py` →
cleared `__pycache__` → re-ran the full suite → confirmed GREEN → confirmed the restored
file's SHA-256 matched the baseline exactly.

**Named test that flipped, and the exact failure:**
```
tests/test_validator.py::RejectEffectDeclarationMismatch::test_fixed_effect_kind_wrong_effect FAILED
    # From the CSV oracle: (0x0004, 0) == Governance/PolicyPublish, effect non_idempotent_write (2).
    ...
    r = V.validate(_obj(0x0004, 0, wrong_effect))
>   self.assertFalse(r.valid)
E   AssertionError: True is not false
```
1 test failed, for the right reason (a candidate declaring the wrong fixed effect for a
registered kind was silently accepted once the mismatch exception was swallowed instead
of reported).

**Post-restore:** full suite `46 passed, 4 subtests passed`. `validator.py` SHA-256
matched the baseline (`40fd14d3...`) exactly.

---

## Mutation 3 — the firewall-refuses gate (`firewall.py`)

**File:** `naalp_validator/firewall.py`, `pre_send_hook()`.

**Baseline:**
```python
    result = validator.validate(candidate, self_authority=self_authority)
    return FirewallDecision(allow=result.valid, violations=result.violations)
```

**Mutation applied:**
```python
    result = validator.validate(candidate, self_authority=self_authority)
    return FirewallDecision(allow=True, violations=result.violations)  # MUTATION M3: fail-open
```

**Procedure:** `cp naalp_validator/firewall.py naalp_validator/firewall.py.bak` →
applied the mutation → ran `pytest -v tests/test_firewall.py` → confirmed RED →
`cp naalp_validator/firewall.py.bak naalp_validator/firewall.py` → cleared `__pycache__`
→ re-ran the full suite → confirmed GREEN → confirmed the restored file's SHA-256 matched
the baseline exactly.

**Named tests that flipped (7 of 9 in `test_firewall.py`), and the exact failures:**
```
tests/test_firewall.py::PreSendHook::test_denies_an_unknown_kind FAILED
tests/test_firewall.py::PreSendHook::test_denies_consume_once_without_audience FAILED
tests/test_firewall.py::PreSendHook::test_never_partial_accepts_on_multiple_violations FAILED
tests/test_firewall.py::PreSendHook::test_self_authority_is_threaded_through FAILED
tests/test_firewall.py::FirewallGatesTheGuardedAction::test_deny_on_unknown_kind_prevents_the_guarded_action FAILED
tests/test_firewall.py::FirewallGatesTheGuardedAction::test_deny_on_bounds_violation_prevents_the_guarded_action FAILED
tests/test_firewall.py::FirewallGatesTheGuardedAction::test_deny_on_wrong_audience_prevents_the_guarded_action FAILED
```
every failure was `AssertionError: True is not false` on `self.assertFalse(decision.allow)`
(the `PreSendHook` class) or on `self.assertFalse(decision.allow)` followed by what would
have been a false `sent == []` (the `FirewallGatesTheGuardedAction` class — the mutation
flips the decision before the spy is even consulted, so the guarded action would have
incorrectly run for every one of these denied candidates). 7 of 9 tests failed, for the
right reason: only the two ALREADY-valid-candidate tests
(`test_allows_a_valid_object`, `test_allow_on_valid_object_permits_the_guarded_action`)
were unaffected, because a fail-open gate agrees with a fail-closed gate exactly when
nothing should have been denied in the first place.

**Post-restore:** full suite `46 passed, 4 subtests passed`. `firewall.py` SHA-256
matched the baseline (`c4ca6931...`) exactly.

---

## Summary

| # | File | Check mutated | Named test(s) flipped RED | Restored SHA-256 == baseline |
|---|---|---|---|---|
| M1 | `validator.py` | `TooManyCauses` bound | `RejectTooManyCauses::test_causes_over_boundary`, `MultipleViolationsCollected::test_unknown_kind_and_too_many_causes_both_reported` | yes |
| M2 | `validator.py` | `EffectDeclarationMismatch` dispatch | `RejectEffectDeclarationMismatch::test_fixed_effect_kind_wrong_effect` | yes |
| M3 | `firewall.py` | fail-closed gate (`pre_send_hook`) | 7 of 9 tests in `test_firewall.py`, including all 3 new guarded-action spy tests | yes |

All three mutations were applied only to `naalp_validator/*.py`, restored via `cp` from a
`.bak` copy (never `git checkout`), and re-verified GREEN with `__pycache__` cleared and
`PYTHONDONTWRITEBYTECODE=1` set. No `.bak` file is committed.
