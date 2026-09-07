<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: naalp-a2a-hook (A2A framework-hook adapter)

Mutation-survival evidence for `naalp_a2a_hook/a2a_hook.py`'s property ("verifies INBOUND
before delivery, rejects with a named reason on failure" -- fail CLOSED, never fail open).
Produced by actually editing `naalp_a2a_hook/a2a_hook.py` (never `naalp_kit/binding.py` or
`impl/python/naalp/*`, both out of scope and already separately graded), confirming the named
tests flip RED for the stated reason, then restoring the file from a `.bak` copy (never
`git checkout` -- this tree is uncommitted), clearing `__pycache__`
(`PYTHONDONTWRITEBYTECODE=1` set for every run), and re-running the full 27-test suite GREEN.

Baseline / reverted file hash for `naalp_a2a_hook/a2a_hook.py` (SHA-256), confirmed identical
before the mutation and after the revert:

```
43759b32387fdc38aae23bd9b14c85bb4ac7014cd7eddeb120b8e162f2237f3c
```

Run command (from the repo root, invoking the real installed Python interpreter for this
platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve
ahead of a real install on `PATH` and hang, so invoke the actual interpreter binary directly
rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-a2a-hook/tests/test_a2a_hook.py -v
```

## M1 -- inbound-gating-fails-closed-never-open (`test_on_message_send_gating_denies_before_the_delegate_is_ever_called`, `test_on_message_send_stream_gating_denies_before_any_event_is_yielded`)

**Mutated:** `NaalpA2ARequestHandler._capture_inbound_message`'s gating branch -- the ONE place
this requires a genuine authorization refusal to actually reach the caller as a raised
`policy.PolicyError`, preventing the wrapped delegate's `on_message_send`/`on_message_send_stream`
from ever running:

```diff
         verified = _capture_and_record(
             self._signer, self._recorder, session_key, payload, effect,
         )
         if self._gating:
-            binding.authorize_action(verified, self._grant)  # raises policy.PolicyError, unwrapped
+            pass  # MUTATION M1 (red-evidence, naalp-a2a-hook): swallow the authorization
+            # decision entirely -- the exact fail-OPEN defect this forbids (a gated inbound
+            # message would be delivered to the local agent regardless of its declared effect).
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-a2a-hook/tests/test_a2a_hook.py::test_on_message_send_gating_denies_before_the_delegate_is_ever_called
    Failed: DID NOT RAISE PolicyError

FAILED ecosystem/naalp-a2a-hook/tests/test_a2a_hook.py::test_on_message_send_stream_gating_denies_before_any_event_is_yielded
    Failed: DID NOT RAISE PolicyError

2 failed, 25 passed in 2.69s
```

Both failures are the assertion (`pytest.raises(policy.PolicyError)` never firing), not an
import/collection error -- confirming the tests genuinely exercise the fail-closed property and
would not pass against a fail-open implementation. `test_on_message_send_gating_denies_...`
additionally asserts `delegate.calls == []` after the raise -- with the mutation live, the
`with pytest.raises(...)` block itself fails before that assertion is reached (the call DOES go
through with the mutation, which is precisely the defect), so the raised-`Failed` above is the
first and correct symptom.

**Reverted, confirmed byte-identical (SHA-256 matches the baseline above), full suite GREEN:**

```
27 passed in 2.45s
```

## Non-circularity

Every RED/GREEN run above verifies the recorded signed object independently through
`naalp.ez.verify(signer.public_key, signed_bytes)` -- the same real, already-graded Part-1 core
-- never through `naalp_a2a_hook`'s own bookkeeping. `binding._extract_payload` is reused from a
DIFFERENT, separately-graded sibling module purely to compare the recovered opaque payload bytes;
none of this module's own new code (payload construction from `canonical_proto_bytes`,
session-key/context-id derivation, the gating decision, the `RequestHandler` delegation) is used
to validate itself.
