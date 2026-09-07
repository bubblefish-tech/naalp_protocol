<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP multi-agent interaction shapes

Mutation-survival evidence for three load-bearing properties described below. Each row
was produced by actually editing `naalp_multiagent/pipeline.py` or `naalp_multiagent/
fanout.py` (never `ecosystem/naalp-react/*` or `ecosystem/naalp-plan/*`, both out of scope
for this task, and never `impl/python/naalp/*`, which is Part-1), confirming the named test flips RED for the stated reason, then restoring the file
from a `.bak` copy (never `git checkout`), clearing `__pycache__`
(`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode can mask a mutation or
fake a revert), sha256-confirming the restored file matches the pre-mutation baseline, and
re-running the full suite GREEN.

Baseline / reverted file hashes (SHA-256), confirmed identical before mutation and after
every revert below:

```
naalp_multiagent/pipeline.py  d5c3b50d3ee8ca8c8fced4abb0f9b521224c8f577e5878f8019402035e6bddda
naalp_multiagent/fanout.py    a58b4df9b7a113c5760824a07d77525b1064329ce4a24145d3a23411b1aff95a
```

Run command (from `ecosystem/naalp-multiagent/`, invoking the real installed Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on `PATH` and hang, so on that platform
invoke the actual interpreter binary directly by its own install path rather than the bare
`python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_pipeline tests.test_fanout tests.test_reconcile
```

All commands below were run from `ecosystem/naalp-multiagent/` with `PYTHONDONTWRITEBYTECODE=1`
set and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on
disk at that moment. Baseline (pre-mutation) and every post-revert run: 14/14 tests GREEN
(`test_pipeline` 4, `test_fanout` 4, `test_reconcile` 6).

## M1 -- causal-edge wiring dropped in the sequential pipeline
(`test_three_stage_pipeline_runs_in_order_with_causal_chain`)

**Mutated:** `pipeline.py`, `SequentialPipeline.run()` -- the line that sets a stage's causal
edge to its predecessor's signed request content id:

```diff
                 action = stage.build_action(prev_observation)
-                causes = (prev_request_id,) if prev_request_id is not None else ()
+                causes = ()  # MUTATION M1 (red-evidence): drop causal-edge wiring to the prior stage
                 linked_action = replace(action, causes=causes)
```

**RED, confirmed** (1 of 4 `test_pipeline` tests flipped):

```
FAIL: test_three_stage_pipeline_runs_in_order_with_causal_chain
AssertionError: Lists differ: [] != [b' 0p\xb0uY\xaf\xa6\xa8F\xb7\x14\xd4\xa3]...']
```

With the wiring dropped, every stage's signed request carries an empty `causes[]` regardless
of which agent preceded it -- the exact failure this property exists to rule out ("agent A's signed
output feeds agent B feeds C", causally). The other three tests were unaffected:
`test_single_stage_pipeline_has_no_prior_observation_and_empty_causes` expects empty causes
anyway (no predecessor exists), `test_stage_refusal_blocks_downstream_and_it_is_never_
signed_or_run` does not assert on causal-edge VALUES, and `test_downstream_build_action_
receives_prior_observation_body` asserts on the Observation body, not on `causes`.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`),
`__pycache__` cleared, hash re-confirmed
`d5c3b50d3ee8ca8c8fced4abb0f9b521224c8f577e5878f8019402035e6bddda`.
**GREEN, confirmed:** 4/4 `test_pipeline` tests pass (14/14 full suite).

## M2 -- an excluded branch is included in the reconciled graph anyway
(`test_branch_failing_verification_is_excluded_with_a_named_error`)

**Mutated:** `fanout.py`, `ParallelFanout.run()` -- the `else` (non-"executed") branch of the
per-branch classification loop, which is supposed to record the branch as `"excluded"` and
never add its content id to `graph_nodes`:

```diff
                 branch_results[b.agent_id] = BranchResult(
                     agent_id=b.agent_id, status="excluded",
                     request=attempt.request, observation=attempt.observation,
                     error=error_name, detail=attempt.detail,
                 )
+                graph_nodes.append(CausalNode(id=attempt.request.id, causes=[shared_input_id]))  # MUTATION M2 (red-evidence): include an excluded branch's node in the reconciled graph anyway

         order = reconcile_nodes(graph_nodes)
```

**RED, confirmed** (1 of 4 `test_fanout` tests flipped):

```
FAIL: test_branch_failing_verification_is_excluded_with_a_named_error
AssertionError: b' 0\xaa.\x82\xa0\xd7\x02...' unexpectedly found in (... 5-element tuple ...)
```

With the exclusion skipped, the WrongAudience branch's own request content id -- despite
`branch_results["agent-bad"].status == "excluded"` still being correctly reported -- is
wrongly folded into the reconciled causal graph and appears in `reconciled_order`, exactly
the failure this property exists to rule out ("a branch failing verification is excluded ...
never included with a fabricated causal edge"). The other three `test_fanout` tests were
unaffected: `test_fanout_branches_all_causally_link_to_the_shared_input` and
`test_reconcile_order_is_deterministic_across_many_runs` have no excluded branch in their
scenario (the `else` arm is never reached), and `test_duplicate_agent_id_is_a_named_error_
before_any_branch_runs` fails before any branch ever runs.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`a58b4df9b7a113c5760824a07d77525b1064329ce4a24145d3a23411b1aff95a`.
**GREEN, confirmed:** 4/4 `test_fanout` tests pass (14/14 full suite).

## M3 -- the reconcile step is bypassed; order follows thread-completion time
(`test_reconcile_order_is_deterministic_across_many_runs`)

**Mutated:** `fanout.py`, `ParallelFanout.run()` -- the line that hands the causal graph to
the real Part-1 reconcile primitive, replaced with an order built directly from `attempts`
(a dict populated inside the `as_completed()` loop, so its insertion order IS thread
completion order -- nondeterministic run to run under the branches' randomized jitter):

```diff
-        order = reconcile_nodes(graph_nodes)
+        order = (shared_input_id,) + tuple(  # MUTATION M3 (red-evidence): bypass the Part-1 reconcile primitive; order by thread-completion time instead of the deterministic linearization
+            a.request.id for a in attempts.values() if a.status == "executed"
+        )
         return FanoutRun(shared_input_id=shared_input_id, branch_results=branch_results, reconciled_order=order)
```

**RED, confirmed** (1 of 4 `test_fanout` tests flipped):

```
FAIL: test_reconcile_order_is_deterministic_across_many_runs
AssertionError: Lists differ: [b' 0...', b' 0\x85\x15\xd3O9\xa3Ke...'] != [b' 0...', b' 0C\x07\xd6\x94C\x9c@Cj...']
```

The failure lands on the test's second, independent assertion -- that the order really IS
the bytewise-ascending content-id tie-break (computed by sorting the executed branches'
request ids independently of the fan-out) -- rather than always on the "N repeated runs
agree with each other" loop: since `ThreadPoolExecutor` scheduling for a small, fast branch
set can occasionally land in the same completion order across a handful of consecutive
invocations by chance, the "N runs agree with each other" check alone is not a fully
reliable RED signal for this specific mutation; the independently-computed sorted-order
comparison is what reliably catches it, and did. This is exactly the failure this property
exists to rule out: with the real Part-1 primitive bypassed, the reconciled order is a
function of scheduling timing, not of the causal graph's content ids -- so it would silently
vary between two runs of the identical parallel set whenever thread timing genuinely differs.
The other three `test_fanout` tests were unaffected (none of them compares two runs'
`reconciled_order`, and `test_branch_failing_verification_is_excluded_with_a_named_error`'s
own `assertNotIn` still holds because the excluded branch is correctly absent from
`attempts`' "executed" subset regardless of ordering).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`a58b4df9b7a113c5760824a07d77525b1064329ce4a24145d3a23411b1aff95a`.
**GREEN, confirmed:** 4/4 `test_fanout` tests pass (14/14 full suite).

## A note on a real, witnessed concurrency defect this task's own design surfaced

Before any of the three mutations above, `ParallelFanout`'s first real run under genuine
`ThreadPoolExecutor` concurrency produced corrupted ML-DSA signatures (`BadSignature`) on 3
of 5 branches. This was diagnosed, not assumed: an isolated repro with NO
`naalp_multiagent` code involved -- 8 threads, each looping `naalp.cose.mldsa_sign` +
`naalp.cose.mldsa_verify` with distinct seeds/messages, no lock -- reproduced 65 failed
verifications out of 160 calls. The cause is that the Part-1 Python reference SDK's ML-DSA
backend (`dilithium_py`) exposes `ML_DSA_65`/`ML_DSA_87` as process-wide singleton objects
that are not thread-safe; `naalp_plan.PlanOrchestrator` never surfaces this because it signs
sequentially in one thread, and `ParallelFanout` is this ecosystem's first genuinely
concurrent caller. This is a Part-1 SDK defect out of this task's scope to fix (the task
scopes edits strictly to a new `ecosystem/` package; `impl/` is import-only). The scoped
mitigation is `naalp_multiagent.CRYPTO_LOCK`, a module-level (process-wide) lock that
serializes only the two calls into the shared backend (`bridge.action_to_request` /
`bridge.response_to_observation`), leaving branch dispatch and the injected `executor` I/O
genuinely concurrent; it is exported so a caller whose own `executor`/`build_action` also
calls `naalp.envelope`/`naalp.cose` locally (as this task's own test harness does, to
simulate a remote counterpart in-process) can serialize against the same lock. See
`fanout.py`'s module docstring for the full writeup. This finding is real, load-bearing,
and belongs to Part-1, not to this package.
