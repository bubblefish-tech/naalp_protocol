<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP Plan-and-Execute orchestrator

Mutation-survival evidence for three load-bearing properties described below. Each
row was produced by actually editing `naalp_plan/orchestrator.py` (never
`ecosystem/naalp-react/*`, which is out of scope for this task, never
`ecosystem/naalp-validator/*`, which is only imported by this task's own test, and never
`impl/python/naalp/*`, which is Part-1), confirming the named test(s) flip RED for the
stated reason, then restoring the file from a `.bak` copy (never `git checkout`), clearing
`__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode can mask a
mutation or fake a revert), and re-running the full suite GREEN.

Baseline / reverted file hash for `naalp_plan/orchestrator.py` (SHA-256), confirmed
identical before mutation 1 and after every one of the three reverts below:

```
ad9b537851743d728e03ceffc6b08a1da00c7c55af491120a1eb106f972c533e
```

Run command (from `ecosystem/naalp-plan/`, invoking the real installed Python interpreter
for this platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs
resolve ahead of a real install on `PATH` and hang, so on that platform invoke the actual
interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_orchestrator
```

All commands below were run from `ecosystem/naalp-plan/` with `PYTHONDONTWRITEBYTECODE=1`
set and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on
disk at that moment. Baseline (pre-mutation) and every post-revert run: 9/9 tests GREEN.

## M1 -- causal-edge wiring dropped (`test_linear_plan_executes_in_order_with_causal_chain`,
`test_diamond_plan_causal_edges_are_the_set_of_prereqs`)

**Mutated:** `PlanOrchestrator.run()`, the line that sets a node's causal edges to its
prerequisites' signed request content ids:

```diff
-            linked_action = replace(task.action, causes=tuple(request_ids[p] for p in task.prereqs))
+            linked_action = replace(task.action, causes=tuple())  # MUTATION M1 (red-evidence): drop causal-edge wiring
```

**RED, confirmed:**

```
FAIL: test_diamond_plan_causal_edges_are_the_set_of_prereqs
AssertionError: 0 != 2

FAIL: test_linear_plan_executes_in_order_with_causal_chain
AssertionError: Lists differ: [] != [b' 0z\x82\xe6B\xa9\xc8!y\\...']
```

With the wiring dropped, every signed request carries an empty `causes[]` regardless of its
declared prerequisites -- the exact failure this property exists to rule out ("the signed graph is
causally linked exactly as the plan specifies"). Both causal-linkage-dependent tests flipped
(7 of 9 still passed); every other check (execution order, fail-closed propagation) is
independent of this line and was unaffected.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`),
`__pycache__` cleared, hash re-confirmed
`ad9b537851743d728e03ceffc6b08a1da00c7c55af491120a1eb106f972c533e`.
**GREEN, confirmed:** 9/9 tests pass.

## M2 -- the prerequisite-success gate is skipped (`test_prerequisite_refused_observation_blocks_downstream_and_it_is_never_signed`,
`test_executor_failure_refuses_the_node_and_blocks_downstream`, `test_own_request_validation_refusal_blocks_downstream`)

**Mutated:** `PlanOrchestrator.run()`, the check that a node's prerequisites all actually
reached `"executed"` before this node is even built:

```diff
-            unresolved = [p for p in task.prereqs if results[p].status != "executed"]
+            unresolved = []  # MUTATION M2 (red-evidence): skip the prerequisite-success gate entirely
```

**RED, confirmed:**

```
FAIL: test_prerequisite_refused_observation_blocks_downstream_and_it_is_never_signed
AssertionError: 'refused' != 'blocked'

FAIL: test_executor_failure_refuses_the_node_and_blocks_downstream
AssertionError: 'refused' != 'blocked'

ERROR: test_own_request_validation_refusal_blocks_downstream
KeyError: 'A'
    (at) linked_action = replace(task.action, causes=tuple(request_ids[p] for p in task.prereqs))
```

With the gate skipped, a node whose prerequisite refused, failed, or was itself blocked is
attempted anyway: the orchestrator tries to build a downstream node's causal edges from a
prerequisite's request id that was NEVER RECORDED (because that prerequisite's own request
was never signed), producing the `KeyError` above -- the exact bypass these properties
exist to rule out ("a node whose prerequisite refused/failed ... is NOT executed"). Three
of nine tests flipped (one as a direct status assertion in each of two tests, one as an
uncaught `KeyError` in the third, since that particular scenario's downstream node has no
recorded prerequisite id to read at all); the remaining six, whose plans have no refused
prerequisite anywhere, were unaffected.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`ad9b537851743d728e03ceffc6b08a1da00c7c55af491120a1eb106f972c533e`.
**GREEN, confirmed:** 9/9 tests pass.

## M3 -- the cycle check never fires (`test_cyclic_plan_is_rejected_before_any_signing`,
`test_self_loop_is_rejected_as_a_cycle`)

**Mutated:** `_topological_order()`, the length check that distinguishes a complete
topological order from an incomplete one (the definitive sign of a cycle):

```diff
-    if len(order) != len(tasks_by_id):
+    if False:  # MUTATION M3 (red-evidence): never actually detect/reject a cyclic plan
         unresolved = sorted(set(tasks_by_id) - set(order))
         raise PlanError(
             "CyclicPlan", "the plan's task DAG contains a cycle reachable from: %s" % ", ".join(unresolved)
         )
```

**RED, confirmed:**

```
FAIL: test_cyclic_plan_is_rejected_before_any_signing
AssertionError: PlanError not raised

FAIL: test_self_loop_is_rejected_as_a_cycle
AssertionError: PlanError not raised
```

With the check dead, a plan whose task DAG contains a cycle (a mutual A<->B dependency, or a
task naming itself as its own prerequisite) is accepted as if it had a valid execution
order -- `_topological_order()` silently returns whatever partial order Kahn's algorithm
managed to produce (empty, for a pure cycle) instead of rejecting the plan, which is exactly
the failure mode this property rules out: a cycle must be rejected with a named error
BEFORE any node is ever signed. Exactly the two cycle-dependent tests flipped (7 of 9 still
passed); every acyclic plan in the other tests is unaffected because its topological order
is already complete and the dead branch is never reached for it.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`ad9b537851743d728e03ceffc6b08a1da00c7c55af491120a1eb106f972c533e`.
**GREEN, confirmed:** 9/9 tests pass.

## Why these three, and why every mutation targets `orchestrator.py` rather than a
Part-1/sibling primitive

`naalp_plan` builds ON `naalp_react`: every cryptographic and structural check (signature
verification, content-id binding, the audience point-of-use gate, the pre-send validator
hook) is delegated to the real sibling `naalp_react.ReActBridge`, which carries its own
graded red-evidence out of scope for this task. What IS this task's own code, and therefore
what these three mutations target, is the orchestrator's OWN choices: that a node's causal
edges are actually computed from its prerequisites' real signed request ids (M1), that a
node whose prerequisite did not reach "executed" is actually never attempted (M2), and that
a cyclic plan is actually rejected before any node is ever signed (M3). All three are
exactly the properties this orchestrator must get right -- not the underlying
ReAct bridge or the Part-1 SDK.
