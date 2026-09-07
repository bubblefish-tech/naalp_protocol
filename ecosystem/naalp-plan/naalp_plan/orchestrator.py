# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP Plan-and-Execute orchestrator (Part-2 ecosystem task E1.2, requirement R2.2).

requirements.md R2.2: given a plan -- a DAG of tasks, each with a name, an effect class,
args, and a set of prerequisite task ids -- the orchestrator converts each node to a real
signed N-AALP request object, sets its causal edges (`causes[]`) to the content ids of its
prerequisite nodes' request objects, executes nodes in a valid topological order, and is
fail-closed: a node whose prerequisite refused/failed (or whose own request cannot be
signed/validated) is NOT executed, and a cycle in the plan is rejected with a named error
before any signing.

    Plan (Task DAG) -> PlanOrchestrator.run() -> a PlanRun: per-task NodeResult, in the
                                                   topological order actually executed.

This module performs NO cryptography, NO CBOR encoding, and NO second content-id
computation of its own: every signed-object-level operation (canonical encoding,
content-id binding, deterministic ML-DSA sign/verify, the audience point-of-use gate, the
causal-linkage check on a response) is the real sibling `naalp_react.ReActBridge`'s own
`action_to_request` / `response_to_observation`, which in turn is the real Part-1
`naalp.envelope` primitive (design.md "Buy-before-make"; this module is DAG-scheduling and
fail-closed-propagation glue, not a second copy of the ReAct bridge or the envelope/COSE
primitive it wraps).

Design choice -- the causal graph here is a PLAN-LEVEL, pre-signing DAG over caller-chosen
task ids (plain strings), never `naalp.graph.verify_causal`'s SIGNED-object causal graph:
`graph.verify_causal` reconciles a set of ALREADY-SIGNED, ALREADY-POSITIONED nodes (it needs
each node's final topological position up front, which does not exist yet for a plan that
has not executed a single node), so it answers a different question than the one this
orchestrator asks before any node is signed: "does this caller-declared task-id DAG contain
a cycle, and in what order can its nodes be executed?" That question is answered here by a
plain Kahn's-algorithm topological sort (ties broken lexicographically by task id, for a
deterministic execution order), exactly mirroring `naalp_react.bridge`'s own documented
choice not to reach for `graph.verify_causal` when the narrower, pre-signing question is a
better fit (bridge.py's module docstring, "a plain membership check, not
`naalp.graph.verify_causal`"). Once a node IS signed, its causal edges are real N-AALP
`causes[]` entries -- the content ids of its prerequisites' real signed request objects --
so the resulting signed graph is exactly what `naalp.graph.verify_causal` would itself
accept were it later run over the finished, positioned output (§8.2-§8.3): a plan-level
topological sort here does not compete with that grading; it produces input that graph.py's
own no-future-cause + acyclicity checks are already known to accept.

Design choice -- injected, duck-typed `bridge` and `executor` (never a hard construction of
either inside this module): `bridge` is any object exposing
`action_to_request(action) -> Request` and `response_to_observation(bytes, Request) ->
Observation` -- exactly `naalp_react.ReActBridge`'s own two public methods, so a real
`ReActBridge` (with its own clock/signing-key/audience/transport already injected into IT)
plugs in with zero adaptation, and a test can substitute a thin recording wrapper around a
real bridge instead. `executor` is any callable `(Task, Request) -> bytes`: the synchronous
"send this signed request, get the raw response bytes back" step -- the orchestrator's own
analogue of a transport, injected exactly like `ReActBridge`'s own `transport=` constructor
argument, so no node's request/response cycle is ever driven by a hidden network call or a
global. This keeps the whole orchestrator testable in isolation (this task's isolation-demo
requirement) while still composing with a real bridge and a real transport exactly as the
design intends.

Design choice -- fail-closed by CATCHING, not by requiring callers to pre-filter: `run()`
never lets a per-node signing/validation/execution/verification failure escape as an
exception that aborts the whole plan. Each of those four failure points is caught at its
own call site and turned into a named `NodeResult(status="refused", ...)` for exactly that
node, so one bad node degrades gracefully into "this node and everything that depends on it
did not run" rather than crashing every other, unrelated branch of the plan. A cycle is the
one failure that IS raised (as `PlanError("CyclicPlan", ...)`) rather than recorded per-node,
because a cyclic plan has no valid execution order at all -- there is no partial result to
report, and (task bar) it must be rejected before any node's request is ever signed.
"""
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (side-effecting import: puts naalp_react + impl/python on sys.path)

from naalp_react import Action, Observation, Request, default_clock_ms  # noqa: F401  (re-exported for callers)


class PlanError(ValueError):
    """A named, fail-closed plan-structure error (E1.2/R2.2). `.kind` is one of:
    "CyclicPlan" (the task DAG contains a cycle -- raised before any node is signed),
    "DuplicateTaskId" (two tasks in the same plan share an id), or "UnknownPrerequisite"
    (a task names a prerequisite id that is not itself a task in the plan)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class Task:
    """One node in a plan (R2.2's "a DAG of tasks, each with a name, an effect class, args,
    and a set of prerequisite task-ids"). `id` is the caller-chosen, plan-local identifier
    used only to express the DAG (`prereqs`) -- it never reaches the wire. `action` is the
    N-AALP `naalp_react.Action` this node will request (name/channel/kind/effect/args);
    its own `causes` field is IGNORED and overwritten by the orchestrator with the real
    content ids of `prereqs`' signed request objects -- the caller declares causal
    STRUCTURE via `prereqs`, never authors `causes[]` bytes directly, because those bytes
    do not exist until a prerequisite is actually signed. `prereqs` is empty for a
    first-turn (root) task."""

    id: str
    action: Action
    prereqs: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NodeResult:
    """The outcome of one task after `PlanOrchestrator.run()`. `status` is exactly one of:
    "executed" (the request was signed, the executor ran, and the response verified `ok`),
    "refused" (this task's OWN request could not be signed/validated, its executor call
    failed, or its response failed verification), or "blocked" (a prerequisite was not
    "executed", so this task's request was never even built or signed). `request` is set
    whenever a signed request was actually produced (including a later-refused response);
    `observation` is set only when a response was actually verified (never fabricated on a
    "blocked" or pre-verification "refused" outcome)."""

    task_id: str
    status: str
    request: Optional[Request] = None
    observation: Optional[Observation] = None
    detail: str = ""


@dataclass(frozen=True)
class PlanRun:
    """The complete result of executing a plan: the topological order actually used, and
    the per-task `NodeResult`s (task_id -> NodeResult, one entry per task in the plan,
    always present regardless of outcome)."""

    order: Tuple[str, ...]
    results: Dict[str, NodeResult]
    started_at: int
    finished_at: int

    def observation_for(self, task_id: str) -> Optional[Observation]:
        return self.results[task_id].observation

    def request_id_for(self, task_id: str) -> Optional[bytes]:
        r = self.results[task_id].request
        return r.id if r is not None else None

    def executed(self) -> Tuple[str, ...]:
        return tuple(tid for tid in self.order if self.results[tid].status == "executed")


Executor = Callable[[Task, Request], bytes]


def _validate_and_order(tasks: Sequence[Task]) -> Tuple[Dict[str, Task], Tuple[str, ...]]:
    """Build the id->Task map and compute a deterministic topological order, or raise a
    named `PlanError` -- BEFORE any node is signed. This is the structural gate task bar
    (d) depends on: `PlanOrchestrator.run()` calls this before its execution loop ever
    touches `bridge.action_to_request`, so a cyclic (or otherwise malformed) plan produces
    zero signed bytes."""
    tasks_by_id: Dict[str, Task] = {}
    for t in tasks:
        if t.id in tasks_by_id:
            raise PlanError("DuplicateTaskId", "task id %r appears more than once in the plan" % (t.id,))
        tasks_by_id[t.id] = t

    for t in tasks_by_id.values():
        for p in t.prereqs:
            if p not in tasks_by_id:
                raise PlanError(
                    "UnknownPrerequisite", "task %r names unknown prerequisite %r" % (t.id, p)
                )

    order = _topological_order(tasks_by_id)
    return tasks_by_id, order


def _topological_order(tasks_by_id: Dict[str, Task]) -> Tuple[str, ...]:
    """Kahn's algorithm over the prereqs DAG, ties broken lexicographically by task id for
    a deterministic execution order. Raises `PlanError("CyclicPlan", ...)` naming every
    task id that could never be scheduled -- the definitive sign of a cycle (a self-loop
    included: a task naming itself as its own prerequisite can never reach indegree 0)."""
    indegree: Dict[str, int] = {tid: 0 for tid in tasks_by_id}
    dependents: Dict[str, List[str]] = {tid: [] for tid in tasks_by_id}
    for tid, task in tasks_by_id.items():
        for p in task.prereqs:
            dependents[p].append(tid)
            indegree[tid] += 1

    ready = sorted(tid for tid, deg in indegree.items() if deg == 0)
    order: List[str] = []
    while ready:
        ready.sort()
        current = ready.pop(0)
        order.append(current)
        for dep in dependents[current]:
            indegree[dep] -= 1
            if indegree[dep] == 0:
                ready.append(dep)

    if len(order) != len(tasks_by_id):
        unresolved = sorted(set(tasks_by_id) - set(order))
        raise PlanError(
            "CyclicPlan", "the plan's task DAG contains a cycle reachable from: %s" % ", ".join(unresolved)
        )
    return tuple(order)


class PlanOrchestrator:
    """R2.2: schedule a Task DAG into a valid topological order, converting each task into
    a real signed N-AALP request (via the injected `bridge`) whose `causes[]` names exactly
    its prerequisites' signed request content ids, running the injected `executor` to get
    each request's response, and verifying that response back into an `Observation` (via
    the same injected `bridge`) before letting any dependent task proceed. The bridge, the
    executor, and the clock are all constructor-injected (never a hidden global, never a
    network call this class makes itself, never a bridge this class constructs on its own)
    so the whole orchestrator is testable in isolation."""

    def __init__(self, *, bridge, executor: Executor, clock: Callable[[], int] = default_clock_ms):
        self._bridge = bridge
        self._executor = executor
        self._clock = clock

    def run(self, tasks: Sequence[Task]) -> PlanRun:
        """Execute `tasks` to completion. Raises `PlanError` (before any signing) if the
        plan itself is malformed (a cycle, a duplicate id, or an unknown prerequisite);
        otherwise NEVER raises -- every per-node failure is recorded as that node's own
        `NodeResult(status="refused"/"blocked", ...)` and execution continues over the
        rest of the plan (module docstring, "fail-closed by catching")."""
        tasks_by_id, order = _validate_and_order(tasks)

        started_at = self._clock()
        results: Dict[str, NodeResult] = {}
        request_ids: Dict[str, bytes] = {}

        for tid in order:
            task = tasks_by_id[tid]

            unresolved = [p for p in task.prereqs if results[p].status != "executed"]
            if unresolved:
                # (task bar c/e): a node whose prerequisite refused, was itself blocked, or
                # never executed is NOT executed -- no request is ever built or signed for
                # it, and no Observation is ever fabricated.
                results[tid] = NodeResult(
                    task_id=tid,
                    status="blocked",
                    detail="blocked on unresolved prerequisite(s): %s" % ", ".join(sorted(unresolved)),
                )
                continue

            linked_action = replace(task.action, causes=tuple(request_ids[p] for p in task.prereqs))

            try:
                request = self._bridge.action_to_request(linked_action)
            except Exception as e:  # noqa: BLE001 -- fail-closed: ANY sign/validate refusal degrades this node only
                results[tid] = NodeResult(
                    task_id=tid,
                    status="refused",
                    detail="request signing/validation refused: %s: %s" % (type(e).__name__, e),
                )
                continue

            request_ids[tid] = request.id

            try:
                response_bytes = self._executor(task, request)
            except Exception as e:  # noqa: BLE001 -- an executor failure refuses this node; it is never an Observation
                results[tid] = NodeResult(
                    task_id=tid, status="refused", request=request,
                    detail="executor failed: %s: %s" % (type(e).__name__, e),
                )
                continue

            observation = self._bridge.response_to_observation(response_bytes, request)
            if not observation.ok:
                results[tid] = NodeResult(
                    task_id=tid, status="refused", request=request, observation=observation,
                    detail="response verification refused: %s" % observation.error,
                )
                continue

            results[tid] = NodeResult(task_id=tid, status="executed", request=request, observation=observation)

        finished_at = self._clock()
        return PlanRun(order=order, results=results, started_at=started_at, finished_at=finished_at)
