# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP parallel multi-agent fan-out + reconcile (Part-2 ecosystem task E1.3,
requirement R2.3).

requirements.md R2.3 (parallel shape): N agents act CONCURRENTLY on a shared input -- each
agent's own signed request causally links (`causes[]`) to that ONE shared input's content id
-- and their resulting signed, causally-linked branches then CONVERGE at a reconcile step
that produces a deterministic linearization of the union causal graph (the sibling
`reconcile.py`'s direct call to the real Part-1 `naalp.federation.reconcile` primitive), so
two runs of the SAME parallel set reconcile to the SAME order regardless of which branch's
thread happened to finish first. A branch whose response fails verification is EXCLUDED from
the reconciled graph under its own named error (never silently dropped without a reason,
never included with a fabricated causal edge); a caller-supplied causal graph that is not a
valid partial order (a cycle) is rejected by the reconcile step with the registered
`CausalViolation` error, propagated unchanged.

    Branch, Branch, ..., shared_input_id -> ParallelFanout.run() -> a FanoutRun:
        per-agent BranchResult (agent_id -> BranchResult) + the reconciled total order.

Design choice -- calls `naalp_react.ReActBridge.action_to_request` / `.response_to_
observation` DIRECTLY (the E1.1 bridge) for each branch's sign -> execute -> verify sequence,
rather than routing through the sibling `naalp_plan.PlanOrchestrator` (E1.2): see
`pipeline.py`'s module docstring for the full reasoning -- `PlanOrchestrator.run()`
unconditionally recomputes a task's causal edges from ITS OWN `task.prereqs` within that one
run under one bridge, so it cannot accept an externally-supplied `shared_input_id` as a
branch's cause (wrapping a branch in a single-task `PlanOrchestrator` and pre-setting
`causes` does NOT survive: `PlanOrchestrator` silently overwrites it with `()`). This module
therefore reuses the underlying primitive `PlanOrchestrator` itself reuses -- the E1.1 bridge
-- directly; the per-branch try/execute/verify/degrade control flow mirrors
`PlanOrchestrator.run()`'s own per-node shape (this task's own scheduling glue, not a
cryptographic primitive). The branches are then dispatched onto a real thread pool
(`concurrent.futures.ThreadPoolExecutor`) so the fan-out is GENUINELY concurrent -- branch
completion order is not fixed by iteration order, which is precisely what makes "two runs
reconcile to the same order" a real property of the reconcile step rather than an artifact of
always processing branches in the same sequence.

Design choice -- `agent_id` uniqueness is enforced BEFORE any branch runs
(`MultiAgentError("DuplicateAgentId", ...)`), never discovered after the fact:
`branch_results` is agent_id-keyed, so two branches sharing an id would silently discard one
branch's real result -- the same class of structural pre-flight check `naalp_plan.
PlanOrchestrator` performs for `DuplicateTaskId` before any node is signed.

Design choice -- the shared input is named by its content id (`shared_input_id: bytes`)
alone, never by a whole `naalp.envelope.Object` or a bridge of its own: R2.3 requires only
that every branch's output causally link to "a shared input", and a caller who wants that
input to be itself a REAL signed N-AALP object (e.g. a coordinator agent's own broadcast
request) simply passes that object's own content id -- this module places no requirement on
how the shared input was produced, or that it was produced by this package at all. The
shared input's own id is included as a root `CausalNode` (with no causes) in every reconciled
graph, so the reconciled order always places it before its dependent branches.

Design choice -- a branch's `error` name is the underlying registered N-AALP error
(`observation.error`, e.g. "WrongAudience"/"BadSignature"/"CausalViolation") whenever a
response was actually verified and refused; only when no response was ever verified at all
(the request itself could not be signed/validated, or the executor call failed) does this
module fall back to its own glue-layer name "SigningOrExecutionRefused" -- never fabricating
a Part-1 registered name for a failure Part-1 never actually classified."""
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from typing import Callable, Dict, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (side-effecting import: puts naalp_react + impl/python on sys.path)

from naalp_react import Action, Observation, Request  # noqa: F401  (re-exported for callers)

from .reconcile import CausalNode, reconcile_nodes

# The Part-1 Python reference SDK's ML-DSA backend (`naalp.cose.mldsa_sign`/`mldsa_verify`,
# via the pure-Python `dilithium_py` library) is NOT thread-safe: `dilithium_py.ml_dsa.
# ML_DSA_65`/`ML_DSA_87` are process-wide SINGLETON objects, and concurrent calls into them
# from multiple threads corrupt each other's signatures. WITNESSED directly (no
# `naalp_multiagent` code involved): 8 threads each looping `cose.mldsa_sign` +
# `cose.mldsa_verify` with distinct seeds/messages produced 65 failed verifications out of
# 160 calls. `naalp_plan.PlanOrchestrator` never hits this because it signs/verifies
# sequentially in one thread; `ParallelFanout` is this ecosystem's first genuinely concurrent
# caller, so it is the first place this needs a fix. `CRYPTO_LOCK` serializes every call this
# module makes into the shared crypto backend (`bridge.action_to_request` /
# `bridge.response_to_observation`) WITHOUT serializing the surrounding dispatch or the
# injected `executor` I/O -- branches still race each other for scheduling and transport
# time (real concurrency, real completion-order variance), only the crypto calls are
# mutually exclusive. It is deliberately a MODULE-level (process-wide), not per-instance,
# lock: the corrupted singleton is shared by the whole process, so a per-`ParallelFanout`
# lock would not protect two fan-outs (or a fan-out and any other direct `naalp.cose`
# caller) running in different threads at once. Exported (`naalp_multiagent.CRYPTO_LOCK`)
# so a caller whose OWN `executor`/`build_action` also calls into `naalp.envelope`/
# `naalp.cose` locally (e.g. an in-process test harness simulating a remote counterpart, as
# this task's own tests do) can serialize against the SAME lock rather than discovering the
# same corruption independently. This is a Part-1 SDK defect this package cannot fix in
# scope (this task may only add `ecosystem/naalp-multiagent/`, never touch `impl/`); the
# lock is the honest, scoped mitigation for the one caller (this package) that actually
# exercises the backend concurrently.
CRYPTO_LOCK = threading.Lock()


class MultiAgentError(ValueError):
    """A named, fail-closed `naalp_multiagent` structural error. `.kind` is currently only
    "DuplicateAgentId" (two branches in the same `ParallelFanout` share an `agent_id` --
    checked before any branch is dispatched, so it never races the thread pool)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class Branch:
    """One branch in a parallel multi-agent fan-out. `agent_id` uniquely labels which agent
    runs this branch (the key into `FanoutRun.branch_results`; MUST be unique across a single
    `ParallelFanout`'s branches -- checked by the constructor). `bridge` is that agent's own
    injected `naalp_react.ReActBridge`-shaped object. `executor` sends this branch's signed
    request and returns the raw response bytes. `build_action` builds this branch's own
    `Action` from the shared input's content id (`bytes`) -- its returned Action's own
    `causes` field is IGNORED and overwritten with `(shared_input_id,)`, exactly as
    `pipeline.Stage.build_action`'s result is overwritten with the prior stage's content id."""

    agent_id: str
    bridge: object
    executor: Callable[["Branch", Request], bytes]
    build_action: Callable[[bytes], Action]


@dataclass(frozen=True)
class BranchResult:
    """The outcome of one fan-out branch. `status` is "executed" (this branch's request was
    signed, its executor ran, and the response verified `ok` -- its request content id IS
    included in the reconciled graph) or "excluded" (this branch's own request could not be
    signed/validated, its executor call failed, or its response failed verification -- its
    `error` names the failure and its content id, if one was ever produced, is NEVER
    included in the reconciled graph)."""

    agent_id: str
    status: str
    request: Optional[Request] = None
    observation: Optional[Observation] = None
    error: str = ""
    detail: str = ""


@dataclass(frozen=True)
class FanoutRun:
    """The complete result of one `ParallelFanout.run()`: the shared input's content id, the
    per-agent `BranchResult` (keyed by `agent_id`), and the reconciled deterministic total
    order (the shared input's content id first, then every EXECUTED branch's signed request
    content id, in the Part-1 reconcile primitive's own tie-broken order)."""

    shared_input_id: bytes
    branch_results: Dict[str, BranchResult]
    reconciled_order: Tuple[bytes, ...]

    def executed(self) -> Tuple[str, ...]:
        return tuple(aid for aid, r in self.branch_results.items() if r.status == "executed")


@dataclass(frozen=True)
class _BranchAttempt:
    """Internal: the outcome of running ONE branch's sign -> execute -> verify sequence,
    before it is classified into a `BranchResult` and (if executed) folded into the
    reconciled graph. Never raises for a per-branch failure -- every failure point is caught
    at its own call site (mirrors `naalp_plan.PlanOrchestrator.run()`'s per-node shape)."""

    status: str
    request: Optional[Request] = None
    observation: Optional[Observation] = None
    detail: str = ""


def _run_branch(branch: Branch, shared_input_id: bytes) -> _BranchAttempt:
    """Run ONE branch's sign -> execute -> verify sequence against `branch`'s own bridge,
    with its Action causally linked to `shared_input_id`. This is the unit dispatched onto
    the thread pool, so it must not touch any state shared across branches -- it only closes
    over the one `branch` and the one shared `shared_input_id` value (immutable bytes).

    `CRYPTO_LOCK` is held ONLY around the two calls that reach into the shared, non-
    thread-safe Part-1 crypto backend (`action_to_request` / `response_to_observation`);
    `build_action` and `executor` run OUTSIDE the lock, so branches still race each other for
    scheduling and transport/executor time -- only the crypto calls are serialized."""
    try:
        action = branch.build_action(shared_input_id)
        linked_action = replace(action, causes=(shared_input_id,))
        with CRYPTO_LOCK:
            request = branch.bridge.action_to_request(linked_action)
    except Exception as e:  # noqa: BLE001 -- fail-closed: ANY build/sign/validate refusal excludes this branch only
        return _BranchAttempt(
            status="refused", detail="action build or request signing/validation refused: %s: %s" % (type(e).__name__, e)
        )

    try:
        response_bytes = branch.executor(branch, request)
    except Exception as e:  # noqa: BLE001 -- an executor failure excludes this branch; never a fabricated Observation
        return _BranchAttempt(
            status="refused", request=request, detail="executor failed: %s: %s" % (type(e).__name__, e)
        )

    with CRYPTO_LOCK:
        observation = branch.bridge.response_to_observation(response_bytes, request)
    if not observation.ok:
        return _BranchAttempt(
            status="refused", request=request, observation=observation,
            detail="response verification refused: %s" % observation.error,
        )

    return _BranchAttempt(status="executed", request=request, observation=observation)


class ParallelFanout:
    """R2.3 (parallel shape): dispatch `branches` CONCURRENTLY (a real
    `concurrent.futures.ThreadPoolExecutor`, never a sequential loop dressed up as
    "parallel") against a shared input, then converge every EXECUTED branch's signed request
    into one deterministic total order via the real Part-1 reconcile primitive
    (`reconcile.reconcile_nodes`). A branch that fails to sign, execute, or verify is
    EXCLUDED from the reconciled graph under its own named error -- never included, never
    silently dropped without a reason. Raises `naalp.graph.CausalViolation` (propagated
    unchanged from the reconcile step) if the resulting causal graph is not a valid partial
    order -- which cannot happen from THIS class's own construction (every branch causes only
    the shared input, never another branch), but is exactly what the shared
    `reconcile.reconcile_nodes` primitive itself guards against for an arbitrary
    caller-built graph (see tests/test_reconcile.py)."""

    def __init__(self, *, branches: Sequence[Branch], max_workers: Optional[int] = None):
        seen = set()
        for b in branches:
            if b.agent_id in seen:
                raise MultiAgentError(
                    "DuplicateAgentId", "agent id %r appears more than once in this fan-out" % (b.agent_id,)
                )
            seen.add(b.agent_id)
        self._branches = tuple(branches)
        self._max_workers = max_workers

    def run(self, shared_input_id: bytes) -> FanoutRun:
        attempts: Dict[str, _BranchAttempt] = {}
        worker_count = self._max_workers or max(len(self._branches), 1)
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_branch = {pool.submit(_run_branch, b, shared_input_id): b for b in self._branches}
            for future in as_completed(future_to_branch):
                b = future_to_branch[future]
                attempts[b.agent_id] = future.result()

        branch_results: Dict[str, BranchResult] = {}
        graph_nodes = [CausalNode(id=shared_input_id, causes=[])]
        for b in self._branches:
            attempt = attempts[b.agent_id]
            if attempt.status == "executed":
                branch_results[b.agent_id] = BranchResult(
                    agent_id=b.agent_id, status="executed",
                    request=attempt.request, observation=attempt.observation,
                )
                graph_nodes.append(CausalNode(id=attempt.request.id, causes=[shared_input_id]))
            else:
                if attempt.observation is not None:
                    error_name = attempt.observation.error
                else:
                    error_name = "SigningOrExecutionRefused"
                branch_results[b.agent_id] = BranchResult(
                    agent_id=b.agent_id, status="excluded",
                    request=attempt.request, observation=attempt.observation,
                    error=error_name, detail=attempt.detail,
                )

        order = reconcile_nodes(graph_nodes)
        return FanoutRun(shared_input_id=shared_input_id, branch_results=branch_results, reconciled_order=order)
