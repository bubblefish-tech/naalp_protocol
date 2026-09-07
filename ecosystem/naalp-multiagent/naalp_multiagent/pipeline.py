# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP sequential multi-agent pipeline (Part-2 ecosystem task E1.3, requirement R2.3).

requirements.md R2.3 (sequential shape): "agent A's signed output feeds agent B feeds C" --
a chain of DISTINCT agents (each with its own signing identity), where each stage's signed
request causally links (`causes[]`) to the PRIOR stage's signed request content id, and a
stage refusal fails the pipeline closed: no downstream stage is ever built, signed, or run.

    [Stage(agent A), Stage(agent B), Stage(agent C)] -> SequentialPipeline.run() -> a
    PipelineRun: one StageResult per stage, in pipeline order.

This is the genuinely MULTI-agent counterpart to the sibling `naalp_plan.PlanOrchestrator`
(E1.2/R2.2): `PlanOrchestrator` schedules a DAG of tasks under ONE bridge (one signing
identity orchestrating several tool/sub-agent calls); a `SequentialPipeline` composes SEVERAL
independent bridges (several signing identities -- "agent A", "agent B", "agent C") into a
straight hand-off chain.

Design choice -- calls `naalp_react.ReActBridge.action_to_request` / `.response_to_
observation` DIRECTLY (the E1.1 bridge), rather than routing through the sibling
`naalp_plan.PlanOrchestrator` (E1.2): `PlanOrchestrator.run()` UNCONDITIONALLY recomputes
each task's causal edges from that same run's own `task.prereqs`
(`causes=tuple(request_ids[p] for p in task.prereqs)`) -- it has no way to accept an
EXTERNALLY-supplied predecessor content id from a prior, independently-run stage under a
DIFFERENT bridge, because `request_ids` is private state scoped to a single `run()` call
under a single bridge. A cross-agent chain's whole point is that stage B's predecessor
content id comes from a PRIOR `ReActBridge` instance's own signed output, not from a
prerequisite task inside THIS stage's own (single-task) DAG -- so wrapping each stage in its
own single-task `PlanOrchestrator` and pre-setting `causes` on the task's Action does NOT
work: `PlanOrchestrator` silently overwrites it with `()` (no prereqs in a lone task) before
ever calling the bridge. This module therefore reuses the underlying primitive
`PlanOrchestrator` itself reuses -- the E1.1 bridge -- directly, at the SAME layer as
`naalp_plan`, not on top of it; the per-stage try/execute/verify/degrade CONTROL FLOW below
intentionally mirrors `PlanOrchestrator.run()`'s own per-node shape (same three failure
points, same fail-closed-by-catching discipline), because that shape is this task's own
scheduling glue, not a cryptographic primitive that would be wrong to write twice.

Design choice -- `build_action` is a caller callable `(Optional[Observation]) -> Action`,
never a value this module inspects/transforms itself: the prior stage's verified Observation
body is caller-defined data (a `naalp_codec` value), and turning it into the NEXT agent's own
Action (its kind/channel/effect/args) is a domain decision this module does not make (module
docstring's "buy-before-make": no second body-parsing/transform layer here, exactly the
sibling `naalp_react.bridge`'s "this module defines no value-coercion rules of its own").
`build_action(None)` is called for the pipeline's first stage (no prior Observation exists).

Design choice -- injected, duck-typed `bridge`/`executor` per stage (never a hard
construction of either): each `Stage.bridge` is anything shaped like `naalp_react.
ReActBridge` (its own clock/signing-key/audience/transport already injected into IT), and
each `Stage.executor` is any callable `(Stage, Request) -> bytes` -- the same "send this
signed request, get the raw response bytes back" shape `naalp_plan.Executor` and
`naalp_react`'s own `transport=` use, so the whole pipeline is testable in isolation (this
task's isolation-demo requirement) with recording spies wrapping real bridges.
"""
from dataclasses import dataclass, replace
from typing import Callable, Optional, Sequence, Tuple

from . import _bootstrap  # noqa: F401  (side-effecting import: puts naalp_react + impl/python on sys.path)

from naalp_react import Action, Observation, Request  # noqa: F401  (re-exported for callers)


@dataclass(frozen=True)
class Stage:
    """One stage in a sequential multi-agent pipeline. `agent_id` is a caller-chosen label
    for which agent runs this stage (used only for reporting; it never reaches the wire).
    `bridge` is THAT agent's own injected `naalp_react.ReActBridge`-shaped object (its own
    signing identity/keys/audience); a different stage normally injects a DIFFERENT bridge,
    which is what makes this a multi-agent chain rather than a single orchestrated plan.
    `executor` sends this stage's signed request and returns the raw response bytes.
    `build_action` builds THIS stage's own `Action` from the prior stage's `Observation`
    (`None` for the pipeline's first stage) -- its returned Action's own `causes` field is
    IGNORED and overwritten by the pipeline with the prior stage's real signed request
    content id, exactly as `naalp_plan.Task.causes` is documented to be ignored and
    overwritten by prerequisite wiring."""

    agent_id: str
    bridge: object
    executor: Callable[["Stage", Request], bytes]
    build_action: Callable[[Optional[Observation]], Action]


@dataclass(frozen=True)
class StageResult:
    """The outcome of one pipeline stage after `SequentialPipeline.run()`. `status` is
    exactly one of: "executed" (this stage's request was signed, its executor ran, and the
    response verified `ok`), "refused" (this stage's OWN request could not be signed/
    validated, its executor call failed, or its response failed verification), or "blocked"
    (an earlier stage in the pipeline did not reach "executed", so this stage's Action was
    never even built and its bridge/executor were never touched)."""

    agent_id: str
    status: str
    request: Optional[Request] = None
    observation: Optional[Observation] = None
    detail: str = ""


@dataclass(frozen=True)
class PipelineRun:
    """The complete result of running a `SequentialPipeline`: one `StageResult` per stage,
    in pipeline (chain) order, always present regardless of outcome."""

    results: Tuple[StageResult, ...]

    def executed(self) -> Tuple[str, ...]:
        return tuple(r.agent_id for r in self.results if r.status == "executed")

    def result_for(self, agent_id: str) -> StageResult:
        for r in self.results:
            if r.agent_id == agent_id:
                return r
        raise KeyError(agent_id)


class SequentialPipeline:
    """R2.3 (sequential shape): run `stages` in chain order, each stage's signed request
    causally linked to the PRIOR stage's signed request content id (empty `causes` for the
    first stage). Fail-closed by PROPAGATING the chain, not by requiring callers to
    pre-filter: the moment a stage does not reach "executed", every remaining stage is
    recorded "blocked" and NONE of them ever reaches its own bridge or executor (verified by
    red-evidence against a spy on the downstream stage's bridge/executor)."""

    def __init__(self, *, stages: Sequence[Stage]):
        self._stages = tuple(stages)

    def run(self) -> PipelineRun:
        results = []
        prev_observation: Optional[Observation] = None
        prev_request_id: Optional[bytes] = None
        chain_broken = False

        for stage in self._stages:
            if chain_broken:
                results.append(
                    StageResult(
                        agent_id=stage.agent_id,
                        status="blocked",
                        detail="an earlier stage in the pipeline did not execute",
                    )
                )
                continue

            try:
                action = stage.build_action(prev_observation)
                causes = (prev_request_id,) if prev_request_id is not None else ()
                linked_action = replace(action, causes=causes)
                request = stage.bridge.action_to_request(linked_action)
            except Exception as e:  # noqa: BLE001 -- fail-closed: ANY build/sign/validate refusal degrades this stage only
                results.append(
                    StageResult(
                        agent_id=stage.agent_id,
                        status="refused",
                        detail="action build or request signing/validation refused: %s: %s" % (type(e).__name__, e),
                    )
                )
                chain_broken = True
                continue

            try:
                response_bytes = stage.executor(stage, request)
            except Exception as e:  # noqa: BLE001 -- an executor failure refuses this stage; never an Observation
                results.append(
                    StageResult(
                        agent_id=stage.agent_id, status="refused", request=request,
                        detail="executor failed: %s: %s" % (type(e).__name__, e),
                    )
                )
                chain_broken = True
                continue

            observation = stage.bridge.response_to_observation(response_bytes, request)
            if not observation.ok:
                results.append(
                    StageResult(
                        agent_id=stage.agent_id, status="refused", request=request, observation=observation,
                        detail="response verification refused: %s" % observation.error,
                    )
                )
                chain_broken = True
                continue

            results.append(
                StageResult(agent_id=stage.agent_id, status="executed", request=request, observation=observation)
            )
            prev_observation = observation
            prev_request_id = request.id

        return PipelineRun(results=tuple(results))
