# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_plan -- the N-AALP Plan-and-Execute orchestrator (Part-2 ecosystem task E1.2,
requirement R2.2).

Schedules a caller-declared Task DAG into a valid topological order, converts each task
into a real signed N-AALP request object (via the sibling `naalp_react.ReActBridge`) whose
causal edges (`causes[]`) name exactly its prerequisites' signed request content ids, and
is fail-closed end to end: a task whose prerequisite refused or was itself blocked is never
executed, and a cyclic plan is rejected with a named error before any node is signed. See
`orchestrator.py` for the full API and design rationale.
"""
from .orchestrator import (
    Executor,
    NodeResult,
    PlanError,
    PlanOrchestrator,
    PlanRun,
    Task,
)

__all__ = [
    "Task", "NodeResult", "PlanRun", "PlanError",
    "PlanOrchestrator", "Executor",
]

__version__ = "0.1.0"
