# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_multiagent -- N-AALP multi-agent interaction shapes (Part-2 ecosystem task E1.3,
requirement R2.3): a SEQUENTIAL PIPELINE (agent A's signed output feeds agent B feeds C, each
stage causally linked to the prior, fail-closed on any stage refusal) and a PARALLEL FAN-OUT
+ RECONCILE (N agents act concurrently on a shared input; their signed, causally-linked
outputs converge through the Part-1 federated-ordering reconcile primitive into one
deterministic linearization, with any verification-failing branch excluded under a named
error). See pipeline.py, fanout.py, and reconcile.py for the full API and design rationale.
"""
from .pipeline import PipelineRun, SequentialPipeline, Stage, StageResult
from .fanout import CRYPTO_LOCK, Branch, BranchResult, FanoutRun, MultiAgentError, ParallelFanout
from .reconcile import CausalNode, reconcile_nodes

__all__ = [
    "Stage", "StageResult", "PipelineRun", "SequentialPipeline",
    "Branch", "BranchResult", "FanoutRun", "ParallelFanout", "MultiAgentError", "CRYPTO_LOCK",
    "CausalNode", "reconcile_nodes",
]

__version__ = "0.1.0"
