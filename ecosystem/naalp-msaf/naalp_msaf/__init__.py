# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_msaf -- the N-AALP Governance Kit's framework adapter for the Microsoft Agent Framework
(MSAF). See msaf_adapter.py for the module docstring and the N-AALP Governance Kit design
(design.md sec.2.1, G1) for the deliverable this implements."""
from .msaf_adapter import (  # noqa: F401
    NaalpMSAFMiddleware,
    ChainRecorder,
    Receipt,
    MalformedResumeDecision,
    CHANNEL_BRIDGE,
    KIND_CARRIAGE,
    canonical_json_bytes,
    args_content_id,
)

__all__ = [
    "NaalpMSAFMiddleware", "ChainRecorder", "Receipt", "MalformedResumeDecision",
    "CHANNEL_BRIDGE", "KIND_CARRIAGE", "canonical_json_bytes", "args_content_id",
]
