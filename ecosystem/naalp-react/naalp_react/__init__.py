# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_react -- the N-AALP ReAct bridge (Part-2 ecosystem task E1.1, requirement R2.1).

Maps an agent's Thought->Action->Observation loop onto signed N-AALP objects: an Action
becomes a real signed, encoded N-AALP request (`ReActBridge.action_to_request`); an async
response becomes a verified, causally-linked Observation
(`ReActBridge.response_to_observation`). See `bridge.py` for the full API and design
rationale.
"""
from .bridge import (
    A,
    B,
    M,
    N,
    T,
    Tag,
    U,
    Action,
    Observation,
    ReActBridge,
    ReActError,
    Request,
    default_clock_ms,
)

__all__ = [
    "U", "N", "B", "T", "A", "M", "Tag",
    "Action", "Request", "Observation",
    "ReActBridge", "ReActError",
    "default_clock_ms",
]

__version__ = "0.1.0"
