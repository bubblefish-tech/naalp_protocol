# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_a2a_bridge -- the N-AALP A2A agent-coordination bridge (Part-2 ecosystem task E2.2,
requirements R4.1/R4.2/R4.3).

Maps foreign-native A2A (Agent2Agent) activity -- a raw Agent Card and an ordered task-state
history expressed exactly as an A2A client observes it -- onto N-AALP's own signed,
receipt-chained wire objects (design.md sec21/sec22) and back, reusing `naalp.naming` and
`naalp.description` for every cryptographic and encoding operation. See a2a_bridge.py for the
full API and rationale.

    from naalp_a2a_bridge import (
        SkillMapping, ForeignTaskEvent, A2ABridgeError,
        bridge_card, verify_card, bridge_activity, verify_activity, verify_and_recover,
    )
"""
from .a2a_bridge import (  # noqa: F401
    A2ABridgeError,
    ForeignTaskEvent,
    SkillMapping,
    bridge_activity,
    bridge_card,
    verify_activity,
    verify_and_recover,
    verify_card,
)

__all__ = [
    "A2ABridgeError",
    "ForeignTaskEvent",
    "SkillMapping",
    "bridge_activity",
    "bridge_card",
    "verify_activity",
    "verify_and_recover",
    "verify_card",
]

__version__ = "0.1.0"
