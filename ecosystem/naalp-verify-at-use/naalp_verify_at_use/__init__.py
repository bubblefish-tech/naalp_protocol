# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_verify_at_use -- the N-AALP verify-at-use guard (Part-2 ecosystem task E6.1,
requirement R12.1, the evidence-layer primitives).

Re-verifies an effecting object's authorization at the INSTANT OF EXECUTION -- not only at
receipt -- refusing fail-closed with a named error when a grant/approval that was valid at
issuance has since expired, been consumed, had its signing key revoked, or is presented
outside its audience. See verify_at_use.py for the core re-check machinery.
"""
from .verify_at_use import (
    GuardedAction,
    VerifyAtUseGuard,
    default_clock_ms,
)

__all__ = [
    "GuardedAction",
    "VerifyAtUseGuard",
    "default_clock_ms",
]

__version__ = "0.1.0"
