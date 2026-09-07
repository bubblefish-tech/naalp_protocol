# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_hitl -- the N-AALP HITL interceptor (Part-2 ecosystem task E0.1, requirement R1).

Pauses an effecting action whose effect class requires human approval, routes it to a
pluggable human interface (terminal built here; web/chat deferred), verifies and consumes a
real Part-1 N-AALP approval object atomically and single-use, and resumes the action -- or
fails closed with the named error and no state change. See interceptor.py for the core
pause/verify/consume/resume machinery and frontend.py for the terminal front end.
"""
from .interceptor import (
    ApprovalRequest,
    PendingAction,
    HumanInterface,
    HITLInterceptor,
    HITLError,
    default_clock_ms,
)
from .frontend import TerminalFrontend
from .refusal_log import RefusalLog, RefusalLogEntry, JsonlRefusalLog
from .nonrepudiation import (
    RefusalDecisionRecord,
    RefusalOutcome,
    sign_refusal_record,
    verify_refusal_record,
    refusal_outcome_for_reason,
)

__all__ = [
    "ApprovalRequest",
    "PendingAction",
    "HumanInterface",
    "HITLInterceptor",
    "HITLError",
    "default_clock_ms",
    "TerminalFrontend",
    "RefusalLog",
    "RefusalLogEntry",
    "JsonlRefusalLog",
    "RefusalDecisionRecord",
    "RefusalOutcome",
    "sign_refusal_record",
    "verify_refusal_record",
    "refusal_outcome_for_reason",
]

__version__ = "0.1.0"
