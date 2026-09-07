# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_validator -- the N-AALP semantic-intent validator (Part-2 ecosystem E0.2, R3).

    from naalp_validator import validate, pre_send_hook

    result = validate(candidate_object)
    if not result.valid:
        for v in result.violations:
            print(v.error, v.field, v.detail)

See `validator.py` for the full check list and `firewall.py` for the firewall-hook entry
point (R3.3). Reuses the Part-1 Python reference SDK (`impl/python/naalp`) for every
byte-level operation; defines no second codec.
"""
from .validator import (  # noqa: F401
    CONSUME_ONCE_KINDS, MAX_CAUSES, MAX_CEXT, MAX_EXT, MAX_NESTING_DEPTH, MAX_OBJECT_SIZE,
    MAX_STREAM_CHUNKS, ValidationResult, Violation, is_consume_once_kind, validate,
    validate_stream_chunk_count,
)
from .firewall import FirewallDecision, pre_send_hook  # noqa: F401

__all__ = [
    "validate", "validate_stream_chunk_count", "ValidationResult", "Violation",
    "is_consume_once_kind", "CONSUME_ONCE_KINDS",
    "pre_send_hook", "FirewallDecision",
    "MAX_CAUSES", "MAX_CEXT", "MAX_EXT", "MAX_NESTING_DEPTH", "MAX_OBJECT_SIZE",
    "MAX_STREAM_CHUNKS",
]

__version__ = "0.1.0"
