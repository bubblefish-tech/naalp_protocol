# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C5 effect vocabulary and authorization for the Python SDK (§6).

The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
(action <= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.
"""
from . import cbor
from .cbor import U, T, M

READ_ONLY = 0
IDEMPOTENT_WRITE = 1
NON_IDEMPOTENT_WRITE = 2
DESTRUCTIVE = 3

_NAMES = ["read_only", "idempotent_write", "non_idempotent_write", "destructive"]


def normalize_effect(v: int) -> int:
    """Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2)."""
    return v if 0 <= v <= 3 else DESTRUCTIVE


def safety_label_name(e: int) -> str:
    return _NAMES[normalize_effect(e)]


def authorizes(ceiling: int, action: int) -> bool:
    """The §6.1 lattice: an action of class `action` is permitted under ceiling iff action <= ceiling."""
    return action <= ceiling


def safety_label_bytes(risk: str, scope: str) -> bytes:
    """The signed safety-label body {1: risk, 2: scope} (R-6.4)."""
    return cbor.encode(M([(U(1), T(risk)), (U(2), T(scope))]))
