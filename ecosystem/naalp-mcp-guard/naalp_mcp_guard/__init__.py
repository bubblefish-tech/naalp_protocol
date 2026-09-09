# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp-mcp-guard: the N-AALP one-command guard for the Model Context Protocol (Group 6,
ecosystem-viral-wire spec). Packages the already-built `naalp-mcp-bridge` (effect
classification + signed McpToolCall carriage), `naalp-hitl` (pause/human-approval/D6 audit), and
this package's own new `EffectReceipt` primitive behind `wrap <server>` / `verify <receipt>`.

See README.md for the verified per-concern coverage table (MCP-VERIFIED-01 sec.4) and the two
deployment preconditions every claim below depends on."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp imports)

from .effect_gate import EffectGate, GateDecision, GuardError
from .proxy import GuardProxy
from .receipt import (
    EffectReceipt,
    ReceiptError,
    DECISION_EXECUTED,
    DECISION_DENIED,
    sign_effect_receipt,
    verify_effect_receipt,
    receipt_file_dict,
    write_receipt_file,
    verify_receipt_bytes,
)

__all__ = [
    "EffectGate", "GateDecision", "GuardError", "GuardProxy",
    "EffectReceipt", "ReceiptError", "DECISION_EXECUTED", "DECISION_DENIED",
    "sign_effect_receipt", "verify_effect_receipt",
    "receipt_file_dict", "write_receipt_file", "verify_receipt_bytes",
]
