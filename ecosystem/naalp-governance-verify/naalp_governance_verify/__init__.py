# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_governance_verify -- K5, the N-AALP Agent Governance Kit's offline, framework-agnostic
verifier and replay tool.

Reads a recorded, length-prefixed chain of mixed-kind signed N-AALP objects (as emitted by K1's
ADK plugin, K3's MCP hook, or any other adapter's `ChainRecorder`-shaped session log), verifies
every object offline through the real Part-1 core, reconstructs and replays the chain's causal
order, and can emit its own signed verification receipt. See `verify.py`'s module docstring for
the full K5-1..K5-3 mapping and the mixed-kind design note.
"""
from .verify import (  # noqa: F401
    ChainVerifyError, LogMalformed, SignatureInvalid, UnresolvedSigner,
    BrokenReferent, ChainOrderBroken,
    read_log, PubkeyResolver, VerifiedLink, VerifiedChain,
    verify_chain, replay, verify_and_replay, k0_payload,
    VERIFICATION_CHANNEL, VERIFICATION_KIND, sign_verification_receipt,
)

__all__ = [
    "ChainVerifyError", "LogMalformed", "SignatureInvalid", "UnresolvedSigner",
    "BrokenReferent", "ChainOrderBroken",
    "read_log", "PubkeyResolver", "VerifiedLink", "VerifiedChain",
    "verify_chain", "replay", "verify_and_replay", "k0_payload",
    "VERIFICATION_CHANNEL", "VERIFICATION_KIND", "sign_verification_receipt",
]

__version__ = "0.1.0"
