# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_fingerprint_cache -- the N-AALP signer-id fingerprint cache (Part-2 ecosystem task
E6.2, requirement R12.2).

Trust-on-first-use pinning of signer-id fingerprints, with an explicit tag-98 Rotation-object
escape hatch for a legitimate key rotation and a fail-closed refusal for everything else. See
fingerprint_cache.py for the pin/compare decision table and the real Part-1 primitives it reuses
(naalp.identity.signer_id, naalp.envelope.verify_rotation_object).
"""
from .fingerprint_cache import (
    FingerprintCache,
    FingerprintCacheError,
    PinnedIdentity,
)

__all__ = [
    "FingerprintCache",
    "FingerprintCacheError",
    "PinnedIdentity",
]

__version__ = "0.1.0"
