# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_bundle -- the N-AALP offline proof bundle (Part-2 ecosystem task E6.5, requirement R12.5).

Packages a signed N-AALP object with the approval that authorized it and the ledger-signed
consume receipt proving that approval was consumed exactly once, into one self-contained byte
string a third party can verify LATER, OFFLINE, with no live service reachable -- using only the
bundle and verifying keys the verifier already holds from an INDEPENDENT source (never keys the
bundle carries about itself; see bundle.py's module docstring for the non-circular-verification
discipline this whole package exists to enforce).

    from naalp_bundle import build_bundle, verify_bundle, TrustAnchor, ProofBundle, BundleError

See bundle.py for the full API and rationale.
"""
from .bundle import (  # noqa: F401
    BundleError,
    ProofBundle,
    TrustAnchor,
    build_bundle,
    default_clock_ms,
    verify_bundle,
)

__all__ = [
    "BundleError",
    "ProofBundle",
    "TrustAnchor",
    "build_bundle",
    "default_clock_ms",
    "verify_bundle",
]

__version__ = "0.1.0"
