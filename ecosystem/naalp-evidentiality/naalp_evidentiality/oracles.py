# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A concrete, reusable basis-1 Oracle: wraps hashlib.sha384 -- the SAME real digest primitive
`naalp.audit.Receipt.head()` already uses (see impl/python/naalp/audit.py), not a
reimplementation. Provided so a caller has a real, working oracle to register for demos and
tests without inventing a domain-specific one; a production caller is free to register any other
deterministic Oracle for its own domain (a price feed, a policy evaluator, ...) under a
different oracle id.
"""
import hashlib

from .evidentiality import Oracle


class Sha384Oracle(Oracle):
    """Establishes a value as SHA-384(input_bytes) -- deterministic, and independently
    checkable by anyone holding the input (hashlib.sha384 is a Python standard-library
    primitive; this class performs no cryptographic work of its own beyond calling it)."""

    def establish(self, input_bytes: bytes) -> bytes:
        return hashlib.sha384(bytes(input_bytes)).digest()
