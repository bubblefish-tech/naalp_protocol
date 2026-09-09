# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Local guard/approver identity seed management for `naalp-mcp-guard wrap` (Group 6).

Honest scope: this is a single-operator local key store -- a raw 32-byte ML-DSA seed persisted
to a file (0600), created on first use. It is NOT a KMS, NOT multi-operator, and NOT rotated.
That is the deliberate MVP scope for the "own the click" free tier (design.md Sec.2.7's compose
mode, Task A.4, is where a deployment with a real key-management story plugs in); nothing here
pretends otherwise."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup)

import os

SEED_BYTES = 32


def load_or_create_seed(path: str) -> bytes:
    """Load the 32-byte seed at `path`, creating it (via a real CSPRNG, `os.urandom`) if absent.
    Raises ValueError if a file exists at `path` but is not exactly 32 bytes (refuse to silently
    truncate or pad a corrupted identity -- fail-closed)."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != SEED_BYTES:
            raise ValueError(
                "guard identity seed file %r is %d bytes, expected %d" % (path, len(data), SEED_BYTES)
            )
        return data

    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    seed = os.urandom(SEED_BYTES)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost a create race to a concurrent invocation; use whatever it wrote.
        with open(path, "rb") as f:
            return f.read()
    with os.fdopen(fd, "wb") as f:
        f.write(seed)
        f.flush()
        os.fsync(f.fileno())
    return seed


__all__ = ["load_or_create_seed", "SEED_BYTES"]
