# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Repo-relative import bootstrap for the AI-native schema generator.

This package REUSES two Part-2 ecosystem siblings rather than reimplementing their jobs:
`naalp-codec` (E0.3, the blessed deterministic-CBOR binding) for every byte-level encode/
decode/content-id operation on a schema-generated body, and `naalp-validator` (E0.2, the
semantic-intent validator) for the deep envelope-level checks (kind registry, effect-class,
consume-once audience, R7 bounds) a JSON-Schema round trip must still pass. Neither sibling
is `pip install -e`d in this checkout, so this module locates both -- and, transitively,
`impl/python` -- by walking upward from this file, exactly like `naalp_codec._bootstrap` and
`naalp_validator._bootstrap` do; it never uses an absolute path.

The walk looks for a directory containing `impl/python/naalp/__init__.py` (the repo-root
marker both siblings already use), then inserts `impl/python`, `ecosystem/naalp-codec`, and
`ecosystem/naalp-validator` onto sys.path -- in that order, each only if not already present
-- before anything in this package imports `naalp`, `naalp_codec`, or `naalp_validator`.
"""
import os
import sys


class NaalpEcosystemNotFound(RuntimeError):
    """Raised when the repo root (marked by impl/python/naalp/__init__.py) cannot be located
    by walking upward from this file. Fail loud rather than silently importing nothing."""


def _find_repo_root(start):
    d = os.path.abspath(start)
    for _ in range(8):
        marker = os.path.join(d, "impl", "python", "naalp", "__init__.py")
        if os.path.isfile(marker):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def ensure_naalp_ecosystem_on_path():
    """Idempotent: insert impl/python, ecosystem/naalp-codec, and ecosystem/naalp-validator
    onto sys.path (each only if not already present) and return the resolved repo root.
    Raises NaalpEcosystemNotFound if the repo root cannot be located."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = _find_repo_root(here)
    if root is None:
        raise NaalpEcosystemNotFound(
            "could not locate the naalp_draft-01 repo root (impl/python/naalp/__init__.py) "
            "by walking up from %r; naalp-schemagen must live inside the naalp_draft-01 tree" % here
        )
    for rel in (
        os.path.join("impl", "python"),
        os.path.join("ecosystem", "naalp-codec"),
        os.path.join("ecosystem", "naalp-validator"),
    ):
        candidate = os.path.join(root, rel)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    return root


ensure_naalp_ecosystem_on_path()
