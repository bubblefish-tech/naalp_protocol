# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative path helpers for the naalp-mcp-guard test suite. No absolute paths -- walks
upward from this file, mirroring naalp_mcp_bridge/tests/_paths.py's convention. READ-ONLY: this
package writes nothing outside ecosystem/naalp-mcp-guard/ (and its own state-dir at test-run
time, always under a tempfile.TemporaryDirectory)."""
import os


def _find_repo_root(start):
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isfile(os.path.join(d, "vectors", "mcp", "cases.json")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    raise RuntimeError(
        "could not locate the naalp_draft-01 repo root (vectors/mcp/cases.json) "
        "by walking up from %r" % start
    )


REPO_ROOT = _find_repo_root(os.path.dirname(os.path.abspath(__file__)))
PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ecosystem/naalp-mcp-guard
