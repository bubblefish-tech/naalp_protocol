# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Repo-relative path helpers shared by the naalp-validator test suite. No absolute paths --
walks upward from this file, mirroring naalp_validator._bootstrap and
impl/python/tests/test_audience.py's _find_vector() convention."""
import csv
import os


def _find_repo_root(start):
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isfile(os.path.join(d, "vectors", "registry", "channels.csv")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    raise RuntimeError("could not locate the naalp_draft-01 repo root (vectors/registry/channels.csv) "
                        "by walking up from %r" % start)


REPO_ROOT = _find_repo_root(os.path.dirname(os.path.abspath(__file__)))


def load_channels_csv():
    """Independently parse vectors/registry/channels.csv -- the F3 non-circular authority for
    the kind/effect registry -- WITHOUT importing naalp.channels or naalp_validator. Returns a
    dict {(channel_id:int, kind_code:int): (kind_name:str, effect:int, variable:bool)}.
    effect is coded exactly as the CDDL `effect` enum: read_only=0, idempotent_write=1,
    non_idempotent_write=2, destructive=3 (design.md; spec/naalp-draft-01.cddl)."""
    effect_code = {
        "read_only": 0, "idempotent_write": 1, "non_idempotent_write": 2, "destructive": 3,
        "variable": None,  # a variable-effect kind names no single fixed effect
    }
    path = os.path.join(REPO_ROOT, "vectors", "registry", "channels.csv")
    table = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            channel_id = int(row["channel_id"], 16)
            kind_code = int(row["kind_code"])
            variable = row["variable_effect"].strip().lower() == "true"
            effect = effect_code[row["effect"].strip()]
            table[(channel_id, kind_code)] = (row["kind_name"], effect, variable)
    return table


def load_registered_error_names():
    """Independently parse vectors/registry/error-codes.csv -- the F3 non-circular authority
    for what counts as a real N-AALP error NAME -- WITHOUT importing naalp.naalperror."""
    path = os.path.join(REPO_ROOT, "vectors", "registry", "error-codes.csv")
    names = set()
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            names.add(row["name"])
    return names
