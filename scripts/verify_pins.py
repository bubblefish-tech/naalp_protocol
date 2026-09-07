# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
verify_pins.py — recompute every pinned SHA-256 and fail on drift.

Proves the reference implementations, SDKs, and the submitted Internet-Draft ride the exact
bytes recorded in PIN.json + MANIFEST.sha256. All pinned files are stored LF (.gitattributes
eol=lf) so the hashes are platform-independent; this recomputes raw file bytes and compares.

Run: python scripts/verify_pins.py   (exit 0 iff every pin matches; non-zero on any drift)

collect_pins() is the provider used both by this standalone CLI and by
scripts/gates/gate_pins.py, which wires this check into the self-testing gate suite
(the gate suite). Keeping ONE collector means the gate and the CLI can never drift
apart — the [unwired-gate] failure that let a stale CDDL pin survive a "13/13 green" report
(2026-08-20) was precisely this check living OUTSIDE the discovered gate set.
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def collect_pins():
    """Gather one record per pinned artifact from MANIFEST.sha256 + PIN.json.

    Each record: {label, path, want, got, status} where status is one of
    'ok' | 'drift' | 'missing' | 'malformed'. Paths are resolved against ROOT so the
    collector has no cwd dependency (it is called from the gate framework, which runs it
    from an arbitrary directory). This reads the tree; the pure verdict is check().
    """
    records = []

    # 1) the per-file manifest
    manifest = os.path.join(ROOT, "MANIFEST.sha256")
    with open(manifest, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            want, _, path = line.partition("  ")
            if not path:
                records.append({"label": "MANIFEST line", "path": None, "want": None,
                                "got": None, "status": "malformed", "detail": line})
                continue
            full = os.path.join(ROOT, path)
            if not os.path.isfile(full):
                records.append({"label": "MANIFEST %s" % path, "path": path, "want": want,
                                "got": None, "status": "missing"})
                continue
            got = sha256(full)
            records.append({"label": "MANIFEST %s" % path, "path": path, "want": want,
                            "got": got, "status": "ok" if got == want else "drift"})

    # 2) PIN.json headline pins (inline draft + corpus + the manifest itself)
    pin = json.load(open(os.path.join(ROOT, "PIN.json"), encoding="utf-8"))
    for key_path, key_hash in [
        ("canonical_draft", "canonical_draft_sha256"),
        ("conformance_corpus", "conformance_corpus_sha256"),
    ]:
        p = pin[key_path]
        full = os.path.join(ROOT, p)
        want = pin[key_hash]
        if not os.path.isfile(full):
            records.append({"label": "PIN.json %s" % key_path, "path": p, "want": want,
                            "got": None, "status": "missing"})
        else:
            got = sha256(full)
            records.append({"label": "PIN.json %s" % key_path, "path": p, "want": want,
                            "got": got, "status": "ok" if got == want else "drift"})
    mg = sha256(manifest)
    want_m = pin.get("manifest_sha256")
    records.append({"label": "PIN.json manifest_sha256", "path": "MANIFEST.sha256",
                    "want": want_m, "got": mg, "status": "ok" if mg == want_m else "drift"})
    return records


def render_failure(r):
    """One human line for a non-ok record."""
    if r["status"] == "drift":
        return "DRIFT %s\n    want %s\n    got  %s" % (r["path"], r["want"], r["got"])
    if r["status"] == "missing":
        return "MISSING %s" % r["path"]
    if r["status"] == "malformed":
        return "malformed MANIFEST line: %r" % r.get("detail", "")
    return "UNEXPECTED status %r for %s" % (r["status"], r.get("path"))


def main():
    records = collect_pins()
    failures = [render_failure(r) for r in records if r["status"] != "ok"]
    checked = sum(1 for r in records if r["status"] == "ok")
    if failures:
        print("PIN VERIFICATION: FAILED")
        for x in failures:
            print("  -", x)
        return 1
    print("PIN VERIFICATION: OK (%d hashes match PIN.json + MANIFEST.sha256)" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
