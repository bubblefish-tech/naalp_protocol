# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
verify_pins.py — recompute every pinned SHA-256 and fail on drift.

Proves the reference implementations, SDKs, and the submitted Internet-Draft ride the exact
bytes recorded in PIN.json + MANIFEST.sha256. All pinned files are stored LF (.gitattributes
eol=lf) so the hashes are platform-independent; this recomputes raw file bytes and compares.

Run: python scripts/verify_pins.py   (exit 0 iff every pin matches; non-zero on any drift)
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    os.chdir(ROOT)
    failures = []
    checked = 0

    # 1) the per-file manifest
    with open("MANIFEST.sha256", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            want, _, path = line.partition("  ")
            if not path:
                failures.append(f"malformed MANIFEST line: {line!r}")
                continue
            if not os.path.isfile(path):
                failures.append(f"MISSING {path}")
                continue
            got = sha256(path)
            checked += 1
            if got != want:
                failures.append(f"DRIFT {path}\n    want {want}\n    got  {got}")

    # 2) PIN.json headline pins (inline draft + corpus + the manifest itself)
    pin = json.load(open("PIN.json", encoding="utf-8"))
    for key_path, key_hash in [
        ("canonical_draft", "canonical_draft_sha256"),
        ("conformance_corpus", "conformance_corpus_sha256"),
    ]:
        p = pin[key_path]
        if not os.path.isfile(p):
            failures.append(f"PIN.json {key_path}: MISSING {p}")
        elif sha256(p) != pin[key_hash]:
            failures.append(f"PIN.json {key_path}: DRIFT {p}")
        else:
            checked += 1
    if sha256("MANIFEST.sha256") != pin.get("manifest_sha256"):
        failures.append("PIN.json manifest_sha256: DRIFT MANIFEST.sha256")
    else:
        checked += 1

    if failures:
        print("PIN VERIFICATION: FAILED")
        for x in failures:
            print("  -", x)
        return 1
    print(f"PIN VERIFICATION: OK ({checked} hashes match PIN.json + MANIFEST.sha256)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
