# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
corpus_fingerprint.py — the ONE command (coding-instructions §4, T4.1) that prints, from a
single invocation, the four drift-pinned facts about the N-AALP conformance corpus:

  * group count  — number of op groups in vectors/conformance/corpus.json
  * case count   — total test cases across all groups
  * draft number — the corpus specRevision (the draft the corpus targets)
  * fingerprint  — a deterministic SHA-256 over the canonical (LF) corpus bytes

The corpus is generated deterministically by tools/conformance_corpus.py with LF line
endings (.gitattributes eol=lf), so the fingerprint is platform-independent. These four
values are pinned in PIN.json under "corpus_fingerprint" and the build fails on any drift
(the pinned-drift gate lives in impl/go/conformance and runs under `go test ./...`).

Run:
  python tools/corpus_fingerprint.py           # print the four values
  python tools/corpus_fingerprint.py --check    # print + compare to PIN.json; exit 1 on drift
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "vectors", "conformance", "corpus.json")
PIN = os.path.join(ROOT, "PIN.json")


def fingerprint():
    """Return (group_count, case_count, draft, sha256_hex) for the committed corpus.

    The fingerprint is SHA-256 over the raw corpus bytes (read in binary), so it is exactly
    the byte stream every reference implementation and SDK rides.
    """
    with open(CORPUS, "rb") as f:
        raw = f.read()
    sha = hashlib.sha256(raw).hexdigest()
    doc = json.loads(raw)
    groups = doc["testGroups"]
    group_count = len(groups)
    case_count = sum(len(g["tests"]) for g in groups)
    draft = doc["specRevision"]
    return group_count, case_count, draft, sha


def main(argv):
    group_count, case_count, draft, sha = fingerprint()
    print("N-AALP conformance corpus fingerprint")
    print(f"  group count:  {group_count}")
    print(f"  case count:   {case_count}")
    print(f"  draft number: {draft}")
    print(f"  fingerprint:  {sha}")

    if "--check" in argv:
        pin = json.load(open(PIN, encoding="utf-8")).get("corpus_fingerprint")
        if not pin:
            print("DRIFT: PIN.json has no corpus_fingerprint block", file=sys.stderr)
            return 1
        drifts = []
        if pin.get("group_count") != group_count:
            drifts.append(f"group count: pinned {pin.get('group_count')} != {group_count}")
        if pin.get("case_count") != case_count:
            drifts.append(f"case count: pinned {pin.get('case_count')} != {case_count}")
        if pin.get("draft") != draft:
            drifts.append(f"draft: pinned {pin.get('draft')!r} != {draft!r}")
        if pin.get("sha256") != sha:
            drifts.append(f"fingerprint: pinned {pin.get('sha256')} != {sha}")
        if drifts:
            print("CORPUS FINGERPRINT DRIFT:", file=sys.stderr)
            for d in drifts:
                print("  -", d, file=sys.stderr)
            return 1
        print("  == PIN.json (no drift)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
