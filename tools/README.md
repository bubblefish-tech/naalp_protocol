# `tools/` — independent conformance oracles

Every graded N-AALP construction is checked against an **independent authority**, never
against the code under test (R-16.1; CLAUDE.md "NON-CIRCULAR ORACLES"). This directory
holds those authorities: from-scratch Python constructors that emit the expected bytes
for a construction, written only against the primary standard (an RFC, a FIPS
known-answer vector, or the multiformats tables) and sharing no code with `impl/go` or
`impl/rust`.

## Naming and dataflow convention

```
tools/<name>_oracle.py   -->   vectors/<name>/cases.json   -->   read by impl/go + impl/rust tests
```

- One oracle per spine construction: `<name>` matches the vector directory
  (`cbor` -> `tools/cbor_oracle.py` -> `vectors/cbor/cases.json`).
- Running `python tools/<name>_oracle.py` (re)writes `vectors/<name>/cases.json`. The
  oracle takes no arguments and is deterministic: the same source always emits the same
  bytes, so a drift between its output and the committed corpus is a real defect (the
  `scripts/verify.sh` step 4 gate fails on it).
- Go and Rust tests read `vectors/<name>/cases.json` and assert their own independently
  computed bytes equal the oracle's. A green run in **both** languages therefore proves
  `Go == Rust == oracle` — the two-implementation byte-parity claim (R-16.2).

## Rules every oracle in this directory follows

1. **Non-circular.** Expected values derive from the cited primary authority only. Each
   oracle names its authorities in its module docstring (e.g. `cbor_oracle.py` cites RFC
   8949 §4.2.1, FIPS 180-4 SHA-384, and the multiformats multihash table).
2. **From scratch.** No import of `impl/go` or `impl/rust`, and no third-party package —
   the Python standard library only (`hashlib`, `json`, ...), so the oracle is
   reproducible with a bare interpreter and depends on nothing the implementations use.
3. **Emits positives and negatives.** Positives carry the exact expected `*_hex` bytes;
   negatives carry hand-crafted malformed inputs with the stable error `Kind` each
   implementation must return (fail-closed, R-3.4).
4. **LF output.** Files are opened with `newline="\n"` so the generated JSON is LF on
   every platform, matching the LF-normalized git blob (`.gitattributes`) so a
   hash-pinned vector gate never drifts on Windows CRLF.
5. **Copyright header.** Every oracle begins with
   `# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.`

## Running

```
python tools/cbor_oracle.py     # regenerate one vector set
bash   scripts/verify.sh        # regenerate all + grade Go and Rust against them
```

New oracles are added by the task that introduces their construction (e.g.
`cose_oracle.py` at T2, `signerid_oracle.py` at T4), each following the rules above.
