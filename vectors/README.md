# `vectors/` — the conformance corpus

These are the graded conformance vectors for N-AALP. Each subdirectory holds the
`cases.json` emitted by the matching independent oracle in `tools/` (see
`tools/README.md`), and each is read by the `impl/go` and `impl/rust` test suites. A
green run in both languages proves `Go == Rust == oracle` for that construction
(R-16.1, R-16.2). **These files are generated — do not hand-edit them;** change the
oracle and regenerate.

## Layout

```
vectors/
  cbor/cases.json        C1  deterministic CBOR + content-id            (T1)
  cose/cases.json        C2  COSE_Sign1 + ML-DSA/hybrid                 (T2)
  envelope/cases.json    C3  full object envelope + extensions          (T3)
  identity/cases.json    C4  signer id + rotation/revocation            (T4)
  effect/cases.json      C5  effect vocabulary + authorization matrix   (T5)
  approval/cases.json    C6  approval + single-use consume ledger       (T6)
  audit/cases.json       C7  receipt chain + causal graph + ordering    (T7)
  delivery/cases.json    C8  delivery stages                            (T8)
  stream/cases.json      C9  stream commitment digest                   (T9)
  transport/cases.json   C11 four transport bindings                    (T10)
  carriage/<class>/...   C12 per carriage class octet-exactness         (T11)
  channels/<channel>/... C10 per-channel baseline surface               (T12)
  federation/cases.json      federated ordering / reconcile             (T13)
  registry/*.csv             machine-readable registries (prose source) (T2, T11, T14)
```

Directories appear as their task lands; the list above is the target set, not a set of
empty placeholders.

## `cases.json` shape

```json
{
  "note":       "human note; states that impls must reproduce every *_hex and reject every negative",
  "positives":  [ /* expected-byte cases */ ],
  "negatives":  [ { "name": "...", "bytes_hex": "...", "expect": "<ErrorKind>" } ],
  "sha384_kat": { "input_utf8": "abc", "digest_hex": "cb00753f..." }
}
```

- **positives** carry the exact expected bytes as lowercase hex (`*_hex` fields) plus,
  where the object is structured, a **tagged, language-neutral value** the Go and Rust
  harnesses rebuild before encoding (so the corpus is not itself CBOR-encoded by any one
  implementation).
- **negatives** carry a malformed byte blob and the stable error `Kind` every
  implementation must return; the object is rejected whole with no partial application
  (fail-closed, R-3.4).
- **sha384_kat** anchors the digest to a FIPS 180-4 known answer so an implementation
  proves it computes a real SHA-384, not a constant.

### Tagged value form (positives)

A logical CBOR value is described as a two-element array `[tag, payload]` so the encoder
under test — not the oracle's language — produces the bytes:

| tag     | payload                              | CBOR                        |
|---------|--------------------------------------|-----------------------------|
| `"u"`   | a non-negative integer               | unsigned int (major 0)      |
| `"b"`   | lowercase hex string                 | byte string (major 2)       |
| `"s"`   | a UTF-8 string                       | text string (major 3)       |
| `"arr"` | `[value, ...]`                       | array (major 4)             |
| `"map"` | `[[key, value], ...]`                | map (major 5), canonical    |

Map key order in the tagged form is irrelevant: a conforming encoder emits keys in
canonical (bytewise-ascending) order regardless of input order.

## Line endings

All `cases.json` are LF-only (`.gitattributes` + each oracle writes `newline="\n"`), so
the committed byte stream is platform-independent and a hash-pinned vector gate (T14 /
CI) is stable on Windows and Unix alike.
