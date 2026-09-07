// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package conformance carries the corpus-fingerprint drift gate (T4.1; coding-instructions
// §4). The N-AALP conformance corpus (vectors/conformance/corpus.json) is generated
// deterministically by tools/conformance_corpus.py from the per-family non-circular
// oracles. Four facts about it — group count, case count, draft number, and a SHA-256
// fingerprint over the canonical (LF) corpus bytes — are pinned in PIN.json under
// "corpus_fingerprint". The test in this package recomputes all four and FAILS the build
// (it runs under `go test ./...`) on any drift, so the corpus cannot silently change out
// from under the reference implementations and SDKs that ride its exact bytes.
//
// There is no production code here — the gate is the test. This file exists so the package
// builds and vets as a real package.
package conformance
