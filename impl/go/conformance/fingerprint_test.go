// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// The corpus-fingerprint drift gate (T4.1). It recomputes the four pinned corpus facts —
// group count, case count, draft number, and the SHA-256 fingerprint over the canonical
// (LF) corpus bytes — and fails if any differs from PIN.json. This is the build-failing
// half of the pin (it runs under `go test ./...`); tools/corpus_fingerprint.py --check is
// the CI/CLI half. Any change to vectors/conformance/corpus.json that is not reflected in
// PIN.json (or vice versa) flips this test pass->fail.
package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type pinnedFingerprint struct {
	Draft      string `json:"draft"`
	GroupCount int    `json:"group_count"`
	CaseCount  int    `json:"case_count"`
	SHA256     string `json:"sha256"`
}

type pinFile struct {
	ConformanceCorpusSHA256 string            `json:"conformance_corpus_sha256"`
	CorpusFingerprint       pinnedFingerprint `json:"corpus_fingerprint"`
}

type corpusDoc struct {
	SpecRevision string `json:"specRevision"`
	TestGroups   []struct {
		Tests []json.RawMessage `json:"tests"`
	} `json:"testGroups"`
}

// repoRoot walks up from this test file to the repository root (the dir with PIN.json).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "PIN.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate the repo root (PIN.json)")
		}
		dir = parent
	}
}

// TestCorpusFingerprintPinned recomputes the four corpus facts from the committed corpus
// and asserts each equals the value pinned in PIN.json. It fails the build on any drift.
func TestCorpusFingerprintPinned(t *testing.T) {
	root := repoRoot(t)

	// Read the corpus as raw bytes (the exact stream the SDKs ride) and hash it.
	corpusRaw, err := os.ReadFile(filepath.Join(root, "vectors", "conformance", "corpus.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	sum := sha256.Sum256(corpusRaw)
	gotSHA := hex.EncodeToString(sum[:])

	var corpus corpusDoc
	if err := json.Unmarshal(corpusRaw, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	gotGroups := len(corpus.TestGroups)
	gotCases := 0
	for _, g := range corpus.TestGroups {
		gotCases += len(g.Tests)
	}
	gotDraft := corpus.SpecRevision

	// Read the pinned values.
	pinRaw, err := os.ReadFile(filepath.Join(root, "PIN.json"))
	if err != nil {
		t.Fatalf("read PIN.json: %v", err)
	}
	var pin pinFile
	if err := json.Unmarshal(pinRaw, &pin); err != nil {
		t.Fatalf("parse PIN.json: %v", err)
	}
	fp := pin.CorpusFingerprint

	if fp.GroupCount != gotGroups {
		t.Errorf("CORPUS DRIFT: group count pinned %d, corpus has %d", fp.GroupCount, gotGroups)
	}
	if fp.CaseCount != gotCases {
		t.Errorf("CORPUS DRIFT: case count pinned %d, corpus has %d", fp.CaseCount, gotCases)
	}
	if fp.Draft != gotDraft {
		t.Errorf("CORPUS DRIFT: draft pinned %q, corpus has %q", fp.Draft, gotDraft)
	}
	if fp.SHA256 != gotSHA {
		t.Errorf("CORPUS DRIFT: fingerprint pinned %s, corpus is %s", fp.SHA256, gotSHA)
	}
	// The fingerprint block and the headline corpus pin must agree (one source of truth).
	if fp.SHA256 != pin.ConformanceCorpusSHA256 {
		t.Errorf("PIN inconsistency: corpus_fingerprint.sha256 %s != conformance_corpus_sha256 %s",
			fp.SHA256, pin.ConformanceCorpusSHA256)
	}

	if !t.Failed() {
		t.Logf("corpus fingerprint pinned OK: %d groups, %d cases, draft %s, sha256 %s",
			gotGroups, gotCases, gotDraft, gotSHA)
	}
}
