// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"bytes"
	"strings"
	"testing"
)

// Independent oracle: SHA-256/SHA-384 of "" and "abc", computed via .NET's
// System.Security.Cryptography (PowerShell, this session) — a different implementation
// and runtime than Go's crypto/sha256, so a match here is not circular (F3).
const (
	sha256EmptyHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sha384EmptyHex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	sha256ABCHex   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	sha384ABCHex   = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
)

func TestDigestBytesMatchesIndependentOracle(t *testing.T) {
	empty := DigestBytes(nil)
	if empty["sha256"] != sha256EmptyHex {
		t.Fatalf("sha256(\"\") = %s, want %s", empty["sha256"], sha256EmptyHex)
	}
	if empty["sha384"] != sha384EmptyHex {
		t.Fatalf("sha384(\"\") = %s, want %s", empty["sha384"], sha384EmptyHex)
	}

	abc := DigestBytes([]byte("abc"))
	if abc["sha256"] != sha256ABCHex {
		t.Fatalf("sha256(\"abc\") = %s, want %s", abc["sha256"], sha256ABCHex)
	}
	if abc["sha384"] != sha384ABCHex {
		t.Fatalf("sha384(\"abc\") = %s, want %s", abc["sha384"], sha384ABCHex)
	}
}

// TestDigestBytesChangesWithInput is the A4 mutation-surviving test: a digest function
// whose body ignores its parameter (e.g. always returning the empty-input digest) fails
// this test, because "abc" and "" produce different digests above and this test asserts
// two DISTINCT non-trivial inputs also produce distinct output.
func TestDigestBytesChangesWithInput(t *testing.T) {
	d1 := DigestBytes([]byte("hello"))
	d2 := DigestBytes([]byte("world"))
	if d1["sha256"] == d2["sha256"] {
		t.Fatal("DigestBytes(\"hello\") and DigestBytes(\"world\") produced the same sha256 — input is being ignored")
	}
	if d1["sha384"] == d2["sha384"] {
		t.Fatal("DigestBytes(\"hello\") and DigestBytes(\"world\") produced the same sha384 — input is being ignored")
	}
	// A single flipped bit changes the digest (avalanche property, not merely "different
	// length input differs").
	d3 := DigestBytes([]byte("hellp")) // last byte 'o'(0x6f) -> 'p'(0x70), one flipped bit... actually two bits; still a minimal edit
	if d1["sha256"] == d3["sha256"] {
		t.Fatal("a one-character edit did not change the sha256 digest")
	}
}

func TestDigestReaderMatchesDigestBytes(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog")
	want := DigestBytes(data)
	got, err := DigestReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DigestReader: %v", err)
	}
	if got["sha256"] != want["sha256"] || got["sha384"] != want["sha384"] {
		t.Fatalf("DigestReader(%q) = %v, want %v (from DigestBytes)", data, got, want)
	}
}

func TestDigestReaderRejectsNilReader(t *testing.T) {
	_, err := DigestReader(nil)
	if err != ErrEmptyInput {
		t.Fatalf("DigestReader(nil) error = %v, want ErrEmptyInput", err)
	}
}

func TestDigestReaderPropagatesReadError(t *testing.T) {
	_, err := DigestReader(errReader{})
	if err == nil {
		t.Fatal("DigestReader did not propagate the underlying read error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

var errBoom = &boomError{}

type boomError struct{}

func (*boomError) Error() string { return "boom" }

func TestDigestSetEqual(t *testing.T) {
	a := DigestSet{"sha256": "aa", "sha384": "bb"}
	b := DigestSet{"sha256": "aa", "sha512": "cc"} // overlapping only on sha256
	if !a.Equal(b) {
		t.Fatal("Equal should be true: sha256 matches, sha384/sha512 are non-overlapping algorithms")
	}
	c := DigestSet{"sha256": "different"}
	if a.Equal(c) {
		t.Fatal("Equal should be false: sha256 values disagree")
	}
	if a.Equal(DigestSet{}) {
		t.Fatal("Equal should be false against an empty set")
	}
	if (DigestSet{}).Equal(a) {
		t.Fatal("Equal should be false from an empty set")
	}
	// A DigestSet sharing zero algorithm names with another is not "equal" by omission.
	d := DigestSet{"sha3-256": "zz"}
	if a.Equal(d) {
		t.Fatal("Equal should be false: no shared algorithm at all")
	}
}

func TestDigestSetHexIsLowercase(t *testing.T) {
	d := DigestBytes([]byte("Case Check"))
	if strings.ToLower(d["sha256"]) != d["sha256"] {
		t.Fatalf("sha256 hex is not lowercase: %s", d["sha256"])
	}
}
