// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package cbor

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// The shared conformance corpus is produced by the independent Python oracle
// (tools/cbor_oracle.py). These tests assert Go reproduces the oracle bytes exactly
// and rejects every non-canonical negative. Rust runs the identical assertions, so a
// green run in both proves Go == Rust == oracle (R-16.1, R-16.2).
const vectorPath = "../../../vectors/cbor/cases.json"

type casesFile struct {
	Positives []struct {
		Name       string                     `json:"name"`
		ObjWithout map[string]json.RawMessage `json:"obj_without_id"`
		BodyNo1Hex string                     `json:"body_no1_hex"`
		IDHex      string                     `json:"id_hex"`
		FullHex    string                     `json:"full_hex"`
	} `json:"positives"`
	Negatives []struct {
		Name     string `json:"name"`
		BytesHex string `json:"bytes_hex"`
		Expect   string `json:"expect"`
	} `json:"negatives"`
	SHA384KAT struct {
		InputUTF8 string `json:"input_utf8"`
		DigestHex string `json:"digest_hex"`
	} `json:"sha384_kat"`
}

func loadCases(t *testing.T) casesFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c casesFile
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// buildValue rebuilds a CBOR Value from the oracle's tagged JSON form:
// ["u", n] | ["b", hex] | ["s", text] | ["arr", [...]] | ["map", [[k,v], ...]].
func buildValue(t *testing.T, raw json.RawMessage) Value {
	t.Helper()
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("tagged value: %v", err)
	}
	var tag string
	if err := json.Unmarshal(arr[0], &tag); err != nil {
		t.Fatalf("tag: %v", err)
	}
	switch tag {
	case "u":
		var num json.Number
		dec := json.NewDecoder(bytes.NewReader(arr[1]))
		dec.UseNumber()
		if err := dec.Decode(&num); err != nil {
			t.Fatalf("uint: %v", err)
		}
		u, err := strconv.ParseUint(num.String(), 10, 64)
		if err != nil {
			t.Fatalf("uint parse: %v", err)
		}
		return Uint(u)
	case "b":
		var s string
		json.Unmarshal(arr[1], &s)
		bs, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bstr hex: %v", err)
		}
		return Bstr(bs)
	case "s":
		var s string
		json.Unmarshal(arr[1], &s)
		return Tstr(s)
	case "arr":
		var items []json.RawMessage
		json.Unmarshal(arr[1], &items)
		out := make(Arr, 0, len(items))
		for _, it := range items {
			out = append(out, buildValue(t, it))
		}
		return out
	case "map":
		var pairs [][]json.RawMessage
		json.Unmarshal(arr[1], &pairs)
		out := make(Map, 0, len(pairs))
		for _, p := range pairs {
			out = append(out, Pair{K: buildValue(t, p[0]), V: buildValue(t, p[1])})
		}
		return out
	}
	t.Fatalf("unknown tag %q", tag)
	return nil
}

// bodyWithoutID rebuilds the object body (fields 2..N, no id) from the oracle case.
func bodyWithoutID(t *testing.T, obj map[string]json.RawMessage) Map {
	t.Helper()
	keys := make([]int, 0, len(obj))
	for k := range obj {
		n, err := strconv.Atoi(k)
		if err != nil {
			t.Fatalf("field key %q: %v", k, err)
		}
		keys = append(keys, n)
	}
	sort.Ints(keys)
	m := make(Map, 0, len(keys))
	for _, k := range keys {
		m = append(m, Pair{K: Uint(uint64(k)), V: buildValue(t, obj[strconv.Itoa(k)])})
	}
	return m
}

func TestPositivesMatchOracle(t *testing.T) {
	c := loadCases(t)
	if len(c.Positives) == 0 {
		t.Fatal("no positive cases in corpus")
	}
	for _, p := range c.Positives {
		body := bodyWithoutID(t, p.ObjWithout)

		bodyEnc, err := Encode(body)
		if err != nil {
			t.Fatalf("%s: encode body: %v", p.Name, err)
		}
		if got := hex.EncodeToString(bodyEnc); got != p.BodyNo1Hex {
			t.Errorf("%s: body_no1\n got %s\nwant %s", p.Name, got, p.BodyNo1Hex)
		}

		id, err := ContentID(body)
		if err != nil {
			t.Fatalf("%s: content id: %v", p.Name, err)
		}
		if got := hex.EncodeToString(id); got != p.IDHex {
			t.Errorf("%s: content-id\n got %s\nwant %s", p.Name, got, p.IDHex)
		}

		full := append(Map{{K: Uint(1), V: Bstr(id)}}, body...)
		fullEnc, err := Encode(full)
		if err != nil {
			t.Fatalf("%s: encode full: %v", p.Name, err)
		}
		if got := hex.EncodeToString(fullEnc); got != p.FullHex {
			t.Errorf("%s: full\n got %s\nwant %s", p.Name, got, p.FullHex)
		}

		// Round-trip: the canonical bytes decode and re-encode identically.
		wantBytes, _ := hex.DecodeString(p.FullHex)
		v, err := Decode(wantBytes)
		if err != nil {
			t.Fatalf("%s: decode full: %v", p.Name, err)
		}
		reEnc, err := Encode(v)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", p.Name, err)
		}
		if !bytes.Equal(reEnc, wantBytes) {
			t.Errorf("%s: round-trip not identical", p.Name)
		}
	}
}

func TestNegativesRejected(t *testing.T) {
	c := loadCases(t)
	if len(c.Negatives) == 0 {
		t.Fatal("no negative cases in corpus")
	}
	for _, n := range c.Negatives {
		raw, err := hex.DecodeString(n.BytesHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", n.Name, err)
		}
		v, err := Decode(raw)
		if err == nil {
			t.Errorf("%s: expected rejection, decoded %v", n.Name, v)
			continue
		}
		ce, ok := err.(*Error)
		if !ok || ce.Kind != n.Expect {
			t.Errorf("%s: expected %s, got %v", n.Name, n.Expect, err)
		}
	}
}

func TestSHA384KAT(t *testing.T) {
	c := loadCases(t)
	d := sha512.Sum384([]byte(c.SHA384KAT.InputUTF8))
	if got := hex.EncodeToString(d[:]); got != c.SHA384KAT.DigestHex {
		t.Errorf("SHA-384 KAT\n got %s\nwant %s", got, c.SHA384KAT.DigestHex)
	}
}

// TestEncodeIsNotConstant is the mutation guard: a constant-returning encoder would
// make two distinct objects encode identically, and would not match the content-id.
func TestEncodeIsNotConstant(t *testing.T) {
	a, _ := Encode(Map{{K: Uint(1), V: Uint(0)}})
	b, _ := Encode(Map{{K: Uint(1), V: Uint(1)}})
	if bytes.Equal(a, b) {
		t.Fatal("encoder produced identical bytes for different inputs (constant?)")
	}
	idA, _ := ContentID(Map{{K: Uint(2), V: Tstr("x")}})
	idB, _ := ContentID(Map{{K: Uint(2), V: Tstr("y")}})
	if bytes.Equal(idA, idB) {
		t.Fatal("content-id identical for different bodies (constant digest?)")
	}
	if idA[0] != 0x20 || idA[1] != 0x30 || len(idA) != 50 {
		t.Fatalf("content-id framing wrong: % x (len %d)", idA[:2], len(idA))
	}
}

// TestEmptyVsAbsentOptional is the R-3.3 "absent != empty" edge case (design.md §3.3):
// an optional field present but empty MUST encode differently from the same object with
// that field absent, must produce a different content id, and both must round-trip with
// the distinction preserved. Independent of the vector file so it grades the codec
// directly; mutation-surviving because a constant encoder collapses the two to equal.
func TestEmptyVsAbsentOptional(t *testing.T) {
	base := Map{
		{K: Uint(2), V: Uint(0)},
		{K: Uint(10), V: Tstr("x")},
	}
	absent := base
	empty := append(append(Map{}, base...), Pair{K: Uint(11), V: Map{}}) // field 11 present, empty

	ea, err := Encode(absent)
	if err != nil {
		t.Fatalf("encode absent: %v", err)
	}
	eb, err := Encode(empty)
	if err != nil {
		t.Fatalf("encode empty: %v", err)
	}
	if bytes.Equal(ea, eb) {
		t.Fatal("absent optional field encoded identically to present-empty field")
	}
	ida, _ := ContentID(absent)
	idb, _ := ContentID(empty)
	if bytes.Equal(ida, idb) {
		t.Fatal("absent vs present-empty produced identical content ids")
	}

	// Both round-trip byte-identically.
	for _, enc := range [][]byte{ea, eb} {
		v, err := Decode(enc)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		re, err := Encode(v)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if !bytes.Equal(re, enc) {
			t.Fatal("round-trip not identical")
		}
	}

	// The distinction survives the round-trip: present-empty keeps key 11 as an empty
	// map; absent has no key 11.
	present, _ := Decode(eb)
	var has11 bool
	for _, p := range present.(Map) {
		if p.K == Uint(11) {
			has11 = true
			if inner, ok := p.V.(Map); !ok || len(inner) != 0 {
				t.Fatal("field 11 should decode to an empty map")
			}
		}
	}
	if !has11 {
		t.Fatal("present-empty field 11 lost on round-trip")
	}
	gone, _ := Decode(ea)
	for _, p := range gone.(Map) {
		if p.K == Uint(11) {
			t.Fatal("absent field 11 appeared after round-trip")
		}
	}
}

// TestNintRFC8949 grades the negative-integer (major type 1) codec extension that COSE
// algorithm ids require, against the RFC 8949 Appendix A worked examples (independent
// authority). Mutation-surviving: a constant encoder fails the fixed hex expectations.
func TestNintRFC8949(t *testing.T) {
	cases := []struct {
		v   int64
		hex string
	}{
		{-1, "20"}, {-10, "29"}, {-100, "3863"}, {-1000, "3903e7"}, // RFC 8949 App. A
		{-49, "3830"}, // COSE ML-DSA-65 alg id
		{-50, "3831"}, // COSE ML-DSA-87 alg id
		{-19, "32"},   // COSE Ed25519 alg id
	}
	for _, c := range cases {
		enc, err := Encode(Nint(c.v))
		if err != nil {
			t.Fatalf("encode Nint(%d): %v", c.v, err)
		}
		if got := hex.EncodeToString(enc); got != c.hex {
			t.Errorf("Encode(Nint(%d)) = %s, want %s", c.v, got, c.hex)
		}
		raw, _ := hex.DecodeString(c.hex)
		v, err := Decode(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", c.hex, err)
		}
		if v != Nint(c.v) {
			t.Errorf("Decode(%s) = %v, want Nint(%d)", c.hex, v, c.v)
		}
	}
	if _, err := Encode(Nint(0)); err == nil {
		t.Error("Nint(0) must be unencodable (not negative)")
	}
}
