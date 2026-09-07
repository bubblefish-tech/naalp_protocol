// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package envelope

import (
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// Decoder bounds (design.md §3.4, R7). Each bound is proven by a BOUNDARY PAIR:
// an otherwise-valid object AT the limit verifies, and an otherwise-valid object one
// past the limit is rejected with the named error. "Otherwise valid" is load-bearing
// for mutation survival: because the only defect is the bound, deleting the bound
// check makes the over-limit object verify, so a constant-return mutation is caught.

func makeCauses(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		b := make([]byte, 50) // a content-id-shaped bstr (multihash sha2-384 = 0x20 0x30 + 48)
		b[0], b[1] = 0x20, 0x30
		out[i] = b
	}
	return out
}

// makeExtMap builds n distinct non-critical extension entries (unknown keys, which the
// may-ignore rule accepts), so the object is otherwise valid at any cardinality.
func makeExtMap(n int) cbor.Map {
	m := make(cbor.Map, n)
	for i := 0; i < n; i++ {
		m[i] = cbor.Pair{K: cbor.Uint(uint64(100 + i)), V: cbor.Uint(0)}
	}
	return m
}

// nestArrays returns k single-element arrays wrapping a zero scalar. As a body value it
// sits at depth 2 (the object body map is depth 1), so the scalar is at depth 2+k.
func nestArrays(k int) cbor.Value {
	var v cbor.Value = cbor.Uint(0)
	for i := 0; i < k; i++ {
		v = cbor.Arr{v}
	}
	return v
}

// TestBoundsAcceptAtLimit: an object exactly AT each cardinality/depth bound verifies,
// so the boundary is inclusive and the reject tests below prove the boundary itself.
func TestBoundsAcceptAtLimit(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)
	accept := func(name string, o *Object) {
		t.Helper()
		obj, err := Sign(o, s)
		if err != nil {
			t.Fatalf("%s sign: %v", name, err)
		}
		if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, obj); err != nil {
			t.Fatalf("%s verify at-limit: %v", name, err)
		}
	}

	oc := buildObject(t, c)
	oc.Causes = makeCauses(MaxCauses)
	accept("causes==MaxCauses", oc)

	oe := buildObject(t, c)
	oe.Ext = makeExtMap(MaxExt)
	accept("ext==MaxExt", oe)

	// body nested so the deepest scalar sits at exactly MaxNestingDepth (2 + (MaxNestingDepth-2)).
	od := buildObject(t, c)
	od.Body = nestArrays(MaxNestingDepth - 2)
	accept("depth==MaxNestingDepth", od)
}

// TestBoundsRejectOverLimit: an otherwise-valid object one past each bound is rejected
// with its named error (fail-closed).
func TestBoundsRejectOverLimit(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)
	expect := func(name string, o *Object, kind string) {
		t.Helper()
		obj, err := Sign(o, s)
		if err != nil {
			t.Fatalf("%s sign: %v", name, err)
		}
		_, err = Verify(cose.ProfilePublic, v, acceptKind, nil, obj)
		ce, ok := err.(*cose.Error)
		if !ok || ce.Kind != kind {
			t.Errorf("%s: want %s, got %v", name, kind, err)
		}
	}

	oc := buildObject(t, c)
	oc.Causes = makeCauses(MaxCauses + 1)
	expect("TooManyCauses", oc, "TooManyCauses")

	oe := buildObject(t, c)
	oe.Ext = makeExtMap(MaxExt + 1)
	expect("TooManyExtensions(ext)", oe, "TooManyExtensions")

	// cext over the limit also yields TooManyExtensions: the cardinality check in
	// objectFromMap fires before the critical-extension recognition check.
	ox := buildObject(t, c)
	ox.Cext = makeExtMap(MaxCext + 1)
	expect("TooManyExtensions(cext)", ox, "TooManyExtensions")

	// body nested so the deepest scalar sits at MaxNestingDepth+1.
	od := buildObject(t, c)
	od.Body = nestArrays(MaxNestingDepth - 1)
	expect("DepthExceeded", od, "DepthExceeded")
}

// TestBoundTooLarge pins the object octet-size bound: a large-but-under-limit signed
// object verifies, and an otherwise-valid object over the limit is rejected TooLarge on
// the raw bytes before any parse (RFC 8949 §10 decoder-memory guard).
func TestBoundTooLarge(t *testing.T) {
	c := load(t)
	s, v := testSigner(t)

	under := buildObject(t, c)
	under.Body = cbor.Bstr(make([]byte, MaxObjectSize-16384))
	uobj, err := Sign(under, s)
	if err != nil {
		t.Fatalf("sign under-limit: %v", err)
	}
	if len(uobj) > MaxObjectSize {
		t.Fatalf("under-limit object is %d bytes, expected < %d", len(uobj), MaxObjectSize)
	}
	if _, err := Verify(cose.ProfilePublic, v, acceptKind, nil, uobj); err != nil {
		t.Fatalf("verify under-limit: %v", err)
	}

	over := buildObject(t, c)
	over.Body = cbor.Bstr(make([]byte, MaxObjectSize))
	bobj, err := Sign(over, s)
	if err != nil {
		t.Fatalf("sign over-limit: %v", err)
	}
	if len(bobj) <= MaxObjectSize {
		t.Fatalf("over-limit object is only %d bytes, expected > %d", len(bobj), MaxObjectSize)
	}
	_, err = Verify(cose.ProfilePublic, v, acceptKind, nil, bobj)
	ce, ok := err.(*cose.Error)
	if !ok || ce.Kind != "TooLarge" {
		t.Errorf("TooLarge: want TooLarge, got %v", err)
	}
}
