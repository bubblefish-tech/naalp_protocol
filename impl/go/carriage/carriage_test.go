// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package carriage_test

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/carriage"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type carriageCase struct {
	ProtocolID     uint64 `json:"protocol_id"`
	Class          uint64 `json:"class"`
	ContentType    uint64 `json:"content_type"`
	CorrelationHex string `json:"correlation_hex"`
	Method         string `json:"method"`
	ForeignHex     string `json:"foreign_hex"`
	BodyHex        string `json:"body_hex"`
}

var classDirs = []struct {
	Dir   string
	Class uint64
}{
	{"jsonrpc", carriage.ClassJSONRPC},
	{"http", carriage.ClassHTTP},
	{"msg", carriage.ClassMSG},
	{"stream", carriage.ClassSTREAM},
	{"doc", carriage.ClassDOC},
	{"opaque", carriage.ClassOPAQUE},
}

func loadClass(t *testing.T, dir string) carriageCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(filepath.Join("../../../vectors/carriage", dir, "cases.json")))
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var c carriageCase
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	return c
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestPerClassOctetExactRoundTrip: R-14.7 — every carriage class encodes to the oracle bytes and
// recovers its foreign message byte-identical (octet-exact), including non-canonical whitespace,
// proving the foreign bytes are never re-serialized (R-14.4). Byte equality with the shared
// oracle in Go and Rust ⟹ Go == Rust.
func TestPerClassOctetExactRoundTrip(t *testing.T) {
	for _, cd := range classDirs {
		c := loadClass(t, cd.Dir)
		if c.Class != cd.Class {
			t.Errorf("%s: class %d, want %d", cd.Dir, c.Class, cd.Class)
		}
		foreign := hx(t, c.ForeignHex)
		cb, err := carriage.Carry(c.ProtocolID, c.Class, c.ContentType, hx(t, c.CorrelationHex), c.Method, foreign)
		if err != nil {
			t.Fatalf("%s: carry: %v", cd.Dir, err)
		}
		if got := hex.EncodeToString(cb.Bytes()); got != c.BodyHex {
			t.Errorf("%s: body bytes\n got %s\nwant %s", cd.Dir, got, c.BodyHex)
		}
		// Round-trip: decode the carriage body and recover the foreign octets exactly.
		v, err := cbor.Decode(cb.Bytes())
		if err != nil {
			t.Fatalf("%s: decode: %v", cd.Dir, err)
		}
		rec, err := carriage.CarriageFromValue(v)
		if err != nil {
			t.Fatalf("%s: from value: %v", cd.Dir, err)
		}
		if !bytes.Equal(rec.Foreign, foreign) {
			t.Fatalf("%s: recovered foreign is not octet-identical", cd.Dir)
		}
		if rec.ProtocolID != c.ProtocolID || rec.Class != c.Class || rec.Method != c.Method {
			t.Errorf("%s: recovered fields differ", cd.Dir)
		}
	}
}

// TestOpaqueUndefinedProtocol: R-18.6 — an undefined protocol carries under OPAQUE on an
// experimental protocol id (no registration), byte-exact.
func TestOpaqueUndefinedProtocol(t *testing.T) {
	c := loadClass(t, "opaque")
	if carriage.ProtocolRange(c.ProtocolID) != "experimental" {
		t.Fatalf("opaque protocol id %#x not experimental", c.ProtocolID)
	}
	blob := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80}
	cb, err := carriage.Carry(c.ProtocolID, carriage.ClassOPAQUE, 1, nil, "", blob)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := cbor.Decode(cb.Bytes())
	rec, err := carriage.CarriageFromValue(v)
	if err != nil || !bytes.Equal(rec.Foreign, blob) {
		t.Fatalf("opaque blob not recovered exactly: err=%v", err)
	}
}

// TestRegistry: the protocol registry CSV assignments are all in the standards range with the
// declared class, and the range boundaries classify per design §13.4.
func TestRegistry(t *testing.T) {
	f, err := os.Open(filepath.Clean("../../../vectors/registry/protocols.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatal("registry has no entries")
	}
	// header: protocol_id,name,class,range,reference
	for _, r := range rows[1:] {
		id, err := strconv.ParseUint(strings.TrimPrefix(r[0], "0x"), 16, 64)
		if err != nil {
			t.Fatalf("bad id %q: %v", r[0], err)
		}
		if carriage.ProtocolRange(id) != "standards" || r[3] != "standards" {
			t.Errorf("id %s: range mismatch (computed %s, csv %s)", r[0], carriage.ProtocolRange(id), r[3])
		}
	}
	// Range boundaries (design §13.4).
	for id, want := range map[uint64]string{0x00: "reserved", 0x01: "standards", 0x0F: "standards", 0x10: "experimental", 0x7F: "experimental", 0x80: "private", 0xFF: "private"} {
		if got := carriage.ProtocolRange(id); got != want {
			t.Errorf("ProtocolRange(%#x)=%s want %s", id, got, want)
		}
	}
}

// TestMappingErrorOnUnknownClass: R-14.8 — an unrepresentable class is a typed mapping error,
// never a silent drop.
func TestMappingErrorOnUnknownClass(t *testing.T) {
	if _, err := carriage.Carry(0x10, 99, 0, nil, "x", []byte("y")); err == nil {
		t.Fatal("unknown class carried")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "MappingError" {
		t.Fatalf("want MappingError, got %v", err)
	}
}

// TestNotDelivered: R-14.8 — a below-foreign failure reports NotDelivered and never a false
// "delivered".
func TestNotDelivered(t *testing.T) {
	rep, err := carriage.Report(false)
	if err == nil || rep.Delivered {
		t.Fatal("failed delivery reported as delivered")
	}
	if ce, ok := err.(*cose.Error); !ok || ce.Kind != "NotDelivered" {
		t.Fatalf("want NotDelivered, got %v", err)
	}
	rep, err = carriage.Report(true)
	if err != nil || !rep.Delivered {
		t.Fatalf("successful delivery not reported: %v", err)
	}
}

// TestIdentityContainment: R-14.6 — a foreign principal named inside the foreign bytes confers no
// authority; the authorizing principal is the N-AALP signer of the carriage object. The carriage
// object is a normal signed envelope object (R-14.2) and its foreign body recovers octet-exact.
func TestIdentityContainment(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 80
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	signer, verifier := cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
	kindOK := func(ch, k uint64) bool { return true }

	foreign := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"from":"attacker-principal"}}`)
	cb, err := carriage.Carry(0x01, carriage.ClassJSONRPC, 0, []byte{1, 2, 3, 4}, "tools/call", foreign)
	if err != nil {
		t.Fatal(err)
	}
	obj := &envelope.Object{Kind: 0, Channel: 13, Tier: 0, Signer: pk.Bytes(), Created: 100, Effect: 0, Profile: uint64(cose.ProfilePublic), Body: cb.ToValue()}
	signed, err := envelope.Sign(obj, signer)
	if err != nil {
		t.Fatal(err)
	}
	o, err := envelope.Verify(cose.ProfilePublic, verifier, kindOK, nil, signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The authority is the N-AALP signer, NOT the foreign principal.
	auth := carriage.CarriageAuthority(o)
	if !bytes.Equal(auth, pk.Bytes()) {
		t.Fatal("authority is not the N-AALP signer")
	}
	if bytes.Contains(auth, []byte("attacker-principal")) {
		t.Fatal("authority leaked from the foreign message")
	}
	// The foreign message still carries the (non-authoritative) principal, recovered octet-exact.
	rec, err := carriage.CarriageFromValue(o.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Foreign, foreign) {
		t.Fatal("foreign not recovered octet-exact from the signed object")
	}
	if !bytes.Contains(rec.Foreign, []byte("attacker-principal")) {
		t.Fatal("foreign principal should be present in the carried message (just not authoritative)")
	}
}
