// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package cbor implements N-AALP's deterministic CBOR encoding (RFC 8949 §4.2.1)
// and the object content-id (design.md §2.3). It is the C1 spine component: one
// canonical byte encoding shared by every object, and a self-certifying content id
// computed as multihash(0x20, SHA-384(canonical-body-without-field-1)).
//
// The encoder emits only shortest-form heads, sorts map keys ascending by their
// encoded bytes, and rejects duplicate keys. The decoder is strict: it rejects any
// non-canonical input (non-shortest heads, indefinite lengths, reserved additional
// information, unsorted or duplicate map keys, trailing bytes, invalid UTF-8) with a
// NonCanonical error and never partially applies it (R-3.1, R-3.4).
package cbor

import (
	"bytes"
	"crypto/sha512"
	"math"
	"sort"
	"unicode/utf8"
)

// Value is a CBOR value in the subset N-AALP's spine uses: unsigned integers, byte
// strings, text strings, arrays, and integer/other-keyed maps. No floats, tags,
// negatives, or booleans appear in the spine (design.md §3.1).
type Value interface{ isValue() }

// Uint is a CBOR unsigned integer (major type 0).
type Uint uint64

// Nint is a CBOR negative integer (major type 1); its value is < 0. The N-AALP object
// body uses no negatives (a surface rule), but the COSE protected header (§4) encodes
// negative algorithm identifiers (e.g. ML-DSA-65 = -49), so the codec must handle
// major type 1. A negative integer n is encoded per RFC 8949 as major 1 with argument
// -1-n (shortest form).
type Nint int64

// Bstr is a CBOR byte string (major type 2).
type Bstr []byte

// Tstr is a CBOR text string (major type 3), carried as UTF-8.
type Tstr string

// Arr is a CBOR array (major type 4).
type Arr []Value

// Tag is a CBOR tag (major type 6): a tag number applied to a tagged content value.
// N-AALP uses tags to make a signed object self-identifying — COSE_Sign1 is tag 18 and
// the hybrid COSE_Sign is tag 98 (RFC 9052), and a verifier selects the structure by the
// tag (design.md §4.2). Deterministic encoding uses the shortest-form tag number.
type Tag struct {
	Number  uint64
	Content Value
}

// Pair is one entry of a Map.
type Pair struct {
	K Value
	V Value
}

// Map is a CBOR map (major type 5). Insertion order is irrelevant; Encode emits the
// canonical order (keys ascending by encoded bytes).
type Map []Pair

func (Uint) isValue() {}
func (Nint) isValue() {}
func (Bstr) isValue() {}
func (Tstr) isValue() {}
func (Arr) isValue()  {}
func (Tag) isValue()  {}
func (Map) isValue()  {}

// Error is a decode/encode failure carrying a stable Kind used by tests and callers.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Msg }

func nonCanonical(msg string) *Error { return &Error{Kind: "NonCanonical", Msg: msg} }

// encHead writes the shortest-form head for a major type and argument n.
func encHead(major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n < 24:
		return []byte{mt | byte(n)}
	case n < 1<<8:
		return []byte{mt | 24, byte(n)}
	case n < 1<<16:
		return []byte{mt | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		return []byte{mt | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{mt | 27,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// Encode returns the deterministic CBOR encoding of v (RFC 8949 §4.2.1).
func Encode(v Value) ([]byte, error) {
	switch t := v.(type) {
	case Uint:
		return encHead(0, uint64(t)), nil
	case Nint:
		if t >= 0 {
			return nil, &Error{Kind: "Unencodable", Msg: "Nint must be negative"}
		}
		// argument = -1 - t, computed without overflow at math.MinInt64
		arg := uint64(-(t + 1))
		return encHead(1, arg), nil
	case Bstr:
		return append(encHead(2, uint64(len(t))), t...), nil
	case Tstr:
		b := []byte(string(t))
		if !utf8.Valid(b) {
			return nil, nonCanonical("text string is not valid UTF-8")
		}
		return append(encHead(3, uint64(len(b))), b...), nil
	case Arr:
		out := encHead(4, uint64(len(t)))
		for _, it := range t {
			e, err := Encode(it)
			if err != nil {
				return nil, err
			}
			out = append(out, e...)
		}
		return out, nil
	case Tag:
		out := encHead(6, t.Number)
		c, err := Encode(t.Content)
		if err != nil {
			return nil, err
		}
		return append(out, c...), nil
	case Map:
		type enc struct{ k, v []byte }
		encs := make([]enc, 0, len(t))
		seen := make(map[string]struct{}, len(t))
		for _, p := range t {
			ek, err := Encode(p.K)
			if err != nil {
				return nil, err
			}
			ev, err := Encode(p.V)
			if err != nil {
				return nil, err
			}
			if _, dup := seen[string(ek)]; dup {
				return nil, nonCanonical("duplicate map key")
			}
			seen[string(ek)] = struct{}{}
			encs = append(encs, enc{ek, ev})
		}
		sort.Slice(encs, func(i, j int) bool { return bytes.Compare(encs[i].k, encs[j].k) < 0 })
		out := encHead(5, uint64(len(t)))
		for _, e := range encs {
			out = append(out, e.k...)
			out = append(out, e.v...)
		}
		return out, nil
	default:
		return nil, &Error{Kind: "Unencodable", Msg: "unsupported value type"}
	}
}

// ContentID computes the object content-id of a body map (design.md §2.3):
// multihash(0x20, SHA-384(canonical-encoding(body))). The caller passes the body
// with field 1 (the id itself) omitted; the returned 50-byte id is 0x20 0x30 || digest.
func ContentID(bodyWithoutID Map) ([]byte, error) {
	enc, err := Encode(bodyWithoutID)
	if err != nil {
		return nil, err
	}
	d := sha512.Sum384(enc)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30) // multihash: sha2-384 code 0x20, length 48 = 0x30
	out = append(out, d[:]...)
	return out, nil
}

// Decode parses one deterministic-CBOR value from data and requires that data is
// exactly one canonical item with no trailing bytes. Any non-canonical input is
// rejected with a NonCanonical error (fail-closed, R-3.4).
func Decode(data []byte) (Value, error) {
	v, rest, err := decode(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, nonCanonical("trailing bytes after item")
	}
	return v, nil
}

func decode(b []byte) (Value, []byte, error) {
	if len(b) == 0 {
		return nil, nil, nonCanonical("unexpected end of input")
	}
	ib := b[0]
	major := ib >> 5
	ai := ib & 0x1f
	arg, rest, err := readArg(ai, b[1:])
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0: // unsigned int
		return Uint(arg), rest, nil
	case 1: // negative int: value = -1 - arg
		if arg > uint64(math.MaxInt64) {
			return nil, nil, nonCanonical("negative integer out of supported range")
		}
		return Nint(-1 - int64(arg)), rest, nil
	case 2: // byte string
		if uint64(len(rest)) < arg {
			return nil, nil, nonCanonical("byte string longer than input")
		}
		return Bstr(append([]byte(nil), rest[:arg]...)), rest[arg:], nil
	case 3: // text string
		if uint64(len(rest)) < arg {
			return nil, nil, nonCanonical("text string longer than input")
		}
		s := rest[:arg]
		if !utf8.Valid(s) {
			return nil, nil, nonCanonical("text string is not valid UTF-8")
		}
		return Tstr(string(s)), rest[arg:], nil
	case 4: // array
		items := make(Arr, 0, arg)
		cur := rest
		for i := uint64(0); i < arg; i++ {
			var it Value
			it, cur, err = decode(cur)
			if err != nil {
				return nil, nil, err
			}
			items = append(items, it)
		}
		return items, cur, nil
	case 5: // map
		pairs := make(Map, 0, arg)
		cur := rest
		var prevKey []byte
		for i := uint64(0); i < arg; i++ {
			keyStart := cur
			var k Value
			k, cur, err = decode(cur)
			if err != nil {
				return nil, nil, err
			}
			kbytes := keyStart[:len(keyStart)-len(cur)]
			if prevKey != nil {
				switch bytes.Compare(prevKey, kbytes) {
				case 1:
					return nil, nil, nonCanonical("map keys not in canonical order")
				case 0:
					return nil, nil, nonCanonical("duplicate map key")
				}
			}
			prevKey = kbytes
			var val Value
			val, cur, err = decode(cur)
			if err != nil {
				return nil, nil, err
			}
			pairs = append(pairs, Pair{K: k, V: val})
		}
		return pairs, cur, nil
	case 6: // tag: tag number (arg) applied to the following content item
		content, rest2, err := decode(rest)
		if err != nil {
			return nil, nil, err
		}
		return Tag{Number: arg, Content: content}, rest2, nil
	default: // major 7 (simple/float) is not in the spine
		return nil, nil, nonCanonical("major type not used in the N-AALP spine")
	}
}

// readArg reads the argument of a head, enforcing shortest form and rejecting
// reserved (28-30) and indefinite (31) additional information.
func readArg(ai byte, b []byte) (uint64, []byte, error) {
	switch {
	case ai < 24:
		return uint64(ai), b, nil
	case ai == 24:
		if len(b) < 1 {
			return 0, nil, nonCanonical("truncated 1-byte argument")
		}
		n := uint64(b[0])
		if n < 24 {
			return 0, nil, nonCanonical("argument not in shortest form")
		}
		return n, b[1:], nil
	case ai == 25:
		if len(b) < 2 {
			return 0, nil, nonCanonical("truncated 2-byte argument")
		}
		n := uint64(b[0])<<8 | uint64(b[1])
		if n < 1<<8 {
			return 0, nil, nonCanonical("argument not in shortest form")
		}
		return n, b[2:], nil
	case ai == 26:
		if len(b) < 4 {
			return 0, nil, nonCanonical("truncated 4-byte argument")
		}
		n := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		if n < 1<<16 {
			return 0, nil, nonCanonical("argument not in shortest form")
		}
		return n, b[4:], nil
	case ai == 27:
		if len(b) < 8 {
			return 0, nil, nonCanonical("truncated 8-byte argument")
		}
		var n uint64
		for i := 0; i < 8; i++ {
			n = n<<8 | uint64(b[i])
		}
		if n < 1<<32 {
			return 0, nil, nonCanonical("argument not in shortest form")
		}
		return n, b[8:], nil
	default: // 28, 29, 30 reserved; 31 indefinite
		return 0, nil, nonCanonical("reserved or indefinite-length additional information")
	}
}
