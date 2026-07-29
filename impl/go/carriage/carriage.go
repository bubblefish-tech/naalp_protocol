// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package carriage implements C12 — foreign carriage by class (design.md §13; requirements
// R-14.1..14.8, R-18.6).
//
// N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed
// N-AALP carriage object whose effect, safety, identity, and audit apply, and whose foreign body
// is interpreted by a carriage class — not a bespoke per-protocol mapping (R-14.1). There are
// five structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that
// makes any protocol — including one nobody has defined — carriable immediately on an
// experimental protocol id with no registration (R-14.1, R-18.6). The foreign field is carried
// VERBATIM and MUST NOT be re-serialized, canonicalized, summarized, or rewritten (R-14.4);
// N-AALP metadata is carried around it, never inside it. The carriage object's signer remains
// the authority — a foreign identity never becomes an N-AALP authorization identity (R-14.6).
package carriage

import (
	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/bubblefish-tech/n-aalp/impl/go/envelope"
)

// Carriage classes (design.md §13.2).
const (
	ClassJSONRPC uint64 = 0
	ClassHTTP    uint64 = 1
	ClassMSG     uint64 = 2
	ClassSTREAM  uint64 = 3
	ClassDOC     uint64 = 4
	ClassOPAQUE  uint64 = 5
)

var classNames = [...]string{"JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"}

// ClassName returns the name of a class code (0..5), or "unknown".
func ClassName(c uint64) string {
	if c < uint64(len(classNames)) {
		return classNames[c]
	}
	return "unknown"
}

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind (design §13.6).
var (
	ErrNotDelivered           = &cose.Error{Kind: "NotDelivered", Msg: "a below-foreign failure; the message was not delivered"}
	ErrMappingUnrepresentable = &cose.Error{Kind: "MappingError", Msg: "an N-AALP semantic cannot be represented by this carriage class"}
	ErrMalformed              = &cose.Error{Kind: "Malformed", Msg: "malformed carriage body"}
)

// CarriageBody is the body of a carriage object (design.md §13.2).
type CarriageBody struct {
	ProtocolID  uint64
	Class       uint64
	ContentType uint64
	Correlation []byte
	Method      string
	Foreign     []byte // the foreign message, carried octet-for-octet (R-14.4)
}

// ToValue builds the carriage body as a CBOR map {1..6}.
func (b CarriageBody) ToValue() cbor.Value {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(b.ProtocolID)},
		{K: cbor.Uint(2), V: cbor.Uint(b.Class)},
		{K: cbor.Uint(3), V: cbor.Uint(b.ContentType)},
		{K: cbor.Uint(4), V: cbor.Bstr(b.Correlation)},
		{K: cbor.Uint(5), V: cbor.Tstr(b.Method)},
		{K: cbor.Uint(6), V: cbor.Bstr(b.Foreign)},
	}
}

// Bytes is the deterministic-CBOR encoding of the carriage body.
func (b CarriageBody) Bytes() []byte {
	enc, _ := cbor.Encode(b.ToValue())
	return enc
}

// ValidateClass rejects a class code outside the defined set with a typed mapping error, never a
// silent drop (R-14.8).
func ValidateClass(class uint64) error {
	if class > ClassOPAQUE {
		return ErrMappingUnrepresentable
	}
	return nil
}

// Carry wraps a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not
// parse, canonicalize, or rewrite the foreign bytes. An undefined protocol carries under
// ClassOPAQUE with an experimental protocol id and zero new specification (R-18.6).
func Carry(protocolID, class, contentType uint64, correlation []byte, method string, foreign []byte) (CarriageBody, error) {
	if err := ValidateClass(class); err != nil {
		return CarriageBody{}, err
	}
	return CarriageBody{
		ProtocolID: protocolID, Class: class, ContentType: contentType,
		Correlation: correlation, Method: method, Foreign: foreign,
	}, nil
}

// CarriageFromValue parses a carriage body from a CBOR value, recovering the foreign field
// octet-for-octet. A structurally invalid body is Malformed; an unknown class is a MappingError.
func CarriageFromValue(v cbor.Value) (CarriageBody, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return CarriageBody{}, ErrMalformed
	}
	var b CarriageBody
	var haveForeign bool
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return CarriageBody{}, ErrMalformed
		}
		switch uint64(k) {
		case 1:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return CarriageBody{}, ErrMalformed
			}
			b.ProtocolID = uint64(u)
		case 2:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return CarriageBody{}, ErrMalformed
			}
			b.Class = uint64(u)
		case 3:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return CarriageBody{}, ErrMalformed
			}
			b.ContentType = uint64(u)
		case 4:
			bs, ok := p.V.(cbor.Bstr)
			if !ok {
				return CarriageBody{}, ErrMalformed
			}
			b.Correlation = bs
		case 5:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return CarriageBody{}, ErrMalformed
			}
			b.Method = string(s)
		case 6:
			bs, ok := p.V.(cbor.Bstr)
			if !ok {
				return CarriageBody{}, ErrMalformed
			}
			b.Foreign = bs
			haveForeign = true
		default:
			return CarriageBody{}, ErrMalformed
		}
	}
	if !haveForeign {
		return CarriageBody{}, ErrMalformed
	}
	if err := ValidateClass(b.Class); err != nil {
		return CarriageBody{}, err
	}
	return b, nil
}

// Protocol id ranges (design.md §13.4): standards 0x01-0x0F (Specification Required),
// experimental 0x10-0x7F (no registration), private 0x80-0xFF. 0x00 is reserved.
func ProtocolRange(id uint64) string {
	switch {
	case id == 0x00:
		return "reserved"
	case id <= 0x0F:
		return "standards"
	case id <= 0x7F:
		return "experimental"
	case id <= 0xFF:
		return "private"
	default:
		return "invalid" // protocol_id is one octet
	}
}

// DeliveryReport records whether a carried message was actually delivered. A report never claims
// delivery it did not achieve (R-14.8).
type DeliveryReport struct {
	Delivered bool
}

// Report produces a delivery report from the below-foreign outcome: a failed delivery yields
// Delivered=false and NotDelivered — never a false "delivered" (R-14.8).
func Report(deliveredBelow bool) (DeliveryReport, error) {
	if !deliveredBelow {
		return DeliveryReport{Delivered: false}, ErrNotDelivered
	}
	return DeliveryReport{Delivered: true}, nil
}

// CarriageAuthority returns the authorizing principal of a carriage object: the N-AALP signer of
// the object (envelope field 5), never any foreign principal named inside the foreign bytes
// (R-14.6). It reads only the signed envelope, never the carried foreign message.
func CarriageAuthority(o *envelope.Object) []byte { return o.Signer }
