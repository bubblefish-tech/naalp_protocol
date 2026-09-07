// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package payment implements C21 task 5B.1 — NAALP-PAY payment import (design.md §24;
// requirements R-PAY-1..6).
//
// NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol
// delegated token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not
// adoption): the foreign bytes are never re-serialized, canonicalized, or rewritten (R-14.4), and a
// foreign identity inside them never becomes an N-AALP authorization identity (R-14.6). It introduces
// NO new envelope, encoding, signature, identity, effect, or ledger mechanism (R-11.3): the imported
// payload becomes a value-bearing charge that N-AALP governs with its OWN added guarantees, reusing
// the closed C5 effect lattice (policy), the §7 approval object, and the §7 single-use consume ledger
// (package approval) UNCHANGED. There is NO fifth effect and NO payment-specific ledger.
//
// The added guarantees over the imported formats:
//
//   - PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
//     wrapper body (envelope field 10). `format` selects the imported FORMAT from the closed
//     payment-format registry (vectors/registry/payment-format.csv); `foreign` carries the imported
//     payload octet-for-octet. An unknown format code is rejected (UnknownPaymentFormat).
//   - THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
//     6: foreign_id} names the exact value the approval binds by content id — including the foreign
//     payload's content id (the carriage binding). A §7 approval binds THIS binding's content id, so a
//     wrong-amount, wrong-payee, wrong-currency, or substituted-payload charge yields a different
//     content id and no longer matches the approval (ApprovalMismatch, from package approval).
//   - THE CHARGE IS SPENT SINGLE-USE. A payment spend is a non_idempotent_write (ChargeEffect); the
//     approval's granted effect must cover it, and AuthorizeCharge consumes the approval single-use
//     through the §7 ledger, so a replayed charge is rejected (AlreadyConsumed) with no state change.
//
// Every check is fail-closed (§15): a failing charge is rejected whole, returns its named error, and
// causes no state change (no ledger append).
package payment

import (
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// HeadSize is the width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit
// chain (audit.HeadSize).
const HeadSize = 48

// ChargeEffect is the C5 effect a payment spend carries: a non_idempotent_write. A charge is
// value-bearing and not safely repeatable, which is exactly why it is spent single-use through the
// §7 ledger; the approval's grant must cover this effect (the value-bearing rule).
const ChargeEffect = policy.NonIdempotentWrite

// Payment format codes (design.md §24; machine-readable payment-format registry). These name the
// imported FORMAT carried octet-for-octet — not an adopted schema. A code outside the closed set is
// rejected (UnknownPaymentFormat).
const (
	FormatAP2Mandate uint64 = 1 // AP2 mandate
	FormatACPToken   uint64 = 2 // Agentic Commerce Protocol delegated token
	FormatX402       uint64 = 3 // x402 payload
)

// formatName maps a format code to its registry name (diagnostics); an unknown code returns "".
var formatName = map[uint64]string{
	FormatAP2Mandate: "ap2-mandate",
	FormatACPToken:   "acp-delegated-token",
	FormatX402:       "x402-payload",
}

// IsRegisteredFormat reports whether code is one of the closed payment formats.
func IsRegisteredFormat(code uint64) bool { _, ok := formatName[code]; return ok }

// FormatName returns the registry name of a format code, or "unknown".
func FormatName(code uint64) string {
	if n, ok := formatName[code]; ok {
		return n
	}
	return "unknown"
}

// Named, fail-closed errors. A failing charge is rejected whole and causes no state change (§15).
// The binding, expiry, replay, and signature errors are the EXISTING §7 errors reused unchanged
// (approval.ErrApprovalMismatch / ErrApprovalExpired / ErrAlreadyConsumed / ErrApprovalRequired,
// cose.ErrBadSignature) — there is no payment-specific ledger or effect.
var (
	ErrMalformed     = &cose.Error{Kind: "PayMalformed", Msg: "object is not a well-formed N-AALP payment-import body"}
	ErrUnknownFormat = &cose.Error{Kind: "UnknownPaymentFormat", Msg: "payment import selects a format outside the closed payment-format registry"}
)

// contentID is the T1 framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets),
// identical to the spine's framing (design §2.3).
func contentID(b []byte) []byte {
	d := sha512.Sum384(b)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30)
	return append(out, d[:]...)
}

// head is SHA-384 over a body — a 48-octet digest.
func head(b []byte) []byte {
	d := sha512.Sum384(b)
	return d[:]
}

// ---- PaymentImport: the imported payload wrapper (design.md §24) ------------------------------

// PaymentImport wraps a foreign payment payload as a value-bearing charge. Format selects the
// imported format (closed registry); Amount/Currency/Payee/NotAfter are the bound charge terms;
// Foreign is the imported payload carried octet-for-octet (carriage, not adoption). The wrapper's OWN
// effect is the envelope field 7 (ChargeEffect); the body carries no effect field.
type PaymentImport struct {
	Format   uint64 // the imported payment format code (closed registry)
	Amount   uint64 // the charge amount in minor units (e.g. cents)
	Currency string // the charge currency code (e.g. "USD")
	Payee    []byte // the payee id (opaque)
	NotAfter uint64 // the charge expiry, epoch ms
	Foreign  []byte // the imported payment payload, carried octet-for-octet (carriage, not adoption)
}

// Bytes is the deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee,
// 5: not_after, 6: foreign}.
func (p PaymentImport) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(p.Format)},
		{K: cbor.Uint(2), V: cbor.Uint(p.Amount)},
		{K: cbor.Uint(3), V: cbor.Tstr(p.Currency)},
		{K: cbor.Uint(4), V: cbor.Bstr(p.Payee)},
		{K: cbor.Uint(5), V: cbor.Uint(p.NotAfter)},
		{K: cbor.Uint(6), V: cbor.Bstr(p.Foreign)},
	})
	return b
}

// Head is the PaymentImport's SHA-384 head (48 octets).
func (p PaymentImport) Head() []byte { return head(p.Bytes()) }

// ID is the PaymentImport's T1 content-id (50 octets).
func (p PaymentImport) ID() []byte { return contentID(p.Bytes()) }

// ForeignID is the T1 content-id of the carried foreign payload — the hash the charge binding binds
// (the carriage binding). A substituted payload yields a different ForeignID.
func (p PaymentImport) ForeignID() []byte { return contentID(p.Foreign) }

// ChargeBinding returns the exact charge value an approval binds for this import (amount + currency +
// payee + expiry + the foreign payload's content id). A change to any bound term — including the
// foreign payload — changes the binding's content id.
func (p PaymentImport) ChargeBinding() ChargeBinding {
	return ChargeBinding{
		Format: p.Format, Amount: p.Amount, Currency: p.Currency,
		Payee: p.Payee, NotAfter: p.NotAfter, ForeignID: p.ForeignID(),
	}
}

// ParsePaymentImport reconstructs a PaymentImport from its body bytes alone. It does NOT validate the
// format against the closed set — that is VerifyPaymentImport's job — so an import carrying an unknown
// format can be represented (and then rejected). Fail-closed on a malformed shape.
func ParsePaymentImport(b []byte) (PaymentImport, error) {
	m, ok := decodeMap(b)
	if !ok {
		return PaymentImport{}, ErrMalformed
	}
	fmtV, ok1 := uintField(m, 1)
	amt, ok2 := uintField(m, 2)
	cur, ok3 := tstrField(m, 3)
	payee, ok4 := bstrField(m, 4)
	na, ok5 := uintField(m, 5)
	foreign, ok6 := bstrField(m, 6)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return PaymentImport{}, ErrMalformed
	}
	return PaymentImport{Format: fmtV, Amount: amt, Currency: cur, Payee: payee, NotAfter: na, Foreign: foreign}, nil
}

// SignPaymentImport produces the tagged COSE_Sign1 object over the PaymentImport body.
func SignPaymentImport(p PaymentImport, s cose.Signer) ([]byte, error) { return cose.Sign1(s, p.Bytes()) }

// VerifyPaymentImport verifies the import's full signature under the profile, reconstructs it from the
// signed body bytes, and validates the format against the closed registry (UnknownPaymentFormat). A
// bad signature propagates from cose.Verify1 (BadSignature). Fail-closed.
func VerifyPaymentImport(obj []byte, profile int, v cose.Verifier) (PaymentImport, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return PaymentImport{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return PaymentImport{}, err
	}
	p, err := ParsePaymentImport(payload)
	if err != nil {
		return PaymentImport{}, err
	}
	if !IsRegisteredFormat(p.Format) {
		return PaymentImport{}, ErrUnknownFormat
	}
	return p, nil
}

// ---- ChargeBinding: the value an approval binds (design.md §24) -------------------------------

// ChargeBinding names the exact charge by value: the format, amount, currency, payee, expiry, and the
// foreign payload's content id. An approval binds THIS binding's content id, so a change to any bound
// term invalidates a prior approval (ApprovalMismatch).
type ChargeBinding struct {
	Format    uint64
	Amount    uint64
	Currency  string
	Payee     []byte
	NotAfter  uint64
	ForeignID []byte // content-id of the foreign payload: multihash(0x20, SHA-384(foreign))
}

// Bytes is the deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee,
// 5: not_after, 6: foreign_id}.
func (c ChargeBinding) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(c.Format)},
		{K: cbor.Uint(2), V: cbor.Uint(c.Amount)},
		{K: cbor.Uint(3), V: cbor.Tstr(c.Currency)},
		{K: cbor.Uint(4), V: cbor.Bstr(c.Payee)},
		{K: cbor.Uint(5), V: cbor.Uint(c.NotAfter)},
		{K: cbor.Uint(6), V: cbor.Bstr(c.ForeignID)},
	})
	return b
}

// Head is the ChargeBinding's SHA-384 head (48 octets).
func (c ChargeBinding) Head() []byte { return head(c.Bytes()) }

// ContentID is the charge content id an approval binds: multihash(0x20, SHA-384(binding)).
func (c ChargeBinding) ContentID() []byte { return contentID(c.Bytes()) }

// ---- the per-charge approval gate (reuses §7 approval + consume ledger) -----------------------

// AuthorizeCharge enforces the value-bearing rule for an imported payment, reusing the §7 approval
// and single-use consume ledger UNCHANGED. The approval MUST bind the EXACT charge binding content id
// (format + amount + currency + payee + expiry + foreign_id) — so it satisfies neither a different
// amount/payee/currency nor a substituted foreign payload (ApprovalMismatch, from package approval) —
// its granted effect must cover the charge's ChargeEffect (a non_idempotent_write), it must be
// unexpired at `now`, and it is consumed single-use by `by` through the §7 ledger. Precedence and
// fail-closed behaviour mirror the spine: a non-matching or under-granting approval denies with no
// ledger append; an already-spent approval denies AlreadyConsumed; the consume (the single state
// change) happens only when every check holds. It returns the ledger entry on success.
func AuthorizeCharge(p PaymentImport, appr approval.ApprovalRecord, approverV cose.Verifier, apprSig []byte, by string, now uint64, ledger *approval.Ledger) (*approval.LedgerEntry, error) {
	if !IsRegisteredFormat(p.Format) {
		return nil, ErrUnknownFormat // an unknown imported format is not chargeable, fail-closed
	}
	chargeCID := p.ChargeBinding().ContentID()
	if err := approval.VerifyApproval(appr, approverV, apprSig, chargeCID, now); err != nil {
		return nil, err // ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature
	}
	if !policy.Effect(appr.Grant).Authorizes(ChargeEffect) {
		return nil, approval.ErrApprovalRequired // the approval's granted effect does not cover the charge
	}
	entry, err := ledger.Consume(appr.ID(), by)
	if err != nil {
		return nil, err // AlreadyConsumed on replay (or IO) — single-use, no double-spend
	}
	return entry, nil
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

func decodeMap(b []byte) (cbor.Map, bool) {
	v, err := cbor.Decode(b)
	if err != nil {
		return nil, false
	}
	m, ok := v.(cbor.Map)
	return m, ok
}

func field(m cbor.Map, k uint64) (cbor.Value, bool) {
	for _, p := range m {
		if p.K == cbor.Uint(k) {
			return p.V, true
		}
	}
	return nil, false
}

func bstrField(m cbor.Map, k uint64) ([]byte, bool) {
	v, ok := field(m, k)
	if !ok {
		return nil, false
	}
	bs, ok := v.(cbor.Bstr)
	return []byte(bs), ok
}

func tstrField(m cbor.Map, k uint64) (string, bool) {
	v, ok := field(m, k)
	if !ok {
		return "", false
	}
	ts, ok := v.(cbor.Tstr)
	return string(ts), ok
}

func uintField(m cbor.Map, k uint64) (uint64, bool) {
	v, ok := field(m, k)
	if !ok {
		return 0, false
	}
	u, ok := v.(cbor.Uint)
	return uint64(u), ok
}
