// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package payment_test

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/payment"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const vectorPath = "../../../vectors/payment/cases.json"

type hdr struct {
	BodyHex string `json:"body_hex"`
	HeadHex string `json:"head_hex"`
	IDHex   string `json:"id_hex"`
}

type importVec struct {
	Format        uint64 `json:"format"`
	Amount        uint64 `json:"amount"`
	Currency      string `json:"currency"`
	PayeeHex      string `json:"payee_hex"`
	NotAfter      uint64 `json:"not_after"`
	ForeignHex    string `json:"foreign_hex"`
	ForeignIDHex  string `json:"foreign_id_hex"`
	BodyHex       string `json:"body_hex"`
	HeadHex       string `json:"head_hex"`
	IDHex         string `json:"id_hex"`
	ChargeBinding hdr    `json:"charge_binding"`
}

type vec struct {
	FormatVocabulary []struct {
		Name string `json:"name"`
		Code uint64 `json:"code"`
	} `json:"format_vocabulary"`
	UnknownFormat uint64 `json:"unknown_format"`
	ChargeEffect  uint64 `json:"charge_effect"`
	Imports       struct {
		AP2  importVec `json:"ap2"`
		ACP  importVec `json:"acp"`
		X402 importVec `json:"x402"`
	} `json:"imports"`
	Mismatch struct {
		WrongAmountChargeIDHex  string `json:"wrong_amount_charge_id_hex"`
		WrongPayeeChargeIDHex   string `json:"wrong_payee_charge_id_hex"`
		SubstitutedForeignHex   string `json:"substituted_foreign_hex"`
		SubstitutedForeignIDHex string `json:"substituted_foreign_id_hex"`
		SubstitutedChargeIDHex  string `json:"substituted_charge_id_hex"`
	} `json:"mismatch"`
	BigAmount struct {
		Format        uint64 `json:"format"`
		AmountStr     string `json:"amount_str"`
		Currency      string `json:"currency"`
		PayeeHex      string `json:"payee_hex"`
		NotAfter      uint64 `json:"not_after"`
		ForeignHex    string `json:"foreign_hex"`
		BodyHex       string `json:"body_hex"`
		IDHex         string `json:"id_hex"`
		ChargeBinding hdr    `json:"charge_binding"`
	} `json:"big_amount"`
	Minimal   importVec `json:"minimal"`
	EdgeCases struct {
		KeysOutOfOrder struct {
			Format              uint64 `json:"format"`
			Amount              uint64 `json:"amount"`
			Currency            string `json:"currency"`
			PayeeHex            string `json:"payee_hex"`
			NotAfter            uint64 `json:"not_after"`
			ForeignHex          string `json:"foreign_hex"`
			CanonicalBodyHex    string `json:"canonical_body_hex"`
			NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
		} `json:"keys_out_of_order"`
		EmptyVsAbsent struct {
			EmptyForeign struct {
				BodyHex      string `json:"body_hex"`
				IDHex        string `json:"id_hex"`
				ForeignIDHex string `json:"foreign_id_hex"`
			} `json:"empty_foreign"`
			PopulatedForeign struct {
				ForeignHex   string `json:"foreign_hex"`
				BodyHex      string `json:"body_hex"`
				IDHex        string `json:"id_hex"`
				ForeignIDHex string `json:"foreign_id_hex"`
			} `json:"populated_foreign"`
			AbsentField struct {
				BodyHex string `json:"body_hex"`
			} `json:"absent_field"`
		} `json:"empty_vs_absent"`
		LookAlike struct {
			BodyHex string `json:"body_hex"`
		} `json:"look_alike"`
	} `json:"edge_cases"`
}

func hb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func loadVec(t *testing.T) vec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(vectorPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

// key derives a real ML-DSA-65 keypair from a seed.
func key(t *testing.T, seed byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier) {
	t.Helper()
	var s [mldsa65.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa65.NewKeyFromSeed(&s)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}
}

func impFrom(iv importVec) payment.PaymentImport {
	return payment.PaymentImport{
		Format:   iv.Format,
		Amount:   iv.Amount,
		Currency: iv.Currency,
		Payee:    mustHex(iv.PayeeHex),
		NotAfter: iv.NotAfter,
		Foreign:  mustHex(iv.ForeignHex),
	}
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// TestByteParityAgainstOracle: Go encoding == the non-circular Python oracle, byte-for-byte, for
// every payment import body/head/id, its foreign content-id, and its charge-binding body/id. Mutation:
// change any Bytes() field order/tag/key and a *_hex compare flips.
func TestByteParityAgainstOracle(t *testing.T) {
	v := loadVec(t)
	for name, iv := range map[string]importVec{"ap2": v.Imports.AP2, "acp": v.Imports.ACP, "x402": v.Imports.X402} {
		p := impFrom(iv)
		if got := hex.EncodeToString(p.Bytes()); got != iv.BodyHex {
			t.Fatalf("%s PaymentImport.Bytes\n got %s\nwant %s", name, got, iv.BodyHex)
		}
		if got := hex.EncodeToString(p.Head()); got != iv.HeadHex {
			t.Fatalf("%s PaymentImport.Head got %s want %s", name, got, iv.HeadHex)
		}
		if got := hex.EncodeToString(p.ID()); got != iv.IDHex {
			t.Fatalf("%s PaymentImport.ID got %s want %s", name, got, iv.IDHex)
		}
		if got := hex.EncodeToString(p.ForeignID()); got != iv.ForeignIDHex {
			t.Fatalf("%s PaymentImport.ForeignID got %s want %s", name, got, iv.ForeignIDHex)
		}
		cb := p.ChargeBinding()
		if got := hex.EncodeToString(cb.Bytes()); got != iv.ChargeBinding.BodyHex {
			t.Fatalf("%s ChargeBinding.Bytes\n got %s\nwant %s", name, got, iv.ChargeBinding.BodyHex)
		}
		if got := hex.EncodeToString(cb.ContentID()); got != iv.ChargeBinding.IDHex {
			t.Fatalf("%s ChargeBinding.ContentID got %s want %s", name, got, iv.ChargeBinding.IDHex)
		}
	}
	// The format registry and the charge effect match the oracle (and the closed set is enforced).
	for _, e := range v.FormatVocabulary {
		if !payment.IsRegisteredFormat(e.Code) {
			t.Fatalf("format %q (code %d) not registered", e.Name, e.Code)
		}
		if payment.FormatName(e.Code) != e.Name {
			t.Fatalf("format code %d name %q != oracle %q", e.Code, payment.FormatName(e.Code), e.Name)
		}
	}
	if payment.IsRegisteredFormat(v.UnknownFormat) {
		t.Fatalf("unknown format %d must not be registered", v.UnknownFormat)
	}
	if uint64(payment.ChargeEffect) != v.ChargeEffect {
		t.Fatalf("charge effect %d != oracle %d", payment.ChargeEffect, v.ChargeEffect)
	}
}

// mkApproval builds and signs a §7 approval binding a charge content-id at grant `grant`.
func mkApproval(t *testing.T, chargeCID []byte, approver string, grant policy.Effect, nonce byte, notAfter uint64, s cose.MLDSA65Signer) (approval.ApprovalRecord, []byte) {
	t.Helper()
	n := make([]byte, 16)
	for i := range n {
		n[i] = nonce
	}
	a := approval.ApprovalRecord{Approves: chargeCID, Approver: approver, Grant: uint64(grant), Nonce: n, NotAfter: notAfter}
	sig, err := approval.SignApproval(a, s)
	if err != nil {
		t.Fatalf("SignApproval: %v", err)
	}
	return a, sig
}

// TestChargeSingleUseAndBinding is the C21 payment checkpoint: an imported payment is spent SINGLE-USE
// through the §7 ledger (a replay is AlreadyConsumed) and is bound to the exact charge (a wrong
// amount, wrong payee, wrong currency, or substituted foreign payload fails its approval binding).
func TestChargeSingleUseAndBinding(t *testing.T) {
	v := loadVec(t)
	approverS, approverV := key(t, 0x11)
	_, foreignV := key(t, 0x22)

	pi := impFrom(v.Imports.AP2)
	chargeCID := pi.ChargeBinding().ContentID()
	appr, apprSig := mkApproval(t, chargeCID, "approver-A", payment.ChargeEffect, 0x01, pi.NotAfter, approverS)

	ledgerPath := filepath.Join(t.TempDir(), "charge.wal")
	ledger, err := approval.OpenLedger(ledgerPath)
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	defer ledger.Close()

	// First charge: authorized and consumed exactly once.
	entry, err := payment.AuthorizeCharge(pi, appr, approverV, apprSig, "payer-1", pi.NotAfter, ledger)
	if err != nil {
		t.Fatalf("AuthorizeCharge (honest): %v", err)
	}
	if entry == nil || entry.Seq != 0 {
		t.Fatalf("first charge did not consume at seq 0: %+v", entry)
	}
	// Replay: the same approval is rejected by the ledger, no second spend, no state change.
	if _, err := payment.AuthorizeCharge(pi, appr, approverV, apprSig, "payer-1", pi.NotAfter, ledger); err != approval.ErrAlreadyConsumed {
		t.Fatalf("replayed charge got %v, want AlreadyConsumed", err)
	}
	if ledger.Len() != 1 {
		t.Fatalf("ledger has %d entries after replay, want 1 (no double-spend)", ledger.Len())
	}

	// A wrong-amount charge yields a different charge content-id, so the approval no longer matches.
	wrongAmount := pi
	wrongAmount.Amount = pi.Amount + 8000
	if got := hex.EncodeToString(wrongAmount.ChargeBinding().ContentID()); got != v.Mismatch.WrongAmountChargeIDHex {
		t.Fatalf("wrong-amount charge id %s != oracle %s", got, v.Mismatch.WrongAmountChargeIDHex)
	}
	if _, err := payment.AuthorizeCharge(wrongAmount, appr, approverV, apprSig, "payer-1", pi.NotAfter, freshLedger(t)); err != approval.ErrApprovalMismatch {
		t.Fatalf("wrong-amount charge got %v, want ApprovalMismatch", err)
	}
	// A wrong-payee charge likewise fails the binding.
	wrongPayee := pi
	wrongPayee.Payee = []byte("merchant:evil-store")
	if got := hex.EncodeToString(wrongPayee.ChargeBinding().ContentID()); got != v.Mismatch.WrongPayeeChargeIDHex {
		t.Fatalf("wrong-payee charge id %s != oracle %s", got, v.Mismatch.WrongPayeeChargeIDHex)
	}
	if _, err := payment.AuthorizeCharge(wrongPayee, appr, approverV, apprSig, "payer-1", pi.NotAfter, freshLedger(t)); err != approval.ErrApprovalMismatch {
		t.Fatalf("wrong-payee charge got %v, want ApprovalMismatch", err)
	}
	// A substituted foreign payload changes the foreign content-id, hence the charge binding.
	substituted := pi
	substituted.Foreign = hb(t, v.Mismatch.SubstitutedForeignHex)
	if got := hex.EncodeToString(substituted.ForeignID()); got != v.Mismatch.SubstitutedForeignIDHex {
		t.Fatalf("substituted foreign id %s != oracle %s", got, v.Mismatch.SubstitutedForeignIDHex)
	}
	if got := hex.EncodeToString(substituted.ChargeBinding().ContentID()); got != v.Mismatch.SubstitutedChargeIDHex {
		t.Fatalf("substituted charge id %s != oracle %s", got, v.Mismatch.SubstitutedChargeIDHex)
	}
	if _, err := payment.AuthorizeCharge(substituted, appr, approverV, apprSig, "payer-1", pi.NotAfter, freshLedger(t)); err != approval.ErrApprovalMismatch {
		t.Fatalf("substituted-payload charge got %v, want ApprovalMismatch", err)
	}

	// A foreign key never authenticates the approval.
	if _, err := payment.AuthorizeCharge(pi, appr, foreignV, apprSig, "payer-1", pi.NotAfter, freshLedger(t)); err != cose.ErrBadSignature {
		t.Fatalf("foreign-key charge got %v, want BadSignature", err)
	}
	// An expired charge is rejected.
	if _, err := payment.AuthorizeCharge(pi, appr, approverV, apprSig, "payer-1", pi.NotAfter+1, freshLedger(t)); err != approval.ErrApprovalExpired {
		t.Fatalf("expired charge got %v, want ApprovalExpired", err)
	}
	// An under-granting approval (read_only cannot authorize a non_idempotent_write charge) is denied.
	underCID := pi.ChargeBinding().ContentID()
	underAppr, underSig := mkApproval(t, underCID, "approver-A", policy.ReadOnly, 0x03, pi.NotAfter, approverS)
	if _, err := payment.AuthorizeCharge(pi, underAppr, approverV, underSig, "payer-1", pi.NotAfter, freshLedger(t)); err != approval.ErrApprovalRequired {
		t.Fatalf("under-granting charge got %v, want ApprovalRequired", err)
	}
	// An unknown imported format is not chargeable.
	unk := pi
	unk.Format = v.UnknownFormat
	if _, err := payment.AuthorizeCharge(unk, appr, approverV, apprSig, "payer-1", pi.NotAfter, freshLedger(t)); err != payment.ErrUnknownFormat {
		t.Fatalf("unknown-format charge got %v, want UnknownPaymentFormat", err)
	}
}

func freshLedger(t *testing.T) *approval.Ledger {
	t.Helper()
	l, err := approval.OpenLedger(filepath.Join(t.TempDir(), "fresh.wal"))
	if err != nil {
		t.Fatalf("OpenLedger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// TestPaymentImportMultiUseMutation is REQUIRED checkpoint mutation (a): an importer that treats a
// payment token as MULTI-USE fails the replay case. The honest AuthorizeCharge consumes single-use
// through the §7 ledger, so a replay is AlreadyConsumed; a MUTANT importer that skips the ledger
// consume (treating the token as multi-use) authorizes the replay a second time — the exact
// double-spend the ledger prevents. The test proves the ledger.Consume is the load-bearing single-use
// guarantee: remove it and the replay is wrongly authorized.
func TestPaymentImportMultiUseMutation(t *testing.T) {
	v := loadVec(t)
	approverS, approverV := key(t, 0x11)
	pi := impFrom(v.Imports.AP2)
	chargeCID := pi.ChargeBinding().ContentID()
	appr, apprSig := mkApproval(t, chargeCID, "approver-A", payment.ChargeEffect, 0x01, pi.NotAfter, approverS)

	// HONEST path: single-use through the ledger — the replay is rejected.
	ledger := freshLedger(t)
	if _, err := payment.AuthorizeCharge(pi, appr, approverV, apprSig, "payer-1", pi.NotAfter, ledger); err != nil {
		t.Fatalf("honest first charge: %v", err)
	}
	if _, err := payment.AuthorizeCharge(pi, appr, approverV, apprSig, "payer-1", pi.NotAfter, ledger); err != approval.ErrAlreadyConsumed {
		t.Fatalf("honest replay got %v, want AlreadyConsumed", err)
	}

	// MUTANT importer: verifies the binding but treats the token as MULTI-USE (no ledger consume).
	// This is the bug the ledger prevents; the mutant wrongly authorizes the replay a second time.
	mutantAuthorize := func(p payment.PaymentImport) error {
		cid := p.ChargeBinding().ContentID()
		return approval.VerifyApproval(appr, approverV, apprSig, cid, p.NotAfter) // no Consume => multi-use
	}
	if err := mutantAuthorize(pi); err != nil {
		t.Fatalf("mutant first charge: %v", err)
	}
	if err := mutantAuthorize(pi); err != nil {
		// The mutant does NOT reject the replay — proving the ledger.Consume the honest path uses is
		// the single-use guarantee. If this ever errored, the binding alone would be enforcing
		// single-use, which it does not.
		t.Fatalf("mutant replay unexpectedly rejected (%v): the multi-use bug must reproduce", err)
	}
}

// crossLangPinnedSignedPaymentSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1 object
// obtained by signing the AP2 payment-import body with the shared all-0x11 32-byte ML-DSA-65 seed.
// Go and Rust both pin it, proving the two independent ML-DSA stacks emit byte-identical signed
// payment-import objects for identical canonical CBOR + seed.
const crossLangPinnedSignedPaymentSHA384 = "c9c7c30eed7bfaf5292bd99e8a892a86f563d8531ccff25d0504d81f3f535b02a8afbd7d41a5ff0f69031841a338bbe4"

// TestCrossLangSignedPaymentPin proves Go and Rust produce a byte-identical signed payment-import for
// the same body + seed (deterministic ML-DSA-65 over identical canonical CBOR).
func TestCrossLangSignedPaymentPin(t *testing.T) {
	v := loadVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}
	pi := impFrom(v.Imports.AP2)
	obj, err := payment.SignPaymentImport(pi, s)
	if err != nil {
		t.Fatalf("SignPaymentImport: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed payment-import SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedPaymentSHA384 != "PIN_ME" && got != crossLangPinnedSignedPaymentSHA384 {
		t.Fatalf("cross-lang signed-payment digest %s != pinned %s", got, crossLangPinnedSignedPaymentSHA384)
	}
	// Round-trip: the signed import re-verifies and reconstructs its fields.
	_, verifier := key(t, 0x11)
	rp, err := payment.VerifyPaymentImport(obj, cose.ProfilePublic, verifier)
	if err != nil {
		t.Fatalf("VerifyPaymentImport: %v", err)
	}
	if rp.Amount != pi.Amount || rp.Format != pi.Format {
		t.Fatalf("verified import mismatch: %+v", rp)
	}
}

// TestPaymentOversizedAmountRoundTrip is Phase 6 edge case #3 (the >2^53 discipline): a charge amount
// (minor units) above 2^53 (0x0102030405060708 = 72623859790382856) MUST round-trip byte-exact
// through the import body AND the charge-binding (uint64 all the way, no float64). The oracle carries
// the amount as a JSON STRING, parsed with a 64-bit integer parser. Mutation: truncate amount to a
// float64 and the body / recovered amount / charge-binding content-id diverge.
func TestPaymentOversizedAmountRoundTrip(t *testing.T) {
	v := loadVec(t)
	amount, err := strconv.ParseUint(v.BigAmount.AmountStr, 10, 64)
	if err != nil {
		t.Fatalf("parse amount_str: %v", err)
	}
	if amount <= 1<<53 {
		t.Fatalf("oracle big amount %d is not > 2^53", amount)
	}
	p := payment.PaymentImport{Format: v.BigAmount.Format, Amount: amount, Currency: v.BigAmount.Currency, Payee: hb(t, v.BigAmount.PayeeHex), NotAfter: v.BigAmount.NotAfter, Foreign: hb(t, v.BigAmount.ForeignHex)}
	if got := hex.EncodeToString(p.Bytes()); got != v.BigAmount.BodyHex {
		t.Fatalf("big-amount import body\n got %s\nwant %s", got, v.BigAmount.BodyHex)
	}
	if got := hex.EncodeToString(p.ChargeBinding().Bytes()); got != v.BigAmount.ChargeBinding.BodyHex {
		t.Fatalf("big-amount charge binding\n got %s\nwant %s", got, v.BigAmount.ChargeBinding.BodyHex)
	}
	got, err := payment.ParsePaymentImport(p.Bytes())
	if err != nil {
		t.Fatalf("ParsePaymentImport(big amount): %v", err)
	}
	if got.Amount != amount {
		t.Fatalf("recovered amount %d != %d (>2^53 corrupted)", got.Amount, amount)
	}
}

// TestPaymentMinimal is Phase 6 edge case #4: the smallest valid payment import (format ap2, amount 0,
// empty currency/payee, not_after 0, empty foreign) encodes, reconstructs, and has a stable content-id.
func TestPaymentMinimal(t *testing.T) {
	v := loadVec(t)
	p := impFrom(v.Minimal)
	if got := hex.EncodeToString(p.Bytes()); got != v.Minimal.BodyHex {
		t.Fatalf("minimal import body\n got %s\nwant %s", got, v.Minimal.BodyHex)
	}
	if got := hex.EncodeToString(p.ID()); got != v.Minimal.IDHex {
		t.Fatalf("minimal import id got %s want %s", got, v.Minimal.IDHex)
	}
	if _, err := payment.ParsePaymentImport(p.Bytes()); err != nil {
		t.Fatalf("ParsePaymentImport(minimal): %v", err)
	}
}

// ---- standard wire-format edge cases (Part 1) --------------------------------------------

// TestPaymentKeysOutOfOrderRejected is edge case #1: an import body with top-level keys in DESCENDING
// order (6,5,4,3,2,1) is rejected NonCanonical by the strict shared decoder ParsePaymentImport routes
// through (RFC 8949 §4.2.1). Mutation: relax the key-order check in the C1 codec and the descending
// body wrongly decodes.
func TestPaymentKeysOutOfOrderRejected(t *testing.T) {
	v := loadVec(t)
	e := v.EdgeCases.KeysOutOfOrder
	p := payment.PaymentImport{Format: e.Format, Amount: e.Amount, Currency: e.Currency, Payee: hb(t, e.PayeeHex), NotAfter: e.NotAfter, Foreign: hb(t, e.ForeignHex)}
	if got := hex.EncodeToString(p.Bytes()); got != e.CanonicalBodyHex {
		t.Fatalf("canonical import body\n got %s\nwant %s", got, e.CanonicalBodyHex)
	}
	canon := hb(t, e.CanonicalBodyHex)
	noncanon := hb(t, e.NoncanonicalBodyHex)
	if _, err := cbor.Decode(canon); err != nil {
		t.Fatalf("canonical body should decode: %v", err)
	}
	if _, err := payment.ParsePaymentImport(canon); err != nil {
		t.Fatalf("canonical body should parse: %v", err)
	}
	if _, err := cbor.Decode(noncanon); err == nil {
		t.Fatal("descending-key import body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != "NonCanonical" {
		t.Fatalf("descending-key body got %v, want NonCanonical", err)
	}
	if _, err := payment.ParsePaymentImport(noncanon); err != payment.ErrMalformed {
		t.Fatalf("ParsePaymentImport(noncanon) got %v, want PayMalformed", err)
	}
}

// TestPaymentEmptyVsAbsentForeign is edge case #2 for the foreign payload (field 6, a bstr): an empty
// foreign payload is PRESENT and valid with its OWN foreign_id (the carriage binding), DISTINCT by
// content-id from a populated one, and BOTH differ from a body whose foreign field is ABSENT — rejected
// PayMalformed (field 6 is mandatory). NAALP-PAY has no truly-optional field, so the foreign bstr is
// the meaningful empty-vs-nonempty. Mutation: drop the foreign-field presence requirement in
// ParsePaymentImport and the absent body wrongly parses.
func TestPaymentEmptyVsAbsentForeign(t *testing.T) {
	v := loadVec(t)
	base := v.EdgeCases.KeysOutOfOrder // same base fields (format/amount/currency/payee/not_after)
	ea := v.EdgeCases.EmptyVsAbsent
	empty := payment.PaymentImport{Format: base.Format, Amount: base.Amount, Currency: base.Currency, Payee: hb(t, base.PayeeHex), NotAfter: base.NotAfter, Foreign: []byte{}}
	populated := payment.PaymentImport{Format: base.Format, Amount: base.Amount, Currency: base.Currency, Payee: hb(t, base.PayeeHex), NotAfter: base.NotAfter, Foreign: hb(t, ea.PopulatedForeign.ForeignHex)}
	if got := hex.EncodeToString(empty.Bytes()); got != ea.EmptyForeign.BodyHex {
		t.Fatalf("empty-foreign body\n got %s\nwant %s", got, ea.EmptyForeign.BodyHex)
	}
	if got := hex.EncodeToString(populated.Bytes()); got != ea.PopulatedForeign.BodyHex {
		t.Fatalf("populated-foreign body\n got %s\nwant %s", got, ea.PopulatedForeign.BodyHex)
	}
	// The empty foreign payload has its OWN, distinct foreign_id — the carriage binding distinguishes it.
	if hex.EncodeToString(empty.ForeignID()) != ea.EmptyForeign.ForeignIDHex {
		t.Fatalf("empty foreign_id diverges from the oracle")
	}
	if hex.EncodeToString(empty.ForeignID()) == hex.EncodeToString(populated.ForeignID()) {
		t.Fatal("empty and populated foreign payloads must have distinct foreign_ids")
	}
	if hex.EncodeToString(empty.ID()) == hex.EncodeToString(populated.ID()) {
		t.Fatal("empty and populated imports must have distinct content-ids")
	}
	if _, err := payment.ParsePaymentImport(empty.Bytes()); err != nil {
		t.Fatalf("ParsePaymentImport(empty foreign): %v", err)
	}
	if _, err := payment.ParsePaymentImport(populated.Bytes()); err != nil {
		t.Fatalf("ParsePaymentImport(populated foreign): %v", err)
	}
	if _, err := payment.ParsePaymentImport(hb(t, ea.AbsentField.BodyHex)); err != payment.ErrMalformed {
		t.Fatalf("absent foreign field got %v, want PayMalformed", err)
	}
}

// TestPaymentLookAlikeRejected is edge case #5: naalp-payment-import and naalp-payment-charge-binding
// share ONE 6-field shape by design, so there is no structurally-distinct in-family sibling; the
// look-alike is a near-miss with a wrong field-3 (currency) type — a bstr where a tstr is required —
// which ParsePaymentImport rejects PayMalformed. Mutation: make the currency accessor accept a bstr and
// the near-miss wrongly parses.
func TestPaymentLookAlikeRejected(t *testing.T) {
	v := loadVec(t)
	if _, err := payment.ParsePaymentImport(hb(t, v.EdgeCases.LookAlike.BodyHex)); err != payment.ErrMalformed {
		t.Fatalf("look-alike (bstr currency) got %v, want PayMalformed", err)
	}
}
