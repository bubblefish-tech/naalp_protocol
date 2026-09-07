// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package approval implements C6 — the approval object that binds exact canonical arguments
// by content id, and the durable, hash-chained, single-use consume ledger (design.md §7;
// requirements R-7.1..7.4).
//
// An Approval binds, under signature, the content id of the exact argument object it
// approves (§7.1); because the args are named by content id, mutating any argument changes
// the id and the approval no longer matches (ApprovalMismatch). The consume ledger is a
// durable compare-and-set set keyed by approval content id: the first consumer wins and a
// second consume of the same approval is rejected (AlreadyConsumed) (§7.2). Atomicity comes
// from a write-ahead log written and fsynced before a consume returns (persist-before-ack)
// and a single-writer discipline (one mutex serialises the compare-and-set), so exactly one
// concurrent consumer succeeds. A held outcome is a distinct signed non-success result
// (ApprovalHeld, §7.4). Every rejection is fail-closed and causes no ledger append.
package approval

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// HeadSize is the width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.
const HeadSize = 48

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind. BadSignature
// is reused directly from package cose.
var (
	ErrApprovalMismatch = &cose.Error{Kind: "ApprovalMismatch", Msg: "approval does not bind these arguments' content id"}
	ErrApprovalExpired  = &cose.Error{Kind: "ApprovalExpired", Msg: "approval is past its not_after"}
	ErrAlreadyConsumed  = &cose.Error{Kind: "AlreadyConsumed", Msg: "approval already consumed"}
	ErrApprovalRequired = &cose.Error{Kind: "ApprovalRequired", Msg: "action requires an approval that is not present"}
	ErrLedgerCorrupt    = &cose.Error{Kind: "LedgerCorrupt", Msg: "consume ledger hash chain does not verify"}
	// T1.5 (NAALP-REQ-121) — the ledger-signed consume receipt with forward-only position.
	ErrLedgerUnsigned         = &cose.Error{Kind: "LedgerUnsigned", Msg: "ledger was not opened with a signing key"}
	ErrConsumeReceiptUnsigned = &cose.Error{Kind: "ConsumeReceiptUnsigned", Msg: "consume receipt is unnamed or its ledger signature does not verify"}
	ErrConsumeForkInvalid     = &cose.Error{Kind: "ConsumeForkInvalid", Msg: "fork evidence does not prove a double spend"}
	ErrConsumeFork            = &cose.Error{Kind: "ConsumeFork", Msg: "two ledger-signed receipts contradict on one approval id"}
)

// contentID is the T1 content-id framing over arbitrary bytes: multihash(0x20, SHA-384).
// The 50-byte id is 0x20 0x30 || digest.
func contentID(b []byte) []byte {
	d := sha512.Sum384(b)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30)
	return append(out, d[:]...)
}

// ApprovalRecord is the body of an Approval object (design.md §7.1). It is signed with the
// C2 crypto over its deterministic-CBOR bytes; wrapping it as a Governance-channel (0x0004)
// envelope object is T12.
type ApprovalRecord struct {
	Approves []byte // content id of the exact canonical args object (§7.1)
	Approver string // approver signer id
	Grant    uint64 // granted effect class (0..3), the C5 effect
	Nonce    []byte // anti-replay nonce (§7.3)
	NotAfter uint64 // expiry, epoch ms (§7.3)
	Audience string // OPTIONAL valid-context (R-TDCS-5); "" == absent (field 6 omitted, unrestricted)
}

// Bytes is the deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6 is
// OMITTED when Audience is "" — an empty string is not a distinct value, so an approval that names
// no audience encodes byte-identically to a 5-field approval (R-TDCS-5, additive by design).
func (a ApprovalRecord) Bytes() []byte {
	m := cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(a.Approves)},
		{K: cbor.Uint(2), V: cbor.Tstr(a.Approver)},
		{K: cbor.Uint(3), V: cbor.Uint(a.Grant)},
		{K: cbor.Uint(4), V: cbor.Bstr(a.Nonce)},
		{K: cbor.Uint(5), V: cbor.Uint(a.NotAfter)},
	}
	if a.Audience != "" {
		m = append(m, cbor.Pair{K: cbor.Uint(6), V: cbor.Tstr(a.Audience)})
	}
	b, _ := cbor.Encode(m)
	return b
}

// ID is the approval content id (the ledger key): multihash(0x20, SHA-384(body)).
func (a ApprovalRecord) ID() []byte { return contentID(a.Bytes()) }

// SignApproval signs the approval body with the approver's key.
func SignApproval(a ApprovalRecord, signer cose.Signer) ([]byte, error) {
	return signer.Sign(a.Bytes())
}

// VerifyApproval checks that an approval (1) is signed by the approver's key, (2) binds the
// exact args by content id, and (3) has not expired at posTime. It returns nil only if all
// three hold; otherwise it returns the specific named error and authorizes nothing. It does
// NOT consume — consumption is a separate atomic step through the ledger (§7.2).
func VerifyApproval(a ApprovalRecord, approverV cose.Verifier, sig, argsContentID []byte, posTime uint64) error {
	if !approverV.VerifyRaw(a.Bytes(), sig) {
		return cose.ErrBadSignature
	}
	if !bytes.Equal(a.Approves, argsContentID) {
		return ErrApprovalMismatch
	}
	if posTime > a.NotAfter {
		return ErrApprovalExpired
	}
	return nil
}

// ErrAudienceMismatch (R-TDCS-5) — an approval that names an audience is valid only in that context;
// presenting it at a different use context is rejected fail-closed, authorizing nothing.
var ErrAudienceMismatch = &cose.Error{Kind: "AudienceMismatch", Msg: "approval names an audience other than the use context"}

// VerifyAudience (R-TDCS-5) enforces the OPTIONAL audience binding. An approval that NAMES an
// audience (a.Audience != "") is valid only in that context: a relying party checks it at use and
// rejects AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted by the
// issuer's explicit choice and passes for any use context — a deployment MAY require an audience by
// local policy above this check. The check is mandatory WHEN a context is present, never
// mandatory-presence (the JWT `aud` present-optional / check-mandatory shape).
func VerifyAudience(a ApprovalRecord, useContext string) error {
	if a.Audience != "" && a.Audience != useContext {
		return ErrAudienceMismatch
	}
	return nil
}

// HeldResult is the distinct, signed, non-success result returned when an action requires an
// approval that has not been granted (design.md §7.4). It is never a silent success or a
// silent denial. Reason is a short accountable explanation.
type HeldResult struct {
	Approves []byte // content id of the args whose approval is pending
	Reason   string
}

// Bytes is the deterministic-CBOR encoding of the held result {1: approves, 2: reason}.
func (h HeldResult) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(h.Approves)},
		{K: cbor.Uint(2), V: cbor.Tstr(h.Reason)},
	})
	return b
}

// SignHeld signs a held result so the "not yet granted" outcome is itself attributable.
func SignHeld(h HeldResult, signer cose.Signer) ([]byte, error) { return signer.Sign(h.Bytes()) }

// LedgerEntry is one append to the consume ledger (design.md §7.2).
type LedgerEntry struct {
	Seq        uint64 // ledger sequence position
	Prev       []byte // prior chain head (HeadSize bytes; genesis is all-zero)
	ApprovalID []byte // the approval content id being consumed
	By         string // consumer signer id
}

// Bytes is the deterministic-CBOR encoding of the entry {1: seq, 2: prev, 3: approval-id,
// 4: by}. The head after this entry is SHA-384(Bytes()); because Bytes carries Prev, editing
// any entry breaks the next entry's linkage.
func (e LedgerEntry) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Uint(e.Seq)},
		{K: cbor.Uint(2), V: cbor.Bstr(e.Prev)},
		{K: cbor.Uint(3), V: cbor.Bstr(e.ApprovalID)},
		{K: cbor.Uint(4), V: cbor.Tstr(e.By)},
	})
	return b
}

func chainNext(entryBytes []byte) []byte {
	d := sha512.Sum384(entryBytes)
	return d[:]
}

// Ledger is the durable, hash-chained, single-use consume set (design.md §7.2). All state
// mutation goes through Consume under a single mutex (the single-writer discipline), and each
// successful consume is written and fsynced to the write-ahead log before it returns.
type Ledger struct {
	mu       sync.Mutex
	f        *os.File
	consumed map[string]uint64 // approval-id hex -> seq
	head     []byte            // current chain head (HeadSize bytes)
	seq      uint64            // next sequence number
	// T1.5 (NAALP-REQ-121): the ledger's own ordering-authority identity + signing key. Set only
	// by OpenLedgerSigned; nil for a plain OpenLedger (which offers Consume, not the signed receipt).
	ledgerID []byte      // this consuming ledger's signer id (the ordering authority)
	signer   cose.Signer // the ledger's signing key
}

// OpenLedger opens (creating if needed) a WAL-backed ledger at path and replays any existing
// log to rebuild the consumed set and chain head. A log that does not hash-chain cleanly is
// refused (LedgerCorrupt) rather than trusted.
func OpenLedger(path string) (*Ledger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Ledger{
		f:        f,
		consumed: make(map[string]uint64),
		head:     make([]byte, HeadSize),
	}
	if err := l.replay(); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

// OpenLedgerSigned opens a WAL-backed ledger (as OpenLedger) and binds it to its own
// ordering-authority identity (ledgerID, the signer-id form of the ledger key) and signing key, so
// it can produce ledger-signed consume receipts (design.md §7.5; T1.5, NAALP-REQ-121). A ledgerID of
// zero length or a nil signer is refused fail-closed: an unnamed or keyless ordering authority cannot
// sign the anti-double-spend position, so ConsumeWithReceipt would have nothing accountable to emit.
func OpenLedgerSigned(path string, ledgerID []byte, signer cose.Signer) (*Ledger, error) {
	if len(ledgerID) == 0 || signer == nil {
		return nil, ErrLedgerUnsigned
	}
	l, err := OpenLedger(path)
	if err != nil {
		return nil, err
	}
	l.ledgerID = append([]byte(nil), ledgerID...)
	l.signer = signer
	return l, nil
}

// replay reads the WAL from the start, rebuilding state and verifying the chain. Each record
// is length-prefixed (uint32 big-endian) so the log is self-framing.
func (l *Ledger) replay() error {
	if _, err := l.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	head := make([]byte, HeadSize)
	var seq uint64
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(l.f, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		rec := make([]byte, n)
		if _, err := io.ReadFull(l.f, rec); err != nil {
			return err // a truncated trailing record is a corrupt log
		}
		e, err := parseEntry(rec)
		if err != nil {
			return err
		}
		if e.Seq != seq || !bytes.Equal(e.Prev, head) {
			return ErrLedgerCorrupt // out-of-order seq or broken chain linkage
		}
		l.consumed[string(e.ApprovalID)] = e.Seq
		head = chainNext(rec)
		seq++
	}
	l.head = head
	l.seq = seq
	return nil
}

// Consume atomically consumes an approval id exactly once (design.md §7.2). The first caller
// for a given id appends a ledger entry (written and fsynced to the WAL before returning) and
// returns it; every later caller for the same id returns AlreadyConsumed with no append. The
// single mutex serialises concurrent callers, so under a race exactly one succeeds.
func (l *Ledger) Consume(approvalID []byte, by string) (*LedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.consumed[string(approvalID)]; ok {
		return nil, ErrAlreadyConsumed
	}
	e := &LedgerEntry{Seq: l.seq, Prev: append([]byte(nil), l.head...), ApprovalID: append([]byte(nil), approvalID...), By: by}
	rec := e.Bytes()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rec)))
	if _, err := l.f.Write(append(lenBuf[:], rec...)); err != nil {
		return nil, err // nothing recorded in memory: the consume did not happen
	}
	if err := l.f.Sync(); err != nil { // persist-before-ack (R-7.2 durability)
		return nil, err
	}
	l.consumed[string(approvalID)] = e.Seq
	l.head = chainNext(rec)
	l.seq++
	return e, nil
}

// ConsumeObject is the audience-checked consume choke point for a single-use object (design.md
// §2.5.3, the single-use consume binding). It enforces the object's audience BEFORE the compare-and-
// set: a consume-once object MUST name THIS ordering authority (l.ledgerID) as its audience, or the
// consume is refused WrongAudience with NO ledger append and no state change — the federated double-
// consume guard (the same use-once object presented to a DIFFERENT authority is rejected, not double-
// spent). It requires a NAMED authority (OpenLedgerSigned): an unnamed ledger cannot be an object's
// one consuming authority, so it fails closed (LedgerUnsigned) rather than consuming an unbound
// object. The check runs at the point of use, never in envelope.Verify — an in-transit relay or
// auditor verifies objects addressed to others (see envelope.CheckAudience).
func (l *Ledger) ConsumeObject(o *envelope.Object, approvalID []byte, by string) (*LedgerEntry, error) {
	if len(l.ledgerID) == 0 {
		return nil, ErrLedgerUnsigned // an unnamed authority cannot enforce the audience binding
	}
	if err := envelope.CheckAudience(o, string(l.ledgerID), true); err != nil {
		return nil, err // WrongAudience -> no append, before the CAS (fail-closed)
	}
	return l.Consume(approvalID, by)
}

// ConsumeApproval is the composed, single-call consume choke point for the approval state machine
// (draft "## Approval state machine"). It runs the table's precedence in ONE impl-owned place — the
// exact sequence that payment.AuthorizeCharge, mcp, agui and delegation each hand-assemble — so a
// caller (and the conformance suite) drives one realization of the reactions rather than re-deriving
// the ordering at each call site:
//
//  1. VerifyApproval checks the signature, then the args-content-id binding (ApprovalMismatch, which
//     the draft says "takes precedence over every cell"), then expiry (ApprovalExpired) — all BEFORE
//     the ledger is consulted. So a request both past not_after AND already in the ledger is refused
//     ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume rule), and the ledger is
//     left untouched by the rejected request.
//  2. The granted effect must be a valid class (0..3) and must cover the action's required effect; a
//     grant outside the closed vocabulary, or one below the required effect, authorizes nothing and is
//     refused ApprovalRequired (fail-closed; the grant-range guard is stricter than the raw callers).
//  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a second
//     returns AlreadyConsumed, and neither a rejected earlier step nor a losing race appends.
//
// Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
// returning the ledger entry. It does NOT enforce object audience — that is ConsumeObject's binding
// (design.md §2.5.3); ConsumeApproval is the args-content-id/effect/single-use choke point.
func ConsumeApproval(a ApprovalRecord, approverV cose.Verifier, aSig, argsContentID []byte, posTime uint64, requiredEffect policy.Effect, ledger *Ledger, by string) (*LedgerEntry, error) {
	if err := VerifyApproval(a, approverV, aSig, argsContentID, posTime); err != nil {
		return nil, err // BadSignature / ApprovalMismatch / ApprovalExpired — all before the ledger (§ precedence)
	}
	if a.Grant > uint64(policy.Destructive) {
		return nil, ErrApprovalRequired // a grant outside the closed 0..3 effect vocabulary authorizes nothing
	}
	if !policy.Effect(a.Grant).Authorizes(requiredEffect) {
		return nil, ErrApprovalRequired // the approval's granted effect does not cover this action
	}
	return ledger.Consume(a.ID(), by)
}

// ConsumeReceipt is the draft-01 (T1.5, NAALP-REQ-121) ledger-signed evidence that a consuming
// ledger — the ORDERING AUTHORITY — bound an approval content id to its own forward-only position.
// The anti-double-spend counter (Position) rides under the LEDGER's signature, never the requester's:
// the requester cannot forge the ledger's position or its signature. A partition that spends one
// approval twice therefore leaves two ledger-signed receipts against one approval id, each carrying a
// position drawn from forked state — a contradiction authored by neither the requester nor a thief,
// provable the instant the two receipts are compared (see ConsumeForkEvidence). It does not PREVENT
// the second spend; it makes the double-spend detectable in bytes neither party could repudiate.
type ConsumeReceipt struct {
	Ledger     []byte // the consuming ledger's signer id (the ordering authority; REQ-121)
	ApprovalID []byte // the approval content id consumed (the compare-and-set key)
	Position   uint64 // the ledger's forward-only position bound to this consume
}

// Bytes is the deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id,
// 3: position} — the exact bytes the ledger signs (T1.5).
func (r ConsumeReceipt) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(r.Ledger)},
		{K: cbor.Uint(2), V: cbor.Bstr(r.ApprovalID)},
		{K: cbor.Uint(3), V: cbor.Uint(r.Position)},
	})
	return b
}

// SignConsumeReceipt signs a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend
// counter is under the ordering authority's signature). The signed input is the receipt Bytes().
func SignConsumeReceipt(r ConsumeReceipt, ledgerSigner cose.Signer) ([]byte, error) {
	return ledgerSigner.Sign(r.Bytes())
}

// VerifyConsumeReceipt checks that a consume receipt is a valid ledger-signed statement: the ledger
// id is present (an unnamed ordering authority is not evidence) and the signature verifies under the
// ledger's key. Fail-closed: either fault returns ConsumeReceiptUnsigned and authorizes nothing.
// ledgerV MUST be the verifier resolved for r.Ledger.
func VerifyConsumeReceipt(r ConsumeReceipt, ledgerV cose.Verifier, sig []byte) error {
	if len(r.Ledger) == 0 {
		return ErrConsumeReceiptUnsigned // an unnamed ordering authority is not evidence
	}
	if !ledgerV.VerifyRaw(r.Bytes(), sig) {
		return ErrConsumeReceiptUnsigned
	}
	return nil
}

// ErrFreshnessSelfAsserted (R-TDCS-4) — the ordering authority that stamps a credential's
// present-moment position MUST be structurally distinct from the party whose credential's freshness
// is being judged. A receipt whose ordering authority (ledger) IS the authenticated party is that
// party asserting its own freshness — the exact self-reference the closure property forbids — and is
// rejected fail-closed, authorizing nothing.
var ErrFreshnessSelfAsserted = &cose.Error{Kind: "FreshnessSelfAsserted", Msg: "the ordering authority that stamps freshness is the authenticated party itself"}

// VerifyFreshIndependent (R-TDCS-4) judges an approval's present-moment validity using time drawn
// from an ordering authority STRUCTURALLY DISTINCT from the party being authenticated. It is the
// named realization of the §18.2 seam — "validity judged on the ordering position, never the
// signer's clock" — composing the existing verifiers and adding the distinctness check a relying
// party runs so a party can never be the source of the time against which its own credential's
// expiry is judged. It (1) verifies the approval binds argsContentID, is signed by the approver, and
// is unexpired at posTime, where posTime is the ORDERING AUTHORITY's forward-only position (never a
// clock the approver supplies); (2) verifies the consume receipt is ledger-signed (the position
// rides under the ordering authority's key, never the requester's); and (3) rejects
// FreshnessSelfAsserted when the ordering authority r.Ledger IS the authenticated party partyID.
// Fail-closed: any fault returns its named error and authorizes nothing.
func VerifyFreshIndependent(a ApprovalRecord, approverV cose.Verifier, aSig, argsContentID []byte, posTime uint64, r ConsumeReceipt, ledgerV cose.Verifier, rSig, partyID []byte) error {
	if err := VerifyApproval(a, approverV, aSig, argsContentID, posTime); err != nil {
		return err
	}
	if err := VerifyConsumeReceipt(r, ledgerV, rSig); err != nil {
		return err
	}
	if bytes.Equal(r.Ledger, partyID) {
		return ErrFreshnessSelfAsserted
	}
	return nil
}

// ConsumeWithReceipt performs the first-append-wins compare-and-set (exactly as Consume) AND, on the
// winning append, returns a ledger-signed ConsumeReceipt binding the approval id to the entry's
// forward-only position (its ledger seq). The ledger must have been opened with OpenLedgerSigned; a
// plain ledger returns LedgerUnsigned (fail-closed). A second consume of the same approval id returns
// AlreadyConsumed and signs nothing — the first receipt stands (first-append-wins). The receipt is
// signed before the WAL write, so a signing failure records nothing. The single mutex serialises
// concurrent callers, so under a race exactly one wins and exactly one receipt is minted.
func (l *Ledger) ConsumeWithReceipt(approvalID []byte, by string) (*LedgerEntry, ConsumeReceipt, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.signer == nil || len(l.ledgerID) == 0 {
		return nil, ConsumeReceipt{}, nil, ErrLedgerUnsigned
	}
	if _, ok := l.consumed[string(approvalID)]; ok {
		return nil, ConsumeReceipt{}, nil, ErrAlreadyConsumed // first-append-wins: no second receipt
	}
	e := &LedgerEntry{Seq: l.seq, Prev: append([]byte(nil), l.head...), ApprovalID: append([]byte(nil), approvalID...), By: by}
	// The receipt binds the approval id to THIS consume's forward-only position (the entry seq),
	// signed by the ledger key. Sign before touching the WAL so a signing failure records nothing.
	receipt := ConsumeReceipt{Ledger: append([]byte(nil), l.ledgerID...), ApprovalID: append([]byte(nil), approvalID...), Position: e.Seq}
	sig, err := l.signer.Sign(receipt.Bytes())
	if err != nil {
		return nil, ConsumeReceipt{}, nil, err
	}
	rec := e.Bytes()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rec)))
	if _, err := l.f.Write(append(lenBuf[:], rec...)); err != nil {
		return nil, ConsumeReceipt{}, nil, err // nothing recorded in memory: the consume did not happen
	}
	if err := l.f.Sync(); err != nil { // persist-before-ack (R-7.2 durability)
		return nil, ConsumeReceipt{}, nil, err
	}
	l.consumed[string(approvalID)] = e.Seq
	l.head = chainNext(rec)
	l.seq++
	return e, receipt, sig, nil
}

// ConsumeForkEvidence is the non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content
// id received TWO conflicting ledger-signed consume receipts — a double spend made provable on
// comparison. It carries both receipts and both ledger signatures; because a verifier checks each
// signature under the key its receipt names, the contradiction is authored by neither the requester
// nor a thief. Both positions (and, cross-ledger, both ledger ids) are surfaced so the contradiction
// is legible to a human and to tooling.
type ConsumeForkEvidence struct {
	ApprovalID []byte         // the one approval content id spent twice
	A          ConsumeReceipt // first receipt
	SigA       []byte         // ledger A's signature over A.Bytes()
	B          ConsumeReceipt // second receipt (same approval id; different position and/or ledger)
	SigB       []byte         // ledger B's signature over B.Bytes()
}

// Verify checks that fe is a genuine fork: (1) the disputed approval id is present and BOTH receipts
// name it; (2) the two receipts actually conflict — they are NOT byte-identical (a byte-identical
// re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures verify under the
// keys their receipts name, resolved through `resolve`. Any failure rejects the whole thing
// (fail-closed): a mismatched/absent approval id or a byte-identical pair is ConsumeForkInvalid, and
// an unnamed/unresolvable ledger or a signature that does not verify is ConsumeReceiptUnsigned. On a
// clean pass the double spend is proven and non-repudiable.
func (fe ConsumeForkEvidence) Verify(resolve func(ledgerID []byte) (cose.Verifier, bool)) error {
	if len(fe.ApprovalID) == 0 {
		return ErrConsumeForkInvalid
	}
	if !bytes.Equal(fe.A.ApprovalID, fe.ApprovalID) || !bytes.Equal(fe.B.ApprovalID, fe.ApprovalID) {
		return ErrConsumeForkInvalid // both receipts must name the one disputed approval id
	}
	if bytes.Equal(fe.A.Bytes(), fe.B.Bytes()) {
		return ErrConsumeForkInvalid // byte-identical receipts are a benign duplicate, not a fork
	}
	va, ok := resolve(fe.A.Ledger)
	if !ok || len(fe.A.Ledger) == 0 {
		return ErrConsumeReceiptUnsigned
	}
	vb, ok := resolve(fe.B.Ledger)
	if !ok || len(fe.B.Ledger) == 0 {
		return ErrConsumeReceiptUnsigned
	}
	if !va.VerifyRaw(fe.A.Bytes(), fe.SigA) || !vb.VerifyRaw(fe.B.Bytes(), fe.SigB) {
		return ErrConsumeReceiptUnsigned
	}
	return nil // a valid, non-repudiable double-spend proof
}

// seenConsumeReceipt is a receipt the ReceiptSet has accepted, kept with its signature so a later
// conflict can be minted into a ConsumeForkEvidence carrying BOTH ledger signatures.
type seenConsumeReceipt struct {
	r   ConsumeReceipt
	sig []byte
}

// ReceiptSet observes ledger-signed consume receipts, keyed by approval content id, and detects a
// fork (a double spend) from the signed receipts alone (T1.5, NAALP-REQ-121) — the consume-layer
// analogue of the audit auditor's equivocation detection. It resolves each receipt's ledger verifier
// through `resolve`, rejects any receipt whose ledger signature does not verify, and on a conflicting
// second receipt for one approval id mints a non-repudiable ConsumeForkEvidence.
type ReceiptSet struct {
	mu      sync.Mutex
	resolve func([]byte) (cose.Verifier, bool)
	seen    map[string]seenConsumeReceipt // approval-id -> first receipt seen
}

// NewReceiptSet makes a fork detector that resolves a ledger id to its verifier via resolve (which
// returns false for an unknown ledger id).
func NewReceiptSet(resolve func(ledgerID []byte) (cose.Verifier, bool)) *ReceiptSet {
	return &ReceiptSet{resolve: resolve, seen: make(map[string]seenConsumeReceipt)}
}

// Observe records a ledger-signed consume receipt. It returns ConsumeReceiptUnsigned if the ledger
// is unnamed/unresolvable or the signature does not verify; a non-nil ConsumeForkEvidence with
// ConsumeFork when a previously-seen receipt for the same approval id conflicts (different position
// and/or ledger); and (nil, nil) otherwise (including a benign byte-identical duplicate).
func (s *ReceiptSet) Observe(r ConsumeReceipt, sig []byte) (*ConsumeForkEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.resolve(r.Ledger)
	if !ok || len(r.Ledger) == 0 || !v.VerifyRaw(r.Bytes(), sig) {
		return nil, ErrConsumeReceiptUnsigned
	}
	key := string(r.ApprovalID)
	if prev, ok := s.seen[key]; ok {
		if bytes.Equal(prev.r.Bytes(), r.Bytes()) {
			return nil, nil // benign byte-identical duplicate
		}
		fe := ConsumeForkEvidence{
			ApprovalID: append([]byte(nil), r.ApprovalID...),
			A:          prev.r,
			SigA:       prev.sig,
			B:          r,
			SigB:       append([]byte(nil), sig...),
		}
		return &fe, ErrConsumeFork
	}
	s.seen[key] = seenConsumeReceipt{r: r, sig: append([]byte(nil), sig...)}
	return nil, nil
}

// IsConsumed reports whether an approval id has been consumed.
func (l *Ledger) IsConsumed(approvalID []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.consumed[string(approvalID)]
	return ok
}

// Head returns the current chain head (a copy).
func (l *Ledger) Head() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.head...)
}

// Len returns the number of consumed approvals.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.consumed)
}

// Close flushes and closes the WAL file.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// parseEntry decodes a ledger entry from its deterministic-CBOR bytes.
func parseEntry(rec []byte) (*LedgerEntry, error) {
	v, err := cbor.Decode(rec)
	if err != nil {
		return nil, err
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, fmt.Errorf("ledger entry is not a map")
	}
	e := &LedgerEntry{}
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return nil, fmt.Errorf("non-uint key")
		}
		switch uint64(k) {
		case 1:
			u, ok := p.V.(cbor.Uint)
			if !ok {
				return nil, fmt.Errorf("seq not uint")
			}
			e.Seq = uint64(u)
		case 2:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, fmt.Errorf("prev not bstr")
			}
			e.Prev = b
		case 3:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return nil, fmt.Errorf("approval-id not bstr")
			}
			e.ApprovalID = b
		case 4:
			s, ok := p.V.(cbor.Tstr)
			if !ok {
				return nil, fmt.Errorf("by not tstr")
			}
			e.By = string(s)
		default:
			return nil, fmt.Errorf("unknown ledger entry key %d", uint64(k))
		}
	}
	return e, nil
}
