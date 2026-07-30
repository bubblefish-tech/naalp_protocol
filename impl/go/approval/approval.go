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
}

// Bytes is the deterministic-CBOR encoding of the approval body {1..5}.
func (a ApprovalRecord) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(a.Approves)},
		{K: cbor.Uint(2), V: cbor.Tstr(a.Approver)},
		{K: cbor.Uint(3), V: cbor.Uint(a.Grant)},
		{K: cbor.Uint(4), V: cbor.Bstr(a.Nonce)},
		{K: cbor.Uint(5), V: cbor.Uint(a.NotAfter)},
	})
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
