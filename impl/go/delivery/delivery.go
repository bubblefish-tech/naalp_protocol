// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package delivery implements C8 — delivery as four signed monotonic stages, the
// persist-before-acknowledge discipline, the live full-duplex switchboard, and the
// content-free relay (design.md §9; requirements R-9.1..9.4).
//
// Delivery is four distinct, separately-observable stages, each a signed delivery.update
// naming the target object's content id and the stage reached — there is no single "sent"
// boolean (§9.1): persisted_origin -> accepted_relay -> persisted_target -> presented. A
// stage is advanced only after the object is durably persisted (WAL fsync), so a crash right
// after an acknowledgment loses nothing (§9.2). Observing a stage earlier than the one already
// reached is StageOutOfOrder (§9.4). The switchboard holds two connections open and passes
// objects through both directions concurrently (§9.3); a relay that holds objects only in
// transit writes an audit trail over content ids while retaining no payload (§9.4, R-9.4).
package delivery

import (
	"crypto/sha512"
	"encoding/binary"
	"io"
	"os"
	"sync"

	"github.com/bubblefish-tech/n-aalp/impl/go/audit"
	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
)

// Delivery stages (design.md §9.1), monotonic in this order.
const (
	StagePersistedOrigin uint64 = 0
	StageAcceptedRelay   uint64 = 1
	StagePersistedTarget uint64 = 2
	StagePresented       uint64 = 3
)

var stageNames = [...]string{"persisted_origin", "accepted_relay", "persisted_target", "presented"}

// StageName returns the name of a stage value (0..3), or "unknown".
func StageName(stage uint64) string {
	if stage < uint64(len(stageNames)) {
		return stageNames[stage]
	}
	return "unknown"
}

// ErrStageOutOfOrder is returned when a stage earlier than the one already reached is observed.
var ErrStageOutOfOrder = &cose.Error{Kind: "StageOutOfOrder", Msg: "a delivery stage regressed to an earlier stage"}

func contentID(b []byte) []byte {
	d := sha512.Sum384(b)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x20, 0x30)
	return append(out, d[:]...)
}

// DeliveryUpdate is one signed delivery-stage notification (design.md §9.1).
type DeliveryUpdate struct {
	Obj   []byte // content id of the object whose delivery this reports
	Stage uint64 // the stage reached (0..3)
	At    uint64 // observer time, epoch ms
}

// Bytes is the deterministic-CBOR encoding {1: obj, 2: stage, 3: at}.
func (d DeliveryUpdate) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(d.Obj)},
		{K: cbor.Uint(2), V: cbor.Uint(d.Stage)},
		{K: cbor.Uint(3), V: cbor.Uint(d.At)},
	})
	return b
}

// SignUpdate signs a delivery.update with the observer's key.
func SignUpdate(d DeliveryUpdate, signer cose.Signer) ([]byte, error) { return signer.Sign(d.Bytes()) }

// Tracker is a durable, per-object delivery-stage tracker enforcing monotonic stages and
// persist-before-acknowledge. Each Advance persists to the write-ahead log and fsyncs before
// returning the acknowledging update, so a crash after the ack loses nothing (§9.2).
type Tracker struct {
	mu      sync.Mutex
	f       *os.File
	current map[string]uint64 // object-id -> highest stage reached
}

// OpenTracker opens (creating if needed) a WAL-backed tracker and replays it to recover the
// last durable stage for every object.
func OpenTracker(path string) (*Tracker, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	t := &Tracker{f: f, current: make(map[string]uint64)}
	if err := t.replay(); err != nil {
		f.Close()
		return nil, err
	}
	return t, nil
}

func (t *Tracker) replay() error {
	if _, err := t.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(t.f, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		rec := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
		if _, err := io.ReadFull(t.f, rec); err != nil {
			return err
		}
		u, err := parseUpdate(rec)
		if err != nil {
			return err
		}
		t.current[string(u.Obj)] = u.Stage // last durable stage wins (monotonic on write)
	}
	return nil
}

// Advance records that obj reached stage at time at, and returns the acknowledging update. A
// stage earlier than the one already reached is StageOutOfOrder (no state change); re-reporting
// the current stage is an idempotent no-op; a later stage is persisted (WAL fsync) before the
// update is returned. Skipping ahead (e.g. a relay-less path) is permitted; only regression is
// an error.
func (t *Tracker) Advance(obj []byte, stage, at uint64) (DeliveryUpdate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := string(obj)
	if cur, seen := t.current[key]; seen {
		if stage < cur {
			return DeliveryUpdate{}, ErrStageOutOfOrder
		}
		if stage == cur {
			return DeliveryUpdate{Obj: append([]byte(nil), obj...), Stage: stage, At: at}, nil
		}
	}
	u := DeliveryUpdate{Obj: append([]byte(nil), obj...), Stage: stage, At: at}
	rec := u.Bytes()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(rec)))
	if _, err := t.f.Write(append(lenBuf[:], rec...)); err != nil {
		return DeliveryUpdate{}, err
	}
	if err := t.f.Sync(); err != nil { // persist-before-ack (R-9.2)
		return DeliveryUpdate{}, err
	}
	t.current[key] = stage
	return u, nil
}

// Stage returns the highest stage reached for obj and whether it has been seen.
func (t *Tracker) Stage(obj []byte) (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.current[string(obj)]
	return s, ok
}

// Close flushes and closes the WAL file.
func (t *Tracker) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.f.Close()
}

func parseUpdate(rec []byte) (DeliveryUpdate, error) {
	v, err := cbor.Decode(rec)
	if err != nil {
		return DeliveryUpdate{}, err
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return DeliveryUpdate{}, &cose.Error{Kind: "Malformed", Msg: "delivery update is not a map"}
	}
	var u DeliveryUpdate
	for _, p := range m {
		k, ok := p.K.(cbor.Uint)
		if !ok {
			return DeliveryUpdate{}, &cose.Error{Kind: "Malformed", Msg: "non-uint key"}
		}
		switch uint64(k) {
		case 1:
			b, ok := p.V.(cbor.Bstr)
			if !ok {
				return DeliveryUpdate{}, &cose.Error{Kind: "Malformed", Msg: "obj not bstr"}
			}
			u.Obj = b
		case 2:
			s, ok := p.V.(cbor.Uint)
			if !ok {
				return DeliveryUpdate{}, &cose.Error{Kind: "Malformed", Msg: "stage not uint"}
			}
			u.Stage = uint64(s)
		case 3:
			a, ok := p.V.(cbor.Uint)
			if !ok {
				return DeliveryUpdate{}, &cose.Error{Kind: "Malformed", Msg: "at not uint"}
			}
			u.At = uint64(a)
		default:
			return DeliveryUpdate{}, &cose.Error{Kind: "Malformed", Msg: "unknown delivery-update key"}
		}
	}
	return u, nil
}

// Endpoint is one side of a switchboard connection: objects written to Send are relayed to the
// peer's Recv, concurrently with the reverse direction.
type Endpoint struct {
	send chan []byte
	recv chan []byte
}

// Send submits an object into the switchboard toward the peer.
func (e *Endpoint) Send(obj []byte) { e.send <- obj }

// Recv receives the next object relayed from the peer (blocks until one arrives).
func (e *Endpoint) Recv() []byte { return <-e.recv }

// Switchboard holds two connections open and relays objects through in both directions
// concurrently (design.md §9.3) — a live full-duplex relay, not a one-object mailbox. Two pump
// goroutines forward left->right and right->left simultaneously.
type Switchboard struct {
	left, right *Endpoint
	done        chan struct{}
	wg          sync.WaitGroup
}

// NewSwitchboard starts a switchboard with per-direction buffering `capacity` and both pumps
// running.
func NewSwitchboard(capacity int) *Switchboard {
	l := &Endpoint{send: make(chan []byte, capacity), recv: make(chan []byte, capacity)}
	r := &Endpoint{send: make(chan []byte, capacity), recv: make(chan []byte, capacity)}
	s := &Switchboard{left: l, right: r, done: make(chan struct{})}
	// left.send -> right.recv, and right.send -> left.recv, concurrently.
	s.wg.Add(2)
	go s.pump(l.send, r.recv)
	go s.pump(r.send, l.recv)
	return s
}

func (s *Switchboard) pump(in, out chan []byte) {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case obj := <-in:
			select {
			case out <- obj: // forwarded in transit; the pump retains nothing
			case <-s.done:
				return
			}
		}
	}
}

// Left and Right return the two endpoints of the switchboard.
func (s *Switchboard) Left() *Endpoint  { return s.left }
func (s *Switchboard) Right() *Endpoint { return s.right }

// Close stops both pumps and waits for them to exit.
func (s *Switchboard) Close() {
	close(s.done)
	s.wg.Wait()
}

// ContentFreeRelay routes objects while retaining no payload at rest: for each routed object it
// appends an audit receipt (§8) over the object's content id and returns the object for
// immediate forwarding, keeping only the receipt chain (content ids), never the payload (§9.4,
// R-9.4). The retained audit trail alone verifies as a valid chain.
type ContentFreeRelay struct {
	auth     *audit.Authority
	receipts []audit.Receipt
	sigs     [][]byte
}

// NewContentFreeRelay makes a relay whose audit trail is signed by signer.
func NewContentFreeRelay(signer cose.Signer) *ContentFreeRelay {
	return &ContentFreeRelay{auth: audit.NewAuthority(signer)}
}

// Route records an audit receipt over obj's content id and returns obj for forwarding. The
// relay keeps the receipt only; it does not store obj.
func (r *ContentFreeRelay) Route(obj []byte, at uint64) ([]byte, error) {
	rec, sig, err := r.auth.Append(contentID(obj), at)
	if err != nil {
		return nil, err
	}
	r.receipts = append(r.receipts, rec)
	r.sigs = append(r.sigs, sig)
	return obj, nil
}

// AuditTrail returns the receipts and signatures the relay retained (its only persistent
// state), for offline chain verification.
func (r *ContentFreeRelay) AuditTrail() ([]audit.Receipt, [][]byte) { return r.receipts, r.sigs }

// ContentID exposes the T1 content-id framing used for relay receipts (for callers/tests).
func ContentID(b []byte) []byte { return contentID(b) }
