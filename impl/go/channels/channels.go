// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package channels implements C10 — the twenty channel surfaces, baseline tier (tier 0)
// (design-channels.md; requirements R-11.1..11.4, R-15A.1..15A.3).
//
// A channel surface is a thin body over the one spine (design.md §2..§10): it adds only kind
// codes and their declared effects; it introduces no channel-local encoding, signature, or
// identity (R-11.3). This package holds the frozen baseline registry for all twenty channels
// (none omitted, R-11.1), builds the envelope KindValidator from it, binds each kind to its
// declared effect, models each channel's state transitions and named errors, and provides the
// channel-specific structural checks the design calls out (CapExceedsParent, TransformCycle) and
// the Workflow input-gate whose crash test proves InputGateBypass cannot occur. Higher tiers
// (tier 1+) are T13.
package channels

import (
	"encoding/binary"
	"io"
	"os"
	"sync"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// KindSpec is one baseline object kind of a channel: its code, name, and declared effect. A
// Variable kind's effect is set per the carried/stream action at run time (authorized by C5),
// not fixed by the kind (Stream StreamOpen, Bridge Carriage).
type KindSpec struct {
	Code     uint64
	Name     string
	Effect   policy.Effect
	Variable bool
}

// ChannelSpec is one channel's frozen baseline surface.
type ChannelSpec struct {
	ID          uint64
	Name        string
	Kinds       []KindSpec
	States      []string
	Transitions [][2]string
	Errors      []string
}

const (
	ro  = policy.ReadOnly
	iw  = policy.IdempotentWrite
	niw = policy.NonIdempotentWrite
	de  = policy.Destructive
)

// Table is the frozen twenty-channel baseline registry (design-channels.md §1..§20). It is the
// impl's authoritative transcription of the design; the test cross-checks it against the
// independent per-channel oracle (Go == oracle == Rust).
var Table = []ChannelSpec{
	{0x0000, "Control", []KindSpec{{0, "Hello", ro, false}, {1, "Bye", iw, false}, {2, "Ack", ro, false}, {3, "Error", ro, false}},
		[]string{"open", "closing"}, [][2]string{{"open", "closing"}}, []string{"UnknownKind", "ProfileMismatch"}},
	{0x0001, "Memory", []KindSpec{{0, "MemoryOffer", iw, false}, {1, "MemoryAccept", iw, false}, {2, "MemoryWrite", niw, false}, {3, "MemoryRead", ro, false}, {4, "MemoryExpire", de, false}, {5, "MemoryRevoke", de, false}},
		[]string{"offered", "accepted", "live", "expired", "revoked"}, [][2]string{{"offered", "accepted"}, {"accepted", "live"}, {"live", "expired"}, {"live", "revoked"}}, []string{"AccessDenied", "MemoryError"}},
	{0x0002, "Capability", []KindSpec{{0, "CapIssue", niw, false}, {1, "CapDelegate", niw, false}, {2, "CapRevoke", de, false}, {3, "CapLookup", ro, false}},
		[]string{"issued", "delegated", "revoked", "expired"}, [][2]string{{"issued", "delegated"}, {"delegated", "delegated"}, {"issued", "revoked"}, {"delegated", "revoked"}, {"issued", "expired"}, {"delegated", "expired"}}, []string{"CapExceedsParent", "CapRevoked"}},
	{0x0003, "Identity", []KindSpec{{0, "Rotation", niw, false}, {1, "Revocation", de, false}, {2, "ForeignLink", iw, false}, {3, "KeyAnnounce", ro, false}},
		[]string{"active", "rotated", "revoked"}, [][2]string{{"active", "rotated"}, {"rotated", "rotated"}, {"active", "revoked"}, {"rotated", "revoked"}}, []string{"RotationUnauthorized", "KeyRevoked", "SignerMismatch"}},
	{0x0004, "Governance", []KindSpec{{0, "PolicyPublish", niw, false}, {1, "Approval", niw, false}, {2, "ApprovalHeld", ro, false}, {3, "Consume", niw, false}},
		[]string{"requested", "held", "approved", "consumed", "expired"}, [][2]string{{"requested", "held"}, {"requested", "approved"}, {"approved", "consumed"}, {"held", "approved"}, {"requested", "expired"}, {"approved", "expired"}}, []string{"ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"}},
	{0x0005, "Immune", []KindSpec{{0, "AnomalyReport", ro, false}, {1, "Quarantine", de, false}, {2, "QuarantineLift", niw, false}},
		[]string{"normal", "quarantined", "lifted", "permanent"}, [][2]string{{"normal", "quarantined"}, {"quarantined", "lifted"}, {"quarantined", "permanent"}}, []string{"AccessDenied"}},
	{0x0006, "Federation", []KindSpec{{0, "AuthorityAnnounce", ro, false}, {1, "ScopeReceipt", niw, false}},
		[]string{"announced", "ordering"}, [][2]string{{"announced", "ordering"}}, []string{"AuthorityUnknown", "ScopeOverlapConflict"}},
	{0x0007, "Settlement", []KindSpec{{0, "SettleIntent", niw, false}, {1, "SettleReceipt", niw, false}, {2, "SettleReject", iw, false}},
		[]string{"intent", "receipt", "reject"}, [][2]string{{"intent", "receipt"}, {"intent", "reject"}}, []string{"ValueMismatch", "SettleExpired"}},
	{0x0008, "Compliance", []KindSpec{{0, "ComplianceRecord", niw, false}, {1, "ComplianceQuery", ro, false}, {2, "ComplianceReport", ro, false}},
		[]string{"appended"}, nil, []string{"RecordUnsigned", "JurisdictionUnknown"}},
	{0x0009, "Sensory", []KindSpec{{0, "Observation", ro, false}, {1, "Subscribe", iw, false}, {2, "Unsubscribe", iw, false}},
		[]string{"active", "cancelled"}, [][2]string{{"active", "cancelled"}}, []string{"SubscriptionUnknown"}},
	{0x000A, "Telemetry", []KindSpec{{0, "Metric", ro, false}, {1, "HealthReport", ro, false}},
		[]string{"stateless"}, nil, []string{"MetricMalformed"}},
	{0x000B, "Audit", []KindSpec{{0, "Receipt", niw, false}, {1, "AuditQuery", ro, false}, {2, "ForkProof", ro, false}},
		[]string{"appended"}, nil, []string{"ChainBroken", "Equivocation", "ReceiptUnsigned"}},
	{0x000C, "Stream", []KindSpec{{0, "StreamOpen", ro, true}, {1, "StreamCommit", ro, false}, {2, "StreamCheckpoint", ro, false}},
		[]string{"open", "committed"}, [][2]string{{"open", "committed"}}, []string{"StreamDigestMismatch", "FlowControlError"}},
	{0x000D, "Bridge", []KindSpec{{0, "Carriage", ro, true}},
		[]string{"carried"}, nil, []string{"EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"}},
	{0x000E, "Commerce", []KindSpec{{0, "Offer", ro, false}, {1, "Order", niw, false}, {2, "Fulfil", niw, false}, {3, "Cancel", de, false}},
		[]string{"offer", "order", "fulfil", "cancel"}, [][2]string{{"offer", "order"}, {"order", "fulfil"}, {"order", "cancel"}}, []string{"OfferExpired", "ApprovalRequired", "OrderMismatch"}},
	{0x000F, "Interaction", []KindSpec{{0, "Elicit", ro, false}, {1, "Respond", iw, false}, {2, "Confirm", niw, false}},
		[]string{"elicit", "respond", "confirm", "timeout"}, [][2]string{{"elicit", "respond"}, {"elicit", "confirm"}, {"elicit", "timeout"}}, []string{"InteractionTimeout", "ElicitUnauthorized"}},
	{0x0010, "Discovery", []KindSpec{{0, "DiscoveryRecord", ro, false}, {1, "DiscoveryQuery", ro, false}},
		[]string{"fresh", "stale"}, [][2]string{{"fresh", "stale"}}, []string{"RecordExpired", "TrustAnchorUnknown"}},
	{0x0011, "Workflow", []KindSpec{{0, "TaskCreate", niw, false}, {1, "TaskInput", niw, false}, {2, "TaskCancel", de, false}, {3, "TaskResult", niw, false}},
		[]string{"created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"},
		[][2]string{{"created", "awaiting-input"}, {"created", "awaiting-approval"}, {"awaiting-input", "running"}, {"awaiting-approval", "running"}, {"running", "result"}, {"created", "cancelled"}, {"awaiting-input", "cancelled"}, {"awaiting-approval", "cancelled"}, {"running", "cancelled"}},
		[]string{"TaskStateError", "InputGateBypass", "ApprovalRequired"}},
	{0x0012, "Knowledge", []KindSpec{{0, "Assert", niw, false}, {1, "Retract", de, false}, {2, "KnowledgeQuery", ro, false}},
		[]string{"asserted", "retracted"}, [][2]string{{"asserted", "retracted"}}, []string{"FactUnsigned", "RetractUnknown"}},
	{0x0013, "Spatial", []KindSpec{{0, "FrameDefine", iw, false}, {1, "Pose", ro, false}, {2, "StateUpdate", ro, false}, {3, "SnapshotQuery", ro, false}},
		[]string{"defined", "observed"}, [][2]string{{"defined", "observed"}}, []string{"FrameUnknown", "TransformCycle"}},
}

// Errors reuse the cose.Error type so every N-AALP error carries a stable Kind.
var (
	ErrEffectDeclarationMismatch = &cose.Error{Kind: "EffectDeclarationMismatch", Msg: "object effect does not match the kind's declared effect"}
	ErrStateTransition           = &cose.Error{Kind: "StateTransitionError", Msg: "state transition not permitted by the channel surface"}
	ErrCapExceedsParent          = &cose.Error{Kind: "CapExceedsParent", Msg: "a delegation may not grant more than its parent"}
	ErrTransformCycle            = &cose.Error{Kind: "TransformCycle", Msg: "coordinate frame tree contains a cycle"}
	ErrInputGateBypass           = &cose.Error{Kind: "InputGateBypass", Msg: "a task reached running without passing the input/approval gate"}
	ErrTaskStateError            = &cose.Error{Kind: "TaskStateError", Msg: "workflow task state transition not permitted"}
)

// byID indexes the table by channel id at package init.
var byID = func() map[uint64]*ChannelSpec {
	m := make(map[uint64]*ChannelSpec, len(Table))
	for i := range Table {
		m[Table[i].ID] = &Table[i]
	}
	return m
}()

// Channel returns the spec for a channel id.
func Channel(id uint64) (*ChannelSpec, bool) {
	c, ok := byID[id]
	return c, ok
}

// Lookup returns the kind spec for a (channel, kind) pair.
func Lookup(channel, kind uint64) (KindSpec, bool) {
	c, ok := byID[channel]
	if !ok {
		return KindSpec{}, false
	}
	for _, k := range c.Kinds {
		if k.Code == kind {
			return k, true
		}
	}
	return KindSpec{}, false
}

// KindValidator is the envelope KindValidator built from the frozen registry: it accepts exactly
// the registered (channel, kind) pairs and rejects everything else (envelope fires UnknownKind).
func KindValidator(channel, kind uint64) bool {
	_, ok := Lookup(channel, kind)
	return ok
}

// CheckEffect binds a kind to its declared effect (R-11.2): a fixed-effect kind's object MUST
// carry exactly the declared effect (EffectDeclarationMismatch otherwise); a variable-effect
// kind (Stream StreamOpen, Bridge Carriage) accepts any valid effect (0..3), its authorization
// handled by C5/T9/T11. An unknown (channel, kind) is UnknownKind.
func CheckEffect(channel, kind, effect uint64) error {
	k, ok := Lookup(channel, kind)
	if !ok {
		return &cose.Error{Kind: "UnknownKind", Msg: "kind/channel not in the baseline registry"}
	}
	if k.Variable {
		if effect > uint64(policy.Destructive) {
			return ErrEffectDeclarationMismatch
		}
		return nil
	}
	if effect != uint64(k.Effect) {
		return ErrEffectDeclarationMismatch
	}
	return nil
}

// AllowedTransition reports whether a channel permits a state transition from -> to.
func AllowedTransition(channel uint64, from, to string) bool {
	c, ok := byID[channel]
	if !ok {
		return false
	}
	for _, t := range c.Transitions {
		if t[0] == from && t[1] == to {
			return true
		}
	}
	return false
}

// CheckDelegation enforces Capability's CapExceedsParent (design-channels.md §3): a delegated
// capability's effect ceiling may not exceed its parent's.
func CheckDelegation(parentMax, childMax policy.Effect) error {
	if !parentMax.Authorizes(childMax) { // childMax <= parentMax
		return ErrCapExceedsParent
	}
	return nil
}

// CheckFrameTree enforces Spatial's TransformCycle (design-channels.md §20): the coordinate-frame
// child->parent links must form a tree (acyclic). A frame mapping to "" (or absent) is a root.
func CheckFrameTree(parent map[string]string) error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(parent))
	var visit func(f string) bool
	visit = func(f string) bool {
		color[f] = gray
		p, ok := parent[f]
		if ok && p != "" {
			switch color[p] {
			case gray:
				return true
			case white:
				if visit(p) {
					return true
				}
			}
		}
		color[f] = black
		return false
	}
	for f := range parent {
		if color[f] == white && visit(f) {
			return ErrTransformCycle
		}
	}
	return nil
}

// ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot occur.

// WorkflowGate is a durable, WAL-backed task-status tracker. A task's status is persisted before
// it is acknowledged (spine §9.2), so a crash recovers to the last durable status and can NEVER
// bypass the input/approval gate: reaching "running" requires an explicit input/approval step
// that a crash cannot manufacture.
type WorkflowGate struct {
	mu     sync.Mutex
	f      *os.File
	status map[string]string
}

// OpenWorkflowGate opens (creating if needed) a WAL-backed gate and replays it.
func OpenWorkflowGate(path string) (*WorkflowGate, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	g := &WorkflowGate{f: f, status: make(map[string]string)}
	if err := g.replay(); err != nil {
		f.Close()
		return nil, err
	}
	return g, nil
}

func (g *WorkflowGate) replay() error {
	if _, err := g.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		var lb [4]byte
		if _, err := io.ReadFull(g.f, lb[:]); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		rec := make([]byte, binary.BigEndian.Uint32(lb[:]))
		if _, err := io.ReadFull(g.f, rec); err != nil {
			return err
		}
		nul := -1
		for i, b := range rec {
			if b == 0 {
				nul = i
				break
			}
		}
		if nul < 0 {
			return &cose.Error{Kind: "Malformed", Msg: "workflow gate record"}
		}
		g.status[string(rec[:nul])] = string(rec[nul+1:])
	}
	return nil
}

func (g *WorkflowGate) persist(task, status string) error {
	rec := append(append([]byte(task), 0), status...)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(rec)))
	if _, err := g.f.Write(append(lb[:], rec...)); err != nil {
		return err
	}
	if err := g.f.Sync(); err != nil { // persist-before-ack (spine §9.2)
		return err
	}
	g.status[task] = status
	return nil
}

// Create records a new task in a non-terminal pre-gate status. TaskCreate never lands in
// "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before returning.
func (g *WorkflowGate) Create(task string, needsApproval bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.status[task]; ok {
		return ErrTaskStateError
	}
	if needsApproval {
		return g.persist(task, "awaiting-approval")
	}
	return g.persist(task, "awaiting-input")
}

// SupplyInput advances a task past its input gate (awaiting-input -> input-supplied) or approval
// gate (awaiting-approval -> approved). Only these transitions may precede Run.
func (g *WorkflowGate) SupplyInput(task string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.status[task] {
	case "awaiting-input":
		return g.persist(task, "input-supplied")
	case "awaiting-approval":
		return g.persist(task, "approved")
	default:
		return ErrTaskStateError
	}
}

// Run moves a task to "running" only if it has passed the gate. A task still "awaiting-input" or
// "awaiting-approval" (or unknown) cannot run: that is InputGateBypass, and it is forbidden.
func (g *WorkflowGate) Run(task string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch g.status[task] {
	case "input-supplied", "approved":
		return g.persist(task, "running")
	case "awaiting-input", "awaiting-approval":
		return ErrInputGateBypass
	default:
		return ErrTaskStateError
	}
}

// Status returns a task's durable status.
func (g *WorkflowGate) Status(task string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.status[task]
	return s, ok
}

// Close flushes and closes the WAL.
func (g *WorkflowGate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.f.Close()
}
