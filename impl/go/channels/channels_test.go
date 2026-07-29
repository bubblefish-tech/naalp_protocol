// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package channels_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bubblefish-tech/n-aalp/impl/go/cbor"
	"github.com/bubblefish-tech/n-aalp/impl/go/channels"
	"github.com/bubblefish-tech/n-aalp/impl/go/cose"
	"github.com/bubblefish-tech/n-aalp/impl/go/envelope"
	"github.com/bubblefish-tech/n-aalp/impl/go/policy"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type channelCase struct {
	ChannelID uint64 `json:"channel_id"`
	Name      string `json:"name"`
	Kinds     []struct {
		Code     uint64 `json:"code"`
		Name     string `json:"name"`
		Effect   uint64 `json:"effect"`
		Variable bool   `json:"variable"`
	} `json:"kinds"`
	States      []string `json:"states"`
	Transitions []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"transitions"`
	Errors []string `json:"errors"`
}

func loadChannel(t *testing.T, dir string) channelCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(filepath.Join("../../../vectors/channels", dir, "cases.json")))
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var c channelCase
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	return c
}

// TestTableMatchesOracle: the frozen impl registry equals the independent per-channel oracle, in
// both directions (⟹ Go == Rust, which grades the same vectors).
func TestTableMatchesOracle(t *testing.T) {
	if len(channels.Table) != 20 {
		t.Fatalf("table has %d channels, want 20", len(channels.Table))
	}
	for _, ch := range channels.Table {
		c := loadChannel(t, strings.ToLower(ch.Name))
		if c.ChannelID != ch.ID || c.Name != ch.Name {
			t.Errorf("%s: id/name %#x/%s vs %#x/%s", ch.Name, c.ChannelID, c.Name, ch.ID, ch.Name)
		}
		if len(c.Kinds) != len(ch.Kinds) {
			t.Fatalf("%s: %d kinds vs oracle %d", ch.Name, len(ch.Kinds), len(c.Kinds))
		}
		for i, k := range ch.Kinds {
			o := c.Kinds[i]
			if k.Code != o.Code || k.Name != o.Name || uint64(k.Effect) != o.Effect || k.Variable != o.Variable {
				t.Errorf("%s kind %d: {%d,%s,%d,%v} vs oracle {%d,%s,%d,%v}", ch.Name, i, k.Code, k.Name, k.Effect, k.Variable, o.Code, o.Name, o.Effect, o.Variable)
			}
		}
		if len(c.Transitions) != len(ch.Transitions) {
			t.Fatalf("%s: %d transitions vs oracle %d", ch.Name, len(ch.Transitions), len(c.Transitions))
		}
		for i, tr := range ch.Transitions {
			if tr[0] != c.Transitions[i].From || tr[1] != c.Transitions[i].To {
				t.Errorf("%s transition %d differs", ch.Name, i)
			}
		}
		if strings.Join(c.States, ",") != strings.Join(ch.States, ",") {
			t.Errorf("%s states differ: %v vs %v", ch.Name, ch.States, c.States)
		}
		if strings.Join(c.Errors, ",") != strings.Join(ch.Errors, ",") {
			t.Errorf("%s errors differ: %v vs %v", ch.Name, ch.Errors, c.Errors)
		}
	}
}

// TestCompleteness: all twenty channels are present with ids 0..19, none thinned — every channel
// has at least one kind, and every kind a valid declared effect (R-11.1/R-11.2).
func TestCompleteness(t *testing.T) {
	seen := map[uint64]bool{}
	for _, ch := range channels.Table {
		if len(ch.Kinds) == 0 {
			t.Errorf("%s has no kinds (thinned surface)", ch.Name)
		}
		for _, k := range ch.Kinds {
			if k.Effect > policy.Destructive {
				t.Errorf("%s.%s has invalid effect %d", ch.Name, k.Name, k.Effect)
			}
		}
		seen[ch.ID] = true
	}
	for id := uint64(0); id <= 0x0013; id++ {
		if !seen[id] {
			t.Errorf("channel %#x missing", id)
		}
	}
}

func testSigner(t *testing.T, b byte) (cose.MLDSA65Signer, cose.MLDSA65Verifier, []byte) {
	t.Helper()
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return cose.MLDSA65Signer{SK: sk}, cose.MLDSA65Verifier{PK: pk}, pk.Bytes()
}

// TestSurfaceOverSpine: R-11.3 — one object per channel, on a registered kind carrying that
// kind's declared effect, signs and verifies end-to-end through the spine with the surface's
// KindValidator. This demonstrates all twenty surfaces are thin bodies over the one spine.
func TestSurfaceOverSpine(t *testing.T) {
	signer, verifier, pkb := testSigner(t, 90)
	for _, ch := range channels.Table {
		k := ch.Kinds[0]
		eff := uint64(k.Effect)
		obj := &envelope.Object{Kind: k.Code, Channel: ch.ID, Tier: 0, Signer: pkb, Created: 100, Effect: eff, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0)}
		signed, err := envelope.Sign(obj, signer)
		if err != nil {
			t.Fatalf("%s sign: %v", ch.Name, err)
		}
		if _, err := envelope.Verify(cose.ProfilePublic, verifier, channels.KindValidator, nil, signed); err != nil {
			t.Fatalf("%s: object does not verify over the spine: %v", ch.Name, err)
		}
		// The surface effect binding accepts the declared effect and rejects a wrong one.
		if err := channels.CheckEffect(ch.ID, k.Code, eff); err != nil {
			t.Errorf("%s.%s: declared effect rejected: %v", ch.Name, k.Name, err)
		}
		if !k.Variable {
			wrong := (eff + 1) % 4
			if err := channels.CheckEffect(ch.ID, k.Code, wrong); err == nil {
				t.Errorf("%s.%s: wrong effect %d accepted", ch.Name, k.Name, wrong)
			}
		}
	}
	// An unknown kind is rejected by the validator (envelope fires UnknownKind).
	if channels.KindValidator(0x0000, 99) {
		t.Fatal("unknown kind accepted by validator")
	}
	obj := &envelope.Object{Kind: 99, Channel: 0, Tier: 0, Signer: pkb, Created: 100, Effect: 0, Profile: uint64(cose.ProfilePublic), Body: cbor.Uint(0)}
	signed, _ := envelope.Sign(obj, signer)
	if _, err := envelope.Verify(cose.ProfilePublic, verifier, channels.KindValidator, nil, signed); err == nil {
		t.Fatal("object with unknown kind verified")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "UnknownKind" {
		t.Fatalf("want UnknownKind, got %v", err)
	}
}

// TestStateMachine: representative channels permit their declared transitions and reject others.
func TestStateMachine(t *testing.T) {
	cases := []struct {
		ch       uint64
		from, to string
		ok       bool
	}{
		{0x0001, "offered", "accepted", true},   // Memory
		{0x0001, "live", "revoked", true},        // Memory
		{0x0001, "revoked", "live", false},        // Memory regression
		{0x000E, "order", "fulfil", true},         // Commerce
		{0x000E, "offer", "fulfil", false},        // Commerce skip
		{0x0011, "awaiting-input", "running", true}, // Workflow
		{0x0011, "created", "running", false},      // Workflow gate skip
	}
	for _, c := range cases {
		if got := channels.AllowedTransition(c.ch, c.from, c.to); got != c.ok {
			t.Errorf("channel %#x %s->%s allowed=%v want %v", c.ch, c.from, c.to, got, c.ok)
		}
	}
}

// TestCapExceedsParent: Capability's named error fires when a delegation exceeds its parent.
func TestCapExceedsParent(t *testing.T) {
	if err := channels.CheckDelegation(policy.NonIdempotentWrite, policy.ReadOnly); err != nil {
		t.Errorf("valid attenuation rejected: %v", err)
	}
	if err := channels.CheckDelegation(policy.NonIdempotentWrite, policy.Destructive); err == nil {
		t.Fatal("over-broad delegation accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "CapExceedsParent" {
		t.Fatalf("want CapExceedsParent, got %v", err)
	}
}

// TestTransformCycle: Spatial's named error fires on a cyclic coordinate-frame tree.
func TestTransformCycle(t *testing.T) {
	tree := map[string]string{"base": "", "arm": "base", "hand": "arm"}
	if err := channels.CheckFrameTree(tree); err != nil {
		t.Errorf("valid frame tree rejected: %v", err)
	}
	cyclic := map[string]string{"a": "b", "b": "c", "c": "a"}
	if err := channels.CheckFrameTree(cyclic); err == nil {
		t.Fatal("cyclic frame tree accepted")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "TransformCycle" {
		t.Fatalf("want TransformCycle, got %v", err)
	}
}

// TestWorkflowInputGateBypass: the gated crash test (design-channels.md §18) — a task cannot
// reach "running" without passing the input/approval gate, and a crash (close→reopen) recovers
// to the pre-gate status rather than bypassing it.
func TestWorkflowInputGateBypass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wf")
	g, err := channels.OpenWorkflowGate(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Create("t1", false); err != nil {
		t.Fatal(err)
	}
	// Running before input is InputGateBypass.
	if err := g.Run("t1"); err == nil {
		t.Fatal("task ran before its input gate")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "InputGateBypass" {
		t.Fatalf("want InputGateBypass, got %v", err)
	}
	// Simulate a crash right after Create: the durable status is still the pre-gate status.
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g2, err := channels.OpenWorkflowGate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	if s, _ := g2.Status("t1"); s != "awaiting-input" {
		t.Fatalf("crash bypassed the gate: recovered status %q", s)
	}
	if err := g2.Run("t1"); err == nil {
		t.Fatal("task ran after crash without passing the gate")
	} else if ce, ok := err.(*cose.Error); !ok || ce.Kind != "InputGateBypass" {
		t.Fatalf("want InputGateBypass after crash, got %v", err)
	}
	// Supplying input opens the gate; only then may it run.
	if err := g2.SupplyInput("t1"); err != nil {
		t.Fatal(err)
	}
	if err := g2.Run("t1"); err != nil {
		t.Fatalf("task did not run after input: %v", err)
	}
	if s, _ := g2.Status("t1"); s != "running" {
		t.Fatalf("status after run %q, want running", s)
	}
}
