// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package channels_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// #277 residual B: channel state-machine safety (design-channels.md §18, Workflow 0x0011).
//
// F3 NON-CIRCULAR AUTHORITY: design-channels.md §18's own prose is the independent
// specification this file checks against, NOT channels.go's switch statements:
//
//	"State: a task is created -> (awaiting-input | awaiting-approval) -> running ->
//	(result | cancelled); a crash recovers to the last durable status (spine §9)."
//	"Errors: TaskStateError, InputGateBypass (forbidden; a crash test proves it cannot occur),
//	ApprovalRequired."
//
// From that prose alone (never from reading WorkflowGate's implementation) three properties
// follow, each checked exhaustively below:
//
//  1. INPUT GATE (the property the spec names explicitly): Run(task) succeeds if and only if
//     the task's current durable status already reflects a passed gate (SupplyInput
//     previously succeeded for it) -- otherwise it is InputGateBypass. This is the property a
//     hostile mutation of the code's own gate check would violate, and #277's crash test names
//     it as "forbidden."
//  2. LINEAR LIFECYCLE (from the arrow-chain "created -> X -> running" appearing once, and a
//     "durable STATUS" model in which a task has exactly one current status): a task may be
//     created only once (a second Create on any known task is rejected); a task may pass the
//     input/approval gate only once (a second SupplyInput on an already-gated task is
//     rejected, not a silent no-op or overwrite); a running task cannot be re-run. These are
//     the ordinary hygiene any state machine matching "created -> X -> running" (a task visits
//     each stage once) must have -- they are NOT pinned to WorkflowGate's exact internal
//     status STRING spelling (this file never asserts against the literal strings
//     "awaiting-input"/"input-supplied"/etc.; it only observes them via the exported Status()
//     accessor to build the table below, and every ASSERTION is phrased over Create/
//     SupplyInput/Run's return values, which is what a caller actually depends on).
//  3. CRASH RECOVERY ("a crash recovers to the last durable status"): reopening a WAL after
//     a crash at ANY point during a write -- not only a clean close, which
//     TestWorkflowInputGateBypass already covers -- must recover exactly the state that was
//     durably (persist()+Sync()'d) established before the crash, and must NEVER refuse to
//     open at all (a #277 finding: the pre-existing implementation raised io.ErrUnexpectedEOF
//     from OpenWorkflowGate on a torn tail record, discarding every prior durable record along
//     with it -- fixed this session, see channels.go's WorkflowGate.replay doc comment).

// ---- 1 & 2: the direct (status x operation) matrix, reached via real API calls only ----

// wfState is a reachable WorkflowGate lifecycle point for task "t1", reached via the listed
// real API call sequence -- never by writing to the WAL file or touching any unexported field.
type wfState struct {
	name string
	// build drives a fresh gate to this state and returns it (t1 in state `name`).
	build func(t *testing.T, g *channels.WorkflowGate)
}

var wfStates = []wfState{
	{"absent", func(t *testing.T, g *channels.WorkflowGate) {}},
	{"awaiting-input (post Create(false))", func(t *testing.T, g *channels.WorkflowGate) {
		mustOK(t, g.Create("t1", false))
	}},
	{"awaiting-approval (post Create(true))", func(t *testing.T, g *channels.WorkflowGate) {
		mustOK(t, g.Create("t1", true))
	}},
	{"input-supplied (post Create(false)+SupplyInput)", func(t *testing.T, g *channels.WorkflowGate) {
		mustOK(t, g.Create("t1", false))
		mustOK(t, g.SupplyInput("t1"))
	}},
	{"approved (post Create(true)+SupplyInput)", func(t *testing.T, g *channels.WorkflowGate) {
		mustOK(t, g.Create("t1", true))
		mustOK(t, g.SupplyInput("t1"))
	}},
	{"running (post ...+Run)", func(t *testing.T, g *channels.WorkflowGate) {
		mustOK(t, g.Create("t1", false))
		mustOK(t, g.SupplyInput("t1"))
		mustOK(t, g.Run("t1"))
	}},
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup step failed: %v", err)
	}
}

func freshGate(t *testing.T) *channels.WorkflowGate {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wf")
	g, err := channels.OpenWorkflowGate(path)
	if err != nil {
		t.Fatalf("OpenWorkflowGate: %v", err)
	}
	t.Cleanup(func() { g.Close() })
	return g
}

// TestWorkflowGateExhaustiveMatrix drives the true Cartesian product of every reachable
// lifecycle status (6, including absent) x every operation (Create(false), Create(true),
// SupplyInput, Run) -- 24 cases, each asserted against design-channels.md §18's prose, never
// against channels.go's own switch-statement literals. A mutation that removes or weakens the
// input-gate check, or that lets a task be re-created / re-supplied / re-run, flips one or more
// of these cells (see the mutation-witness recorded in the #277 build report).
func TestWorkflowGateExhaustiveMatrix(t *testing.T) {
	for _, st := range wfStates {
		st := st
		t.Run("from="+st.name, func(t *testing.T) {
			t.Run("op=Create(false)", func(t *testing.T) {
				g := freshGate(t)
				st.build(t, g)
				err := g.Create("t1", false)
				if st.name == "absent" {
					if err != nil {
						t.Fatalf("Create on a never-created task must succeed, got %v", err)
					}
					if _, ok := g.Status("t1"); !ok {
						t.Fatalf("Create must leave the task with a recorded status")
					}
					return
				}
				// LINEAR LIFECYCLE: a task already known in ANY status may not be re-Created.
				if err == nil {
					t.Fatalf("Create on an already-existing task (%s) must be rejected, was accepted", st.name)
				}
			})
			t.Run("op=Create(true)", func(t *testing.T) {
				g := freshGate(t)
				st.build(t, g)
				err := g.Create("t1", true)
				if st.name == "absent" {
					if err != nil {
						t.Fatalf("Create on a never-created task must succeed, got %v", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("Create on an already-existing task (%s) must be rejected, was accepted", st.name)
				}
			})
			t.Run("op=SupplyInput", func(t *testing.T) {
				g := freshGate(t)
				st.build(t, g)
				err := g.SupplyInput("t1")
				switch st.name {
				case "awaiting-input (post Create(false))", "awaiting-approval (post Create(true))":
					if err != nil {
						t.Fatalf("SupplyInput on a freshly-created pre-gate task must succeed, got %v", err)
					}
				default:
					// absent (nothing to supply for), already-gated, or already-running: a
					// second/out-of-turn SupplyInput must be rejected, never silently accepted.
					if err == nil {
						t.Fatalf("SupplyInput from %s must be rejected, was accepted", st.name)
					}
				}
			})
			t.Run("op=Run", func(t *testing.T) {
				g := freshGate(t)
				st.build(t, g)
				err := g.Run("t1")
				switch st.name {
				case "input-supplied (post Create(false)+SupplyInput)", "approved (post Create(true)+SupplyInput)":
					if err != nil {
						t.Fatalf("Run after a passed gate must succeed, got %v", err)
					}
				case "awaiting-input (post Create(false))", "awaiting-approval (post Create(true))":
					// THE NAMED PROPERTY: running before the gate is InputGateBypass, not any
					// other error and not silent acceptance.
					ce, ok := err.(*cose.Error)
					if !ok || ce.Kind != "InputGateBypass" {
						t.Fatalf("Run before the gate from %s must be InputGateBypass, got %v", st.name, err)
					}
				default:
					// absent (never created) or already running: Run must still be rejected
					// (never succeed a second time, never succeed for nothing), though the
					// specific error name for these two is not pinned by the quoted prose.
					if err == nil {
						t.Fatalf("Run from %s must be rejected, was accepted", st.name)
					}
				}
			})
		})
	}
}

// ---- 3: crash-injection sweep -- exhaustive byte-offset truncation + tail corruption ----

// buildSequenceWAL runs Create(needsApproval)->SupplyInput->Run against a fresh WAL file and
// returns the path plus the exact on-disk byte length after each of the three steps, so the
// truncation sweep below can target every meaningful boundary AND every byte in between.
func buildSequenceWAL(t *testing.T, needsApproval bool) (path string, afterCreate, afterSupply, afterRun int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "wf")
	g, err := channels.OpenWorkflowGate(path)
	if err != nil {
		t.Fatalf("OpenWorkflowGate: %v", err)
	}
	mustOK(t, g.Create("t1", needsApproval))
	afterCreate = fileLen(t, path)
	mustOK(t, g.SupplyInput("t1"))
	afterSupply = fileLen(t, path)
	mustOK(t, g.Run("t1"))
	afterRun = fileLen(t, path)
	mustOK(t, g.Close())
	return
}

func fileLen(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	return fi.Size()
}

// truncateCopy makes a fresh copy of the WAL at path truncated to n bytes, at a NEW path (the
// original full-length file is left untouched so the sweep can reuse it for every offset).
func truncateCopy(t *testing.T, path string, n int64) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n > int64(len(data)) {
		n = int64(len(data))
	}
	dst := filepath.Join(t.TempDir(), "wf-truncated")
	if err := os.WriteFile(dst, data[:n], 0o600); err != nil {
		t.Fatalf("write truncated copy: %v", err)
	}
	return dst
}

// TestWorkflowGateCrashInjectionExhaustive truncates the WAL at EVERY byte offset from 0
// through its full length (a small, genuinely-enumerable file -- tens of bytes) and asserts,
// for each offset, BOTH halves of the crash-recovery property from design-channels.md §18:
//
//  1. OpenWorkflowGate must NEVER return an error, for ANY truncation point (a #277 finding:
//     it used to, for a torn tail record -- see channels.go's replay() doc comment).
//  2. The recovered status must correspond to exactly the LAST FULLY-WRITTEN record at or
//     before that offset, and Run()'s outcome from that recovered status must obey the SAME
//     input-gate property TestWorkflowGateExhaustiveMatrix already pins above: InputGateBypass
//     from a pre-gate recovery, success from a gated recovery, rejection from absent/running.
//
// Run once for needsApproval=false (awaiting-input -> input-supplied -> running) and once for
// needsApproval=true (awaiting-approval -> approved -> running), covering both gate variants.
func TestWorkflowGateCrashInjectionExhaustive(t *testing.T) {
	for _, needsApproval := range []bool{false, true} {
		needsApproval := needsApproval
		t.Run(map[bool]string{false: "input-gate", true: "approval-gate"}[needsApproval], func(t *testing.T) {
			path, afterCreate, afterSupply, afterRun := buildSequenceWAL(t, needsApproval)
			for k := int64(0); k <= afterRun; k++ {
				k := k
				t.Run(offsetLabel(k, afterCreate, afterSupply, afterRun), func(t *testing.T) {
					truncated := truncateCopy(t, path, k)
					g, err := channels.OpenWorkflowGate(truncated)
					if err != nil {
						t.Fatalf("OpenWorkflowGate must never fail on a truncated WAL (offset %d): %v", k, err)
					}
					defer g.Close()

					status, ok := g.Status("t1")
					runErr := g.Run("t1")

					switch {
					case k < afterCreate:
						// The very first record itself is torn or absent: t1 was never durably
						// created.
						if ok {
							t.Fatalf("offset %d (< afterCreate=%d): task should not be known, got status %q", k, afterCreate, status)
						}
						if runErr == nil {
							t.Fatalf("offset %d: Run on a never-durably-created task must be rejected", k)
						}
					case k < afterSupply:
						// The Create record is complete; the SupplyInput record is torn/absent:
						// the durable status is still pre-gate.
						if !ok {
							t.Fatalf("offset %d (afterCreate<=k<afterSupply): expected a recovered pre-gate status", k)
						}
						ce, isCose := runErr.(*cose.Error)
						if !isCose || ce.Kind != "InputGateBypass" {
							t.Fatalf("offset %d: recovered pre-gate status %q must reject Run with InputGateBypass, got %v", k, status, runErr)
						}
					case k < afterRun:
						// SupplyInput's record is complete; Run's record is torn/absent: the
						// durable status already passed the gate, so a (re-)Run must now succeed
						// -- proving the crash did NOT lose the gate-passed acknowledgment.
						if !ok {
							t.Fatalf("offset %d (afterSupply<=k<afterRun): expected a recovered gated status", k)
						}
						if runErr != nil {
							t.Fatalf("offset %d: recovered gated status %q must allow Run to succeed, got %v", k, status, runErr)
						}
					default: // k == afterRun: full recovery, already running
						if !ok || status != "running" {
							t.Fatalf("offset %d (== afterRun): expected recovered status \"running\", got %q (ok=%v)", k, status, ok)
						}
						if runErr == nil {
							t.Fatalf("offset %d: a second Run on an already-running recovered task must be rejected", k)
						}
					}
				})
			}
		})
	}
}

func offsetLabel(k, afterCreate, afterSupply, afterRun int64) string {
	switch {
	case k < afterCreate:
		return "pre-create-complete"
	case k < afterSupply:
		return "pre-supply-complete"
	case k < afterRun:
		return "pre-run-complete"
	default:
		return "full"
	}
}

// TestWorkflowGateTailCorruptionExhaustive complements the truncation sweep: instead of a
// SHORT tail (a torn write), it flips ONE byte within the LAST record's on-disk bytes at
// every possible position, for a full sequence (Create->SupplyInput->Run). Every single-byte
// corruption of the tail record must be caught by the CRC32 checksum this session's fix added
// (channels.go's WorkflowGate.persist/replay) and recovered exactly as if that record were
// simply absent -- OpenWorkflowGate must never error, and the recovered status must be exactly
// the second-to-last durable status (input-supplied), with Run() succeeding from it.
func TestWorkflowGateTailCorruptionExhaustive(t *testing.T) {
	path, _, afterSupply, afterRun := buildSequenceWAL(t, false)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if afterRun <= afterSupply {
		t.Fatalf("test setup invariant violated: afterRun=%d must exceed afterSupply=%d", afterRun, afterSupply)
	}
	for pos := afterSupply; pos < afterRun; pos++ {
		pos := pos
		t.Run("byte_"+offsetLabel(pos, 0, 0, afterRun), func(t *testing.T) {
			corrupted := append([]byte(nil), data...)
			corrupted[pos] ^= 0xFF // flip every bit at this position -- guaranteed to differ
			dst := filepath.Join(t.TempDir(), "wf-corrupt")
			if err := os.WriteFile(dst, corrupted, 0o600); err != nil {
				t.Fatalf("write corrupted copy: %v", err)
			}
			g, err := channels.OpenWorkflowGate(dst)
			if err != nil {
				t.Fatalf("OpenWorkflowGate must never fail on a corrupted tail record (byte %d): %v", pos, err)
			}
			defer g.Close()
			status, ok := g.Status("t1")
			if !ok || status != "input-supplied" {
				t.Fatalf("byte %d corrupted: expected recovery to \"input-supplied\" (the last GOOD record), got %q (ok=%v)", pos, status, ok)
			}
			if err := g.Run("t1"); err != nil {
				t.Fatalf("byte %d corrupted: recovered gated status must allow Run to succeed, got %v", pos, err)
			}
		})
	}
}
