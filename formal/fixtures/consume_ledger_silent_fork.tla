---- MODULE consume_ledger_silent_fork ----
\* Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
\*
\* MUTATION-WITNESS FIXTURE for formal/consume_ledger.tla and
\* scripts/gates/gate_formal_consume_ledger.py's self-test.
\*
\* THIS FILE DOES NOT DESCRIBE REAL CODE. It is a deliberately-broken COPY of
\* formal/consume_ledger.tla, used only to prove the gate (and, manually, the model itself) is
\* actually sensitive to a silently-accepted double spend -- per the test-driven-development
\* discipline "a check that has never been observed failing is not known to be a check"
\* (rules/test-driven-development.md) and the gate framework's own rule that every gate ships a
\* fixture that MUST make it fail (scripts/gates/_gate.py). Mirrors
\* formal/fixtures/monotone_attenuation_widening.tla's approach exactly: one deliberate mutation,
\* every other operator byte-for-byte identical (parameterized only by this file's own smaller N).
\*
\* THE ONE DELIBERATE MUTATION: `ConsumeA`/`ConsumeB` below DROP the fork-flagging branch of
\* design.md SS7.5 entirely -- they still enforce the first-append-wins CAS (exactly-once per
\* side is UNCHANGED and still holds) and the consistent-signer guard, but a genuine cross-side
\* conflict for the same approval id is never appended to `forkLog` -- simulating a ReceiptSet
\* that forgot to call Observe, or an Observe that forgot to compare against the opposing side --
\* i.e. exactly the bug this proof exists to rule out (a real double spend that completes
\* silently, with NO fork evidence a third party could ever re-verify). `Init`, `Inv`, `IndInit`,
\* `CInit`, and every helper (`HasConsumed`, `RecordFor`, `IsFlagged`, `SameReceipt`,
\* `UniqueA`/`B`, `ConsistentKeyA`/`B`, `ForkLogNoDup`, `ForkLogSound`, `NoSilentFork`) are
\* BYTE-FOR-BYTE IDENTICAL to formal/consume_ledger.tla: the property being checked (Inv) is not
\* touched, only the per-transition ENFORCEMENT (Next's fork-flagging branch) is weakened. The
\* inductive-step check (`Inv /\ Next => Inv'`) is expected to flip from NoError to a
\* counterexample, because Next can now construct a second-side record that conflicts with an
\* existing opposing-side record for the same approval id without ever setting forkLog -- an edge
\* the (unchanged) Inv's NoSilentFork clause forbids.

EXTENDS Integers, Sequences, FiniteSets, Apalache

\* @typeAlias: recordT = { approvalId: Int, ledgerKey: Int, position: Int };
typedefs == TRUE

\* N is DELIBERATELY SMALLER here than in formal/consume_ledger.tla (N=3). This fixture exists
\* only to prove the gate's inductive-step check is sensitive to the injected fault (the dropped
\* fork-flagging branch below), NOT to carry the unbounded guarantee itself -- that is the real
\* model's job, at its own N. A silent-fork counterexample needs only ONE pre-existing record on
\* one side (the arbitrary IndInit predecessor) plus ONE new conflicting record Next appends on
\* the other side, so N=1 is large enough for Apalache's counterexample search to find it (Gen(1)
\* still allows length 0 or 1, matching formal/monotone_attenuation_widening.tla's own smaller-N
\* rationale), and searching a slot-count-1 predecessor space per side is faster than N=3's.
N == 1

CONSTANTS
    \* @type: Seq($recordT);
    ledgerA0,
    \* @type: Seq($recordT);
    ledgerB0,
    \* @type: Seq(Int);
    forkLog0

VARIABLES
    \* @type: Seq($recordT);
    ledgerA,
    \* @type: Seq($recordT);
    ledgerB,
    \* @type: Seq(Int);
    forkLog

Init ==
    /\ ledgerA = <<>>
    /\ ledgerB = <<>>
    /\ forkLog = <<>>

\* @type: (Seq($recordT), Int) => Bool;
HasConsumed(ledger, aid) == \E i \in DOMAIN ledger : ledger[i].approvalId = aid
\* @type: (Seq($recordT), Int) => $recordT;
RecordFor(ledger, aid) == CHOOSE r \in {ledger[i] : i \in DOMAIN ledger} : r.approvalId = aid
\* @type: (Int) => Bool;
IsFlagged(aid) == \E i \in DOMAIN forkLog : forkLog[i] = aid
\* @type: ($recordT, $recordT) => Bool;
SameReceipt(r1, r2) == r1.ledgerKey = r2.ledgerKey /\ r1.position = r2.position

\* ------------------------------------------------------------------------------------------
\* MUTATION: the fork-flagging branch of design.md SS7.5 is DROPPED here. First-append-wins
\* (the `~HasConsumed` guard) and the consistent-signer guard both survive unchanged -- only the
\* "mint forkLog on a genuine cross-side conflict" reaction is removed.
\* ------------------------------------------------------------------------------------------
\* @type: (Int, Int) => Bool;
ConsumeA(aid, lk) ==
    /\ ~HasConsumed(ledgerA, aid)
    /\ \A i \in DOMAIN ledgerA : ledgerA[i].ledgerKey = lk
    /\ LET \* @type: $recordT;
           rec == [approvalId |-> aid, ledgerKey |-> lk, position |-> Len(ledgerA)]
       IN /\ ledgerA' = Append(ledgerA, rec)
          /\ UNCHANGED forkLog          \* (the real model's fork-flagging IF/THEN is absent)
    /\ UNCHANGED ledgerB

\* @type: (Int, Int) => Bool;
ConsumeB(aid, lk) ==
    /\ ~HasConsumed(ledgerB, aid)
    /\ \A i \in DOMAIN ledgerB : ledgerB[i].ledgerKey = lk
    /\ LET \* @type: $recordT;
           rec == [approvalId |-> aid, ledgerKey |-> lk, position |-> Len(ledgerB)]
       IN /\ ledgerB' = Append(ledgerB, rec)
          /\ UNCHANGED forkLog          \* (the real model's fork-flagging IF/THEN is absent)
    /\ UNCHANGED ledgerA

Next ==
    \/ \E aid \in Nat, lk \in Nat : ConsumeA(aid, lk)
    \/ \E aid \in Nat, lk \in Nat : ConsumeB(aid, lk)

\* ---- UNCHANGED IN STRUCTURE from formal/consume_ledger.tla below this line: the same Inv,
\* IndInit, CInit, and every consistency clause, each parameterized by THIS FILE's own N=1 (not
\* the real model's N=3). Every operator's TEXT is identical to the real model's EXCEPT for (a)
\* the N constant itself and (b) Next's two fork-flagging branches above, which are the one
\* deliberate mutation this fixture exists to inject. ------------------------------------------

UniqueA == \A i, j \in DOMAIN ledgerA : ledgerA[i].approvalId = ledgerA[j].approvalId => i = j
UniqueB == \A i, j \in DOMAIN ledgerB : ledgerB[i].approvalId = ledgerB[j].approvalId => i = j

ConsistentKeyA == \A i, j \in DOMAIN ledgerA : ledgerA[i].ledgerKey = ledgerA[j].ledgerKey
ConsistentKeyB == \A i, j \in DOMAIN ledgerB : ledgerB[i].ledgerKey = ledgerB[j].ledgerKey

ForkLogNoDup == \A i, j \in DOMAIN forkLog : forkLog[i] = forkLog[j] => i = j

ForkLogSound ==
    \A i \in DOMAIN forkLog :
        LET aid == forkLog[i]
        IN /\ HasConsumed(ledgerA, aid)
           /\ HasConsumed(ledgerB, aid)
           /\ ~SameReceipt(RecordFor(ledgerA, aid), RecordFor(ledgerB, aid))

Consistency ==
    /\ UniqueA /\ UniqueB
    /\ ConsistentKeyA /\ ConsistentKeyB
    /\ ForkLogNoDup
    /\ ForkLogSound

\* See formal/consume_ledger.tla's NoSilentFork comment: quantifies over the FINITE set of
\* approval ids present in ledgerA, not the infinite Nat (Apalache cannot expand a `\A` over an
\* infinite set) -- logically equivalent since the antecedent is vacuously false for any aid
\* outside ledgerA.
NoSilentFork ==
    \A aid \in {ledgerA[i].approvalId : i \in DOMAIN ledgerA} :
        (/\ HasConsumed(ledgerB, aid)
         /\ ~SameReceipt(RecordFor(ledgerA, aid), RecordFor(ledgerB, aid)))
        => IsFlagged(aid)

Inv == Consistency /\ NoSilentFork

\* NoForkedPredecessor is defined here for STRUCTURAL parity with formal/consume_ledger.tla --
\* gate_formal_consume_ledger.py does NOT run the non-vacuity leg against this fixture (same
\* reasoning as formal/fixtures/monotone_attenuation_widening.tla's own NoMultiHop comment: this
\* fixture's smaller N is sized only for the one deliberate mutation's counterexample, not for
\* carrying an independent non-vacuity argument, and running it here would manufacture a spurious
\* self-test failure unrelated to what this fixture exists to prove).
NoForkedPredecessor == forkLog = <<>>

RecordSet == [approvalId: Nat, ledgerKey: Nat, position: Nat]

CInit ==
    /\ ledgerA0 = Gen(N)
    /\ \A i \in DOMAIN ledgerA0 : ledgerA0[i] \in RecordSet
    /\ ledgerB0 = Gen(N)
    /\ \A i \in DOMAIN ledgerB0 : ledgerB0[i] \in RecordSet
    /\ forkLog0 = Gen(N)
    /\ \A i \in DOMAIN forkLog0 : forkLog0[i] \in Nat

IndInit ==
    /\ ledgerA = ledgerA0
    /\ ledgerB = ledgerB0
    /\ forkLog = forkLog0
    /\ Inv

====
