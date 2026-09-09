---- MODULE consume_ledger ----
\* Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
\*
\* UNBOUNDED (inductive-invariant) TLA+ model of the N-AALP §7 consume ledger's EXACTLY-ONCE
\* compare-and-set plus the draft-01 §7.5 consume-receipt fork-evidence contradiction, checked
\* with Apalache v0.62.2+ using the SAME technique and the SAME toolchain/idiom choices as
\* formal/monotone_attenuation.tla (that file's header explains the Apalache-specific reasoning
\* -- Gen(N) for unbounded sequences, DOMAIN over Len(_)-bounded ranges, etc. -- in full; this
\* header states only what differs for THIS property).
\*
\* NORMATIVE SOURCE (transcribed from design.md/requirements.md/impl text, never re-derived):
\*   - design.md SS7.2: "Consume is an atomic compare-and-set: the first consumer that appends
\*     ... wins; a second append for the same approval id is rejected (AlreadyConsumed)." (R-7.2)
\*   - design.md SS7.5 (draft-01, NAALP-REQ-121): the ledger-signed consume receipt
\*     { ledger, approval_id, position }, "minted by the same first-append-wins compare-and-set
\*     as SS7.2"; "a partition that spends one approval twice leaves two ledger-signed receipts
\*     against one approval id ... the two receipts contradict on comparison ... surfaced as
\*     fork evidence"; "Two receipts naming the same approval id that are byte-identical are a
\*     benign duplicate, not a fork."
\*   - impl/go/approval/approval.go: Ledger.Consume / LedgerSigned.ConsumeWithReceipt
\*     (first-append-wins CAS), ReceiptSet.Observe (fork classification: byte-identical ->
\*     (nil,nil); differs -> ConsumeForkEvidence + ErrConsumeFork), ConsumeForkEvidence.Verify.
\*   - impl/go/approval/approval_test.go: TestExactlyOnceUnderRace / TestConsumeFirstAppendWinsCAS
\*     / TestConsumeReceiptExactlyOnceUnderRace exercise ONE fixed interleaving (N=64 goroutines,
\*     ONE approval id, ONE ledger). This model generalizes that to an ARBITRARILY long history,
\*     an ARBITRARY interleaving, MANY distinct approval ids, and -- for the fork property -- TWO
\*     independent ledger partitions (the scenario Go's single-process tests cannot exercise at
\*     all, since it requires two genuinely independent stores).
\*
\* WHY A TRANSITION SYSTEM, NOT A STATIC RELATIONAL MODEL: same rationale as
\* formal/monotone_attenuation.tla -- the inductive-invariant technique (Init=>Inv,
\* Inv/\Next=>Inv') proves the two properties below for a consume history of ANY length, not
\* merely the bounded N=64-single-interleaving the Go race tests exercise.
\*
\* MODELING CHOICES:
\*
\* (1) TWO INDEPENDENT LEDGER SIDES AS GROWING SEQUENCES. `ledgerA`/`ledgerB` are APPEND-ONLY
\*     sequences of consume records, one per partition/replica. A record's "id" is simply its
\*     1-based position in ITS OWN side's sequence (matching approval.go's `e.Seq` /
\*     `r1.Position`, the ledger's own forward-only append count -- the first-ever consume on a
\*     fresh ledger gets position 0, per TestConsumeFirstAppendWinsCAS). This directly mirrors
\*     formal/monotone_attenuation.tla's header note (1) (Seq, not an id-keyed function over an
\*     infinite domain -- the same Apalache limitation applies here and the same Gen(N) workaround
\*     is used for IndInit below).
\*
\* (2) "SAME-LEDGER FORK" VS "CROSS-LEDGER DOUBLE SPEND" AS ONE UNIFIED MODEL. design.md SS7.5
\*     names two failure shapes: the SAME ledger key forking across a partition (both sides sign
\*     with the same key), or two genuinely DISTINCT ledgers each holding a receipt for one
\*     single-use approval. Rather than modeling these as two separate specs, each side's records
\*     all share ONE `ledgerKey` value (a consistent-signer discipline enforced as BOTH a guard on
\*     Next -- a real ledger does not change its own signing identity mid-run -- and an invariant
\*     conjunct IndInit's arbitrary predecessor must also satisfy), and that value is left FULLY
\*     SYMBOLIC (an unbounded Int, never fixed or enumerated) with NO constraint that ledgerA's key
\*     differs from ledgerB's. The two named scenarios are exactly the two cases of this one
\*     symbolic value: equal (same-ledger fork) or unequal (cross-ledger double spend) -- the
\*     model proves the fork-evidence property for BOTH simultaneously, since neither case is
\*     privileged in the state space Apalache searches.
\*
\* (3) THE OBSERVER'S COMPARISON IS ATOMIC WITH THE SECOND SIDE'S CONSUME. impl/go/approval.go's
\*     ReceiptSet.Observe is invoked by a caller at a time of the caller's choosing (whenever a
\*     receipt is presented for verification) -- it is not automatically broadcast. This model
\*     abstracts "a receipt was presented for observation" as happening in the SAME atomic step as
\*     the second side's own consume (the strongest -- earliest possible -- observation schedule),
\*     which is a conservative sequential idealization consistent with how every OTHER per-hop
\*     check in this build's formal models is made atomic with its triggering action (see
\*     formal/monotone_attenuation.tla's header note (3) for the same idealization applied to
\*     ghost-state maintenance). What this idealization does NOT cover: a real deployment where
\*     observation is deferred or never performed at all -- that is a named, NOT machine-checked,
\*     residual (see the honest-scope note in scripts/gates/gate_formal_consume_ledger.py).
\*
\* HONEST SCOPE (read before citing this model anywhere): the two proof obligations below
\* establish an INDUCTIVE BASIS over predecessor histories of at most N=3 records per side (plus
\* up to N=3 already-flagged forks), with every FIELD (approval id, ledger key, position) left
\* fully symbolic/unbounded -- i.e. a real theorem about every reachable two-sided consume history
\* built from predecessors of that shape, NOT an exhaustive bounded search over enumerated field
\* values. Exactly as formal/monotone_attenuation.tla documents for its own N, extending this
\* basis to an ARBITRARILY long two-sided history rests on the SAME kind of LOCALITY argument
\* (each transition's obligation -- "does this one new record correctly (dis)agree with the one
\* opposing-side record already present for the same approval id" -- depends only on that single
\* pair of records, never on the rest of either history) made once in prose here, NOT re-derived
\* by Apalache. This is the pen-and-paper, NOT machine-checked, residual. Cite this model as: "a
\* machine-verified inductive basis over predecessor histories of <=3 records per side with
\* unbounded fields, plus a documented but not machine-checked locality argument extending it to
\* histories of arbitrary length" -- never as "an unbounded guarantee over history length,
\* machine-checked."
\*
\* A SEPARATE, NAMED, NOT-MODELED RESIDUAL (the "coincidental byte-identical collision"): design.md
\* SS7.5 defines a fork as two receipts that are NOT byte-identical; a byte-identical pair is
\* explicitly "a benign duplicate, not a fork." This model faithfully encodes that literal
\* definition (see NoSilentFork below, which only requires flagging when SameReceipt is FALSE) --
\* it does not attempt to prove, and design.md does not claim, that two INDEPENDENTLY-issued
\* consumes on a same-ledger-key fork can never coincidentally land on the identical position (a
\* real coincidence would require BOTH sides to have appended the exact same COUNT of unrelated
\* records before this one, since position = the side's own append count). Whether that coincidence
\* is negligible in practice is a pen-and-paper argument about real-world WAL divergence after a
\* partition, not something this model decides either way; it is named here so the gap is visible,
\* not silently assumed away.

EXTENDS Integers, Sequences, FiniteSets, Apalache

\* ---- typedefs ---------------------------------------------------------------------------------
\* @typeAlias: recordT = { approvalId: Int, ledgerKey: Int, position: Int };
typedefs == TRUE

\* CInit's bound on the arbitrary IndInit predecessor's per-side record count (and the flagged-
\* fork log's length). N=3 mirrors formal/monotone_attenuation.tla's own N (empirically, the
\* smallest bound that still lets the inductive-step search finish quickly while giving headroom
\* beyond the single-record-per-side minimum the counterexample shape below actually needs).
N == 3

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

\* ---- helpers, over DOMAIN (never 1..Len(_) -- Apalache requires a CONSTANT bound for `a..b`,
\* and Len(ledgerA) is symbolic; DOMAIN avoids this, matching formal/monotone_attenuation.tla). ---

\* @type: (Seq($recordT), Int) => Bool;
HasConsumed(ledger, aid) == \E i \in DOMAIN ledger : ledger[i].approvalId = aid

\* Well-defined only where HasConsumed(ledger, aid) holds AND UniqueA/UniqueB (below) has already
\* forced at most one matching record -- exactly the same CHOOSE-over-a-provably-singleton-set
\* pattern this build's other formal models rely on.
\* @type: (Seq($recordT), Int) => $recordT;
RecordFor(ledger, aid) == CHOOSE r \in {ledger[i] : i \in DOMAIN ledger} : r.approvalId = aid

\* @type: (Int) => Bool;
IsFlagged(aid) == \E i \in DOMAIN forkLog : forkLog[i] = aid

\* "Byte-identical" per design.md SS7.5: same approval id (already the lookup key), same ledger
\* key, same position -- the full receipt is { ledger, approval_id, position }.
\* @type: ($recordT, $recordT) => Bool;
SameReceipt(r1, r2) == r1.ledgerKey = r2.ledgerKey /\ r1.position = r2.position

\* ---- the two ways Next can extend the state -----------------------------------------------
\* Each is gated by design.md SS7.2's first-append-wins CAS (the `~HasConsumed` guard) plus a
\* consistent-signer guard (a real ledger's signing identity does not change mid-run -- see
\* header note (2)), and mints fork evidence atomically the moment a genuine cross-side conflict
\* for the same approval id is created (header note (3)).

\* @type: (Int, Int) => Bool;
ConsumeA(aid, lk) ==
    /\ ~HasConsumed(ledgerA, aid)                                    \* first-append-wins CAS
    /\ \A i \in DOMAIN ledgerA : ledgerA[i].ledgerKey = lk            \* consistent signer identity
    /\ LET \* @type: $recordT;
           rec == [approvalId |-> aid, ledgerKey |-> lk, position |-> Len(ledgerA)]
       IN /\ ledgerA' = Append(ledgerA, rec)
          /\ IF /\ HasConsumed(ledgerB, aid)
                /\ ~SameReceipt(rec, RecordFor(ledgerB, aid))
                /\ ~IsFlagged(aid)
             THEN forkLog' = Append(forkLog, aid)
             ELSE UNCHANGED forkLog
    /\ UNCHANGED ledgerB

\* @type: (Int, Int) => Bool;
ConsumeB(aid, lk) ==
    /\ ~HasConsumed(ledgerB, aid)
    /\ \A i \in DOMAIN ledgerB : ledgerB[i].ledgerKey = lk
    /\ LET \* @type: $recordT;
           rec == [approvalId |-> aid, ledgerKey |-> lk, position |-> Len(ledgerB)]
       IN /\ ledgerB' = Append(ledgerB, rec)
          /\ IF /\ HasConsumed(ledgerA, aid)
                /\ ~SameReceipt(rec, RecordFor(ledgerA, aid))
                /\ ~IsFlagged(aid)
             THEN forkLog' = Append(forkLog, aid)
             ELSE UNCHANGED forkLog
    /\ UNCHANGED ledgerA

Next ==
    \/ \E aid \in Nat, lk \in Nat : ConsumeA(aid, lk)
    \/ \E aid \in Nat, lk \in Nat : ConsumeB(aid, lk)

\* ================================================================================================
\* Inv: structural consistency (each side's log obeys first-append-wins-once and one signer
\* identity, and the fork log records real, non-duplicated conflicts) CONJOINED WITH the two
\* C-DEL/R-7.2/R-7.5-family clauses:
\*   EXACTLY-ONCE  : UniqueA, UniqueB (a second successful consume for one approval id, on one
\*                   side, never happens -- generalizes TestExactlyOnceUnderRace /
\*                   TestConsumeFirstAppendWinsCAS beyond their fixed N=64/one-ledger/one-id case).
\*   NO SILENT FORK: NoSilentFork -- whenever both sides have genuinely-different receipts for the
\*                   same approval id, that id is in forkLog (design.md SS7.5's core guarantee:
\*                   the contradiction is detectable, never silently accepted as two independent
\*                   valid consumes).
\* ================================================================================================

UniqueA == \A i, j \in DOMAIN ledgerA : ledgerA[i].approvalId = ledgerA[j].approvalId => i = j
UniqueB == \A i, j \in DOMAIN ledgerB : ledgerB[i].approvalId = ledgerB[j].approvalId => i = j

ConsistentKeyA == \A i, j \in DOMAIN ledgerA : ledgerA[i].ledgerKey = ledgerA[j].ledgerKey
ConsistentKeyB == \A i, j \in DOMAIN ledgerB : ledgerB[i].ledgerKey = ledgerB[j].ledgerKey

\* ForkLogNoDup: an approval id is flagged at most once (matches ReceiptSet.Observe's `~IsFlagged`
\* guard -- a re-observed, already-flagged conflict does not mint a second fork-evidence record).
ForkLogNoDup == \A i, j \in DOMAIN forkLog : forkLog[i] = forkLog[j] => i = j

\* ForkLogSound: nothing in forkLog is a false positive -- every flagged id genuinely has two
\* present, non-identical receipts (the converse of NoSilentFork; together they say forkLog is
\* EXACTLY the set of genuine cross-side conflicts, neither over- nor under-reporting).
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

\* NoSilentFork: THE core fork-evidence-non-silence property. Whenever an approval id has been
\* consumed on BOTH sides with a receipt that is NOT byte-identical (SameReceipt false -- i.e. a
\* genuine cross-side double spend, same-ledger-fork or cross-ledger, per header note (2)), that
\* id MUST already be in forkLog. There is no reachable state where a genuine two-sided conflict
\* exists unflagged -- design.md SS7.5's "the contradiction is surfaced ... so any third party
\* re-verifies it ... with no further evidence," never "silently accepted as two independent valid
\* consumes." (The one named exception -- a byte-identical coincidental collision -- is, per
\* design.md's own definition, not a fork at all; see the module header's residual note.)
\* Quantifies aid over the FINITE set of approval ids present in ledgerA -- not the infinite Nat
\* -- which Apalache's bounded model checker cannot expand a `\A` over directly (confirmed
\* empirically this session: "Expansion of InfSet[CellTFrom(Int)] is not supported"). This is
\* logically equivalent to quantifying over all of Nat: the antecedent below is false (vacuously
\* satisfying the implication) for any aid not present in ledgerA, since `HasConsumed(ledgerA,
\* aid)` is its first conjunct -- so narrowing the OUTER quantifier's range to exactly the ids
\* that could ever make the antecedent true loses no case. `\A` over DOMAIN/a derived finite set
\* is exactly the same pattern formal/monotone_attenuation.tla's own Inv already uses (DOMAIN
\* grants, DOMAIN actions -- never `\A x \in Nat`).
NoSilentFork ==
    \A aid \in {ledgerA[i].approvalId : i \in DOMAIN ledgerA} :
        (/\ HasConsumed(ledgerB, aid)
         /\ ~SameReceipt(RecordFor(ledgerA, aid), RecordFor(ledgerB, aid)))
        => IsFlagged(aid)

Inv == Consistency /\ NoSilentFork

\* NoForkedPredecessor: the NON-VACUITY sanity invariant (gate_formal_consume_ledger.py's third,
\* "nonvacuous" leg -- mirrors formal/monotone_attenuation.tla's NoMultiHop exactly). Asserts NO
\* predecessor state in the CInit/IndInit-generated space has ANY flagged fork at all. Apalache is
\* REQUIRED to find a COUNTEREXAMPLE (a generated predecessor with forkLog # <<>>): that
\* counterexample is the positive witness that the space base/inductive reason over genuinely
\* contains a state with a real, already-recorded cross-side conflict -- not merely trivial
\* always-empty ledgers. If Apalache instead reports NoError, the inductive result above would be
\* proving something true only because it never had to reason about a state with a real fork
\* already present.
NoForkedPredecessor == forkLog = <<>>

\* ================================================================================================
\* IndInit: an "arbitrary state satisfying Inv", made assignment-compatible via Gen(N) (Apalache's
\* `--init` requires each variable to be assigned via `=` or `\in`; see
\* formal/monotone_attenuation.tla's IndInit header for the full Gen(N) rationale, identical here).
\* ================================================================================================

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
