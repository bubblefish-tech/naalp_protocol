---- MODULE monotone_attenuation_widening ----
\* Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
\*
\* MUTATION-WITNESS FIXTURE for formal/monotone_attenuation.tla and
\* scripts/gates/gate_formal_attenuation_unbounded.py's self-test.
\*
\* THIS FILE DOES NOT DESCRIBE REAL CODE. It is a deliberately-broken COPY of
\* formal/monotone_attenuation.tla, used only to prove the gate (and, manually, the model itself)
\* is actually sensitive to a widening delegation edge -- per the test-driven-development
\* discipline "a check that has never been observed failing is not known to be a check"
\* (rules/test-driven-development.md) and the gate framework's own rule that every gate ships a
\* fixture that MUST make it fail (scripts/gates/_gate.py). Mirrors
\* formal/fixtures/monotone_attenuation_widening.als's approach for the existing bounded Alloy
\* gate exactly: same one deliberate mutation, same non-mutated assert/property being checked.
\*
\* THE ONE DELIBERATE MUTATION: `AddChildGrant` below drops the EFFECT-ceiling half of design.md
\* SS18.2 step 6 (it keeps the scope-containment half and the declared-depth half unchanged),
\* simulating a verifier that forgot to enforce `childEffect <= G.effect_cap` at each hop -- i.e.
\* exactly the bug this proof exists to rule out. `AddRootGrant`, `AddAction`, `Inv`, `IndInit`,
\* `CInit`, and every other operator are BYTE-FOR-BYTE IDENTICAL to
\* formal/monotone_attenuation.tla: the property being checked (Inv) is not touched, only the
\* per-hop ENFORCEMENT (the "verifier", i.e. Next's guard) is weakened. The inductive-step check
\* (`Inv /\ Next => Inv'`) is expected to flip from NoError to a counterexample, because Next can
\* now construct a child grant whose effectCap strictly exceeds its parent's -- an edge the
\* (unchanged) Inv forbids.

EXTENDS Integers, Sequences, FiniteSets, Apalache

NoGrant == 0
NoScope == -1

ScopeContained(child, par) ==
    IF par = NoScope THEN TRUE
    ELSE IF child = NoScope THEN FALSE
    ELSE child % par = 0

\* @typeAlias: grantT = { effectCap: Int, scope: Int, maxDepth: Int, parent: Int, ancestors: Set(Int), depth: Int };
\* @typeAlias: actionT = { effect: Int, scope: Int, leafGrant: Int };
typedefs == TRUE

\* N is DELIBERATELY SMALLER here than in formal/monotone_attenuation.tla (N=3). This fixture
\* exists only to prove the gate's inductive-step check is sensitive to the injected fault (the
\* dropped effect-ceiling guard below), NOT to carry the unbounded guarantee itself -- that is the
\* real model's job, at its own N. A widening bug is witnessed by a 2-grant parent->child chain
\* (one root grant already present in the arbitrary IndInit predecessor, one more child appended by
\* Next with cap > parent.effectCap), so N=2 is large enough for Apalache's counterexample search
\* to find it, and searching a slot-count-2 predecessor space is faster than N=3's (let alone the
\* old N=6's, which made the real model's inductive check itself intractable -- see
\* formal/monotone_attenuation.tla's N definition for the measured numbers).
N == 2

CONSTANTS
    \* @type: Seq($grantT);
    grants0,
    \* @type: Seq($actionT);
    actions0

VARIABLES
    \* @type: Seq($grantT);
    grants,
    \* @type: Seq($actionT);
    actions

Init ==
    /\ grants = <<>>
    /\ actions = <<>>

\* @type: (Int, Int, Int) => Bool;
AddRootGrant(cap, scope, depth) ==
    LET \* @type: $grantT;
        NewRec == [effectCap |-> cap, scope |-> scope, maxDepth |-> depth,
                   parent |-> NoGrant, ancestors |-> {Len(grants) + 1}, depth |-> 0]
    IN /\ grants' = Append(grants, NewRec)
       /\ UNCHANGED actions

\* ------------------------------------------------------------------------------------------
\* MUTATION: the effect-ceiling half of step 6 ("childEffect <= G.effect_cap") is DROPPED here.
\* Only scope containment + declared depth survive. This is the injected fault -- it does NOT
\* describe impl/go/delegation/delegation.go, which enforces all three (VerifyChain step 6/8).
\* ------------------------------------------------------------------------------------------
\* @type: (Int, Int, Int, Int) => Bool;
AddChildGrant(cap, scope, depth, pid) ==
    LET \* @type: $grantT;
        NewRec == [effectCap |-> cap, scope |-> scope, maxDepth |-> depth, parent |-> pid,
                   ancestors |-> grants[pid].ancestors \union {Len(grants) + 1},
                   depth |-> grants[pid].depth + 1]
    IN /\ pid \in DOMAIN grants
       /\ ScopeContained(scope, grants[pid].scope)             \* step 6 (scope half) -- KEPT
       /\ depth < grants[pid].maxDepth                          \* step 8 -- KEPT
       \* (the real model's `cap <= grants[pid].effectCap` conjunct is intentionally absent)
       /\ grants' = Append(grants, NewRec)
       /\ UNCHANGED actions

\* @type: (Int, Int, Int) => Bool;
AddAction(eff, scope, lg) ==
    LET \* @type: $actionT;
        NewRec == [effect |-> eff, scope |-> scope, leafGrant |-> lg]
    IN /\ lg \in DOMAIN grants
       /\ eff <= grants[lg].effectCap
       /\ ScopeContained(scope, grants[lg].scope)
       /\ actions' = Append(actions, NewRec)
       /\ UNCHANGED grants

Next ==
    \/ \E cap \in 0..3, scope \in (Nat \union {NoScope}), depth \in Nat :
         AddRootGrant(cap, scope, depth)
    \/ \E cap \in 0..3, scope \in (Nat \union {NoScope}), depth \in Nat, pid \in DOMAIN grants :
         AddChildGrant(cap, scope, depth, pid)
    \/ \E eff \in 0..3, scope \in (Nat \union {NoScope}), lg \in DOMAIN grants :
         AddAction(eff, scope, lg)

\* ---- UNCHANGED IN STRUCTURE from formal/monotone_attenuation.tla below this line: the same
\* Inv, IndInit, CInit, WellFormed, PerHopDeclaredDepth, GhostConsistency, GrantRecordSet and
\* ActionRecordSet operators, each parameterized by THIS FILE's own N=2 (not the real model's
\* N=3 -- see the N definition above for why a smaller predecessor bound is deliberately used
\* here). Every operator's TEXT is therefore identical to the real model's EXCEPT for (a) the N
\* constant itself and (b) Next's AddChildGrant guard above, which is the one deliberate
\* mutation this fixture exists to inject. ------------------------------------------------------

WellFormed ==
    /\ \A d \in DOMAIN grants : grants[d].parent = NoGrant \/ grants[d].parent \in DOMAIN grants
    /\ \A a \in DOMAIN actions : actions[a].leafGrant \in DOMAIN grants

PerHopDeclaredDepth ==
    \A d \in DOMAIN grants :
        grants[d].parent # NoGrant => grants[d].maxDepth < grants[grants[d].parent].maxDepth

GhostConsistency ==
    /\ WellFormed
    /\ PerHopDeclaredDepth
    /\ \A d \in DOMAIN grants :
        /\ d \in grants[d].ancestors
        /\ grants[d].ancestors =
             {d} \union (IF grants[d].parent = NoGrant THEN {} ELSE grants[grants[d].parent].ancestors)
        /\ grants[d].depth = IF grants[d].parent = NoGrant THEN 0 ELSE grants[grants[d].parent].depth + 1

Inv ==
    /\ GhostConsistency
    /\ \A d \in DOMAIN grants, anc \in DOMAIN grants :
         anc \in grants[d].ancestors =>
             /\ grants[d].effectCap <= grants[anc].effectCap
             /\ ScopeContained(grants[d].scope, grants[anc].scope)
             /\ (grants[d].depth - grants[anc].depth) <= grants[anc].maxDepth
    /\ \A act \in DOMAIN actions, anc \in DOMAIN grants :
         anc \in grants[actions[act].leafGrant].ancestors =>
             /\ actions[act].effect <= grants[anc].effectCap
             /\ ScopeContained(actions[act].scope, grants[anc].scope)
             /\ (grants[actions[act].leafGrant].depth - grants[anc].depth) <= grants[anc].maxDepth

\* NoMultiHop is defined here for STRUCTURAL parity with formal/monotone_attenuation.tla (see
\* that file's own NoMultiHop comment) -- gate_formal_attenuation_unbounded.py does NOT run the
\* non-vacuity leg against this fixture. This fixture's N=2 predecessor bound cannot represent a
\* depth>=2 chain at all (3 grants are needed; only 2 slots exist here), so a non-vacuity check
\* against THIS file would report NoError for a reason having nothing to do with the fixture's
\* one deliberate mutation (the dropped effect-ceiling guard) -- it would manufacture a spurious
\* self-test failure unrelated to what this fixture exists to prove. See
\* gate_formal_attenuation_unbounded.py's `_classify()` docstring for the full reasoning.
NoMultiHop == ~(\E d \in DOMAIN grants : grants[d].depth >= 2)

GrantRecordSet == [effectCap: 0..3, scope: (Nat \union {NoScope}), maxDepth: Nat,
                    parent: 0..N, ancestors: SUBSET (1..N), depth: Nat]
ActionRecordSet == [effect: 0..3, scope: (Nat \union {NoScope}), leafGrant: 0..N]

CInit ==
    /\ grants0 = Gen(N)
    /\ \A i \in DOMAIN grants0 : grants0[i] \in GrantRecordSet
    /\ actions0 = Gen(N)
    /\ \A i \in DOMAIN actions0 : actions0[i] \in ActionRecordSet

IndInit ==
    /\ grants = grants0
    /\ actions = actions0
    /\ Inv

====
