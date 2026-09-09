// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// MUTATION-WITNESS FIXTURE for formal/monotone_attenuation.als and
// scripts/gates/gate_formal_attenuation.py's self-test.
//
// THIS FILE DOES NOT DESCRIBE REAL CODE. It is a deliberately-broken COPY of
// formal/monotone_attenuation.als, used only to prove the gate (and, manually, the model
// itself) is actually sensitive to a widening delegation edge -- per the test-driven-development
// discipline "a check that has never been observed failing is not known to be a check"
// (rules/test-driven-development.md) and the gate framework's own rule that every gate ships a
// fixture that MUST make it fail (scripts/gates/_gate.py).
//
// THE ONE DELIBERATE MUTATION: `PerHopAttenuation` below is weakened to drop the EFFECT-ceiling
// half of design.md §18.2 step 6 (it keeps the scope-containment half unchanged), simulating a
// verifier that forgot to enforce `childEffect <= G.effect_cap` at each hop -- i.e. exactly the
// bug this proof exists to rule out. `PerHopDeclaredDepth` and `LeafAttenuation` are UNCHANGED
// copies of the real model. A second fact then FORCES at least one such widening edge (a grant
// whose effect_cap is STRICTLY GREATER than its delegation parent's -- "child.caps _> parent.caps"
// in the task's own words) to exist in every instance, so the mutation is not merely permitted
// but guaranteed present.
//
// The `assert MonotoneAttenuation` and `check MonotoneAttenuation for 4 but 3 int` below are
// BYTE-FOR-BYTE IDENTICAL to formal/monotone_attenuation.als (same scope, same assert): the
// property being checked is not touched. Only the per-hop enforcement (the "verifier") is
// weakened. Alloy is expected to find a counterexample (SAT) because the weakened per-hop fact
// now admits an edge the assert forbids.

open util/ordering[Effect]

abstract sig Effect {}
one sig ReadOnly, IdempotentWrite, NonIdempotentWrite, Destructive extends Effect {}

sig Scope {
  parentScope: lone Scope
}

fact ScopeIsATree {
  no s: Scope | s in s.^parentScope
}

pred scopeContained[child: lone Scope, par: lone Scope] {
  no par or (some child and par in child.*parentScope)
}

sig Grant {
  effectCap: one Effect,
  scope:     lone Scope,
  maxDepth:  one Int,
  parent:    lone Grant
}

fact GrantChainIsAcyclic {
  no g: Grant | g in g.^parent
}

fact MaxDepthIsNonNegative {
  all g: Grant | g.maxDepth >= 0
}

sig Action {
  effect:    one Effect,
  scope:     lone Scope,
  leafGrant: one Grant
}

pred attenuated[e: Effect, s: lone Scope, p: Grant] {
  lte[e, p.effectCap]
  and scopeContained[s, p.scope]
}

// ------------------------------------------------------------------------------------------
// MUTATION: the effect-ceiling half of step 6 ("childEffect <= G.effect_cap") is DROPPED here.
// Only scope containment survives. This is the injected fault -- it does NOT describe
// impl/go/delegation.go, which enforces both halves (VerifyChain step 6, both conjuncts).
// ------------------------------------------------------------------------------------------
fact PerHopAttenuation {
  all g: Grant | some g.parent implies scopeContained[g.scope, g.parent.scope]
  // (the real model's `lte[g.effectCap, g.parent.effectCap]` conjunct is intentionally absent)
}

fact PerHopDeclaredDepth {
  all g: Grant | some g.parent implies g.maxDepth < g.parent.maxDepth
}

fact LeafAttenuation {
  all a: Action | attenuated[a.effect, a.scope, a.leafGrant]
}

// ------------------------------------------------------------------------------------------
// FORCE THE WITNESS: guarantee at least one grant/parent pair where the child's effect_cap
// STRICTLY EXCEEDS its parent's -- the concrete "child.caps _> parent.caps" widening edge the
// weakened PerHopAttenuation fact (above) now permits.
// ------------------------------------------------------------------------------------------
fact ForceEffectWideningWitness {
  some g: Grant | some g.parent and gt[g.effectCap, g.parent.effectCap]
}

// ------------------------------------------------------------------------------------------
// UNCHANGED from formal/monotone_attenuation.als: the same transitive property, the same
// bounded scope. Expected result here: SAT (Alloy finds the forced widening edge as a
// counterexample to the effect-monotonicity conjunct of the assert).
// ------------------------------------------------------------------------------------------
assert MonotoneAttenuation {
  all d: Grant, anc: Grant | anc in d.*parent implies
    (lte[d.effectCap, anc.effectCap] and scopeContained[d.scope, anc.scope])

  and all d: Grant, anc: Grant | anc in d.*parent implies
    #(d.*parent - anc.*parent) =< anc.maxDepth

  and all act: Action, anc: Grant | anc in act.leafGrant.*parent implies
    (lte[act.effect, anc.effectCap]
     and scopeContained[act.scope, anc.scope]
     and #(act.leafGrant.*parent - anc.*parent) =< anc.maxDepth)
}

check MonotoneAttenuation for 4 but 3 int
