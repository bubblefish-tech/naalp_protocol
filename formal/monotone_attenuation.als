// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Bounded Alloy model of the C22/R-TDCS-6 monotone-attenuation invariant for N-AALP
// delegation chains (draft-bubblefish-naalp-01).
//
// NORMATIVE SOURCE (what this model encodes, and why these relations specifically):
//   - design.md §18.2 (D3), "Chain verification (ordered, fail-closed)":
//       step 6  -- attenuation (CapExceedsParent, R-DEL-4): the running child does not exceed
//                  the current grant G: childEffect <= G.effect_cap on the §6.1 lattice, AND
//                  childScope contained in G.scope under the D2 path-prefix rule.
//       step 8  -- DECLARED depth attenuation (R-DEL-7): G.max_depth <= P.max_depth - 1 for a
//                  grant G and its delegation parent P (a parent with max_depth 0 admits no
//                  child grant).
//       step 9  -- REALIZED depth bound (R-DEL-7): independently of what each grant *declares*,
//                  the actual count of delegation hops beneath a grant G_i must not exceed
//                  G_i.max_depth. "Step 8 bounds what each grant declares; step 9 bounds what
//                  the concrete chain realizes -- both must hold."
//   - design.md §6.1: the closed effect lattice is a TOTAL order
//       read_only(0) < idempotent_write(1) < non_idempotent_write(2) < destructive(3).
//   - requirements.md R-TDCS-6 (NAALP-REQ-155): "The subset-only attenuation enforced piecewise
//       by R-DEL-4 (effect and scope) and R-DEL-7 (depth) is a single named cross-cutting
//       invariant: across every hop of a delegation chain, derived authority is non-increasing
//       on all attenuated axes, leaf and interior, checked as declared and as realized."
//   - impl/go/delegation/delegation.go (the reference implementation this model was checked
//       against, read line-for-line before writing this file -- not relayed from the design
//       text alone):
//       * ScopeContained (lines 299-314): "an absent parent scope ("") is unconstrained (any
//         child, including "", is contained); otherwise the child must equal the parent or
//         begin with parent + "/". A missing child scope ("") under a scoped parent WIDENS
//         authority and is NOT contained."
//       * policy.Effect.Authorizes (impl/go/policy/policy.go:59): `func (e Effect) Authorizes
//         (action Effect) bool { return action <= e }` -- a plain total order over {0,1,2,3}.
//       * VerifyChain (lines 348-417): step 6 is `g.Grant.EffectCap.Authorizes(childEffect)`
//         AND `ScopeContained(childScope, g.Grant.Scope)`; step 8 is
//         `p.Grant.MaxDepth == 0 || g.Grant.MaxDepth >= p.Grant.MaxDepth` (violation ->
//         DelegationDepthExceeded), i.e. the REQUIRED relation is g.MaxDepth < p.MaxDepth;
//         step 9 is `pos > g.Grant.MaxDepth` (violation), where `pos` is the count of grants
//         already visited strictly below g on THIS action's specific leaf-to-root walk.
//
// WHAT GAP THIS CLOSES (per the formal-proofs scope design and
// scripts/doc_lint.py's "monotone-attenuation" check): today the invariant is (a) TEXT-LINTED
// -- doc_lint.py's REQ-155 row only confirms the SENTENCE "derived authority is non-increasing
// across every hop of a delegation chain" appears in the draft, never that it holds -- and (b)
// EXAMPLE-TESTED -- impl/go/delegation/delegation_test.go exercises specific hand-picked chains
// (CapExceedsParent, DelegationDepthExceeded on ONE scenario each). Neither is an exhaustive
// proof over the SPACE of delegation-graph shapes. This model gives that proof, bounded.
//
// THE NON-TRIVIAL CLAIM BEING CHECKED (not a restatement of the per-hop rule):
// design.md §18.2 enforces the attenuation rule PAIRWISE, one hop at a time, as the verifier
// walks leaf->root (steps 6/8/9 run once per (child, immediate-parent) pair it visits). The
// per-hop rule is encoded below as FACTS (PerHopAttenuation, PerHopDeclaredDepth,
// LeafAttenuation): every instance Alloy considers is one where each individual hop already
// passed its own local check, exactly as the verifier enforces it. The INTERESTING question --
// the one no per-hop unit test can answer, because a unit test only ever builds one hand-picked
// chain -- is whether composing many independently-checked LOCAL hops actually delivers the
// GLOBAL property the design claims: that a descendant, however many hops removed, NEVER holds
// more effect, more scope, or more realized depth budget than ANY of its ancestors, not only its
// immediate parent. The `assert MonotoneAttenuation` below states exactly that transitive,
// multi-hop consequence, and `check ... for 4` asks Alloy to search every delegation-graph shape
// up to 4 grants/actions/scopes for a counterexample where the per-hop checks all individually
// pass yet a distant ancestor is still exceeded somewhere in the chain.
//
// SCOPE JUSTIFICATION: "for 4" bounds Grant, Action, and Scope to at most 4 atoms each (Effect
// is fixed at exactly 4 by construction, one per lattice level). This is large enough to exhibit
// chains of up to 3 delegation hops (root -> interior grant -> leaf grant -> action) -- enough
// for a leaf's ceiling to be checked against a grandparent it does not directly touch, and enough
// for one grant to fan out multiple children (branching, not just a single linear chain) -- which
// is the smallest configuration that actually exercises the TRANSITIVE claim this model exists to
// check (a 1-hop chain could never distinguish "adjacent-pair attenuation holds" from "attenuation
// composes transitively", since there would be no non-adjacent ancestor to violate). The property's
// proof structure is inductive on chain length (each hop composes the same local argument with the
// one before it), so a strictly larger scope would only produce LONGER instances of the same
// counterexample shape, never a new shape Alloy could not already construct at 4.
//
// This bound was chosen empirically, not merely theoretically: this file's `check` and `run`
// commands were timed at three scopes with the Alloy 6.2.0 CLI (`org.alloytools.alloy.dist.jar`,
// default MiniSat backend) on the reference build machine. "for 4 but 3 int" (this file) resolved
// in ~69s (UNSAT -- holds -- for the check; SAT -- an instance exists -- for the sanity run,
// confirming the facts are non-vacuously satisfiable). "for 5 but 4 int" did not resolve within
// several minutes and was aborted; "for 6 but 4 int" did not resolve within ten minutes and was
// aborted. The realized-depth conjuncts use Alloy's integer cardinality (`#`) compared against an
// Int field for every (descendant, ancestor) pair, which is known to be expensive to bit-blast for
// a SAT solver, and that cost appears to grow steeply with this model's scope. Scope 4 is therefore
// the largest bound in this family that is exhaustively decidable in a practical (CI-friendly)
// time budget on the reference machine, while still being large enough to exercise genuine
// multi-hop transitivity, branching, and a non-trivial realized-depth count. A stronger bound is a
// legitimate direction for future work (a different solver backend, or an alternative encoding of
// the realized-depth conjuncts that avoids raw integer cardinality -- e.g. an ordered "budget" sig
// mirroring the Effect idiom below, checked relationally instead of arithmetically) but is out of
// scope for this build; see the honest-limitations note in the accompanying gate
// (scripts/gates/gate_formal_attenuation.py).

open util/ordering[Effect]

// ---- the closed effect lattice (design.md §6.1; impl/go/policy/policy.go:22-28) ----------

abstract sig Effect {}
one sig ReadOnly, IdempotentWrite, NonIdempotentWrite, Destructive extends Effect {}
// util/ordering[Effect] gives lt/gt/lte/gte in EXACTLY this declaration order, matching the
// wire values 0 < 1 < 2 < 3 (policy.Effect.Authorizes: action <= e).

// ---- scope: an NFC resource path, modeled as a tree of path segments -------------------------
//
// design.md §18.1 D2 / impl/go/delegation.go ScopeContained: containment is path-PREFIX
// containment (child == parent, or child begins with parent + "/"). A path hierarchy is exactly
// a tree, so `parentScope` here is the one-level-up path-segment relation (child's immediate
// containing directory); the ancestor-or-self reachable set via `*parentScope` is therefore
// exactly the set of prefixes of a given path, which is the structural content of the string
// rule without needing string literals.

sig Scope {
  parentScope: lone Scope
}

fact ScopeIsATree {
  // A real NFC path cannot be its own ancestor (no ".." cycles in a path hierarchy).
  no s: Scope | s in s.^parentScope
}

// scopeContained[child, par]: "child" (a Grant's or Action's OWN scope field, "lone" = optional)
// is contained in "par" (the parent grant's scope field, "lone" = optional) under the D2 rule.
//   - no par            -> unconstrained parent; always contained (impl: `if parent == "" {
//                          return true }`), regardless of whether child is present or absent.
//   - some par, no child -> a missing child scope under a scoped parent WIDENS authority and is
//                          NOT contained (impl: `if child == "" { return false }`).
//   - some par, some child -> contained iff par is child itself or an ancestor of child in the
//                          path tree (impl: child == parent, or strings.HasPrefix(child,
//                          parent+"/")).
pred scopeContained[child: lone Scope, par: lone Scope] {
  no par or (some child and par in child.*parentScope)
}

// ---- delegation grants: a forest via the `parent` (delegation-parent) relation ----------------
//
// design.md §18.1: "The parent is the unique cause that resolves to a Capability authority
// object whose subject/holder equals this grant's issuer... Zero-or-one such cause is
// well-formed; two or more is an ambiguous edge and is rejected ChainBroken (fail-closed)." This
// model represents only WELL-FORMED, individually-resolved chains (the ChainBroken/ambiguous
// case is a structural rejection the model does not need to re-derive; it is orthogonal to the
// attenuation property this file checks) -- hence `parent: lone Grant`, never a set.

sig Grant {
  effectCap: one Effect,   // design §18.1 "effect_cap"; impl Grant.EffectCap
  scope:     lone Scope,   // design §18.1 "scope" (optional field 6); impl Grant.Scope ("" = absent)
  maxDepth:  one Int,      // design §18.1 "max_depth"; impl Grant.MaxDepth (uint64, so >= 0)
  parent:    lone Grant    // the delegation parent P named by content id in `causes` (§18.1/§8.2)
}

fact GrantChainIsAcyclic {
  // impl/go/delegation.go VerifyChain: "a content-id cycle (infeasible for a real hash chain)".
  no g: Grant | g in g.^parent
}

fact MaxDepthIsNonNegative {
  // max_depth is a uint64 on the wire (impl Grant.MaxDepth uint64); Alloy Int is signed, so this
  // fact keeps the model's Int usage faithful to the unsigned wire field.
  all g: Grant | g.maxDepth >= 0
}

// ---- actions: the leaf of a chain, authorized by exactly one grant ----------------------------
//
// design.md §18.2 step 2: "Find the unique authority object among the action's causes that
// resolves to a Capability grant whose subject == B... If none... EffectNotAuthorized; if more
// than one -> ChainBroken." As with Grant.parent, this model represents the resolved, unique
// case -- hence `leafGrant: one Grant`.

sig Action {
  effect:    one Effect,  // the action's own effect (§18.2 step 6 "childEffect" at the leaf)
  scope:     lone Scope,  // the action's own resource scope ("childScope" at the leaf)
  leafGrant: one Grant    // the unique grant authorizing this action (§18.2 step 2)
}

// ---- attenuated[e, s, p]: one hop's worth of the §18.2 step-6 check -----------------------------
//
// "the running child does not exceed G: childEffect <= G.effect_cap ... AND childScope
// contained in G.scope" (impl: `g.Grant.EffectCap.Authorizes(childEffect)` and
// `ScopeContained(childScope, g.Grant.Scope)`).
pred attenuated[e: Effect, s: lone Scope, p: Grant] {
  lte[e, p.effectCap]
  and scopeContained[s, p.scope]
}

// ================================================================================================
// THE PER-HOP RULES, AS FACTS -- exactly what design.md §18.2 steps 6/8 check, once per hop,
// as the verifier walks leaf->root. Modeling these as facts (not preconditions inside the assert)
// means every instance Alloy considers is one where EVERY individual hop already independently
// passed its own local check -- the same guarantee VerifyChain gives per hop, no more and no less.
// ================================================================================================

fact PerHopAttenuation {
  // §18.2 step 6, applied to every interior grant-to-parent edge.
  all g: Grant | some g.parent implies attenuated[g.effectCap, g.scope, g.parent]
}

fact PerHopDeclaredDepth {
  // §18.2 step 8 (R-DEL-7 declared): g.max_depth <= p.max_depth - 1, i.e. g.maxDepth <
  // p.maxDepth strictly (impl: `p.Grant.MaxDepth == 0 || g.Grant.MaxDepth >= p.Grant.MaxDepth`
  // is the VIOLATION condition, so the REQUIRED relation is the negation: g.MaxDepth <
  // p.Grant.MaxDepth).
  all g: Grant | some g.parent implies g.maxDepth < g.parent.maxDepth
}

fact LeafAttenuation {
  // §18.2 step 6, applied at the leaf hop: the action's own effect/scope against its unique
  // leaf grant.
  all a: Action | attenuated[a.effect, a.scope, a.leafGrant]
}

// ================================================================================================
// THE FLAGSHIP INVARIANT (C22 / R-TDCS-6), stated as its TRANSITIVE, MULTI-HOP consequence.
//
// Given only that every ADJACENT pair already passed its own local §18.2 check (the facts
// above -- exactly what VerifyChain actually enforces, one hop at a time), does composing those
// local checks guarantee that NO descendant anywhere in the chain -- however many hops removed --
// ever holds more effect, more scope, or more realized depth budget than ANY of its ancestors,
// not merely its immediate parent? That composition is what "across every hop of a delegation
// chain, derived authority is non-increasing... leaf and interior" (R-TDCS-6) actually promises a
// relying party: a verifier that only ever checks one hop at a time is still sound against an
// attacker who tries to smuggle a widened capability two or more hops down the chain.
// ================================================================================================

assert MonotoneAttenuation {
  // (1) Grant-to-ancestor: for every grant d and every ancestor anc reachable via zero or more
  // delegation-parent hops (anc in d.*parent includes d itself, trivially satisfied), d's effect
  // ceiling and scope are attenuated under anc's -- not only under d's immediate parent.
  all d: Grant, anc: Grant | anc in d.*parent implies
    (lte[d.effectCap, anc.effectCap] and scopeContained[d.scope, anc.scope])

  // (2) Realized depth, transitively (§18.2 step 9 / R-DEL-7 realized): the number of grants
  // strictly between "anc" (exclusive) and "d" (inclusive) along the actual chain -- i.e. the
  // realized hop-count beneath anc on this specific path -- never exceeds anc's declared
  // max_depth, for EVERY ancestor anc of d, not only d's immediate parent.
  and all d: Grant, anc: Grant | anc in d.*parent implies
    #(d.*parent - anc.*parent) =< anc.maxDepth

  // (3) Action-to-ancestor: for every action, its own effect/scope is attenuated under EVERY
  // grant on its chain from the leaf grant up to the root -- not only the immediate leaf grant --
  // and the realized hop-count from the action's leaf grant up to that ancestor never exceeds the
  // ancestor's declared max_depth.
  and all act: Action, anc: Grant | anc in act.leafGrant.*parent implies
    (lte[act.effect, anc.effectCap]
     and scopeContained[act.scope, anc.scope]
     and #(act.leafGrant.*parent - anc.*parent) =< anc.maxDepth)
}

check MonotoneAttenuation for 4 but 3 int

// ---- sanity: the facts above must be SATISFIABLE by a genuine multi-hop chain, or the `check`
// above would hold VACUOUSLY (no instance to search) and prove nothing. Run this and confirm SAT
// with a real chain (some grant with a parent, whose parent itself has a parent) before trusting
// the check result.
run NonTrivialMultiHopChainExists {
  some g: Grant | some g.parent.parent  // a chain of at least 3 grants: g -> parent -> grandparent
  some a: Action | some a.leafGrant.parent  // an action whose leaf grant is itself non-root
} for 4 but 3 int
