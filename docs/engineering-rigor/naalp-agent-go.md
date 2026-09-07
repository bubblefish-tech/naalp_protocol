<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP Go agent-pattern SDK

Mutation-survival evidence for seven load-bearing fail-closed properties, one, two, or
three from each of this module's four packages (two from `react`, one each from `plan`
and `multiagent`, three from `mixedmode`). Each row was produced by actually editing the named
`.go` file (never a Part-1 `impl/go/*` file, which is out of scope for this task),
confirming the named test(s) flip RED for the stated reason, restoring the file from a
`.bak` copy made BEFORE any mutation (never `git checkout` -- every file in this module is
new/untracked, so `git checkout` would silently no-op and leave a mutation live), and
re-confirming the file's SHA-256 matches the baseline exactly before re-running the full
suite GREEN. Go's build cache is content-addressed (not mtime-based), so no forced-rebuild
step is needed after a byte-exact revert -- unlike an mtime-based incremental build system,
the cache key is already correct.

Run command (from `ecosystem/naalp-agent-go/`):

```
GOWORK=off go test -race -count=1 -v ./...
```

Baseline (pre-mutation) and every post-revert run: 28/28 tests GREEN across `react`,
`plan`, and `multiagent`; 15/15 additional top-level tests GREEN in `mixedmode` (10 for
M5/M6; +5 top-level / +2 subtests for M7) -- 43/43 top-level tests
across the whole module.

## M1 -- pre-send validator refusal is ignored (`react/bridge.go`, `Bridge.ActionToRequest`)

**Baseline SHA-256:** `dd655c8c0c2f0dad67bfb2b7509082727e5cc2e7364b5f5ce0a09c643ce7e4e0`

**Mutated:** the branch that decides whether an injected `Validator`'s refusal is
actually acted on:

```diff
 	if b.Validator != nil {
-		if err := b.Validator(candidate); err != nil {
+		if err := b.Validator(candidate); false { // MUTATION M1: never act on a validator refusal
+			_ = err
 			return Request{}, &Error{"ValidationRefused", ...}
 		}
 	}
```

**RED, confirmed** (`TestValidatorRejectsCandidatePreSend`):

```
bridge_test.go:134: expected ActionToRequest to fail closed on validator refusal
--- FAIL: TestValidatorRejectsCandidatePreSend (0.00s)
```

With the refusal branch dead, a candidate the injected validator flags is signed and
emitted anyway. Exactly 1 of 11 `react` tests flipped; the other 10 were unaffected
(this branch is reached only when a `Validator` is injected and it returns a non-nil
error).

**Reverted:** the file was restored from its `.bak` copy, SHA-256 re-confirmed
`dd655c8c0c2f0dad67bfb2b7509082727e5cc2e7364b5f5ce0a09c643ce7e4e0`.
**GREEN, confirmed:** 11/11 `react` tests pass.

## M2 -- causal linkage never enforced (`react/bridge.go`, `Bridge.ResponseToObservation`)

**Baseline SHA-256:** `dd655c8c0c2f0dad67bfb2b7509082727e5cc2e7364b5f5ce0a09c643ce7e4e0`

**Mutated:** the membership check against the response's own `Causes`:

```diff
-	if !linked {
+	if false { // MUTATION M2: never enforce the causal-linkage check
+		_ = linked
 		return Observation{
 			OK:    false,
 			Error: "CausalViolation",
```

**RED, confirmed** (`TestResponseToObservationMissingCausalLinkFailsClosed`,
`TestResponseToObservationWrongCausalLinkFailsClosed`):

```
--- FAIL: TestResponseToObservationMissingCausalLinkFailsClosed (0.00s)
--- FAIL: TestResponseToObservationWrongCausalLinkFailsClosed (0.00s)
```

With the check dead, a real, correctly-signed, correctly-addressed response that names
no causal edge back to the request (or names a completely unrelated one) is accepted as
a valid Observation anyway. Exactly the two causal-linkage-dependent tests flipped (9 of
11 still passed); every other verification step (signature, audience) is independent of
this check and was unaffected.

**Reverted:** restored from `.bak`, SHA-256 re-confirmed
`dd655c8c0c2f0dad67bfb2b7509082727e5cc2e7364b5f5ce0a09c643ce7e4e0`.
**GREEN, confirmed:** 11/11 `react` tests pass.

## M3 -- a blocked prerequisite is never propagated (`plan/orchestrator.go`, `Orchestrator.Run`)

**Baseline SHA-256:** `277e9b56df0834eb00bd0267a68e206a814ab8d2ede2f2bb0b4df2c18a71f32d`

**Mutated:** the branch that records a task as "blocked" when a prerequisite did not
reach "executed":

```diff
-		if len(unresolved) > 0 {
+		if false { // MUTATION M3: never propagate a blocked prerequisite
 			sort.Strings(unresolved)
 			results[tid] = NodeResult{TaskID: tid, Status: "blocked", ...}
 			continue
 		}
```

**RED, confirmed** (`TestRunRefusedPrerequisiteBlocksDependent`):

```
orchestrator_test.go:116: expected child blocked, got executed
--- FAIL: TestRunRefusedPrerequisiteBlocksDependent (0.00s)
```

With the block dead, `child` proceeds to sign and "execute" even though its prerequisite
`root` was refused -- the exact fail-closed-DAG-propagation guarantee the orchestrator must
enforce. Exactly 1 of 7 `plan` tests flipped.

**Reverted:** restored from `.bak`, SHA-256 re-confirmed
`277e9b56df0834eb00bd0267a68e206a814ab8d2ede2f2bb0b4df2c18a71f32d`.
**GREEN, confirmed:** 7/7 `plan` tests pass.

## M4 -- a broken pipeline chain is never propagated (`multiagent/pipeline.go`, `Pipeline.Run`)

**Baseline SHA-256:** `d89e37c0e174b118516d1d40e317946c8187dfcb205e1b02564ec53f99c4327f`

**Mutated:** the branch that short-circuits every remaining stage to "blocked" once an
earlier stage did not reach "executed":

```diff
 	for _, stage := range p.Stages {
-		if chainBroken {
+		if false { // MUTATION M4: never propagate a broken chain
+			_ = chainBroken
 			results = append(results, StageResult{AgentID: stage.AgentID, Status: "blocked", ...})
 			continue
 		}
```

**RED, confirmed** (`TestPipelineRefusalBlocksDownstreamStagesWithoutTouchingThem`):

```
pipeline_test.go:117: expected stage B blocked, got refused
--- FAIL: TestPipelineRefusalBlocksDownstreamStagesWithoutTouchingThem (0.00s)
```

With the short-circuit dead, stage B is actually attempted (its bridge IS touched) even
though stage A refused -- `Status` becomes "refused" (stage B's own bridge returning a
default zero-value `Observation{OK:false}`) rather than "blocked", proving the chain was
NOT propagated and stage B's bridge WAS reached, exactly the property
`touchedB`/fail-closed-by-propagating exists to rule out. Exactly 1 of 10 `multiagent`
tests flipped.

**Reverted:** restored from `.bak`, SHA-256 re-confirmed
`d89e37c0e174b118516d1d40e317946c8187dfcb205e1b02564ec53f99c4327f`.
**GREEN, confirmed:** 10/10 `multiagent` tests pass.

## Empirical concurrency-safety check (not a mutation, a positive finding)

`multiagent/fanout_test.go`'s `TestConcurrentSignVerifyNoCorruption` independently
confirms (under `go test -race`) that the Go Part-1 reference SDK's ML-DSA backend
(`github.com/cloudflare/circl`) has no shared mutable signing/verification state, so
`ParallelFanout`'s concurrent goroutine dispatch needs no crypto-serialization lock --
unlike the sibling Python `naalp_multiagent.ParallelFanout`, whose `CRYPTO_LOCK` exists
specifically because the Python reference SDK's `dilithium_py` backend IS a
non-thread-safe process-wide singleton. `multiagent/fanout.go`'s SHA-256 was unchanged by
this session (`8d25d2314e55fab49aeb4f2aea7016c2c43d3585d8b19944fa55983415565005` before and
after) -- it carries no mutation of its own; the design decision it documents is verified
by this dedicated positive test instead.

## M5 -- the legacy path's read-only ceiling is never enforced (`mixedmode/endpoint.go`, `Endpoint.Authorize`)

**Property:** the Go mixed-mode SDK (mirrors the Python mixed-mode SDK). This is the CRITICAL
AUTHZ property this component must enforce: a legacy-origin `Record` must never gain effecting
authority above `read_only`, independent of any `Grant` and independent of anything the legacy
JSON body itself claims.

**Baseline SHA-256:** `0b976d1d366f6ce12c6c665f25be598316ec4d5406cd0647513b18eca59d695c`

**Mutated:** the branch that caps a legacy record's requested effect at `read_only`:

```diff
 	if r.Origin == OriginLegacy {
-		if requestedEffect > policy.ReadOnly {
+		if false && requestedEffect > policy.ReadOnly { // MUTATION M5: never enforce the legacy read_only ceiling
 			return ErrLegacyEffectNotAuthorized
 		}
 		return nil
 	}
```

**RED, confirmed** (`TestAuthorize_LegacyRecord_CappedAtReadOnly_RegardlessOfGrantOrForeignClaim`):

```
endpoint_test.go:196: effect 1: expected ErrLegacyEffectNotAuthorized, got nil authorization
--- FAIL: TestAuthorize_LegacyRecord_CappedAtReadOnly_RegardlessOfGrantOrForeignClaim (0.00s)
```

With the ceiling dead, a legacy record whose (unsigned) foreign JSON body claims
`"effect":3,"audience":"admin"` is authorized for `idempotent_write`,
`non_idempotent_write`, and `destructive` alike, under the most permissive `Grant` the
test constructs -- exactly the effect-authorization-gate bypass the design forecloses
("no code path may route a legacy-origin record around the effect-authorization gate...
on the theory that it isn't really an N-AALP object").

**Reverted:** the file was restored from its `.bak` copy (made before the mutation,
never `git checkout` -- this file is new/untracked, so `git checkout` would silently
no-op), SHA-256 re-confirmed `0b976d1d366f6ce12c6c665f25be598316ec4d5406cd0647513b18eca59d695c`.
**GREEN, confirmed:** `go test -race -count=1 ./mixedmode/...` -- 10/10 tests pass. Go's
content-addressed build cache needed no forced rebuild after the byte-exact revert.

## M6 -- the migration path can skip straight from mixed to strict (`mixedmode/migration.go`, `Migration.Tighten`)

**Property:** register an endpoint as mixed-mode, then tighten to strict-only, with a
`Deprecation`/`Sunset` signal on the legacy path. The load-bearing property: an endpoint MUST pass through
`StageDeprecated` (and therefore emit the Deprecation/Sunset signal) before it may
refuse legacy traffic outright -- no silent overnight cutover.

**Baseline SHA-256:** `c876ce73d88cc55d04a8e4f376577f32deecc82d7bd77b598bf273894918d656`

**Mutated:** the transition guard on `Tighten`:

```diff
 func (m *Migration) Tighten() error {
-	if m.stage != StageDeprecated {
+	if false && m.stage != StageDeprecated { // MUTATION M6: never enforce the deprecated-first transition guard
 		return &Error{"InvalidMigrationTransition", "Tighten is only valid from StageDeprecated, got " + m.stage.String()}
 	}
 	m.stage = StageStrict
 	return nil
 }
```

**RED, confirmed** (`TestMigration_Tighten_CannotSkipDeprecatedStage`):

```
migration_test.go:75: expected Tighten from StageMixed to be refused (cannot skip the deprecation signal)
--- FAIL: TestMigration_Tighten_CannotSkipDeprecatedStage (0.00s)
```

With the guard dead, a zero-value (`StageMixed`) `Migration` advances straight to
`StageStrict` on a bare `Tighten()` call -- every caller who was ever told to expect a
`Deprecation`/`Sunset` warning period gets none; legacy traffic is cut off with zero
notice.

**Reverted:** restored from `.bak`, SHA-256 re-confirmed
`c876ce73d88cc55d04a8e4f376577f32deecc82d7bd77b598bf273894918d656`.
**GREEN, confirmed:** `go test -race -count=1 ./mixedmode/...` -- 10/10 tests pass.

## M7 -- the strict leg's consume-once audience gate is never enforced (`mixedmode/endpoint.go`, `Endpoint.Authorize`)

**Property:** close a cross-SDK parity asymmetry identified by review: the Python
mixed-mode SDK's `_authorize_strict` already carries a third step calling
`envelope.check_audience` for a (channel, kind) registered consume-once, but the Go
`Endpoint.Authorize` stopped after `channels.CheckEffect` + `grant.AuthorizeObject` -- it
never checked the single-use consume/audience binding at all, on either leg. This session adds
`Endpoint.SelfAuthority` + `Endpoint.ConsumeOnceKinds` and a third strict-leg step that
reuses the real Part-1 `envelope.CheckAudience` (never reimplemented), plus the mirrored
legacy-leg surrogate refusal (`Authorize`'s new variadic `legacyTarget` argument, since
`Handle` never parses the untrusted foreign body and a legacy `Record` therefore carries
no channel/kind of its own to check).

**Baseline SHA-256:** `97bc323cda3bfb57191139032b934d3931bcdd3b6f7a9b0fdd4323813471349a`

**Mutated:** the branch that runs the new strict-leg consume-once audience gate:

```diff
-	if e.ConsumeOnceKinds[ConsumeOnceKey{Channel: r.Object.Channel, Kind: r.Object.Kind}] {
+	if false && e.ConsumeOnceKinds[ConsumeOnceKey{Channel: r.Object.Channel, Kind: r.Object.Kind}] { // MUTATION M7: never enforce the strict-leg consume-once audience gate
 		if err := envelope.CheckAudience(r.Object, e.SelfAuthority, true); err != nil {
 			return err
 		}
 	}
 	return nil
 }
```

**RED, confirmed** (`TestAuthorize_StrictRecord_ConsumeOnceKind_WrongOrAbsentAudienceRefused`,
both subtests):

```
endpoint_test.go:275: expected the consume-once audience gate to refuse, got nil authorization
--- FAIL: TestAuthorize_StrictRecord_ConsumeOnceKind_WrongOrAbsentAudienceRefused (0.00s)
    --- FAIL: TestAuthorize_StrictRecord_ConsumeOnceKind_WrongOrAbsentAudienceRefused/absent (0.00s)
    --- FAIL: TestAuthorize_StrictRecord_ConsumeOnceKind_WrongOrAbsentAudienceRefused/wrong-authority (0.00s)
```

With the gate dead, a fully-verified, fully-effect-authorized strict object targeting a
registered `ConsumeOnceKinds` pair is authorized regardless of whether its `audience`
field is absent or names a completely different consuming authority -- exactly the
single-use/audience-bound property the spec exists to enforce, and exactly the property
the Python sibling's `_authorize_strict` step 3 already had and this Go SDK previously
lacked (the cross-SDK parity finding). Exactly 1 of 15 top-level `mixedmode` tests flipped
(its 2 subtests); the other 14 top-level tests (including
`TestAuthorize_StrictRecord_ConsumeOnceKind_MatchingAudienceAuthorized`,
`TestAuthorize_StrictRecord_NonConsumeOnceKind_AudienceNeverChecked`, both legacy-leg
consume-once tests, and every pre-existing test) were unaffected -- the mutated branch
is reached only for a strict record on a registered consume-once pair.

**Reverted:** the file was restored from its `.bak` copy (made before the mutation,
never `git checkout` -- this file is new/untracked, so `git checkout` would silently
no-op), SHA-256 re-confirmed `97bc323cda3bfb57191139032b934d3931bcdd3b6f7a9b0fdd4323813471349a`.
**GREEN, confirmed:** `go build ./...` clean, `go vet ./...` clean,
`go test -race -count=1 ./mixedmode/...` -- 15/15 top-level tests pass (10 `Handle`/
`Authorize`-family + 5 `Migration`-family; one `Authorize` test carries 2 subtests, 17
`--- PASS` lines total including subtests). Go's content-addressed build cache needed no
forced rebuild after the byte-exact revert.

## Why these seven, and why every mutation targets glue code, never a Part-1 primitive

`react`, `plan`, `multiagent`, and `mixedmode` are all glue: every cryptographic and
structural check (signature verification, content-id binding, the audience point-of-use
gate, the topological-sort cycle detection inherited from graph theory, the
federated-ordering reconcile linearization) is delegated to the real Part-1
`impl/go/envelope` / `impl/go/channels` / `impl/go/audit` / `impl/go/federation` /
`impl/go/policy` / `impl/go/carriage` primitives, each of which carries its own graded
red-evidence out of scope for this task. What IS this task's own code, and therefore what
these seven mutations target, is each package's OWN fail-closed scheduling/propagation/
authorization choice: that a validator's refusal is actually acted on (M1), that a
response is actually checked for the causal edge back to its request (M2), that a DAG node
whose prerequisite refused is actually blocked rather than executed (M3), that a pipeline
stage whose predecessor refused is actually blocked rather than touching its own bridge
(M4), that a legacy-origin mixed-mode record is actually capped at `read_only` regardless
of any `Grant` or any claim inside its own (unsigned) body (M5), that a mixed-mode
endpoint's migration path actually cannot skip the mandatory Deprecation/Sunset stage on
its way to strict-only (M6), and that a strict-origin mixed-mode record targeting a
registered consume-once (channel, kind) actually passes the Sec.2.5.3 audience gate
rather than being authorized on signature-and-effect alone (M7). All seven are exactly
the properties this ecosystem module must get right -- not the underlying Part-1 SDK.
M5 in particular is the module's single most security-relevant test:
`mixedmode.Endpoint.Authorize` is the ONE choke point standing between an
unauthenticated legacy request and effecting authority it must never receive.
