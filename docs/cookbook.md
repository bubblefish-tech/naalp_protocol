<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Cookbook: agent patterns on N-AALP

Four runnable recipes, one per common agent interaction shape. Each recipe is a real
script under [`docs/examples/`](examples/README.md) that runs end-to-end against the real
Part-2 ecosystem packages (`naalp_react`, `naalp_plan`, `naalp_multiagent`,
`naalp_hitl`) and the Part-1 `naalp` core — no mocked cryptography anywhere. Run any of
them yourself and compare your output to what is printed on this page.

All four share one underlying primitive: `naalp_react.ReActBridge` turns an agent's
`Action` into a real signed N-AALP request, and turns a counterpart's signed response
back into a typed `Observation` — verifying signature, audience, and causal linkage
(`causes[]`) before the agent ever sees the result. Plan-and-Execute and multi-agent both
compose that same bridge; they do not define a second signing path.

If you have not read the [quickstart](quickstart.md) yet, it walks the underlying
object lifecycle (build → validate → sign → verify → approve → execute) one step at a
time; this page assumes that background and moves straight to the patterns.

## ReAct: Thought → Action → Observation

A ReAct agent's loop turns each `Action` into a signed request and each response into a
typed `Observation`. A response that fails verification — a tampered signature, the
wrong audience, a missing causal link — becomes a typed refusal with a named error, never
a silent accept and never a crash.

Script: [`docs/examples/e5_react.py`](examples/e5_react.py)

```python
from naalp_react import Action, M, ReActBridge, T, U
from naalp import cose, envelope, identity, policy

bridge = ReActBridge(
    alg=cose.ALG_MLDSA65, seed=agent_seed, signer_id=agent_sid,
    profile=cose.PROFILE_PUBLIC, audience="svc:weather-tool", self_identity=agent_sid,
    responder_alg=cose.ALG_MLDSA65, responder_pubkey=tool_pk, transport=transport,
)

action = Action(
    name="get_weather", channel=0x0011, kind=0, effect=policy.NON_IDEMPOTENT_WRITE,
    args=M([(U(1), T("Tokyo"))]), args_summary="get_weather(city='Tokyo')",
)
request = bridge.action_to_request(action)        # Action -> a real signed request
observation = bridge.response_to_observation(response_bytes, request)  # -> Observation
```

Run: `python docs/examples/e5_react.py`

```text
Thought: I need the current weather in Tokyo before I recommend a departure time.
Action -> signed request: 3555 bytes, content id 2030397e1c0a8094...
transport received exactly this request: True
Observation: ok=True body=[(1, '72F and sunny')]
Thought: 72F and sunny -- a good departure window.
A tampered response instead yields: ok=False error=BadSignature

REACT COOKBOOK: PASS
```

## Plan-and-Execute: a task graph, run in dependency order

`naalp_plan.PlanOrchestrator` runs a `Task` graph — each task naming its prerequisite
task ids — in dependency order. Every node's signed request carries `causes[]` pointing
at the content ids of the prerequisites it actually depended on: the causal graph on the
wire **is** the plan's dependency graph, not a side record of it. A node whose
prerequisite is refused (wrong audience, bad signature, …) is never signed and never run.

Script: [`docs/examples/e5_plan.py`](examples/e5_plan.py)

```python
from naalp_plan import PlanOrchestrator, Task

plan = [
    Task(id="fetch_itinerary", action=_action("fetch_itinerary")),
    Task(id="price_flights", action=_action("price_flights"), prereqs=("fetch_itinerary",)),
    Task(id="price_hotels", action=_action("price_hotels"), prereqs=("fetch_itinerary",)),
    Task(id="book_trip", action=_action("book_trip"), prereqs=("price_flights", "price_hotels")),
]
run = PlanOrchestrator(bridge=bridge, executor=_tool_executor).run(plan)
```

Run: `python docs/examples/e5_plan.py`

```text
Execution order: ('fetch_itinerary', 'price_flights', 'price_hotels', 'book_trip')
  fetch_itinerary  status=executed  causes=[]
  price_flights    status=executed  causes=['2030201f3667']
  price_hotels     status=executed  causes=['2030201f3667']
  book_trip        status=executed  causes=['2030eb210f54', '2030319401fd']

'book_trip' causally cites BOTH 'price_flights' and 'price_hotels' -- the wire
causal graph IS the plan's dependency graph.

PLAN COOKBOOK: PASS
```

## Multi-agent: sequential pipelines and parallel fan-out

`naalp_multiagent` composes several **distinct** agent identities around the same
`ReActBridge`, two ways:

- `SequentialPipeline` — each stage's `Observation` feeds the next stage's `Action`; a
  chain, each request causally linked to the one before it.
- `ParallelFanout` — several distinct agents act concurrently on the **same shared
  input**, and their signed results are reconciled into one deterministic total order —
  the same order on every run, independent of thread-scheduling nondeterminism.

Script: [`docs/examples/e5_multiagent.py`](examples/e5_multiagent.py)

```python
from naalp_multiagent import Branch, ParallelFanout, SequentialPipeline, Stage

seq_run = SequentialPipeline(stages=[stage_a, stage_b, stage_c]).run()

par_run = ParallelFanout(branches=[branch_0, branch_1, branch_2, branch_3, branch_4]) \
    .run(shared_input_id)
```

Run: `python docs/examples/e5_multiagent.py`

```text
==========================================================================
SEQUENTIAL: three DISTINCT agents, drafter -> reviewer -> booker
==========================================================================
  drafter   status=executed
  reviewer  status=executed
  booker    status=executed

==========================================================================
PARALLEL: five DISTINCT agents fan out on ONE shared input, then reconcile
==========================================================================
  branch results: {'specialist-0': 'executed', 'specialist-1': 'executed', 'specialist-2': 'executed', 'specialist-3': 'executed', 'specialist-4': 'executed'}
  reconciled order: ['20309ae342c0', '2030349bb2c2', '20308247947a', '203095c6bb5a', '2030bb20f8ad', '2030ec7e6ef3']
  reconciled order (second run): ['20309ae342c0', '2030349bb2c2', '20308247947a', '203095c6bb5a', '2030bb20f8ad', '2030ec7e6ef3']
  same total order on both runs, despite concurrent thread scheduling: CONFIRMED

MULTI-AGENT COOKBOOK: PASS
```

## HITL: pause, approve, resume — or fail closed

`naalp_hitl.HITLInterceptor` gates any effecting action whose effect meets or exceeds a
threshold (`non_idempotent_write` by default) behind a real human decision. This recipe
runs the same kind of destructive action through the gate twice: once approved (the
action runs), once declined (the action never runs, and the ledger records no partial
state).

Script: [`docs/examples/e5_hitl.py`](examples/e5_hitl.py)

```python
from naalp_hitl import HITLError, HITLInterceptor, PendingAction, TerminalFrontend

action = PendingAction(
    kind="db.drop_table", effect=policy.DESTRUCTIVE,
    args=M([(U(1), T("stale_sessions"))]),
    args_summary="DROP TABLE stale_sessions (retention policy expired)",
    execute=_drop_table,
)
interceptor = HITLInterceptor(ledger, cose.ALG_MLDSA65, approver_pk, audience, "hitl-cookbook", frontend)
try:
    outcome = interceptor.intercept(action)   # blocks for the human, then verifies+consumes
except HITLError as e:
    ...  # e.kind == "ApprovalDenied" on a decline; action.execute() never ran
```

Run: `python docs/examples/e5_hitl.py`

```text
==========================================================================
The human APPROVES: the destructive action runs exactly once
==========================================================================
================================================================
N-AALP HITL approval request
  kind:       db.drop_table
  effect:     destructive (3)
  content-id: 2030ac48542cced5d912bc0769741c620e325f131f2f8ddc532769c5eeddeb6235772b20e20fdfe48ae0dc2d39d1006db45c
  args:       DROP TABLE stale_sessions (retention policy expired)
  audience:   svc:database-admin-hitl-cookbook
================================================================
intercept() outcome: TABLE_DROPPED
action executed: ['TABLE_DROPPED']

==========================================================================
The human DECLINES: the SAME kind of action never runs, no state change
==========================================================================
================================================================
N-AALP HITL approval request
  kind:       db.drop_table
  effect:     destructive (3)
  content-id: 20301cfbb40fb5e934423087ce36d92f6cb9d2d2c96cd8576fc093a22617a3bd3e114588c0d99b72f56d89b5cbac97769b93
  args:       DROP TABLE customer_orders
  audience:   svc:database-admin-hitl-cookbook
================================================================
intercept() raised: ApprovalDenied
action executed: []

ledger entries: 1 (one append, for the APPROVED action only --
the declined request never touched the ledger)

HITL COOKBOOK: PASS
```

## Where to go next

- [Quickstart](quickstart.md) — the underlying object lifecycle, one step at a time.
- [The twenty channels](spec/channels.md) — every registered channel/kind/effect surface
  these recipes build objects against.
- [Worked example](examples/worked-object.md) — a complete signed object, byte by byte.
