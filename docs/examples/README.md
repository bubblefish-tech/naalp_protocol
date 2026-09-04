<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Runnable examples

The `e5_*.py` scripts here are the actual code behind [`../quickstart.md`](../quickstart.md)
(E5.1) and [`../cookbook.md`](../cookbook.md) (E5.2). Each one is standalone, runs
end-to-end against the real Part-1 `naalp` core and the real Part-2 ecosystem packages
under `../../ecosystem/` (no mocked cryptography), and exits 0 on success. Run any of
them from the repository root:

```sh
python docs/examples/e5_quickstart.py   # the quickstart: build -> validate -> sign ->
                                         # verify -> HITL-approve -> execute -> fail-closed replay
python docs/examples/e5_react.py        # cookbook: ReAct (Thought -> Action -> Observation)
python docs/examples/e5_plan.py         # cookbook: Plan-and-Execute (a task graph)
python docs/examples/e5_multiagent.py   # cookbook: sequential pipeline + parallel fan-out
python docs/examples/e5_hitl.py         # cookbook: HITL approve-path and decline-path
```

`worked-object.md`'s reference bytes are regenerated from the Go implementation
(`impl/go/cmd/naalp-worked-example`), not from a script here — see that page for how to
reproduce it.
