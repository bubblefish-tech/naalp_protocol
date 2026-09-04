<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Quickstart: a verified, audience-bound, HITL-gated effecting object

This page takes you from install to a complete N-AALP lifecycle — build, validate, sign,
verify, human-approve, execute, and single-use-consume — in one runnable script, in the
Python application core. Every step below is real code: no mocked cryptography, no
narrated behavior. Run the script yourself and compare your output to what is printed
here.

## What you will build

A destructive action — cancelling a running workflow task — that:

1. Is validated for semantic correctness **before** it is ever signed.
2. Is signed with a real post-quantum identity (ML-DSA-65, FIPS 204) and verified offline.
3. Is bound to an **audience** (the authority allowed to act on it).
4. Cannot execute until a **human approves it** through a real, single-use N-AALP
   approval object.
5. Cannot be replayed: the same approval, used a second time, is refused fail-closed.

## Install

The Python core (`naalp`) and the ecosystem packages used in this quickstart
(`naalp_codec`, `naalp_validator`, `naalp_hitl`) live in this repository:

- The core SDK: `impl/python/naalp` (see [the Python SDK guide](../impl/python/QUICKSTART.md)
  for the standalone `pip install naalp` path).
- The ecosystem packages: `ecosystem/naalp-codec` (the blessed deterministic-CBOR codec
  binding — re-exports the Part-1 codec directly, never a second encoder),
  `ecosystem/naalp-validator`, `ecosystem/naalp-hitl` (published to PyPI once the
  supply-chain task lands; until then, import them directly from the repo).

Dependencies: `dilithium-py>=1.4.0` (deterministic ML-DSA) and `cryptography>=42`
(Ed25519). Everything else is the Python standard library.

```sh
pip install dilithium-py cryptography
```

No API key, no network call, and no external service is required anywhere in this
walkthrough — every signature, verification, and ledger append below runs entirely
offline, on your machine.

## The full script

The script behind this page lives at
[`docs/examples/e5_quickstart.py`](examples/e5_quickstart.py). Run it from the
repository root:

```sh
python docs/examples/e5_quickstart.py
```

The five steps below are that same script, in order, with real output from a run.

### Step 1 — a real post-quantum agent identity

The signer id is a pure function of the public key (no certificate authority):

```python
from naalp import cose, identity

seed = bytes([0x11]) * 32               # a real 32-byte key seed in production
pk   = cose.mldsa_keygen("ML-DSA-65", seed)
sid  = identity.signer_id(cose.ALG_MLDSA65, pk)
```

```text
agent signer id: bciqo2gxjfh673hbdbpfhdzzkxqy2fz7ixe6nm7vs5ckzuiskpczhfni
```

### Step 2 — build the candidate object and validate it before signing

The args body is built with `naalp_codec`'s own value classes (`U`/`T`/`M`) — the
blessed codec binding, so a caller never hand-rolls a second encoder. Then
`naalp_validator.validate()` checks CDDL structure, the channel/kind/effect registry, and
the consume-once audience rule against an **unsigned** candidate — catching a
hallucinated or malformed object before it is ever signed, let alone sent.

```python
from naalp import envelope, policy
from naalp_codec import M, T, U
from naalp_validator import validate

WORKFLOW_CHANNEL, TASK_CANCEL = 0x0011, 2   # Workflow channel: declared effect = DESTRUCTIVE
AUDIENCE = "svc:workflow-cancel-quickstart"

args = M([(U(1), T("task-4821")), (U(2), T("cancel: upstream vendor SLA breach"))])
candidate = envelope.Object(
    kind=TASK_CANCEL, channel=WORKFLOW_CHANNEL, signer=sid.encode("utf-8"),
    created=1785000000000, effect=policy.DESTRUCTIVE, profile=cose.PROFILE_PUBLIC,
    body=args, audience=AUDIENCE,
)
result = validate(candidate)
```

```text
pre-sign validation: valid=True violations=[]
```

### Step 3 — sign it, then verify it offline

```python
signed_bytes = envelope.sign(candidate, cose.ALG_MLDSA65, seed)
verified = envelope.verify(
    cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, pk,
    lambda c, k: (c, k) == (WORKFLOW_CHANNEL, TASK_CANCEL), signed_bytes,
)
```

```text
signed object: 3611 bytes, content id 20305d64387a0f68...
verify(): channel=0x0011 kind=2 effect=3 audience='svc:workflow-cancel-quickstart'
```

This is the **verified effecting object**: a signed, offline-verifiable, audience-bound
N-AALP object. It is not yet allowed to take effect — its effect class (`destructive`)
requires a human sign-off first.

### Step 4 — gate the side effect behind HITL

`naalp_hitl.HITLInterceptor` pauses any action whose effect meets or exceeds a
configurable threshold (`non_idempotent_write` by default), routes a real
`ApprovalRequest` to a human interface, and resumes only after a real signed approval —
bound to the exact args and audience above — has been verified and durably consumed.

```python
from naalp import approval
from naalp_hitl import HITLInterceptor, PendingAction, TerminalFrontend

ledger = approval.open_ledger("consume.wal")   # a real durable, hash-chained, single-writer ledger

approver_seed = bytes([0x22]) * 32
approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)

def _cancel_task():
    return "TASK_CANCELLED"           # the real side effect, run only after approval

action = PendingAction(
    kind="workflow.task_cancel", effect=policy.DESTRUCTIVE, args=args,
    args_summary="cancel task-4821 (upstream vendor SLA breach)", execute=_cancel_task,
)
frontend = TerminalFrontend("ops-approver-1", approver_seed)   # a real terminal prompt
interceptor = HITLInterceptor(
    ledger, cose.ALG_MLDSA65, approver_pk, AUDIENCE, "quickstart-interceptor", frontend,
)
outcome = interceptor.intercept(action)
```

Running this prompts the terminal for a real y/N decision. In the script, that keystroke
is scripted to `"y"` so the demo runs unattended — everything downstream of it (signing
the approval, verifying it, appending to the durable ledger, and only then calling
`execute()`) is real, unfaked code:

```text
================================================================
N-AALP HITL approval request
  kind:       workflow.task_cancel
  effect:     destructive (3)
  content-id: 2030f720dd659cdd75d935ee1f5994b72230118e07ebc3871583d1bd956d1c06c46f4e38f42acf09732ff2607ca4c10fc3dc
  args:       cancel task-4821 (upstream vendor SLA breach)
  audience:   svc:workflow-cancel-quickstart
================================================================
intercept() outcome: TASK_CANCELLED
action actually executed: ['TASK_CANCELLED']
```

### Step 5 — fail closed on replay

The approval above was bound to a single content id. Minting a second approval for the
identical action, consuming it once, and then replaying that exact same approval object
demonstrates the ledger's single-use guarantee:

```python
first  = interceptor.verify_and_consume(rec, sig, args_id, policy.DESTRUCTIVE)   # OK
second = interceptor.verify_and_consume(rec, sig, args_id, policy.DESTRUCTIVE)   # raises
```

```text
first consume of this approval object: OK (ledger entries: 2)
replay of the SAME approval object rejected fail-closed: kind=AlreadyConsumed
```

No partial state change occurs on the rejected replay: `AlreadyConsumed` is raised before
`execute()` would ever be reached, and the ledger records exactly one append per approval
object, ever.

## What just happened

You built an object that was:

- **Semantically validated** before it was signed (`naalp_validator`).
- **Cryptographically signed** with a post-quantum identity and **offline-verified**
  (`naalp.envelope`, `naalp.cose`).
- **Audience-bound** — the object itself, and the approval that authorized it, both name
  the exact authority allowed to act on it.
- **Gated on a human decision**, paused and resumed by a real interceptor
  (`naalp_hitl`), never executed without a verified approval.
- **Single-use**: the approval that authorized it cannot be replayed.

## Where to go next

- [Cookbook](cookbook.md) — the four agent patterns (ReAct, Plan-and-Execute,
  multi-agent, HITL) as runnable recipes.
- [The object model](spec/object-model.md) — the full signed envelope this quickstart
  built one field at a time.
- [Worked example](examples/worked-object.md) — the same object model, byte by byte.
- [The twenty channels](spec/channels.md) — every registered channel/kind/effect
  combination, including `Workflow/TaskCancel` used above.
