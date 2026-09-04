<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Protocol mapping: A2A (Agent2Agent)

A developer working against an A2A stack holds two foreign-native things: an **A2A Agent Card**
(raw bytes fetched from a card endpoint) and an ordered sequence of `TaskStatusUpdateEvent`-shaped
observations of one task's lifecycle — a task id and an A2A `TaskState` **string** (`submitted`,
`working`, `input-required`, `auth-required`, `completed`, `canceled`, `failed`, `rejected`; A2A
§4.1.3), never an N-AALP wire code.

N-AALP maps both onto its own signed, receipt-chained wire objects and back — two profiles working
together:

- **Signed description and directories** (the draft's Channel Surfaces section): a service's operation table travels
  as a signed bearer object whose authority is the signature over its bytes, not the connection that
  served it. A foreign description (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent
  Badge) is carried octet-for-octet inside a `naalp-description-import`, under the importer's own
  N-AALP effect mapping for the card's skills.
- **Name bindings and the A2A task-state profile** (the draft's Channel Surfaces section): the A2A `TaskState`
  vocabulary is imported and each transition becomes a receipt-chained signed object, dated by chain
  position — not by a self-asserted clock — exactly like the audit receipt chain the rest of N-AALP
  already uses.

Reference implementation: [`ecosystem/naalp-a2a-bridge`](https://github.com/bubblefish-tech/naalp_protocol/tree/main/ecosystem/naalp-a2a-bridge)
(Python), built directly on the Part-1 `naalp.naming` / `naalp.description` primitives — every
cryptographic and encoding operation (ML-DSA signing/verification, deterministic-CBOR body encoding,
the content-id framing, the receipt-chain construction, the A2A legal-edge table, the confused-deputy
importer check) is delegated to those, never re-implemented in the bridge. Mutation-tested.

## The card side: bridging an A2A Agent Card

| A2A-native shape | N-AALP wire object |
|---|---|
| An A2A Agent Card (raw JSON bytes from a card endpoint) | `naalp-description-import` field 3 (`foreign`, bstr) — carried octet-for-octet |
| The importer's own effect/approval declaration per skill | `naalp-description-import` field 4 (`operations`, `[* naalp-description-operation]`) |

The card bytes are never parsed or re-serialized by N-AALP (carriage, not adoption): the attestation
binds the foreign bytes' content id (so a changed card invalidates the attestation) and an N-AALP
effect mapping for the described skills, expressed in the closed effect lattice a verifier can
authorize on.

**Confused-deputy containment.** The `importer` field — the wrapping signer — is the sole
authorization identity. Verification recomputes the self-certifying signer id from the verifying key
and requires it to equal the attestation's `importer` field (`ImporterMismatch` otherwise). No field
inside the carried A2A Card — including any identity the card asserts about itself — can become the
N-AALP authorization identity: a signer can only ever import *as itself*.

```python
from naalp_a2a_bridge import bridge_card, verify_card, SkillMapping
from naalp import cose, policy

CARD_BYTES = (
    b'{"protocolVersion":"0.2.5","name":"billing-agent","url":"https://agent.example/a2a",'
    b'"skills":[{"id":"submit","name":"Submit invoice"},{"id":"get","name":"Get status"}]}'
)

card_seed = bytes([0xC1]) * 32
card_pk = cose.mldsa_keygen("ML-DSA-65", card_seed)
mappings = [
    SkillMapping("submit", policy.NON_IDEMPOTENT_WRITE, True),   # requires approval
    SkillMapping("get", policy.READ_ONLY, False),
]
im, card_obj = bridge_card(card_seed, CARD_BYTES, mappings)   # im.id() is the bound scope for a task profile

# Later, a fresh verifier holding only the wire bytes:
resolved, im2 = verify_card(card_obj, card_pk)
assert im2.foreign == CARD_BYTES                              # octet-exact recovery
submit_op, ok = im2.operation("submit")
assert ok and submit_op.effect_class() == policy.NON_IDEMPOTENT_WRITE
```

## The activity side: bridging an A2A task-state history

| A2A-native shape | N-AALP wire object |
|---|---|
| An ordered sequence of `TaskState` string observations for one task | a chain of `naalp-task-transition` objects, each `{1: task, 2: card, 3: from, 4: to, 5: seq, 6: prev}` |

Each transition is a signed, receipt-chained object bound to a card's scope by content id. The
**A2A legal-edge table** — derived from the A2A specification's start state (`submitted`), terminal
states (`completed`, `canceled`, `failed`, `rejected`; no out-edge), and interrupted states
(`input-required`, `auth-required`) — is checked on every edge **before it is ever signed**: an
illegal transition is refused before a single signature is spent on it, never deferred to whenever
the chain is next verified.

```python
from naalp_a2a_bridge import ForeignTaskEvent, bridge_activity, verify_and_recover
from naalp import cose

task_seed = bytes([0xC2]) * 32
task_pk = cose.mldsa_keygen("ML-DSA-65", task_seed)

activity = [
    ForeignTaskEvent("task-9001", "working"),
    ForeignTaskEvent("task-9001", "input-required"),
    ForeignTaskEvent("task-9001", "working"),
    ForeignTaskEvent("task-9001", "completed"),
]
transitions, activity_objs = bridge_activity(activity, im.id(), task_seed)

# A fresh verifier, holding only the wire bytes and both public keys, recovers the exact
# original activity — and non-circularly derives the bound card scope from ITS OWN
# verification of the card, never from a caller-supplied bare card-id value.
resolved_card, recovered_card_bytes, im2, verified, recovered_activity = verify_and_recover(
    card_obj, card_pk, activity_objs, task_pk,
)
assert recovered_activity == activity   # value-exact recovery of the TaskState-string sequence
```

`verify_and_recover` is the safer combined entry point: it verifies the card attestation *first* and
derives the task chain's bound scope from that verification's own content id — never from a
caller-supplied bare `card_id` value the bridge would otherwise have to trust blindly. An activity
genuinely, independently valid but bound to an *unrelated* card's scope is refused (`ForeignCard`)
rather than silently accepted because some bare id parameter happened to match.

## Failure modes

| Error kind | When |
|---|---|
| `ImporterMismatch` | The attested importer does not match the verifying key's self-certifying signer id |
| `DescMalformed` | The object is not a well-formed description/directory/import body |
| `MalformedApprovalFlag` | A `requires_approval` value outside `{0,1}` |
| `IllegalTransition` | An edge the A2A category rules forbid — including any edge out of a terminal state |
| `TaskChainBroken` | A task-transition gap or reorder |
| `ForeignCard` | A transition bound to a card other than the profile's bound A2A Agent Card |
| `UnknownTaskState` (bridge-only) | A `TaskState` string outside the closed A2A vocabulary |
| `EmptyActivity` / `ForeignTask` (bridge-only) | An empty activity, or events naming more than one task in a single chain |
| `BadSignature` | A signature that does not verify |

Every check is fail-closed: a failing object is rejected whole, returns its named error, and causes
no state change. See
[`ecosystem/naalp-a2a-bridge/examples/isolation_demo.py`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/ecosystem/naalp-a2a-bridge/examples/isolation_demo.py)
for the full runnable demonstration, including the illegal-edge and foreign-scope refusals.

## What this mapping does not decide

- **Who may append the next name-binding rotation.** The name-binding chain (the draft's Channel Surfaces section) is a separate, more general primitive than the task-state
  profile above; the policy for which key is entitled to append a rotation is a deployment concern.
- **A2A transport and card discovery.** How an A2A card endpoint is found or connected to is out of
  scope; this profile governs a *carried* card and a *carried* task-state history, not the A2A
  session.
- **Non-Go/Rust SDK ports.** The profile is graded on the Go and Rust two-implementation parity path
  against a non-circular oracle; the Python bridge above is an ecosystem package built on the Python
  SDK, and porting the profile itself to the other reference SDKs is tracked in the parity ledger.

See also: [the object model](../spec/object-model.md) and the [MCP mapping](mcp.md) for the sibling
tool-integration profile.
