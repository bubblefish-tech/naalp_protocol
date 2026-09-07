<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->
# Prompt: schema an EFFECTING N-AALP object that requires an audience

Use this template when the object you are designing is NOT read-only -- it changes state,
and in particular when it is a "consume-once" object: one whose acceptance spends a
single-use ledger resource (design.md sec.2.5.3). The baseline example of this is a
Governance/Consume object (channel `0x0004`, kind `3`).

## Instructions to give the model

1. Set `"x-naalp-effect"` to the object's real effect class:
   - `"idempotent_write"` -- repeating the same object has no additional effect.
   - `"non_idempotent_write"` -- repeating it changes state again (most consume-once objects
     are this class).
   - `"destructive"` -- it deletes or irreversibly invalidates something.
2. Include an **`"audience"` property at the schema's TOP level**:
   ```json
   "audience": {"type": "string", "maxLength": 128}
   ```
   and add `"audience"` to the top-level `"required"` list if the object cannot be
   meaningfully constructed without naming its consuming authority (this is REQUIRED for a
   consume-once object -- one whose acceptance spends a single-use ledger resource).
3. Everything else in the schema (the rest of the properties) describes the object's real
   body payload -- what is actually being consumed, approved, or changed. `audience` is
   reserved and is NOT part of that payload: the generator lifts it into the object's real
   envelope-level `audience` field (field 13) and does not duplicate it inside the CBOR body.
4. If you skip step 2 while declaring an effecting `x-naalp-effect`, the generator emits an
   `EffectingWithoutAudience` warning (or refuses the schema outright in strict mode) -- the
   object you are describing would have no way to name who is authorized to consume it, and
   design.md sec.2.5.3's audience rule would reject it at the real envelope-validation layer
   regardless.

## Worked example -- a consume request

```json
{
  "type": "object",
  "x-naalp-effect": "non_idempotent_write",
  "properties": {
    "audience": {"type": "string", "maxLength": 128},
    "resource_id": {"type": "string", "maxLength": 64},
    "quantity": {"type": "integer", "minimum": 1, "maximum": 1000}
  },
  "required": ["audience", "resource_id", "quantity"],
  "additionalProperties": false
}
```

An instance for this schema:

```json
{"audience": "ledger-authority-7", "resource_id": "res-42", "quantity": 3}
```

When this is round-tripped, the generated object carries `resource_id`/`quantity` in its
CBOR body and `audience = "ledger-authority-7"` in the real envelope field -- exactly what
the E0.2 semantic validator's consume-once audience check expects.
