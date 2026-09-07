<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->
# Prompt: author an N-AALP object-body JSON Schema

Use this template when asking an LLM to propose the shape of a NEW N-AALP object body --
the `10: any` field of a `naalp-object` -- as a JSON Schema (draft 2020-12).

## Instructions to give the model

You are designing the BODY of an N-AALP object -- one channel/kind's payload, not the
envelope around it (id, kind, channel, tier, signer, created, effect, causes, profile are
handled separately; do not include them in this schema).

Produce a single JSON Schema document, draft 2020-12, `"type": "object"` at the root, that
follows every rule below. These rules exist because the object is carried as deterministic
CBOR (RFC 8949 sec.4.2.1) over a wire whose decoder enforces fixed resource bounds; a schema
that violates them describes something that cannot actually be sent.

1. **Every property has a concrete JSON type.** Use exactly one of: `"object"`, `"array"`,
   `"string"`, `"integer"`. Do NOT use `"number"`, `"boolean"`, or `"null"` -- see the
   "Forbidden types" section below.
2. **Every string has `"maxLength"`.** Every array has `"maxItems"`. Every integer has
   `"maximum"` (or `"exclusiveMaximum"`). An unbounded construct cannot be decoded safely and
   will be REJECTED or WARNED ON by the generator.
3. **`"additionalProperties": false` on every object**, and list every field you actually use
   in `"required"` unless it is genuinely optional.
4. **Declare the object's intended effect** with the vendor extension keyword
   `"x-naalp-effect"`, one of `"read_only"`, `"idempotent_write"`, `"non_idempotent_write"`,
   `"destructive"`. This is not a standard JSON-Schema keyword; the N-AALP generator reads it,
   generic JSON-Schema tools ignore it.
5. **If the effect is anything other than `"read_only"`, include an `"audience"` property**
   (`"type": "string"`, bounded with `"maxLength"`) at the TOP level of the schema. This is a
   reserved name: the generator lifts it out of the body and places it in the object's real
   envelope-level `audience` field (field 13) -- it is never duplicated inside the CBOR body.
   Some effecting kinds (a "consume-once" kind, i.e. one that spends a single-use ledger
   resource) REQUIRE an audience; the generator warns if you declare an effecting kind with no
   `audience` property to author against.
6. **Do not use `$ref`, `oneOf`, `anyOf`, `allOf`, `not`, `if`/`then`/`else`,
   `patternProperties`, or `dependentSchemas`.** The generator maps one JSON Schema node to
   one concrete CDDL/CBOR shape; these composition keywords have no such single shape.

## Forbidden types, and why

- `"number"` -- N-AALP's CBOR value model has NO floating-point wire representation at all
  (not merely "discouraged"). If you need a fractional quantity, use a scaled integer (e.g.
  cents instead of dollars) with `"type": "integer"`.
- `"boolean"` -- N-AALP's CBOR value model has no boolean wire representation either (CBOR
  major type 7 -- simple values -- is not defined). Use an integer `0`/`1`, or better, an
  `"enum"` of two integers with self-documenting names in a comment.
- `"null"` -- same reason. Omit the field entirely instead of setting it to null.

## Worked example

```json
{
  "type": "object",
  "x-naalp-effect": "read_only",
  "properties": {
    "task_id": {"type": "string", "maxLength": 64},
    "priority": {"type": "integer", "minimum": 0, "maximum": 10},
    "tags": {
      "type": "array",
      "items": {"type": "string", "maxLength": 32},
      "maxItems": 8
    }
  },
  "required": ["task_id", "priority"],
  "additionalProperties": false
}
```

This schema is bounded (every string/array/integer has an upper bound), uses only
representable types, and is `read_only` so it needs no `audience` property.
