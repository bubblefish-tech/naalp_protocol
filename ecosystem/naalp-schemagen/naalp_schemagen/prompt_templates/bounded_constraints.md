<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->
# Prompt: bound every construct in an N-AALP object-body schema

Use this template as a focused follow-up when a proposed schema already has the right
shape but is missing bounds, or when reviewing a schema an LLM produced against the
`object_body_schema` template and checking it for the specific failure mode of leaving a
construct unbounded.

## Instructions to give the model

Every JSON Schema construct below MUST carry an explicit upper bound. This mirrors N-AALP's
own decoder-resource-bounds discipline (design.md, R7): the wire decoder enforces a fixed
maximum object octet size, a fixed maximum `causes[]`/`ext`/`cext` cardinality, and a fixed
maximum CBOR nesting depth -- an unbounded body construct is the same category of problem one
level down, and the schema generator will WARN (`Unbounded`) on each of the three cases below,
or REFUSE outright in strict mode.

1. **Strings** -- every `{"type": "string", ...}` node needs `"maxLength"`. Pick the smallest
   bound that comfortably fits real values (a UUID needs 36, not 4096).
2. **Arrays** -- every `{"type": "array", ...}` node needs `"maxItems"`. Also set `"items"`
   explicitly (a schema-checked item type, not an open `{}`), so the elements themselves are
   checked too.
3. **Integers** -- every `{"type": "integer", ...}` node needs `"maximum"` (or
   `"exclusiveMaximum"`). Prefer a `"minimum"` of `0` unless the value is genuinely signed.

## Before / after

Before (three unbounded constructs -- each produces an `Unbounded` warning):

```json
{
  "type": "object",
  "x-naalp-effect": "read_only",
  "properties": {
    "notes": {"type": "string"},
    "history": {"type": "array", "items": {"type": "string", "maxLength": 32}},
    "retry_count": {"type": "integer", "minimum": 0}
  },
  "required": ["notes"],
  "additionalProperties": false
}
```

After (every construct bounded -- zero `Unbounded` warnings):

```json
{
  "type": "object",
  "x-naalp-effect": "read_only",
  "properties": {
    "notes": {"type": "string", "maxLength": 2048},
    "history": {
      "type": "array",
      "items": {"type": "string", "maxLength": 32},
      "maxItems": 64
    },
    "retry_count": {"type": "integer", "minimum": 0, "maximum": 32}
  },
  "required": ["notes"],
  "additionalProperties": false
}
```

Ask the model to re-check its own output against this checklist before returning it: does
every `"string"` node have `"maxLength"`, every `"array"` node have `"maxItems"`, and every
`"integer"` node have `"maximum"` or `"exclusiveMaximum"`? If any answer is "no", the schema
is not ready to generate CDDL from yet.
