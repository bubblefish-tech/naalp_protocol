# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Validate every N-AALP code-point registry CSV against its JSON Schema (draft 2020-12).

A structural verifier for the four machine-readable registries under vectors/registry/*.csv
(signatures, multicodec, protocols, channels), mirroring the substrate project's
validate-registries.py. For each registry it:

  (1) converts the CSV to a JSON array of row objects (header row -> object keys), coercing the
      declared-integer columns from their CSV string form to int so the schema's integer/range
      constraints actually apply (CSV has no types of its own). An empty integer cell (e.g. the
      reserved SLH-DSA row's cose_alg) is left as "" so the schema's own if/then/else catches it
      rather than crashing here;

  (2) validates the array against its schema in vectors/registry/schemas/, catching wrong-format
      code points, missing/empty required columns, out-of-enum tokens, out-of-range integers, and
      the effect<->variable_effect / status<->cose_alg correlations the schemas encode; and

  (3) runs a composite-key duplicate pass that JSON Schema CANNOT express -- JSON Schema's
      uniqueItems only compares whole objects, never a chosen key across rows, so duplicate code
      points (or duplicate (channel_id, kind_code) pairs) must be caught here.

Exit 0 only if every registry validates AND has no duplicate keys; exit 1 on any failure.

Stdlib only. If the third-party `jsonschema` package is importable it is used (and each schema is
first self-checked as a valid draft-2020-12 schema); otherwise a built-in validator covers the
JSON Schema subset these registry schemas use (type, enum, const, pattern, min/maxLength,
minimum/maximum, required, additionalProperties:false, properties, items, oneOf, if/then/else).
"""
import csv
import json
import os
import re
import sys

try:
    from jsonschema import Draft202012Validator  # type: ignore
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # scripts/ -> repo root
REG = os.path.join(ROOT, "vectors", "registry")
SCH = os.path.join(ROOT, "vectors", "registry", "schemas")

# Per registry: the schema file, which columns are integers (coerced from the CSV string), and the
# column(s) that form the uniqueness key the duplicate pass enforces.
#   signatures: keyed by algorithm name (cose_alg is empty for the reserved row, so name is the key).
#   channels  : keyed by the (channel_id, kind_code) PAIR -- channel_id repeats across its kinds.
REGISTRIES = [
    {"csv": "signatures.csv", "schema": "signatures.schema.json",
     "int_cols": ["cose_alg", "nist_level"], "key_cols": ["name"]},
    {"csv": "multicodec.csv", "schema": "multicodec.schema.json",
     "int_cols": [], "key_cols": ["code"]},
    {"csv": "protocols.csv", "schema": "protocols.schema.json",
     "int_cols": [], "key_cols": ["protocol_id"]},
    {"csv": "channels.csv", "schema": "channels.schema.json",
     "int_cols": ["kind_code"], "key_cols": ["channel_id", "kind_code"]},
]


def csv_to_rows(path, int_cols):
    """Read a registry CSV into a list of row dicts (header row -> keys).

    Empty cells stay as "" so a required-but-blank column trips the schema's minLength/enum instead
    of vanishing. A declared-integer column is coerced to int when it holds an integer literal; a
    blank or non-integer value is left as the original string so the schema's type check reports it
    rather than this function crashing.
    """
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return rows
        for raw in reader:
            row = dict(raw)
            for col in int_cols:
                v = row.get(col, "")
                if isinstance(v, str) and v.strip().lstrip("-").isdigit():
                    row[col] = int(v.strip())
            rows.append(row)
    return rows


def find_duplicate_keys(rows, key_cols):
    """Return a list of duplicate findings for the registry's uniqueness key.

    The key is the tuple of key_cols (a single column for a point-code registry, or the
    (channel_id, kind_code) pair for channels). An exact repeat of the key on two rows is a finding;
    this is the single-/composite-field uniqueness JSON Schema cannot express.
    """
    findings = []
    seen = {}
    label = "+".join(key_cols)
    for i, row in enumerate(rows):
        key = tuple(str(row.get(c, "")) for c in key_cols)
        shown = key[0] if len(key) == 1 else key
        if key in seen:
            findings.append(f"duplicate {label} {shown!r} (rows {seen[key]} and {i})")
        else:
            seen[key] = i
    return findings


# --------------------------------------------------------------------------------------------------
# Built-in JSON Schema subset validator (used only when the `jsonschema` package is not importable).
# --------------------------------------------------------------------------------------------------

def _type_ok(inst, t):
    if t == "string":
        return isinstance(inst, str)
    if t == "integer":
        return isinstance(inst, int) and not isinstance(inst, bool)
    if t == "number":
        return isinstance(inst, (int, float)) and not isinstance(inst, bool)
    if t == "boolean":
        return isinstance(inst, bool)
    if t == "array":
        return isinstance(inst, list)
    if t == "object":
        return isinstance(inst, dict)
    if t == "null":
        return inst is None
    return True


def _typename(inst):
    if isinstance(inst, bool):
        return "boolean"
    if isinstance(inst, int):
        return "integer"
    if isinstance(inst, str):
        return "string"
    if isinstance(inst, list):
        return "array"
    if isinstance(inst, dict):
        return "object"
    if inst is None:
        return "null"
    return type(inst).__name__


def hv_errors(inst, schema, path):
    """Validate `inst` against `schema`, returning a list of (path, message) findings. Covers the
    keyword subset the registry schemas use."""
    errs = []
    if "type" in schema:
        t = schema["type"]
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(inst, tt) for tt in types):
            return [(path, f"expected type {t}, got {_typename(inst)}")]  # type wrong: stop here
    if "const" in schema and inst != schema["const"]:
        errs.append((path, f"expected const {schema['const']!r}, got {inst!r}"))
    if "enum" in schema and inst not in schema["enum"]:
        errs.append((path, f"{inst!r} not in enum {schema['enum']}"))
    if isinstance(inst, str):
        if "minLength" in schema and len(inst) < schema["minLength"]:
            errs.append((path, f"string shorter than minLength {schema['minLength']}"))
        if "maxLength" in schema and len(inst) > schema["maxLength"]:
            errs.append((path, f"string longer than maxLength {schema['maxLength']}"))
        if "pattern" in schema and re.search(schema["pattern"], inst) is None:
            errs.append((path, f"{inst!r} does not match pattern {schema['pattern']!r}"))
    if isinstance(inst, int) and not isinstance(inst, bool):
        if "minimum" in schema and inst < schema["minimum"]:
            errs.append((path, f"{inst} < minimum {schema['minimum']}"))
        if "maximum" in schema and inst > schema["maximum"]:
            errs.append((path, f"{inst} > maximum {schema['maximum']}"))
    if "oneOf" in schema:
        n = sum(1 for sub in schema["oneOf"] if not hv_errors(inst, sub, path))
        if n != 1:
            errs.append((path, f"matched {n} of oneOf subschemas (expected exactly 1)"))
    if isinstance(inst, list) and "items" in schema:
        for i, item in enumerate(inst):
            errs.extend(hv_errors(item, schema["items"], f"{path}[{i}]"))
    if isinstance(inst, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in inst:
                errs.append((path, f"missing required property {req!r}"))
        if schema.get("additionalProperties") is False:
            for k in inst:
                if k not in props:
                    errs.append((path, f"additional property {k!r} not allowed"))
        for k, subschema in props.items():
            if k in inst:
                errs.extend(hv_errors(inst[k], subschema, f"{path}/{k}"))
        if "if" in schema:
            branch = "then" if not hv_errors(inst, schema["if"], path) else "else"
            if branch in schema:
                errs.extend(hv_errors(inst, schema[branch], path))
    return errs


def validate_array(rows, schema):
    """Return a sorted list of "loc: message" strings for every schema violation in `rows`.

    Uses the `jsonschema` package when available (also self-checking the schema is valid
    draft-2020-12), else the built-in subset validator above.
    """
    if HAVE_JSONSCHEMA:
        Draft202012Validator.check_schema(schema)  # the schema itself must be valid draft 2020-12
        validator = Draft202012Validator(schema)
        out = []
        for e in sorted(validator.iter_errors(rows), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in e.path) or "<root>"
            out.append(f"{loc}: {e.message}")
        return out
    findings = hv_errors(rows, schema, "<root>")
    return [f"{loc or '<root>'}: {msg}" for loc, msg in findings]


def main():
    engine = "jsonschema" if HAVE_JSONSCHEMA else "built-in stdlib validator"
    print(f"N-AALP registry validation (engine: {engine})")
    print()
    fail = 0
    for r in REGISTRIES:
        csv_path = os.path.join(REG, r["csv"])
        sch_path = os.path.join(SCH, r["schema"])
        if not os.path.exists(csv_path):
            print(f"MISSING csv    : {r['csv']}")
            fail += 1
            continue
        if not os.path.exists(sch_path):
            print(f"MISSING schema : {r['schema']}")
            fail += 1
            continue
        try:
            with open(sch_path, encoding="utf-8") as f:
                schema = json.load(f)
            rows = csv_to_rows(csv_path, r["int_cols"])
            errors = validate_array(rows, schema)
            dups = find_duplicate_keys(rows, r["key_cols"])
            if errors or dups:
                print(f"INVALID : {r['csv']} <- {r['schema']}")
                for e in errors:
                    print(f"    schema  @ {e}")
                for d in dups:
                    print(f"    dup     : {d}")
                fail += 1
            else:
                print(f"ok      : {r['csv']} <- {r['schema']}  ({len(rows)} rows)")
        except Exception as e:  # noqa: BLE001 - any parse/schema failure is a gate failure
            first = str(e).splitlines()[0] if str(e) else ""
            print(f"INVALID : {r['csv']} <- {r['schema']}\n    {type(e).__name__}: {first}")
            fail += 1
    print()
    if fail:
        print(f"REGISTRY VALIDATION: {fail} failure(s)")
        sys.exit(1)
    print(f"REGISTRY VALIDATION: ALL PASS ({len(REGISTRIES)} registries)")
    sys.exit(0)


if __name__ == "__main__":
    main()
