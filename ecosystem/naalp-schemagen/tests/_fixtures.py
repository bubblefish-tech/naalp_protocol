# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Shared JSON-Schema fixtures for the naalp-schemagen test suite. No absolute paths."""

SIGNER = bytes.fromhex("5349474e45525f41")  # "SIGNER_A" -- a fixed synthetic signer
CREATED = 1785000000000

# --- Schema A: read_only, Control/Hello (0x0000, kind 0, effect read_only=0) -----------------
SCHEMA_TASK_NOTE = {
    "type": "object",
    "x-naalp-effect": "read_only",
    "properties": {
        "task_id": {"type": "string", "maxLength": 64},
        "priority": {"type": "integer", "minimum": 0, "maximum": 10},
        "tags": {
            "type": "array",
            "items": {"type": "string", "maxLength": 32},
            "maxItems": 8,
        },
    },
    "required": ["task_id", "priority"],
    "additionalProperties": False,
}
INSTANCE_TASK_NOTE = {"task_id": "abc123", "priority": 7, "tags": ["urgent", "review"]}
INSTANCE_TASK_NOTE_BAD = {"task_id": "abc123", "priority": 99}  # priority out of bounds

# --- Schema B: effecting, Governance/Consume (0x0004, kind 3, effect non_idempotent_write=2) -
SCHEMA_CONSUME_REQUEST = {
    "type": "object",
    "x-naalp-effect": "non_idempotent_write",
    "properties": {
        "audience": {"type": "string", "maxLength": 128},
        "resource_id": {"type": "string", "maxLength": 64},
        "quantity": {"type": "integer", "minimum": 1, "maximum": 1000},
    },
    "required": ["audience", "resource_id", "quantity"],
    "additionalProperties": False,
}
INSTANCE_CONSUME_REQUEST = {"audience": "ledger-authority-7", "resource_id": "res-42", "quantity": 3}
INSTANCE_CONSUME_REQUEST_BAD = {"audience": "ledger-authority-7", "resource_id": "res-42", "quantity": 5000}

# --- A schema declaring an effecting kind but omitting the reserved 'audience' property -------
SCHEMA_EFFECTING_NO_AUDIENCE = {
    "type": "object",
    "x-naalp-effect": "non_idempotent_write",
    "properties": {
        "resource_id": {"type": "string", "maxLength": 64},
        "quantity": {"type": "integer", "minimum": 1, "maximum": 1000},
    },
    "required": ["resource_id", "quantity"],
    "additionalProperties": False,
}
INSTANCE_EFFECTING_NO_AUDIENCE = {"resource_id": "res-1", "quantity": 1}
