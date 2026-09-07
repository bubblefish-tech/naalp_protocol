# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""D6 Layer 1 -- the structured refusal-log sink for the N-AALP HITL interceptor (NIST SP
800-53 AU-2/AU-3 audit baseline).

Before this task the interceptor raised a named error on every refusal and persisted NOTHING:
no durable record of what was refused, when, where, from whom, why, or under which approver's
identity. That falls short of even the AU-3 minimum ("content of audit records"), which
requires every auditable event to record: what type of event occurred, when it occurred, where
it occurred, the source of the event, the outcome, and the identity of any individuals or
subjects associated with the event.

`RefusalLogEntry` carries exactly those six fields for one HITL refusal. `RefusalLog` is the
pluggable sink contract (one method, `record`), mirroring the existing pluggable
`HumanInterface` in interceptor.py. `JsonlRefusalLog` is the default sink: an append-only JSONL
file, written with the same persist-before-ack discipline as the Part-1 consume ledger
(naalp.approval.Ledger.consume) -- flush + fsync before `record()` returns, so a crash
immediately after a successful call can never lose the entry it just acknowledged.
"""
import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RefusalLogEntry:
    """The six AU-3 fields persisted for ONE HITL refusal.

    what_kind / what_content_id  -- WHAT: the action's kind and the hex content id of the exact
                                     args it was refused for.
    when_ms                      -- WHEN: the interceptor's own clock, epoch milliseconds (never
                                     a caller- or approver-supplied clock).
    where_identity / where_audience -- WHERE: this interceptor's own identity and the audience
                                        (use context) it serves.
    source_principal              -- SOURCE: the requesting party/principal that asked for the
                                      action (empty string when the caller supplied none).
    outcome_reason                 -- OUTCOME: the refusal reason -- the exact
                                      naalp.approval.ApprovalError.kind (or HITLError.kind) that
                                      was raised (e.g. "ApprovalDenied", "BadSignature").
    approver_identity              -- IDENTITY: the approver identity named in the presented
                                      approval record, when one exists (empty string when no
                                      approval object was ever produced, e.g. a human decline).
    """

    what_kind: str
    what_content_id: str  # hex
    when_ms: int
    where_identity: str
    where_audience: str
    source_principal: str
    outcome_reason: str
    approver_identity: str

    def to_dict(self):
        """The AU-3 fields as a plain JSON-serializable dict, in a fixed field order."""
        return {
            "what_kind": self.what_kind,
            "what_content_id": self.what_content_id,
            "when_ms": self.when_ms,
            "where_identity": self.where_identity,
            "where_audience": self.where_audience,
            "source_principal": self.source_principal,
            "outcome_reason": self.outcome_reason,
            "approver_identity": self.approver_identity,
        }


class RefusalLog:
    """The pluggable AU-3 sink contract: given a fully-populated `RefusalLogEntry`, persist it
    durably before returning. A concrete sink MUST raise on a persistence failure rather than
    return normally having recorded nothing (fail-closed) -- silently swallowing a logging
    failure would let a refusal happen with no durable trace of it, exactly the gap this task
    closes."""

    def record(self, entry: RefusalLogEntry) -> None:
        raise NotImplementedError


class JsonlRefusalLog(RefusalLog):
    """The default AU-3 sink: an append-only JSONL file, one line per refusal. `record()`
    writes the entry, flushes, and fsyncs the file descriptor before returning
    (persist-before-ack, matching naalp.approval.Ledger.consume's own durability discipline) --
    so a crash the instant after `record()` returns cannot lose the entry it just
    acknowledged."""

    def __init__(self, path: str):
        self._path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    @property
    def path(self) -> str:
        return self._path

    def record(self, entry: RefusalLogEntry) -> None:
        line = json.dumps(entry.to_dict(), sort_keys=True) + "\n"
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        f = os.fdopen(fd, "a", encoding="utf-8")
        try:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        finally:
            f.close()

    def read_all(self):
        """Read back every persisted entry as a list of dicts, in append order. Test/audit
        convenience only -- not part of the RefusalLog contract (a sink need not be readable
        the same way it was written; e.g. a remote syslog sink)."""
        if not os.path.exists(self._path):
            return []
        out = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
