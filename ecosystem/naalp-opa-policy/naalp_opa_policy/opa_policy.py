# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""N-AALP OPA/Rego policy-enforcement integration for the Python SDK (Part-2 E3.2, requirement
R5.2; design.md "Governance (R5)").

Defense-in-depth, NOT a replacement: this module consults a REAL OPA (Open Policy Agent)
engine, evaluating an administrator-authored Rego policy (policies/naalp_authz.rego) against
an N-AALP object's AUTHENTICATED fields, BEFORE the SDK's own Part-1 authorization floor
(naalp.policy.Grant.authorize_object). A policy Deny -- or ANY problem reaching a decision at
all (the opa binary missing, a timeout, a parse/eval error, or the query resolving to
undefined) -- refuses the action fail-closed with the EXISTING naalp.policy.PolicyError
('EffectNotAuthorized') error: this module never invents a new wire code (naalperror.py's
119-entry registry is unchanged) and never fails open. Calling
naalp.policy.Grant.authorize_object afterward remains the caller's responsibility -- this
module adds an earlier gate, it does not remove or replace the Part-1 one.

This module performs NO Rego evaluation itself. Every policy decision is produced by
INVOKING the real `opa` binary (github.com/open-policy-agent/opa, `opa eval`) as a
subprocess against the checked-in policy directory; nothing here re-implements Rego
semantics -- doing so would be exactly the raw-text-as-enrichment / fake-verifier failure
this programme's rules forbid (naalp_draft-01/CLAUDE.md; Section A7/A11).

The ONLY fields that ever reach the OPA input document are (design.md "Governance (R5)"; the
E3.2 grounding research): the object's `effect` (int 0..3), `audience` (string, "" if
absent), `kind` (int), `channel` (int), the AUTHENTICATED `signer` (a string, resolved
through naalp.policy.resolve_auth_principal from the SAME alg+pubkey the caller already used
to successfully verify the object with naalp.envelope.verify -- NEVER `obj.signer`, which is
an unauthenticated body field the object's own author fully controls, per R-6.5 and
policy.py's own module docstring), and the caller-supplied `grant`
({principal, max_effect}) the caller already resolved for that SAME authenticated identity.
No self-asserted field (a transport tag, a client-claimed name, or the object's own bstr
`signer` field) is ever part of the input document.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import json
import os
import shutil
import subprocess
from typing import Optional

from naalp import envelope, identity, policy  # noqa: F401 (envelope re-exported for callers)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

# The checked-in policy directory this package ships (naalp_authz.rego + data.json). An
# administrator deploying this integration points OPAEngine at their OWN directory instead;
# this default is the worked example the graded bar (RED-EVIDENCE.md, isolation_demo.py, the
# F3 conformance vectors) exercises.
DEFAULT_POLICY_DIR = os.path.join(_THIS_DIR, "policies")

# The query this package's worked-example policy exposes (package naalp.authz, rule allow).
DEFAULT_QUERY = "data.naalp.authz.allow"

DEFAULT_TIMEOUT_SECONDS = 5.0


class OPAEngineError(RuntimeError):
    """Raised internally when the real `opa` process cannot be invoked, times out, or reports a
    hard parse/eval error. Never escapes OPAEngine.decide() -- decide() catches this and
    returns False (fail-closed); it is exposed for callers/tests that want to distinguish 'the
    engine could not reach a decision' from 'the engine reached Deny' at a lower level than
    decide()."""


def _locate_opa_binary(opa_binary: Optional[str]) -> str:
    """Resolve the real `opa` executable: an explicit path/name if given, else whatever `opa`
    resolves to on PATH via shutil.which. Returns the bare fallback name "opa" (never None)
    when it cannot be found on PATH, so subprocess itself raises a diagnosable
    FileNotFoundError/OSError rather than this function silently guessing a fake path --
    OPAEngine._run turns that into OPAEngineError, which decide() turns into a fail-closed
    False."""
    if opa_binary:
        return opa_binary
    return shutil.which("opa") or "opa"


class OPAEngine:
    """Wraps the real `opa eval` subprocess invocation against a checked-in policy directory.
    `policy_dir` MUST contain the administrator's .rego policy (and any supporting data.json
    config); it is loaded as a WHOLE DIRECTORY (`opa eval -d <dir>`, which recursively loads
    every *.rego/*.json/*.yaml file under it -- confirmed against `opa eval --help` and a real
    run, see RED-EVIDENCE.md), never a re-implementation of Rego's module/data-loading rules.

    Windows note: the real `opa` binary's file loader mis-parses an absolute path whose first
    component is a drive letter followed by a colon (e.g. a `-d` argument shaped like
    "<letter>:<backslash>...") as a URL with that letter as its scheme, and fails with a bogus
    "cannot find the path specified" error -- a reproduced defect in the OPA CLI's Windows path
    handling (confirmed by hand this session against opa 1.19.1; a bare relative path resolved
    from the right `cwd` does not trigger it), not a re-implementation choice. This class works
    around it by ALWAYS invoking `opa` with `cwd` set to the PARENT of `policy_dir` and passing
    only `policy_dir`'s basename on the command line -- never an absolute path -- which
    sidesteps the bug on every platform (harmless where the bug does not exist)."""

    def __init__(
        self,
        policy_dir: str = DEFAULT_POLICY_DIR,
        query: str = DEFAULT_QUERY,
        opa_binary: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._policy_dir = os.path.abspath(policy_dir)
        self._cwd = os.path.dirname(self._policy_dir)
        self._policy_dir_name = os.path.basename(self._policy_dir)
        self._query = query
        self._opa_binary = _locate_opa_binary(opa_binary)
        self._timeout_seconds = timeout_seconds

    def _run(self, input_doc: dict) -> dict:
        """Invoke the real opa binary once with `input_doc` piped as its stdin input document
        (`opa eval -I`, JSON on stdin, RFC 8259). Returns the parsed JSON result on a clean
        run. Raises OPAEngineError on ANY failure to reach a clean result: the binary
        missing/unusable (OSError -- e.g. FileNotFoundError), a timeout
        (subprocess.TimeoutExpired), non-JSON stdout, a non-zero exit code, or a top-level
        'errors' key in the engine's own JSON output (opa's documented shape for a parse/eval
        error -- confirmed by hand against a real `opa eval` run on a missing file and on a
        deliberately malformed .rego, see RED-EVIDENCE.md)."""
        payload = json.dumps(input_doc).encode("utf-8")
        try:
            proc = subprocess.run(
                [self._opa_binary, "eval", "-f", "json", "-d", self._policy_dir_name, "-I", self._query],
                input=payload,
                capture_output=True,
                cwd=self._cwd,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise OPAEngineError("opa engine unreachable: %r" % (e,)) from e
        try:
            stdout_text = proc.stdout.decode("utf-8") if proc.stdout else ""
            result = json.loads(stdout_text) if stdout_text.strip() else {}
        except ValueError as e:
            raise OPAEngineError("opa engine returned non-JSON output: %r" % (e,)) from e
        if proc.returncode != 0 or "errors" in result:
            raise OPAEngineError(
                "opa engine reported an error (exit=%d): %r"
                % (proc.returncode, result.get("errors", proc.stderr))
            )
        return result

    def decide(self, input_doc: dict) -> bool:
        """The single decision choke point: returns True iff the real OPA engine, evaluating
        the checked-in policy against `input_doc`, resolves `self._query` to the LITERAL
        Python boolean True. Fail-closed on every other outcome:
          - an unreachable/erroring engine        -> OPAEngineError, caught here -> False
          - an undefined query result              -> opa's own JSON carries no 'result' key
                                                        (or an empty 'result' list) -- confirmed
                                                        by hand: a package with no matching rule
                                                        prints bare `{}` -- -> False
          - a malformed/unexpected result shape    -> False
          - any resolved value other than exactly
            the Python bool True                    -> False
        This is the ONE place a policy decision becomes a Python bool; nothing downstream
        re-derives or second-guesses it."""
        try:
            result = self._run(input_doc)
        except OPAEngineError:
            return False  # fail-closed: an unreachable/erroring engine denies, never allows
        results = result.get("result")
        if not results:
            return False  # fail-closed: an undefined query result denies
        expressions = results[0].get("expressions")
        if not expressions:
            return False  # fail-closed: a malformed result shape denies
        return expressions[0].get("value") is True


def build_input(obj: "envelope.Object", alg: int, verified_pubkey: bytes, grant: "policy.Grant") -> dict:
    """Build the OPA input document from a REAL, already-verified N-AALP object (design.md
    "Governance (R5)": {effect, audience, kind, signer, channel, grant}). `obj` MUST already
    have passed `naalp.envelope.verify(profile, alg, verified_pubkey, ...)` -- this function
    performs no verification itself; it only reads fields off an object the caller already
    trusts because that call succeeded.

    `signer` is resolved through `naalp.policy.resolve_auth_principal` from the SAME alg+
    pubkey that verification succeeded against (R-6.5): it is `identity.signer_id(alg,
    verified_pubkey)`, the self-certifying id of the key that CRYPTOGRAPHICALLY produced the
    object's signature. It is NEVER `obj.signer` -- that is an unauthenticated body field the
    object's own author fully controls (naalp.envelope.verify only checks it is internally
    consistent with the protected header, never that it matches the pubkey the caller chose to
    verify against), so treating it as an identity would let an object's author claim to be
    any principal it likes (exactly the failure R-6.5 and naalp.policy's module docstring both
    name).

    `grant` is the caller's OWN already-resolved capability for that same authenticated
    principal (e.g. a lookup the caller performed keyed on `identity.signer_id(alg,
    verified_pubkey)`) -- never derived from anything the object itself carries."""
    principal = policy.resolve_auth_principal(
        policy.SOURCE_SIGNATURE, identity.signer_id(alg, verified_pubkey)
    )
    return {
        "effect": obj.effect,
        "audience": obj.audience,
        "kind": obj.kind,
        "channel": obj.channel,
        "signer": principal,
        "grant": {"principal": grant.principal, "max_effect": grant.max_effect},
    }


def authorize_with_policy(
    obj: "envelope.Object",
    alg: int,
    verified_pubkey: bytes,
    grant: "policy.Grant",
    engine: OPAEngine,
) -> None:
    """R5.2: the pre-execution policy consult. Builds the input strictly from authenticated
    fields (build_input), consults the real OPA engine (engine.decide), and raises the
    EXISTING `naalp.policy.PolicyError('EffectNotAuthorized')` -- reusing the Part-1 wire
    code, never inventing a new one -- on a Deny OR on any engine problem (engine.decide
    already fails closed to False for those, so this function's fail-closed behaviour is
    inherited, not re-implemented). Performs no side effect and no ledger/state change; a
    denial raises before returning, causing no state change of any kind.

    This function does NOT call `naalp.policy.Grant.authorize_object`. Callers MUST still
    call it (or an equivalent Part-1 floor check) afterward -- this is an ADDITIONAL, earlier
    gate, never a substitute for it (defense-in-depth, design.md "Governance (R5)")."""
    input_doc = build_input(obj, alg, verified_pubkey, grant)
    if not engine.decide(input_doc):
        raise policy.PolicyError(
            "EffectNotAuthorized",
            "policy engine denied the object (kind=%d channel=%d effect=%d signer=%r)"
            % (obj.kind, obj.channel, obj.effect, input_doc["signer"]),
        )
