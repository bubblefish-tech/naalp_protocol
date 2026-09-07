# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Demonstrates the N-AALP mixed-mode HTTP discrimination endpoint in ISOLATION (A9): a
concrete input for each path producing a concrete, correct output, independent of any test
harness. Imports the real Part-1 `naalp` SDK -- nothing here is faked.

Run (from ecosystem/naalp-mixed-mode/), using the real Python interpreter for this platform
(on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve ahead of a
real install on PATH and hang, so invoke the actual interpreter binary directly rather than the
bare `python` command):
    python scripts/isolation_demo.py
"""
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-mixed-mode
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mixed_mode import MixedModeEndpoint, MigrationPolicy  # noqa: E402
from naalp import carriage, cose, envelope, policy  # noqa: E402

ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC
SELF_AUTHORITY = "svc:mixed-mode-endpoint"
BRIDGE_CHANNEL = 0x000D
CARRIAGE_KIND = 0


def main():
    seed = bytes([0x42]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    grants = {pk.hex(): policy.Grant(principal=pk.hex(), max_effect=policy.NON_IDEMPOTENT_WRITE)}
    migration = MigrationPolicy(deprecated_since_epoch_seconds=1_700_000_000, sunset_epoch_seconds=1_800_000_000)
    endpoint = MixedModeEndpoint(
        profile=PROFILE, alg=ALG, pubkey=pk, self_authority=SELF_AUTHORITY, grants=grants,
        consume_once_kinds=frozenset({(BRIDGE_CHANNEL, CARRIAGE_KIND)}), migration_policy=migration,
        allow_legacy=True,  # AC4: this demo exercises the legacy path (2)-(4), so opt in explicitly.
    )

    print("--- (1) strict signed N-AALP envelope, read_only, correct audience -> succeeds ---")
    foreign = b'{"jsonrpc":"2.0","method":"tools/call","params":{}}'
    cb = carriage.carry(0x01, carriage.CLASS_JSONRPC, 0, b"corr-1", "tools/call", foreign)
    obj = envelope.Object(
        kind=CARRIAGE_KIND, channel=BRIDGE_CHANNEL, signer=pk, created=1, effect=policy.READ_ONLY,
        body=cb.to_value(), profile=PROFILE, audience=SELF_AUTHORITY,
    )
    signed = envelope.sign(obj, ALG, seed)
    result = endpoint.handle(signed)
    print("  mode=%s effect=%d headers=%r" % (result.mode, result.effect, result.headers))
    assert result.mode == "strict" and result.effect == policy.READ_ONLY

    print("--- (2) legacy NPAMP-CC-HTTP JSON body, no claims -> read-only-equivalent ---")
    body = json.dumps({"tool": "search", "query": "n-aalp"}).encode("utf-8")
    result = endpoint.handle(body)
    print("  mode=%s effect=%d foreign_len=%d headers=%r" % (
        result.mode, result.effect, len(result.carriage_body.foreign), result.headers))
    assert result.mode == "legacy" and result.effect == policy.READ_ONLY
    assert result.carriage_body.foreign == body

    print("--- (3) legacy JSON claiming an elevated effect -> refused (D15) ---")
    try:
        endpoint.handle(json.dumps({"effect": policy.DESTRUCTIVE}).encode("utf-8"))
        raise SystemExit("FAIL: elevated legacy effect claim was not refused")
    except policy.PolicyError as e:
        print("  refused as expected: %s" % e.kind)
        assert e.kind == "UnauthenticatedPrincipal"

    print("--- (4) legacy JSON targeting a consume-once kind, self-asserted audience -> refused ---")
    try:
        endpoint.handle(json.dumps({
            "channel": BRIDGE_CHANNEL, "kind": CARRIAGE_KIND, "effect": 0,
            "audience": SELF_AUTHORITY,
        }).encode("utf-8"))
        raise SystemExit("FAIL: self-asserted audience was treated as authoritative")
    except envelope.EnvelopeError as e:
        print("  refused as expected: %s" % e.kind)
        assert e.kind == "WrongAudience"

    print("--- (5) tighten to strict-only: legacy now refused outright ---")
    migration.tighten_to_strict()
    try:
        endpoint.handle(b'{"tool": "search"}')
        raise SystemExit("FAIL: legacy carriage was accepted after tightening to strict")
    except Exception as e:
        print("  refused as expected: %s" % getattr(e, "kind", e))
        assert getattr(e, "kind", None) == "LegacyRefused"
    result = endpoint.handle(signed)
    print("  strict still works: mode=%s headers=%r" % (result.mode, result.headers))
    assert result.mode == "strict" and result.headers == {}

    print("ALL ISOLATION DEMOS PASSED")


if __name__ == "__main__":
    main()
