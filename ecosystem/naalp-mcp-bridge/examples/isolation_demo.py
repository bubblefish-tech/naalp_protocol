# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A9 isolation demonstration for the N-AALP MCP tool-integration bridge (E2.1/R4.1-4.3): carry
a FOREIGN-NATIVE MCP tool call -- a `tools/list` tool definition (with real MCP annotations) and
a JSON-RPC 2.0 `tools/call` request, exactly as a developer's MCP stack hands them over -- into a
signed N-AALP object with a real deterministic ML-DSA-65 key, then LATER, standing alone in a
fresh Python process's worth of state, verify it and RECOVER the exact foreign call. Then shows
the four properties the whole bridge exists to enforce: (1) octet-exact recovery, (2) the
annotation->effect mapping is genuinely applied, (3) a tampered object fails closed with a named
error, and (4) an approval binds the EXACT call -- a changed argument invalidates it.

Run (from ecosystem/naalp-mcp-bridge/, using the real Python on this machine, not the Microsoft
Store `python` stub):
    python examples/isolation_demo.py
"""
import os
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-mcp-bridge
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mcp_bridge import (  # noqa: E402
    carry_tool_call_from_objects, receive_tool_call, bridged_call_request,
)
from naalp import approval, cose, envelope, mcp, policy  # noqa: E402


def _seed(b):
    return bytes([b]) * 32


def main() -> int:
    print("=" * 72)
    print("PASS 1: carry a foreign-native MCP tool call into a signed N-AALP object")
    print("=" * 72)

    # Exactly what a developer's MCP client already has in hand: a tool definition from
    # `tools/list` (carrying the tool's MCP behavioural annotations), and a JSON-RPC 2.0
    # `tools/call` request naming that tool and its arguments.
    tool_definition = {
        "name": "transfer_funds",
        "description": "Transfer funds between two accounts",
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    }
    call_request = {
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "transfer_funds", "arguments": {"to": "acct-778-441", "amount": 500000}},
    }

    signer_seed = _seed(0xC1)
    signer_pk = cose.mldsa_keygen("ML-DSA-65", signer_seed)

    carried = carry_tool_call_from_objects(
        tool_definition, call_request, signer_seed=signer_seed, created=1_800_000_000_000,
    )
    print("signed McpToolCall object: %d bytes" % len(carried.signed_object))
    print("annotation-mapped effect: %s" % policy.safety_label_name(carried.annotation_mapped_effect))
    print("declared effect (signer attests): %s" % policy.safety_label_name(carried.declared_effect))
    print("call-binding content id: %s" % carried.call_binding_content_id.hex())

    print()
    print("=" * 72)
    print("PASS 2: LATER, standing alone, verify it and RECOVER the exact foreign call")
    print("=" * 72)
    # Simulate "later, standing alone": a fresh verify starting from nothing but the wire bytes
    # and the signer's public key -- no state is shared with PASS 1 beyond the signed bytes.
    recv = receive_tool_call(carried.signed_object, cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, signer_pk)
    print("verified. enforced effect: %s (mismatch=%r)"
          % (policy.safety_label_name(recv.enforced_effect), recv.mismatch))

    # (1) octet-exact recovery: the recovered foreign octets are byte-identical to what was
    # carried, and the reconstructed JSON-RPC request is exactly the original.
    assert recv.tool_bytes == carried.tool_bytes
    assert recv.args_bytes == carried.args_bytes
    rebuilt_request = bridged_call_request(recv, rpc_id=7)
    assert rebuilt_request == call_request
    print("PROPERTY (1) octet-exact recovery: PASS "
          "(recovered tool/args bytes byte-identical; JSON-RPC request recovers exactly)")

    # (2) the annotation->effect mapping is genuinely applied: this tool's own annotations
    # (readOnlyHint=false, destructiveHint=true) map to `destructive`, and the honest signer's
    # declared effect agrees -- enforced == destructive, no mismatch.
    assert recv.annotation_mapped_effect == policy.DESTRUCTIVE
    assert recv.enforced_effect == policy.DESTRUCTIVE
    assert not recv.mismatch
    print("PROPERTY (2) annotation->effect mapping applied: PASS (destructiveHint=true -> destructive)")

    print()
    print("=" * 72)
    print("PASS 3: a tampered object fails closed with a named error")
    print("=" * 72)
    tampered = bytearray(carried.signed_object)
    tampered[-1] ^= 0xFF
    try:
        receive_tool_call(bytes(tampered), cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, signer_pk)
        print("FAIL: a tampered signature verified -- this would be a security bug")
        return 1
    except envelope.EnvelopeError as e:
        print("PROPERTY (3) tampered object rejected fail-closed: PASS (kind=%s)" % e.kind)
        assert e.kind == "BadSignature"

    print()
    print("=" * 72)
    print("PASS 4: an approval binds the EXACT call -- a changed argument invalidates it")
    print("=" * 72)
    approver_seed = _seed(0xC2)
    approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)
    rec = approval.ApprovalRecord(
        recv.call_binding_content_id, "approver-demo-1", policy.DESTRUCTIVE, b"\x09" * 8,
        9_999_999_999_999, "",
    )
    sig = approval.sign_approval(rec, cose.ALG_MLDSA65, approver_seed)

    # A DIFFERENT call -- same tool, DIFFERENT arguments -- carried and verified the same way.
    other_call = {
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "transfer_funds", "arguments": {"to": "acct-999-000", "amount": 500000}},
    }
    other_carried = carry_tool_call_from_objects(
        tool_definition, other_call, signer_seed=signer_seed, created=1_800_000_000_001,
    )
    other_recv = receive_tool_call(other_carried.signed_object, cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, signer_pk)
    assert other_recv.call_binding_content_id != recv.call_binding_content_id

    with tempfile.TemporaryDirectory() as d:
        ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
        try:
            try:
                other_recv.authorize(rec, cose.ALG_MLDSA65, approver_pk, sig, "requester-demo-1", 1, ledger)
                print("FAIL: an approval for the ORIGINAL call authorized a DIFFERENT call")
                return 1
            except mcp.McpError as e:
                print("PROPERTY (4a) wrong-args approval rejected: PASS (kind=%s)" % e.kind)
                assert e.kind == "ApprovalRequired"

            # The SAME approval still authorizes the call it was actually bound to.
            recv.authorize(rec, cose.ALG_MLDSA65, approver_pk, sig, "requester-demo-1", 1, ledger)
            print("PROPERTY (4b) approval authorizes the exact call it was bound to: PASS")

            # And it is single-use: a replay against the same call is refused.
            try:
                recv.authorize(rec, cose.ALG_MLDSA65, approver_pk, sig, "requester-demo-1", 1, ledger)
                print("FAIL: a consumed approval authorized a second time")
                return 1
            except approval.ApprovalError as e:
                print("PROPERTY (4c) replay rejected single-use: PASS (kind=%s)" % e.kind)
                assert e.kind == "AlreadyConsumed"
        finally:
            ledger.close()

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
