# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for K5, the N-AALP Governance Kit's offline verifier and replay tool
(ecosystem/naalp-governance-verify/naalp_governance_verify/verify.py). Every assertion here would
fail if its target function were replaced by a constant return (anti-fake rule A5).

Non-circularity (F3): every signed record used to build a test chain is independently decoded
through `naalp.ez.verify` -- the same real, already-graded Part-1 core -- to obtain the content
id used to wire the NEXT record's `causes[]`, never through `naalp_governance_verify`'s own code
(the module under test). Tamper fixtures (bad signature, broken referent, out-of-order link,
duplicate content id, truncated log) are hand-constructed byte edits, never derived from
`verify_chain`'s own output.

MIXED-KIND chains throughout: every fixture spans at least three DIFFERENT (channel, kind) pairs
(Bridge/Carriage, Governance/Approval, Audit/Receipt) in one log, proving K5-3 -- this module
reconstructs causal order and verifies without regard to which "kind" of governed action each
record is, and without any framework SDK import.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-governance-verify/tests/test_verify.py -v
"""
import os
import struct
import sys

import pytest

# ecosystem/naalp-governance-verify's package dir name has hyphens and so cannot itself be part
# of a dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path
# so `naalp_governance_verify` (the underscore package, sibling of tests/) is importable
# regardless of invocation cwd -- same convention as naalp-mcp-hook/tests/test_mcp_hook.py.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_governance_verify.verify import (
    ChainVerifyError, LogMalformed, SignatureInvalid, UnresolvedSigner,
    BrokenReferent, ChainOrderBroken,
    read_log, verify_chain, replay, verify_and_replay, k0_payload,
    VERIFICATION_CHANNEL, VERIFICATION_KIND, sign_verification_receipt,
)
from naalp import cbor, cose, envelope, ez
from naalp.cbor import U, B, A, M

# --- fixture channels/kinds: three genuinely different (channel, kind) surfaces ----------------
BRIDGE, CARRIAGE = 0x000D, 0     # variable effect
GOVERNANCE, APPROVAL = 0x0004, 1  # fixed effect (NonIdempotentWrite)
AUDIT, RECEIPT = 0x000B, 0        # fixed effect (NonIdempotentWrite)


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x31):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


def _sign(signer, channel, kind, body, causes=(), created=None, effect=None):
    """Sign through the real core and independently decode (F3 -- via naalp.ez.verify, NOT
    through naalp_governance_verify) to recover the content id for wiring the NEXT record's
    causes[]."""
    signed = signer.sign(channel, kind, body, effect=effect, created=created, causes=list(causes))
    obj = ez.verify(signer.public_key, signed)
    return signed, obj.id


def _frame(records):
    """The exact length-prefixed framing K1's/K3's ChainRecorder write -- built independently
    here (never by calling naalp_governance_verify.read_log's own writer, since K5 has none;
    matches the real recorder's on-wire shape byte-for-byte)."""
    out = bytearray()
    for r in records:
        out += struct.pack(">I", len(r))
        out += r
    return bytes(out)


def _mixed_chain(signer):
    """A three-record, three-(channel,kind) causal chain: root (Bridge/Carriage) -> middle
    (Governance/Approval) -> leaf (Audit/Receipt), each in a DIFFERENT channel/kind, signed by
    ONE signer, appended in causal order."""
    root_body = M([(U(1), B(b"root-payload"))])
    root, root_cid = _sign(signer, BRIDGE, CARRIAGE, root_body, effect=2, created=1000)

    mid_body = M([(U(1), B(b"approval-payload"))])
    mid, mid_cid = _sign(signer, GOVERNANCE, APPROVAL, mid_body, causes=(root_cid,), created=2000)

    leaf_body = M([(U(1), B(b"receipt-payload"))])
    leaf, leaf_cid = _sign(signer, AUDIT, RECEIPT, leaf_body, causes=(mid_cid,), created=3000)

    return [root, mid, leaf], [root_cid, mid_cid, leaf_cid]


# --- read_log -------------------------------------------------------------------------------

def test_read_log_round_trips_a_recorded_chain():
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    log_bytes = _frame(records)
    recovered = read_log(log_bytes)
    assert recovered == records
    assert len(recovered) == 3


def test_read_log_accepts_a_stream_object_not_only_bytes():
    import io
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    stream = io.BytesIO(_frame(records))
    recovered = read_log(stream)
    assert recovered == records


def test_read_log_rejects_truncated_log():
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    log_bytes = _frame(records)
    truncated = log_bytes[:-5]  # chop mid final record
    with pytest.raises(LogMalformed) as excinfo:
        read_log(truncated)
    assert excinfo.value.kind == "E_LOG_MALFORMED"


def test_read_log_rejects_truncated_length_prefix():
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    log_bytes = _frame(records) + b"\x00\x01"  # a dangling 2-byte length prefix
    with pytest.raises(LogMalformed):
        read_log(log_bytes)


# --- verify_chain: accept the honest, mixed-kind path -------------------------------------------

def test_verify_chain_accepts_a_real_mixed_kind_chain():
    signer = _signer()
    records, cids = _mixed_chain(signer)
    chain = verify_chain(records, signer.public_key)
    assert [l.content_id for l in chain.links] == cids
    assert [l.channel for l in chain.links] == [BRIDGE, GOVERNANCE, AUDIT]
    assert [l.kind for l in chain.links] == [CARRIAGE, APPROVAL, RECEIPT]
    # a strictly linear causal chain replays in the SAME order it was appended
    assert chain.replay_order == (0, 1, 2)


def test_verify_and_replay_returns_links_in_causal_order():
    signer = _signer()
    records, cids = _mixed_chain(signer)
    replayed = verify_and_replay(records, signer.public_key)
    assert [l.content_id for l in replayed] == cids


def test_verify_chain_accepts_empty_log():
    chain = verify_chain([], b"\x00" * 32)
    assert chain.links == ()
    assert chain.replay_order == ()


def test_k0_payload_recovers_opaque_payload_for_a_k0_shaped_link():
    # naalp_kit.binding.build_body's own shape: a single opaque bstr field, key 1 -- the SAME
    # field number this test's own mixed-chain bodies happen to use, so k0_payload recovers it.
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    chain = verify_chain(records, signer.public_key)
    assert k0_payload(chain.links[0]) == b"root-payload"
    assert k0_payload(chain.links[1]) == b"approval-payload"


# --- verify_chain: fail-closed on a bad signature (E_VERIFY) ------------------------------------

def test_verify_chain_rejects_a_tampered_signature():
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    tampered = list(records)
    mutated = bytearray(tampered[1])
    mutated[-1] ^= 0xFF  # flip the last byte -- inside the ML-DSA signature
    tampered[1] = bytes(mutated)
    with pytest.raises(SignatureInvalid) as excinfo:
        verify_chain(tampered, signer.public_key)
    assert excinfo.value.kind == "E_VERIFY"
    assert excinfo.value.index == 1


def test_verify_chain_rejects_bytes_that_are_not_a_signed_object_at_all_multi_signer_path():
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    garbage = list(records)
    garbage[0] = b"not a cose sign1 object at all"
    resolver = {signer.signer_id.encode("utf-8"): signer.public_key}
    with pytest.raises(SignatureInvalid) as excinfo:
        verify_chain(garbage, resolver)
    assert excinfo.value.kind == "E_VERIFY"
    assert excinfo.value.index == 0


# --- verify_chain: fail-closed on a missing referent (E_REFERENT) -------------------------------

def test_verify_chain_rejects_a_missing_referent():
    signer = _signer()
    ghost_cid = bytes([0x20, 0x30]) + b"\x00" * 48  # well-formed 50-byte id, present nowhere
    root_body = M([(U(1), B(b"root"))])
    root, _root_cid = _sign(signer, BRIDGE, CARRIAGE, root_body, effect=2)
    orphan_body = M([(U(1), B(b"orphan"))])
    orphan, _orphan_cid = _sign(signer, AUDIT, RECEIPT, orphan_body, causes=(ghost_cid,))
    with pytest.raises(BrokenReferent) as excinfo:
        verify_chain([root, orphan], signer.public_key)
    assert excinfo.value.kind == "E_REFERENT"
    assert excinfo.value.index == 1


# --- verify_chain: fail-closed on out-of-order / reordered links (E_CHAIN) ----------------------

def test_verify_chain_rejects_an_out_of_order_causal_link():
    signer = _signer()
    root_body = M([(U(1), B(b"root"))])
    root, root_cid = _sign(signer, BRIDGE, CARRIAGE, root_body, effect=2)
    child_body = M([(U(1), B(b"child"))])
    child, _child_cid = _sign(signer, AUDIT, RECEIPT, child_body, causes=(root_cid,))
    # append the CHILD before its own cause -- a reordered/dropped-link chain
    with pytest.raises(ChainOrderBroken) as excinfo:
        verify_chain([child, root], signer.public_key)
    assert excinfo.value.kind == "E_CHAIN"
    assert excinfo.value.index == 0


def test_verify_chain_rejects_a_duplicate_content_id():
    signer = _signer()
    root_body = M([(U(1), B(b"root"))])
    root, _root_cid = _sign(signer, BRIDGE, CARRIAGE, root_body, effect=2)
    with pytest.raises(ChainOrderBroken) as excinfo:
        verify_chain([root, root], signer.public_key)  # the identical signed bytes, twice
    assert excinfo.value.kind == "E_CHAIN"
    assert excinfo.value.index == 1


# --- verify_chain: fail-closed on an unresolved signer (E_UNRESOLVED_SIGNER) --------------------

def test_verify_chain_rejects_an_unresolved_signer():
    signer = _signer()
    records, _cids = _mixed_chain(signer)
    empty_resolver = {}
    with pytest.raises(UnresolvedSigner) as excinfo:
        verify_chain(records, empty_resolver)
    assert excinfo.value.kind == "E_UNRESOLVED_SIGNER"
    assert excinfo.value.index == 0


# --- multi-signer chains via a resolver mapping/callable ----------------------------------------

def test_verify_chain_multi_signer_via_mapping_resolver():
    signer_a = _signer(0x41)
    signer_b = _signer(0x42)
    root_body = M([(U(1), B(b"local-agent-call"))])
    root, root_cid = _sign(signer_a, BRIDGE, CARRIAGE, root_body, effect=2)
    remote_body = M([(U(1), B(b"remote-agent-ack"))])
    remote, remote_cid = _sign(signer_b, AUDIT, RECEIPT, remote_body, causes=(root_cid,))

    resolver = {
        signer_a.signer_id.encode("utf-8"): signer_a.public_key,
        signer_b.signer_id.encode("utf-8"): signer_b.public_key,
    }
    chain = verify_chain([root, remote], resolver)
    assert [l.content_id for l in chain.links] == [root_cid, remote_cid]
    assert chain.links[0].signer == signer_a.signer_id.encode("utf-8")
    assert chain.links[1].signer == signer_b.signer_id.encode("utf-8")


def test_verify_chain_multi_signer_via_callable_resolver():
    signer_a = _signer(0x51)
    signer_b = _signer(0x52)
    keymap = {
        signer_a.signer_id.encode("utf-8"): signer_a.public_key,
        signer_b.signer_id.encode("utf-8"): signer_b.public_key,
    }
    root, root_cid = _sign(signer_a, BRIDGE, CARRIAGE, M([(U(1), B(b"x"))]), effect=1)
    leaf, _leaf_cid = _sign(signer_b, AUDIT, RECEIPT, M([(U(1), B(b"y"))]), causes=(root_cid,))
    chain = verify_chain([root, leaf], lambda sid: keymap.get(sid))
    assert len(chain.links) == 2


# --- replay reconstructs CAUSAL order, not merely append order ----------------------------------

def test_replay_order_follows_causal_timestamps_not_log_append_order():
    signer = _signer(0x61)
    root_body = M([(U(1), B(b"root"))])
    root, root_cid = _sign(signer, BRIDGE, CARRIAGE, root_body, effect=2, created=1000)
    # two independent children of the SAME root, appended child1-then-child2, but child2's
    # causal timestamp is EARLIER than child1's -- both are valid (root precedes both in the
    # log), so this is not an out-of-order defect; it tests that replay order follows the
    # objects' own `created` field, not merely the raw log's append sequence.
    child1_body = M([(U(1), B(b"child1"))])
    child1, child1_cid = _sign(signer, GOVERNANCE, APPROVAL, child1_body,
                                causes=(root_cid,), created=2000)
    child2_body = M([(U(1), B(b"child2"))])
    child2, child2_cid = _sign(signer, AUDIT, RECEIPT, child2_body,
                                causes=(root_cid,), created=1500)

    records = [root, child1, child2]  # append order: root, child1, child2
    chain = verify_chain(records, signer.public_key)
    assert chain.links[0].content_id == root_cid  # raw log order preserved in `links`
    assert chain.links[1].content_id == child1_cid
    assert chain.links[2].content_id == child2_cid

    replayed_cids = [l.content_id for l in replay(chain)]
    # causal replay order: root first, then child2 (created=1500) before child1 (created=2000)
    assert replayed_cids == [root_cid, child2_cid, child1_cid]
    assert replayed_cids != [l.content_id for l in chain.links]  # differs from raw log order


# --- K5's own signed verification receipt --------------------------------------------------------

def test_sign_verification_receipt_is_a_real_verifiable_audit_receipt_object():
    signer = _signer(0x71)
    records, cids = _mixed_chain(signer)
    chain = verify_chain(records, signer.public_key)

    receipt = sign_verification_receipt(signer, chain)
    # independently decode+verify (F3) -- not through naalp_governance_verify's own code
    obj = ez.verify(signer.public_key, receipt)
    assert obj.channel == VERIFICATION_CHANNEL == AUDIT
    assert obj.kind == VERIFICATION_KIND == RECEIPT

    fields = {k.v: v for k, v in obj.body.pairs}
    assert fields[1].v == 3  # number of links verified
    expected_digest = cbor.content_id(A([B(c) for c in cids]))
    assert fields[2].v == expected_digest
    assert fields[3].v == cids[0]
    assert fields[4].v == cids[-1]


def test_sign_verification_receipt_digest_is_non_circular_to_the_replayed_chain():
    """Two DIFFERENT chains produce DIFFERENT receipt digests -- the digest is recomputed from
    what verify_chain actually walked, not a caller-suppliable constant (A4 -- the function's
    output changes with its real input)."""
    signer = _signer(0x81)
    records_a, _cids_a = _mixed_chain(signer)
    chain_a = verify_chain(records_a, signer.public_key)
    receipt_a = sign_verification_receipt(signer, chain_a)

    other_body = M([(U(1), B(b"different-root"))])
    other_root, _other_cid = _sign(signer, BRIDGE, CARRIAGE, other_body, effect=2)
    chain_b = verify_chain([other_root], signer.public_key)
    receipt_b = sign_verification_receipt(signer, chain_b)

    obj_a = ez.verify(signer.public_key, receipt_a)
    obj_b = ez.verify(signer.public_key, receipt_b)
    digest_a = dict((k.v, v) for k, v in obj_a.body.pairs)[2].v
    digest_b = dict((k.v, v) for k, v in obj_b.body.pairs)[2].v
    assert digest_a != digest_b


def test_sign_verification_receipt_on_empty_chain_omits_first_last_fields():
    signer = _signer(0x91)
    chain = verify_chain([], signer.public_key)
    receipt = sign_verification_receipt(signer, chain)
    obj = ez.verify(signer.public_key, receipt)
    fields = {k.v: v for k, v in obj.body.pairs}
    assert fields[1].v == 0
    assert 3 not in fields
    assert 4 not in fields
