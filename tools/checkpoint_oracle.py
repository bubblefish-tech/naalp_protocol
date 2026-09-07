# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for S3 — the neither-party anchor primitive (design.md section 26.5;
spec/naalp-draft-01.cddl naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof,
FROZEN commit c488c6d3). Supplies the binding-fixed-by-T leg of the accountability triple: a record's
content id, proven included under a witnessed checkpoint, establishes existed-no-later-than the
checkpoint, verifiable offline from the bytes alone.

Merkle tree construction and inclusion-proof verification follow RFC 9162 ("Certificate Transparency
Version 2") section 2.1 EXACTLY, instantiated with SHA-384 (the module's profile hash throughout,
matching the C7 audit-chain hash, design section 8.1). The formulas below are quoted VERBATIM from
RFC 9162, fetched and read from https://www.rfc-editor.org/rfc/rfc9162.html THIS SESSION (not
recalled from training-data memory, per rule B1/E8):

  RFC 9162 section 2.1.1 (Merkle Tree Hash, MTH):
    "MTH({}) = HASH()."                                                  -- empty list
    "MTH({d[0]}) = HASH(0x00 || d[0])."                                  -- single leaf
    "MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))"                -- n > 1
  where k is the largest power of two strictly smaller than n. "The hash calculations for leaves and
  nodes differ; this domain separation is required to give second preimage resistance."

  RFC 9162 section 2.1.1 (Merkle audit PATH(m, D_n) for leaf d[m]):
    "PATH(0, {d[0]}) = {}"                                               -- single-leaf tree, base case
    "PATH(m, D_n) = PATH(m, D[0:k]) : MTH(D[k:n])"          for m < k    -- target in left subtree
    "PATH(m, D_n) = PATH(m - k, D[k:n]) : MTH(D[0:k])"      for m >= k   -- target in right subtree
  (":" is list concatenation; the sibling hash is appended at the END of each recursive call, so the
  final list is ordered leaf-to-root — the same order design.md section 26.5 states for the wire
  field `naalp-inclusion-proof.path`.)

  RFC 9162 section 2.1.3.2 (Verifying an Inclusion Proof): the client supplies the LEAF HASH `hash` =
  MTH({d[leaf_index]}) = HASH(0x00 || d[leaf_index]), computed by the client itself before invoking
  the procedure (confirmed this session: "the `hash` parameter is pre-supplied... the pre-computed
  leaf hash being verified", NOT derived inside the procedure). The FULL procedure, re-fetched and
  quoted verbatim this session after an initial paraphrase omitted a load-bearing sub-step (the
  RFC-fidelity self-check below caught the omission BEFORE any vector was trusted — see step 4.b.ii):

    1. If leaf_index >= tree_size, fail.
    2. fn = leaf_index; sn = tree_size - 1.
    3. r = hash.
    4. For each value p in inclusion_path:
       a. If sn is 0, stop the iteration and fail.
       b. If LSB(fn) is set, or fn == sn, then:
          i.  r = HASH(0x01 || p || r).
          ii. If LSB(fn) is NOT set, right-shift both fn and sn EQUALLY, repeatedly, until either
              LSB(fn) is set or fn is 0. (This is the sub-step the first paraphrase dropped: it
              lets the "last node on the right border" of a non-power-of-two-sized tree skip
              levels that have no sibling to consume, and is required for any tree_size that is
              not itself a power of two — e.g. size 3, leaf index 2, which is exactly this
              oracle's leaf3_of7 fixture below.)
          Otherwise: r = HASH(0x01 || r || p).
       c. Finally, right-shift both fn and sn one time (unconditionally, once per path element).
    5. Accept iff sn == 0 AND r == root_hash.

WIRE OBJECTS (spec/naalp-draft-01.cddl):
  naalp-checkpoint-root  {1: log, 2: size, 3: root, 4: prev, 5: at}
    root = MTH(leaf_set) (48 bytes, the Merkle tree head itself).
    prev = SHA-384(the PRIOR checkpoint's own encoded body) (48 bytes; genesis = 48 zero bytes) — the
    SAME receipt-chain idiom as the C7 audit chain (design section 8.1, confirmed this session
    against tools/audit_oracle.py: `prev` chains by the previous object's own HEAD, not by an inner
    field of the previous object). This is a chain-of-custody hash chain OVER checkpoint objects; it
    is NOT the same 48-byte quantity as field 3's Merkle root value, even though both happen to be
    48 bytes (SHA-384 width) — the CDDL's "prior checkpoint root value" names the PRIOR
    naalp-checkpoint-root object's head, following section 26.5's explicit statement that checkpoints
    chain by `prev` "the same receipt-chain idiom the C7 audit chain... already use".
  naalp-witness-cosign   {1: witness, 2: root, 3: at}
    root = the T1 CONTENT ID (50 bytes, multihash(0x20,SHA-384(...))) of the EXACT
    naalp-checkpoint-root object cosigned — a cross-reference, unlike checkpoint-root.prev above.
  naalp-inclusion-proof  {1: root, 2: leaf, 3: index, 4: path[]}
    root = content id (50 bytes) of the naalp-checkpoint-root proven against; leaf = the included
    record's OWN content id (50 bytes) — the raw value MTH's leaf-hash step consumes; index = the
    leaf's 0-based tree position; path = the leaf-to-root audit path (48-byte SHA-384 values).

Non-circular authority (NOT the code under test):
  * The Merkle tree (MTH/PATH/inclusion-verify) is implemented here from scratch in Python, straight
    from the RFC 9162 text quoted above, using only stdlib hashlib.sha384 — never by importing or
    shelling out to impl/go or impl/rust.
  * Every checkpoint/witness/inclusion body is built by the shared deterministic-CBOR constructor
    (cbor_oracle, graded against RFC 8949 in T1).
  * Before ANY vector is emitted, this file asserts internal RFC-fidelity: for every leaf count
    n in 1..12 and every leaf index m in range(n), PATH(m, leaves[:n]) recomputed through the
    section-2.1.3.2 procedure above reproduces MTH(leaves[:n]) exactly. This is a self-consistency
    proof that the from-scratch implementation is faithful to the RFC text quoted above; it is NOT
    what makes the oracle non-circular (the RFC text is the independent authority) — it is what makes
    this implementation of that authority trustworthy before Go/Rust ever see it.

Emits vectors/checkpoint/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

GENESIS = b"\x00" * 48  # SHA-384 width; the empty-chain prev, same idiom as audit_oracle.GENESIS


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def noncanon_map(pairs):
    n = len(pairs)
    assert n < 24
    out = bytes([0xA0 | n])
    for (k, v) in reversed(pairs):
        out += cbor_oracle.encode(k) + cbor_oracle.encode(v)
    return out


# ---- RFC 9162 section 2.1 Merkle tree, SHA-384-profiled -----------------------------------------

def leaf_hash(leaf_bytes):
    """MTH({d}) = HASH(0x00 || d) — RFC 9162 section 2.1.1, single-leaf case."""
    return sha384(b"\x00" + leaf_bytes)


def node_hash(left, right):
    """the n>1 combining step: HASH(0x01 || left || right) — RFC 9162 section 2.1.1."""
    return sha384(b"\x01" + left + right)


def largest_pow2_lt(n):
    """k, the largest power of two STRICTLY smaller than n (RFC 9162 section 2.1.1 notation), for
    n >= 2. E.g. n=2->1, n=3->2, n=4->2, n=5->4, n=7->4, n=8->4, n=9->8."""
    assert n >= 2
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def MTH(leaves):
    """Merkle Tree Hash, RFC 9162 section 2.1.1: MTH({})=HASH(); MTH({d0})=HASH(0x00||d0);
    MTH(D_n)=HASH(0x01||MTH(D[0:k])||MTH(D[k:n])) for n>1, k = largest power of two < n."""
    n = len(leaves)
    if n == 0:
        return sha384(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = largest_pow2_lt(n)
    return node_hash(MTH(leaves[:k]), MTH(leaves[k:]))


def PATH(m, leaves):
    """Merkle audit PATH(m, D_n), RFC 9162 section 2.1.1: PATH(0,{d0})={}; for m<k,
    PATH(m,D_n)=PATH(m,D[0:k]):MTH(D[k:n]); for m>=k, PATH(m,D_n)=PATH(m-k,D[k:n]):MTH(D[0:k]).
    Returns the audit path as a list, ordered leaf-to-root (the sibling appended by the OUTERMOST
    call — the top of the tree — lands LAST in the returned list, per the ":" concatenation order)."""
    n = len(leaves)
    assert 0 <= m < n
    if n == 1:
        return []
    k = largest_pow2_lt(n)
    if m < k:
        return PATH(m, leaves[:k]) + [MTH(leaves[k:])]
    return PATH(m - k, leaves[k:]) + [MTH(leaves[:k])]


def recompute_root(leaf_index, tree_size, leaf_hash_value, path):
    """RFC 9162 section 2.1.3.2 inclusion-proof verification procedure, quoted in full in this
    file's module docstring (step 4.b.ii — the extra "shift fn/sn until LSB(fn) set or fn==0"
    sub-step — is the piece an initial paraphrase of the RFC dropped; the RFC-fidelity self-check
    below (self_check_rfc_fidelity) is what caught the omission, on the very first non-power-of-two
    leaf count it tried). Returns (ok, computed_root): ok is False if leaf_index/tree_size is out of
    range, or if step 4.a's mid-loop `sn == 0` guard trips (path longer than the tree shape allows),
    or if the terminal `sn == 0` check (step 5) fails."""
    if leaf_index >= tree_size:
        return False, None
    fn, sn, r = leaf_index, tree_size - 1, leaf_hash_value
    for p in path:
        if sn == 0:
            return False, None  # step 4.a: ran out of tree before the path did
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:  # step 4.b.ii: LSB(fn) not set -> shift until it is, or fn == 0
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1  # step 4.c: unconditional, once per path element
        sn >>= 1
    return (sn == 0), r


def self_check_rfc_fidelity(max_n=12):
    """Internal RFC-fidelity proof (see module docstring): for every n in 1..max_n and every leaf
    index m, an inclusion proof built by PATH() and verified by recompute_root() must recompute the
    SAME root MTH() independently produces. Raises AssertionError on any mismatch — this MUST pass
    before any vector below is trusted."""
    checked = 0
    for n in range(1, max_n + 1):
        leaves = [sha384(("leaf-%d" % i).encode()) for i in range(n)]
        root = MTH(leaves)
        for m in range(n):
            path = PATH(m, leaves)
            ok, recomputed = recompute_root(m, n, leaf_hash(leaves[m]), path)
            assert ok, "recompute_root reported out-of-range/malformed for n=%d m=%d" % (n, m)
            assert recomputed == root, "RFC 9162 fidelity check FAILED at n=%d m=%d" % (n, m)
            checked += 1
    return checked


# ---- wire object bodies --------------------------------------------------------------------------

def checkpoint_body(log, size, root, prev, at):
    return cbor_oracle.encode(("map", [(1, log), (2, size), (3, root), (4, prev), (5, at)]))


def checkpoint_out(log, size, root, prev, at):
    body = checkpoint_body(log, size, root, prev, at)
    return {
        "log_hex": log.hex(), "size": size, "root_hex": root.hex(), "prev_hex": prev.hex(),
        "at_str": str(at),
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


def witness_body(witness, root_cid, at):
    return cbor_oracle.encode(("map", [(1, witness), (2, root_cid), (3, at)]))


def witness_out(witness, root_cid, at):
    body = witness_body(witness, root_cid, at)
    return {
        "witness_hex": witness.hex(), "root_hex": root_cid.hex(), "at_str": str(at),
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


def inclusion_body(root_cid, leaf, index, path):
    return cbor_oracle.encode(("map", [(1, root_cid), (2, leaf), (3, index), (4, list(path))]))


def inclusion_out(root_cid, leaf, index, path):
    body = inclusion_body(root_cid, leaf, index, path)
    return {
        "root_hex": root_cid.hex(), "leaf_hex": leaf.hex(), "index": index,
        "path_hex": [p.hex() for p in path],
        "body_hex": body.hex(), "head_hex": sha384(body).hex(), "id_hex": cid(body).hex(),
    }


def build():
    fidelity_checked = self_check_rfc_fidelity(max_n=12)

    log_signer = bytes.fromhex("5349474e45525f4c4f47") + b"-transparency-log-1"  # "SIGNER_LOG"...
    witness_signer = bytes.fromhex("5349474e45525f57") + b"-witness-1"           # "SIGNER_W"...

    # A 7-leaf checkpoint: the leaf set is a set of RECORD content ids (e.g. naalp-decision-record
    # ids) — here synthesized as cid() over placeholder record byte-strings.
    leaves7 = [cid(("record-%d" % i).encode()) for i in range(7)]
    root7 = MTH(leaves7)
    at0 = 1735689600000  # 2025-01-01T00:00:00Z epoch ms
    checkpoint0 = checkpoint_out(log_signer, 7, root7, GENESIS, at0)
    checkpoint0_body = checkpoint_body(log_signer, 7, root7, GENESIS, at0)
    checkpoint0_head = sha384(checkpoint0_body)
    checkpoint0_cid = cid(checkpoint0_body)
    assert checkpoint0["head_hex"] == checkpoint0_head.hex()

    # An 8th leaf appended: the log grows, chained by prev = head(checkpoint0) (design section 26.5 /
    # the C7 receipt-chain idiom, NOT checkpoint0's own Merkle root field-3 value).
    leaves8 = leaves7 + [cid(b"record-7")]
    root8 = MTH(leaves8)
    at1 = 1738368000000  # 2025-02-01T00:00:00Z epoch ms
    checkpoint1 = checkpoint_out(log_signer, 8, root8, checkpoint0_head, at1)
    checkpoint1_body = checkpoint_body(log_signer, 8, root8, checkpoint0_head, at1)
    checkpoint1_cid = cid(checkpoint1_body)

    # Genesis checkpoint: prev is explicitly 48 zero bytes (checkpoint0 above already demonstrates
    # this; called out again as its own named fixture for direct assertion by impls).
    genesis_note = {
        "prev_hex": GENESIS.hex(),
        "note": "the genesis prev value: 48 zero bytes, matching checkpoint0.prev_hex above.",
    }
    assert checkpoint0["prev_hex"] == GENESIS.hex()

    # --- witness cosigns ---
    at_w0 = 1735689660000
    witness_ok = witness_out(witness_signer, checkpoint0_cid, at_w0)
    assert witness_ok["root_hex"] == checkpoint0_cid.hex()

    at_w1 = 1738368060000
    witness_ok_checkpoint1 = witness_out(witness_signer, checkpoint1_cid, at_w1)

    # WitnessRootMismatch: a witness-cosign naming checkpoint1's content id but PRESENTED alongside
    # checkpoint0 — the accompanying checkpoint's cid does not match the cosign's field-2 root.
    mismatch_cosign = witness_out(witness_signer, checkpoint1_cid, at_w0)
    witness_root_mismatch = {
        "checkpoint_accompanied_id_hex": checkpoint0_cid.hex(),
        "cosign_body_hex": mismatch_cosign["body_hex"],
        "cosign_names_root_hex": mismatch_cosign["root_hex"],
        "reject": "WitnessRootMismatch",
        "note": "the cosign names checkpoint1's content id (field 2) while accompanying checkpoint0 "
                "— cosign.root != cid(the checkpoint it accompanies).",
    }

    # --- fork evidence: two witness-cosigned roots at the SAME (log, size) with DIFFERENT root ---
    forked_leaves = [cid(("fork-record-%d" % i).encode()) for i in range(7)]
    forked_leaves[3] = cid(b"fork-record-3-DIVERGENT")  # one differing leaf -> a different root
    root_fork_b = MTH(forked_leaves)
    assert root_fork_b != root7, "fork fixture must diverge from checkpoint0's root"
    checkpoint_fork_b = checkpoint_out(log_signer, 7, root_fork_b, GENESIS, at0)
    checkpoint_fork_b_body = checkpoint_body(log_signer, 7, root_fork_b, GENESIS, at0)
    checkpoint_fork_b_cid = cid(checkpoint_fork_b_body)
    witness_fork_a = witness_out(witness_signer, checkpoint0_cid, at_w0)
    witness_fork_b = witness_out(witness_signer, checkpoint_fork_b_cid, at_w0)
    fork_evidence = {
        "log_hex": log_signer.hex(), "size": 7,
        "checkpoint_a": {"root_hex": checkpoint0["root_hex"], "id_hex": checkpoint0["id_hex"], "witness_cosign": witness_fork_a},
        "checkpoint_b": {"root_hex": checkpoint_fork_b["root_hex"], "id_hex": checkpoint_fork_b["id_hex"], "witness_cosign": witness_fork_b},
        "note": ("two witness-cosigned naalp-checkpoint-root objects at the SAME (log, size)=(log,7) "
                 "carrying DIFFERENT root values — the log has signed two incompatible histories, and "
                 "both signatures are the proof (design section 26.5, the same idiom as the C7/section "
                 "8.5 naalp-fork-proof)."),
    }

    # --- inclusion proofs (positive) ---
    m3 = 3
    path3 = PATH(m3, leaves7)
    ok3, recomputed3 = recompute_root(m3, 7, leaf_hash(leaves7[m3]), path3)
    assert ok3 and recomputed3 == root7
    inclusion_leaf3_of7 = inclusion_out(checkpoint0_cid, leaves7[m3], m3, path3)

    m7 = 7  # the newly appended 8th leaf, index 7, in the 8-leaf tree
    path7 = PATH(m7, leaves8)
    ok7, recomputed7 = recompute_root(m7, 8, leaf_hash(leaves8[m7]), path7)
    assert ok7 and recomputed7 == root8
    inclusion_leaf7_of8 = inclusion_out(checkpoint1_cid, leaves8[m7], m7, path7)

    # single-leaf tree: PATH(0,{d0}) = {} (RFC 9162 base case) — trivial inclusion proof, empty path.
    single_leaf = [cid(b"only-record")]
    root_single = MTH(single_leaf)
    path_single = PATH(0, single_leaf)
    assert path_single == []
    ok_single, recomputed_single = recompute_root(0, 1, leaf_hash(single_leaf[0]), path_single)
    assert ok_single and recomputed_single == root_single
    checkpoint_single = checkpoint_out(log_signer, 1, root_single, GENESIS, at0)
    checkpoint_single_cid = cid(checkpoint_body(log_signer, 1, root_single, GENESIS, at0))
    inclusion_single_leaf_tree = inclusion_out(checkpoint_single_cid, single_leaf[0], 0, path_single)

    # empty-tree KAT: MTH({}) = HASH() = SHA-384 of the empty octet string (RFC 9162 section 2.1.1).
    empty_tree_root = MTH([])
    assert empty_tree_root == hashlib.sha384(b"").digest()
    empty_tree_kat = {
        "root_hex": empty_tree_root.hex(),
        "note": "MTH({}) = HASH() = SHA-384(''), the empty-list base case (RFC 9162 section 2.1.1).",
    }

    # --- inclusion proof negatives: wrong-index, wrong-path -> InclusionProofInvalid ---
    wrong_index = m3 + 1  # off-by-one index against the SAME (correct) path3/leaf
    ok_wi, recomputed_wi = recompute_root(wrong_index, 7, leaf_hash(leaves7[m3]), path3)
    assert (not ok_wi) or recomputed_wi != root7, "wrong-index fixture must fail to recompute the true root"
    inclusion_wrong_index = {
        "root_hex": checkpoint0_cid.hex(), "leaf_hex": leaves7[m3].hex(),
        "claimed_index": wrong_index, "true_index": m3, "path_hex": [p.hex() for p in path3],
        "reject": "InclusionProofInvalid",
        "note": "leaf3's real audit path, claimed at index 4 instead of 3 — recomputation diverges "
                "from the true root (or the sn==0 terminal check fails).",
    }

    corrupted_path3 = list(path3)
    corrupted_path3[0] = sha384(corrupted_path3[0])  # corrupt the first (leaf-nearest) sibling
    ok_wp, recomputed_wp = recompute_root(m3, 7, leaf_hash(leaves7[m3]), corrupted_path3)
    assert (not ok_wp) or recomputed_wp != root7, "corrupted-path fixture must fail to recompute the true root"
    inclusion_wrong_path = {
        "root_hex": checkpoint0_cid.hex(), "leaf_hex": leaves7[m3].hex(), "index": m3,
        "path_hex": [p.hex() for p in corrupted_path3],
        "true_path_hex": [p.hex() for p in path3],
        "reject": "InclusionProofInvalid",
        "note": "leaf3's real index/leaf but the first audit-path entry is corrupted (re-hashed) — "
                "recomputation does not reach the true root.",
    }

    # --- checkpoint negatives: keys-out-of-order, missing field ---
    canon_pairs = [(1, log_signer), (2, 7), (3, root7), (4, GENESIS), (5, at0)]
    canon_body = checkpoint_body(log_signer, 7, root7, GENESIS, at0)
    noncanon_body = noncanon_map(canon_pairs)
    assert noncanon_body != canon_body and len(noncanon_body) == len(canon_body)
    checkpoint_keys_out_of_order = {
        "canonical_body_hex": canon_body.hex(), "noncanonical_body_hex": noncanon_body.hex(),
        "reject": "NonCanonical",
        "note": "checkpoint0's body with top-level keys emitted descending (5,4,3,2,1).",
    }
    missing_root_body = cbor_oracle.encode(("map", [(1, log_signer), (2, 7), (4, GENESIS), (5, at0)]))  # field 3 omitted
    checkpoint_missing_field = {
        "body_hex": missing_root_body.hex(), "reject": "CheckpointMalformed",
        "note": "field 3 (root) is absent — a naalp-checkpoint-root is malformed without it.",
    }

    return {
        "source": ("design.md section 26.5 / spec/naalp-draft-01.cddl naalp-checkpoint-root / "
                   "naalp-witness-cosign / naalp-inclusion-proof (FROZEN commit c488c6d3). Tree "
                   "construction and inclusion-proof verification follow RFC 9162 section 2.1 "
                   "EXACTLY, SHA-384-profiled: leaf hash = HASH(0x00||leaf), interior node = "
                   "HASH(0x01||left||right), read from https://www.rfc-editor.org/rfc/rfc9162.html "
                   "this session and quoted verbatim in this file's module docstring. "
                   "checkpoint-root.prev chains by the PRIOR checkpoint's own head (SHA-384 of its "
                   "body), the same receipt-chain idiom as the C7 audit chain (design section 8.1); "
                   "witness-cosign.root and inclusion-proof.root are T1 CONTENT IDS (50 bytes) of "
                   "the checkpoint object, a distinct 48-vs-50-byte quantity from checkpoint-root.prev "
                   "— both conventions are stated explicitly in this file to avoid the two 48-byte "
                   "quantities (a Merkle root and a chain head) being confused with each other."),
        "rfc9162_fidelity_check": {
            "leaf_counts_checked": 12, "total_leaf_positions_checked": fidelity_checked,
            "note": "for every n in 1..12 and every leaf index m in range(n), PATH()+recompute_root() "
                    "reproduces MTH() exactly — asserted at generation time, before any vector below "
                    "is trusted.",
        },
        "genesis": genesis_note,
        "checkpoints": {
            "checkpoint0_size7": checkpoint0,
            "checkpoint1_size8": checkpoint1,
            "checkpoint_single_leaf": checkpoint_single,
        },
        "witness_cosigns": {
            "witness_ok_checkpoint0": witness_ok,
            "witness_ok_checkpoint1": witness_ok_checkpoint1,
        },
        "fork_evidence": fork_evidence,
        "inclusion_proofs": {
            "leaf3_of7": inclusion_leaf3_of7,
            "leaf7_of8_newly_appended": inclusion_leaf7_of8,
            "single_leaf_tree_empty_path": inclusion_single_leaf_tree,
        },
        "empty_tree_kat": empty_tree_kat,
        "negative": {
            "witness_root_mismatch": witness_root_mismatch,
            "inclusion_wrong_index": inclusion_wrong_index,
            "inclusion_wrong_path": inclusion_wrong_path,
            "checkpoint_keys_out_of_order": checkpoint_keys_out_of_order,
            "checkpoint_missing_field": checkpoint_missing_field,
        },
        "note": ("every *_hex value in this corpus is produced by the shared deterministic-CBOR "
                 "constructor (cbor_oracle, T1), stdlib hashlib SHA-384, and the from-scratch "
                 "RFC-9162 Merkle implementation in this file — never by the Go/Rust checkpoint code "
                 "under test. Go and Rust are graded byte-for-byte against these bodies, heads, "
                 "content ids, roots, and audit paths (Go == Rust == oracle)."),
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "checkpoint", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  RFC 9162 fidelity: %d leaf positions checked across n=1..12" %
          data["rfc9162_fidelity_check"]["total_leaf_positions_checked"])
    print("  checkpoint0 (size=7) root=%s... id=%s..." % (
        data["checkpoints"]["checkpoint0_size7"]["root_hex"][:16],
        data["checkpoints"]["checkpoint0_size7"]["id_hex"][:16]))
    print("  checkpoint1 (size=8) prev=%s..." % data["checkpoints"]["checkpoint1_size8"]["prev_hex"][:16])
    print("  fork_evidence: checkpoint_a root=%s... checkpoint_b root=%s..." % (
        data["fork_evidence"]["checkpoint_a"]["root_hex"][:16],
        data["fork_evidence"]["checkpoint_b"]["root_hex"][:16]))
    print("  inclusion leaf3_of7 index=%d path_len=%d" % (
        data["inclusion_proofs"]["leaf3_of7"]["index"], len(data["inclusion_proofs"]["leaf3_of7"]["path_hex"])))
    print("  negative cases: %s" % [k for k in data["negative"].keys()])


if __name__ == "__main__":
    main()
