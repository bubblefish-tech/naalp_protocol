# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""S3 naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof conformance for the
Python SDK, graded against the shared independent corpus vectors/checkpoint/cases.json (NOT
produced by this code): RFC 9162-profiled Merkle math (leaf hash, interior node hash, empty-tree
KAT), byte-exact checkpoint/witness-cosign/inclusion-proof body/head/content-id, fork evidence,
inclusion-proof verification against the resolved checkpoint's own size/root, and the named
negative rejections (witness-root mismatch, wrong index, wrong path, descending-key body, missing
mandatory field).

Mirrors impl/go/gateway/checkpoint_test.go. Written test-first: this fails RED on import until
naalp/gateway.py carries the checkpoint family, and a mutation forcing MerkleRoot to a constant
flips test_rfc9162_self_fidelity.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1 to avoid stale-bytecode strands):
  python -m pytest impl/python/tests/test_checkpoint.py -q
"""
import json
import os
import unittest

from naalp import cbor, cose, gateway


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "checkpoint", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/checkpoint/cases.json not found")


def _cp_from(cv):
    return gateway.CheckpointRoot(
        log=bytes.fromhex(cv["log_hex"]), size=cv["size"], root=bytes.fromhex(cv["root_hex"]),
        prev=bytes.fromhex(cv["prev_hex"]), at=int(cv["at_str"]))


def _wc_from(wv):
    return gateway.WitnessCosign(
        witness=bytes.fromhex(wv["witness_hex"]), root=bytes.fromhex(wv["root_hex"]), at=int(wv["at_str"]))


class CheckpointConformance(unittest.TestCase):
    C = _vectors()

    def test_checkpoint_bodies_match_oracle(self):
        self.assertEqual(gateway.genesis_prev().hex(), self.C["genesis"]["prev_hex"])
        for name, cv in self.C["checkpoints"].items():
            c = _cp_from(cv)
            self.assertEqual(c.bytes().hex(), cv["body_hex"], name)
            self.assertEqual(c.head().hex(), cv["head_hex"], name)
            self.assertEqual(c.id().hex(), cv["id_hex"], name)
            parsed = gateway.parse_checkpoint_root(c.bytes())
            self.assertEqual(parsed.bytes().hex(), cv["body_hex"], name)

    def test_witness_cosign_byte_parity(self):
        for name, wv in self.C["witness_cosigns"].items():
            w = _wc_from(wv)
            self.assertEqual(w.bytes().hex(), wv["body_hex"], name)
            self.assertEqual(w.head().hex(), wv["head_hex"], name)
            self.assertEqual(w.id().hex(), wv["id_hex"], name)

    def test_fork_evidence(self):
        fe = self.C["fork_evidence"]
        self.assertNotEqual(fe["checkpoint_a"]["root_hex"], fe["checkpoint_b"]["root_hex"])
        self.assertNotEqual(fe["checkpoint_a"]["id_hex"], fe["checkpoint_b"]["id_hex"])

        wc_a = _wc_from(fe["checkpoint_a"]["witness_cosign"])
        wc_b = _wc_from(fe["checkpoint_b"]["witness_cosign"])
        self.assertEqual(wc_a.bytes().hex(), fe["checkpoint_a"]["witness_cosign"]["body_hex"])
        self.assertEqual(wc_b.bytes().hex(), fe["checkpoint_b"]["witness_cosign"]["body_hex"])

        id_a = bytes.fromhex(fe["checkpoint_a"]["id_hex"])
        id_b = bytes.fromhex(fe["checkpoint_b"]["id_hex"])
        gateway.validate_witness_cosign(wc_a, id_a)  # no raise
        gateway.validate_witness_cosign(wc_b, id_b)  # no raise
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.validate_witness_cosign(wc_a, id_b)
        self.assertEqual(cm.exception.kind, "WitnessRootMismatch")
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.validate_witness_cosign(wc_b, id_a)
        self.assertEqual(cm.exception.kind, "WitnessRootMismatch")

    def test_inclusion_proof_byte_parity_and_verify(self):
        checkpoint_for = {
            "leaf3_of7": "checkpoint0_size7",
            "leaf7_of8_newly_appended": "checkpoint1_size8",
            "single_leaf_tree_empty_path": "checkpoint_single_leaf",
        }
        for name, iv in self.C["inclusion_proofs"].items():
            cp_name = checkpoint_for[name]
            cp = self.C["checkpoints"][cp_name]
            resolved_id = _cp_from(cp).id()
            self.assertEqual(resolved_id.hex(), iv["root_hex"], name)

            p = gateway.InclusionProof(
                root=bytes.fromhex(iv["root_hex"]), leaf=bytes.fromhex(iv["leaf_hex"]),
                index=iv["index"], path=[bytes.fromhex(h) for h in iv["path_hex"]])
            self.assertEqual(p.bytes().hex(), iv["body_hex"], name)
            self.assertEqual(p.head().hex(), iv["head_hex"], name)
            self.assertEqual(p.id().hex(), iv["id_hex"], name)
            parsed = gateway.parse_inclusion_proof(p.bytes())
            gateway.verify_inclusion_proof(parsed.leaf, parsed.index, cp["size"], parsed.path,
                                            bytes.fromhex(cp["root_hex"]))  # no raise

    def test_inclusion_proof_negative(self):
        cp0 = self.C["checkpoints"]["checkpoint0_size7"]
        root0 = bytes.fromhex(cp0["root_hex"])

        wi = self.C["negative"]["inclusion_wrong_index"]
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_inclusion_proof(
                bytes.fromhex(wi["leaf_hex"]), wi["claimed_index"], cp0["size"],
                [bytes.fromhex(h) for h in wi["path_hex"]], root0)
        self.assertEqual(cm.exception.kind, "InclusionProofInvalid")

        wp = self.C["negative"]["inclusion_wrong_path"]
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_inclusion_proof(
                bytes.fromhex(wp["leaf_hex"]), wp["index"], cp0["size"],
                [bytes.fromhex(h) for h in wp["path_hex"]], root0)
        self.assertEqual(cm.exception.kind, "InclusionProofInvalid")

    def test_witness_root_mismatch(self):
        wm = self.C["negative"]["witness_root_mismatch"]
        w = gateway.parse_witness_cosign(bytes.fromhex(wm["cosign_body_hex"]))
        self.assertEqual(w.root.hex(), wm["cosign_names_root_hex"])
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.validate_witness_cosign(w, bytes.fromhex(wm["checkpoint_accompanied_id_hex"]))
        self.assertEqual(cm.exception.kind, wm["reject"])

    def test_checkpoint_negative(self):
        koo = self.C["negative"]["checkpoint_keys_out_of_order"]
        gateway.parse_checkpoint_root(bytes.fromhex(koo["canonical_body_hex"]))  # should parse
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(bytes.fromhex(koo["noncanonical_body_hex"]))
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_checkpoint_root(bytes.fromhex(koo["noncanonical_body_hex"]))
        self.assertEqual(cm.exception.kind, "CheckpointMalformed")

        mf = self.C["negative"]["checkpoint_missing_field"]
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.parse_checkpoint_root(bytes.fromhex(mf["body_hex"]))
        self.assertEqual(cm.exception.kind, mf["reject"])

    def test_empty_tree_kat(self):
        want = self.C["empty_tree_kat"]["root_hex"]
        self.assertEqual(gateway.merkle_root(None).hex(), want)
        self.assertEqual(gateway.merkle_root([]).hex(), want)

    def test_rfc9162_self_fidelity(self):
        # Independently re-derives the oracle's own claimed property using Python's OWN Merkle
        # construction over synthetic leaves -- never the oracle's numbers -- so this test would
        # catch an algorithmic defect the byte-parity vectors above (which only exercise n in
        # {1,7,8}) do not reach.
        total = 0
        for n in range(1, 13):
            leaves = [("synthetic-leaf-%d" % i).encode() for i in range(n)]
            root = gateway.merkle_root(leaves)
            for m in range(n):
                path = gateway.generate_inclusion_proof_path(leaves, m)
                gateway.verify_inclusion_proof(leaves[m], m, n, path, root)  # no raise
                total += 1
        self.assertEqual(total, 78)  # sum(1..12) == 78, matching the oracle's own count

        # A tampered leaf must NOT verify against the untouched root.
        leaves = [("synthetic-leaf-%d" % i).encode() for i in range(5)]
        root = gateway.merkle_root(leaves)
        path = gateway.generate_inclusion_proof_path(leaves, 2)
        with self.assertRaises(gateway.GatewayError) as cm:
            gateway.verify_inclusion_proof(b"tampered-leaf", 2, 5, path, root)
        self.assertEqual(cm.exception.kind, "InclusionProofInvalid")

    def test_sign_verify_checkpoint_in_isolation(self):
        # NOT corpus-graded (the corpus carries no signed COSE vector): demonstrates
        # sign/verify_checkpoint_root round-tripping in isolation with a local seed.
        cv = self.C["checkpoints"]["checkpoint0_size7"]
        c = _cp_from(cv)
        seed = bytes([0x11] * 32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        obj = gateway.sign_checkpoint_root(c, alg, seed)
        prot, payload, sig = cose.parse_sign1_raw(obj)
        self.assertTrue(cose.cose_verify1_raw(alg, pk, cose.to_be_signed_raw(prot, payload), sig))
        self.assertEqual(payload, c.bytes())


if __name__ == "__main__":
    unittest.main()
