# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C5 effect vocabulary and authorization conformance for the Python SDK (design.md §6),
graded against the shared independent corpus vectors/effect/cases.json (NOT produced by this
code): the full granted x effect authorization matrix (R-6.3), the principal-source gate --
only a signature-derived identity is an authorization principal, never transport metadata, a
foreign header, or a client-supplied name (R-6.5) -- and the optional signed safety label's
extraction from an object's ext map, including its malformed-rejection cases (R-6.4).

Run:  python -m unittest -v tests.test_policy      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, policy
from naalp.cbor import U, T, M


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "effect", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/effect/cases.json not found")


SRC_MAP = {
    "signature": policy.SOURCE_SIGNATURE,
    "transport_metadata": policy.SOURCE_TRANSPORT_METADATA,
    "foreign_header": policy.SOURCE_FOREIGN_HEADER,
    "client_name": policy.SOURCE_CLIENT_NAME,
}


class PolicyAuthorizationConformance(unittest.TestCase):
    C = _vectors()

    # ---- R-6.3: the full granted x effect authorization matrix ---------------------------

    def test_authorization_matrix(self):
        """TestAuthorizationMatrix (Go parity): a policy that ignored the object effect
        (constant allow/deny) would fail here -- the matrix contains both allows and
        denies."""
        rows = self.C["authorization_matrix"]
        self.assertEqual(len(rows), 16, "want 16 matrix cells")
        allows = denies = 0
        for r in rows:
            g = policy.Grant(principal="pA", max_effect=r["granted"])
            if r["allow"]:
                allows += 1
                # a granted row must SUCCEED and return None (no side effect, no error).
                self.assertIsNone(
                    g.authorize_object(policy.SOURCE_SIGNATURE, "pA", r["effect"]),
                    "granted=%d effect=%d: want allow" % (r["granted"], r["effect"]),
                )
            else:
                denies += 1
                with self.assertRaises(policy.PolicyError) as cm:
                    g.authorize_object(policy.SOURCE_SIGNATURE, "pA", r["effect"])
                self.assertEqual(
                    cm.exception.kind, "EffectNotAuthorized",
                    "granted=%d effect=%d" % (r["granted"], r["effect"]),
                )
            # the raw lattice must agree with the matrix.
            self.assertEqual(
                policy.authorizes(r["granted"], policy.normalize_effect(r["effect"])),
                r["allow"],
            )
        self.assertTrue(allows > 0 and denies > 0, "matrix must contain both allows and denies")

    # ---- R-6.5: only a signature-derived identity is an authorization principal ----------

    def test_principal_source_gate(self):
        """TestPrincipalSourceGate (Go parity): a grant that would authorize the effect is
        still denied when the presenter's identity is transport metadata, a foreign header,
        or a client-supplied name -- even for a read_only object within the ceiling."""
        rows = self.C["principal_sources"]
        self.assertTrue(len(rows) > 0)
        g = policy.Grant(principal="pA", max_effect=policy.DESTRUCTIVE)  # maximally permissive
        for row in rows:
            src = SRC_MAP[row["source"]]
            accepted = row["accepted"]

            if accepted:
                self.assertEqual(policy.resolve_auth_principal(src, "pA"), "pA")
            else:
                with self.assertRaises(policy.PolicyError) as cm:
                    policy.resolve_auth_principal(src, "pA")
                self.assertEqual(cm.exception.kind, "UnauthenticatedPrincipal", row["source"])

            # even a read_only object (within the ceiling) is denied from a non-signature
            # source.
            if accepted:
                self.assertIsNone(g.authorize_object(src, "pA", policy.READ_ONLY))
            else:
                with self.assertRaises(policy.PolicyError) as cm:
                    g.authorize_object(src, "pA", policy.READ_ONLY)
                self.assertEqual(cm.exception.kind, "UnauthenticatedPrincipal", row["source"])

    # ---- R-6.4: the optional signed safety label's extraction from an ext map ------------

    def test_safety_label_from_ext_present(self):
        sl = self.C["safety_label"]
        ext = M([(U(sl["ext_key"]), M([(U(1), T(sl["risk"])), (U(2), T(sl["scope"]))]))])
        label, present = policy.safety_label_from_ext(ext)
        self.assertTrue(present)
        self.assertEqual(label, policy.SafetyLabel(sl["risk"], sl["scope"]))
        # the built ext's inner map matches the independently-hex-pinned oracle bytes.
        inner = M([(U(1), T(sl["risk"])), (U(2), T(sl["scope"]))])
        self.assertEqual(cbor.encode(inner).hex(), sl["cbor_hex"])
        self.assertEqual(policy.SafetyLabel(sl["risk"], sl["scope"]).encode().hex(), sl["cbor_hex"])

    def test_safety_label_from_ext_absent(self):
        # an empty ext map: no key 1 present -> absent, no error.
        label, present = policy.safety_label_from_ext(M([]))
        self.assertIsNone(label)
        self.assertFalse(present)
        # no ext at all (None).
        label, present = policy.safety_label_from_ext(None)
        self.assertIsNone(label)
        self.assertFalse(present)

    def test_safety_label_from_ext_malformed_non_map(self):
        # ext[1] present but not a map at all.
        bad = M([(U(policy.SAFETY_LABEL_EXT_KEY), U(9))])
        with self.assertRaises(policy.PolicyError) as cm:
            policy.safety_label_from_ext(bad)
        self.assertEqual(cm.exception.kind, "MalformedSafetyLabel")

    def test_safety_label_from_ext_incomplete(self):
        # ext[1] is a map missing the scope field (key 2).
        bad = M([(U(policy.SAFETY_LABEL_EXT_KEY), M([(U(1), T("x"))]))])
        with self.assertRaises(policy.PolicyError) as cm:
            policy.safety_label_from_ext(bad)
        self.assertEqual(cm.exception.kind, "MalformedSafetyLabel")


if __name__ == "__main__":
    unittest.main()
