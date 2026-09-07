# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C15 multi-hop agent-delegation conformance for the Python SDK, graded against the shared
independent corpus vectors/delegation/cases.json (NOT produced by this code): the DelegationGrant
body/content-id byte parity, the D2 scope-containment truth table, and the 12-step leaf->root D3
chain verifier's verdict for every scenario (both the authorized outcomes and every named deny).
The chain scenarios are driven as REAL ML-DSA-65 signed grant chains (each grant a signed envelope
whose issuer is its verified signer, real envelope content-ids wired into `causes`), so the
delegation CREDENTIAL path uses the real crypto (R-DEL-2/3), not a stand-in.

Dedicated crypto tests port the Go tamper/forge/baseline/NFC checks. The D4 two-gate composition
(AuthorizeDestructive) wires delegation onto the new approval module's single-use consume ledger and
proves the replay guarantee end-to-end. test_attenuation_denies_escalation is the mutation target:
removing the CapExceedsParent effect-attenuation check flips it (a child would exceed its parent).

Written test-first; the module is absent until ported, so this fails RED on import until
impl/python/naalp/delegation.py lands.

Run:  python -m unittest -v tests.test_delegation      (from impl/python/)
"""
import json
import os
import tempfile
import unittest

from naalp import cose, delegation, identity, policy
from naalp.cbor import T


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "delegation", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/delegation/cases.json not found")


def _hb(s):
    return bytes.fromhex(s)


ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC

# ---- deterministic key material (label -> real ML-DSA-65 keypair + signer id) -----------------
# Cached globally: reusing an identity for a label across independent scenarios is harmless (each
# scenario's verdict depends only on the chain structure, matched by signer-id string, not on which
# specific key). A fresh seed is minted for each new label.
_KEYCACHE = {}
_NEXT_SEED = [1]


class _Key:
    __slots__ = ("seed", "pk", "id")

    def __init__(self, seed):
        self.seed = seed
        self.pk = cose.mldsa_keygen("ML-DSA-65", seed)
        self.id = identity.signer_id(ALG, self.pk)


def _key_for(label):
    if label not in _KEYCACHE:
        n = _NEXT_SEED[0]
        _NEXT_SEED[0] += 1
        _KEYCACHE[label] = _Key(bytes([n & 0xFF] * 32))
    return _KEYCACHE[label]


def _content_id_of(b):
    """The T1 content-id framing over arbitrary bytes: multihash(0x20, SHA-384(b))."""
    from naalp import cbor
    return cbor.content_id(bytes(b))


def _sign_grant(issuer_key, subject_id, effect_cap, max_depth, not_before, not_after, scope, causes):
    """Build, sign (real ML-DSA-65), and verify a DelegationGrant; return its Resolved form."""
    g = delegation.Grant(subject_id, effect_cap, max_depth, not_before, not_after, scope)
    obj = g.envelope_object(issuer_key.id.encode(), 1, PROFILE, causes)
    signed = delegation.sign_grant(obj, ALG, issuer_key.seed)
    return delegation.verify_grant_object(PROFILE, ALG, issuer_key.pk, signed), signed


def _build_action(signer_key, effect, scope, causes):
    """Build, sign, and verify a real action object by the signer (D3 step 1), then the Action."""
    from naalp import envelope
    obj = envelope.Object(kind=2, channel=1, signer=signer_key.id.encode(), created=1,
                          effect=effect, body=T("action"), tier=0, profile=PROFILE, causes=causes)
    signed = envelope.sign(obj, ALG, signer_key.seed)
    o = envelope.verify(PROFILE, ALG, signer_key.pk, delegation.composed_kind_validator, signed)
    assert o.signer == signer_key.id.encode()
    return delegation.Action(o.signer.decode(), o.effect, scope, o.causes)


class DelegationConformance(unittest.TestCase):
    C = _vectors()

    # ---- DelegationGrant body / content-id byte parity (design §18.1) ---------------------

    def test_grant_bytes_match_oracle(self):
        self.assertTrue(self.C["grants"])
        for gj in self.C["grants"]:
            g = delegation.Grant(gj["subject"], gj["effect_cap"], gj["max_depth"],
                                 gj["not_before"], gj["not_after"], gj["scope"])
            self.assertEqual(g.bytes().hex(), gj["body_hex"], gj["name"])
            self.assertEqual(g.content_id().hex(), gj["content_id_hex"], gj["name"])

    # ---- D2 scope-containment truth table (design §18.1) ----------------------------------

    def test_scope_containment_matches_oracle(self):
        self.assertTrue(self.C["scope_containment"])
        for r in self.C["scope_containment"]:
            self.assertEqual(delegation.scope_contained(r["child"], r["parent"]), r["contained"],
                             "ScopeContained(%r, %r)" % (r["child"], r["parent"]))

    # ---- the 12-step D3 chain verifier verdicts (design §18.2), REAL signed chains ---------

    def test_chain_scenarios_match_oracle(self):
        self.assertTrue(self.C["scenarios"])
        for sc in self.C["scenarios"]:
            with self.subTest(scenario=sc["name"]):
                keys = {}

                def kf(label):
                    if label not in keys:
                        keys[label] = _key_for("%s::%s" % (sc["name"], label))
                    return keys[label]

                grant_cid = [None] * len(sc["grants"])
                grants = delegation.GrantSet()
                for i, gj in enumerate(sc["grants"]):
                    ik = kf(gj["issuer"])
                    sk = kf(gj["subject"])
                    causes = [grant_cid[ci] for ci in gj["causes"]]
                    res, _ = _sign_grant(ik, sk.id, gj["effect_cap"], gj["max_depth"],
                                         gj["not_before"], gj["not_after"], gj["scope"], causes)
                    grant_cid[i] = res.content_id
                    grants[bytes(res.content_id)] = res

                act = sc["action"]
                action = _build_action(kf(act["signer"]), act["effect"], act["scope"],
                                       [grant_cid[ci] for ci in act["causes"]])
                anchors = set(kf(a).id for a in sc["anchors"])
                revoked = {}
                for r in sc["revoked"]:
                    revoked[bytes(grant_cid[r["grant"]])] = r["pos"]

                if sc["expect"] == "authorized":
                    self.assertIsNone(
                        delegation.verify_chain(action, grants, anchors, revoked, sc["now"]),
                        "%s: expected authorized" % sc["name"])
                else:
                    with self.assertRaises(delegation.DelegationError) as cm:
                        delegation.verify_chain(action, grants, anchors, revoked, sc["now"])
                    self.assertEqual(cm.exception.kind, sc["expect"], sc["name"])

    # ---- dedicated real-crypto deny paths (ported from the Go behavioural tests) -----------

    def _valid_2hop(self, effect):
        a = _key_for("2hop-A-%d" % effect)   # trust anchor / root issuer
        m = _key_for("2hop-M-%d" % effect)   # middle
        b = _key_for("2hop-B-%d" % effect)   # actor
        root, _ = _sign_grant(a, m.id, policy.DESTRUCTIVE, 2, 0, 1_000_000, "", [])
        leaf, leaf_signed = _sign_grant(m, b.id, policy.DESTRUCTIVE, 1, 0, 1_000_000, "",
                                        [root.content_id])
        grants = delegation.new_grant_set(root, leaf)
        action = _build_action(b, effect, "", [leaf.content_id])
        return {"a": a, "m": m, "b": b, "grants": grants, "anchors": {a.id: True},
                "action": action, "leaf_signed": leaf_signed}

    def test_valid_2hop_authorized(self):
        bc = self._valid_2hop(policy.NON_IDEMPOTENT_WRITE)
        self.assertIsNone(delegation.verify_chain(bc["action"], bc["grants"],
                                                  set(bc["anchors"]), {}, 500))

    def test_attenuation_denies_escalation(self):
        # MUTATION TARGET: a valid chain but an action effect ABOVE the leaf effect_cap must be denied
        # CapExceedsParent (a child can never exceed its parent's authority).
        bc = self._valid_2hop(policy.DESTRUCTIVE)
        # leaf cap is DESTRUCTIVE(3); build an over-effect action by lowering the leaf cap chain.
        a = _key_for("att-A")
        m = _key_for("att-M")
        b = _key_for("att-B")
        root, _ = _sign_grant(a, m.id, policy.NON_IDEMPOTENT_WRITE, 2, 0, 1_000_000, "", [])
        leaf, _ = _sign_grant(m, b.id, policy.NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "",
                              [root.content_id])
        grants = delegation.new_grant_set(root, leaf)
        action = _build_action(b, policy.DESTRUCTIVE, "", [leaf.content_id])   # 3 > leaf cap 2
        with self.assertRaises(delegation.DelegationError) as cm:
            delegation.verify_chain(action, grants, {a.id}, {}, 500)
        self.assertEqual(cm.exception.kind, "CapExceedsParent")

    def test_tampered_grant_signature_rejected(self):
        bc = self._valid_2hop(policy.NON_IDEMPOTENT_WRITE)
        tampered = bytearray(bc["leaf_signed"])
        tampered[-1] ^= 0x01
        with self.assertRaises(Exception) as cm:
            delegation.verify_grant_object(PROFILE, ALG, bc["m"].pk, bytes(tampered))
        self.assertEqual(getattr(cm.exception, "kind", None), "BadSignature")

    def test_forged_issuer_rejected(self):
        real = _key_for("forge-real")
        victim = _key_for("forge-victim")     # the id the forger tries to impersonate
        subject = _key_for("forge-subject")
        g = delegation.Grant(subject.id, policy.NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "")
        obj = g.envelope_object(victim.id.encode(), 1, PROFILE, [])   # claim victim as issuer...
        signed = delegation.sign_grant(obj, ALG, real.seed)           # ...but sign with real's key
        with self.assertRaises(Exception) as cm:
            delegation.verify_grant_object(PROFILE, ALG, real.pk, signed)
        self.assertEqual(getattr(cm.exception, "kind", None), "SignerMismatch")

    def test_baseline_verifier_rejects_grant_kind(self):
        from naalp import channels, envelope
        issuer = _key_for("base-issuer")
        subject = _key_for("base-subject")
        g = delegation.Grant(subject.id, policy.NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "")
        obj = g.envelope_object(issuer.id.encode(), 1, PROFILE, [])
        signed = delegation.sign_grant(obj, ALG, issuer.seed)

        def baseline_validator(channel, kind):
            try:
                channels.lookup(channel, kind)
                return True
            except channels.UnknownKind:
                return False

        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(PROFILE, ALG, issuer.pk, baseline_validator, signed)
        self.assertEqual(cm.exception.kind, "UnknownKind")

    def test_non_nfc_subject_rejected(self):
        issuer = _key_for("nfc-issuer")
        non_nfc = "é"                     # 'é' as e + combining acute (NFD, not NFC)
        g = delegation.Grant(non_nfc, policy.READ_ONLY, 0, 0, 1, "")
        with self.assertRaises(delegation.DelegationError) as cm:
            g.envelope_object(issuer.id.encode(), 1, PROFILE, [])
        self.assertEqual(cm.exception.kind, "NonNFC")

    # ---- D4 two-gate composition with the single-use approval ledger (R-DEL-8) --------------

    def _destructive_setup(self, tmpdir):
        from naalp import approval
        bc = self._valid_2hop(policy.DESTRUCTIVE)
        ledger = approval.open_ledger(os.path.join(tmpdir, "consume.log"))
        approver = _key_for("d4-approver")
        args_cid = _content_id_of(b"the exact canonical action args")
        appr = approval.ApprovalRecord(args_cid, approver.id, policy.DESTRUCTIVE,
                                       b"\x01\x02\x03\x04", 1_000_000)
        sig = approval.sign_approval(appr, ALG, approver.seed)
        return bc, ledger, approver, appr, sig, args_cid

    def test_composition_both_gates_authorize_and_consume(self):
        from naalp import approval
        with tempfile.TemporaryDirectory() as tmp:
            bc, ledger, approver, appr, sig, args_cid = self._destructive_setup(tmp)
            try:
                self.assertIsNone(delegation.authorize_destructive(
                    bc["action"], bc["grants"], set(bc["anchors"]), {}, 500,
                    appr, ALG, approver.pk, sig, args_cid, ledger))
                self.assertTrue(ledger.is_consumed(appr.id()))
            finally:
                ledger.close()

    def test_composition_chain_without_approval_denies(self):
        from naalp import approval
        with tempfile.TemporaryDirectory() as tmp:
            bc, ledger, approver, appr, sig, args_cid = self._destructive_setup(tmp)
            try:
                other = _content_id_of(b"some other args the approval does not bind")
                with self.assertRaises(delegation.DelegationError) as cm:
                    delegation.authorize_destructive(
                        bc["action"], bc["grants"], set(bc["anchors"]), {}, 500,
                        appr, ALG, approver.pk, sig, other, ledger)
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
                self.assertEqual(len(ledger), 0)          # fail-closed: no append on a rejected action
            finally:
                ledger.close()

    def test_composition_broken_chain_precedes_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            bc, ledger, approver, appr, sig, args_cid = self._destructive_setup(tmp)
            try:
                with self.assertRaises(delegation.DelegationError) as cm:
                    delegation.authorize_destructive(
                        bc["action"], bc["grants"], set(), {}, 500,   # no anchors -> untrusted root
                        appr, ALG, approver.pk, sig, args_cid, ledger)
                self.assertEqual(cm.exception.kind, "UntrustedChainRoot")   # chain checked first
                self.assertEqual(len(ledger), 0)
            finally:
                ledger.close()

    def test_composition_approval_replay_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bc, ledger, approver, appr, sig, args_cid = self._destructive_setup(tmp)
            try:
                delegation.authorize_destructive(
                    bc["action"], bc["grants"], set(bc["anchors"]), {}, 500,
                    appr, ALG, approver.pk, sig, args_cid, ledger)
                with self.assertRaises(delegation.DelegationError) as cm:
                    delegation.authorize_destructive(
                        bc["action"], bc["grants"], set(bc["anchors"]), {}, 500,
                        appr, ALG, approver.pk, sig, args_cid, ledger)
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")   # a spent approval is not fresh
                self.assertEqual(len(ledger), 1)
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
