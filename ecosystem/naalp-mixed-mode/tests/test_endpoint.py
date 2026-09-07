# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP mixed-mode HTTP discrimination
endpoint (Part-2 N2.1/N2.2, design.md §13.8, D15).

Every test exercises the REAL Part-1 envelope/channels/policy/carriage primitives through the
endpoint's thin discrimination + authorization wrapper -- no cryptography, effect lattice, or
carriage logic is faked.

The D15 anti-bypass property (the task bar's required mutation witness) is
`test_legacy_consume_once_without_signed_audience_is_rejected` and its companion
`test_legacy_consume_once_self_asserted_audience_still_rejected`: a legacy (unsigned) request
targeting a consume-once (channel, kind) MUST be refused regardless of what audience the
untrusted JSON claims, because `endpoint._handle_legacy` never copies a self-asserted audience
onto the surrogate object it checks. See RED-EVIDENCE.md for the recorded mutation.

Run (from ecosystem/naalp-mixed-mode/, PYTHONDONTWRITEBYTECODE=1, using the real Python on
this machine -- not the Microsoft Store `python` stub):
    python -m pytest ../naalp-mixed-mode/tests/  (or: python -m unittest -v tests.test_endpoint)
"""
import json
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-mixed-mode
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mixed_mode import (  # noqa: E402
    MODE_STRICT,
    MODE_LEGACY,
    MixedModeError,
    MixedModeResult,
    MixedModeEndpoint,
    MigrationPolicy,
    default_kind_validator,
)
from naalp import carriage, cbor, cose, channels, envelope, policy  # noqa: E402

ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC
SELF_AUTHORITY = "svc:mixed-mode-endpoint"
BRIDGE_CHANNEL = 0x000D  # Bridge
CARRIAGE_KIND = 0        # Carriage (variable effect 0..3)


def _key(seed_byte=0x11):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _signed_bridge_object(pk, seed, effect, created=1000):
    foreign = b'{"jsonrpc":"2.0","method":"tools/call","params":{}}'
    cb = carriage.carry(0x01, carriage.CLASS_JSONRPC, 0, b"corr-1", "tools/call", foreign)
    obj = envelope.Object(
        kind=CARRIAGE_KIND, channel=BRIDGE_CHANNEL, signer=pk, created=created,
        effect=effect, body=cb.to_value(), tier=0, profile=PROFILE,
    )
    return envelope.sign(obj, ALG, seed)


class DefaultKindValidatorTests(unittest.TestCase):
    """Not a stub: dispatches against the real channels registry (channels.lookup), so its
    output varies with input rather than a constant lambda: True."""

    def test_accepts_a_registered_kind(self):
        self.assertTrue(default_kind_validator(BRIDGE_CHANNEL, CARRIAGE_KIND))

    def test_rejects_an_unregistered_kind(self):
        self.assertFalse(default_kind_validator(BRIDGE_CHANNEL, 99))
        self.assertFalse(default_kind_validator(0x1234, 0))


class StrictPathTests(unittest.TestCase):
    def _endpoint(self, pk, max_effect=policy.DESTRUCTIVE, consume_once_kinds=frozenset()):
        grants = {pk.hex(): policy.Grant(principal=pk.hex(), max_effect=max_effect)}
        return MixedModeEndpoint(
            profile=PROFILE, alg=ALG, pubkey=pk, self_authority=SELF_AUTHORITY,
            grants=grants, consume_once_kinds=consume_once_kinds, allow_legacy=True,
        )

    def test_valid_signed_request_within_grant_succeeds(self):
        seed, pk = _key(0x01)
        signed = _signed_bridge_object(pk, seed, effect=policy.READ_ONLY)
        ep = self._endpoint(pk)
        result = ep.handle(signed)
        self.assertIsInstance(result, MixedModeResult)
        self.assertEqual(result.mode, MODE_STRICT)
        self.assertEqual(result.effect, policy.READ_ONLY)
        self.assertIsNotNone(result.object_)
        self.assertIsNone(result.carriage_body)

    def test_signer_with_no_registered_grant_is_refused(self):
        seed, pk = _key(0x02)
        signed = _signed_bridge_object(pk, seed, effect=policy.READ_ONLY)
        ep = MixedModeEndpoint(
            profile=PROFILE, alg=ALG, pubkey=pk, self_authority=SELF_AUTHORITY, grants={},
        )
        with self.assertRaises(policy.PolicyError) as cm:
            ep.handle(signed)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")

    def test_effect_exceeding_grant_ceiling_is_refused_never_falls_back_to_legacy(self):
        # D15 anti-bypass: a validly-signed, correctly-parsed object whose effect exceeds its
        # grant's ceiling must be REFUSED outright -- never silently reinterpreted as a
        # permissive legacy record just because authorization (not parsing) is what failed.
        seed, pk = _key(0x03)
        signed = _signed_bridge_object(pk, seed, effect=policy.DESTRUCTIVE)
        ep = self._endpoint(pk, max_effect=policy.READ_ONLY)
        with self.assertRaises(policy.PolicyError) as cm:
            ep.handle(signed)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")

    def test_consume_once_kind_without_audience_is_refused(self):
        seed, pk = _key(0x04)
        signed = _signed_bridge_object(pk, seed, effect=policy.READ_ONLY)
        ep = self._endpoint(pk, consume_once_kinds=frozenset({(BRIDGE_CHANNEL, CARRIAGE_KIND)}))
        with self.assertRaises(envelope.EnvelopeError) as cm:
            ep.handle(signed)
        self.assertEqual(cm.exception.kind, "WrongAudience")

    def test_consume_once_kind_with_correct_audience_succeeds(self):
        seed, pk = _key(0x05)
        foreign = b'{"jsonrpc":"2.0","method":"m","params":{}}'
        cb = carriage.carry(0x01, carriage.CLASS_JSONRPC, 0, b"c", "m", foreign)
        obj = envelope.Object(
            kind=CARRIAGE_KIND, channel=BRIDGE_CHANNEL, signer=pk, created=1,
            effect=policy.READ_ONLY, body=cb.to_value(), profile=PROFILE,
            audience=SELF_AUTHORITY,
        )
        signed = envelope.sign(obj, ALG, seed)
        ep = self._endpoint(pk, consume_once_kinds=frozenset({(BRIDGE_CHANNEL, CARRIAGE_KIND)}))
        result = ep.handle(signed)
        self.assertEqual(result.mode, MODE_STRICT)

    def test_bad_signature_falls_back_to_legacy_which_then_fails_closed(self):
        # §13.8(a): "if and only if that parse fails does the endpoint fall back". A tampered
        # signature makes envelope.verify raise BadSignature (a ValueError subclass) -- the
        # request falls back to the legacy path, but the bytes are binary COSE/CBOR, not valid
        # UTF-8 JSON, so it fails closed there too (never silently accepted either way).
        seed, pk = _key(0x06)
        signed = bytearray(_signed_bridge_object(pk, seed, effect=policy.READ_ONLY))
        signed[-1] ^= 0xFF  # flip the last signature byte
        ep = self._endpoint(pk)
        with self.assertRaises(MixedModeError) as cm:
            ep.handle(bytes(signed))
        self.assertEqual(cm.exception.kind, "LegacyMalformed")


class LegacyPathTests(unittest.TestCase):
    def _endpoint(self, pk=None, consume_once_kinds=frozenset(), migration_policy=None):
        seed_pk = pk or _key(0x07)[1]
        grants = {seed_pk.hex(): policy.Grant(principal=seed_pk.hex(), max_effect=policy.DESTRUCTIVE)}
        return MixedModeEndpoint(
            profile=PROFILE, alg=ALG, pubkey=seed_pk, self_authority=SELF_AUTHORITY,
            grants=grants, consume_once_kinds=consume_once_kinds, migration_policy=migration_policy,
            allow_legacy=True,
        )

    def test_default_endpoint_refuses_legacy_body_without_allow_legacy_opt_in(self):
        """AC4: strict is the default. A `MixedModeEndpoint` constructed WITHOUT `allow_legacy`
        (so it defaults False) MUST refuse a legacy JSON body outright -- `MixedModeError
        ("LegacyDisabled")` -- rather than implicitly falling back to `_handle_legacy`. Mirrors
        the Go SDK's `Endpoint.AllowLegacy` zero-value-false / `ErrLegacyDisabled` behavior
        (ecosystem/naalp-agent-go/mixedmode/endpoint.go, endpoint_test.go
        TestHandle_LegacyJSON_AllowLegacyFalse_RefusedLegacyDisabled)."""
        seed, pk = _key(0x09)
        grants = {pk.hex(): policy.Grant(principal=pk.hex(), max_effect=policy.DESTRUCTIVE)}
        ep = MixedModeEndpoint(
            profile=PROFILE, alg=ALG, pubkey=pk, self_authority=SELF_AUTHORITY, grants=grants,
        )
        body = json.dumps({"hello": "world"}).encode("utf-8")
        with self.assertRaises(MixedModeError) as cm:
            ep.handle(body)
        self.assertEqual(cm.exception.kind, "LegacyDisabled")

    def test_plain_legacy_json_with_no_claims_succeeds_read_only(self):
        ep = self._endpoint()
        body = json.dumps({"hello": "world"}).encode("utf-8")
        result = ep.handle(body)
        self.assertEqual(result.mode, MODE_LEGACY)
        self.assertEqual(result.effect, policy.READ_ONLY)
        self.assertIsNotNone(result.carriage_body)
        self.assertEqual(result.carriage_body.foreign, body)  # R-14.4 octet-for-octet
        self.assertEqual(result.carriage_body.klass, carriage.CLASS_HTTP)
        self.assertEqual(result.carriage_body.content_type, 0)

    def test_legacy_json_claiming_elevated_effect_is_refused(self):
        # D15's core rule: "a legacy NPAMP-CC-HTTP JSON request carrying no N-AALP effect class
        # + audience MUST NOT gain effecting authority".
        ep = self._endpoint()
        body = json.dumps({"effect": policy.NON_IDEMPOTENT_WRITE}).encode("utf-8")
        with self.assertRaises(policy.PolicyError) as cm:
            ep.handle(body)
        self.assertEqual(cm.exception.kind, "UnauthenticatedPrincipal")

    def test_legacy_consume_once_without_signed_audience_is_rejected(self):
        """The task-bar mutation-witness test: a legacy record targeting a (channel, kind) this
        endpoint has registered as consume-once, with NO audience claimed at all, must be
        refused. See RED-EVIDENCE.md M1."""
        ep = self._endpoint(consume_once_kinds=frozenset({(BRIDGE_CHANNEL, CARRIAGE_KIND)}))
        body = json.dumps({"channel": BRIDGE_CHANNEL, "kind": CARRIAGE_KIND, "effect": 0}).encode("utf-8")
        with self.assertRaises(envelope.EnvelopeError) as cm:
            ep.handle(body)
        self.assertEqual(cm.exception.kind, "WrongAudience")

    def test_legacy_consume_once_self_asserted_audience_still_rejected(self):
        """Even when the untrusted JSON claims the CORRECT audience string, the endpoint must
        never treat that self-assertion as authoritative -- there is no signature behind it."""
        ep = self._endpoint(consume_once_kinds=frozenset({(BRIDGE_CHANNEL, CARRIAGE_KIND)}))
        body = json.dumps({
            "channel": BRIDGE_CHANNEL, "kind": CARRIAGE_KIND, "effect": 0,
            "audience": SELF_AUTHORITY,
        }).encode("utf-8")
        with self.assertRaises(envelope.EnvelopeError) as cm:
            ep.handle(body)
        self.assertEqual(cm.exception.kind, "WrongAudience")

    def test_legacy_malformed_non_json_body_fails_closed(self):
        ep = self._endpoint()
        with self.assertRaises(MixedModeError) as cm:
            ep.handle(b"not json at all {{{")
        self.assertEqual(cm.exception.kind, "LegacyMalformed")

    def test_legacy_malformed_json_array_body_fails_closed(self):
        ep = self._endpoint()
        with self.assertRaises(MixedModeError) as cm:
            ep.handle(b"[1, 2, 3]")  # valid JSON, but not an object
        self.assertEqual(cm.exception.kind, "LegacyMalformed")

    def test_migration_tightened_endpoint_refuses_legacy_but_strict_still_works(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=1000, sunset_epoch_seconds=2000)
        mp.tighten_to_strict()
        seed, pk = _key(0x08)
        ep = self._endpoint(pk=pk, migration_policy=mp)
        with self.assertRaises(MixedModeError) as cm:
            ep.handle(b'{"hello":"world"}')
        self.assertEqual(cm.exception.kind, "LegacyRefused")
        signed = _signed_bridge_object(pk, seed, effect=policy.READ_ONLY)
        result = ep.handle(signed)
        self.assertEqual(result.mode, MODE_STRICT)
        self.assertEqual(result.headers, {})  # nothing left to announce once strict

    def test_deprecation_and_sunset_headers_attached_while_mixed(self):
        mp = MigrationPolicy(deprecated_since_epoch_seconds=1_700_000_000, sunset_epoch_seconds=1_800_000_000)
        ep = self._endpoint(migration_policy=mp)
        result = ep.handle(b'{"hello":"world"}')
        self.assertEqual(result.headers["Deprecation"], "@1700000000")
        self.assertTrue(result.headers["Sunset"].endswith("GMT"))


if __name__ == "__main__":
    unittest.main()
