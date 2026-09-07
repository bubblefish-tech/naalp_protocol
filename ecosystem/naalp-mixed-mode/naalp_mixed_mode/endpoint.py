# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""N-AALP mixed-mode HTTP discrimination endpoint (design.md §13.8, R11).

A `MixedModeEndpoint` is ONE HTTP endpoint that accepts EITHER a strict N-AALP CBOR/COSE
envelope OR a legacy `NPAMP-CC-HTTP` JSON body on the SAME channel, per design.md §13.8(a):
the endpoint FIRST attempts to parse+cryptographically-verify the request body as a strict
N-AALP envelope (a COSE_Sign1-wrapped naalp-object, §2/§4). If and only if that attempt fails
does it fall back to interpreting the body as a `ClassHTTP` (class=1) / `content_type=0` (json)
legacy carriage payload (§13.2, §13.7). No new wire field, CDDL production, or `naalp-version`
bump is introduced -- the discrimination is a parsing-order policy at the endpoint, reusing the
already-registered carriage class/content-type tag.

The mixed-mode discrimination rule (design.md §13.8, R11):
Default STRICT. The legacy/untyped path is an explicit FAIL-CLOSED opt-in that gains NO
authority the strict checks (effect-class, audience, signature) would deny -- a legacy request
carrying no signed effect class + audience MUST NOT gain effecting authority. The legacy path
is read-only-equivalent unless upgraded to a signed strict N-AALP envelope (§2) carrying an
explicit effect class (§6.1, §6.3) and, where consume-once semantics apply, an `audience`
(§2.5.3). No code path here routes a legacy-origin record around the effect-authorization gate
(channels.check_effect / policy.Grant.authorize_object / envelope.check_audience) on the theory
that "it isn't really an N-AALP object" -- a permissive second parser that skipped the strict
authorization checks would be a request-smuggling shape, which this module is built to foreclose:

  * The STRICT path calls the real Part-1 chokepoints unchanged: `channels.check_effect`,
    `policy.Grant.authorize_object` (which in turn calls `policy.resolve_auth_principal` --
    only a signature-derived identity is ever an authorization principal, R-6.5), and, for a
    consume-once (channel, kind), `envelope.check_audience`.
  * The LEGACY path is UNSIGNED by construction, so it can never present a signature-derived
    principal. Any legacy claim of an effect above read_only is routed through the SAME
    `policy.resolve_auth_principal` gate with a non-signature source
    (`policy.SOURCE_FOREIGN_HEADER`), which unconditionally refuses (UnauthenticatedPrincipal)
    -- exactly the same refusal a forged-source strict request would get. And any legacy claim
    targeting a (channel, kind) this endpoint has registered as consume-once is routed through
    the SAME `envelope.check_audience` gate with a surrogate whose `audience` is left absent
    (a self-asserted audience string in the untrusted JSON is NEVER copied onto the surrogate,
    because a claim with no signature behind it carries no authority to bind an audience) --
    `check_audience`'s own absent-audience-on-consume-once branch then raises WrongAudience,
    unconditionally, for every legacy record.

The result: a legacy record can only ever succeed as read_only-equivalent, non-consume-once
carriage. Reaching any higher effect requires actually presenting a signed strict N-AALP
envelope, which takes the strict path from the start.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import json
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Optional, Tuple

from naalp import carriage, cbor, channels, envelope, policy

MODE_STRICT = "strict"
MODE_LEGACY = "legacy"

# §13.4: HTTP carriage's registered standards protocol_id (the reference id this SDK defaults
# a legacy NPAMP-CC-HTTP carriage body to when the caller does not name a specific protocol).
DEFAULT_LEGACY_PROTOCOL_ID = 0x03


class MixedModeError(ValueError):
    """A named, fail-closed mixed-mode endpoint error; .kind is the stable error kind."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def default_kind_validator(channel_id: int, kind: int) -> bool:
    """The default strict-path kind validator: REAL dispatch against the frozen twenty-channel
    baseline registry (naalp.channels.lookup), never a permissive `lambda: True`. A (channel,
    kind) pair not registered there is rejected (mirrors envelope.verify's own UnknownKind
    check-order slot, §3.2)."""
    try:
        channels.lookup(channel_id, kind)
        return True
    except channels.UnknownKind:
        return False


@dataclass(frozen=True)
class MixedModeResult:
    """The outcome of one `MixedModeEndpoint.handle()` call. `mode` names which path processed
    the request (MODE_STRICT / MODE_LEGACY). `effect` is the resolved, AUTHORIZED effect class
    (never a self-asserted or unchecked value). `object_` carries the verified strict
    `envelope.Object` (MODE_STRICT only); `carriage_body` carries the wrapped legacy carriage
    body (MODE_LEGACY only). `headers` carries any RFC 9745 Deprecation / RFC 8594 Sunset
    headers a configured `migration.MigrationPolicy` wants attached to the response."""

    mode: str
    effect: int
    object_: Optional["envelope.Object"] = None
    carriage_body: Optional["carriage.CarriageBody"] = None
    headers: Dict[str, str] = field(default_factory=dict)


class MixedModeEndpoint:
    """ONE HTTP endpoint discriminating strict N-AALP envelopes from legacy NPAMP-CC-HTTP JSON
    bodies on the same channel (design.md §13.8).

    `profile`/`alg`/`pubkey` are the fixed verification context for the strict path (a
    mixed-mode endpoint here models one signed peer relationship, matching the SDK-facing scope
    of E1.6 -- not a multi-tenant PKI registry). `kind_validator` defaults to
    `default_kind_validator`. `self_authority` is this endpoint's own consuming-authority id,
    passed to `envelope.check_audience` for both paths. `grants` maps a signer's hex-encoded
    public key to the `policy.Grant` authorizing that signer's ceiling effect; a strict request
    from a signer with no registered grant is refused (EffectNotAuthorized) -- no default,
    ambient authority. `consume_once_kinds` is the set of (channel, kind) pairs this endpoint
    treats as single-use/audience-bound (§2.5.3) on EITHER path. `legacy_protocol_id` is the
    carriage `protocol_id` a recognized legacy body is wrapped under (§13.4).
    `migration_policy` is an optional `migration.MigrationPolicy` whose deprecation headers are
    attached to every result, and which -- once tightened to strict -- makes the legacy path
    refuse outright (LegacyRefused). `allow_legacy` (AC4) is the explicit, fail-closed opt-in
    into the legacy fallback at all: it DEFAULTS FALSE (strict-only), mirroring the Go SDK's
    `Endpoint.AllowLegacy` field (ecosystem/naalp-agent-go/mixedmode/endpoint.go) -- a caller
    must set it True before `handle()` will even ATTEMPT the legacy path on a strict-parse
    failure. There is no implicit fallback: a strict-only endpoint that receives a body its
    strict parser rejects is refused `LegacyDisabled`, never silently retried as legacy."""

    def __init__(
        self,
        *,
        profile: int,
        alg: int,
        pubkey: bytes,
        self_authority: str,
        grants: Dict[str, "policy.Grant"],
        kind_validator: Callable[[int, int], bool] = default_kind_validator,
        consume_once_kinds: FrozenSet[Tuple[int, int]] = frozenset(),
        legacy_protocol_id: int = DEFAULT_LEGACY_PROTOCOL_ID,
        migration_policy=None,
        allow_legacy: bool = False,
    ):
        self._profile = profile
        self._alg = alg
        self._pubkey = bytes(pubkey)
        self._kind_validator = kind_validator
        self._self_authority = self_authority
        self._grants = dict(grants)
        self._consume_once_kinds = frozenset(consume_once_kinds)
        self._legacy_protocol_id = legacy_protocol_id
        self._migration = migration_policy
        self._allow_legacy = allow_legacy

    def _headers(self) -> Dict[str, str]:
        if self._migration is None:
            return {}
        return self._migration.deprecation_headers()

    def handle(self, body: bytes, *, correlation: bytes = b"", method: str = "") -> MixedModeResult:
        """Discriminate and process one request body (§13.8(a)). Attempts the strict parse
        first; ANY failure there (structural, ContentIdMismatch, UnknownKind, an unregistered
        alg, a profile-floor downgrade, or a bad signature -- every failure `envelope.verify`
        itself raises is a `ValueError` subclass, exactly the check-order §13.8(a) calls "that
        parse fails") falls back to the legacy path -- but ONLY when `allow_legacy` was
        explicitly set True at construction (AC4). A strict-only endpoint (the default) that
        cannot parse a body as a strict envelope refuses it outright, `MixedModeError
        ("LegacyDisabled")`, rather than implicitly attempting the legacy interpretation: there
        is no second, permissive parser a caller can reach without opting in. A SUCCESSFUL
        strict parse never falls back: from there, authorization failures (EffectNotAuthorized,
        WrongAudience, ...) propagate as hard fail-closed rejections of the whole request (R11
        AC1's anti-bypass rule -- a validly-signed-but-over-privileged object is REFUSED, never
        silently reinterpreted as a permissive legacy record)."""
        try:
            obj = envelope.verify(self._profile, self._alg, self._pubkey, self._kind_validator, body)
        except ValueError:
            if not self._allow_legacy:
                raise MixedModeError(
                    "LegacyDisabled",
                    "endpoint is strict-only; allow_legacy was not explicitly enabled, so a "
                    "strict-parse failure is refused rather than silently retried as legacy",
                )
            return self._handle_legacy(body, correlation=correlation, method=method)
        return self._authorize_strict(obj)

    def _authorize_strict(self, obj: "envelope.Object") -> MixedModeResult:
        # (1) the object's declared effect must match its kind's C10 declaration (§3.2).
        channels.check_effect(obj.channel, obj.kind, obj.effect)
        # (2) the C5 effect-authorization gate: a signature-derived principal, checked against
        # a REGISTERED grant's ceiling (R-6.3/R-6.5) -- never a default/ambient grant.
        principal = bytes(obj.signer).hex()
        grant = self._grants.get(principal)
        if grant is None:
            raise policy.PolicyError(
                "EffectNotAuthorized", "no grant registered for signer %s" % principal
            )
        grant.authorize_object(policy.SOURCE_SIGNATURE, principal, obj.effect)
        # (3) the §2.5.3 single-use consume binding, for a (channel, kind) this endpoint has
        # registered as consume-once.
        if (obj.channel, obj.kind) in self._consume_once_kinds:
            envelope.check_audience(obj, self._self_authority, consume_once=True)
        return MixedModeResult(
            mode=MODE_STRICT, effect=obj.effect, object_=obj, headers=self._headers()
        )

    def _handle_legacy(self, body: bytes, *, correlation: bytes, method: str) -> MixedModeResult:
        if self._migration is not None and self._migration.state == "strict":
            raise MixedModeError(
                "LegacyRefused",
                "the migration policy has tightened to strict-only; legacy carriage is no "
                "longer accepted on this endpoint",
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MixedModeError(
                "LegacyMalformed", "legacy body is not a strict envelope and is not valid UTF-8 JSON (%s)" % exc
            )
        if not isinstance(payload, dict):
            raise MixedModeError(
                "LegacyMalformed", "legacy NPAMP-CC-HTTP body must be a JSON object"
            )

        # The claimed effect/audience/channel/kind below are SELF-ASSERTED, UNSIGNED JSON --
        # never trusted as authorization input on their own. They are read only to decide
        # whether this record needs to be REFUSED for asking for more than read-only-equivalent
        # carriage; the actual refusal is always produced by the SAME chokepoints the strict
        # path uses (policy.resolve_auth_principal / envelope.check_audience), never by ad hoc
        # comparison logic here (D15's anti-bypass rule).
        try:
            requested_effect = policy.normalize_effect(int(payload.get("effect", policy.READ_ONLY)))
            claimed_channel = payload.get("channel")
            claimed_kind = payload.get("kind")
            if claimed_channel is not None:
                claimed_channel = int(claimed_channel)
            if claimed_kind is not None:
                claimed_kind = int(claimed_kind)
        except (TypeError, ValueError) as exc:
            raise MixedModeError(
                "LegacyMalformed", "legacy body's effect/channel/kind fields are not integers (%s)" % exc
            )
        claimed_method = str(payload.get("method", method or ""))

        carriage_body = carriage.carry(
            protocol_id=self._legacy_protocol_id,
            klass=carriage.CLASS_HTTP,
            content_type=0,  # §13.7: content_type 0 = json
            correlation=correlation,
            method=claimed_method,
            foreign=body,
        )

        if requested_effect > policy.READ_ONLY:
            # D15: an unsigned legacy claim gains NO effecting authority. Force the SAME
            # authorization primitive the strict path's Grant.authorize_object calls; a legacy
            # record has no signature-derived principal, so this call unconditionally refuses
            # (UnauthenticatedPrincipal, R-6.5) -- never a second, permissive parser that skips
            # the gate.
            policy.resolve_auth_principal(policy.SOURCE_FOREIGN_HEADER, "")

        if claimed_channel is not None and claimed_kind is not None:
            key = (claimed_channel, claimed_kind)
            if key in self._consume_once_kinds:
                # D15: the same reasoning applies to the audience-binding gate. Build a
                # surrogate object carrying the UNAUTHENTICATED signer (b"") and, critically,
                # leave `audience` at its default "" -- the JSON's self-asserted `audience`
                # field (if any) is NEVER copied here, because an unsigned claim carries no
                # authority to bind one. envelope.check_audience's own absent-audience-on-
                # consume-once branch then refuses unconditionally (WrongAudience).
                surrogate = envelope.Object(
                    kind=key[1], channel=key[0], signer=b"", created=0,
                    effect=requested_effect, body=cbor.M([]),
                )
                envelope.check_audience(surrogate, self._self_authority, consume_once=True)

        return MixedModeResult(
            mode=MODE_LEGACY, effect=policy.READ_ONLY, carriage_body=carriage_body,
            headers=self._headers(),
        )
