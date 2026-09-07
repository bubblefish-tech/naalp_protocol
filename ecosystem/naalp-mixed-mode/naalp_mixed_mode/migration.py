# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The register-mixed -> tighten-to-strict migration state machine for a mixed-mode HTTP
endpoint (design.md §13.8, N2.2), signaling the planned retirement of the legacy
`NPAMP-CC-HTTP` JSON path via the two IETF-registered HTTP response header fields built for
exactly this purpose:

  * `Sunset` (RFC 8594): "The Sunset value is an HTTP-date timestamp, as defined in
    Section 7.1.1.1 of [RFC7231]" -- an IMF-fixdate string, e.g. "Sat, 31 Dec 2018 23:59:59 GMT".
  * `Deprecation` (RFC 9745): an Item Structured Header Field (RFC 9651 §3.3.7 Date) whose
    value is a Unix-timestamp token, e.g. "@1688169599" -- naming WHEN deprecation took effect.
    RFC 9745 requires "the timestamp given in the Sunset HTTP header field MUST NOT be earlier
    than the one given in the Deprecation header field" when both are sent together, which
    `MigrationPolicy` enforces at construction (fail-closed: an inverted pair never builds).

Two states only: MIXED (register-mixed -- both strict and legacy carriage are accepted;
responses carry both headers to announce the coming retirement) and STRICT (tighten-to-strict
-- the legacy path is refused outright, per `endpoint.MixedModeEndpoint._handle_legacy`'s
LegacyRefused check; no headers are emitted, since there is nothing left to announce). The
transition is one-way and irreversible in this API: `tighten_to_strict()` moves MIXED -> STRICT
and raises on a second call (AlreadyStrict) -- there is no `loosen_to_mixed()`, matching D15's
"default strict; legacy is an explicit fail-closed opt-in" posture (an endpoint that has
tightened does not silently re-open the legacy path)."""
from email.utils import formatdate

STATE_MIXED = "mixed"
STATE_STRICT = "strict"


class MigrationError(ValueError):
    """A named, fail-closed migration-policy error; .kind is the stable error kind."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def _http_date(epoch_seconds: int) -> str:
    """RFC 7231 §7.1.1.1 IMF-fixdate, e.g. "Sat, 31 Dec 2018 23:59:59 GMT" -- the Sunset value
    format (RFC 8594 §3)."""
    return formatdate(epoch_seconds, usegmt=True)


def _deprecation_token(epoch_seconds: int) -> str:
    """RFC 9745's Item Structured Header Field Date token, "@<unix-timestamp>" (RFC 9651
    §3.3.7)."""
    return "@%d" % epoch_seconds


class MigrationPolicy:
    """The register-mixed -> tighten-to-strict transition for one mixed-mode endpoint.
    `deprecated_since_epoch_seconds` is the timestamp the `Deprecation` header names (when the
    legacy path was announced deprecated); `sunset_epoch_seconds` is the timestamp the `Sunset`
    header names (when the legacy path will stop being accepted). RFC 9745 requires Sunset to
    not precede Deprecation -- an inverted pair raises InvertedTimestamps at construction,
    never silently accepted (fail-closed)."""

    __slots__ = ("state", "deprecated_since_epoch_seconds", "sunset_epoch_seconds")

    def __init__(self, deprecated_since_epoch_seconds: int, sunset_epoch_seconds: int,
                 state: str = STATE_MIXED):
        if sunset_epoch_seconds < deprecated_since_epoch_seconds:
            raise MigrationError(
                "InvertedTimestamps",
                "the Sunset timestamp must not be earlier than the Deprecation timestamp (RFC 9745)",
            )
        if state not in (STATE_MIXED, STATE_STRICT):
            raise MigrationError("UnknownState", "state must be %r or %r" % (STATE_MIXED, STATE_STRICT))
        self.state = state
        self.deprecated_since_epoch_seconds = deprecated_since_epoch_seconds
        self.sunset_epoch_seconds = sunset_epoch_seconds

    def tighten_to_strict(self) -> None:
        """The one-way register-mixed -> tighten-to-strict transition. Raises AlreadyStrict on
        a second call: there is no path back to MIXED through this API."""
        if self.state == STATE_STRICT:
            raise MigrationError("AlreadyStrict", "the migration policy has already tightened to strict-only")
        self.state = STATE_STRICT

    def deprecation_headers(self) -> dict:
        """The RFC 9745 `Deprecation` + RFC 8594 `Sunset` header pair to attach to a response
        while this endpoint is still in MIXED state; the empty dict once tightened to STRICT
        (there is nothing left to announce -- the legacy path is simply gone)."""
        if self.state != STATE_MIXED:
            return {}
        return {
            "Deprecation": _deprecation_token(self.deprecated_since_epoch_seconds),
            "Sunset": _http_date(self.sunset_epoch_seconds),
        }
