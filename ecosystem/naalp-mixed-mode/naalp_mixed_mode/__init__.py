# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_mixed_mode -- the N-AALP mixed-mode HTTP discrimination SDK (Part-2 N2.1/N2.2,
design.md §13.8, R11, D15).

ONE endpoint that accepts EITHER a strict N-AALP CBOR/COSE envelope OR a legacy
`NPAMP-CC-HTTP` JSON body on the same channel, discriminating via the existing carriage
`class`/`content_type` primitives (§13.2, §13.7) and enforcing D15's anti-bypass authorization
rule: the legacy path gains NO effecting authority the strict path would deny. See
endpoint.py for the discrimination + authorization machinery and migration.py for the
register-mixed -> tighten-to-strict transition and its RFC 9745 Deprecation / RFC 8594 Sunset
headers.
"""
from .endpoint import (
    MODE_STRICT,
    MODE_LEGACY,
    DEFAULT_LEGACY_PROTOCOL_ID,
    MixedModeError,
    MixedModeResult,
    MixedModeEndpoint,
    default_kind_validator,
)
from .migration import (
    STATE_MIXED,
    STATE_STRICT,
    MigrationError,
    MigrationPolicy,
)

__all__ = [
    "MODE_STRICT",
    "MODE_LEGACY",
    "DEFAULT_LEGACY_PROTOCOL_ID",
    "MixedModeError",
    "MixedModeResult",
    "MixedModeEndpoint",
    "default_kind_validator",
    "STATE_MIXED",
    "STATE_STRICT",
    "MigrationError",
    "MigrationPolicy",
]

__version__ = "0.1.0"
