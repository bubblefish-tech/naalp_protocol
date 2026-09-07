# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The R3.3 firewall-hook entry point: exposes the semantic validator as a single synchronous
call a pre-send interception point can invoke -- one candidate object in, one fail-closed
decision out. This is the calling convention N-PAMP Part 2 R1's firewall is cross-referenced
against; no such firewall component exists yet in this repository (N-PAMP Part 2 is separate,
future work), so this module is demonstrated here in isolation (A9) as the stable entry point
that component will call, not claimed as already wired into any specific gateway.
"""
from . import validator

__all__ = ["FirewallDecision", "pre_send_hook"]


class FirewallDecision:
    """allow=True iff the candidate had zero violations. Always fail-closed: any violation,
    of any kind, denies -- there is no partial-accept path, matching the wire's own
    fail-closed discipline (a rejected object causes no state change)."""
    __slots__ = ("allow", "violations")

    def __init__(self, allow, violations):
        self.allow = allow
        self.violations = list(violations)

    def __bool__(self):
        return self.allow

    def __repr__(self):
        return "FirewallDecision(allow=%r, violations=%r)" % (self.allow, self.violations)


def pre_send_hook(candidate, *, self_authority=None):
    """Validate `candidate` (see `validator.validate` for the accepted shapes and the checks
    performed) and return a FirewallDecision. A firewall/gateway wires this in at the point
    an agent runtime is about to sign and transmit an object; on deny, the caller MUST NOT
    proceed to sign -- a denied candidate never reaches the wire."""
    result = validator.validate(candidate, self_authority=self_authority)
    return FirewallDecision(allow=result.valid, violations=result.violations)
