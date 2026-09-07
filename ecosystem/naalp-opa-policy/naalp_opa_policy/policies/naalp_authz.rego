package naalp.authz

import rego.v1

# An administrator-authored N-AALP policy (Part-2 E3.2, requirement R5.2): inspects an
# N-AALP object's authenticated {effect, audience, kind, channel, signer} plus the caller's
# already-resolved {grant: {principal, max_effect}} and refuses an action BEFORE execution.
# This is a WORKED EXAMPLE administrators are expected to adapt -- the shape of the input
# document (naalp_opa_policy.opa_policy.build_input) is the stable contract; this policy's
# rules are not.
#
# Deliberately mirrors, in Rego, the SAME two floor checks Part-1's
# naalp.policy.Grant.authorize_object already enforces in the SDK (identity match + effect
# ceiling) -- this integration is DEFENSE-IN-DEPTH, consulted BEFORE that Part-1 floor, never
# a replacement for it. Adding the audience check is the policy-engine's own value-add: a
# concrete third check an administrator can write here without touching SDK code.

default allow := false

# Effect ceiling (mirrors naalp.policy.authorizes: action <= ceiling): the object's effect
# class must not exceed the capability the grant issued to this signer.
effect_within_ceiling if input.effect <= input.grant.max_effect

# Identity match (mirrors naalp.policy.Grant.authorize_object's principal check): the
# CRYPTOGRAPHICALLY-RESOLVED signer (never a self-asserted field -- see build_input's
# docstring) must be exactly the principal this grant was issued to.
signer_matches_grant if input.signer == input.grant.principal

# Audience: an object naming no audience (a non-consume-once, broadcast-style object) passes;
# an object that DOES name an audience must name exactly this deployment's configured serving
# authority (data.naalp.this_authority, policies/data.json) -- an object addressed elsewhere
# is refused here even before it would reach naalp.envelope.check_audience at the point of use.
audience_ok if input.audience == ""

audience_ok if input.audience == data.naalp.this_authority

allow if {
	signer_matches_grant
	effect_within_ceiling
	audience_ok
}
