<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Channel: Capability (`0x0002`)

Capability tokens: issuance, delegation, revocation, and lookup. Like every channel surface,
Capability adds **only** kind codes and their declared effects over the one object model — no
channel-local encoding, signature, or identity (the draft's Channel Surfaces section).

## Baseline kinds

| Code | Kind | Effect | Notes |
|---|---|---|---|
| 0 | `CapIssue` | `non_idempotent_write` | issue a new capability token |
| 1 | `CapDelegate` | `non_idempotent_write` | delegate a capability, forming a `causes` chain to its parent |
| 2 | `CapRevoke` | `destructive` | revoke a capability |
| 3 | `CapLookup` | `read_only` | look up a capability's status |

This is the baseline registry `impl/go/channels/channels.go` carries verbatim
([Table entry for Capability](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L61-L62)),
cross-checked against an independent per-channel oracle so Go, Rust, and the oracle agree on
every kind code and effect.

## State model

A capability is `issued → (delegated…)* → (revoked | expired)`. Delegation forms a `causes`
chain (the draft's Audit, Causal Graph, and Ordering section) so a delegated capability names its parent by content id — the parent
relationship is not a separate field, it is the object graph itself.

## The attenuation rule: `CapExceedsParent`

The one channel-specific structural check Capability defines is that **a delegation may not
grant more than its parent**. `CheckDelegation` in the shared registry enforces the effect
ceiling:

```go
// impl/go/channels/channels.go
func CheckDelegation(parentMax, childMax policy.Effect) error {
	if !parentMax.Authorizes(childMax) { // childMax <= parentMax
		return ErrCapExceedsParent
	}
	return nil
}
```

([`CheckDelegation`, channels.go:184-189](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels.go#L184-L189)),
tested directly by
[`TestCapExceedsParent`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/channels/channels_test.go#L188-L196):
a delegation asking for a `Destructive` ceiling under a `NonIdempotentWrite` parent is rejected
`CapExceedsParent`; a delegation asking for a ceiling at or below the parent's succeeds. This is
the same lattice-attenuation rule from the draft's Effects and Authorization section, and it is the one rule every
higher-privilege escalation in the protocol — including the tier-1 multi-hop delegation below —
reuses rather than re-deriving.

## Tier 1+: multi-hop agent delegation

Capability's baseline (`CapIssue` / `CapDelegate`) answers **what** a token may do in a single
hop. A tier-1 escalation, `DelegationGrant` (the draft's Channel Surfaces section), answers a related but
distinct question: **who** may act on whose behalf, across multiple hops, terminating at a
trust anchor. It is deliberately built as an escalation of the same substrate rather than a
parallel mechanism — the delegation parent is still named by content id in `causes` (the draft's Audit, Causal Graph, and Ordering section), and it reuses the identical `CapExceedsParent` attenuation rule:

```go
// impl/go/delegation/delegation.go
const (
	ChannelCapability   uint64 = 0x0002 // reuses the CapDelegate substrate
	KindDelegationGrant uint64 = 4      // the next free code after CapIssue/CapDelegate/CapRevoke/CapLookup
	Tier                uint64 = 1      // a named escalation, not a deferral
)
```

([`delegation.go:41-50`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/delegation/delegation.go#L41-L50)).
A `Grant` carries the delegatee (`Subject`), the effect ceiling it confers (`EffectCap`), the
maximum further onward-delegation depth (`MaxDepth`), an optional resource `Scope`, and a
validity window — the issuer is never a body field, it is the verified envelope signer
(the draft's Channel Surfaces section). Chain verification is a 12-step leaf-to-root walk, graded so that Go and
Rust reproduce the independent oracle's verdict for every scenario over real ML-DSA-65 signed
chains — including expired grants, revoked grants, untrusted chain roots, and a chain whose
realized depth exceeds `MaxDepth`.

## Failure modes

| Error kind | When |
|---|---|
| `CapExceedsParent` | a delegation (baseline or tier-1) asks for more than its parent grants |
| `CapRevoked` | the capability named has been revoked |
| `ChainBroken` | (tier-1) a delegation-chain link is missing, ambiguous, or unverifiable |
| `GrantExpired` / `GrantNotYetValid` / `GrantRevoked` | (tier-1) the grant is outside its validity window, or revoked |
| `UntrustedChainRoot` | (tier-1) the chain's root issuer is not in the trust-anchor set |
| `DelegationDepthExceeded` | (tier-1) the declared or realized depth exceeds `MaxDepth` |
| `NonNFC` | (tier-1) `Subject` or `Scope` is not Unicode NFC |
| `GrantMalformed` | (tier-1) the grant body is not the expected shape or has an out-of-range field |

Every check is fail-closed (the draft's Security Considerations section): a failing action is rejected whole, returns its
named error, and causes no state change. There is no partial credit and no fail-open path.

See also: [the twenty channels](../spec/channels.md), [effects and safety](../spec/object-model.md).
