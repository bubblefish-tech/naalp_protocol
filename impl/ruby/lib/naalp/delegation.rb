# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C15 multi-hop AGENT delegation for the Ruby SDK (design.md §18; R-DEL-1..8), a Phase-3
# draft-01 ADDITIVE tier-1 surface over the frozen spine (design.md §2..§10). It introduces NO new
# envelope, encoding, signature, identity, or audit mechanism (R-11.3): a DelegationGrant is a normal
# N-AALP object (envelope §2), and the mechanism REUSES the -00 CapDelegate substrate --
# parent-by-content-id in `causes` (§8.2) and the `CapExceedsParent` attenuation (§6.1 lattice) --
# rather than a parallel mechanism. The only additions over CapDelegate are the body's `subject`,
# `max_depth`, and validity window.
#
# Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
# terminates at a trust anchor. A DelegationGrant is a tier-1 Capability surface (kind 4); its body
# carries the delegatee `subject`, the `effect_cap` ceiling it confers, the `max_depth`
# onward-delegation bound, and the validity window (plus an optional `scope`). The ISSUER is NOT a
# body field -- it is the verified envelope signer (R-DEL-3); the delegation PARENT is named by
# content id in the envelope `causes`.
#
# The two graded surfaces: the DelegationGrant wire body (byte-graded == oracle), and the 12-step
# leaf->root chain verifier (verdict-graded == oracle, over REAL ML-DSA-65 signed chains). Every
# check is fail-closed (§15): an action that fails any step is rejected whole, returns its named
# error, and causes no state change. Ported from impl/go/delegation (cross-read against
# impl/python/naalp/delegation.py); graded against vectors/delegation/cases.json. The D4 composition
# (authorize_destructive) reuses the new approval module's single-use consume ledger for the
# per-action approval gate -- a real wiring of delegation onto approval, not a stub.
require_relative 'cbor'
require_relative 'cose'
require_relative 'channels'
require_relative 'envelope'
require_relative 'identity'
require_relative 'policy'
require_relative 'approval'

module Naalp
  module Delegation
    U = Naalp::CBOR::U
    T = Naalp::CBOR::T
    M = Naalp::CBOR::M

    # Channel binding, the tier-1 kind code, and the tier for agent-delegation (design §18.1).
    CHANNEL_CAPABILITY = 0x0002    # Capability channel (reuses the CapDelegate substrate)
    KIND_DELEGATION_GRANT = 4      # tier-1 kind code, the next free code after CapIssue/Delegate/Revoke/Lookup
    TIER = 1                       # a named escalation adding multi-hop capability

    # A grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write. This is
    # separate from the body's effect_cap, which is the ceiling the grant CONFERS on its subject.
    GRANT_EFFECT = Naalp::Policy::NON_IDEMPOTENT_WRITE

    # A named, fail-closed delegation error; #kind is the stable error kind (§18.6, §15). Kinds reused
    # from other layers (CapExceedsParent, EffectNotAuthorized, ApprovalRequired, SignerMismatch,
    # AlreadyConsumed) carry those exact kind strings so a verifier's verdict is identical to the Go
    # reference.
    class DelegationError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # ---- the DelegationGrant object body (design §18.1, §18.5) ------------------------------------

    # The signed body of a DelegationGrant. `subject` is the delegatee agent id (signer-id form, MUST
    # be NFC); `effect_cap` is the max effect this grant conveys; `max_depth` the max FURTHER
    # delegation hops below it; `not_before`/`not_after` the validity window; `scope` an OPTIONAL NFC
    # resource scope ("" = absent/unconstrained, field 6 omitted).
    class Grant
      attr_accessor :subject, :effect_cap, :max_depth, :not_before, :not_after, :scope

      def initialize(subject, effect_cap, max_depth, not_before, not_after, scope = "")
        @subject = subject
        @effect_cap = effect_cap.to_i
        @max_depth = max_depth.to_i
        @not_before = not_before.to_i
        @not_after = not_after.to_i
        @scope = scope || ""
      end

      def to_map
        pairs = [
          [U.new(1), T.new(@subject)],
          [U.new(2), U.new(@effect_cap)],
          [U.new(3), U.new(@max_depth)],
          [U.new(4), U.new(@not_before)],
          [U.new(5), U.new(@not_after)],
        ]
        pairs << [U.new(6), T.new(@scope)] if @scope != "" # "" == absent (field 6 omitted)
        M.new(pairs)
      end

      # Deterministic-CBOR encoding {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,
      # ?6:scope}.
      def bytes
        Naalp::CBOR.encode(to_map)
      end

      # The grant body's content id: multihash(0x20, SHA-384(body)). This is the body's self-address;
      # the ENVELOPE content id is what a delegation chain wires into `causes`.
      def content_id
        Naalp::CBOR.content_id(bytes)
      end

      # Build the (unsigned) N-AALP envelope object carrying this grant: tier 1, Capability channel,
      # kind DelegationGrant, the grant's own effect non_idempotent_write, the grant body as the object
      # body, and `causes` naming the delegation parent by content id (empty for a root grant). A
      # non-NFC subject/scope or an out-of-range effect_cap is rejected fail-closed.
      def envelope_object(issuer, created, profile, causes)
        begin
          Naalp::Identity.require_nfc(@subject)
        rescue Naalp::Identity::NonNFC
          raise DelegationError.new("NonNFC", "subject is not Unicode NFC")
        end
        if @scope != ""
          begin
            Naalp::Identity.require_nfc(@scope)
          rescue Naalp::Identity::NonNFC
            raise DelegationError.new("NonNFC", "scope is not Unicode NFC")
          end
        end
        if @effect_cap > Naalp::Policy::DESTRUCTIVE
          raise DelegationError.new("GrantMalformed", "effect_cap outside the closed lattice")
        end
        Naalp::Envelope::Object.new(
          kind: KIND_DELEGATION_GRANT, channel: CHANNEL_CAPABILITY, tier: TIER,
          signer: issuer, created: created, effect: GRANT_EFFECT,
          causes: causes, profile: profile, body: to_map)
      end
    end

    # A DelegationGrant that has passed envelope verification and integrity binding: its ENVELOPE
    # content id (what `causes` point to), its verified issuer id (the envelope signer -- NOT a body
    # field, R-DEL-3), the parsed grant body, and the grant's own `causes`.
    Resolved = Struct.new(:content_id, :issuer, :grant, :causes)

    # The verified action whose delegated authority is being checked. It carries the acting agent (the
    # verified signer of the action object), the action's own effect and resource scope (the running
    # child at the leaf hop), and the action's `causes` (from which the leaf grant is located).
    class Action
      attr_reader :signer, :effect, :scope, :causes
      def initialize(signer, effect, scope, causes)
        @signer = signer.dup.force_encoding(Encoding::UTF_8)
        @effect = effect.to_i
        @scope = scope
        @causes = causes.map { |c| c.dup.force_encoding(Encoding::BINARY) }
      end
    end

    module_function

    # Sign a DelegationGrant envelope object with a real deterministic ML-DSA key; the signer BECOMES
    # the grant's issuer (R-DEL-3).
    def sign_grant(obj, alg, seed)
      Naalp::Envelope.sign(obj, alg, seed)
    end

    # Parse an envelope object body back into a Grant. A body that is not exactly the {1,2,3,4,5,?6}
    # map with the right value types and an in-range effect_cap is an unverifiable/malformed grant link
    # and is rejected ChainBroken (fail-closed). An out-of-range effect_cap is NEVER normalized up
    # (that would widen a ceiling -- fail-open); it is rejected.
    def grant_from_body(v)
      raise DelegationError.new("ChainBroken", "grant body is not a map") unless v.is_a?(M)
      g = Grant.new("", 0, 0, 0, 0, "")
      seen = {}
      v.pairs.each do |k, val|
        unless k.is_a?(U) && k.v >= 1 && k.v <= 6
          raise DelegationError.new("ChainBroken", "grant body has an out-of-range field")
        end
        case k.v
        when 1
          raise DelegationError.new("ChainBroken", "subject is not a tstr") unless val.is_a?(T)
          g.subject = val.v
        when 2
          unless val.is_a?(U) && val.v <= Naalp::Policy::DESTRUCTIVE
            raise DelegationError.new("ChainBroken", "effect_cap absent or out of range")
          end
          g.effect_cap = val.v
        when 3
          raise DelegationError.new("ChainBroken", "max_depth is not a uint") unless val.is_a?(U)
          g.max_depth = val.v
        when 4
          raise DelegationError.new("ChainBroken", "not_before is not a uint") unless val.is_a?(U)
          g.not_before = val.v
        when 5
          raise DelegationError.new("ChainBroken", "not_after is not a uint") unless val.is_a?(U)
          g.not_after = val.v
        when 6
          raise DelegationError.new("ChainBroken", "scope is not a tstr") unless val.is_a?(T)
          g.scope = val.v
        end
        seen[k.v] = true
      end
      unless [1, 2, 3, 4, 5].all? { |n| seen[n] } # scope (6) is optional
        raise DelegationError.new("ChainBroken", "grant body is missing a mandatory field")
      end
      g
    end

    # ---- kind validation (composes with the frozen baseline) -------------------------------------

    # Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant).
    def kind_validator?(channel, kind)
      channel == CHANNEL_CAPABILITY && kind == KIND_DELEGATION_GRANT
    end

    def baseline_kind_validator?(channel, kind)
      Naalp::Channels.lookup(channel, kind)
      true
    rescue Naalp::Channels::UnknownKind
      false
    end

    # Accepts the frozen baseline kinds OR the tier-1 DelegationGrant -- the validator a
    # delegation-aware endpoint passes to envelope.verify. A baseline-only endpoint using the baseline
    # validator alone correctly rejects a DelegationGrant as UnknownKind (fail-closed).
    def composed_kind_validator(channel, kind)
      baseline_kind_validator?(channel, kind) || kind_validator?(channel, kind)
    end

    # ---- verified grants + the trust/revocation inputs -------------------------------------------

    # Verify a signed DelegationGrant end-to-end with real crypto (envelope.verify against the composed
    # validator), confirm it is a tier-1 Capability DelegationGrant whose own effect is
    # non_idempotent_write, bind the claimed issuer id to the verifying key (a self-asserted issuer
    # that does not derive from the authenticated key confers nothing, R-DEL-3), and parse the grant
    # body. Any failure is an unverifiable link (ChainBroken / SignerMismatch / the envelope's named
    # error), fail-closed.
    def verify_grant_object(profile, alg, pubkey, signed_obj)
      validator = ->(ch, k) { composed_kind_validator(ch, k) }
      o = Naalp::Envelope.verify(profile, alg, pubkey, validator, signed_obj)
      if o.channel != CHANNEL_CAPABILITY || o.kind != KIND_DELEGATION_GRANT || o.tier != TIER
        raise DelegationError.new("ChainBroken", "not a tier-1 Capability DelegationGrant")
      end
      if o.effect != GRANT_EFFECT
        raise DelegationError.new("ChainBroken", "a DelegationGrant's own effect must be non_idempotent_write")
      end
      issuer = Naalp::Identity.signer_id(alg, pubkey)
      unless o.signer.b == issuer.b # the envelope signer field MUST be the authenticated id
        raise DelegationError.new("SignerMismatch", "issuer id does not derive from the verifying key")
      end
      g = grant_from_body(o.body)
      Resolved.new(o.id, issuer, g, o.causes)
    end

    # Build a GrantSet (a Hash keyed by envelope content id bytes) from verified grants, so the chain
    # walk can resolve a parent named in `causes`.
    def new_grant_set(*grants)
      s = {}
      grants.each { |g| s[g.content_id.b] = g }
      s
    end

    # Whether the grant named by content id `cid` is revoked as of `now` (a revoke ordered at or before
    # `now`). `revoked` is a Hash keyed by content id bytes -> revoke position.
    def revoked_at?(revoked, cid, now)
      p = revoked[cid.b]
      !p.nil? && p <= now
    end

    # ---- D2 scope containment (design §18.1) -----------------------------------------------------

    # Whether `child` is contained in `parent` under the D2 path-prefix rule: an absent parent scope
    # ("") is unconstrained; otherwise the child must equal the parent or begin with parent + "/". A
    # missing child scope ("") under a scoped parent WIDENS authority and is NOT contained.
    def scope_contained(child, parent)
      return true if parent == ""           # unconstrained parent
      return false if child == ""           # missing child scope under a scoped parent widens authority
      return true if child == parent
      child.start_with?(parent + "/")
    end

    # The distinct verified grants named in `causes` whose subject equals `subject` (the parent/leaf
    # resolution predicate). Duplicate content ids are counted once.
    def matching_causes(causes, subject, grants)
      seen = {}
      out = []
      causes.each do |c|
        key = c.b
        next if seen[key]
        r = grants[key]
        if r && r.grant.subject == subject
          seen[key] = true
          out << r
        end
      end
      out
    end

    # ---- D3 chain verification (design §18.2) ----------------------------------------------------

    # The 12-step leaf->root delegation-chain walk, fail-closed with no partial credit. `grants` is a
    # Hash keyed by envelope content id bytes; `anchors` is the trust-anchor issuer-id set (responds to
    # #include?); `revoked` maps a revoked grant's content id bytes to its revoke position; `now` is the
    # action's authoritative ordering position. Returns nil iff the chain terminates at a trusted root
    # with every hop holding; otherwise raises the specific named error and authorizes nothing.
    def verify_chain(action, grants, anchors, revoked, now)
      # step 2 -- locate the unique leaf grant among the action's causes whose subject == the actor.
      leaves = matching_causes(action.causes, action.signer, grants)
      raise DelegationError.new("EffectNotAuthorized", "no delegation authorizes this action") if leaves.empty?
      raise DelegationError.new("ChainBroken", "more than one authorizing grant is ambiguous") if leaves.length > 1
      g = leaves[0]
      child_effect = action.effect
      child_scope = action.scope
      pos = 0 # realized delegation hops beneath the current grant
      visited = {}

      loop do
        key = g.content_id.b
        raise DelegationError.new("ChainBroken", "content-id cycle in the delegation chain") if visited[key]
        visited[key] = true

        # step 4 -- validity window at `now`.
        raise DelegationError.new("GrantNotYetValid", "grant is before its not_before at this position") if now < g.grant.not_before
        raise DelegationError.new("GrantExpired", "grant is past its not_after at this position") if now > g.grant.not_after
        # step 5 -- revocation at `now`.
        raise DelegationError.new("GrantRevoked", "grant is revoked at or before this position") if revoked_at?(revoked, g.content_id, now)
        # step 6 -- attenuation (CapExceedsParent): effect ceiling AND scope containment.
        unless Naalp::Policy.authorizes(g.grant.effect_cap, child_effect)
          raise DelegationError.new("CapExceedsParent", "child effect exceeds this grant's effect_cap")
        end
        unless scope_contained(child_scope, g.grant.scope)
          raise DelegationError.new("CapExceedsParent", "child scope is not contained in this grant's scope")
        end
        # step 9 -- realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
        raise DelegationError.new("DelegationDepthExceeded", "realized delegation depth exceeds max_depth") if pos > g.grant.max_depth
        # step 7 -- resolve g's delegation parent (the unique cause whose subject == g's issuer).
        parents = matching_causes(g.causes, g.issuer, grants)
        raise DelegationError.new("ChainBroken", "ambiguous delegation parent") if parents.length > 1
        if parents.empty?
          # steps 10 / 11 -- root test: g has no delegation parent.
          return nil if anchors.include?(g.issuer) # terminated at a trusted root: authorized
          raise DelegationError.new("UntrustedChainRoot", "the chain root's issuer is not a trust anchor")
        end
        p = parents[0]
        # step 8 -- declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned underflow;
        # a parent with max_depth 0 admits no child grant).
        if p.grant.max_depth == 0 || g.grant.max_depth >= p.grant.max_depth
          raise DelegationError.new("DelegationDepthExceeded", "declared delegation depth exceeds parent")
        end
        child_effect = g.grant.effect_cap
        child_scope = g.grant.scope
        g = p
        pos += 1
      end
    end

    # ---- D4 composition with per-action approval (design §18.3, R-DEL-8) ---------------------------

    # The D4 two-gate composition: a destructive-effect action requires BOTH a valid delegation chain
    # (D3) terminating at a trusted root AND a valid, unconsumed, exact-bytes §7 approval whose granted
    # effect covers the action, CONSUMED single-use by the acting agent (accountability binds to it).
    # Precedence: the chain is checked first, so a broken chain denies with its D3 error even when an
    # approval is present; a valid chain with no valid approval denies ApprovalRequired; a
    # valid-but-already-consumed approval denies AlreadyConsumed. The approval is CONSUMED (the single
    # state change) only when both gates hold; a rejected action makes no ledger append. Returns nil on
    # authorization.
    def authorize_destructive(action, grants, anchors, revoked, now,
                              appr, approver_alg, approver_pubkey, appr_sig, args_content_id, ledger)
      # Gate 1 -- the delegation chain (D3). A broken chain denies with its named D3 error.
      verify_chain(action, grants, anchors, revoked, now)
      # Gate 2 -- a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
      begin
        Naalp::Approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, args_content_id, now)
      rescue Naalp::Approval::ApprovalError
        raise DelegationError.new("ApprovalRequired", "no valid approval on a destructive action (held §7.3)")
      end
      unless Naalp::Policy.authorizes(appr.grant, action.effect)
        raise DelegationError.new("ApprovalRequired", "the approval's granted effect does not cover the action")
      end
      # Consume single-use. The ledger's named error (AlreadyConsumed) is surfaced uniformly as a
      # DelegationError so the composition's whole deny contract is one error type (as the Go/Python
      # reference). Fail-closed: a spent approval is not fresh authority.
      begin
        ledger.consume(appr.id, action.signer)
      rescue Naalp::Approval::ApprovalError => e
        raise DelegationError.new(e.kind, e.message)
      end
      nil
    end
  end
end
