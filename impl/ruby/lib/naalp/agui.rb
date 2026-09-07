# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C21 NAALP-AGUI UI-consent binding for the Ruby SDK (design.md §24; R-AGUI-1..6).
#
# NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
# tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
# RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
# envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary signed
# N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction (§8.1)
# unchanged -- head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head
# carried in `prev` so editing or omitting an event breaks the next event's linkage -- and the §7
# approval binding (module Naalp::Approval) UNCHANGED.
#
#   - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
#     `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id
#     of the action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.
#
# The load-bearing properties, graded across implementations:
#
#   - A UI approval verifies ONLY against the EXACT action shown. verify_consent walks the shown chain,
#     takes the action content id from the shown-and-approved event, and requires the action actually
#     being executed to hash to THAT content id (ActionSubstituted otherwise) AND the human approval to
#     bind it (the §7 approval, ApprovalMismatch otherwise). A substituted action has a different content
#     id and is rejected.
#   - A removed/omitted shown-event is detected with its POSITION. walk_shown enforces contiguity and
#     returns UIChainBroken on a gap; detect_hole reports the first-broken position.
#
# Every check is fail-closed (§15). Ported from impl/go/agui (cross-read against impl/python/naalp/agui.py);
# the byte surface (kind vocabulary, event bodies/heads/ids, action content ids, the shown-chain walk,
# hole position, rejections) is graded against vectors/agui/cases.json; the signed shown-chain and the
# consent binding use real deterministic ML-DSA-65 and are demonstrated in isolation (the corpus carries
# no signed vector).
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'approval'

module Naalp
  module AGUI
    U = Naalp::CBOR::U
    N = Naalp::CBOR::N
    B = Naalp::CBOR::B
    M = Naalp::CBOR::M

    # The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis
    # is zero.
    HEAD_SIZE = 48

    # UI event kinds -- the closed AG-UI tool-lifecycle set. A kind outside the set is rejected
    # (UnknownUIEventKind).
    KIND_SHOWN = 0        # the action / tool call was shown (rendered) to the user
    KIND_ARGS_SHOWN = 1   # the arguments were shown to the user
    KIND_APPROVED = 2     # the user approved the shown action
    KIND_REJECTED = 3     # the user rejected the shown action

    KIND_NAMES = {
      KIND_SHOWN => "shown", KIND_ARGS_SHOWN => "args-shown",
      KIND_APPROVED => "approved", KIND_REJECTED => "rejected",
    }.freeze

    # A named, fail-closed AGUI error; #kind is the stable error kind (mirroring the Go/Rust kinds
    # UIMalformed, UIChainBroken, UnknownUIEventKind, ActionSubstituted, UINoConsent, plus the reused §7
    # approval + cose kinds ApprovalMismatch / ApprovalExpired / BadSignature).
    class AguiError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    module_function

    # Whether code is one of the closed UI-event kinds.
    def is_known_kind(code)
      KIND_NAMES.key?(code)
    end

    # The kind name, or 'unknown'.
    def kind_name(code)
      KIND_NAMES.fetch(code, "unknown")
    end

    # A fresh 48-octet zero prev -- the empty-chain link (the C7 chain genesis).
    def genesis
      ("\x00" * HEAD_SIZE).b
    end

    def head_bytes(b)
      OpenSSL::Digest::SHA384.digest(b.dup.force_encoding(Encoding::BINARY))
    end

    # T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets). The content id
    # of an ACTION, which a UI event names in field 3 and a human approval binds. A relying party
    # computes it over the exact action bytes it is about to execute.
    def content_id(b)
      Naalp::CBOR.content_id(b.dup.force_encoding(Encoding::BINARY))
    end

    # ---- UIEvent: one receipt-chained shown tool-lifecycle event (design §24) ---------------------

    # One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event:
    # `prev` is the prior event's head (genesis for seq 0). `action` is the content id of the exact
    # action bytes shown to the user at this step.
    class UIEvent
      attr_reader :session, :kind, :action, :seq, :prev

      def initialize(session, kind, action, seq, prev)
        @session = session.dup.force_encoding(Encoding::BINARY)
        @kind = kind.to_i
        @action = action.dup.force_encoding(Encoding::BINARY)
        @seq = seq.to_i
        @prev = prev.dup.force_encoding(Encoding::BINARY)
      end

      # Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}.
      def bytes
        Naalp::CBOR.encode(M.new([
          [U.new(1), B.new(@session)],
          [U.new(2), U.new(@kind)],
          [U.new(3), B.new(@action)],
          [U.new(4), U.new(@seq)],
          [U.new(5), B.new(@prev)],
        ]))
      end

      # The chain head after this event: SHA-384 of the event body (48 octets). Because the body carries
      # prev, editing any event breaks the next event's linkage.
      def head
        Naalp::AGUI.head_bytes(bytes)
      end

      # The event's T1 content id (50 octets).
      def id
        Naalp::AGUI.content_id(bytes)
      end
    end

    # Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint key,
    # a mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed.
    def parse_ui_event(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise AguiError.new("UIMalformed", "ui-event body is not well-formed deterministic CBOR")
      end
      raise AguiError.new("UIMalformed", "ui-event body is not a map") unless v.is_a?(M)
      sess = kind = action = seq = prev = nil
      v.pairs.each do |k, val|
        raise AguiError.new("UIMalformed", "non-uint ui-event key") unless k.is_a?(U)
        if k.v == 1 && val.is_a?(B)
          sess = val.v
        elsif k.v == 2 && val.is_a?(U)
          kind = val.v
        elsif k.v == 3 && val.is_a?(B)
          action = val.v
        elsif k.v == 4 && val.is_a?(U)
          seq = val.v
        elsif k.v == 5 && val.is_a?(B)
          prev = val.v
        else
          raise AguiError.new("UIMalformed", "unknown or mistyped ui-event field")
        end
      end
      if sess.nil? || kind.nil? || action.nil? || seq.nil? || prev.nil?
        raise AguiError.new("UIMalformed", "ui-event body missing a mandatory field")
      end
      UIEvent.new(sess, kind, action, seq, prev)
    end

    # Produce the tagged COSE_Sign1 object over the event body (real deterministic ML-DSA).
    def sign_ui_event(e, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), e.bytes)
    end

    # Verify the event's full signature under the profile, reconstruct it from the signed body bytes,
    # and validate the kind against the closed set (UnknownUIEventKind). A bad signature propagates
    # BadSignature. Fail-closed.
    def verify_ui_event(obj, profile, alg, pubkey)
      payload = verify_sign1(obj, profile, alg, pubkey)
      e = parse_ui_event(payload)
      raise AguiError.new("UnknownUIEventKind", "ui-event kind is outside the closed set") unless is_known_kind(e.kind)
      e
    end

    # ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) -----------------

    # One step of a walked shown chain: the chain position, the event kind, the action content id shown,
    # and the chain head after it.
    ShownEvent = Struct.new(:seq, :kind, :action, :head)

    # Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered
    # shown events. It requires every event to name the SAME session, seq i to equal its index, each
    # kind to be in the closed set, and prev to link to the previous event's head (genesis for seq 0). A
    # gap, reorder, omitted event, or a session change is UIChainBroken (fail-closed); an unknown kind is
    # UnknownUIEventKind.
    def walk_shown(events)
      out = []
      h = genesis
      session = nil
      events.each_with_index do |e, i|
        if i == 0
          session = e.session
        elsif e.session.b != session.b
          raise AguiError.new("UIChainBroken", "a chain is for exactly one session")
        end
        raise AguiError.new("UnknownUIEventKind", "ui-event kind is outside the closed set") unless is_known_kind(e.kind)
        if e.seq != i || e.prev.b != h.b
          raise AguiError.new("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
        end
        h = e.head
        out << ShownEvent.new(e.seq, e.kind, e.action.dup, h.dup)
      end
      out
    end

    # Check a UI event chain offline against the UI authority's key. Each element is the tagged
    # COSE_Sign1 object for one event; verify every signature under the profile (verify_ui_event), then
    # enforce the same structural continuity as walk_shown. A bad signature propagates BadSignature; a
    # broken link, seq gap, or session change is UIChainBroken. Detects any reorder, omission, or
    # substitution of a shown event (§8.1). Fail-closed.
    def verify_shown_chain(objs, profile, alg, pubkey)
      h = genesis
      session = nil
      out = []
      objs.each_with_index do |obj, i|
        e = verify_ui_event(obj, profile, alg, pubkey)
        if i == 0
          session = e.session
        elsif e.session.b != session.b
          raise AguiError.new("UIChainBroken", "a chain is for exactly one session")
        end
        if e.seq != i || e.prev.b != h.b
          raise AguiError.new("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
        end
        h = e.head
        out << e
      end
      out
    end

    # Report whether a presented (possibly gappy) event list breaks contiguity -- a deleted/omitted
    # shown-event -- and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's
    # seq is not i or its prev does not link to the previous event's head. A contiguous list returns
    # [0, false].
    def detect_hole(events)
      h = genesis
      events.each_with_index do |e, i|
        return [i, true] if e.seq != i || e.prev.b != h.b
        h = e.head
      end
      [0, false]
    end

    # ---- the UI consent binding (reuses the §7 approval) ------------------------------------------

    # The content id of the action shown-and-approved in a walked chain, and whether an approved event
    # is present. It is the content id a valid consent binds; a chain with no approved event has no
    # consent to bind.
    def approved_action_cid(shown)
      shown.each { |ev| return [ev.action.dup, true] if ev.kind == KIND_APPROVED }
      [nil, false]
    end

    # Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks the
    # shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content id
    # from the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7
    # approval binds THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired /
    # BadSignature, from Naalp::Approval and Naalp::COSE); and (4) requires the action actually being
    # executed (`action_bytes`) to hash to the shown-and-approved content id -- a SUBSTITUTED action has
    # a different content id and is rejected (ActionSubstituted). Every failure returns its named error
    # and authorizes nothing (fail-closed). On success the caller may execute exactly `action_bytes`.
    def verify_consent(chain, action_bytes, appr, approver_alg, approver_pubkey, appr_sig, now)
      shown = walk_shown(chain) # UIChainBroken / UnknownUIEventKind on a hole
      shown_cid, ok = approved_action_cid(shown)
      raise AguiError.new("UINoConsent", "the shown chain carries no approved event") unless ok
      # The human approval must be a valid signature binding the shown-and-approved action content id.
      Naalp::Approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, shown_cid, now)
      # The action actually being executed MUST be the exact one shown and approved: a substitution has a
      # different content id and is rejected. This is the seam a lax UI profile would drop.
      unless content_id(action_bytes).b == shown_cid.b
        raise AguiError.new("ActionSubstituted", "the executed action is not the exact action shown+approved")
      end
      nil
    end

    # ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

    # The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits.
    def protected_header(alg)
      Naalp::CBOR.encode(M.new([[U.new(1), N.new(alg)]]))
    end

    # Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
    # Mirrors the shared verify: alg registry, profile floor, key-alg match, signature. Fail-closed with
    # a named AguiError.
    def verify_sign1(obj, profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise AguiError.new("UnknownAlg", "unregistered alg #{halg}") unless known
      if level < Naalp::COSE.profile_min_level(profile)
        raise AguiError.new("ProfileDowngrade", "signature level below the profile minimum")
      end
      raise AguiError.new("KeyAlgMismatch", "alg #{halg} does not match the verifier key alg #{alg}") if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
        raise AguiError.new("BadSignature", "signature does not verify")
      end
      payload
    end

    def alg_from_protected(prot)
      v = Naalp::CBOR.decode(prot)
      if v.is_a?(M)
        v.pairs.each do |k, val|
          return val.v if k.is_a?(U) && k.v == 1 && (val.is_a?(N) || val.is_a?(U))
        end
      end
      raise AguiError.new("UIMalformed", "protected header has no alg")
    end
  end
end
