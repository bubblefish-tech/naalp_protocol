# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C17 N-AALP-CONT flow continuation for the Ruby SDK (design.md §20; R-CONT-1..7).
#
# N-AALP-CONT generalizes native streaming (one signed StreamOpen, cheap per-chunk data, one signed
# StreamCommit over a rolling digest) into a domain-agnostic flow:
#
#   - FlowOpen is the ONE full ML-DSA signature that fixes the flow's authority: its flow_id, its
#     effect ceiling, and the content-ids of the approvals that authorize it up to that ceiling. The
#     authority is reconstructable from the FlowOpen bytes ALONE (parse_flow_open) -- no session or
#     server state is needed to know what a continuation is allowed to do.
#   - Continuation is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link. Each
#     link's head is SHA-384(link body); its `prev` is the previous link's head; the genesis prev is
#     the FlowOpen's head, which anchors every link to THIS FlowOpen. A link carries its own effect,
#     which MUST stay at or below the ceiling (AboveCeiling otherwise -- the cheap path can never
#     escalate past the one full signature + approval).
#   - Checkpoint lets a verifier confirm a contiguous prefix and DETECT A GAP (GapDetected).
#   - FlowCommit is a second full ML-DSA signature binding the whole ordered sequence with ONE
#     signature regardless of the number of continuations.
#
# A continuation replayed under a different FlowOpen fails: it carries the originating flow_open_id
# (WrongFlow) and its prev no longer chains to the other FlowOpen's head (ChainBroken). Domain
# separation is structural: FlowOpen (3 fields), Continuation (5 fields), Checkpoint (3 fields, a
# bstr head at 3), and FlowCommit (2 fields) are each a distinct deterministic-CBOR shape. Every
# check is fail-closed (§15). Ported from impl/go/continuation (cross-read against
# impl/python/naalp/continuation.py); graded against vectors/continuation/cases.json. The FlowOpen /
# FlowCommit signatures are real deterministic ML-DSA-65 (COSE_Sign1) but not corpus-graded.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'policy'

module Naalp
  module Continuation
    # The width of a chain head / prev link (SHA-384 = 48 bytes). A FlowOpen head anchors a flow's
    # continuation chain (matching the C7 audit chain width).
    HEAD_SIZE = 48

    MAX_U64 = (2**64) - 1

    # A named, fail-closed N-AALP-CONT error; #kind is the stable error kind mirroring Go/Rust/Python
    # (§15).
    class ContError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    module_function

    # Whether v is a value of the closed C5 effect lattice (0..3). An out-of-lattice value is rejected
    # RangeError, NEVER normalized to destructive -- normalizing a CEILING to destructive would
    # silently make an out-of-range ceiling the MOST-permissive one (a fail-open).
    def in_lattice?(v)
      v >= 0 && v <= Naalp::Policy::DESTRUCTIVE
    end

    # SHA-384 over a body -- a 48-octet chain head.
    def head_of(b)
      OpenSSL::Digest::SHA384.digest(b)
    end

    # The T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
    def content_id_of(b)
      Naalp::CBOR.content_id(b)
    end

    # ---- FlowOpen: the one full signature fixing the flow's authority (design.md §20.2) ---------

    # FlowOpen fixes a flow's identity, effect ceiling, and approval bindings. It is signed with a
    # full ML-DSA signature (sign_flow_open); its authority is reconstructable from its bytes alone.
    FlowOpen = Struct.new(:flow_id, :effect_ceiling, :approvals) do
      # Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(flow_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(effect_ceiling)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::A.new(approvals.map { |a| Naalp::CBOR::B.new(a) })],
        ]))
      end

      # The FlowOpen's SHA-384 head -- the genesis prev that anchors the continuation chain.
      def head
        Naalp::Continuation.head_of(bytes)
      end

      # The FlowOpen's content-id -- carried by every child object.
      def id
        Naalp::Continuation.content_id_of(bytes)
      end
    end

    # Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An
    # out-of-lattice effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed
    # (ContMalformed) on any malformed shape.
    def parse_flow_open(b)
      m = decode_map(b)
      fid = bstr_field(m, 1)
      ceil = uint_field(m, 2)
      apps_v = field(m, 3)
      if fid.nil? || ceil.nil? || apps_v.nil? || !apps_v.is_a?(Naalp::CBOR::A)
        raise ContError.new("ContMalformed", "object is not a well-formed FlowOpen body")
      end
      raise ContError.new("RangeError", "effect_ceiling is outside the closed 0..3 lattice") unless in_lattice?(ceil)
      apps = apps_v.items.map do |e|
        raise ContError.new("ContMalformed", "approval is not a bstr") unless e.is_a?(Naalp::CBOR::B)
        e.v
      end
      FlowOpen.new(fid, ceil, apps)
    end

    # ---- Continuation: the cheap hash-chain link (design.md §20.3) ------------------------------

    # One cheap link in a flow's chain. NOT individually signed; its authenticity derives from the
    # FlowOpen signature plus the hash chain plus the FlowCommit signature.
    Continuation = Struct.new(:flow_open_id, :seq, :effect, :payload_id, :prev) do
      # Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(flow_open_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(seq)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(effect)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(payload_id)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::B.new(prev)],
        ]))
      end

      # This link's SHA-384 head -- the prev of the next link.
      def head
        Naalp::Continuation.head_of(bytes)
      end
    end

    # The single audited decode path for untrusted Continuation wire bytes. Reconstructs the 5-field
    # body and range-checks the effect against the closed lattice (0..3): an out-of-lattice effect is
    # rejected RangeError, never carried as an unknown value. Fail-closed (ContMalformed).
    def parse_continuation(b)
      m = decode_map(b)
      fid = bstr_field(m, 1)
      seq = uint_field(m, 2)
      effect = uint_field(m, 3)
      pid = bstr_field(m, 4)
      prev = bstr_field(m, 5)
      if fid.nil? || seq.nil? || effect.nil? || pid.nil? || prev.nil?
        raise ContError.new("ContMalformed", "object is not a well-formed Continuation body")
      end
      raise ContError.new("RangeError", "effect is outside the closed 0..3 lattice") unless in_lattice?(effect)
      Continuation.new(fid, seq, effect, pid, prev)
    end

    # The CHEAP-path check of a single link against the flow's fixed authority: same flow (WrongFlow),
    # next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to the previous
    # head (ChainBroken). Performs no signature verification -- that is what makes it cheap. Both the
    # ceiling and the link effect are closed effects; an out-of-lattice value is RangeError, never
    # normalized (fail-closed). Returns nil on success.
    def verify_continuation(c, flow_open_id, prev_head, expected_seq, ceiling)
      raise ContError.new("RangeError", "ceiling is outside the closed 0..3 lattice") unless in_lattice?(ceiling)
      raise ContError.new("RangeError", "effect is outside the closed 0..3 lattice") unless in_lattice?(c.effect)
      raise ContError.new("WrongFlow", "object's flow_open_id does not match the FlowOpen") unless c.flow_open_id.b == flow_open_id.b
      raise ContError.new("SeqGap", "continuation seq is not the next expected value") if c.seq != expected_seq
      raise ContError.new("AboveCeiling", "continuation effect exceeds the FlowOpen effect ceiling") unless Naalp::Policy.authorizes(ceiling, c.effect)
      raise ContError.new("ChainBroken", "continuation prev does not chain to the previous head") unless c.prev.b == prev_head.b
      nil
    end

    # Verify a whole ordered continuation sequence starting from the FlowOpen and return the final
    # chain head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the one
    # full signature authorized.
    def verify_chain(open_, conts)
      raise ContError.new("RangeError", "effect_ceiling is outside the closed 0..3 lattice") unless in_lattice?(open_.effect_ceiling)
      fid = open_.id
      prev = open_.head
      ceiling = open_.effect_ceiling
      conts.each_with_index do |c, i|
        verify_continuation(c, fid, prev, i, ceiling)
        prev = c.head
      end
      prev
    end

    # ---- Checkpoint: confirm a prefix, detect a gap (design.md §20.4) ---------------------------

    # Asserts the chain head after a contiguous prefix of continuations (seq 0..through_seq).
    Checkpoint = Struct.new(:flow_open_id, :through_seq, :head) do
      # Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(flow_open_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(through_seq)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(head)],
        ]))
      end
    end

    # The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body (field 3 a
    # bstr head). A 2-field FlowCommit look-alike is rejected here (missing field 3). Fail-closed
    # (ContMalformed).
    def parse_checkpoint(b)
      m = decode_map(b)
      fid = bstr_field(m, 1)
      through = uint_field(m, 2)
      h = bstr_field(m, 3)
      if fid.nil? || through.nil? || h.nil?
        raise ContError.new("ContMalformed", "object is not a well-formed Checkpoint body")
      end
      Checkpoint.new(fid, through, h)
    end

    # Confirm the prefix is exactly the contiguous sequence seq 0..through_seq and that its recomputed
    # head matches the checkpoint. A dropped or reordered link -- a missing seq, a broken prev, or the
    # wrong count -- is reported GapDetected. Returns nil on a clean confirmation.
    def verify_checkpoint(cp, open_, prefix)
      raise ContError.new("WrongFlow", "checkpoint flow_open_id does not match the FlowOpen") unless cp.flow_open_id.b == open_.id.b
      # through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq ==
      # u64::MAX that addition would wrap and false-accept an EMPTY prefix as covering the whole
      # counter space -- reject it as a gap instead (there can be no MAX+1 contiguous links).
      raise ContError.new("GapDetected", "through_seq at u64::MAX admits no contiguous prefix") if cp.through_seq == MAX_U64
      raise ContError.new("GapDetected", "wrong count: a link is missing or extra") if prefix.length != cp.through_seq + 1
      begin
        h = verify_chain(open_, prefix)
      rescue ContError
        raise ContError.new("GapDetected", "a seq/prev break inside the prefix is a gap")
      end
      raise ContError.new("GapDetected", "recomputed prefix head does not match the checkpoint") unless cp.head.b == h.b
      nil
    end

    # ---- FlowCommit: the second full signature binding the whole sequence (design.md §20.5) ------

    # Binds a completed flow's final chain head under one full ML-DSA signature.
    FlowCommit = Struct.new(:flow_open_id, :final_head) do
      # Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} -- the 2-field shape that
      # distinguishes it from the 3-field Checkpoint.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(flow_open_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(final_head)],
        ]))
      end
    end

    # ---- full-signature helpers (FlowOpen / FlowCommit) -- real ML-DSA, isolation --------------

    # The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).
    def protected_header(alg)
      Naalp::CBOR.encode(Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::N.new(alg)]]))
    end

    # The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow).
    def sign_flow_open(o, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), o.bytes)
    end

    # The tagged COSE_Sign1 over the FlowCommit body.
    def sign_flow_commit(c, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), c.bytes)
    end

    # Verify the FlowOpen's full signature, then reconstruct the authority from the signed body bytes
    # (fail-closed BadSignature).
    def verify_flow_open(obj, _profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      unless Naalp::COSE.cose_verify1_raw(alg, pubkey, tbs, sig)
        raise ContError.new("BadSignature", "flow-open signature does not verify")
      end
      parse_flow_open(payload)
    end

    # Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head
    # equals the chain recomputed over the delivered continuations (CommitMismatch otherwise).
    def verify_flow_commit(obj, _profile, alg, pubkey, open_, conts)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      unless Naalp::COSE.cose_verify1_raw(alg, pubkey, tbs, sig)
        raise ContError.new("BadSignature", "flow-commit signature does not verify")
      end
      m = decode_map(payload)
      fid = bstr_field(m, 1)
      fh = bstr_field(m, 2)
      raise ContError.new("ContMalformed", "object is not a well-formed FlowCommit body") if fid.nil? || fh.nil?
      fc = FlowCommit.new(fid, fh)
      raise ContError.new("WrongFlow", "flow-commit does not bind this FlowOpen") unless fc.flow_open_id.b == open_.id.b
      final = verify_chain(open_, conts)
      raise ContError.new("CommitMismatch", "flow commit final_head does not match the recomputed chain") unless fc.final_head.b == final.b
      fc
    end

    # ---- small deterministic-CBOR field accessors ----------------------------------------------

    def decode_map(b)
      v = Naalp::CBOR.decode(b) # strict decoder: raises NonCanonical on a non-canonical body
      raise ContError.new("ContMalformed", "object is not a map") unless v.is_a?(Naalp::CBOR::M)
      v
    end

    def field(m, k)
      m.pairs.each do |key, val|
        return val if key.is_a?(Naalp::CBOR::U) && key.v == k
      end
      nil
    end

    def bstr_field(m, k)
      v = field(m, k)
      v.is_a?(Naalp::CBOR::B) ? v.v : nil
    end

    def uint_field(m, k)
      v = field(m, k)
      v.is_a?(Naalp::CBOR::U) ? v.v : nil
    end
  end
end
