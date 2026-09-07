# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C19 name-bindings + the signed A2A task-state profile for the Ruby SDK (design.md §22;
# R-NAME-1..6, R-A2A-1..7).
#
# C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
# object. Both reuse the C7 audit receipt-chain construction (§8.1) unchanged -- head = SHA-384(body),
# genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or
# omitting a record breaks the next record's linkage -- and they add NO new envelope, encoding,
# signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body
# (COSE_Sign1, §4), reusing the T1 content-id framing (§2.3) and the C7 chain.
#
# Task 4.1 -- name bindings: NameBinding {1:name,2:signer,3:seq,4:prev} maps a name to a signer id and
# CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis prev is zero). A
# key rotation is a NEW binding at the next seq naming the new signer. A binding is DATED BY its chain
# position (seq); the envelope's `created` field is advisory only. A name's history is WALKABLE offline
# (walk_history), a deleted/omitted binding leaves a detectable HOLE at the first-broken position
# (detect_hole), and two bindings by ONE authority at the SAME (name, seq) naming DIFFERENT signers are
# a FORK reported at that seq (detect_fork / NameForkProof).
#
# Task 4.2 -- the signed A2A task-state profile: the imported A2A (Agent2Agent) TaskState vocabulary
# (carriage, not adoption): the eight states submitted, working, input-required, auth-required,
# completed, canceled, failed, rejected (A2A §4.1.3: start = submitted; terminal =
# completed/canceled/failed/rejected; interrupted = input-required/auth-required). A Transition
# {1:task,2:card,3:from,4:to,5:seq,6:prev} is one receipt-CHAINED signed state transition. The
# legal-edge table is DERIVED from those documented A2A category rules; verify_transition rejects an
# illegal edge, and verify_task_chain walks a task's transition chain enforcing the start state,
# contiguity, the legal-edge table, prev/seq linkage, the card binding, and the signatures. `card` is
# the content-id of the A2A Agent Card attestation (a C18 naalp-description-import) that binds the
# profile to an agent/operation; a transition carrying a foreign card is rejected.
#
# Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
# causes no state change. Ported from impl/go/naming (cross-read against impl/python/naalp/naming.py);
# graded against the shared vectors/naming/cases.json. The signed chain verifiers run over REAL
# deterministic ML-DSA-65 COSE_Sign1 objects (Naalp::COSE.cose_sign1, protected header {1: alg}
# directly -- NOT the full envelope), so Ruby signed bytes are byte-identical to Go/Rust/Python.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'

module Naalp
  module Naming
    U = Naalp::CBOR::U
    N = Naalp::CBOR::N
    B = Naalp::CBOR::B
    T = Naalp::CBOR::T
    M = Naalp::CBOR::M

    # The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis
    # is zero.
    HEAD_SIZE = 48

    # A named, fail-closed C19 error; #kind is the stable error kind (§15). The signature kinds
    # (BadSignature, UnknownAlg, ProfileDowngrade, KeyAlgMismatch) are reused from the C2 cose layer so
    # a verifier's verdict is identical to the Go/Python reference.
    class NamingError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # ==== Task 4.1 -- name bindings ==============================================================

    # NameBinding maps a name to a signer id at a chain position. It chains onto the prior binding for
    # the same name: prev is the prior binding's head (genesis for seq 0). A key rotation is a new
    # binding at the next seq naming the new signer. The binding is DATED BY seq; the envelope's
    # `created` field is advisory only.
    class NameBinding
      attr_reader :name, :signer, :seq, :prev

      def initialize(name, signer, seq, prev)
        @name = name.to_s                                        # the name being bound (durable, human-readable)
        @signer = signer.dup.force_encoding(Encoding::BINARY)    # the signer id this binding maps the name to (opaque bytes)
        @seq = seq.to_i                                          # monotonic per-name chain position; seq 0 is genesis
        @prev = prev.dup.force_encoding(Encoding::BINARY)        # the prior binding's head (HEAD_SIZE bytes; genesis is zero)
      end

      # Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}.
      def bytes
        Naalp::CBOR.encode(M.new([
          [U.new(1), T.new(@name)],
          [U.new(2), B.new(@signer)],
          [U.new(3), U.new(@seq)],
          [U.new(4), B.new(@prev)],
        ]))
      end

      # The chain head after this binding: SHA-384 of the binding body (48 octets). Because the body
      # carries prev, editing any binding breaks the next binding's linkage.
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The binding's T1 content-id (50 octets): multihash(0x20, SHA-384(body)).
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # One step of a walked name history: the chain position and the signer the name mapped to at that
    # position, with the chain head after it.
    NameEvent = Struct.new(:seq, :signer, :head)

    # Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority at
    # the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
    # objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the
    # proof is self-contained -- any third party confirms both signatures against the accused key.
    NameForkProof = Struct.new(:signer, :signed_a, :signed_b) do
      # Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the key
      # (which, because a single verifier checks both, proves one authority); (3) the two bindings share
      # one name and seq; and (4) their bodies differ. Returns the seq position at which it forks. An
      # unnamed signer, a different name/seq, or identical bodies is NameForkProofInvalid; a signature
      # that does not verify is BadSignature. Fail-closed.
      def verify(profile, alg, pubkey)
        raise NamingError.new("NameForkProofInvalid", "an unnamed accused is not evidence") if signer.to_s.b.bytesize.zero?
        a = Naalp::Naming.verify_binding(signed_a, profile, alg, pubkey)
        b = Naalp::Naming.verify_binding(signed_b, profile, alg, pubkey)
        pos, fork = Naalp::Naming.detect_fork(a, b)
        raise NamingError.new("NameForkProofInvalid", "not the same (name, seq) or identical bodies") unless fork
        pos
      end
    end

    # A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
    # authority). Each append records a name -> signer mapping at the next chain position; a rotation is
    # simply an append naming the new signer. Signs with a real deterministic ML-DSA key from `seed`.
    class Registrar
      def initialize(name, alg, seed)
        @name = name.to_s
        @alg = alg
        @seed = seed.dup.force_encoding(Encoding::BINARY)
        @head = ("\x00" * HEAD_SIZE).b
        @seq = 0
      end

      # Record a binding of the registrar's name to `subject` at the next chain position, returning
      # [binding, tagged COSE_Sign1 object]. Seq increases by one per append; the head advances.
      def append(subject)
        nb = NameBinding.new(@name, subject, @seq, @head)
        obj = Naalp::Naming.sign_binding(nb, @alg, @seed)
        @head = nb.head
        @seq += 1
        [nb, obj]
      end
    end

    # ==== Task 4.2 -- the signed A2A task-state profile ==========================================

    # TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A §4.1.3).
    STATE_SUBMITTED = 0       # acknowledged, not yet started (the start state)
    STATE_WORKING = 1         # actively processed
    STATE_INPUT_REQUIRED = 2  # interrupted, awaiting client input
    STATE_AUTH_REQUIRED = 3   # interrupted, awaiting authentication
    STATE_COMPLETED = 4       # terminal success
    STATE_CANCELED = 5        # terminal, canceled before completion
    STATE_FAILED = 6          # terminal, finished with an error
    STATE_REJECTED = 7        # terminal, the agent declined the task

    START_STATE = STATE_SUBMITTED

    STATE_NAMES = {
      STATE_SUBMITTED => "submitted", STATE_WORKING => "working", STATE_INPUT_REQUIRED => "input-required",
      STATE_AUTH_REQUIRED => "auth-required", STATE_COMPLETED => "completed", STATE_CANCELED => "canceled",
      STATE_FAILED => "failed", STATE_REJECTED => "rejected",
    }.freeze
    TERMINAL = [STATE_COMPLETED, STATE_CANCELED, STATE_FAILED, STATE_REJECTED].freeze
    INTERRUPTED = [STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED].freeze

    # The explicit A2A transition table: the legal (from, to) edges DERIVED from the A2A category rules
    # (design §22.3). It is the authoritative source both legal_edge and verify_task_chain consult; the
    # two-implementation parity grades it against the independently-listed edge set in the corpus.
    LEGAL_EDGES = begin
      active = [STATE_SUBMITTED, STATE_WORKING]
      edges = {}
      add = ->(f, t) { edges[[f, t]] = true }
      add.call(STATE_SUBMITTED, STATE_WORKING)          # begin processing (the only active->active edge)
      active.each { |s| INTERRUPTED.each { |t| add.call(s, t) } }  # active -> interrupted
      active.each { |s| TERMINAL.each { |t| add.call(s, t) } }     # active -> terminal
      INTERRUPTED.each { |s| add.call(s, STATE_WORKING) }          # interrupted -> working (client acted)
      INTERRUPTED.each { |s| TERMINAL.each { |t| add.call(s, t) } } # interrupted -> terminal
      edges.freeze
    end

    # One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto the prior
    # transition of the same task: prev is the prior transition's head (genesis for seq 0). Dated by
    # seq. card is the content-id of the A2A Agent Card attestation (a C18 import) that binds this
    # profile to an agent/operation.
    class Transition
      attr_reader :task, :card, :from, :to, :seq, :prev

      def initialize(task, card, from, to, seq, prev)
        @task = task.dup.force_encoding(Encoding::BINARY)  # the task id (opaque bytes)
        @card = card.dup.force_encoding(Encoding::BINARY)  # content-id of the bound A2A Agent Card attestation (C18 import)
        @from = from.to_i                                  # the source state
        @to = to.to_i                                      # the target state
        @seq = seq.to_i                                    # monotonic per-task chain position; seq 0's from MUST be the start state
        @prev = prev.dup.force_encoding(Encoding::BINARY)  # the prior transition's head (HEAD_SIZE bytes; genesis is zero)
      end

      # Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}.
      def bytes
        Naalp::CBOR.encode(M.new([
          [U.new(1), B.new(@task)],
          [U.new(2), B.new(@card)],
          [U.new(3), U.new(@from)],
          [U.new(4), U.new(@to)],
          [U.new(5), U.new(@seq)],
          [U.new(6), B.new(@prev)],
        ]))
      end

      # The chain head after this transition: SHA-384 of the transition body (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The transition's T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    module_function

    # A fresh 48-octet zero prev -- the empty-chain link (the C7 chain genesis).
    def genesis
      ("\x00" * HEAD_SIZE).b
    end

    # The A2A state name, or "unknown" for an out-of-range code.
    def state_name(s)
      STATE_NAMES.fetch(s, "unknown")
    end

    # Whether s is one of the eight defined A2A states.
    def state?(s)
      STATE_NAMES.key?(s)
    end

    # Whether s is a terminal state (completed/canceled/failed/rejected).
    def terminal?(s)
      TERMINAL.include?(s)
    end

    # Whether s is an interrupted state (input-required/auth-required).
    def interrupted?(s)
      INTERRUPTED.include?(s)
    end

    # Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
    # terminal state, an edge touching an undefined state, and any edge not in the table are all false.
    def legal_edge(from, to)
      return false unless state?(from) && state?(to)
      LEGAL_EDGES.key?([from, to])
    end

    # A copy of the legal transition table as a sorted list of [from, to] pairs.
    def legal_edges
      LEGAL_EDGES.keys.sort
    end

    # The edge-legality gate: returns nil iff (from -> to) is a legal A2A edge, else raises
    # NamingError(IllegalTransition). Fail-closed.
    def verify_transition(from, to)
      raise NamingError.new("IllegalTransition", "not a legal A2A transition edge") unless legal_edge(from, to)
      nil
    end

    # ---- the COSE_Sign1 signing/verification helpers (reuse the C2 layer, R-11.3) ----------------

    # The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits (NOT the
    # full N-AALP envelope header). alg is a negative COSE alg id, so it encodes as a CBOR nint.
    def protected_header(alg)
      Naalp::CBOR.encode(M.new([[U.new(1), N.new(alg)]]))
    end

    def alg_from_protected(prot)
      v = Naalp::CBOR.decode(prot)
      if v.is_a?(M)
        v.pairs.each do |k, val|
          return val.v if k.is_a?(U) && k.v == 1 && (val.is_a?(N) || val.is_a?(U))
        end
      end
      raise NamingError.new("NameMalformed", "protected header has no alg")
    end

    # Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
    # Check order (mirroring cose.Verify1): alg registry -> profile floor -> key-alg match -> signature.
    # Fail-closed with a named error.
    def verify_sign1(obj, profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise NamingError.new("UnknownAlg", "unregistered alg #{halg}") unless known
      if level < Naalp::COSE.profile_min_level(profile)
        raise NamingError.new("ProfileDowngrade", "signature level below the profile minimum")
      end
      raise NamingError.new("KeyAlgMismatch", "alg #{halg} does not match the verifier key alg #{alg}") if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
        raise NamingError.new("BadSignature", "signature does not verify")
      end
      payload
    rescue OpenSSL::PKey::PKeyError
      raise NamingError.new("BadSignature", "signature does not verify")
    end

    # Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4} map
    # with the right value types is NameMalformed (fail-closed).
    def parse_name_binding(b)
      m = decode_map(b)
      raise NamingError.new("NameMalformed", "body is not a well-formed name binding") if m.nil?
      name = tstr_field(m, 1)
      signer = bstr_field(m, 2)
      seq = uint_field(m, 3)
      prev = bstr_field(m, 4)
      if name.nil? || signer.nil? || seq.nil? || prev.nil?
        raise NamingError.new("NameMalformed", "body is not a well-formed name binding")
      end
      NameBinding.new(name, signer, seq, prev)
    end

    # Produce the tagged COSE_Sign1 object over the binding body (real deterministic ML-DSA).
    def sign_binding(nb, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), nb.bytes)
    end

    # Verify the binding's full signature under the profile, then reconstruct it from the signed body
    # bytes. A bad signature is BadSignature; a malformed body is NameMalformed. Fail-closed.
    def verify_binding(obj, profile, alg, pubkey)
      payload = verify_sign1(obj, profile, alg, pubkey)
      parse_name_binding(payload)
    end

    # Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the ordered
    # signer succession. Requires every binding to name the SAME name, seq i to equal its index, and
    # prev to link to the previous binding's head (genesis zero for seq 0). A gap, reorder, omitted
    # binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer is the last event's
    # signer.
    def walk_history(bindings)
      events = []
      h = genesis
      name = nil
      bindings.each_with_index do |nb, i|
        if i.zero?
          name = nb.name
        elsif nb.name != name
          raise NamingError.new("NameChainBroken", "a chain is for exactly one name")
        end
        if nb.seq != i || nb.prev.b != h
          raise NamingError.new("NameChainBroken", "prev/seq does not chain to the previous binding")
        end
        h = nb.head
        events << NameEvent.new(nb.seq, nb.signer, h)
      end
      events
    end

    # Check a name-binding chain offline against the authority's key. Each element is the tagged
    # COSE_Sign1 object for one binding. Verifies every signature under the profile (verify_binding),
    # then enforces structural continuity -- every binding names the SAME name, seq i equals its index,
    # prev links to the previous head -- returning the verified, ordered bindings. A bad signature is
    # BadSignature; a broken link, a seq gap, or a name change is NameChainBroken. Fail-closed.
    def verify_chain(objs, profile, alg, pubkey)
      h = genesis
      name = nil
      out = []
      objs.each_with_index do |obj, i|
        nb = verify_binding(obj, profile, alg, pubkey)
        if i.zero?
          name = nb.name
        elsif nb.name != name
          raise NamingError.new("NameChainBroken", "a chain is for exactly one name")
        end
        if nb.seq != i || nb.prev.b != h
          raise NamingError.new("NameChainBroken", "prev/seq does not chain to the previous binding")
        end
        h = nb.head
        out << nb
      end
      out
    end

    # Report whether a presented (possibly gappy) binding list breaks contiguity -- a deleted/omitted
    # binding -- and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's
    # seq is not i or its prev does not link to the previous binding's head. A contiguous list returns
    # [0, false].
    def detect_hole(bindings)
      h = genesis
      bindings.each_with_index do |nb, i|
        return [i, true] if nb.seq != i || nb.prev.b != h
        h = nb.head
      end
      [0, false]
    end

    # Compare two bindings for the SAME name and report whether they equivocate -- the SAME name and seq
    # but DIFFERENT bodies (a different signer or prev) -- and, if so, the seq position at which they
    # conflict. A different name or seq is a legitimate distinct binding; byte-identical bindings are a
    # benign duplicate. Both non-fork cases return [0, false].
    def detect_fork(a, b)
      return [0, false] if a.name != b.name || a.seq != b.seq
      return [0, false] if a.bytes == b.bytes
      [a.seq, true]
    end

    # Produce the tagged COSE_Sign1 object over the transition body (real deterministic ML-DSA).
    def sign_transition(t, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), t.bytes)
    end

    # Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6}
    # map with the right value types is NameMalformed (fail-closed).
    def parse_transition(b)
      m = decode_map(b)
      raise NamingError.new("NameMalformed", "body is not a well-formed task transition") if m.nil?
      task = bstr_field(m, 1)
      card = bstr_field(m, 2)
      from = uint_field(m, 3)
      to = uint_field(m, 4)
      seq = uint_field(m, 5)
      prev = bstr_field(m, 6)
      if task.nil? || card.nil? || from.nil? || to.nil? || seq.nil? || prev.nil?
        raise NamingError.new("NameMalformed", "body is not a well-formed task transition")
      end
      Transition.new(task, card, from, to, seq, prev)
    end

    # Verify a transition's full signature under the profile, reconstruct it from the signed body bytes,
    # AND check that its edge is legal. A bad signature is BadSignature; an illegal edge is
    # IllegalTransition. Fail-closed.
    def verify_transition_object(obj, profile, alg, pubkey)
      payload = verify_sign1(obj, profile, alg, pubkey)
      t = parse_transition(payload)
      verify_transition(t.from, t.to)
      t
    end

    # Walk a task's transition chain offline against the authority's key and the bound card attestation.
    # Enforces, in order and fail-closed: (1) the SIGNATURE of every transition (BadSignature
    # otherwise); (2) prev/seq linkage (each prev links to the prior head, genesis zero for seq 0; seq i
    # == index) -- a gap/reorder is TaskChainBroken; (3) the CARD BINDING (every transition's card
    # equals `card`) -- ForeignCard otherwise; and (4) the START STATE (seq-0's from is START_STATE),
    # CONTIGUITY (each from == the prior to), and the LEGAL-EDGE TABLE at every step (including the
    # terminal-cannot-continue rule) -- IllegalTransition otherwise. Returns the verified, ordered
    # transitions. It never authorizes; it accepts or rejects.
    def verify_task_chain(objs, card, profile, alg, pubkey)
      h = genesis
      card = card.dup.force_encoding(Encoding::BINARY)
      prev_to = nil
      out = []
      objs.each_with_index do |obj, i|
        payload = verify_sign1(obj, profile, alg, pubkey)   # BadSignature (foreign/tampered)
        t = parse_transition(payload)
        if t.seq != i || t.prev.b != h
          raise NamingError.new("TaskChainBroken", "prev/seq does not chain to the previous transition")
        end
        if t.card.b != card
          raise NamingError.new("ForeignCard", "transition binds a card other than the profile's bound card")
        end
        if i.zero?
          if t.from != START_STATE
            raise NamingError.new("IllegalTransition", "the first transition must leave the start state")
          end
        elsif t.from != prev_to
          raise NamingError.new("IllegalTransition", "non-contiguous: this from must equal the prior to")
        end
        verify_transition(t.from, t.to)                     # an illegal edge (incl. from-terminal)
        h = t.head
        prev_to = t.to
        out << t
      end
      out
    end

    # Report whether a presented (possibly gappy) transition list breaks contiguity -- a deleted/omitted
    # or reordered transition -- and, if so, the FIRST-BROKEN position. A contiguous list returns
    # [0, false]. (The gap-evident detector for the task chain, mirroring detect_hole.)
    def detect_task_gap(transitions)
      h = genesis
      transitions.each_with_index do |t, i|
        return [i, true] if t.seq != i || t.prev.b != h
        h = t.head
      end
      [0, false]
    end

    # ---- small deterministic-CBOR field accessors (strict decode; NonCanonical propagates) -------

    def decode_map(b)
      v = Naalp::CBOR.decode(b)
      v.is_a?(M) ? v : nil
    rescue Naalp::CBOR::NonCanonical
      nil
    end

    def field(m, k)
      m.pairs.each { |kk, vv| return vv if kk.is_a?(U) && kk.v == k }
      nil
    end

    def bstr_field(m, k)
      v = field(m, k)
      v.is_a?(B) ? v.v : nil
    end

    def tstr_field(m, k)
      v = field(m, k)
      v.is_a?(T) ? v.v : nil
    end

    def uint_field(m, k)
      v = field(m, k)
      v.is_a?(U) ? v.v : nil
    end
  end
end
