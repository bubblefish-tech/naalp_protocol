# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C7 audit for the Ruby SDK -- the signed hash-chained receipt (the baseline
# single-authority ordering tier), the equivocation auditor and its non-repudiable fork proof, and
# the offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
#
# An ordering authority records each accepted object by appending a signed Receipt
# {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
# substitution breaks a `prev` link or a `seq` (§8.1). The authority never mutates the origin object
# to order it -- ordering is an outer signed layer, and the object's own signature stays valid
# (§8.2). The causal graph is the authority-independent foundation: an edge "A causes B" is proven
# by B's signature over A's content id (envelope field 8) and is checkable offline; a total order is
# a policy layered over this partial order (§8.2). A cause an effect could not have seen (later
# position, or a cycle) is rejected (CausalViolation, §8.3). An auditor detects equivocation -- two
# receipts by one authority at one seq naming different objects -- from the signed receipts alone
# (§8.5), and mints a non-repudiable ForkProof carrying BOTH of the accused's signatures and an
# external monotonic counter (draft-01 finding #70).
#
# Ported from impl/go/audit (cross-read against impl/python/naalp/audit.py). Receipt/fork-proof
# signatures are a RAW deterministic ML-DSA signature over the record body (Naalp::COSE.mldsa_sign /
# mldsa_verify), exactly as the reference's cose.Signer/Verifier sign the receipt body directly. The
# causal partial order is checked by the shared Naalp::Graph (the same foundation the reference
# reuses). Graded against the shared vectors/audit/cases.json.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'graph'

module Naalp
  module Audit
    # The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is zero.
    HEAD_SIZE = 48

    # A named, fail-closed audit error; #kind is the stable error kind mirroring Go/Rust (design §8.6).
    class AuditError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # Receipt is one signed append to an ordering authority's chain (design §8.1): prev is the hash
    # of the previous receipt body (HEAD_SIZE bytes; genesis is zero); obj is the content id of the
    # accepted object (never the object itself -- §8.2); seq is the monotonic position; at is the
    # authority's time anchor, epoch ms (independent of the signer's clock, R-8.4).
    Receipt = Struct.new(:prev, :obj, :seq, :at) do
      # Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(prev)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(obj)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(seq)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::U.new(at)],
        ]))
      end

      # The chain head after this receipt: SHA-384 of the receipt body. Because the body carries prev,
      # editing any receipt breaks the next receipt's linkage.
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end
    end

    # An object's place in the causal graph: its content id, the content ids of its causes (envelope
    # field 8), and its ordering position (authority seq, or `created` absent a receipt).
    CausalNode = Struct.new(:id, :causes, :position)

    # Non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3): two validly-signed receipts by
    # ONE authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two signatures and
    # an external monotonic counter -- self-contained, so any third party verifies both signatures
    # against the accused key with no further evidence and no repudiation.
    ForkProof = Struct.new(:signer, :ext_counter, :a, :sig_a, :b, :sig_b) do
      # Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a,
      # 5: body_b, 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature
      # covers.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(signer)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(ext_counter)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(a.bytes)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(sig_a)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::B.new(b.bytes)],
          [Naalp::CBOR::U.new(6), Naalp::CBOR::B.new(sig_b)],
        ]))
      end

      # The deterministic-CBOR framing witness: the fork-proof body with the two signature
      # byte-strings elided to empty. It is the structural authority the independent oracle reproduces
      # byte-for-byte; the two ML-DSA signatures are graded by cross-implementation byte-parity
      # elsewhere. This is not a wire object; it exists only to grade the framing.
      def preimage
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(signer)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(ext_counter)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(a.bytes)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new("".b)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::B.new(b.bytes)],
          [Naalp::CBOR::U.new(6), Naalp::CBOR::B.new("".b)],
        ]))
      end

      # Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq;
      # (3) they name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any
      # failure rejects the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer
      # proof is ForkProofInvalid, and a signature that does not verify is ReceiptUnsigned. Returns nil
      # on a valid, non-repudiable proof of Equivocation.
      def verify(alg, pubkey)
        raise AuditError.new("ForkProofInvalid", "an unnamed accused is not evidence") if signer.bytesize.zero?
        raise AuditError.new("ForkProofInvalid", "receipts at different sequence positions") if a.seq != b.seq
        raise AuditError.new("ForkProofInvalid", "same object named twice -- no equivocation") if a.obj == b.obj
        unless Naalp::COSE.mldsa_verify(alg, pubkey, a.bytes, sig_a) &&
               Naalp::COSE.mldsa_verify(alg, pubkey, b.bytes, sig_b)
          raise AuditError.new("ReceiptUnsigned", "a signature does not verify under the accused key")
        end
        nil
      end
    end

    # A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
    # content ids; it holds no object bodies and mutates none. Signs with a real deterministic ML-DSA
    # key derived from `seed` (a RAW signature over each receipt body).
    class Authority
      def initialize(alg, seed)
        @alg = alg
        @seed = seed.dup.force_encoding(Encoding::BINARY)
        @head = ("\x00" * HEAD_SIZE).b
        @seq = 0
      end

      # Record acceptance of the object named by content id obj at time at, returning [receipt,
      # signature]. Seq increases by one per append (monotonic).
      def append(obj, at)
        r = Receipt.new(@head.dup, obj.dup.force_encoding(Encoding::BINARY), @seq, at)
        sig = Naalp::COSE.mldsa_sign(@alg, @seed, r.bytes)
        @head = r.head
        @seq += 1
        [r, sig]
      end
    end

    # Observes an authority's receipts and detects equivocation from the signed receipts alone (§8.5).
    # On a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both
    # conflicting signatures, and an external monotonic counter (T2.1).
    class Auditor
      def initialize(alg, pubkey, signer, ext_base = 0)
        @alg = alg
        @pk = pubkey.dup.force_encoding(Encoding::BINARY)
        @signer = signer.dup.force_encoding(Encoding::BINARY)
        @ext = ext_base
        @seen = {} # seq -> [Receipt, signature]
      end

      # Record a signed receipt. Raises AuditError(ReceiptUnsigned) on a bad signature. Returns a
      # ForkProof (Equivocation) if a previously-seen receipt at the same seq named a different
      # object -- the proof carries the accused signer id, both signatures, and the auditor's current
      # external counter, which then advances. Returns nil otherwise (including a benign exact
      # duplicate).
      def observe(r, sig)
        unless Naalp::COSE.mldsa_verify(@alg, @pk, r.bytes, sig)
          raise AuditError.new("ReceiptUnsigned", "receipt signature does not verify")
        end
        prev = @seen[r.seq]
        unless prev.nil?
          prev_r, prev_sig = prev
          if prev_r.obj != r.obj
            fp = Naalp::Audit.new_fork_proof(@signer, prev_r, prev_sig, r, sig, @ext)
            @ext += 1
            return fp
          end
          return nil
        end
        @seen[r.seq] = [r, sig.dup]
        nil
      end
    end

    module_function

    # Check a receipt chain offline against the authority's key: each receipt's seq is the next
    # expected value, its prev links to the previous receipt's head (genesis is zero), and its raw
    # signature verifies. A broken link or a seq gap is ChainBroken; a bad signature is
    # ReceiptUnsigned. Detects any reorder, omission, or substitution (§8.1). Returns nil on success.
    def verify_chain(receipts, sigs, alg, pubkey)
      raise AuditError.new("ChainBroken", "receipt/signature count mismatch") if receipts.length != sigs.length
      head = ("\x00" * HEAD_SIZE).b
      receipts.each_with_index do |r, i|
        if r.seq != i || r.prev != head
          raise AuditError.new("ChainBroken", "receipt prev/seq does not chain to the previous receipt")
        end
        unless Naalp::COSE.mldsa_verify(alg, pubkey, r.bytes, sigs[i])
          raise AuditError.new("ReceiptUnsigned", "receipt signature does not verify")
        end
        head = r.head
      end
      nil
    end

    # An object cannot be created after the authority ordered it, so created MUST NOT exceed at
    # (R-8.4). The receipt's `at` is signed and chained, so it is evidence a verifier checks
    # independently of the signer's clock.
    def consistent_with_anchor(created, at)
      created <= at
    end

    # Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an
    # external monotonic counter. Performs no checks -- ForkProof#verify is the fail-closed gate; this
    # is the pure constructor (A9). Copies the byte slices so the proof owns its evidence.
    def new_fork_proof(signer, a, sig_a, b, sig_b, ext_counter)
      ForkProof.new(
        signer.dup.force_encoding(Encoding::BINARY),
        ext_counter,
        a,
        sig_a.dup.force_encoding(Encoding::BINARY),
        b,
        sig_b.dup.force_encoding(Encoding::BINARY),
      )
    end

    # Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
    # exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either fault
    # is CausalViolation. Edges to causes not present in the set are ignored (external references).
    # Runs with no ordering authority present (R-8.5). Delegates to the shared Naalp::Graph, which
    # implements exactly this partial order. Returns nil on success.
    def verify_causal(nodes)
      Naalp::Graph.verify_causal(nodes.map { |n| [n.id, n.causes.dup, n.position] })
      nil
    end

    # Return the causal nodes' content ids in a deterministic topological order (a cause before its
    # effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
    # Raises CausalViolation if the graph does not verify. NOTE: the audit tie-break is by POSITION --
    # distinct from the federation reconcile, whose tie-break is the content id (Naalp::Graph.reconcile).
    def topo_order(nodes)
      verify_causal(nodes)
      idx = {}
      nodes.each_with_index { |n, i| idx[n.id] = i }
      indeg = Array.new(nodes.length, 0)
      effects = Array.new(nodes.length) { [] } # cause index -> effect indices
      nodes.each_with_index do |n, i|
        n.causes.each do |c|
          j = idx[c]
          unless j.nil?
            effects[j] << i
            indeg[i] += 1
          end
        end
      end
      done = Array.new(nodes.length, false)
      order = []
      while order.length < nodes.length
        pick = -1
        nodes.each_index do |i|
          next if done[i] || indeg[i] != 0
          pick = i if pick == -1 || nodes[i].position < nodes[pick].position
        end
        raise Naalp::Graph::CausalViolation, "no ready node (unreachable after verify_causal)" if pick == -1
        done[pick] = true
        order << nodes[pick].id
        effects[pick].each { |e| indeg[e] -= 1 }
      end
      order
    end
  end
end
