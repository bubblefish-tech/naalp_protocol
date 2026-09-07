# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C6 approval object + single-use consume ledger for the Ruby SDK (design.md §7;
# R-7.1..7.4).
#
# An ApprovalRecord binds, under signature, the content id of the exact canonical argument object it
# approves (§7.1); because the args are named by content id, mutating any argument changes the id and
# the approval no longer matches (ApprovalMismatch). The consume ledger is a durable compare-and-set
# set keyed by approval content id: the FIRST consumer of an id wins and every later consume of the
# same id is rejected AlreadyConsumed (§7.2). Atomicity is honest, not decorative -- the membership
# check AND the append run inside ONE mutex-held critical section (the single-writer discipline, as
# the Go single mutex), so there is no read-then-write TOCTOU window and a race spends an approval
# EXACTLY ONCE. Each winning consume is written and fsynced to the write-ahead log before it returns
# (persist-before-ack). A held outcome is a distinct signed non-success result (HeldResult, §7.4).
# Every rejection is fail-closed and causes no ledger append.
#
# Ported from impl/go/approval (cross-read against impl/python/naalp/approval.py). The approval
# SIGNATURE is a real deterministic ML-DSA-65 signature over the body bytes DIRECTLY (as the
# reference cose.Signer.Sign -- NOT a COSE Sig_structure); the corpus carries no signed vector, so
# sign/verify is demonstrated in isolation only. The record bodies reuse the shared spine builders
# (Naalp::Records.approval_body / ledger_entry) where those builders already support the shape;
# ApprovalRecord's own body is built directly (not via Records) so it can carry the OPTIONAL R-TDCS-5
# audience field 6. Graded against the shared vectors/approval/cases.json.
#
# T1.5 (NAALP-REQ-121, design.md §7.5): the ledger-signed ConsumeReceipt / ConsumeForkEvidence /
# ReceiptSet double-spend-evidence surface, graded against the SEPARATE independent corpus
# vectors/consume_receipt/cases.json (non-circular, F3 -- verdicts come from the oracle's from-scratch
# is_fork() model, not this code). R-TDCS-3 (party-visible coarse Refusal, no leaked detail),
# R-TDCS-4 (VerifyFreshIndependent -- freshness judged by an ordering authority structurally distinct
# from the authenticated party) and R-TDCS-5 (VerifyAudience, the approval's optional audience field)
# are graded against vectors/trust_decision/cases.json. All ML-DSA signing here is the same raw
# body-bytes convention as the base approval signature (no COSE Sig_structure).
require 'openssl'
require 'thread'
require_relative 'cbor'
require_relative 'cose'
require_relative 'records'
require_relative 'envelope'
require_relative 'policy'

module Naalp
  module Approval
    # The width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is all-zero.
    HEAD_SIZE = 48

    # A named, fail-closed approval error; #kind is the stable error kind mirroring Go/Rust/Python
    # (design §7, §15).
    class ApprovalError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # ApprovalRecord is the body of an Approval object (§7.1). It is signed over its
    # deterministic-CBOR bytes. `approves` is the content id of the exact canonical args object; a
    # changed argument changes the id and the approval no longer matches (ApprovalMismatch).
    # `audience` is the R-TDCS-5 OPTIONAL valid-context; nil/"" == absent (field 6 omitted --
    # unrestricted). A 5-positional-arg construction (the pre-audience call shape) leaves `audience`
    # nil, so existing callers are unaffected.
    ApprovalRecord = Struct.new(:approves, :approver, :grant, :nonce, :not_after, :audience) do
      # Deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6 is OMITTED
      # when `audience` is nil/"" -- an empty string is not a distinct value, so an approval that
      # names no audience encodes byte-identically to a 5-field approval (R-TDCS-5, additive by
      # design). Built directly (not via Naalp::Records.approval_body) so the optional 6th field can
      # be conditionally present; canonical map ordering is enforced by the encoder regardless of
      # pair-list order.
      def bytes
        pairs = [
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(approves)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(approver)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(grant)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(nonce)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::U.new(not_after)],
        ]
        pairs << [Naalp::CBOR::U.new(6), Naalp::CBOR::T.new(audience)] if audience && !audience.empty?
        Naalp::CBOR.encode(Naalp::CBOR::M.new(pairs))
      end

      # The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # HeldResult is the distinct, signed, non-success result returned when an action requires an
    # approval that has not been granted (§7.4). It is never a silent success or a silent denial.
    HeldResult = Struct.new(:approves, :reason) do
      # Deterministic-CBOR encoding of the held result {1: approves, 2: reason}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(approves)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(reason)],
        ]))
      end
    end

    # LedgerEntry is one append to the consume ledger (§7.2).
    LedgerEntry = Struct.new(:seq, :prev, :approval_id, :by) do
      # Deterministic-CBOR encoding of the entry {1: seq, 2: prev, 3: approval-id, 4: by} (reuses the
      # shared spine records builder). The head after this entry is SHA-384(bytes); because the body
      # carries prev, editing any entry breaks the next entry's linkage.
      def bytes
        Naalp::Records.ledger_entry(seq, prev, approval_id, by)
      end

      # This entry's chain head -- the prev of the next entry.
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end
    end

    # ConsumeReceipt is the draft-01 (T1.5, NAALP-REQ-121) ledger-signed evidence that a consuming
    # ledger -- the ORDERING AUTHORITY -- bound an approval content id to its own forward-only
    # position. The anti-double-spend counter (`position`) rides under the LEDGER's signature, never
    # the requester's: the requester cannot forge the ledger's position or its signature. A partition
    # that spends one approval twice leaves two ledger-signed receipts against one approval id, each
    # carrying a position drawn from forked state -- a contradiction authored by neither the requester
    # nor a thief, provable the instant the two receipts are compared (see ConsumeForkEvidence). It
    # does not PREVENT the second spend; it makes the double-spend detectable in bytes neither party
    # could repudiate.
    ConsumeReceipt = Struct.new(:ledger, :approval_id, :position) do
      # Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position} --
      # the exact bytes the ledger signs (T1.5). A nil `ledger` encodes as a zero-length byte string
      # (matching a nil Go slice), distinct from an ABSENT field (empty != absent, per the wire corpus).
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(ledger || "".b)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(approval_id)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(position)],
        ]))
      end
    end

    # ConsumeForkEvidence is the non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval
    # content id received TWO conflicting ledger-signed consume receipts -- a double spend made
    # provable on comparison. It carries both receipts and both ledger signatures; because a verifier
    # checks each signature under the key its receipt names, the contradiction is authored by neither
    # the requester nor a thief. Both positions (and, cross-ledger, both ledger ids) are surfaced so
    # the contradiction is legible to a human and to tooling.
    ConsumeForkEvidence = Struct.new(:approval_id, :a, :sig_a, :b, :sig_b) do
      # Check that this is a genuine fork: (1) the disputed approval id is present and BOTH receipts
      # name it; (2) the two receipts actually conflict -- they are NOT byte-identical (a
      # byte-identical re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures
      # verify under the keys their receipts name, resolved through `resolve` -- a callable taking a
      # ledger id and returning `[alg, pubkey]` or nil/false if unresolvable. Any failure raises the
      # specific fail-closed error (fail-closed): a mismatched/absent approval id or a byte-identical
      # pair raises ConsumeForkInvalid, and an unnamed/unresolvable ledger or a signature that does
      # not verify raises ConsumeReceiptUnsigned. Returns nil on a clean pass -- the double spend is
      # proven and non-repudiable.
      def verify(resolve)
        if approval_id.nil? || approval_id.empty?
          raise ApprovalError.new("ConsumeForkInvalid", "fork evidence does not prove a double spend")
        end
        unless a.approval_id.b == approval_id.b && b.approval_id.b == approval_id.b
          raise ApprovalError.new("ConsumeForkInvalid", "both receipts must name the disputed approval id")
        end
        if a.bytes == b.bytes
          raise ApprovalError.new("ConsumeForkInvalid", "byte-identical receipts are a benign duplicate, not a fork")
        end
        ra = resolve.call(a.ledger)
        if ra.nil? || a.ledger.nil? || a.ledger.empty?
          raise ApprovalError.new("ConsumeReceiptUnsigned", "ledger a is unnamed or unresolvable")
        end
        rb = resolve.call(b.ledger)
        if rb.nil? || b.ledger.nil? || b.ledger.empty?
          raise ApprovalError.new("ConsumeReceiptUnsigned", "ledger b is unnamed or unresolvable")
        end
        alg_a, pk_a = ra
        alg_b, pk_b = rb
        ok_a = begin
          Naalp::COSE.cose_verify1_raw(alg_a, pk_a, a.bytes, sig_a)
        rescue OpenSSL::PKey::PKeyError
          false
        end
        ok_b = begin
          Naalp::COSE.cose_verify1_raw(alg_b, pk_b, b.bytes, sig_b)
        rescue OpenSSL::PKey::PKeyError
          false
        end
        unless ok_a && ok_b
          raise ApprovalError.new("ConsumeReceiptUnsigned", "a ledger signature does not verify")
        end
        nil # a valid, non-repudiable double-spend proof
      end
    end

    # ReceiptSet observes ledger-signed consume receipts, keyed by approval content id, and detects a
    # fork (a double spend) from the signed receipts alone (T1.5, NAALP-REQ-121) -- the consume-layer
    # analogue of the audit auditor's equivocation detection. It resolves each receipt's ledger
    # verifier through `resolve` (a callable ledger id -> `[alg, pubkey]` or nil/false for an unknown
    # ledger), rejects any receipt whose ledger signature does not verify, and on a conflicting second
    # receipt for one approval id mints a non-repudiable ConsumeForkEvidence. Use
    # Naalp::Approval.new_receipt_set to build one.
    class ReceiptSet
      def initialize(resolve)
        @lock = Mutex.new
        @resolve = resolve
        @seen = {} # approval-id bytes -> { r:, sig: } (first receipt seen)
      end

      # Record a ledger-signed consume receipt. Returns `[nil, ApprovalError("ConsumeReceiptUnsigned")]`
      # if the ledger is unnamed/unresolvable or the signature does not verify; `[evidence,
      # ApprovalError("ConsumeFork")]` when a previously-seen receipt for the same approval id
      # conflicts (different position and/or ledger); and `[nil, nil]` otherwise (including a benign
      # byte-identical duplicate).
      def observe(r, sig)
        @lock.synchronize do
          resolved = @resolve.call(r.ledger)
          ok = false
          unless resolved.nil? || r.ledger.nil? || r.ledger.empty?
            alg, pk = resolved
            begin
              ok = Naalp::COSE.cose_verify1_raw(alg, pk, r.bytes, sig)
            rescue OpenSSL::PKey::PKeyError
              ok = false
            end
          end
          unless ok
            return [nil, ApprovalError.new("ConsumeReceiptUnsigned", "receipt ledger is unnamed/unresolvable or its signature does not verify")]
          end
          key = r.approval_id.dup.force_encoding(Encoding::BINARY)
          prev = @seen[key]
          if prev
            if prev[:r].bytes == r.bytes
              return [nil, nil] # benign byte-identical duplicate
            end
            fe = ConsumeForkEvidence.new(key.dup, prev[:r], prev[:sig], r, sig.dup)
            return [fe, ApprovalError.new("ConsumeFork", "two ledger-signed receipts contradict on one approval id")]
          end
          @seen[key] = { r: r, sig: sig.dup }
          [nil, nil]
        end
      end
    end

    # The closed refusal-outcome set (CDDL refusal-outcome; R-TDCS-3, design.md §25/C22).
    REFUSAL_DENIED = 0       # the action is refused
    REFUSAL_HELD = 1         # the action requires a further step not yet taken
    REFUSAL_UNVERIFIABLE = 2 # required evidence did not verify

    REFUSAL_OUTCOME_NAME = { REFUSAL_DENIED => "denied", REFUSAL_HELD => "held", REFUSAL_UNVERIFIABLE => "unverifiable" }.freeze

    # Refusal is the party-visible coarse refusal body {1: outcome, 2: record} (R-TDCS-3). `outcome`
    # is the closed-set coarse outcome; `record` is the T1 content id of the full signed record
    # carrying the discriminating detail -- a reference, not the reason. The detail exists, is
    # signed, and is auditor-resolvable through the record channel, but never reaches the
    # adversary-facing surface, so repeated refusals cannot serve an adaptive party as an oracle.
    Refusal = Struct.new(:outcome, :record) do
      # Deterministic-CBOR encoding {1: outcome, 2: record}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(outcome)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(record)],
        ]))
      end
    end

    # The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through
    # #consume under a single mutex (the single-writer discipline), and each winning consume is
    # written and fsynced to the WAL before it returns. Use Naalp::Approval.open_ledger to build one.
    #
    # T1.5 (NAALP-REQ-121): a ledger opened with a signing alg+seed (via Naalp::Approval.open_ledger_signed)
    # also carries its own ordering-authority identity (`authority`, the ledger_id) and signing key, so
    # #consume_with_receipt can mint a ledger-signed consume receipt binding the approval id to the
    # ledger's forward-only position. A ledger opened without a signing key offers #consume only.
    class Ledger
      def initialize(path, authority = "", signing_alg = nil, signing_seed = nil)
        @lock = Mutex.new
        @f = File.open(path, File::RDWR | File::CREAT | File::BINARY, 0o600)
        @f.binmode
        @consumed = {}                        # approval-id bytes -> seq
        @head = ("\x00" * HEAD_SIZE).b        # current chain head (genesis is all-zero)
        @seq = 0                              # next sequence number
        @ledger_id = authority                # consuming-authority NAME (§2.5.3 audience target; T1.5 ordering-authority id)
        @signing_alg = signing_alg            # T1.5: the ledger's own signing alg, or nil if unsigned
        @signing_seed = signing_seed          # T1.5: the ledger's own signing seed, or nil if unsigned
      end

      # Read the WAL from the start, rebuilding state and verifying the chain. Each record is
      # length-prefixed (uint32 big-endian) so the log is self-framing. An out-of-order seq or a
      # broken prev linkage is refused LedgerCorrupt. Returns self.
      def replay
        @f.seek(0)
        head = ("\x00" * HEAD_SIZE).b
        seq = 0
        loop do
          lb = @f.read(4)
          break if lb.nil? || lb.empty?
          raise ApprovalError.new("LedgerCorrupt", "truncated length prefix") if lb.bytesize != 4
          n = lb.unpack1("N")
          rec = @f.read(n)
          raise ApprovalError.new("LedgerCorrupt", "truncated record") if rec.nil? || rec.bytesize != n
          e = Naalp::Approval.parse_entry(rec)
          if e.seq != seq || e.prev.b != head
            raise ApprovalError.new("LedgerCorrupt", "out-of-order seq or broken chain linkage")
          end
          @consumed[e.approval_id.b] = e.seq
          head = OpenSSL::Digest::SHA384.digest(rec)
          seq += 1
        end
        @head = head
        @seq = seq
        self
      end

      # Atomically consume an approval id EXACTLY ONCE (§7.2). The first caller for a given id appends
      # a ledger entry (written and fsynced before returning) and returns it; every later caller for
      # the same id raises AlreadyConsumed with no append. The single mutex serialises the
      # compare-and-set, so under a race exactly one caller wins.
      def consume(approval_id, by)
        aid = approval_id.dup.force_encoding(Encoding::BINARY)
        @lock.synchronize do
          raise ApprovalError.new("AlreadyConsumed", "approval already consumed") if @consumed.key?(aid)
          e = LedgerEntry.new(@seq, @head.dup, aid, by)
          rec = e.bytes
          framed = [rec.bytesize].pack("N") + rec
          @f.seek(0, IO::SEEK_END)
          @f.write(framed)
          @f.flush
          @f.fsync                            # persist-before-ack (R-7.2 durability)
          @consumed[aid] = e.seq
          @head = OpenSSL::Digest::SHA384.digest(rec)
          @seq += 1
          e
        end
      end

      # Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at the
      # choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's
      # consuming authority, or the object is rejected WrongAudience with no ledger append. An unnamed
      # ledger (no authority) refuses LedgerUnsigned -- it cannot be the audience of any object. The
      # audience check is NEVER inside Envelope.verify (a relay/auditor legitimately verifies objects
      # addressed to others). Mirrors Go/Rust Ledger.ConsumeObject -- the authority is this port's NAME.
      def consume_object(o, approval_id, by)
        raise ApprovalError.new("LedgerUnsigned", "ledger has no consuming authority") if @ledger_id.empty?
        # fail-closed, before the CAS: raises Envelope::EnvelopeError("WrongAudience") and appends nothing
        Naalp::Envelope.check_audience(o, @ledger_id, true)
        consume(approval_id, by)
      end

      # Perform the first-append-wins compare-and-set (exactly as #consume) AND, on the winning
      # append, return a ledger-signed ConsumeReceipt binding the approval id to the entry's
      # forward-only position (its ledger seq) (T1.5, NAALP-REQ-121). The ledger must have been opened
      # with a signing alg+seed (Naalp::Approval.open_ledger_signed); an unsigned ledger raises
      # LedgerUnsigned (fail-closed). A second consume of the same approval id raises AlreadyConsumed
      # and signs nothing -- the first receipt stands (first-append-wins). The receipt is signed
      # BEFORE the WAL write, so a signing failure records nothing. The single mutex serialises
      # concurrent callers, so under a race exactly one wins and exactly one receipt is minted.
      # Returns [entry, receipt, sig].
      def consume_with_receipt(approval_id, by)
        raise ApprovalError.new("LedgerUnsigned", "ledger was not opened with a signing key") if @ledger_id.empty? || @signing_seed.nil?
        aid = approval_id.dup.force_encoding(Encoding::BINARY)
        @lock.synchronize do
          raise ApprovalError.new("AlreadyConsumed", "approval already consumed") if @consumed.key?(aid) # first-append-wins: no second receipt
          e = LedgerEntry.new(@seq, @head.dup, aid, by)
          # The receipt binds the approval id to THIS consume's forward-only position (the entry seq),
          # signed by the ledger key. Sign before touching the WAL so a signing failure records nothing.
          receipt = ConsumeReceipt.new(@ledger_id.dup, aid.dup, e.seq)
          sig = Naalp::COSE.mldsa_sign(@signing_alg, @signing_seed, receipt.bytes)
          rec = e.bytes
          framed = [rec.bytesize].pack("N") + rec
          @f.seek(0, IO::SEEK_END)
          @f.write(framed)
          @f.flush
          @f.fsync                            # persist-before-ack (R-7.2 durability)
          @consumed[aid] = e.seq
          @head = OpenSSL::Digest::SHA384.digest(rec)
          @seq += 1
          [e, receipt, sig]
        end
      end

      # Whether an approval id has been consumed.
      def consumed?(approval_id)
        @lock.synchronize { @consumed.key?(approval_id.b) }
      end

      # The current chain head (a copy).
      def head
        @lock.synchronize { @head.dup }
      end

      # The number of consumed approvals.
      def count
        @lock.synchronize { @consumed.length }
      end

      # Flush and close the WAL file.
      def close
        @lock.synchronize { @f.close }
      end
    end

    module_function

    # Open (creating if needed) a WAL-backed consume ledger at path and replay any existing log to
    # rebuild the consumed set and chain head. A log that does not hash-chain cleanly is refused
    # (LedgerCorrupt) rather than trusted. On a refused replay the file handle is closed before the
    # error propagates (as the Go reference closes it), so a corrupt log leaks no descriptor.
    def open_ledger(path, authority = "")
      led = Ledger.new(path, authority)
      begin
        led.replay
      rescue Exception
        led.close
        raise
      end
      led
    end

    # Open a WAL-backed ledger (as .open_ledger) bound to its own ordering-authority identity
    # (`ledger_id`) and a real deterministic ML-DSA signing key (`alg`/`seed`), so it can produce
    # ledger-signed consume receipts (T1.5, NAALP-REQ-121). An unnamed authority (nil/empty
    # `ledger_id`) or a missing seed is refused fail-closed: an unnamed or keyless ordering authority
    # cannot sign the anti-double-spend position, so #consume_with_receipt would have nothing
    # accountable to emit.
    def open_ledger_signed(path, ledger_id, alg, seed)
      raise ApprovalError.new("LedgerUnsigned", "ledger requires a named authority and a signing key") if ledger_id.nil? || ledger_id.empty? || seed.nil?
      led = Ledger.new(path, ledger_id, alg, seed)
      begin
        led.replay
      rescue Exception
        led.close
        raise
      end
      led
    end

    # Sign the approval body with a real deterministic ML-DSA key derived from seed. The signed input
    # is the approval body bytes DIRECTLY (matching the reference cose.Signer.Sign: raw message, empty
    # context, rnd=0 -- there is NO COSE Sig_structure wrapping here).
    def sign_approval(a, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, a.bytes)
    end

    # Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact
    # args by content id, (3) not expired at pos_time. Returns nil only if all three hold; otherwise
    # raises the specific named error and authorizes nothing. Check order is fail-closed: BadSignature
    # -> ApprovalMismatch -> ApprovalExpired. It does NOT consume -- consumption is the separate
    # atomic ledger step (§7.2).
    def verify_approval(a, alg, pubkey, sig, args_content_id, pos_time)
      unless Naalp::COSE.cose_verify1_raw(alg, pubkey, a.bytes, sig)
        raise ApprovalError.new("BadSignature", "approval signature does not verify")
      end
      unless a.approves.b == args_content_id.b
        raise ApprovalError.new("ApprovalMismatch", "approval does not bind these arguments' content id")
      end
      if pos_time > a.not_after
        raise ApprovalError.new("ApprovalExpired", "approval is past its not_after")
      end
      nil
    rescue OpenSSL::PKey::PKeyError
      raise ApprovalError.new("BadSignature", "approval signature does not verify")
    end

    # consume_approval is the composed, single-call consume choke point for the approval state machine
    # (draft "## Approval state machine"). It runs the table's precedence in ONE impl-owned place -- the
    # exact sequence Go's approval.ConsumeApproval / Rust's approval::consume_approval realize -- so a
    # caller (and the conformance suite) drives one realization of the reactions rather than re-deriving
    # the ordering at each call site:
    #
    #  1. verify_approval checks the signature, then the args-content-id binding (ApprovalMismatch,
    #     which the draft says "takes precedence over every cell"), then expiry (ApprovalExpired) --
    #     all BEFORE the ledger is consulted. So a request both past not_after AND already in the
    #     ledger raises ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume rule),
    #     and the ledger is left untouched by the rejected request.
    #  2. The granted effect must be a valid class (0..3) and must cover the action's required effect;
    #     a grant outside the closed vocabulary, or one below the required effect, authorizes nothing
    #     and raises ApprovalRequired (fail-closed; the grant-range guard is stricter than a raw
    #     Policy.authorizes call, which would otherwise treat an out-of-range grant as satisfying any
    #     required effect via its `action <= ceiling` lattice).
    #  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
    #     second raises AlreadyConsumed, and neither a rejected earlier step nor a losing race appends.
    #
    # Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
    # returning the ledger entry. It does NOT enforce object audience -- that is Ledger#consume_object's
    # binding (design.md §2.5.3); consume_approval is the args-content-id/effect/single-use choke point.
    def consume_approval(a, alg, pubkey, sig, args_content_id, pos_time, required_effect, ledger, by)
      verify_approval(a, alg, pubkey, sig, args_content_id, pos_time) # BadSignature/ApprovalMismatch/ApprovalExpired, all before the ledger
      if a.grant > Naalp::Policy::DESTRUCTIVE
        raise ApprovalError.new("ApprovalRequired", "action requires an approval that is not present")
      end
      unless Naalp::Policy.authorizes(a.grant, required_effect)
        raise ApprovalError.new("ApprovalRequired", "action requires an approval that is not present")
      end
      ledger.consume(a.id, by)
    end

    # Sign a held result so the "not yet granted" outcome is itself attributable (real ML-DSA).
    def sign_held(h, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, h.bytes)
    end

    # (R-TDCS-5) Enforce the OPTIONAL audience binding. An approval that NAMES an audience
    # (`a.audience` non-nil, non-empty) is valid only in that context: a relying party checks it at
    # use and raises AudienceMismatch on a mismatch. An approval that names NO audience is
    # unrestricted by the issuer's explicit choice and passes for any use context -- a deployment MAY
    # require an audience by local policy above this check. The check is mandatory WHEN a context is
    # present, never mandatory-presence (the JWT `aud` present-optional / check-mandatory shape).
    def verify_audience(a, use_context)
      if a.audience && !a.audience.empty? && a.audience != use_context
        raise ApprovalError.new("AudienceMismatch", "approval names an audience other than the use context")
      end
      nil
    end

    # ---- T1.5 (NAALP-REQ-121): ledger-signed consume receipt --------------------------------------

    # Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is under
    # the ordering authority's signature, never the requester's). The signed input is the receipt
    # bytes DIRECTLY (no COSE Sig_structure).
    def sign_consume_receipt(r, alg, seed)
      Naalp::COSE.mldsa_sign(alg, seed, r.bytes)
    end

    # Check that a consume receipt is a valid ledger-signed statement: the ledger id is present (an
    # unnamed ordering authority is not evidence) and the signature verifies under the ledger's key.
    # Fail-closed: either fault raises ConsumeReceiptUnsigned and authorizes nothing. `pubkey` MUST be
    # the key resolved for `r.ledger`.
    def verify_consume_receipt(r, alg, pubkey, sig)
      if r.ledger.nil? || r.ledger.empty?
        raise ApprovalError.new("ConsumeReceiptUnsigned", "an unnamed ordering authority is not evidence")
      end
      unless Naalp::COSE.cose_verify1_raw(alg, pubkey, r.bytes, sig)
        raise ApprovalError.new("ConsumeReceiptUnsigned", "consume receipt signature does not verify")
      end
      nil
    rescue OpenSSL::PKey::PKeyError
      raise ApprovalError.new("ConsumeReceiptUnsigned", "consume receipt signature does not verify")
    end

    # Build a fork detector (Naalp::Approval::ReceiptSet) that resolves a ledger id to `[alg, pubkey]`
    # via `resolve` (which returns nil/false for an unknown ledger id).
    def new_receipt_set(resolve)
      ReceiptSet.new(resolve)
    end

    # (R-TDCS-4, design.md §25) Judge an approval's present-moment validity using time drawn from an
    # ordering authority STRUCTURALLY DISTINCT from the party being authenticated. It is the named
    # realization of the §18.2 seam -- "validity judged on the ordering position, never the signer's
    # clock" -- composing the existing verifiers and adding the distinctness check a relying party
    # runs so a party can never be the source of the time against which its own credential's expiry is
    # judged. It (1) verifies the approval binds args_content_id, is signed by the approver, and is
    # unexpired at pos_time, where pos_time is the ORDERING AUTHORITY's forward-only position (never a
    # clock the approver supplies); (2) verifies the consume receipt is ledger-signed (the position
    # rides under the ordering authority's key, never the requester's); and (3) raises
    # FreshnessSelfAsserted when the ordering authority r.ledger IS the authenticated party party_id.
    # Fail-closed: any fault raises its named error and authorizes nothing.
    def verify_fresh_independent(a, approver_alg, approver_pubkey, a_sig, args_content_id, pos_time,
                                  r, ledger_alg, ledger_pubkey, r_sig, party_id)
      verify_approval(a, approver_alg, approver_pubkey, a_sig, args_content_id, pos_time)
      verify_consume_receipt(r, ledger_alg, ledger_pubkey, r_sig)
      if r.ledger.b == party_id.b
        raise ApprovalError.new("FreshnessSelfAsserted", "the ordering authority that stamps freshness is the authenticated party itself")
      end
      nil
    end

    # ---- R-TDCS-3: party-visible coarse refusal -----------------------------------------------

    # Whether code is in the closed refusal-outcome set (denied/held/unverifiable).
    def is_known_refusal_outcome(code)
      REFUSAL_OUTCOME_NAME.key?(code)
    end

    # Build the party-visible refusal for a full signed record: it carries the coarse outcome and the
    # content id of full_record, and NOTHING drawn from inside full_record -- the discriminating
    # detail stays in the record, referenced only by its id. This is the coarse-to-party split the
    # closure property requires (R-TDCS-3).
    def refusal_from_record(outcome, full_record)
      Refusal.new(outcome, Naalp::CBOR.content_id(full_record))
    end

    # Reconstruct a Refusal from its body bytes, enforcing that a party-visible refusal carries ONLY
    # {outcome, record} and nothing more (R-TDCS-3). Raises, fail-closed: a malformed body, any key
    # other than 1 and 2, a missing or empty record id (RefusalDetailLeak -- discriminating detail
    # leaked, or the auditor reference dropped), and an outcome outside the closed set
    # (UnknownRefusalOutcome). It authorizes nothing.
    def parse_refusal(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise ApprovalError.new("RefusalDetailLeak", "malformed refusal body")
      end
      raise ApprovalError.new("RefusalDetailLeak", "refusal body is not a map") unless v.is_a?(Naalp::CBOR::M)
      outcome = nil
      record = nil
      have_outcome = false
      have_record = false
      v.pairs.each do |k, val|
        raise ApprovalError.new("RefusalDetailLeak", "non-uint refusal key") unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          raise ApprovalError.new("RefusalDetailLeak", "outcome not uint") unless val.is_a?(Naalp::CBOR::U)
          outcome = val.v
          have_outcome = true
        when 2
          raise ApprovalError.new("RefusalDetailLeak", "record not bstr") unless val.is_a?(Naalp::CBOR::B)
          record = val.v
          have_record = true
        else
          raise ApprovalError.new("RefusalDetailLeak", "field #{k.v} beyond the closed {1,2} set is leaked detail")
        end
      end
      if !have_outcome || !have_record || record.empty?
        raise ApprovalError.new("RefusalDetailLeak", "a refusal must carry the full-record content id")
      end
      unless is_known_refusal_outcome(outcome)
        raise ApprovalError.new("UnknownRefusalOutcome", "refusal outcome is outside the closed set denied/held/unverifiable")
      end
      Refusal.new(outcome, record)
    end

    # Decode a ledger entry from its deterministic-CBOR bytes. A malformed shape, a non-uint key, a
    # mistyped field, an unknown field, or a missing field is a corrupt log (LedgerCorrupt). A
    # non-canonical body raises Naalp::CBOR::NonCanonical from the strict decoder.
    def parse_entry(rec)
      v = Naalp::CBOR.decode(rec)
      raise ApprovalError.new("LedgerCorrupt", "ledger entry is not a map") unless v.is_a?(Naalp::CBOR::M)
      seq = prev = aid = by = nil
      v.pairs.each do |k, val|
        raise ApprovalError.new("LedgerCorrupt", "non-uint ledger entry key") unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          raise ApprovalError.new("LedgerCorrupt", "seq not uint") unless val.is_a?(Naalp::CBOR::U)
          seq = val.v
        when 2
          raise ApprovalError.new("LedgerCorrupt", "prev not bstr") unless val.is_a?(Naalp::CBOR::B)
          prev = val.v
        when 3
          raise ApprovalError.new("LedgerCorrupt", "approval-id not bstr") unless val.is_a?(Naalp::CBOR::B)
          aid = val.v
        when 4
          raise ApprovalError.new("LedgerCorrupt", "by not tstr") unless val.is_a?(Naalp::CBOR::T)
          by = val.v
        else
          raise ApprovalError.new("LedgerCorrupt", "unknown ledger entry field #{k.v}")
        end
      end
      if seq.nil? || prev.nil? || aid.nil? || by.nil?
        raise ApprovalError.new("LedgerCorrupt", "ledger entry missing a mandatory field")
      end
      LedgerEntry.new(seq, prev, aid, by)
    end
  end
end
