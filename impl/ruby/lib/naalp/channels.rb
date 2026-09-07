# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C10 channel registry for the Ruby SDK — the frozen twenty-channel baseline surface
# (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
# effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription
# of the design, cross-checked against the shared conformance corpus (== Go == Rust == oracle).
#
# Also ported (channels parity cluster, task #174; design-channels.md §18, §20; mirrors
# impl/go/channels/channels.go and impl/rust/src/channels.rs): the per-channel state machine
# (ChannelSpec/KindSpec + Channels.channel/allowed_transition), Spatial's TransformCycle
# structural check (Channels.check_frame_tree), and the Workflow durable input/approval gate
# (Channels::WorkflowGate / Channels.open_workflow_gate) whose crash test proves InputGateBypass
# cannot occur -- a task's status is persisted (written + fsynced) before it is acknowledged, so a
# crash recovers to the last durable status and can never manufacture a bypass of the gate.
#
# NOTE (baseline_notes): Capability's CapExceedsParent delegation-ceiling check already exists as
# a real wiring in impl/ruby/lib/naalp/delegation.rb (step 6, via Naalp::Policy.authorizes) -- it
# is not duplicated here as a standalone check_delegation(); this port's per-channel table below
# still carries CapExceedsParent in Capability's `errors` list for oracle parity, matching the
# same precedent already recorded in the Python port's channels.py.

module Naalp
  module Channels
    RO = 0  # read_only
    IW = 1  # idempotent_write
    NIW = 2 # non_idempotent_write
    DE = 3  # destructive

    # One baseline object kind of a channel: its code, name, and declared effect. A Variable kind's
    # effect is set per the carried/stream action at run time (Stream StreamOpen, Bridge Carriage),
    # not fixed by the kind.
    KindSpec = Struct.new(:code, :name, :effect, :variable)

    # One channel's frozen baseline surface (mirrors Go/Rust ChannelSpec byte-for-byte).
    ChannelSpec = Struct.new(:id, :name, :kinds, :states, :transitions, :errors)

    k = lambda { |code, name, effect, variable| KindSpec.new(code, name, effect, variable) }
    cs = lambda { |id, name, kinds, states, transitions, errors| ChannelSpec.new(id, name, kinds, states, transitions, errors) }

    # The frozen twenty-channel baseline registry (design-channels.md §1..§20), transcribed
    # directly from the shared independent per-channel oracle vectors/channels/<name>/cases.json
    # (== Go == Rust). transitions is an array of [from, to] pairs.
    TABLE = [
      cs.(0x0000, "Control", [k.(0, "Hello", RO, false), k.(1, "Bye", IW, false), k.(2, "Ack", RO, false), k.(3, "Error", RO, false)],
          ["open", "closing"], [["open", "closing"]], ["UnknownKind", "ProfileMismatch"]),
      cs.(0x0001, "Memory", [k.(0, "MemoryOffer", IW, false), k.(1, "MemoryAccept", IW, false), k.(2, "MemoryWrite", NIW, false), k.(3, "MemoryRead", RO, false), k.(4, "MemoryExpire", DE, false), k.(5, "MemoryRevoke", DE, false)],
          ["offered", "accepted", "live", "expired", "revoked"], [["offered", "accepted"], ["accepted", "live"], ["live", "expired"], ["live", "revoked"]], ["AccessDenied", "MemoryError"]),
      cs.(0x0002, "Capability", [k.(0, "CapIssue", NIW, false), k.(1, "CapDelegate", NIW, false), k.(2, "CapRevoke", DE, false), k.(3, "CapLookup", RO, false)],
          ["issued", "delegated", "revoked", "expired"], [["issued", "delegated"], ["delegated", "delegated"], ["issued", "revoked"], ["delegated", "revoked"], ["issued", "expired"], ["delegated", "expired"]], ["CapExceedsParent", "CapRevoked"]),
      cs.(0x0003, "Identity", [k.(0, "Rotation", NIW, false), k.(1, "Revocation", DE, false), k.(2, "ForeignLink", IW, false), k.(3, "KeyAnnounce", RO, false)],
          ["active", "rotated", "revoked"], [["active", "rotated"], ["rotated", "rotated"], ["active", "revoked"], ["rotated", "revoked"]], ["RotationUnauthorized", "KeyRevoked", "SignerMismatch"]),
      cs.(0x0004, "Governance", [k.(0, "PolicyPublish", NIW, false), k.(1, "Approval", NIW, false), k.(2, "ApprovalHeld", RO, false), k.(3, "Consume", NIW, false), k.(4, "GatewayDecision", NIW, false), k.(5, "DecisionRecord", NIW, false), k.(6, "EgressAttestation", NIW, false), k.(7, "HazardAuthorization", NIW, false)],
          ["requested", "held", "approved", "consumed", "expired"], [["requested", "held"], ["requested", "approved"], ["approved", "consumed"], ["held", "approved"], ["requested", "expired"], ["approved", "expired"]], ["ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"]),
      cs.(0x0005, "Immune", [k.(0, "AnomalyReport", RO, false), k.(1, "Quarantine", DE, false), k.(2, "QuarantineLift", NIW, false)],
          ["normal", "quarantined", "lifted", "permanent"], [["normal", "quarantined"], ["quarantined", "lifted"], ["quarantined", "permanent"]], ["AccessDenied"]),
      cs.(0x0006, "Federation", [k.(0, "AuthorityAnnounce", RO, false), k.(1, "ScopeReceipt", NIW, false)],
          ["announced", "ordering"], [["announced", "ordering"]], ["AuthorityUnknown", "ScopeOverlapConflict"]),
      cs.(0x0007, "Settlement", [k.(0, "SettleIntent", NIW, false), k.(1, "SettleReceipt", NIW, false), k.(2, "SettleReject", IW, false), k.(3, "PaymentImport", NIW, false), k.(4, "PaymentChargeBinding", NIW, false)],
          ["intent", "receipt", "reject"], [["intent", "receipt"], ["intent", "reject"]], ["ValueMismatch", "SettleExpired"]),
      cs.(0x0008, "Compliance", [k.(0, "ComplianceRecord", NIW, false), k.(1, "ComplianceQuery", RO, false), k.(2, "ComplianceReport", RO, false)],
          ["appended"], [], ["RecordUnsigned", "JurisdictionUnknown"]),
      cs.(0x0009, "Sensory", [k.(0, "Observation", RO, false), k.(1, "Subscribe", IW, false), k.(2, "Unsubscribe", IW, false)],
          ["active", "cancelled"], [["active", "cancelled"]], ["SubscriptionUnknown"]),
      cs.(0x000A, "Telemetry", [k.(0, "Metric", RO, false), k.(1, "HealthReport", RO, false)],
          ["stateless"], [], ["MetricMalformed"]),
      cs.(0x000B, "Audit", [k.(0, "Receipt", NIW, false), k.(1, "AuditQuery", RO, false), k.(2, "ForkProof", RO, false), k.(3, "CheckpointRoot", NIW, false), k.(4, "WitnessCosign", NIW, false), k.(5, "InclusionProof", RO, false)],
          ["appended"], [], ["ChainBroken", "Equivocation", "ReceiptUnsigned"]),
      cs.(0x000C, "Stream", [k.(0, "StreamOpen", RO, true), k.(1, "StreamCommit", RO, false), k.(2, "StreamCheckpoint", RO, false)],
          ["open", "committed"], [["open", "committed"]], ["StreamDigestMismatch", "FlowControlError"]),
      cs.(0x000D, "Bridge", [k.(0, "Carriage", RO, true)],
          ["carried"], [], ["EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"]),
      cs.(0x000E, "Commerce", [k.(0, "Offer", RO, false), k.(1, "Order", NIW, false), k.(2, "Fulfil", NIW, false), k.(3, "Cancel", DE, false)],
          ["offer", "order", "fulfil", "cancel"], [["offer", "order"], ["order", "fulfil"], ["order", "cancel"]], ["OfferExpired", "ApprovalRequired", "OrderMismatch"]),
      cs.(0x000F, "Interaction", [k.(0, "Elicit", RO, false), k.(1, "Respond", IW, false), k.(2, "Confirm", NIW, false), k.(3, "UiEvent", NIW, false)],
          ["elicit", "respond", "confirm", "timeout"], [["elicit", "respond"], ["elicit", "confirm"], ["elicit", "timeout"]], ["InteractionTimeout", "ElicitUnauthorized"]),
      cs.(0x0010, "Discovery", [k.(0, "DiscoveryRecord", RO, false), k.(1, "DiscoveryQuery", RO, false)],
          ["fresh", "stale"], [["fresh", "stale"]], ["RecordExpired", "TrustAnchorUnknown"]),
      cs.(0x0011, "Workflow", [k.(0, "TaskCreate", NIW, false), k.(1, "TaskInput", NIW, false), k.(2, "TaskCancel", DE, false), k.(3, "TaskResult", NIW, false)],
          ["created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"],
          [["created", "awaiting-input"], ["created", "awaiting-approval"], ["awaiting-input", "running"], ["awaiting-approval", "running"], ["running", "result"], ["created", "cancelled"], ["awaiting-input", "cancelled"], ["awaiting-approval", "cancelled"], ["running", "cancelled"]],
          ["TaskStateError", "InputGateBypass", "ApprovalRequired"]),
      cs.(0x0012, "Knowledge", [k.(0, "Assert", NIW, false), k.(1, "Retract", DE, false), k.(2, "KnowledgeQuery", RO, false)],
          ["asserted", "retracted"], [["asserted", "retracted"]], ["FactUnsigned", "RetractUnknown"]),
      cs.(0x0013, "Spatial", [k.(0, "FrameDefine", IW, false), k.(1, "Pose", RO, false), k.(2, "StateUpdate", RO, false), k.(3, "SnapshotQuery", RO, false)],
          ["defined", "observed"], [["defined", "observed"]], ["FrameUnknown", "TransformCycle"]),
    ].freeze

    # Index of TABLE by channel id, built once at load time.
    BY_ID = TABLE.each_with_object({}) { |c, h| h[c.id] = c }.freeze

    class UnknownKind < StandardError
      def kind; "UnknownKind"; end
    end
    class EffectDeclarationMismatch < StandardError
      def kind; "EffectDeclarationMismatch"; end
    end
    # Spatial's TransformCycle (design-channels.md §20): the coordinate-frame child->parent links
    # do not form a tree (a cycle was found).
    class TransformCycle < StandardError
      def kind; "TransformCycle"; end
    end
    # A Workflow task reached "running" without passing its input/approval gate (design-channels.md
    # §18). FAIL-CLOSED, SECURITY-CRITICAL: a task may not execute on input that was never
    # supplied/authorized, and this holds across a crash (close -> reopen with no input supplied).
    class InputGateBypass < StandardError
      def kind; "InputGateBypass"; end
    end
    # A Workflow gate state transition not permitted (re-creating a known task, or acting on an
    # unknown one) -- distinct from InputGateBypass, which is specifically the gate-skip violation.
    class TaskStateError < StandardError
      def kind; "TaskStateError"; end
    end
    # The WorkflowGate's on-disk WAL is not well-formed (a length-prefixed record with no NUL
    # task/status separator).
    class MalformedGateRecord < StandardError
      def kind; "Malformed"; end
    end

    module_function

    # Return [name, effect, variable] for a (channel, kind), or raise UnknownKind.
    def lookup(channel, kind)
      c = BY_ID[channel]
      raise UnknownKind, format("channel 0x%04x not registered", channel) if c.nil?
      c.kinds.each do |ks|
        return [ks.name, ks.effect, ks.variable] if ks.code == kind
      end
      raise UnknownKind, format("kind %d not in channel 0x%04x", kind, channel)
    end

    # A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3.
    def check_effect(channel, kind, effect)
      _name, declared, variable = lookup(channel, kind)
      if variable
        raise EffectDeclarationMismatch, "effect #{effect} out of range" if effect > DE
        return nil
      end
      unless effect == declared
        raise EffectDeclarationMismatch, "object effect #{effect} != declared #{declared}"
      end
      nil
    end

    # Channel returns the frozen ChannelSpec for a channel id, or nil if unregistered (mirrors Go
    # channels.Channel(id) / Rust channels::channel(id)).
    def channel(id)
      BY_ID[id]
    end

    # AllowedTransition reports whether `channel` permits a state transition from -> to. An
    # unregistered channel permits nothing.
    def allowed_transition(channel, from, to)
      c = BY_ID[channel]
      return false if c.nil?
      c.transitions.any? { |f, t| f == from && t == to }
    end

    # CheckFrameTree enforces Spatial's TransformCycle (design-channels.md §20): the
    # coordinate-frame child->parent links must form a tree (acyclic). A frame mapping to "" (or
    # absent from `parent` entirely) is a root.
    def check_frame_tree(parent)
      white, gray, black = 0, 1, 2
      color = Hash.new(white)
      visit = nil
      visit = lambda do |f|
        color[f] = gray
        p = parent[f]
        if p && !p.empty?
          case color[p]
          when gray
            return true
          when white
            return true if visit.call(p)
          end
        end
        color[f] = black
        false
      end
      parent.each_key do |f|
        if color[f] == white && visit.call(f)
          raise TransformCycle, "coordinate frame tree contains a cycle"
        end
      end
      nil
    end

    # ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot
    # occur.

    # WorkflowGate is a durable, WAL-backed task-status tracker (mirrors Go/Rust byte-for-byte). A
    # task's status is persisted (written + fsynced) before it is acknowledged (spine §9.2), so a
    # crash recovers to the last durable status and can NEVER bypass the input/approval gate:
    # reaching "running" requires an explicit input/approval step a crash cannot manufacture.
    class WorkflowGate
      def initialize(file, status)
        @lock = Mutex.new
        @f = file
        @status = status
      end

      # Read the WAL from the start, rebuilding the in-memory status map. Each record is
      # length-prefixed (uint32 big-endian) so the log is self-framing.
      def replay
        @f.seek(0, IO::SEEK_SET)
        loop do
          lb = @f.read(4)
          break if lb.nil? || lb.bytesize < 4
          n = lb.unpack1("N")
          rec = @f.read(n)
          raise MalformedGateRecord, "workflow gate record" if rec.nil? || rec.bytesize != n
          nul = rec.index(0.chr)
          raise MalformedGateRecord, "workflow gate record" if nul.nil?
          task = rec[0...nul]
          st = rec[(nul + 1)..]
          @status[task] = st
        end
        self
      end

      def persist(task, status)
        rec = (task.to_s.b + "\x00".b + status.b)
        framed = [rec.bytesize].pack("N") + rec
        @f.seek(0, IO::SEEK_END)
        @f.write(framed)
        @f.flush
        @f.fsync # persist-before-ack (spine §9.2)
        @status[task] = status
        nil
      end
      private :persist

      # Create records a new task in a non-terminal pre-gate status. TaskCreate never lands in
      # "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before
      # returning.
      def create(task, needs_approval)
        @lock.synchronize do
          raise TaskStateError, "task already known" if @status.key?(task)
          persist(task, needs_approval ? "awaiting-approval" : "awaiting-input")
        end
      end

      # SupplyInput advances a task past its input gate (awaiting-input -> input-supplied) or
      # approval gate (awaiting-approval -> approved). Only these transitions may precede Run.
      def supply_input(task)
        @lock.synchronize do
          case @status[task]
          when "awaiting-input"
            persist(task, "input-supplied")
          when "awaiting-approval"
            persist(task, "approved")
          else
            raise TaskStateError, "task not awaiting input/approval"
          end
        end
      end

      # Run moves a task to "running" only if it has passed the gate. A task still
      # "awaiting-input" or "awaiting-approval" (or unknown) cannot run: that is InputGateBypass,
      # and it is forbidden.
      def run(task)
        @lock.synchronize do
          case @status[task]
          when "input-supplied", "approved"
            persist(task, "running")
          when "awaiting-input", "awaiting-approval"
            raise InputGateBypass, "a task reached running without passing the input/approval gate"
          else
            raise TaskStateError, "unknown task"
          end
        end
      end

      # Status returns a task's durable status, or nil if the task is unknown.
      def status(task)
        @lock.synchronize { @status[task] }
      end

      # Close flushes and closes the WAL.
      def close
        @lock.synchronize { @f.close }
      end
    end

    # OpenWorkflowGate opens (creating if needed) a WAL-backed gate and replays it (mirrors Go
    # channels.OpenWorkflowGate / Rust channels::open_workflow_gate).
    def open_workflow_gate(path)
      f = File.open(path, File::RDWR | File::CREAT | File::BINARY, 0o600)
      g = WorkflowGate.new(f, {})
      begin
        g.replay
      rescue Exception
        g.close
        raise
      end
      g
    end
  end
end
