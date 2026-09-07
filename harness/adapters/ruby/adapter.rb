# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# naalp-adapter-ruby — the Ruby N-AALP conformance adapter.
#
# Wraps the impl/ruby `Naalp` SDK behind the length-prefixed JSON op protocol the naalp-conform
# runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON {"op","in"}
# request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on stdout, flushed
# after each. The platform OpenSSL (>= 3.5) supplies deterministic ML-DSA and Ed25519, so this
# adapter implements every op including the crypto leg.
require 'json'
require 'tempfile'

# make the impl/ruby SDK requireable regardless of cwd (gem layout: lib/ is the require root)
_here = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(_here, "..", "..", "..", "impl", "ruby", "lib"))
require 'naalp'

CBOR = Naalp::CBOR
COSE = Naalp::COSE
Envelope = Naalp::Envelope
Identity = Naalp::Identity
Policy = Naalp::Policy
Records = Naalp::Records
Graph = Naalp::Graph
Channels = Naalp::Channels
Delivery = Naalp::Delivery
Federation = Naalp::Federation

# Convert a language-neutral tagged value [tag, payload] into a CBOR value.
def tagged(v)
  raise "tagged value must be [tag, payload]" unless v.is_a?(Array) && v.length == 2
  tag, p = v
  case tag
  when "u"   then CBOR::U.new(Integer(p))
  when "b"   then CBOR::B.new([p].pack("H*"))
  when "s"   then CBOR::T.new(p.to_s)
  when "arr" then CBOR::A.new(p.map { |i| tagged(i) })
  when "map" then CBOR::M.new(p.map { |k, val| [tagged(k), tagged(val)] })
  else raise "unknown tag #{tag.inspect}"
  end
end

def u(inp, k)
  v = inp[k]
  return 0 if v.nil?
  return v.to_i if v.is_a?(String)
  Integer(v)
end

def hx(inp, k)
  [inp[k]].pack("H*")
end

def hexout(bytes)
  bytes.unpack1("H*")
end

def err(e)
  kind = e.respond_to?(:kind) ? e.kind : e.class.name
  { "error" => "#{kind}: #{e.message}" }
end

# Federation::CausalNode list from the corpus's language-neutral {id_hex, causes_hex, position}
# nodes (shared by reconcile.state's "linearize" and "verify" events). Position is not part of
# Federation::CausalNode -- reconcile()'s tie-break is content id, never position.
def federation_nodes_from(inp)
  (inp["nodes"] || []).map do |n|
    causes = (n["causes_hex"] || []).map { |c| [c].pack("H*") }
    Federation::CausalNode.new([n["id_hex"]].pack("H*"), causes)
  end
end

# Deterministic ML-DSA needs OpenSSL >= 3.5 (this box has 3.6.x). Where it is absent (e.g. a CI
# runner on OpenSSL 3.0), the three ML-DSA ops return an honest {skipped} instead of crashing, so
# the runner reports them Unimplemented (never a false red); the pure ops + Ed25519 still grade.
$MLDSA_OK = nil
def mldsa_available?
  return $MLDSA_OK unless $MLDSA_OK.nil?
  $MLDSA_OK = begin
    COSE.mldsa_keygen("ML-DSA-65", ("\x00" * 32).b)
    true
  rescue Exception
    false
  end
end

def handle(op, inp)
  case op
  when "sha384"
    { "out" => { "digest_hex" => OpenSSL::Digest::SHA384.hexdigest(hx(inp, "msg_hex")) } }
  when "cbor.encode"
    { "out" => { "bytes_hex" => hexout(CBOR.encode(tagged(inp["value"]))) } }
  when "cbor.decode"
    begin
      CBOR.decode(hx(inp, "bytes_hex"))
      { "out" => { "ok" => true } }
    rescue => e
      err(e)
    end
  when "content.id"
    v = CBOR.decode(hx(inp, "body_hex"))
    { "out" => { "id_hex" => hexout(CBOR.content_id(v)) } }
  when "cose.tbs"
    { "out" => { "tobesigned_hex" => hexout(COSE.to_be_signed_raw(hx(inp, "protected_hex"), hx(inp, "payload_hex"))) } }
  when "mldsa.keygen"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    { "out" => { "pk_hex" => hexout(COSE.mldsa_keygen(inp.fetch("param", "ML-DSA-65"), hx(inp, "seed_hex"))) } }
  when "ed25519.sign"
    { "out" => { "sig_hex" => hexout(COSE.ed25519_sign(hx(inp, "sk_hex"), hx(inp, "msg_hex"))) } }
  when "cose.sign1"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    obj = COSE.cose_sign1(Integer(inp["alg"]), hx(inp, "seed_hex"), hx(inp, "protected_hex"), hx(inp, "payload_hex"))
    { "out" => { "obj_hex" => hexout(obj) } }
  when "cose.verify1"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    { "out" => { "valid" => COSE.cose_verify1(Integer(inp["alg"]), hx(inp, "pubkey_hex"), hx(inp, "obj_hex")) } }
  when "rotation.leg_tbs"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    { "out" => { "tbs_hex" => hexout(COSE.signature_to_be_signed(hx(inp, "body_protected_hex"), Integer(inp["leg_alg"]), hx(inp, "payload_hex"))) } }
  when "rotation.sign"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    prot = hx(inp, "protected_hex")
    payload = hx(inp, "payload_hex")
    old_leg = COSE.signature_leg(prot, Integer(inp["old_alg"]), hx(inp, "old_seed_hex"), payload)
    new_leg = COSE.signature_leg(prot, Integer(inp["new_alg"]), hx(inp, "new_seed_hex"), payload)
    { "out" => { "obj_hex" => hexout(COSE.assemble_sign_raw(prot, payload, [old_leg, new_leg])) } }
  when "rotation.verify"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    obj = hx(inp, "obj_hex")
    old_alg = Integer(inp["old_alg"])
    new_alg = Integer(inp["new_alg"])
    profile = Integer(inp["profile"])
    old_pk = hx(inp, "old_pubkey_hex")
    new_pk = hx(inp, "new_pubkey_hex")
    kind_ok = ->(ch, k) { ch == 3 && k == 0 }
    # dispatch by COSE tag: tag-98 (0xd8 0x62) -> two-leg verify_rotation_object; a tag-18
    # single-sig object -> the general verify, which rejects a (3,0) single-sig rotation.
    begin
      if obj.bytesize >= 2 && obj.getbyte(0) == 0xd8 && obj.getbyte(1) == 0x62
        Envelope.verify_rotation_object(profile, old_alg, old_pk, new_alg, new_pk, kind_ok, obj)
      else
        Envelope.verify(profile, new_alg, new_pk, kind_ok, obj)
      end
      { "out" => { "valid" => true, "error" => "" } }
    rescue => e
      { "out" => { "valid" => false, "error" => (e.respond_to?(:kind) ? e.kind : "Malformed") } }
    end
  when "signerid"
    begin
      { "out" => { "signer_id" => Identity.signer_id(Integer(inp["alg"]), hx(inp, "pubkey_hex")) } }
    rescue => e
      err(e)
    end
  when "nfc.check"
    begin
      s = hx(inp, "utf8_hex").force_encoding(Encoding::UTF_8)
      Identity.require_nfc(s)
      { "out" => { "ok" => true } }
    rescue => e
      err(e)
    end
  when "effect.normalize"
    { "out" => { "effect" => Policy.normalize_effect(u(inp, "value")) } }
  when "effect.authorize"
    { "out" => { "allow" => Policy.authorizes(Policy.normalize_effect(u(inp, "granted")), u(inp, "effect")) } }
  when "effect.safety_label"
    { "out" => { "cbor_hex" => hexout(Policy.safety_label_bytes(inp.fetch("risk", ""), inp.fetch("scope", ""))) } }
  when "approval.body"
    { "out" => { "body_hex" => hexout(Records.approval_body(hx(inp, "approves_hex"), inp.fetch("approver", ""), u(inp, "grant"), hx(inp, "nonce_hex"), u(inp, "not_after"))) } }
  when "approval.id"
    { "out" => { "id_hex" => hexout(Records.approval_id(hx(inp, "approves_hex"), inp.fetch("approver", ""), u(inp, "grant"), hx(inp, "nonce_hex"), u(inp, "not_after"))) } }
  when "ledger.entry"
    { "out" => { "body_hex" => hexout(Records.ledger_entry(u(inp, "seq"), hx(inp, "prev_hex"), hx(inp, "approval_id_hex"), inp.fetch("by", ""))) } }
  when "receipt.body"
    { "out" => { "body_hex" => hexout(Records.receipt_body(hx(inp, "prev_hex"), hx(inp, "obj_hex"), u(inp, "seq"), u(inp, "at"))) } }
  when "receipt.head"
    { "out" => { "head_hex" => hexout(Records.receipt_head(hx(inp, "body_hex"))) } }
  when "causal.verify"
    nodes = inp["nodes"].map do |n|
      [[n["id_hex"]].pack("H*"), (n["causes_hex"] || []).map { |c| [c].pack("H*") }, Integer(n.fetch("position", 0))]
    end
    begin
      Graph.verify_causal(nodes)
      { "out" => { "valid" => true } }
    rescue => e
      err(e)
    end
  when "delivery.update"
    { "out" => { "body_hex" => hexout(Records.delivery_update(hx(inp, "obj_hex"), u(inp, "stage"), u(inp, "at"))) } }
  when "delivery.state"
    # ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object through an
    # ordered `events` list of signed delivery updates on a fresh WAL-backed Tracker; report the LAST
    # event's outcome plus the object's final stage name. A rejected event (regress ->
    # StageOutOfOrder) leaves the recorded stage unchanged.
    # Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
    raw_events = inp["events"] || []
    tf = Tempfile.new(["naalp-delivery-state-", ".wal"])
    path = tf.path
    tf.close
    tr = Delivery.open_tracker(path)
    last_err = nil
    last_obj = "".b
    begin
      raw_events.each do |em|
        obj = hx(em, "obj_hex")
        last_obj = obj
        last_err = nil
        case em["ev"]
        when "update"
          begin
            tr.advance(obj, u(em, "stage"), 0)
          rescue Delivery::DeliveryError => e
            last_err = e
          end
        else
          return { "error" => "delivery.state: unknown event #{em["ev"].inspect}" }
        end
      end
      st, _found = tr.stage(last_obj)
      {
        "out" => {
          "valid" => last_err.nil?,
          "error" => (last_err.nil? ? "" : last_err.kind),
          "state" => Delivery.stage_name(st),
        },
      }
    ensure
      tr.close
      File.delete(path) if File.exist?(path)
    end
  when "approval.state"
    # ietf draft "## Approval state machine" (# Object State Machines): build ONE signed approval,
    # then drive it through an ordered `events` list of consume attempts through the REAL composed
    # choke point Naalp::Approval.consume_approval on a fresh single-use ledger; report the LAST
    # event's {valid, error} plus the ledger length after it (the draft's "ledger left untouched by
    # a rejected request", observable via Ledger#count). Graded against the independent,
    # non-circular tools/approval_state_oracle.py (F3). The approver key is a deterministic Ed25519
    # test key -- the signature is verified inside this port, NOT graded across ports (ruby skips
    # deterministic ML-DSA on OpenSSL < 3.5, so this op uses Ed25519 rather than the base ML-DSA
    # convention the other approval ops use).
    am = inp["approval"]
    return { "error" => "approval.state: missing approval object" } unless am.is_a?(Hash)
    a = Naalp::Approval::ApprovalRecord.new(
      hx(am, "approves_hex"), am.fetch("approver", ""), u(am, "grant"), hx(am, "nonce_hex"), u(am, "not_after"), nil
    )
    seed = ("\x00" * 32).b # deterministic all-zero test approver seed
    pubkey = OpenSSL::PKey.new_raw_private_key("ED25519", seed).raw_public_key
    sig = COSE.ed25519_sign(seed, a.bytes)

    tf = Tempfile.new(["naalp-approval-state-", ".wal"])
    path = tf.path
    tf.close
    ledger = Naalp::Approval.open_ledger(path)
    last_err = nil
    begin
      (inp["events"] || []).each do |em|
        case em["ev"]
        when "consume"
          begin
            Naalp::Approval.consume_approval(
              a, COSE::ALG_ED25519, pubkey, sig, hx(em, "present_cid_hex"),
              u(em, "pos_time"), u(em, "required_effect"), ledger, em.fetch("by", "")
            )
            last_err = nil
          rescue Naalp::Approval::ApprovalError => e
            last_err = e
          end
        else
          return { "error" => "approval.state: unknown event #{em["ev"].inspect}" }
        end
      end
      {
        "out" => {
          "valid" => last_err.nil?,
          "error" => (last_err.nil? ? "" : last_err.kind),
          "ledger_len" => ledger.count,
        },
      }
    ensure
      ledger.close
      File.delete(path) if File.exist?(path)
    end
  when "reconcile.state"
    # ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine through
    # ONE event (add-chain | linearize | verify) on fresh state and report {valid, error}. add-chain
    # runs the draft's fixed VerifyChain-then-Observe pipeline (a `chain` that must independently
    # pass VerifyChain, plus an optional `extra` receipt fed only to Observe -- a chain array cannot
    # itself carry a duplicate seq without independently tripping ChainBroken, so equivocation is
    # exercised via the separate `extra` observation); linearize runs Federation.reconcile (which
    # calls Graph.verify_causal internally); verify runs Federation.verify_reconcile_order, which
    # MUST recompute via reconcile (content-id tie-break), never Audit.topo_order (position
    # tie-break). Graded against the independent, non-circular tools/reconcile_state_oracle.py (F3).
    # The authority key is a deterministic all-zero-seed ML-DSA-65 test key -- the signature is
    # verified, not graded (bytes are not compared across ports for this op).
    case inp["event"]
    when "add-chain"
      return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
      seed = ("\x00" * 32).b # deterministic all-zero test authority seed
      alg = COSE::ALG_MLDSA65
      pubkey = COSE.mldsa_keygen("ML-DSA-65", seed)
      build_receipt = lambda do |rm|
        Naalp::Audit::Receipt.new(hx(rm, "prev_hex"), hx(rm, "obj_hex"), u(rm, "seq"), u(rm, "at"))
      end
      raw_chain = inp["chain"] || []
      receipts = raw_chain.map { |rm| build_receipt.call(rm) }
      sigs = receipts.map { |r| COSE.mldsa_sign(alg, seed, r.bytes) }
      if inp["corrupt_sig_at"]
        idx = Integer(inp["corrupt_sig_at"])
        bad = sigs[idx].dup
        bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 0xFF)
        sigs[idx] = bad
      end
      err_kind = nil
      begin
        Naalp::Audit.verify_chain(receipts, sigs, alg, pubkey)
        auditor = Naalp::Audit::Auditor.new(alg, pubkey, pubkey)
        receipts.each_with_index do |r, i|
          fp = auditor.observe(r, sigs[i])
          if fp
            err_kind = "Equivocation"
            break
          end
        end
        if err_kind.nil? && inp["extra"].is_a?(Hash)
          er = build_receipt.call(inp["extra"])
          esig = COSE.mldsa_sign(alg, seed, er.bytes)
          fp = auditor.observe(er, esig)
          err_kind = "Equivocation" if fp
        end
      rescue Naalp::Audit::AuditError => e
        err_kind = e.kind
      end
      { "out" => { "valid" => err_kind.nil?, "error" => (err_kind || "") } }
    when "linearize"
      nodes = federation_nodes_from(inp)
      begin
        Federation.reconcile(nodes)
        { "out" => { "valid" => true, "error" => "" } }
      rescue => e
        { "out" => { "valid" => false, "error" => (e.respond_to?(:kind) ? e.kind : e.class.name) } }
      end
    when "verify"
      nodes = federation_nodes_from(inp)
      order = (inp["claimed_order_hex"] || []).map { |h| [h].pack("H*") }
      rec = Federation::ReconcileRecord.new([], order)
      begin
        Federation.verify_reconcile_order(rec, nodes)
        { "out" => { "valid" => true, "error" => "" } }
      rescue => e
        { "out" => { "valid" => false, "error" => (e.respond_to?(:kind) ? e.kind : e.class.name) } }
      end
    else
      { "error" => "reconcile.state: unknown event #{inp["event"].inspect}" }
    end
  when "stream.digest"
    chunks = inp["chunks"].map { |c| [Integer(c["offset"]), [c["data_hex"]].pack("H*")] }
    { "out" => { "digest_hex" => hexout(Records.stream_digest(chunks)) } }
  when "stream.open"
    approval = (inp["approval_hex"] && !inp["approval_hex"].empty?) ? [inp["approval_hex"]].pack("H*") : "".b
    { "out" => { "body_hex" => hexout(Records.stream_open_body(hx(inp, "stream_id_hex"), u(inp, "effect"), approval, u(inp, "substream"))) } }
  when "stream.commit"
    { "out" => { "body_hex" => hexout(Records.stream_commit_body(hx(inp, "stream_id_hex"), hx(inp, "digest_hex"))) } }
  when "stream.checkpoint"
    { "out" => { "body_hex" => hexout(Records.stream_checkpoint_body(hx(inp, "stream_id_hex"), u(inp, "through_offset"), hx(inp, "digest_so_far_hex"))) } }
  when "stream.state"
    # design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream through an
    # ordered `events` list on a fresh Guard; report the LAST event's outcome plus the stream's final
    # state. Graded against the independent, non-circular tools/streamstate_oracle.py (F3).
    raw_events = inp["events"] || []
    g = Naalp::Streaming::Guard.new
    last_kind = nil
    last_stream = "".b
    raw_events.each do |em|
      sid = hx(em, "stream_hex")
      last_stream = sid
      last_kind = nil
      begin
        case em["ev"]
        when "open"
          o = Naalp::Streaming::StreamOpen.new(sid, u(em, "effect"), nil, 0)
          g.open(o, u(em, "granted"))
        when "chunk"
          g.chunk(sid)
        when "checkpoint"
          g.checkpoint(sid)
        when "commit"
          chunks = (em["chunks"] || []).map { |c| Naalp::Streaming::Chunk.new(u(c, "offset"), [c["data_hex"]].pack("H*")) }
          digest = hx(em, "digest_hex")
          g.commit(Naalp::Streaming::StreamCommit.new(sid, digest), chunks)
        when "expire"
          g.expire(sid)
        else
          return { "error" => "stream.state: unknown event #{em["ev"].inspect}" }
        end
      rescue Naalp::Streaming::StreamError => e
        last_kind = e.kind
      end
    end
    {
      "out" => {
        "valid" => last_kind.nil?,
        "error" => (last_kind || ""),
        "state" => Naalp::Streaming.state_name(g.state(last_stream)),
      },
    }
  when "transport.emit"
    begin
      { "out" => { "result" => Records.transport_emit(inp.fetch("transport", ""), !!inp["sensitive"], !!inp["require_peer_auth"]) } }
    rescue => e
      err(e)
    end
  when "carriage.body"
    begin
      body = Records.carriage_body(u(inp, "protocol_id"), u(inp, "class"), u(inp, "content_type"),
                                   hx(inp, "correlation_hex"), inp.fetch("method", ""), hx(inp, "foreign_hex"))
      { "out" => { "body_hex" => hexout(body) } }
    rescue => e
      err(e)
    end
  when "channels.lookup"
    begin
      name, effect, variable = Channels.lookup(u(inp, "channel"), u(inp, "kind"))
      { "out" => { "name" => name, "effect" => effect, "variable" => variable } }
    rescue => e
      err(e)
    end
  when "channels.effect_check"
    begin
      Channels.check_effect(u(inp, "channel"), u(inp, "kind"), u(inp, "effect"))
      { "out" => { "ok" => true } }
    rescue => e
      err(e)
    end
  when "federation.reconcile"
    nodes = inp["nodes"].map do |n|
      [[n["id_hex"]].pack("H*"), (n["causes_hex"] || []).map { |c| [c].pack("H*") }, Integer(n.fetch("position", 0))]
    end
    begin
      order = Graph.reconcile(nodes)
      { "out" => { "order" => order.map { |o| hexout(o) } } }
    rescue => e
      err(e)
    end
  when "federation.record"
    order = (inp["order"] || []).map { |o| [o].pack("H*") }
    { "out" => { "body_hex" => hexout(Graph.reconcile_record(inp.fetch("authorities", []), order)) } }
  # ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
  when "composite.mprime"
    { "out" => { "mprime_hex" => hexout(COSE.compute_mprime("COMPSIG-MLDSA65-Ed25519-SHA512".b, "".b, hx(inp, "m_hex"))) } }
  when "composite.signerid"
    begin
      { "out" => { "signer_id" => Identity.composite_signer_id(Integer(inp["mldsa_alg"]), hx(inp, "mldsa_pubkey_hex"), hx(inp, "ed_pubkey_hex")) } }
    rescue => e
      err(e)
    end
  when "composite.sign"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    { "out" => { "value_hex" => hexout(COSE.composite_sign(hx(inp, "mldsa_seed_hex"), hx(inp, "ed_seed_hex"), hx(inp, "tbs_hex"))) } }
  when "composite.verify"
    return { "skipped" => "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" } unless mldsa_available?
    { "out" => { "valid" => COSE.composite_verify(hx(inp, "mldsa_pubkey_hex"), hx(inp, "ed_pubkey_hex"), hx(inp, "m_hex"), hx(inp, "sig_hex")) } }
  # ---- R7 decoder resource bounds: decode + bound-enforce an untrusted object; all four
  # object-level bounds fire BEFORE the COSE signature is checked, so no verifier is ever
  # reached for a reject -- kind_ok is fully permissive and pubkey/alg are dummies. over_size
  # materializes the octet-size bound (rejected on raw length before any parse). ----
  when "object.decode"
    begin
      obj = inp.key?("over_size") ? ("\x00".b * Integer(inp["over_size"])) : hx(inp, "obj_hex")
      kind_ok = ->(ch, k) { true }
      Envelope.verify(1, 0, "".b, kind_ok, obj)
      { "out" => { "valid" => true, "error" => "" } }
    rescue => e
      { "out" => { "valid" => false, "error" => (e.respond_to?(:kind) ? e.kind : "Malformed") } }
    end
  when "stream.verify_commit"
    begin
      n = Integer(inp["chunk_count"])
      chunks = Array.new(n) { Naalp::Streaming::Chunk.new(0, "".b) } # n empty chunks
      commit = Naalp::Streaming::StreamCommit.new("".b, "".b)
      Naalp::Streaming.verify_commit(commit, chunks) # count check fires before digest
      { "out" => { "valid" => true, "error" => "" } }
    rescue => e
      { "out" => { "valid" => false, "error" => (e.respond_to?(:kind) ? e.kind : "Malformed") } }
    end
  when "error.name_for_code"
    # T3.3: the naalp-error registry table lookup (design.md §3.5). Grades the port's embedded
    # 119-entry name<->code table per-code, plus the unknown-code (opaque) contract.
    name, registered = Naalp::Naalperror.name_for_code(u(inp, "code"))
    { "out" => { "name" => name, "registered" => registered } }
  when "error.encode"
    # T3.3: deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail, ?4:subject}.
    subj = inp.key?("subject_hex") ? hx(inp, "subject_hex") : nil
    detail = inp.fetch("detail", "")
    name = inp.fetch("name", "")
    begin
      b = Naalp::Naalperror.encode(u(inp, "code"), name, detail, subj)
      { "out" => { "body_hex" => hexout(b) } }
    rescue => e
      err(e)
    end
  when "error.decode"
    # T3.3: parse + dual-carriage validate a naalp-error body (registered code + wrong name ->
    # Malformed; unknown code -> opaque accept).
    begin
      o = Naalp::Naalperror.decode(hx(inp, "body_hex"))
      { "out" => { "valid" => true, "code" => o.code, "name" => o.name } }
    rescue Naalp::Naalperror::Error => e
      { "out" => { "valid" => false, "error" => e.kind } }
    end
  else
    { "skipped" => "op not implemented: #{op}" }
  end
end

def main
  stdin = STDIN
  stdout = STDOUT
  stdin.binmode
  stdout.binmode
  loop do
    lp = stdin.read(4)
    break if lp.nil? || lp.bytesize < 4
    n = lp.unpack1("V")
    body = n.zero? ? "".b : stdin.read(n)
    break if body.nil? || body.bytesize < n
    begin
      req = JSON.parse(body.force_encoding(Encoding::UTF_8))
      resp = handle(req["op"] || "", req["in"] || {})
    rescue => e
      resp = { "error" => "adapter exception: #{e.class}: #{e.message}" }
    end
    ob = JSON.generate(resp).force_encoding(Encoding::BINARY)
    stdout.write([ob.bytesize].pack("V"))
    stdout.write(ob)
    stdout.flush
  end
end

main if __FILE__ == $PROGRAM_NAME
