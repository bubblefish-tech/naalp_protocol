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

# make the impl/ruby SDK requireable regardless of cwd (gem layout: lib/ is the require root)
_here = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(_here, "..", "..", "..", "impl", "ruby", "lib"))
require 'naalp'

CBOR = Naalp::CBOR
COSE = Naalp::COSE
Identity = Naalp::Identity
Policy = Naalp::Policy
Records = Naalp::Records
Graph = Naalp::Graph
Channels = Naalp::Channels

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
