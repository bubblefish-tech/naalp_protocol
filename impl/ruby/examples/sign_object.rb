# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# examples/sign_object.rb — build, sign, and verify a full N-AALP object.
#
# Run:  ruby -Ilib examples/sign_object.rb
# Expected output:
#     signer   bciq...
#     signed   <N> bytes, verifies=true
#     tampered rejected: BadSignature
require 'naalp'

include Naalp::CBOR

def main
  # a deterministic 32-byte key seed (use a real random seed in production)
  seed = ("\x2a" * 32).b
  alg = Naalp::COSE::ALG_MLDSA65
  pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
  signer_id = Naalp::Identity.signer_id(alg, pk)
  puts "signer   #{signer_id}"

  # a Governance Approval object (channel 0x0004, kind 1) on the Public profile
  args_id = Naalp.object(
    kind: 0, channel: 0, signer: "".b, created: 0, effect: 0,
    body: M.new([[U.new(1), T.new("the-args")]])
  ).content_id
  approval = M.new([
    [U.new(1), B.new(args_id)],
    [U.new(2), T.new(signer_id)],
    [U.new(3), U.new(2)],                                   # granted effect: non_idempotent_write
    [U.new(4), B.new([1, 2, 3, 4, 5, 6, 7, 8].pack("C*"))], # nonce
    [U.new(5), U.new(1785000000000)],                       # not_after (epoch ms)
  ])
  obj = Naalp.object(
    kind: 1, channel: 4, tier: 0, signer: signer_id.b,
    created: 1785000000000, effect: 2, profile: Naalp::COSE::PROFILE_PUBLIC, body: approval
  )

  signed = Naalp.sign(obj, alg, seed)
  got = Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, alg, pk, ->(c, k) { [c, k] == [4, 1] }, signed)
  puts "signed   #{signed.bytesize} bytes, verifies=#{got.kind == 1 && got.channel == 4}"

  tampered = signed.dup
  tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 1)
  begin
    Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, alg, pk, ->(c, k) { true }, tampered)
    puts "tampered NOT rejected (bug)"
  rescue => e
    kind = e.respond_to?(:kind) ? e.kind : e.class.name
    puts "tampered rejected: #{kind}"
  end
end

main if __FILE__ == $PROGRAM_NAME
