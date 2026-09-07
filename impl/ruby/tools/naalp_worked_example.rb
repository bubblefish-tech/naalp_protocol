# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Emit the worked-example N-AALP object as one line of lowercase hex: the whole
# COSE_Sign1 the reference produces from the fixed 0x2a seed for the Governance
# Approval object (channel 0x0004, kind 1) -- the same construction the Go
# cmd/naalp-worked-example emitter and test/worked_example_test.rb build.
# scripts/record_cross_port_objects.py runs this and records the bytes; the
# cross-port object gate compares them to vectors/worked/example.json. Prints ONLY
# the hex so the recorder reads it unambiguously.
#
#   ruby -Ilib tools/naalp_worked_example.rb        (from impl/ruby/)

require 'naalp'
include Naalp::CBOR

SEED = ("\x2a" * 32).b
ALG = Naalp::COSE::ALG_MLDSA65
ARGS_ID_HEX = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"

pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
signer_id = Naalp::Identity.signer_id(ALG, pk)
body = M.new([
  [U.new(1), B.new([ARGS_ID_HEX].pack("H*"))],
  [U.new(2), T.new(signer_id)],
  [U.new(3), U.new(2)],
  [U.new(4), B.new([1, 2, 3, 4, 5, 6, 7, 8].pack("C*"))],
  [U.new(5), U.new(1785000000000)],
])
obj = Naalp.object(
  kind: 1, channel: 4, tier: 0, signer: signer_id.b,
  created: 1785000000000, effect: 2, profile: Naalp::COSE::PROFILE_PUBLIC, body: body
)
puts Naalp.sign(obj, ALG, SEED).unpack1("H*")
