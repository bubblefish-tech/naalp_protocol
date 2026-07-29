# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# naalp — the Ruby reference SDK for N-AALP (draft-bubblefish-naalp-00).
#
# N-AALP makes the *object*, not the connection, the unit of security: every message is a
# deterministically-encoded CBOR structure signed with COSE that carries, under one signature,
# its content identity, its signer, a closed effect label, optional approval/audit bindings, and
# its causal derivation — verifiable offline, over any transport.
#
# Requiring this file loads the whole spine: deterministic CBOR + content-id (C1), COSE_Sign1 +
# deterministic ML-DSA/Ed25519 (C2), the full object envelope (C3), self-certifying identity (C4),
# effect vocabulary/authorization (C5), the spine record bodies (C6-C9, C11-C12), the causal graph
# + federation reconcile, and the 20-channel/65-kind registry. The ergonomic surface is
# Naalp::Envelope::Object + Naalp.sign / Naalp.verify (re-exported below).
#
# Quick start (sign and verify a full object):
#
#     require 'naalp'
#     include Naalp::CBOR
#
#     seed = ("\x00" * 32).b                             # a real 32-byte key seed in production
#     alg  = Naalp::COSE::ALG_MLDSA65
#     pk   = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
#     sid  = Naalp::Identity.signer_id(alg, pk)
#
#     body   = M.new([[U.new(1), T.new("hello")]])
#     obj    = Naalp.object(kind: 1, channel: 4, signer: sid.b,
#                           created: 1785000000000, effect: 2, body: body)
#     signed = Naalp.sign(obj, alg, seed)                # bytes: a self-describing signed object
#     got    = Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, alg, pk, ->(c, k) { [c, k] == [4, 1] }, signed)
require_relative 'naalp/cbor'
require_relative 'naalp/cose'
require_relative 'naalp/envelope'
require_relative 'naalp/identity'
require_relative 'naalp/policy'
require_relative 'naalp/records'
require_relative 'naalp/graph'
require_relative 'naalp/channels'

module Naalp
  VERSION = "0.1.0".freeze

  # The full object type (the ergonomic surface, == naalp.Object in the Python SDK).
  Object = Naalp::Envelope::Object

  module_function

  # Build a full N-AALP object (keyword args mirror Naalp::Envelope::Object.new).
  def object(**kwargs)
    Naalp::Envelope::Object.new(**kwargs)
  end

  # Content-id-bind and deterministically sign a full object -> tagged COSE_Sign1 bytes.
  def sign(obj, alg, seed)
    Naalp::Envelope.sign(obj, alg, seed)
  end

  # Verify a signed object end-to-end, offline -> the Object, or raise EnvelopeError.
  def verify(profile, alg, pubkey, kind_validator, obj_bytes, known_cext = {}, &blk)
    Naalp::Envelope.verify(profile, alg, pubkey, kind_validator, obj_bytes, known_cext, &blk)
  end
end
