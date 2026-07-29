# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C5 effect vocabulary and authorization for the Ruby SDK (§6).
#
# The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
# unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
# (action <= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.
require_relative 'cbor'

module Naalp
  module Policy
    READ_ONLY = 0
    IDEMPOTENT_WRITE = 1
    NON_IDEMPOTENT_WRITE = 2
    DESTRUCTIVE = 3

    NAMES = ["read_only", "idempotent_write", "non_idempotent_write", "destructive"].freeze

    module_function

    # Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2).
    def normalize_effect(v)
      (v >= 0 && v <= 3) ? v : DESTRUCTIVE
    end

    def safety_label_name(e)
      NAMES[normalize_effect(e)]
    end

    # The §6.1 lattice: an action of class `action` is permitted under `ceiling` iff action <= ceiling.
    def authorizes(ceiling, action)
      action <= ceiling
    end

    # The signed safety-label body {1: risk, 2: scope} (R-6.4).
    def safety_label_bytes(risk, scope)
      Naalp::CBOR.encode(
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(risk)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(scope)],
        ])
      )
    end
  end
end
