# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C12 foreign carriage by class for the Ruby SDK (design.md §13; R-14.1..14.8, R-18.6).
#
# N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed N-AALP
# carriage object whose effect, safety, identity, and audit apply, and whose foreign body is interpreted
# by a carriage CLASS -- not a bespoke per-protocol mapping (R-14.1). There are five structured classes
# (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any protocol -- including
# one nobody has defined -- carriable immediately on an experimental protocol id with no registration
# (R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST NOT be re-serialized, canonicalized,
# summarized, or rewritten (R-14.4); N-AALP metadata is carried AROUND it, never inside it. The carriage
# object's signer remains the authority -- a foreign identity never becomes an N-AALP authorization
# identity (R-14.6).
#
# Ported from impl/go/carriage (cross-read against impl/python/naalp/carriage.py). Each carriage class
# is graded against its OWN per-class oracle at vectors/carriage/<class>/cases.json. Every check is
# fail-closed: a failing body is rejected whole and returns its named error.
require_relative 'cbor'

module Naalp
  module Carriage
    # Carriage classes (design.md §13.2).
    CLASS_JSONRPC = 0
    CLASS_HTTP = 1
    CLASS_MSG = 2
    CLASS_STREAM = 3
    CLASS_DOC = 4
    CLASS_OPAQUE = 5

    CLASS_NAMES = ["JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"].freeze

    # A named, fail-closed carriage error; #kind is the stable error kind (design §13.6).
    class CarriageError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # The body of a carriage object (design.md §13.2). klass is the carriage class (spelled klass
    # because class is a Ruby keyword); foreign is the foreign message carried octet-for-octet (R-14.4).
    CarriageBody = Struct.new(:protocol_id, :klass, :content_type, :correlation, :method, :foreign) do
      # The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type, 4: correlation,
      # 5: method, 6: foreign}.
      def to_value
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(protocol_id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(klass)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(content_type)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(correlation)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::T.new(method)],
          [Naalp::CBOR::U.new(6), Naalp::CBOR::B.new(foreign)],
        ])
      end

      # The deterministic-CBOR encoding of the carriage body.
      def bytes
        Naalp::CBOR.encode(to_value)
      end
    end

    # Records whether a carried message was actually delivered. A report never claims delivery it did
    # not achieve (R-14.8).
    DeliveryReport = Struct.new(:delivered)

    module_function

    # The name of a class code (0..5), or "unknown".
    def class_name(c)
      (c >= 0 && c < CLASS_NAMES.length) ? CLASS_NAMES[c] : "unknown"
    end

    # Reject a class code outside the defined set with a typed mapping error, never a silent drop
    # (R-14.8). Returns nil when the class is representable.
    def validate_class(klass)
      if klass > CLASS_OPAQUE || klass < 0
        raise CarriageError.new("MappingError", "an N-AALP semantic cannot be represented by this carriage class")
      end
      nil
    end

    # Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not parse,
    # canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
    # experimental protocol id and zero new specification (R-18.6).
    def carry(protocol_id, klass, content_type, correlation, method, foreign)
      validate_class(klass)
      CarriageBody.new(protocol_id, klass, content_type, correlation, method, foreign)
    end

    # Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A
    # structurally invalid body is Malformed; an unknown class is a MappingError. The mandatory foreign
    # field (key 6) must be present.
    def carriage_from_value(v)
      raise CarriageError.new("Malformed", "carriage body is not a map") unless v.is_a?(Naalp::CBOR::M)
      protocol_id = 0
      klass = 0
      content_type = 0
      correlation = "".b
      method = ""
      foreign = "".b
      have_foreign = false
      v.pairs.each do |k, val|
        raise CarriageError.new("Malformed", "non-uint carriage key") unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          raise CarriageError.new("Malformed", "protocol_id not a uint") unless val.is_a?(Naalp::CBOR::U)
          protocol_id = val.v
        when 2
          raise CarriageError.new("Malformed", "class not a uint") unless val.is_a?(Naalp::CBOR::U)
          klass = val.v
        when 3
          raise CarriageError.new("Malformed", "content_type not a uint") unless val.is_a?(Naalp::CBOR::U)
          content_type = val.v
        when 4
          raise CarriageError.new("Malformed", "correlation not a bstr") unless val.is_a?(Naalp::CBOR::B)
          correlation = val.v
        when 5
          raise CarriageError.new("Malformed", "method not a tstr") unless val.is_a?(Naalp::CBOR::T)
          method = val.v
        when 6
          raise CarriageError.new("Malformed", "foreign not a bstr") unless val.is_a?(Naalp::CBOR::B)
          foreign = val.v
          have_foreign = true
        else
          raise CarriageError.new("Malformed", "unknown carriage field #{k.v}")
        end
      end
      raise CarriageError.new("Malformed", "carriage body missing the mandatory foreign field") unless have_foreign
      validate_class(klass)
      CarriageBody.new(protocol_id, klass, content_type, correlation, method, foreign)
    end

    # The protocol-id range (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
    # experimental 0x10-0x7F (no registration), private 0x80-0xFF. protocol_id is one octet;
    # anything wider is invalid.
    def protocol_range(id)
      if id == 0x00
        "reserved"
      elsif id <= 0x0F
        "standards"
      elsif id <= 0x7F
        "experimental"
      elsif id <= 0xFF
        "private"
      else
        "invalid"
      end
    end

    # Produce a delivery report from the below-foreign outcome: a failed delivery raises NotDelivered
    # (never a false "delivered"); a success returns DeliveryReport(delivered=true) (R-14.8).
    def report(delivered_below)
      unless delivered_below
        raise CarriageError.new("NotDelivered", "a below-foreign failure; the message was not delivered")
      end
      DeliveryReport.new(true)
    end

    # The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field
    # 5), never any foreign principal named inside the foreign bytes (R-14.6). It reads only the signed
    # envelope, never the carried foreign message.
    def carriage_authority(obj)
      obj.signer
    end
  end
end
