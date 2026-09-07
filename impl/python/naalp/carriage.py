# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C12 foreign carriage by class for the Python SDK (design.md §13; R-14.1..14.8, R-18.6).

N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed N-AALP
carriage object whose effect, safety, identity, and audit apply, and whose foreign body is interpreted
by a carriage CLASS -- not a bespoke per-protocol mapping (R-14.1). There are five structured classes
(JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any protocol -- including
one nobody has defined -- carriable immediately on an experimental protocol id with no registration
(R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST NOT be re-serialized, canonicalized,
summarized, or rewritten (R-14.4); N-AALP metadata is carried around it, never inside it. The carriage
object's signer remains the authority -- a foreign identity never becomes an N-AALP authorization
identity (R-14.6).

Ported from impl/go/carriage; each carriage class is graded against its own per-class oracle at
vectors/carriage/<class>/cases.json.
"""
from . import cbor
from .cbor import U, B, T, M

# Carriage classes (design.md §13.2).
CLASS_JSONRPC = 0
CLASS_HTTP = 1
CLASS_MSG = 2
CLASS_STREAM = 3
CLASS_DOC = 4
CLASS_OPAQUE = 5

_CLASS_NAMES = ["JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"]


def class_name(c):
    """The name of a class code (0..5), or 'unknown'."""
    return _CLASS_NAMES[c] if 0 <= c < len(_CLASS_NAMES) else "unknown"


class CarriageError(ValueError):
    """A named, fail-closed carriage error; .kind is the stable error kind (design §13.6)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


class CarriageBody:
    """The body of a carriage object (design.md §13.2). `klass` is the carriage class (spelled `klass`
    because `class` is a Python keyword); `foreign` is the foreign message carried octet-for-octet
    (R-14.4)."""

    __slots__ = ("protocol_id", "klass", "content_type", "correlation", "method", "foreign")

    def __init__(self, protocol_id, klass, content_type, correlation, method, foreign):
        self.protocol_id = int(protocol_id)
        self.klass = int(klass)
        self.content_type = int(content_type)
        self.correlation = bytes(correlation)
        self.method = str(method)
        self.foreign = bytes(foreign)

    def to_value(self):
        """The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type,
        4: correlation, 5: method, 6: foreign}."""
        return M([
            (U(1), U(self.protocol_id)),
            (U(2), U(self.klass)),
            (U(3), U(self.content_type)),
            (U(4), B(self.correlation)),
            (U(5), T(self.method)),
            (U(6), B(self.foreign)),
        ])

    def bytes(self):
        """The deterministic-CBOR encoding of the carriage body."""
        return cbor.encode(self.to_value())


def validate_class(klass):
    """Reject a class code outside the defined set with a typed mapping error, never a silent drop
    (R-14.8). Returns None when the class is representable."""
    if klass > CLASS_OPAQUE or klass < 0:
        raise CarriageError("MappingError", "an N-AALP semantic cannot be represented by this carriage class")
    return None


def carry(protocol_id, klass, content_type, correlation, method, foreign):
    """Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not parse,
    canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
    experimental protocol id and zero new specification (R-18.6)."""
    validate_class(klass)
    return CarriageBody(protocol_id, klass, content_type, correlation, method, foreign)


def carriage_from_value(v):
    """Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A
    structurally invalid body is Malformed; an unknown class is a MappingError. The mandatory foreign
    field (key 6) must be present."""
    if not isinstance(v, M):
        raise CarriageError("Malformed", "carriage body is not a map")
    protocol_id = klass = content_type = 0
    correlation = foreign = b""
    method = ""
    have_foreign = False
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise CarriageError("Malformed", "non-uint carriage key")
        if k.v == 1:
            if not isinstance(val, U):
                raise CarriageError("Malformed", "protocol_id not a uint")
            protocol_id = val.v
        elif k.v == 2:
            if not isinstance(val, U):
                raise CarriageError("Malformed", "class not a uint")
            klass = val.v
        elif k.v == 3:
            if not isinstance(val, U):
                raise CarriageError("Malformed", "content_type not a uint")
            content_type = val.v
        elif k.v == 4:
            if not isinstance(val, B):
                raise CarriageError("Malformed", "correlation not a bstr")
            correlation = val.v
        elif k.v == 5:
            if not isinstance(val, T):
                raise CarriageError("Malformed", "method not a tstr")
            method = val.v
        elif k.v == 6:
            if not isinstance(val, B):
                raise CarriageError("Malformed", "foreign not a bstr")
            foreign = val.v
            have_foreign = True
        else:
            raise CarriageError("Malformed", "unknown carriage field %d" % k.v)
    if not have_foreign:
        raise CarriageError("Malformed", "carriage body missing the mandatory foreign field")
    validate_class(klass)
    return CarriageBody(protocol_id, klass, content_type, correlation, method, foreign)


def protocol_range(id_):
    """The protocol-id range (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
    experimental 0x10-0x7F (no registration), private 0x80-0xFF. protocol_id is one octet;
    anything wider is invalid."""
    if id_ == 0x00:
        return "reserved"
    if id_ <= 0x0F:
        return "standards"
    if id_ <= 0x7F:
        return "experimental"
    if id_ <= 0xFF:
        return "private"
    return "invalid"


class DeliveryReport:
    """Records whether a carried message was actually delivered. A report never claims delivery it did
    not achieve (R-14.8)."""

    __slots__ = ("delivered",)

    def __init__(self, delivered):
        self.delivered = bool(delivered)


def report(delivered_below):
    """Produce a delivery report from the below-foreign outcome: a failed delivery raises NotDelivered
    (never a false 'delivered'); a success returns DeliveryReport(delivered=True) (R-14.8)."""
    if not delivered_below:
        raise CarriageError("NotDelivered", "a below-foreign failure; the message was not delivered")
    return DeliveryReport(True)


def carriage_authority(obj):
    """The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field
    5), never any foreign principal named inside the foreign bytes (R-14.6). It reads only the signed
    envelope, never the carried foreign message."""
    return obj.signer
