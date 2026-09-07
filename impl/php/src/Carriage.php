<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C12 foreign carriage by class for the PHP SDK (design.md §13; R-14.1..14.8, R-18.6).
 *
 * N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed N-AALP
 * carriage object whose effect, safety, identity, and audit apply, and whose foreign body is interpreted
 * by a carriage CLASS — not a bespoke per-protocol mapping (R-14.1). There are five structured classes
 * (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any protocol — including one
 * nobody has defined — carriable immediately on an experimental protocol id with no registration
 * (R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST NOT be re-serialized, canonicalized,
 * summarized, or rewritten (R-14.4); N-AALP metadata is carried around it, never inside it. The carriage
 * object's signer remains the authority — a foreign identity never becomes an N-AALP authorization
 * identity (R-14.6).
 *
 * An independent transcription of impl/go/carriage (cross-read against impl/python/naalp/carriage.py);
 * each carriage class is graded against its own per-class oracle at vectors/carriage/<class>/cases.json.
 * Every check is fail-closed (design §13.6): a failing object is rejected whole and returns its named
 * error. This module is PURE: the carriage body, the octet-exact round-trip, the class/range validation,
 * and the delivery report carry no cryptography of their own — the object is an ordinary signed N-AALP
 * envelope object (identity containment is demonstrated in the test with a real Ed25519-signed object).
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A named, fail-closed carriage error; $kind mirrors the Go/Rust/Python/Ruby error kind (Malformed,
 * NotDelivered). An unrepresentable class reuses the shared Naalp\MappingError (kind "MappingError").
 */
class CarriageError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * The body of a carriage object (design.md §13.2). $klass is the carriage class (spelled `klass` because
 * `class` is a reserved word); $foreign is the foreign message carried octet-for-octet (R-14.4).
 */
final class CarriageBody
{
    public int $protocolId;
    public int $klass;
    public int $contentType;
    public string $correlation;
    public string $method;
    public string $foreign;

    public function __construct(int $protocolId, int $klass, int $contentType, string $correlation, string $method, string $foreign)
    {
        $this->protocolId = $protocolId;
        $this->klass = $klass;
        $this->contentType = $contentType;
        $this->correlation = $correlation;
        $this->method = $method;
        $this->foreign = $foreign;
    }

    /**
     * The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type, 4: correlation,
     * 5: method, 6: foreign}. The foreign field (6) is a byte string carried verbatim.
     */
    public function toValue(): M
    {
        return new M([
            [new U(1), new U($this->protocolId)],
            [new U(2), new U($this->klass)],
            [new U(3), new U($this->contentType)],
            [new U(4), new B($this->correlation)],
            [new U(5), new T($this->method)],
            [new U(6), new B($this->foreign)],
        ]);
    }

    /** The deterministic-CBOR encoding of the carriage body. */
    public function bytes(): string
    {
        return Cbor::encode($this->toValue());
    }
}

/**
 * Records whether a carried message was actually delivered. A report never claims delivery it did not
 * achieve (R-14.8).
 */
final class DeliveryReport
{
    public bool $delivered;

    public function __construct(bool $delivered)
    {
        $this->delivered = $delivered;
    }
}

final class Carriage
{
    // Carriage classes (design.md §13.2).
    public const CLASS_JSONRPC = 0;
    public const CLASS_HTTP = 1;
    public const CLASS_MSG = 2;
    public const CLASS_STREAM = 3;
    public const CLASS_DOC = 4;
    public const CLASS_OPAQUE = 5;

    private const CLASS_NAMES = ["JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"];

    /** The name of a class code (0..5), or "unknown". */
    public static function className(int $c): string
    {
        return ($c >= 0 && $c < \count(self::CLASS_NAMES)) ? self::CLASS_NAMES[$c] : "unknown";
    }

    /**
     * Reject a class code outside the defined set with a typed mapping error, never a silent drop
     * (R-14.8). Returns when the class is representable.
     */
    public static function validateClass(int $klass): void
    {
        if ($klass > self::CLASS_OPAQUE || $klass < 0) {
            throw new MappingError("an N-AALP semantic cannot be represented by this carriage class");
        }
    }

    /**
     * Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not parse,
     * canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
     * experimental protocol id and zero new specification (R-18.6).
     */
    public static function carry(int $protocolId, int $klass, int $contentType, string $correlation, string $method, string $foreign): CarriageBody
    {
        self::validateClass($klass);
        return new CarriageBody($protocolId, $klass, $contentType, $correlation, $method, $foreign);
    }

    /**
     * Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A
     * structurally invalid body is Malformed; an unknown class is a MappingError. The mandatory foreign
     * field (key 6) must be present. Fail-closed.
     */
    public static function carriageFromValue(mixed $v): CarriageBody
    {
        if (!($v instanceof M)) {
            throw new CarriageError("Malformed", "carriage body is not a map");
        }
        $protocolId = 0;
        $klass = 0;
        $contentType = 0;
        $correlation = "";
        $method = "";
        $foreign = "";
        $haveForeign = false;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new CarriageError("Malformed", "non-uint carriage key");
            }
            switch ($k->v) {
                case 1:
                    if (!($val instanceof U)) {
                        throw new CarriageError("Malformed", "protocol_id not a uint");
                    }
                    $protocolId = $val->v;
                    break;
                case 2:
                    if (!($val instanceof U)) {
                        throw new CarriageError("Malformed", "class not a uint");
                    }
                    $klass = $val->v;
                    break;
                case 3:
                    if (!($val instanceof U)) {
                        throw new CarriageError("Malformed", "content_type not a uint");
                    }
                    $contentType = $val->v;
                    break;
                case 4:
                    if (!($val instanceof B)) {
                        throw new CarriageError("Malformed", "correlation not a bstr");
                    }
                    $correlation = $val->v;
                    break;
                case 5:
                    if (!($val instanceof T)) {
                        throw new CarriageError("Malformed", "method not a tstr");
                    }
                    $method = $val->v;
                    break;
                case 6:
                    if (!($val instanceof B)) {
                        throw new CarriageError("Malformed", "foreign not a bstr");
                    }
                    $foreign = $val->v;
                    $haveForeign = true;
                    break;
                default:
                    throw new CarriageError("Malformed", "unknown carriage field {$k->v}");
            }
        }
        if (!$haveForeign) {
            throw new CarriageError("Malformed", "carriage body missing the mandatory foreign field");
        }
        self::validateClass($klass);
        return new CarriageBody($protocolId, $klass, $contentType, $correlation, $method, $foreign);
    }

    /**
     * The protocol-id range (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
     * experimental 0x10-0x7F (no registration), private 0x80-0xFF. protocol_id is one octet;
     * anything wider is invalid.
     */
    public static function protocolRange(int $id): string
    {
        if ($id === 0x00) {
            return "reserved";
        }
        if ($id <= 0x0F) {
            return "standards";
        }
        if ($id <= 0x7F) {
            return "experimental";
        }
        if ($id <= 0xFF) {
            return "private";
        }
        return "invalid";
    }

    /**
     * Produce a delivery report from the below-foreign outcome: a failed delivery raises NotDelivered
     * (never a false "delivered"); a success returns a delivered report (R-14.8).
     */
    public static function report(bool $deliveredBelow): DeliveryReport
    {
        if (!$deliveredBelow) {
            throw new CarriageError("NotDelivered", "a below-foreign failure; the message was not delivered");
        }
        return new DeliveryReport(true);
    }

    /**
     * The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field 5),
     * never any foreign principal named inside the foreign bytes (R-14.6). It reads only the signed
     * envelope, never the carried foreign message.
     */
    public static function authority(NaalpObject $o): string
    {
        return $o->signer;
    }
}
