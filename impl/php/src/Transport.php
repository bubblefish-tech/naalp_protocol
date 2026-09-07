<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C11 transport bindings for the PHP SDK (design.md §12; R-13.1..13.4).
 *
 * A binding carries exactly one signed object as one message unit, with identical object semantics
 * across N-PAMP, QUIC, WebSocket and HTTP (R-13.1). The object is self-secured by C2..C8; the
 * binding adds only framing plus, from the transport, confidentiality and connection authentication
 * (R-13.2, R-13.3). The media type is application/vnd.bubblefish.naalp+cbor. The confidentiality boundary is
 * normative: a sensitive object MUST NOT be emitted in cleartext over a non-confidential transport —
 * the binding refuses it (ConfidentialTransportRequired, §12.3). A transport lacking peer
 * authentication where policy requires it is PeerUnauthenticated (§12.4). Fail-closed: a refusal
 * returns a named error and frames nothing.
 *
 * An independent transcription of impl/go/transport, graded against the shared
 * vectors/transport/cases.json (== Go == Rust == Python == Ruby == oracle). Pure logic only, so the
 * whole surface is corpus-graded on the pure PHP port.
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A named, fail-closed transport failure (§12.4); $kind is a stable string mirroring the
 * Go/Rust/Python/Ruby error kinds (ConfidentialTransportRequired, PeerUnauthenticated, Malformed).
 */
class TransportError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * One binding and its two conditional guarantees: confidentiality (TLS / PQ AEAD) and
 * connection-level peer authentication (§12.3). Object-level guarantees (integrity, identity,
 * non-repudiation, effect, audit) are always present regardless. This value type also carries the
 * media type constant and the static binding registry + framing/emit operations.
 */
final class Transport
{
    /** The one-object-per-representation N-AALP media type (§12.1). */
    public const MEDIA_TYPE = "application/vnd.bubblefish.naalp+cbor";

    public string $name;
    public bool $confidential;
    public bool $peerAuthenticated;

    public function __construct(string $name, bool $confidential, bool $peerAuthenticated)
    {
        $this->name = $name;
        $this->confidential = $confidential;
        $this->peerAuthenticated = $peerAuthenticated;
    }

    /**
     * Every transport variant (§12.2). WebSocket and HTTP have a confidential (wss/https) and a
     * cleartext (ws/http) variant; confidentiality is what the §12.3 boundary turns on. Built once.
     *
     * @return array<int,Transport>
     */
    public static function all(): array
    {
        static $all = null;
        if ($all !== null) {
            return $all;
        }
        $all = [
            new self("npamp", true, true),
            new self("quic", true, true),
            new self("websocket+wss", true, false),
            new self("websocket+ws", false, false),
            new self("https", true, false),
            new self("http", false, false),
        ];
        return $all;
    }

    /** Return the transport variant with this name, or null if there is no such binding. */
    public static function byName(string $name): ?Transport
    {
        foreach (self::all() as $t) {
            if ($t->name === $name) {
                return $t;
            }
        }
        return null;
    }

    /** Carry one signed object as one message unit, adding only framing (R-13.2). */
    public static function frame(Transport $t, string $obj): MessageUnit
    {
        return new MessageUnit($t->name, self::MEDIA_TYPE, $obj);
    }

    /**
     * Apply the §12.3 confidentiality boundary and the §12.4 peer-auth rule before framing: a
     * sensitive object over a non-confidential transport is refused first
     * (ConfidentialTransportRequired); a transport lacking peer authentication where policy requires
     * it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged. No partial
     * state: a refusal returns a named error and emits nothing.
     */
    public static function emit(Transport $t, string $obj, bool $sensitive, bool $requirePeerAuth): MessageUnit
    {
        if ($sensitive && !$t->confidential) {
            throw new TransportError(
                "ConfidentialTransportRequired",
                "a sensitive object may not be emitted in cleartext over a non-confidential transport"
            );
        }
        if ($requirePeerAuth && !$t->peerAuthenticated) {
            throw new TransportError(
                "PeerUnauthenticated",
                "transport peer is not authenticated where policy requires it"
            );
        }
        return self::frame($t, $obj);
    }
}

/**
 * One signed object framed for a transport: one object per unit (§12.1). The payload is the object
 * bytes verbatim — the binding transforms nothing (R-13.2).
 */
final class MessageUnit
{
    public string $transport;
    public string $mediaType;
    public string $payload;

    public function __construct(string $transport, string $mediaType, string $payload)
    {
        $this->transport = $transport;
        $this->mediaType = $mediaType;
        $this->payload = $payload;
    }

    /** Recover the object bytes, rejecting a wrong media type (Malformed). */
    public function object(): string
    {
        if ($this->mediaType !== Transport::MEDIA_TYPE) {
            throw new TransportError("Malformed", "message unit is not " . Transport::MEDIA_TYPE);
        }
        return $this->payload;
    }
}
