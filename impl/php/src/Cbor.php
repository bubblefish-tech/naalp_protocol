<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
 *
 * An independent PHP port of the same deterministic profile the Python, Go, and Rust
 * reference implementations produce: shortest-form integer heads, no indefinite lengths,
 * canonical (bytewise-ascending, by encoded key) map ordering, no duplicate keys. The
 * strict decoder rejects every non-canonical form. content_id is
 * multihash(0x20 sha2-384, 0x30 len-48, SHA-384(body)) over the deterministic body bytes (§2.3).
 *
 * The value model (U/N/B/T/A/M/Tag) mirrors the Python cbor.Value variants exactly so the
 * emitted bytes are byte-identical.
 */

declare(strict_types=1);

namespace Naalp;

/** Raised on any non-canonical CBOR (encode or strict decode). */
class NonCanonical extends \RuntimeException
{
    public string $kind = "NonCanonical";
}

// --- value model (mirrors the Go/Rust/Python cbor.Value variants) ---

/** CBOR unsigned integer (major 0). */
final class U
{
    public int $v;
    public function __construct(int $v) { $this->v = $v; }
}

/** CBOR negative integer (major 1); v is the negative value itself. */
final class N
{
    public int $v;
    public function __construct(int $v) { $this->v = $v; }
}

/** CBOR byte string (major 2); v is a raw binary string. */
final class B
{
    public string $v;
    public function __construct(string $v) { $this->v = $v; }
}

/** CBOR text string (major 3); v is a UTF-8 string. */
final class T
{
    public string $v;
    public function __construct(string $v) { $this->v = $v; }
}

/** CBOR array (major 4). */
final class A
{
    /** @var array<int,mixed> */
    public array $items;
    /** @param array<int,mixed> $items */
    public function __construct(array $items) { $this->items = array_values($items); }
}

/** CBOR map (major 5); pairs is a list of [key_value, value]. */
final class M
{
    /** @var array<int,array{0:mixed,1:mixed}> */
    public array $pairs;
    /** @param array<int,array{0:mixed,1:mixed}> $pairs */
    public function __construct(array $pairs) { $this->pairs = array_values($pairs); }
}

/** CBOR tag (major 6). */
final class Tag
{
    public int $n;
    public mixed $content;
    public function __construct(int $n, mixed $content) { $this->n = $n; $this->content = $content; }
}

final class Cbor
{
    /** Encode a definite-length head: (major<<5)|arg, shortest form (RFC 8949 §4.2.1). */
    private static function head(int $major, int $n): string
    {
        $m = $major << 5;
        if ($n < 24) {
            return \chr($m | $n);
        }
        if ($n < 256) {
            return \chr($m | 24) . \chr($n);
        }
        if ($n < 65536) {
            return \chr($m | 25) . \pack('n', $n);
        }
        if ($n < 4294967296) {
            return \chr($m | 26) . \pack('N', $n);
        }
        return \chr($m | 27) . \pack('J', $n);
    }

    /** Deterministic-CBOR encode a value; map keys are emitted in canonical order. */
    public static function encode(mixed $v): string
    {
        if ($v instanceof U) {
            if ($v->v < 0) {
                throw new NonCanonical("uint is negative");
            }
            return self::head(0, $v->v);
        }
        if ($v instanceof N) {
            return self::head(1, -1 - $v->v);
        }
        if ($v instanceof B) {
            return self::head(2, \strlen($v->v)) . $v->v;
        }
        if ($v instanceof T) {
            return self::head(3, \strlen($v->v)) . $v->v;
        }
        if ($v instanceof A) {
            $out = self::head(4, \count($v->items));
            foreach ($v->items as $i) {
                $out .= self::encode($i);
            }
            return $out;
        }
        if ($v instanceof M) {
            $enc = [];
            foreach ($v->pairs as $kv) {
                $enc[] = [self::encode($kv[0]), self::encode($kv[1])];
            }
            // canonical: sort by encoded-key bytes, bytewise ascending (strcmp = memcmp, unsigned)
            \usort($enc, static fn(array $a, array $b): int => \strcmp($a[0], $b[0]));
            for ($i = 1; $i < \count($enc); $i++) {
                if ($enc[$i][0] === $enc[$i - 1][0]) {
                    throw new NonCanonical("duplicate map key");
                }
            }
            $out = self::head(5, \count($enc));
            foreach ($enc as $kv) {
                $out .= $kv[0] . $kv[1];
            }
            return $out;
        }
        if ($v instanceof Tag) {
            return self::head(6, $v->n) . self::encode($v->content);
        }
        throw new \TypeError("not a cbor value");
    }

    /**
     * Decode one item at $off. Returns [value, newOffset]. Strict: rejects any non-canonical
     * encoding (non-shortest int, indefinite length, out-of-order/duplicate map keys, trailing bytes).
     *
     * @return array{0:mixed,1:int}
     */
    private static function dec(string $data, int $off): array
    {
        $len = \strlen($data);
        if ($off >= $len) {
            throw new NonCanonical("truncated");
        }
        $ib = \ord($data[$off]);
        $major = $ib >> 5;
        $ai = $ib & 0x1F;
        $p = $off + 1;

        if ($ai === 31) {
            throw new NonCanonical("indefinite length");
        }
        if ($ai < 24) {
            $arg = $ai;
        } elseif ($ai === 24) {
            if ($p + 1 > $len) {
                throw new NonCanonical("truncated head");
            }
            $arg = \ord($data[$p]);
            $p += 1;
            if ($arg < 24) {
                throw new NonCanonical("non-shortest integer");
            }
        } elseif ($ai === 25) {
            if ($p + 2 > $len) {
                throw new NonCanonical("truncated head");
            }
            $arg = (\ord($data[$p]) << 8) | \ord($data[$p + 1]);
            $p += 2;
            if ($arg < 256) {
                throw new NonCanonical("non-shortest integer");
            }
        } elseif ($ai === 26) {
            if ($p + 4 > $len) {
                throw new NonCanonical("truncated head");
            }
            $arg = 0;
            for ($k = 0; $k < 4; $k++) {
                $arg = ($arg << 8) | \ord($data[$p + $k]);
            }
            $p += 4;
            if ($arg < 65536) {
                throw new NonCanonical("non-shortest integer");
            }
        } elseif ($ai === 27) {
            if ($p + 8 > $len) {
                throw new NonCanonical("truncated head");
            }
            // 64-bit big-endian; corpus values fit in a signed 64-bit int
            $u = \unpack('J', \substr($data, $p, 8));
            $arg = $u[1];
            $p += 8;
            if ($arg >= 0 && $arg < 4294967296) {
                throw new NonCanonical("non-shortest integer");
            }
        } else {
            throw new NonCanonical("reserved additional-info");
        }

        switch ($major) {
            case 0:
                return [new U($arg), $p];
            case 1:
                return [new N(-1 - $arg), $p];
            case 2:
                if ($p + $arg > $len) {
                    throw new NonCanonical("truncated byte string");
                }
                return [new B(\substr($data, $p, $arg)), $p + $arg];
            case 3:
                if ($p + $arg > $len) {
                    throw new NonCanonical("truncated text string");
                }
                return [new T(\substr($data, $p, $arg)), $p + $arg];
            case 4:
                $items = [];
                for ($i = 0; $i < $arg; $i++) {
                    [$it, $p] = self::dec($data, $p);
                    $items[] = $it;
                }
                return [new A($items), $p];
            case 5:
                $pairs = [];
                $prev = null;
                for ($i = 0; $i < $arg; $i++) {
                    $before = $p;
                    [$k, $p] = self::dec($data, $p);
                    $kbytes = \substr($data, $before, $p - $before);
                    [$val, $p] = self::dec($data, $p);
                    if ($prev !== null && \strcmp($kbytes, $prev) <= 0) {
                        throw new NonCanonical("map keys out of order or duplicate");
                    }
                    $prev = $kbytes;
                    $pairs[] = [$k, $val];
                }
                return [new M($pairs), $p];
            case 6:
                [$content, $p] = self::dec($data, $p);
                return [new Tag($arg, $content), $p];
            default:
                throw new NonCanonical("unsupported major type");
        }
    }

    /** Strict canonical decode: rejects any non-canonical encoding with NonCanonical. */
    public static function decode(string $data): mixed
    {
        [$v, $off] = self::dec($data, 0);
        if ($off !== \strlen($data)) {
            throw new NonCanonical("trailing bytes after top-level item");
        }
        return $v;
    }

    /**
     * content id = multihash(0x20 [sha2-384], 0x30 [48], SHA-384(body-bytes)) (§2.3).
     * $body may be a cbor value (re-encoded) or a raw binary string.
     */
    public static function contentId(mixed $body): string
    {
        if ($body instanceof U || $body instanceof N || $body instanceof B
            || $body instanceof T || $body instanceof A || $body instanceof M || $body instanceof Tag) {
            $body = self::encode($body);
        }
        return "\x20\x30" . \hash('sha384', (string) $body, true);
    }
}
