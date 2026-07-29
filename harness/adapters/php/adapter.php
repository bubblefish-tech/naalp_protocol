<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * naalp-adapter-php — the PHP N-AALP conformance adapter.
 *
 * Wraps the impl/php `Naalp` SDK behind the length-prefixed JSON op protocol the naalp-conform
 * runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON {"op","in"}
 * request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on stdout, flushed
 * after each.
 *
 * PHP crypto verdict is PURE-ONLY: it has no deterministic (rnd=0) ML-DSA SIGN path and no PHP
 * binding for deterministic ML-DSA seed->pk keygen (liboqs/OpenSSL 3.5 ML-DSA is randomized-only),
 * so mldsa.keygen / cose.sign1 / cose.verify1 return an honest `skipped`. Ed25519 seed->sign IS
 * deterministic via ext-sodium and is implemented; every pure op is implemented.
 *
 * Launch: php -d extension=sodium -d extension=intl harness/adapters/php/adapter.php
 */

declare(strict_types=1);

namespace Naalp;

$SRC = \dirname(__DIR__, 3) . '/impl/php/src';
require_once $SRC . '/Cbor.php';
require_once $SRC . '/Cose.php';
require_once $SRC . '/Identity.php';
require_once $SRC . '/Policy.php';
require_once $SRC . '/Records.php';
require_once $SRC . '/Graph.php';
require_once $SRC . '/Channels.php';

/** Parse a 64-bit counter that may arrive as a JSON number or a decimal string. */
function u(array $in, string $k): int
{
    if (!\array_key_exists($k, $in) || $in[$k] === null) {
        return 0;
    }
    $v = $in[$k];
    if (\is_string($v)) {
        return (int) $v;
    }
    return (int) $v;
}

/** Decode a hex field to raw bytes. */
function hx(array $in, string $k): string
{
    $s = $in[$k] ?? '';
    if ($s === '') {
        return '';
    }
    $b = \hex2bin($s);
    if ($b === false) {
        throw new \RuntimeException("invalid hex in field " . $k);
    }
    return $b;
}

/** Convert a language-neutral tagged value [tag, payload] into a cbor value. */
function tagged(mixed $v): mixed
{
    if (!\is_array($v) || \count($v) !== 2 || !\array_is_list($v)) {
        throw new \RuntimeException("tagged value must be [tag, payload]");
    }
    [$tag, $p] = $v;
    switch ($tag) {
        case "u":
            return new U(\is_string($p) ? (int) $p : (int) $p);
        case "b":
            $bytes = ($p === '') ? '' : \hex2bin((string) $p);
            if ($bytes === false) {
                throw new \RuntimeException("invalid hex in tagged byte string");
            }
            return new B($bytes);
        case "s":
            return new T((string) $p);
        case "arr":
            $items = [];
            foreach ($p as $i) {
                $items[] = tagged($i);
            }
            return new A($items);
        case "map":
            $pairs = [];
            foreach ($p as $kv) {
                $pairs[] = [tagged($kv[0]), tagged($kv[1])];
            }
            return new M($pairs);
        default:
            throw new \RuntimeException("unknown tag " . \var_export($tag, true));
    }
}

/** The error `kind` an exception carries, defaulting to a supplied fallback. */
function errKind(\Throwable $e, string $fallback): string
{
    if (\property_exists($e, 'kind')) {
        // @phpstan-ignore-next-line dynamic kind property on the SDK exceptions
        return (string) $e->kind;
    }
    return $fallback;
}

/**
 * Dispatch one op. Returns an assoc array with exactly one of: out, error, skipped.
 *
 * @param array<string,mixed> $in
 * @return array<string,mixed>
 */
function handle(string $op, array $in): array
{
    switch ($op) {
        case "sha384":
            return ["out" => ["digest_hex" => \hash('sha384', hx($in, "msg_hex"))]];

        case "cbor.encode":
            return ["out" => ["bytes_hex" => \bin2hex(Cbor::encode(tagged($in["value"])))]];

        case "cbor.decode":
            try {
                Cbor::decode(hx($in, "bytes_hex"));
                return ["out" => ["ok" => true]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "Malformed") . ": " . $e->getMessage()];
            }

        case "content.id":
            $v = Cbor::decode(hx($in, "body_hex"));
            return ["out" => ["id_hex" => \bin2hex(Cbor::contentId($v))]];

        case "cose.tbs":
            return ["out" => ["tobesigned_hex" => \bin2hex(Cose::toBeSignedRaw(hx($in, "protected_hex"), hx($in, "payload_hex")))]];

        case "mldsa.keygen":
            return ["skipped" => "no deterministic ML-DSA keygen-from-seed in PHP (liboqs/OpenSSL 3.5 have no PHP-exposed seed->pk path)"];

        case "ed25519.sign":
            return ["out" => ["sig_hex" => \bin2hex(Cose::ed25519Sign(hx($in, "sk_hex"), hx($in, "msg_hex")))]];

        case "cose.sign1":
            return ["skipped" => "no deterministic ML-DSA sign in PHP (liboqs/OpenSSL are randomized-only)"];

        case "cose.verify1":
            return ["skipped" => "no deterministic ML-DSA verify path wired in PHP (crypto leg is pure-only)"];

        case "signerid":
            try {
                return ["out" => ["signer_id" => Identity::signerId((int) $in["alg"], hx($in, "pubkey_hex"))]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "UnknownAlg") . ": " . $e->getMessage()];
            }

        case "nfc.check":
            try {
                Identity::requireNfc(hx($in, "utf8_hex"));
                return ["out" => ["ok" => true]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "NonNFC") . ": " . $e->getMessage()];
            }

        case "effect.normalize":
            return ["out" => ["effect" => Policy::normalizeEffect(u($in, "value"))]];

        case "effect.authorize":
            return ["out" => ["allow" => Policy::authorizes(Policy::normalizeEffect(u($in, "granted")), u($in, "effect"))]];

        case "effect.safety_label":
            return ["out" => ["cbor_hex" => \bin2hex(Policy::safetyLabelBytes((string) ($in["risk"] ?? ""), (string) ($in["scope"] ?? "")))]];

        case "approval.body":
            return ["out" => ["body_hex" => \bin2hex(Records::approvalBody(
                hx($in, "approves_hex"), (string) ($in["approver"] ?? ""), u($in, "grant"), hx($in, "nonce_hex"), u($in, "not_after")))]];

        case "approval.id":
            return ["out" => ["id_hex" => \bin2hex(Records::approvalId(
                hx($in, "approves_hex"), (string) ($in["approver"] ?? ""), u($in, "grant"), hx($in, "nonce_hex"), u($in, "not_after")))]];

        case "ledger.entry":
            return ["out" => ["body_hex" => \bin2hex(Records::ledgerEntry(
                u($in, "seq"), hx($in, "prev_hex"), hx($in, "approval_id_hex"), (string) ($in["by"] ?? "")))]];

        case "receipt.body":
            return ["out" => ["body_hex" => \bin2hex(Records::receiptBody(
                hx($in, "prev_hex"), hx($in, "obj_hex"), u($in, "seq"), u($in, "at")))]];

        case "receipt.head":
            return ["out" => ["head_hex" => \bin2hex(Records::receiptHead(hx($in, "body_hex")))]];

        case "causal.verify":
            $nodes = [];
            foreach ($in["nodes"] as $n) {
                $causes = [];
                foreach (($n["causes_hex"] ?? []) as $c) {
                    $causes[] = \hex2bin($c);
                }
                $nodes[] = [\hex2bin($n["id_hex"]), $causes, (int) ($n["position"] ?? 0)];
            }
            try {
                Graph::verifyCausal($nodes);
                return ["out" => ["valid" => true]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "CausalViolation") . ": " . $e->getMessage()];
            }

        case "delivery.update":
            return ["out" => ["body_hex" => \bin2hex(Records::deliveryUpdate(hx($in, "obj_hex"), u($in, "stage"), u($in, "at")))]];

        case "stream.digest":
            $chunks = [];
            foreach ($in["chunks"] as $c) {
                $chunks[] = [(int) $c["offset"], \hex2bin($c["data_hex"])];
            }
            return ["out" => ["digest_hex" => \bin2hex(Records::streamDigest($chunks))]];

        case "stream.open":
            $approval = !empty($in["approval_hex"]) ? \hex2bin($in["approval_hex"]) : "";
            return ["out" => ["body_hex" => \bin2hex(Records::streamOpenBody(
                hx($in, "stream_id_hex"), u($in, "effect"), $approval, u($in, "substream")))]];

        case "stream.commit":
            return ["out" => ["body_hex" => \bin2hex(Records::streamCommitBody(hx($in, "stream_id_hex"), hx($in, "digest_hex")))]];

        case "stream.checkpoint":
            return ["out" => ["body_hex" => \bin2hex(Records::streamCheckpointBody(
                hx($in, "stream_id_hex"), u($in, "through_offset"), hx($in, "digest_so_far_hex")))]];

        case "transport.emit":
            try {
                return ["out" => ["result" => Records::transportEmit(
                    (string) ($in["transport"] ?? ""), (bool) ($in["sensitive"] ?? false), (bool) ($in["require_peer_auth"] ?? false))]];
            } catch (\Throwable $e) {
                return ["error" => $e->getMessage()];
            }

        case "carriage.body":
            try {
                $body = Records::carriageBody(
                    u($in, "protocol_id"), u($in, "class"), u($in, "content_type"),
                    hx($in, "correlation_hex"), (string) ($in["method"] ?? ""), hx($in, "foreign_hex"));
                return ["out" => ["body_hex" => \bin2hex($body)]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "MappingError") . ": " . $e->getMessage()];
            }

        case "channels.lookup":
            try {
                [$name, $effect, $variable] = Channels::lookup(u($in, "channel"), u($in, "kind"));
                return ["out" => ["name" => $name, "effect" => $effect, "variable" => $variable]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "UnknownKind") . ": " . $e->getMessage()];
            }

        case "channels.effect_check":
            try {
                Channels::checkEffect(u($in, "channel"), u($in, "kind"), u($in, "effect"));
                return ["out" => ["ok" => true]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "EffectDeclarationMismatch") . ": " . $e->getMessage()];
            }

        case "federation.reconcile":
            $nodes = [];
            foreach ($in["nodes"] as $n) {
                $causes = [];
                foreach (($n["causes_hex"] ?? []) as $c) {
                    $causes[] = \hex2bin($c);
                }
                $nodes[] = [\hex2bin($n["id_hex"]), $causes, (int) ($n["position"] ?? 0)];
            }
            try {
                $order = Graph::reconcile($nodes);
                return ["out" => ["order" => \array_map('bin2hex', $order)]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "CausalViolation") . ": " . $e->getMessage()];
            }

        case "federation.record":
            $order = [];
            foreach (($in["order"] ?? []) as $o) {
                $order[] = \hex2bin($o);
            }
            return ["out" => ["body_hex" => \bin2hex(Graph::reconcileRecord($in["authorities"] ?? [], $order))]];

        default:
            return ["skipped" => "op not implemented: " . $op];
    }
}

function readExact($stream, int $n): ?string
{
    $buf = '';
    while (\strlen($buf) < $n) {
        $chunk = \fread($stream, $n - \strlen($buf));
        if ($chunk === false || $chunk === '') {
            if (\feof($stream)) {
                return null;
            }
            // brief non-EOF empty read; retry
            continue;
        }
        $buf .= $chunk;
    }
    return $buf;
}

function main(): void
{
    $stdin = \fopen('php://stdin', 'rb');
    $stdout = \fopen('php://stdout', 'wb');
    \stream_set_read_buffer($stdin, 0);

    while (true) {
        $lp = readExact($stdin, 4);
        if ($lp === null || \strlen($lp) < 4) {
            return;
        }
        $n = \unpack('V', $lp)[1];
        $body = $n === 0 ? '' : readExact($stdin, $n);
        if ($body === null) {
            return;
        }
        try {
            $req = \json_decode($body, true, 512, \JSON_THROW_ON_ERROR);
            $resp = handle((string) ($req["op"] ?? ""), \is_array($req["in"] ?? null) ? $req["in"] : []);
        } catch (\Throwable $e) {
            $resp = ["error" => "adapter exception: " . $e->getMessage()];
        }
        $ob = \json_encode($resp, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);
        \fwrite($stdout, \pack('V', \strlen($ob)) . $ob);
        \fflush($stdout);
    }
}

main();
