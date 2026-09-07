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
 * PHP crypto is FULL where OpenSSL >= 3.5 is reachable: mldsa.keygen / cose.sign1 / cose.verify1 run
 * deterministic (rnd=0) ML-DSA-65/87 via MlDsa (PHP-FFI to OpenSSL >= 3.5), byte-identical to the
 * FIPS 204 consensus; where the runtime OpenSSL is older or FFI is off, MlDsa::available() is false and
 * those ops return an honest `skipped` (never a false green). Ed25519 seed->sign IS deterministic via
 * ext-sodium and is implemented; every pure op is implemented.
 *
 * Launch: php -d extension=sodium -d extension=intl harness/adapters/php/adapter.php
 */

declare(strict_types=1);

namespace Naalp;

$SRC = \dirname(__DIR__, 3) . '/impl/php/src';
require_once $SRC . '/Cbor.php';
require_once $SRC . '/NaalpError.php';
require_once $SRC . '/Cose.php';
require_once $SRC . '/MlDsa.php';
require_once $SRC . '/WireConstants.php';
require_once $SRC . '/Envelope.php';
require_once $SRC . '/Identity.php';
require_once $SRC . '/Policy.php';
require_once $SRC . '/Records.php';
require_once $SRC . '/Graph.php';
require_once $SRC . '/Gateway.php'; // BadSignature (Approval::verifyApproval's signature-gate error)
require_once $SRC . '/Audit.php'; // Authority/Receipt used by Delivery's ContentFreeRelay
require_once $SRC . '/Approval.php'; // C6 approval + single-use consume ledger (approval.state, T20.1)
require_once $SRC . '/Delivery.php';
require_once $SRC . '/Channels.php';
require_once $SRC . '/Delegation.php'; // EffectNotAuthorized (Streaming::openStream / Guard::open throw it)
require_once $SRC . '/Streaming.php';
require_once $SRC . '/Federation.php'; // Federation::verifyReconcileOrder (reconcile.state "verify" event)

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

/**
 * Resolve the ML-DSA COSE alg id from a corpus op input. The corpus names the parameter set with
 * the string field "param" ("ML-DSA-65" / "ML-DSA-87"), matching the Go/Rust/Python adapters; an
 * explicit integer "alg" (as some ops carry) wins when present. Defaults to ML-DSA-65. Reading a
 * non-existent "alg" was the bug behind mldsa.keygen tc2 (ML-DSA-87 silently ran as ML-DSA-65).
 */
function mldsaAlg(array $in): int
{
    if (isset($in['alg']) && $in['alg'] !== null && $in['alg'] !== '') {
        return (int) $in['alg'];
    }
    return (($in['param'] ?? '') === 'ML-DSA-87') ? MlDsa::ALG_MLDSA87 : MlDsa::ALG_MLDSA65;
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
            // A uint value can reach 2^64-1, beyond signed PHP_INT_MAX; large uints are carried as decimal
            // strings. If the string exceeds PHP_INT_MAX, subtract 2^64 (bcmath) to get the two's-complement
            // bit pattern PHP int / Cbor\U holds -- matching the Java (parseUnsignedLong) and C#
            // ((long)ulong.Parse) adapters. A small value or a bare JSON number is within range.
            return new U(\is_string($p) && \bccomp($p, '9223372036854775807') > 0
                ? (int) \bcsub($p, '18446744073709551616')
                : (int) $p);
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

/** Build a reconcile.state chain/extra Receipt from {prev_hex, obj_hex, seq, at}. */
function reconcileReceiptFrom(array $rm): Receipt
{
    return new Receipt(hx($rm, "prev_hex"), hx($rm, "obj_hex"), u($rm, "seq"), u($rm, "at"));
}

/** Build CausalNode[] from a reconcile.state `nodes` array ({id_hex, causes_hex}). */
function reconcileNodesFrom(array $in): array
{
    $nodes = [];
    foreach (($in["nodes"] ?? []) as $n) {
        $causes = [];
        foreach (($n["causes_hex"] ?? []) as $c) {
            $causes[] = \hex2bin($c);
        }
        $nodes[] = new CausalNode(\hex2bin($n["id_hex"]), $causes);
    }
    return $nodes;
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
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            return ["out" => ["pk_hex" => \bin2hex(MlDsa::keygenFromSeed(hx($in, "seed_hex"), mldsaAlg($in)))]];

        case "ed25519.sign":
            return ["out" => ["sig_hex" => \bin2hex(Cose::ed25519Sign(hx($in, "sk_hex"), hx($in, "msg_hex")))]];

        case "cose.sign1":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            $prot = hx($in, "protected_hex");
            $payload = hx($in, "payload_hex");
            $tbs = Cose::toBeSignedRaw($prot, $payload);
            $sig = MlDsa::sign(hx($in, "seed_hex"), $tbs, mldsaAlg($in));
            return ["out" => ["obj_hex" => \bin2hex(Cose::assembleSign1Raw($prot, $payload, $sig))]];

        case "cose.verify1":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            [$prot, $payload, $sig] = Cose::parseSign1Raw(hx($in, "obj_hex"));
            $tbs = Cose::toBeSignedRaw($prot, $payload);
            return ["out" => ["valid" => MlDsa::verify(hx($in, "pubkey_hex"), $tbs, $sig, mldsaAlg($in))]];

        case "rotation.leg_tbs":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            return ["out" => ["tbs_hex" => \bin2hex(Cose::signatureToBeSigned(hx($in, "body_protected_hex"), (int) $in["leg_alg"], hx($in, "payload_hex")))]];

        case "rotation.sign":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            $prot = hx($in, "protected_hex");
            $payload = hx($in, "payload_hex");
            $oldLeg = Cose::signatureLeg($prot, (int) $in["old_alg"], hx($in, "old_seed_hex"), $payload);
            $newLeg = Cose::signatureLeg($prot, (int) $in["new_alg"], hx($in, "new_seed_hex"), $payload);
            return ["out" => ["obj_hex" => \bin2hex(Cose::assembleSignRaw($prot, $payload, [$oldLeg, $newLeg]))]];

        case "rotation.verify":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            $obj = hx($in, "obj_hex");
            $oldAlg = (int) $in["old_alg"];
            $newAlg = (int) $in["new_alg"];
            $profile = (int) $in["profile"];
            $oldPk = hx($in, "old_pubkey_hex");
            $newPk = hx($in, "new_pubkey_hex");
            $kindOk = static fn (int $ch, int $k): bool => $ch === 3 && $k === 0;
            // dispatch by COSE tag: tag-98 (0xd8 0x62) -> two-leg verifyRotationObject; a tag-18
            // single-sig object -> the general verify, which rejects a (3,0) single-sig rotation.
            try {
                if (\strlen($obj) >= 2 && \ord($obj[0]) === 0xd8 && \ord($obj[1]) === 0x62) {
                    Envelope::verifyRotationObject($profile, $oldAlg, $oldPk, $newAlg, $newPk, $kindOk, $obj);
                } else {
                    Envelope::verify($profile, $newAlg, $newPk, $kindOk, $obj);
                }
                return ["out" => ["valid" => true, "error" => ""]];
            } catch (\Throwable $e) {
                return ["out" => ["valid" => false, "error" => errKind($e, "Malformed")]];
            }

        // R7 decoder resource bounds (T7.1): decode + bound-enforce an untrusted object; all four
        // object-level bounds (TooLarge/DepthExceeded/TooManyCauses/TooManyExtensions) fire BEFORE
        // the COSE signature is checked, so no verifier is ever reached -- the kind validator is
        // permissive (accepts any channel/kind) and the pubkey/alg/profile args are unused on every
        // reject path this op grades.
        case "object.decode":
            $obj = \array_key_exists("over_size", $in)
                ? \str_repeat("\x00", (int) $in["over_size"])
                : hx($in, "obj_hex");
            $kindOk = static fn (int $ch, int $k): bool => true;
            try {
                Envelope::verify(1, 0, "", $kindOk, $obj);
                return ["out" => ["valid" => true, "error" => ""]];
            } catch (\Throwable $e) {
                return ["out" => ["valid" => false, "error" => errKind($e, "Malformed")]];
            }

        case "stream.verify_commit":
            $n = (int) u($in, "chunk_count");
            // n empty chunks; the count bound fires before the digest is ever computed (verifyCommit
            // checks count first), so every entry may safely share one immutable Chunk instance --
            // avoids materializing >1M distinct objects for the over-bound case.
            $chunks = \array_fill(0, $n, new Chunk(0, ""));
            try {
                Streaming::verifyCommit(new StreamCommit("", ""), $chunks);
                return ["out" => ["valid" => true, "error" => ""]];
            } catch (\Throwable $e) {
                return ["out" => ["valid" => false, "error" => errKind($e, "Malformed")]];
            }

        // ---- naalp-error object + numeric error-code registry (design.md §3.5, T3.3) ----
        case "error.name_for_code":
            [$name, $reg] = NaalpError::nameForCode((int) u($in, "code"));
            return ["out" => ["name" => $name, "registered" => $reg]];

        case "error.encode":
            $subject = \array_key_exists("subject_hex", $in) ? hx($in, "subject_hex") : null;
            $detail = (string) ($in["detail"] ?? "");
            $name = (string) ($in["name"] ?? "");
            $body = NaalpError::encode((int) u($in, "code"), $name, $detail, $subject);
            return ["out" => ["body_hex" => \bin2hex($body)]];

        case "error.decode":
            try {
                $eo = NaalpError::decode(hx($in, "body_hex"));
                return ["out" => ["valid" => true, "code" => $eo->code, "name" => $eo->name]];
            } catch (\Throwable $e) {
                return ["out" => ["valid" => false, "error" => errKind($e, "Malformed")]];
            }

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

        // ietf draft "## Approval state machine" (# Object State Machines): build ONE signed approval,
        // then drive it through an ordered `events` list of consume attempts through the REAL composed
        // choke point Approval::consumeApproval on a fresh single-use ledger; report the LAST event's
        // {valid, error} plus the ledger length after it. Graded against the independent, non-circular
        // tools/approval_state_oracle.py (F3). The approver key is a deterministic all-zero-seed Ed25519
        // test key — the signature is verified inside this port, not graded across ports (bytes are not
        // compared for this op). Ed25519 (ext-sodium), not ML-DSA: this port has no deterministic ML-DSA
        // signer on OpenSSL < 3.5, exactly as every other signature-gated surface in this adapter.
        case "approval.state":
            $am = $in["approval"] ?? null;
            if (!\is_array($am)) {
                return ["error" => "approval.state: missing approval object"];
            }
            $a = new ApprovalRecord(
                hx($am, "approves_hex"),
                (string) ($am["approver"] ?? ""),
                u($am, "grant"),
                hx($am, "nonce_hex"),
                u($am, "not_after")
            );
            $seed = \str_repeat("\x00", 32); // deterministic all-zero test approver seed
            $pk = \sodium_crypto_sign_publickey(\sodium_crypto_sign_seed_keypair($seed));
            $sig = Cose::ed25519Sign($seed, $a->bytes());
            $verify = static fn(string $msg, string $s): bool => Cose::ed25519Verify($pk, $msg, $s);

            $walPath = \tempnam(\sys_get_temp_dir(), 'naalp-approval-state-');
            $ledger = Approval::openLedger($walPath);
            try {
                $lastErr = null;
                foreach (($in["events"] ?? []) as $ev) {
                    if (!\is_array($ev)) {
                        return ["error" => "approval.state: event is not an object"];
                    }
                    $kind = (string) ($ev["ev"] ?? "");
                    if ($kind !== "consume") {
                        return ["error" => "approval.state: unknown event " . \var_export($ev["ev"] ?? null, true)];
                    }
                    // present_cid_hex is decoded OUTSIDE the try — a malformed hex field is a
                    // protocol-level adapter fault (matches the Go/Rust adapters), not a machine reaction.
                    $presentCid = hx($ev, "present_cid_hex");
                    $lastErr = null;
                    try {
                        Approval::consumeApproval(
                            $a,
                            $verify,
                            $sig,
                            $presentCid,
                            u($ev, "pos_time"),
                            u($ev, "required_effect"),
                            $ledger,
                            (string) ($ev["by"] ?? "")
                        );
                    } catch (\Throwable $e) {
                        $lastErr = $e;
                    }
                }
                return ["out" => [
                    "valid" => $lastErr === null,
                    "error" => $lastErr === null ? "" : errKind($lastErr, "Malformed"),
                    "ledger_len" => $ledger->len(),
                ]];
            } finally {
                $ledger->close();
                @\unlink($walPath);
            }

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

        case "delivery.state":
            // ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
            // through an ordered `events` list of signed delivery updates on a fresh WAL-backed
            // Tracker; report the LAST event's outcome plus the object's final stage name. A
            // rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
            // Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
            $rawEvents = $in["events"] ?? [];
            $tmpPath = \tempnam(\sys_get_temp_dir(), 'naalp-delivery-state-');
            if ($tmpPath === false) {
                return ["error" => "delivery.state: cannot create temp WAL"];
            }
            $tr = Delivery::openTracker($tmpPath);
            $lastErr = null;
            $lastObj = "";
            foreach ($rawEvents as $em) {
                $obj = hx($em, "obj_hex");
                $lastObj = $obj;
                $ev = (string) ($em["ev"] ?? "");
                if ($ev !== "update") {
                    $tr->close();
                    \unlink($tmpPath);
                    return ["error" => "delivery.state: unknown event " . \var_export($ev, true)];
                }
                $lastErr = null;
                try {
                    $tr->advance($obj, u($em, "stage"), 0);
                } catch (\Throwable $e) {
                    $lastErr = $e;
                }
            }
            [$st, ] = $tr->stage($lastObj);
            $tr->close();
            \unlink($tmpPath);
            return ["out" => [
                "valid" => $lastErr === null,
                "error" => $lastErr === null ? "" : errKind($lastErr, \get_class($lastErr)),
                "state" => Delivery::stageName($st),
            ]];

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

        case "stream.state":
            // design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream
            // through an ordered `events` list on a fresh Guard; report the LAST event's outcome
            // plus the stream's final state. Graded against the independent, non-circular
            // tools/streamstate_oracle.py (F3).
            $rawEvents = $in["events"] ?? [];
            $g = new Guard();
            $lastErr = null;
            $lastStream = "";
            foreach ($rawEvents as $em) {
                $sid = hx($em, "stream_hex");
                $lastStream = $sid;
                $ev = (string) ($em["ev"] ?? "");
                $lastErr = null;
                try {
                    switch ($ev) {
                        case "open":
                            $o = new StreamOpen($sid, u($em, "effect"), null, 0);
                            $g->open($o, u($em, "granted"));
                            break;
                        case "chunk":
                            $g->chunk($sid);
                            break;
                        case "checkpoint":
                            $g->checkpoint($sid);
                            break;
                        case "commit":
                            $rawChunks = $em["chunks"] ?? [];
                            $chunks = [];
                            foreach ($rawChunks as $cm) {
                                $data = \hex2bin((string) ($cm["data_hex"] ?? ""));
                                if ($data === false) {
                                    return ["error" => "stream.state: invalid data_hex"];
                                }
                                $chunks[] = new Chunk((int) ($cm["offset"] ?? 0), $data);
                            }
                            $digest = hx($em, "digest_hex");
                            $g->commit(new StreamCommit($sid, $digest), $chunks);
                            break;
                        case "expire":
                            $g->expire($sid);
                            break;
                        default:
                            return ["error" => "stream.state: unknown event " . \var_export($ev, true)];
                    }
                } catch (\Throwable $e) {
                    $lastErr = $e;
                }
            }
            return ["out" => [
                "valid" => $lastErr === null,
                "error" => $lastErr === null ? "" : errKind($lastErr, \get_class($lastErr)),
                "state" => State::name($g->state($lastStream)),
            ]];

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

        case "reconcile.state":
            // ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine
            // through ONE event (add-chain | linearize | verify) on fresh state and report
            // {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe pipeline (a
            // `chain` that must independently pass VerifyChain, plus an optional `extra` receipt fed
            // only to Observe — a chain array cannot itself carry a duplicate seq without independently
            // tripping ChainBroken, so equivocation is exercised via the separate `extra` observation);
            // linearize runs Federation::reconcile (which calls Graph::verifyCausal internally); verify
            // runs Federation::verifyReconcileOrder, which MUST recompute via Federation::reconcile
            // (content-id tie-break), never a position tie-break. Graded against the independent,
            // non-circular tools/reconcile_state_oracle.py (F3). The authority key is a deterministic
            // all-zero Ed25519 test seed (PURE-ONLY PHP has no deterministic ML-DSA signer) — the
            // signature is verified, not graded (bytes are not compared across ports for this op).
            $seed = \str_repeat("\x00", 32); // deterministic all-zero test authority seed
            $pk = \sodium_crypto_sign_publickey(\sodium_crypto_sign_seed_keypair($seed));
            $verify = static fn(string $msg, string $sig): bool => Cose::ed25519Verify($pk, $msg, $sig);

            $event = (string) ($in["event"] ?? "");
            switch ($event) {
                case "add-chain":
                    $rawChain = $in["chain"] ?? [];
                    $receipts = [];
                    $sigs = [];
                    foreach ($rawChain as $rm) {
                        $r = reconcileReceiptFrom($rm);
                        $receipts[] = $r;
                        $sigs[] = Cose::ed25519Sign($seed, $r->bytes());
                    }
                    if (isset($in["corrupt_sig_at"]) && $in["corrupt_sig_at"] !== null) {
                        $idx = (int) $in["corrupt_sig_at"];
                        $s = $sigs[$idx];
                        $s[0] = $s[0] ^ "\xFF";
                        $sigs[$idx] = $s;
                    }
                    // Auditor::observe signals equivocation by RETURNING a non-null ForkProof (not by
                    // throwing) — distinct from verifyChain, which throws ChainBroken/ReceiptUnsigned.
                    $lastErrKind = "";
                    try {
                        Audit::verifyChain($receipts, $sigs, $verify);
                        $auditor = new Auditor($verify, $pk);
                        $equivocated = false;
                        foreach ($receipts as $i => $r) {
                            if ($auditor->observe($r, $sigs[$i]) !== null) {
                                $equivocated = true;
                                break;
                            }
                        }
                        if (!$equivocated && isset($in["extra"]) && \is_array($in["extra"])) {
                            $er = reconcileReceiptFrom($in["extra"]);
                            $esig = Cose::ed25519Sign($seed, $er->bytes());
                            if ($auditor->observe($er, $esig) !== null) {
                                $equivocated = true;
                            }
                        }
                        if ($equivocated) {
                            $lastErrKind = "Equivocation";
                        }
                    } catch (\Throwable $e) {
                        $lastErrKind = errKind($e, \get_class($e));
                    }
                    return ["out" => [
                        "valid" => $lastErrKind === "",
                        "error" => $lastErrKind,
                    ]];

                case "linearize":
                    $nodes = reconcileNodesFrom($in);
                    try {
                        Federation::reconcile($nodes);
                        return ["out" => ["valid" => true, "error" => ""]];
                    } catch (\Throwable $e) {
                        return ["out" => ["valid" => false, "error" => errKind($e, \get_class($e))]];
                    }

                case "verify":
                    $nodes = reconcileNodesFrom($in);
                    $order = [];
                    foreach (($in["claimed_order_hex"] ?? []) as $o) {
                        $order[] = \hex2bin($o);
                    }
                    $rec = new ReconcileRecord([], $order);
                    try {
                        Federation::verifyReconcileOrder($rec, $nodes);
                        return ["out" => ["valid" => true, "error" => ""]];
                    } catch (\Throwable $e) {
                        return ["out" => ["valid" => false, "error" => errKind($e, \get_class($e))]];
                    }

                default:
                    return ["error" => "reconcile.state: unknown event " . \var_export($event, true)];
            }

        // ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
        case "composite.mprime":
            return ["out" => ["mprime_hex" => \bin2hex(Cose::computeMprime("COMPSIG-MLDSA65-Ed25519-SHA512", "", hx($in, "m_hex")))]];

        case "composite.signerid":
            try {
                return ["out" => ["signer_id" => Identity::compositeSignerId((int) $in["mldsa_alg"], hx($in, "mldsa_pubkey_hex"), hx($in, "ed_pubkey_hex"))]];
            } catch (\Throwable $e) {
                return ["error" => errKind($e, "UnknownAlg") . ": " . $e->getMessage()];
            }

        case "composite.sign":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            return ["out" => ["value_hex" => \bin2hex(Cose::compositeSign(hx($in, "mldsa_seed_hex"), hx($in, "ed_seed_hex"), hx($in, "tbs_hex")))]];

        case "composite.verify":
            if (!MlDsa::available()) { return ["skipped" => MlDsa::unavailableReason()]; }
            return ["out" => ["valid" => Cose::compositeVerify(hx($in, "mldsa_pubkey_hex"), hx($in, "ed_pubkey_hex"), hx($in, "m_hex"), hx($in, "sig_hex"))]];

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
