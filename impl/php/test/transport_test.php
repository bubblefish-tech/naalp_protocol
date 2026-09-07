<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C11 transport-binding conformance for the PHP SDK, graded against the shared independent corpus
// vectors/transport/cases.json (NOT produced by this code): the media type, the four bindings'
// confidentiality/peer-auth guarantees, the framing round-trip, and the §12.3/§12.4 emit-boundary
// matrix. Every property below is a PURE deterministic assertion (no crypto), so all of transport
// is corpus-graded on the pure PHP port.
//
// Written test-first: the Naalp\Transport class is absent until Transport.php lands, so this fails
// RED with a fatal "class not found" on the first reference; a mutation to the emit boundary flips
// the "emit ... websocket+ws sensitive" check.
//
// Run:  php -d extension=sodium -d extension=intl test/transport_test.php   (from impl/php/)
require __DIR__ . '/../src/bootstrap.php';

use Naalp\Transport;
use Naalp\TransportError;

$fails = 0;
function check(string $name, string $got, string $want): void
{
    global $fails;
    if ($got === $want) {
        echo "  ok   $name\n";
    } else {
        $fails++;
        echo "  FAIL $name\n       got  $got\n       want $want\n";
    }
}

/** Walk up from this dir to the repository's shared corpus (the independent oracle). */
function transport_vectors(): array
{
    $d = __DIR__;
    for ($i = 0; $i < 6; $i++) {
        $p = $d . '/vectors/transport/cases.json';
        if (is_file($p)) {
            return json_decode(file_get_contents($p), true, 512, JSON_THROW_ON_ERROR);
        }
        $d = dirname($d);
    }
    throw new RuntimeException("vectors/transport/cases.json not found");
}

$C = transport_vectors();
echo "transport conformance (PHP) — graded vs vectors/transport/cases.json\n";

// 1. media type is the one-object-per-representation N-AALP type (§12.1).
check("media type", Transport::MEDIA_TYPE, $C["media_type"]);

// 2. every transport variant's confidentiality/peer-auth guarantees == the oracle.
foreach ($C["transports"] as $t) {
    $got = Transport::byName($t["name"]);
    check("variant present: " . $t["name"], $got === null ? "absent" : "present", "present");
    if ($got !== null) {
        check(
            "variant guarantees: " . $t["name"],
            ($got->confidential ? "1" : "0") . ($got->peerAuthenticated ? "1" : "0"),
            ($t["confidential"] ? "1" : "0") . ($t["peer_authenticated"] ? "1" : "0"),
        );
    }
}

// 3. framing round-trips the object bytes verbatim; the media type is the N-AALP type (R-13.2).
$np = Transport::byName("npamp");
$mu = Transport::frame($np, "\x01\x02\x03");
check("frame media type", $mu->mediaType, Transport::MEDIA_TYPE);
check("frame roundtrip object", bin2hex($mu->object()), "010203");

// 4. a message unit with a wrong media type is rejected Malformed (fail-closed).
$bad = new \Naalp\MessageUnit("npamp", "application/json", "x");
$got = "no-error";
try {
    $bad->object();
} catch (TransportError $e) {
    $got = $e->kind;
}
check("wrong media type rejected", $got, "Malformed");

// 5. the §12.3 confidentiality / §12.4 peer-auth emit-boundary matrix == the oracle, row by row.
foreach ($C["emit_matrix"] as $c) {
    $t = Transport::byName($c["transport"]);
    $label = sprintf(
        "emit %s sensitive=%s peer=%s",
        $c["transport"],
        $c["sensitive"] ? "1" : "0",
        $c["require_peer_auth"] ? "1" : "0",
    );
    $result = "no-error";
    try {
        $emitted = Transport::emit($t, "obj", $c["sensitive"], $c["require_peer_auth"]);
        // on success the framed unit must carry the object bytes unchanged.
        $result = ($emitted->object() === "obj") ? "ok" : "framed-wrong-bytes";
    } catch (TransportError $e) {
        $result = $e->kind;
    }
    check($label, $result, $c["result"]);
}

echo ($fails === 0 ? "PASS" : "FAIL ($fails)") . "\n";
exit($fails === 0 ? 0 : 1);
