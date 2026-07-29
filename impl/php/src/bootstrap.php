<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * bootstrap.php — require the PHP N-AALP SDK source files in dependency order.
 *
 * The SDK carries no runtime dependency and, by design, works without Composer: a caller may
 * `require_once __DIR__ . '/src/bootstrap.php'` (or use the Composer classmap autoloader declared
 * in composer.json). The load order mirrors the C1..C4 spine so that each file's referenced value
 * classes are already defined.
 */

declare(strict_types=1);

require_once __DIR__ . '/Cbor.php';
require_once __DIR__ . '/Cose.php';
require_once __DIR__ . '/Identity.php';
require_once __DIR__ . '/Policy.php';
require_once __DIR__ . '/Records.php';
require_once __DIR__ . '/Graph.php';
require_once __DIR__ . '/Channels.php';
require_once __DIR__ . '/Envelope.php';
require_once __DIR__ . '/Naalp.php';
