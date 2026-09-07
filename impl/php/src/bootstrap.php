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

require_once __DIR__ . '/WireConstants.php'; // generated wire constants (no dependencies; Envelope aliases them)
require_once __DIR__ . '/Cbor.php';
require_once __DIR__ . '/NaalpError.php'; // C0 error object + code registry (needs Cbor only; T3.3)
require_once __DIR__ . '/Cose.php';
require_once __DIR__ . '/MlDsa.php';  // deterministic ML-DSA via PHP-FFI to OpenSSL >= 3.5 (no deps)
require_once __DIR__ . '/Identity.php';
require_once __DIR__ . '/Hazard.php';       // Manufacturing Add-ons Component F (needs Cbor, Identity for NFC)
require_once __DIR__ . '/Policy.php';
require_once __DIR__ . '/Records.php';
require_once __DIR__ . '/Graph.php';
require_once __DIR__ . '/Channels.php';
require_once __DIR__ . '/Envelope.php';
require_once __DIR__ . '/Transport.php';
require_once __DIR__ . '/Federation.php';
require_once __DIR__ . '/Gateway.php';
require_once __DIR__ . '/Audit.php';       // C7 audit (needs Cbor, Cose, Graph)
require_once __DIR__ . '/Approval.php';    // C6 approval + single-use consume ledger (needs Cbor, Cose, Records)
require_once __DIR__ . '/Delivery.php';    // C8 delivery (needs Cbor, Cose, Audit)
require_once __DIR__ . '/Payment.php';     // C21 payment import (needs Cbor, Cose, Policy)
require_once __DIR__ . '/Continuation.php'; // C17 flow continuation (needs Cbor, Cose, Policy)
require_once __DIR__ . '/Delegation.php';   // C15 multi-hop delegation (needs Channels, Envelope, Identity, Policy, Approval)
require_once __DIR__ . '/Agui.php';          // C21 NAALP-AGUI UI-consent binding (needs Cbor, Cose, Approval, Policy)
require_once __DIR__ . '/Description.php';   // C18 signed description/directory/import (needs Cbor, Cose, Policy, Identity, Gateway errors)
require_once __DIR__ . '/Mcp.php';           // NAALP-MCP binding profile (needs Cbor, Cose, Policy, Identity, Channels, Envelope, Approval)
require_once __DIR__ . '/Rooms.php';         // rooms/membership tier-1 (needs Audit, Envelope, Identity, Channels, Policy)
require_once __DIR__ . '/Naming.php';        // C19 name bindings + signed A2A task-state profile (needs Cbor, Cose, Gateway BadSignature)
require_once __DIR__ . '/Negotiation.php';   // C20 governed negotiation + risk labels + trust refs (needs Cbor, Cose, Policy)
require_once __DIR__ . '/Streaming.php';     // C9 native streaming commitment (needs Cbor, Cose, Policy, Delegation EffectNotAuthorized)
require_once __DIR__ . '/Carriage.php';      // C12 foreign carriage by class (needs Cbor, Envelope, Records MappingError)
require_once __DIR__ . '/Naalp.php';
