<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP PHP SDK — Quickstart

A reference implementation of the N-AALP (draft-bubblefish-naalp-00) spine in PHP (8.1+),
byte-identical to the Python, Go, and Rust reference implementations. Namespace `Naalp`.
Composer package `bubblefish/naalp`.

## Requirements

- **PHP 8.1+** (CLI).
- **ext-sodium** — bundled with PHP; used for deterministic Ed25519 (RFC 8032).
- **ext-intl** — bundled with PHP; used for Unicode NFC checks (`Normalizer`).

On a stock Windows PHP build these two extensions ship as `ext/php_sodium.dll` and
`ext/php_intl.dll` but may not be enabled in `php.ini`. Enable them either in `php.ini`
(`extension=sodium`, `extension=intl`) or per-invocation:

```sh
php -d extension=sodium -d extension=intl your_script.php
```

## Layout

```
impl/php/src/
  Cbor.php       deterministic CBOR (RFC 8949 §4.2.1) encode + strict canonical decode + content_id
  Cose.php       COSE_Sign1 (RFC 9052) ToBeSigned / assembly / parse; deterministic Ed25519
  Identity.php   self-certifying signer id (multiformats PeerHandle) + NFC rule
  Policy.php     the closed four-value effect set, the §6.1 authorization lattice, safety label
  Records.php    approval/ledger/receipt/delivery/stream/carriage bodies + transport boundary
  Graph.php      causal verify + deterministic federation reconcile + reconcile record
  Channels.php   the frozen 20-channel / 65-kind registry with declared effects
  Envelope.php   the full object envelope (NaalpObject + contentId/buildPayload/protectedHeader/
                 toBeSigned/assembleSigned + structural verify)
  Naalp.php      the one-import facade (`Naalp\Naalp`) over the object surface
  bootstrap.php  require the SDK files in dependency order
```

There is no Composer dependency; the classes are plain PSR-agnostic files. Pull the whole SDK in
with one require (or use the Composer classmap autoloader in `composer.json`):

```php
require 'impl/php/src/bootstrap.php';       // loads Cbor..Channels, Envelope, and the Naalp facade
```

## Use

```php
<?php
require 'impl/php/src/Cbor.php';
require 'impl/php/src/Policy.php';

use Naalp\Cbor;
use Naalp\Policy;
use Naalp\U;
use Naalp\T;
use Naalp\M;

// deterministic CBOR — canonical map ordering regardless of insertion order
$bytes = Cbor::encode(new M([
    [new U(2), new T("world")],
    [new U(1), new U(42)],
]));
echo bin2hex($bytes), "\n";        // a2012a0265776f726c64

// content id = 0x2030 || SHA-384(body)
echo bin2hex(Cbor::contentId($bytes)), "\n";

// effect vocabulary: unknown values fail closed to destructive (3)
echo Policy::normalizeEffect(9), "\n";                 // 3
var_dump(Policy::authorizes(2, 1));                    // true (action 1 <= ceiling 2)
```

```php
use Naalp\Cose;

// deterministic Ed25519 (RFC 8032) — seed is the 32-byte private seed
$sig = Cose::ed25519Sign(hex2bin('9d61b19d...'), $msg);
```

## Sign and verify a full object

The `Naalp\Naalp` facade is the one-import object surface. PHP's from-key signing leg is Ed25519
(see Crypto scope); the round-trip is checked at the COSE signature layer:

```php
require 'impl/php/src/bootstrap.php';

use Naalp\Naalp;
use Naalp\Cose;
use Naalp\U;
use Naalp\T;
use Naalp\M;

$seed = str_repeat("\x2a", 32);                       // a real 32-byte key seed in production
$pk   = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
$sid  = Naalp::signerId(Naalp::ALG_ED25519, $pk);

$obj = Naalp::object(
    kind: 1, channel: 4, signer: $sid, created: 1785000000000,
    effect: 2, body: new M([[new U(1), new T("hello")]]),
    profile: Naalp::PROFILE_PUBLIC,
);

$signed = Naalp::signWithEd25519($obj, $seed);        // a real, tagged COSE_Sign1 object

// The Ed25519 signature round-trips at the COSE layer:
[$prot, $payload, $sig] = Cose::parseSign1Raw($signed);
$ok = Cose::ed25519Verify($pk, Cose::toBeSignedRaw($prot, $payload), $sig);   // true
```

Every failure is a fail-closed `Naalp\EnvelopeError` (or a `Cbor` `NonCanonical`) carrying a stable
`->kind` (`ContentIdMismatch`, `HeaderBodyMismatch`, `ProfileDowngrade`, `BadSignature`, …).

**On the profile floor.** N-AALP floors *every* profile at ML-DSA strength (level ≥ 3; Sovereign at
5), and Ed25519 is level 0 — so `Naalp::verify` deliberately **rejects** a pure-Ed25519 object at
`ProfileDowngrade` (Ed25519 is valid only as a hybrid leg). A production object carries an ML-DSA
signature: build it, take `Naalp::toBeSigned($prot, $payload)`, have an external FIPS 204 signer
sign those exact bytes, then `Naalp::assembleSigned(...)`. `Naalp::verify` then runs every
structural + policy check and passes (PHP does not re-check the ML-DSA signature itself — PURE-ONLY).

## Crypto scope (PURE-ONLY)

PHP has **no deterministic (rnd=0) ML-DSA signing path**: liboqs and OpenSSL 3.5 ML-DSA signing
are randomized-only, and no PHP binding exposes a deterministic seed→public-key ML-DSA keygen.
Therefore this SDK implements **Ed25519 only** on the crypto leg. In the conformance adapter the
ML-DSA-dependent operations (`mldsa.keygen`, `cose.sign1`, `cose.verify1`) return an honest
`skipped`; every pure operation and `ed25519.sign` are fully implemented and graded.

## Conformance

The adapter at `harness/adapters/php/adapter.php` grades this SDK against the shared corpus:

```sh
./harness/runner/naalp-conform.exe run \
  --testee "php -d extension=sodium -d extension=intl harness/adapters/php/adapter.php"
```

Result: **PASS (235 graded, 4 unimplemented/skipped)** — the 4 skips are the ML-DSA-dependent
crypto operations, which are Unimplemented for PHP by design, not failures.
