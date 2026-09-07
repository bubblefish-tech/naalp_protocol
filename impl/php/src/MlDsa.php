<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * MlDsa.php — deterministic (FIPS 204, rnd=0) ML-DSA-65/87 for the PHP N-AALP SDK, via PHP-FFI to an
 * OpenSSL >= 3.5 libcrypto. It performs keygen from a 32-byte seed (xi), a pure-ML-DSA signature with
 * per-message randomness forced to 32 zero bytes (deterministic=1), and verification — byte-identical
 * to the Go (cloudflare/circl), Rust (fips204) and Python (dilithium-py) FIPS 204 consensus, which the
 * conformance corpus grades against NIST ACVP.
 *
 * The FFI surface used: EVP_PKEY_fromdata with the OSSL_PKEY_PARAM_ML_DSA_SEED ("seed") octet-string
 * param for keygen; EVP_PKEY_sign_message_init with OSSL_SIGNATURE_PARAM_DETERMINISTIC=1 and the
 * defaults message-encoding=1 (Pure ML-DSA), empty context-string, mu=0 (raw message) for signing;
 * EVP_PKEY_verify_message_init / EVP_PKEY_verify for verification.
 *
 * AVAILABILITY: requires the PHP `ffi` extension enabled AND a reachable OpenSSL >= 3.5 libcrypto
 * (bundled beside php on Windows; system libcrypto.so.3 on Linux; openssl@3 on macOS). Where either is
 * absent, self::available() is false and the adapter returns an honest `skipped` — never a false green.
 * Set the NAALP_LIBCRYPTO env var to point at a specific libcrypto if auto-discovery does not find one.
 *
 * The from-scratch-free path (binding an audited FIPS 204 implementation) is deliberate: it inherits
 * OpenSSL's ACVP-validated ML-DSA rather than re-implementing the lattice math. It is NOT constant-time
 * hardened beyond what OpenSSL provides; that is acceptable for a conformance reference SDK.
 */

declare(strict_types=1);

namespace Naalp;

final class MlDsa
{
    public const ALG_MLDSA65 = -49;
    public const ALG_MLDSA87 = -50;

    private const OSSL_PARAM_INTEGER = 1;
    private const OSSL_PARAM_OCTET_STRING = 5;
    private const EVP_PKEY_PUBLIC_KEY = 0x86;
    private const EVP_PKEY_KEYPAIR = 0x87;
    private const OPENSSL_3_5_0 = 0x30500000;

    /** @var \FFI|null resolved lazily; null once resolution has failed (reason in self::$why). */
    private static $ffi = null;
    private static ?string $why = null;

    private const CDEF = <<<'C'
typedef struct ossl_param_st { const char *key; unsigned int data_type; void *data; size_t data_size; size_t return_size; } OSSL_PARAM;
unsigned long OpenSSL_version_num(void);
void *EVP_PKEY_CTX_new_from_name(void *libctx, const char *name, const char *propquery);
int EVP_PKEY_fromdata_init(void *ctx);
int EVP_PKEY_fromdata(void *ctx, void **ppkey, int selection, OSSL_PARAM *params);
void *EVP_PKEY_CTX_new_from_pkey(void *libctx, void *pkey, const char *propquery);
void *EVP_SIGNATURE_fetch(void *libctx, const char *algorithm, const char *properties);
int EVP_PKEY_sign_message_init(void *ctx, void *algo, OSSL_PARAM *params);
int EVP_PKEY_sign(void *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_message_init(void *ctx, void *algo, OSSL_PARAM *params);
int EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_get_octet_string_param(const void *pkey, const char *k, unsigned char *buf, size_t max, size_t *out);
void EVP_PKEY_free(void *pkey);
void EVP_PKEY_CTX_free(void *ctx);
void EVP_SIGNATURE_free(void *s);
unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);
C;

    /** @return array{0:string,1:int,2:int} [OpenSSL name, public-key bytes, signature bytes] */
    private static function paramsFor(int $alg): array
    {
        switch ($alg) {
            case self::ALG_MLDSA65: return ["ML-DSA-65", 1952, 3309];
            case self::ALG_MLDSA87: return ["ML-DSA-87", 2592, 4627];
            default: throw new \RuntimeException("unknown ML-DSA alg $alg");
        }
    }

    /** Portable libcrypto search list — NEVER a hardcoded absolute build path. */
    private static function candidates(): array
    {
        $c = [];
        $env = \getenv('NAALP_LIBCRYPTO');
        if ($env !== false && $env !== '') { $c[] = $env; }
        $bin = \defined('PHP_BINARY') && \PHP_BINARY !== '' ? \dirname(\PHP_BINARY) : '';
        if (\PHP_OS_FAMILY === 'Windows') {
            foreach (['libcrypto-3-x64.dll', 'libcrypto-3.dll'] as $n) {
                if ($bin !== '') { $c[] = $bin . \DIRECTORY_SEPARATOR . $n; }
                $c[] = $n; // on PATH
            }
        } elseif (\PHP_OS_FAMILY === 'Darwin') {
            $c[] = 'libcrypto.3.dylib';
            $c[] = 'libcrypto.dylib';
            foreach (['/opt/homebrew/opt/openssl@3/lib', '/usr/local/opt/openssl@3/lib', '/usr/local/lib', '/usr/lib'] as $d) {
                $c[] = "$d/libcrypto.3.dylib";
            }
        } else { // Linux / BSD
            $c[] = 'libcrypto.so.3';
            $c[] = 'libcrypto.so';
            foreach (['/usr/lib/x86_64-linux-gnu', '/usr/lib64', '/usr/lib', '/usr/local/lib', '/lib/x86_64-linux-gnu'] as $d) {
                $c[] = "$d/libcrypto.so.3";
            }
        }
        return $c;
    }

    /** Resolve (once) an FFI handle to a libcrypto that has ML-DSA, or null with a reason. */
    private static function ffi(): ?\FFI
    {
        if (self::$ffi !== null) { return self::$ffi; }
        if (self::$why !== null) { return null; }
        if (!\extension_loaded('ffi')) { self::$why = 'the PHP ffi extension is not enabled'; return null; }
        foreach (self::candidates() as $lib) {
            try {
                $ffi = \FFI::cdef(self::CDEF, $lib);
                if ($ffi->OpenSSL_version_num() < self::OPENSSL_3_5_0) { continue; } // need >= 3.5.0
                $ctx = $ffi->EVP_PKEY_CTX_new_from_name(null, "ML-DSA-65", null);
                if (\FFI::isNull($ctx)) { continue; }
                $ffi->EVP_PKEY_CTX_free($ctx);
            } catch (\Throwable $e) {
                continue;
            }
            self::$ffi = $ffi;
            return $ffi;
        }
        self::$why = 'no OpenSSL >= 3.5 libcrypto with ML-DSA is reachable via FFI';
        return null;
    }

    public static function available(): bool { return self::ffi() !== null; }

    public static function unavailableReason(): string { self::ffi(); return self::$why ?? 'unknown'; }

    private static function need(): \FFI
    {
        $ffi = self::ffi();
        if ($ffi === null) { throw new \RuntimeException("ML-DSA unavailable: " . self::unavailableReason()); }
        return $ffi;
    }

    private static function fail(\FFI $ffi, string $where): void
    {
        $e = $ffi->ERR_get_error();
        $buf = $ffi->new('char[256]');
        if ($e) { $ffi->ERR_error_string($e, $buf); }
        throw new \RuntimeException("ML-DSA $where failed: " . ($e ? \FFI::string($buf) : '(no openssl error)'));
    }

    private static function cstr(\FFI $ffi, string $s)
    {
        $n = \strlen($s) + 1;
        $c = $ffi->new("char[$n]", false);
        \FFI::memcpy($c, $s . "\0", $n);
        return $c;
    }

    /** Build an EVP_PKEY (KEYPAIR from a 32-byte seed, or PUBLIC_KEY from a raw pk). Caller frees it. */
    private static function pkeyFromData(\FFI $ffi, string $name, string $paramKey, string $bytes, int $selection)
    {
        $ctx = $ffi->EVP_PKEY_CTX_new_from_name(null, $name, null);
        if (\FFI::isNull($ctx)) { self::fail($ffi, "ctx($name)"); }
        try {
            if ($ffi->EVP_PKEY_fromdata_init($ctx) <= 0) { self::fail($ffi, "fromdata_init"); }
            $len = \strlen($bytes);
            $bb = $ffi->new("unsigned char[$len]", false);
            \FFI::memcpy($bb, $bytes, $len);
            $kn = self::cstr($ffi, $paramKey);
            $p = $ffi->new("OSSL_PARAM[2]", false); // element [1] stays zeroed = OSSL_PARAM_END
            $p[0]->key = $ffi->cast("char*", \FFI::addr($kn[0]));
            $p[0]->data_type = self::OSSL_PARAM_OCTET_STRING;
            $p[0]->data = $ffi->cast("void*", \FFI::addr($bb[0]));
            $p[0]->data_size = $len;
            $pp = $ffi->new("void*[1]", false);
            if ($ffi->EVP_PKEY_fromdata($ctx, $pp, $selection, $p) <= 0) { self::fail($ffi, "fromdata($paramKey)"); }
            if (\FFI::isNull($pp[0])) { self::fail($ffi, "fromdata($paramKey) null"); }
            return $pp[0];
        } finally {
            $ffi->EVP_PKEY_CTX_free($ctx);
        }
    }

    /** Public key (raw FIPS 204 serialization) derived deterministically from a 32-byte seed. */
    public static function keygenFromSeed(string $seed, int $alg): string
    {
        $ffi = self::need();
        [$name, $pklen] = self::paramsFor($alg);
        if (\strlen($seed) !== 32) { throw new \RuntimeException("ML-DSA seed must be 32 bytes, got " . \strlen($seed)); }
        $pkey = self::pkeyFromData($ffi, $name, "seed", $seed, self::EVP_PKEY_KEYPAIR);
        try {
            $buf = $ffi->new("unsigned char[$pklen]", false);
            $ol = $ffi->new("size_t", false);
            if ($ffi->EVP_PKEY_get_octet_string_param($pkey, "pub", $buf, $pklen, \FFI::addr($ol)) <= 0) { self::fail($ffi, "get pub"); }
            return \FFI::string($buf, (int) $ol->cdata);
        } finally {
            $ffi->EVP_PKEY_free($pkey);
        }
    }

    /**
     * Deterministic (rnd=0) pure-ML-DSA signature over $tbs, key derived from the 32-byte seed.
     * $context (default empty) sets the FIPS 204 context string (OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
     * the opt-in LAMPS composite (design.md §4.2) signs the ML-DSA leg with context = the suite Label.
     */
    public static function sign(string $seed, string $tbs, int $alg, string $context = ""): string
    {
        $ffi = self::need();
        [$name, , $siglen] = self::paramsFor($alg);
        if (\strlen($seed) !== 32) { throw new \RuntimeException("ML-DSA seed must be 32 bytes, got " . \strlen($seed)); }
        $pkey = self::pkeyFromData($ffi, $name, "seed", $seed, self::EVP_PKEY_KEYPAIR);
        $sctx = null; $sig_alg = null;
        try {
            $sctx = $ffi->EVP_PKEY_CTX_new_from_pkey(null, $pkey, null);
            if (\FFI::isNull($sctx)) { self::fail($ffi, "ctx_from_pkey"); }
            $sig_alg = $ffi->EVP_SIGNATURE_fetch(null, $name, null);
            if (\FFI::isNull($sig_alg)) { self::fail($ffi, "signature_fetch"); }
            $one = $ffi->new("int", false); $one->cdata = 1;
            $dn = self::cstr($ffi, "deterministic");
            $hasCtx = $context !== "";
            $np = $hasCtx ? 3 : 2;
            $sp = $ffi->new("OSSL_PARAM[$np]", false);
            $sp[0]->key = $ffi->cast("char*", \FFI::addr($dn[0]));
            $sp[0]->data_type = self::OSSL_PARAM_INTEGER;
            $sp[0]->data = $ffi->cast("void*", \FFI::addr($one));
            $sp[0]->data_size = 4;
            if ($hasCtx) {
                // OSSL_SIGNATURE_PARAM_CONTEXT_STRING = "context-string" (octet string); buffers below
                // stay alive for the whole function scope (owned=false), so they remain valid through sign.
                $cn = self::cstr($ffi, "context-string");
                $clen = \strlen($context);
                $cb = $ffi->new("unsigned char[$clen]", false); \FFI::memcpy($cb, $context, $clen);
                $sp[1]->key = $ffi->cast("char*", \FFI::addr($cn[0]));
                $sp[1]->data_type = self::OSSL_PARAM_OCTET_STRING;
                $sp[1]->data = $ffi->cast("void*", \FFI::addr($cb[0]));
                $sp[1]->data_size = $clen;
            }
            if ($ffi->EVP_PKEY_sign_message_init($sctx, $sig_alg, $sp) <= 0) { self::fail($ffi, "sign_message_init"); }
            $tlen = \strlen($tbs);
            $tb = $ffi->new("unsigned char[$tlen]", false); \FFI::memcpy($tb, $tbs, $tlen);
            $sl = $ffi->new("size_t", false); $sl->cdata = $siglen;
            $sg = $ffi->new("unsigned char[$siglen]", false);
            if ($ffi->EVP_PKEY_sign($sctx, $sg, \FFI::addr($sl), $tb, $tlen) <= 0) { self::fail($ffi, "sign"); }
            return \FFI::string($sg, (int) $sl->cdata);
        } finally {
            if ($sig_alg !== null && !\FFI::isNull($sig_alg)) { $ffi->EVP_SIGNATURE_free($sig_alg); }
            if ($sctx !== null && !\FFI::isNull($sctx)) { $ffi->EVP_PKEY_CTX_free($sctx); }
            $ffi->EVP_PKEY_free($pkey);
        }
    }

    /**
     * Verify a pure-ML-DSA signature over $tbs against a raw public key. $context (default empty) sets
     * the FIPS 204 context string; the composite (§4.2) verifies its ML-DSA leg with context = Label.
     */
    public static function verify(string $pk, string $tbs, string $sig, int $alg, string $context = ""): bool
    {
        $ffi = self::need();
        [$name, $pklen] = self::paramsFor($alg);
        if (\strlen($pk) !== $pklen) { throw new \RuntimeException("$name public key must be $pklen bytes, got " . \strlen($pk)); }
        $pkey = self::pkeyFromData($ffi, $name, "pub", $pk, self::EVP_PKEY_PUBLIC_KEY);
        $vctx = null; $sig_alg = null;
        try {
            $vctx = $ffi->EVP_PKEY_CTX_new_from_pkey(null, $pkey, null);
            if (\FFI::isNull($vctx)) { self::fail($ffi, "ctx_from_pkey"); }
            $sig_alg = $ffi->EVP_SIGNATURE_fetch(null, $name, null);
            if (\FFI::isNull($sig_alg)) { self::fail($ffi, "signature_fetch"); }
            $vp = null;
            if ($context !== "") {
                $cn = self::cstr($ffi, "context-string");
                $clen = \strlen($context);
                $cb = $ffi->new("unsigned char[$clen]", false); \FFI::memcpy($cb, $context, $clen);
                $vp = $ffi->new("OSSL_PARAM[2]", false);
                $vp[0]->key = $ffi->cast("char*", \FFI::addr($cn[0]));
                $vp[0]->data_type = self::OSSL_PARAM_OCTET_STRING;
                $vp[0]->data = $ffi->cast("void*", \FFI::addr($cb[0]));
                $vp[0]->data_size = $clen;
            }
            if ($ffi->EVP_PKEY_verify_message_init($vctx, $sig_alg, $vp) <= 0) { self::fail($ffi, "verify_message_init"); }
            $slen = \strlen($sig); $tlen = \strlen($tbs);
            $sg = $ffi->new("unsigned char[$slen]", false); \FFI::memcpy($sg, $sig, $slen);
            $tb = $ffi->new("unsigned char[$tlen]", false); \FFI::memcpy($tb, $tbs, $tlen);
            return $ffi->EVP_PKEY_verify($vctx, $sg, $slen, $tb, $tlen) === 1;
        } finally {
            if ($sig_alg !== null && !\FFI::isNull($sig_alg)) { $ffi->EVP_SIGNATURE_free($sig_alg); }
            if ($vctx !== null && !\FFI::isNull($vctx)) { $ffi->EVP_PKEY_CTX_free($vctx); }
            $ffi->EVP_PKEY_free($pkey);
        }
    }
}
