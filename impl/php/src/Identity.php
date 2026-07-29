<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C4 identity for the PHP SDK: the self-certifying signer id (§5.1) and the NFC rule.
 *
 * signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
 * identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats
 * registry: ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.
 * base32 is RFC 4648 lowercase, no padding, with the multibase 'b' prefix.
 */

declare(strict_types=1);

namespace Naalp;

class UnknownAlg extends \RuntimeException
{
    public string $kind = "UnknownAlg";
}

class SignerMismatch extends \RuntimeException
{
    public string $kind = "SignerMismatch";
}

class NonNFC extends \RuntimeException
{
    public string $kind = "NonNFC";
}

final class Identity
{
    private const MULTICODEC = [
        Cose::ALG_ED25519 => 0xED,
        Cose::ALG_MLDSA65 => 0x1211,
        Cose::ALG_MLDSA87 => 0x1212,
    ];
    private const MH_SHA256 = 0x12;

    /** LEB128 unsigned varint (multiformats). */
    private static function uvarint(int $n): string
    {
        $out = "";
        while (true) {
            $b = $n & 0x7F;
            $n >>= 7;
            if ($n) {
                $out .= \chr($b | 0x80);
            } else {
                $out .= \chr($b);
                return $out;
            }
        }
    }

    /** RFC 4648 base32 lowercase, no padding. */
    private static function base32LowerNoPad(string $data): string
    {
        $alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        $out = "";
        $buffer = 0;
        $bits = 0;
        $len = \strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $buffer = ($buffer << 8) | \ord($data[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) {
            $out .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }
        return $out;
    }

    /** Compute the signer id (multiformats PeerHandle form) for an alg + raw public key. */
    public static function signerId(int $alg, string $pubkey): string
    {
        if (!\array_key_exists($alg, self::MULTICODEC)) {
            throw new UnknownAlg("no multicodec for alg " . $alg);
        }
        $tagged = self::uvarint(self::MULTICODEC[$alg]) . $pubkey;
        $digest = \hash('sha256', $tagged, true);
        $mh = self::uvarint(self::MH_SHA256) . self::uvarint(\strlen($digest)) . $digest;
        return "b" . self::base32LowerNoPad($mh);
    }

    public static function checkSigner(string $claimed, int $alg, string $pubkey): void
    {
        if (self::signerId($alg, $pubkey) !== $claimed) {
            throw new SignerMismatch("signer id does not recompute from the key");
        }
    }

    /** Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3). */
    public static function requireNfc(string $s): void
    {
        $nfc = \Normalizer::normalize($s, \Normalizer::FORM_C);
        if ($nfc !== $s) {
            throw new NonNFC("string is not Unicode NFC");
        }
    }
}
