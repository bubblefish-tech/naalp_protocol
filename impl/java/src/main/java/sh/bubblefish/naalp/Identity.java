// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;

/**
 * N-AALP C4 identity for the Java SDK: the self-certifying signer id (§5.1) and the NFC rule.
 *
 * <p>signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
 * identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats registry:
 * ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12. The
 * multibase prefix is 'b' (base32 lowercase, no padding).
 */
public final class Identity {
    private static final int MH_SHA256 = 0x12;
    private static final char[] B32 = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();

    private Identity() {}

    private static int multicodec(int alg) {
        switch (alg) {
            case Cose.ALG_ED25519:
                return 0xED;
            case Cose.ALG_MLDSA65:
                return 0x1211;
            case Cose.ALG_MLDSA87:
                return 0x1212;
            default:
                throw new NaalpException("UnknownAlg", "no multicodec for alg " + alg);
        }
    }

    /** LEB128 unsigned varint. */
    static byte[] uvarint(int n) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long v = n & 0xFFFFFFFFL;
        while (true) {
            int b = (int) (v & 0x7F);
            v >>>= 7;
            if (v != 0) {
                out.write(b | 0x80);
            } else {
                out.write(b);
                break;
            }
        }
        return out.toByteArray();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Base32 (RFC 4648) lowercase, no padding. */
    static String base32NoPad(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(B32[(buffer >>> bits) & 0x1F]);
            }
        }
        if (bits > 0) {
            sb.append(B32[(buffer << (5 - bits)) & 0x1F]);
        }
        return sb.toString();
    }

    /** The self-certifying signer id for (alg, pubkey). */
    public static String signerId(int alg, byte[] pubkey) {
        int mc = multicodec(alg);
        byte[] mcv = uvarint(mc);
        byte[] tagged = new byte[mcv.length + pubkey.length];
        System.arraycopy(mcv, 0, tagged, 0, mcv.length);
        System.arraycopy(pubkey, 0, tagged, mcv.length, pubkey.length);
        byte[] digest = sha256().digest(tagged);
        byte[] mhCode = uvarint(MH_SHA256);
        byte[] mhLen = uvarint(digest.length);
        byte[] mh = new byte[mhCode.length + mhLen.length + digest.length];
        System.arraycopy(mhCode, 0, mh, 0, mhCode.length);
        System.arraycopy(mhLen, 0, mh, mhCode.length, mhLen.length);
        System.arraycopy(digest, 0, mh, mhCode.length + mhLen.length, digest.length);
        return "b" + base32NoPad(mh);
    }

    public static void checkSigner(String claimed, int alg, byte[] pubkey) {
        if (!signerId(alg, pubkey).equals(claimed)) {
            throw new NaalpException("SignerMismatch", "signer id does not recompute from the key");
        }
    }

    /** Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3). */
    public static void requireNfc(String s) {
        if (!Normalizer.normalize(s, Normalizer.Form.NFC).equals(s)) {
            throw new NaalpException("NonNFC", "string is not Unicode NFC");
        }
    }

    /** Decode a UTF-8 byte payload to a String (matches the adapter's utf8_hex handling). */
    public static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
