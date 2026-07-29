// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

/** Lowercase-hex encode/decode for the byte-valued wire fields of the conformance protocol. */
public final class Hex {
    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {}

    public static String encode(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xFF;
            out[2 * i] = DIGITS[v >>> 4];
            out[2 * i + 1] = DIGITS[v & 0x0F];
        }
        return new String(out);
    }

    public static byte[] decode(String s) {
        if ((s.length() & 1) != 0) {
            throw new NaalpException("Malformed", "odd-length hex string");
        }
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new NaalpException("Malformed", "invalid hex digit");
            }
            b[i] = (byte) ((hi << 4) | lo);
        }
        return b;
    }
}
