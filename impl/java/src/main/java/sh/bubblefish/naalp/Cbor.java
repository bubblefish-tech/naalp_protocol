// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
 *
 * <p>An independent Java implementation of the same deterministic profile the Go, Rust and Python
 * reference implementations produce: shortest-form integer heads, no indefinite lengths, canonical
 * (bytewise-ascending, by encoded key) map ordering, and no duplicate keys. The strict decoder
 * rejects every non-canonical encoding — out-of-order or duplicate map keys, non-shortest integers,
 * indefinite lengths, trailing bytes — with a {@link NaalpException} of kind {@code NonCanonical}.
 * The content id is {@code multihash(0x20, 0x30, SHA-384(body))} over the deterministic body bytes
 * (§2.3).
 */
public final class Cbor {
    private Cbor() {}

    // --- value model (mirrors the Go/Rust/Python cbor.Value variants) ---

    /** Base of the CBOR value hierarchy. */
    public abstract static class Value {}

    /** CBOR unsigned integer (major 0). */
    public static final class U extends Value {
        public final long v;
        public U(long v) { this.v = v; }
    }

    /** CBOR negative integer (major 1); {@code v} is the negative value itself. */
    public static final class N extends Value {
        public final long v;
        public N(long v) { this.v = v; }
    }

    /** CBOR byte string (major 2). */
    public static final class B extends Value {
        public final byte[] v;
        public B(byte[] v) { this.v = v; }
    }

    /** CBOR text string (major 3). */
    public static final class T extends Value {
        public final String v;
        public T(String v) { this.v = v; }
    }

    /** CBOR array (major 4). */
    public static final class A extends Value {
        public final List<Value> items;
        public A(List<Value> items) { this.items = items; }
    }

    /** A single map entry. */
    public static final class Pair {
        public final Value k;
        public final Value val;
        public Pair(Value k, Value val) { this.k = k; this.val = val; }
    }

    /** CBOR map (major 5); pairs is a list of (key, value). */
    public static final class M extends Value {
        public final List<Pair> pairs;
        public M(List<Pair> pairs) { this.pairs = pairs; }
    }

    /** CBOR tag (major 6). */
    public static final class Tag extends Value {
        public final long n;
        public final Value content;
        public Tag(long n, Value content) { this.n = n; this.content = content; }
    }

    // --- encoder ---

    private static byte[] head(int major, long n) {
        int m = major << 5;
        if (n < 24) {
            return new byte[]{(byte) (m | (int) n)};
        }
        if (n < 256) {
            return new byte[]{(byte) (m | 24), (byte) n};
        }
        if (n < 65536L) {
            return new byte[]{(byte) (m | 25), (byte) (n >>> 8), (byte) n};
        }
        if (n < 4294967296L) {
            return new byte[]{(byte) (m | 26),
                    (byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
        }
        return new byte[]{(byte) (m | 27),
                (byte) (n >>> 56), (byte) (n >>> 48), (byte) (n >>> 40), (byte) (n >>> 32),
                (byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n};
    }

    /** Deterministic-CBOR encode a value; map keys are emitted in canonical order. */
    public static byte[] encode(Value v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encodeInto(v, out);
        return out.toByteArray();
    }

    private static void encodeInto(Value v, ByteArrayOutputStream out) {
        if (v instanceof U u) {
            if (u.v < 0) {
                throw new NaalpException("NonCanonical", "uint is negative");
            }
            out.writeBytes(head(0, u.v));
        } else if (v instanceof N n) {
            out.writeBytes(head(1, -1 - n.v));
        } else if (v instanceof B b) {
            out.writeBytes(head(2, b.v.length));
            out.writeBytes(b.v);
        } else if (v instanceof T t) {
            byte[] s = t.v.getBytes(StandardCharsets.UTF_8);
            out.writeBytes(head(3, s.length));
            out.writeBytes(s);
        } else if (v instanceof A a) {
            out.writeBytes(head(4, a.items.size()));
            for (Value item : a.items) {
                encodeInto(item, out);
            }
        } else if (v instanceof M m) {
            List<byte[]> keys = new ArrayList<>(m.pairs.size());
            List<byte[]> vals = new ArrayList<>(m.pairs.size());
            for (Pair p : m.pairs) {
                keys.add(encode(p.k));
                vals.add(encode(p.val));
            }
            Integer[] order = new Integer[m.pairs.size()];
            for (int i = 0; i < order.length; i++) {
                order[i] = i;
            }
            java.util.Arrays.sort(order, (x, y) -> compareBytes(keys.get(x), keys.get(y)));
            out.writeBytes(head(5, m.pairs.size()));
            byte[] prev = null;
            for (int idx : order) {
                byte[] k = keys.get(idx);
                if (prev != null && compareBytes(prev, k) == 0) {
                    throw new NaalpException("NonCanonical", "duplicate map key");
                }
                prev = k;
                out.writeBytes(k);
                out.writeBytes(vals.get(idx));
            }
        } else if (v instanceof Tag tg) {
            out.writeBytes(head(6, tg.n));
            encodeInto(tg.content, out);
        } else {
            throw new NaalpException("NonCanonical", "not a cbor value");
        }
    }

    /** Unsigned bytewise lexicographic comparison. */
    static int compareBytes(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int x = a[i] & 0xFF;
            int y = b[i] & 0xFF;
            if (x != y) {
                return x - y;
            }
        }
        return a.length - b.length;
    }

    // --- decoder (strict canonical) ---

    private static final class Cursor {
        final byte[] data;
        int pos;
        Cursor(byte[] data) { this.data = data; }
        int remaining() { return data.length - pos; }
    }

    private static Value dec(Cursor c) {
        if (c.remaining() < 1) {
            throw new NaalpException("NonCanonical", "truncated");
        }
        int ib = c.data[c.pos++] & 0xFF;
        int major = ib >>> 5;
        int ai = ib & 0x1F;
        if (ai == 31) {
            throw new NaalpException("NonCanonical", "indefinite length");
        }
        long arg;
        if (ai < 24) {
            arg = ai;
        } else if (ai == 24) {
            if (c.remaining() < 1) {
                throw new NaalpException("NonCanonical", "truncated head");
            }
            arg = c.data[c.pos++] & 0xFFL;
            if (arg < 24) {
                throw new NaalpException("NonCanonical", "non-shortest integer");
            }
        } else if (ai == 25) {
            if (c.remaining() < 2) {
                throw new NaalpException("NonCanonical", "truncated head");
            }
            arg = readBE(c, 2);
            if (arg < 256) {
                throw new NaalpException("NonCanonical", "non-shortest integer");
            }
        } else if (ai == 26) {
            if (c.remaining() < 4) {
                throw new NaalpException("NonCanonical", "truncated head");
            }
            arg = readBE(c, 4);
            if (arg < 65536L) {
                throw new NaalpException("NonCanonical", "non-shortest integer");
            }
        } else if (ai == 27) {
            if (c.remaining() < 8) {
                throw new NaalpException("NonCanonical", "truncated head");
            }
            arg = readBE(c, 8);
            if (Long.compareUnsigned(arg, 4294967296L) < 0) {
                throw new NaalpException("NonCanonical", "non-shortest integer");
            }
        } else {
            throw new NaalpException("NonCanonical", "reserved additional-info");
        }

        switch (major) {
            case 0:
                return new U(arg);
            case 1:
                return new N(-1 - arg);
            case 2: {
                int len = lenOf(arg);
                if (c.remaining() < len) {
                    throw new NaalpException("NonCanonical", "truncated byte string");
                }
                byte[] b = new byte[len];
                System.arraycopy(c.data, c.pos, b, 0, len);
                c.pos += len;
                return new B(b);
            }
            case 3: {
                int len = lenOf(arg);
                if (c.remaining() < len) {
                    throw new NaalpException("NonCanonical", "truncated text string");
                }
                String s = new String(c.data, c.pos, len, StandardCharsets.UTF_8);
                c.pos += len;
                return new T(s);
            }
            case 4: {
                int len = lenOf(arg);
                List<Value> items = new ArrayList<>(len);
                for (int i = 0; i < len; i++) {
                    items.add(dec(c));
                }
                return new A(items);
            }
            case 5: {
                int len = lenOf(arg);
                List<Pair> pairs = new ArrayList<>(len);
                byte[] prev = null;
                for (int i = 0; i < len; i++) {
                    int before = c.pos;
                    Value k = dec(c);
                    byte[] kbytes = new byte[c.pos - before];
                    System.arraycopy(c.data, before, kbytes, 0, kbytes.length);
                    Value val = dec(c);
                    if (prev != null && compareBytes(kbytes, prev) <= 0) {
                        throw new NaalpException("NonCanonical", "map keys out of order or duplicate");
                    }
                    prev = kbytes;
                    pairs.add(new Pair(k, val));
                }
                return new M(pairs);
            }
            case 6: {
                Value content = dec(c);
                return new Tag(arg, content);
            }
            default:
                throw new NaalpException("NonCanonical", "unsupported major type " + major);
        }
    }

    private static long readBE(Cursor c, int n) {
        long v = 0;
        for (int i = 0; i < n; i++) {
            v = (v << 8) | (c.data[c.pos++] & 0xFFL);
        }
        return v;
    }

    private static int lenOf(long arg) {
        if (arg < 0 || arg > Integer.MAX_VALUE) {
            throw new NaalpException("NonCanonical", "length out of range");
        }
        return (int) arg;
    }

    /** Strict canonical decode: rejects any non-canonical encoding with a NonCanonical error. */
    public static Value decode(byte[] data) {
        Cursor c = new Cursor(data);
        Value v = dec(c);
        if (c.remaining() != 0) {
            throw new NaalpException("NonCanonical", "trailing bytes after top-level item");
        }
        return v;
    }

    // --- content id ---

    private static MessageDigest sha384() {
        try {
            return MessageDigest.getInstance("SHA-384");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** Content id = multihash(0x20 [sha2-384], 0x30 [48], SHA-384(body-bytes)) (§2.3). */
    public static byte[] contentId(byte[] body) {
        byte[] digest = sha384().digest(body);
        byte[] out = new byte[2 + digest.length];
        out[0] = 0x20;
        out[1] = 0x30;
        System.arraycopy(digest, 0, out, 2, digest.length);
        return out;
    }
}
