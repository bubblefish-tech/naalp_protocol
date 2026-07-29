// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
 *
 * An independent Kotlin implementation of the same deterministic profile the Go, Rust, Python and
 * Java reference implementations produce: shortest-form integer heads, no indefinite lengths,
 * canonical (bytewise-ascending, by encoded key) map ordering, and no duplicate keys. The strict
 * decoder rejects every non-canonical encoding — out-of-order or duplicate map keys, non-shortest
 * integers, indefinite lengths, trailing bytes — with a NaalpException of kind `NonCanonical`. The
 * content id is `multihash(0x20, 0x30, SHA-384(body))` over the deterministic body bytes (§2.3).
 */
object Cbor {

    // --- value model (mirrors the Go/Rust/Python/Java cbor.Value variants) ---

    /** Base of the CBOR value hierarchy. */
    sealed class Value

    /** CBOR unsigned integer (major 0). */
    class U(val v: Long) : Value()

    /** CBOR negative integer (major 1); [v] is the negative value itself. */
    class N(val v: Long) : Value()

    /** CBOR byte string (major 2). */
    class B(val v: ByteArray) : Value()

    /** CBOR text string (major 3). */
    class T(val v: String) : Value()

    /** CBOR array (major 4). */
    class A(val items: List<Value>) : Value()

    /** A single map entry. */
    class Pair(val k: Value, val v: Value)

    /** CBOR map (major 5); [pairs] is a list of (key, value). */
    class M(val pairs: List<Pair>) : Value()

    /** CBOR tag (major 6). */
    class Tag(val n: Long, val content: Value) : Value()

    // --- encoder ---

    private fun head(major: Int, n: Long): ByteArray {
        val m = major shl 5
        return when {
            n < 24 -> byteArrayOf((m or n.toInt()).toByte())
            n < 256 -> byteArrayOf((m or 24).toByte(), n.toByte())
            n < 65536L -> byteArrayOf((m or 25).toByte(), (n ushr 8).toByte(), n.toByte())
            n < 4294967296L -> byteArrayOf(
                (m or 26).toByte(),
                (n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()
            )
            else -> byteArrayOf(
                (m or 27).toByte(),
                (n ushr 56).toByte(), (n ushr 48).toByte(), (n ushr 40).toByte(), (n ushr 32).toByte(),
                (n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()
            )
        }
    }

    /** Deterministic-CBOR encode a value; map keys are emitted in canonical order. */
    fun encode(v: Value): ByteArray {
        val out = ByteArrayOutputStream()
        encodeInto(v, out)
        return out.toByteArray()
    }

    private fun encodeInto(v: Value, out: ByteArrayOutputStream) {
        when (v) {
            is U -> {
                if (v.v < 0) throw NaalpException("NonCanonical", "uint is negative")
                out.writeBytes(head(0, v.v))
            }
            is N -> out.writeBytes(head(1, -1 - v.v))
            is B -> {
                out.writeBytes(head(2, v.v.size.toLong()))
                out.writeBytes(v.v)
            }
            is T -> {
                val s = v.v.toByteArray(Charsets.UTF_8)
                out.writeBytes(head(3, s.size.toLong()))
                out.writeBytes(s)
            }
            is A -> {
                out.writeBytes(head(4, v.items.size.toLong()))
                for (item in v.items) encodeInto(item, out)
            }
            is M -> {
                val keys = ArrayList<ByteArray>(v.pairs.size)
                val vals = ArrayList<ByteArray>(v.pairs.size)
                for (p in v.pairs) {
                    keys.add(encode(p.k))
                    vals.add(encode(p.v))
                }
                val order = (0 until v.pairs.size).sortedWith { x, y -> compareBytes(keys[x], keys[y]) }
                out.writeBytes(head(5, v.pairs.size.toLong()))
                var prev: ByteArray? = null
                for (idx in order) {
                    val k = keys[idx]
                    if (prev != null && compareBytes(prev, k) == 0) {
                        throw NaalpException("NonCanonical", "duplicate map key")
                    }
                    prev = k
                    out.writeBytes(k)
                    out.writeBytes(vals[idx])
                }
            }
            is Tag -> {
                out.writeBytes(head(6, v.n))
                encodeInto(v.content, out)
            }
        }
    }

    /** Unsigned bytewise lexicographic comparison. */
    fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val x = a[i].toInt() and 0xFF
            val y = b[i].toInt() and 0xFF
            if (x != y) return x - y
        }
        return a.size - b.size
    }

    // --- decoder (strict canonical) ---

    private class Cursor(val data: ByteArray) {
        var pos = 0
        fun remaining() = data.size - pos
    }

    private fun dec(c: Cursor): Value {
        if (c.remaining() < 1) throw NaalpException("NonCanonical", "truncated")
        val ib = c.data[c.pos++].toInt() and 0xFF
        val major = ib ushr 5
        val ai = ib and 0x1F
        if (ai == 31) throw NaalpException("NonCanonical", "indefinite length")
        val arg: Long
        when {
            ai < 24 -> arg = ai.toLong()
            ai == 24 -> {
                if (c.remaining() < 1) throw NaalpException("NonCanonical", "truncated head")
                arg = c.data[c.pos++].toLong() and 0xFFL
                if (arg < 24) throw NaalpException("NonCanonical", "non-shortest integer")
            }
            ai == 25 -> {
                if (c.remaining() < 2) throw NaalpException("NonCanonical", "truncated head")
                arg = readBE(c, 2)
                if (arg < 256) throw NaalpException("NonCanonical", "non-shortest integer")
            }
            ai == 26 -> {
                if (c.remaining() < 4) throw NaalpException("NonCanonical", "truncated head")
                arg = readBE(c, 4)
                if (arg < 65536L) throw NaalpException("NonCanonical", "non-shortest integer")
            }
            ai == 27 -> {
                if (c.remaining() < 8) throw NaalpException("NonCanonical", "truncated head")
                arg = readBE(c, 8)
                if (java.lang.Long.compareUnsigned(arg, 4294967296L) < 0) {
                    throw NaalpException("NonCanonical", "non-shortest integer")
                }
            }
            else -> throw NaalpException("NonCanonical", "reserved additional-info")
        }

        return when (major) {
            0 -> U(arg)
            1 -> N(-1 - arg)
            2 -> {
                val len = lenOf(arg)
                if (c.remaining() < len) throw NaalpException("NonCanonical", "truncated byte string")
                val b = c.data.copyOfRange(c.pos, c.pos + len)
                c.pos += len
                B(b)
            }
            3 -> {
                val len = lenOf(arg)
                if (c.remaining() < len) throw NaalpException("NonCanonical", "truncated text string")
                val s = String(c.data, c.pos, len, Charsets.UTF_8)
                c.pos += len
                T(s)
            }
            4 -> {
                val len = lenOf(arg)
                val items = ArrayList<Value>(len)
                repeat(len) { items.add(dec(c)) }
                A(items)
            }
            5 -> {
                val len = lenOf(arg)
                val pairs = ArrayList<Pair>(len)
                var prev: ByteArray? = null
                repeat(len) {
                    val before = c.pos
                    val k = dec(c)
                    val kbytes = c.data.copyOfRange(before, c.pos)
                    val value = dec(c)
                    if (prev != null && compareBytes(kbytes, prev!!) <= 0) {
                        throw NaalpException("NonCanonical", "map keys out of order or duplicate")
                    }
                    prev = kbytes
                    pairs.add(Pair(k, value))
                }
                M(pairs)
            }
            6 -> {
                val content = dec(c)
                Tag(arg, content)
            }
            else -> throw NaalpException("NonCanonical", "unsupported major type $major")
        }
    }

    private fun readBE(c: Cursor, n: Int): Long {
        var v = 0L
        for (i in 0 until n) {
            v = (v shl 8) or (c.data[c.pos++].toLong() and 0xFFL)
        }
        return v
    }

    private fun lenOf(arg: Long): Int {
        if (arg < 0 || arg > Int.MAX_VALUE) throw NaalpException("NonCanonical", "length out of range")
        return arg.toInt()
    }

    /** Strict canonical decode: rejects any non-canonical encoding with a NonCanonical error. */
    fun decode(data: ByteArray): Value {
        val c = Cursor(data)
        val v = dec(c)
        if (c.remaining() != 0) {
            throw NaalpException("NonCanonical", "trailing bytes after top-level item")
        }
        return v
    }

    // --- content id ---

    private fun sha384(): MessageDigest = MessageDigest.getInstance("SHA-384")

    /** Content id = multihash(0x20 [sha2-384], 0x30 [48], SHA-384(body-bytes)) (§2.3). */
    fun contentId(body: ByteArray): ByteArray {
        val digest = sha384().digest(body)
        val out = ByteArray(2 + digest.size)
        out[0] = 0x20
        out[1] = 0x30
        System.arraycopy(digest, 0, out, 2, digest.size)
        return out
    }
}
