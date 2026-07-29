// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.BufferedOutputStream
import java.security.MessageDigest

/**
 * naalp-adapter-kotlin — the Kotlin N-AALP conformance adapter.
 *
 * Wraps the `sh.bubblefish.naalp` Kotlin SDK behind the length-prefixed JSON op protocol the
 * naalp-conform runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON
 * {"op","in"} request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on
 * stdout, flushed after each. Kotlin has a deterministic ML-DSA (FIPS 204) library (Bouncy Castle
 * MLDSASigner, rnd=0) and Ed25519 (RFC 8032), so it implements every op including the crypto leg —
 * it skips none.
 */

// ---- input helpers ----

private fun hx(inp: Map<String, Any?>, k: String): ByteArray {
    val v = inp[k]
    if (v !is String) throw NaalpException("Malformed", "missing hex field $k")
    return Hex.decode(v)
}

private fun str(inp: Map<String, Any?>, k: String): String {
    val v = inp[k]
    return if (v is String) v else ""
}

/** Parse a 64-bit counter from a JSON number or a decimal string. */
private fun u64(inp: Map<String, Any?>, k: String): Long {
    return when (val v = inp[k]) {
        is Long -> v
        is Int -> v.toLong()
        is Double -> v.toLong()
        is String -> v.toLong()
        else -> 0L
    }
}

private fun intVal(inp: Map<String, Any?>, k: String): Int {
    return when (val v = inp[k]) {
        is Long -> v.toInt()
        is Int -> v
        is Double -> v.toInt()
        is String -> v.toInt()
        else -> 0
    }
}

private fun boolVal(inp: Map<String, Any?>, k: String): Boolean {
    val v = inp[k]
    return v is Boolean && v
}

private fun out(vararg kv: Any?): Map<String, Any?> {
    val m = LinkedHashMap<String, Any?>()
    var i = 0
    while (i < kv.size) {
        m[kv[i] as String] = kv[i + 1]
        i += 2
    }
    val resp = LinkedHashMap<String, Any?>()
    resp["out"] = m
    return resp
}

private fun error(msg: String): Map<String, Any?> {
    val resp = LinkedHashMap<String, Any?>()
    resp["error"] = msg
    return resp
}

private fun skipped(why: String): Map<String, Any?> {
    val resp = LinkedHashMap<String, Any?>()
    resp["skipped"] = why
    return resp
}

private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

// ---- tagged-value -> Cbor.Value ----

private fun tagged(v: Any?): Cbor.Value {
    if (v !is List<*> || v.size != 2) throw NaalpException("Malformed", "tagged value must be [tag, payload]")
    val tag = v[0] as String
    val p = v[1]
    return when (tag) {
        "u" -> {
            val n: Long = when (p) {
                is Long -> p
                is Int -> p.toLong()
                is Double -> p.toLong()
                is String -> java.lang.Long.parseUnsignedLong(p)
                else -> throw NaalpException("Malformed", "u payload not a number")
            }
            Cbor.U(n)
        }
        "b" -> Cbor.B(Hex.decode(p as String))
        "s" -> Cbor.T(p as String)
        "arr" -> {
            val items = p as List<*>
            Cbor.A(items.map { tagged(it) })
        }
        "map" -> {
            val pairs = p as List<*>
            Cbor.M(pairs.map { pr ->
                val kv = pr as List<*>
                if (kv.size != 2) throw NaalpException("Malformed", "map pair must be [k, v]")
                Cbor.Pair(tagged(kv[0]), tagged(kv[1]))
            })
        }
        else -> throw NaalpException("Malformed", "unknown tag $tag")
    }
}

private fun nodesFrom(inp: Map<String, Any?>): List<Graph.Node> {
    val raw = (inp["nodes"] as? List<*>) ?: emptyList<Any?>()
    return raw.map { r ->
        val nm = r as Map<*, *>
        val id = Hex.decode(nm["id_hex"] as String)
        val causes = ArrayList<ByteArray>()
        val cr = nm["causes_hex"]
        if (cr is List<*>) for (c in cr) causes.add(Hex.decode(c as String))
        var pos = 0L
        when (val pp = nm["position"]) {
            is Long -> pos = pp
            is Int -> pos = pp.toLong()
            is Double -> pos = pp.toLong()
        }
        Graph.Node(id, causes, pos)
    }
}

// ---- dispatch ----

private fun handle(op: String, inp: Map<String, Any?>): Map<String, Any?> {
    when (op) {
        "sha384" ->
            return out("digest_hex", Hex.encode(sha384(hx(inp, "msg_hex"))))

        "cbor.encode" ->
            return out("bytes_hex", Hex.encode(Cbor.encode(tagged(inp["value"]))))

        "cbor.decode" -> {
            Cbor.decode(hx(inp, "bytes_hex")) // throws NonCanonical on a MUST-reject case
            return out("ok", true)
        }

        "content.id" -> {
            val v = Cbor.decode(hx(inp, "body_hex"))
            return out("id_hex", Hex.encode(Cbor.contentId(Cbor.encode(v))))
        }

        "cose.tbs" ->
            return out("tobesigned_hex", Hex.encode(Cose.toBeSignedRaw(hx(inp, "protected_hex"), hx(inp, "payload_hex"))))

        "mldsa.keygen" -> {
            val param = inp["param"] as? String ?: "ML-DSA-65"
            return out("pk_hex", Hex.encode(Cose.mldsaKeygen(param, hx(inp, "seed_hex"))))
        }

        "ed25519.sign" ->
            return out("sig_hex", Hex.encode(Cose.ed25519Sign(hx(inp, "sk_hex"), hx(inp, "msg_hex"))))

        "cose.sign1" -> {
            val obj = Cose.coseSign1(intVal(inp, "alg"), hx(inp, "seed_hex"), hx(inp, "protected_hex"), hx(inp, "payload_hex"))
            return out("obj_hex", Hex.encode(obj))
        }

        "cose.verify1" ->
            return out("valid", Cose.coseVerify1(intVal(inp, "alg"), hx(inp, "pubkey_hex"), hx(inp, "obj_hex")))

        "signerid" ->
            return out("signer_id", Identity.signerId(intVal(inp, "alg"), hx(inp, "pubkey_hex")))

        "nfc.check" -> {
            Identity.requireNfc(Identity.utf8(hx(inp, "utf8_hex"))) // throws NonNFC on a reject case
            return out("ok", true)
        }

        "effect.normalize" ->
            return out("effect", Policy.normalizeEffect(u64(inp, "value")))

        "effect.authorize" ->
            return out("allow", Policy.authorizes(Policy.normalizeEffect(u64(inp, "granted")), u64(inp, "effect")))

        "effect.safety_label" ->
            return out("cbor_hex", Hex.encode(Policy.safetyLabelBytes(str(inp, "risk"), str(inp, "scope"))))

        "approval.body", "approval.id" -> {
            val approves = hx(inp, "approves_hex")
            val approver = str(inp, "approver")
            val grant = u64(inp, "grant")
            val nonce = hx(inp, "nonce_hex")
            val notAfter = u64(inp, "not_after")
            return if (op == "approval.id") {
                out("id_hex", Hex.encode(Records.approvalId(approves, approver, grant, nonce, notAfter)))
            } else {
                out("body_hex", Hex.encode(Records.approvalBody(approves, approver, grant, nonce, notAfter)))
            }
        }

        "ledger.entry" ->
            return out("body_hex", Hex.encode(Records.ledgerEntry(u64(inp, "seq"), hx(inp, "prev_hex"), hx(inp, "approval_id_hex"), str(inp, "by"))))

        "receipt.body" ->
            return out("body_hex", Hex.encode(Records.receiptBody(hx(inp, "prev_hex"), hx(inp, "obj_hex"), u64(inp, "seq"), u64(inp, "at"))))

        "receipt.head" ->
            return out("head_hex", Hex.encode(Records.receiptHead(hx(inp, "body_hex"))))

        "causal.verify" -> {
            Graph.verifyCausal(nodesFrom(inp)) // throws CausalViolation on a reject case
            return out("valid", true)
        }

        "delivery.update" ->
            return out("body_hex", Hex.encode(Records.deliveryUpdate(hx(inp, "obj_hex"), u64(inp, "stage"), u64(inp, "at"))))

        "stream.digest" -> {
            val raw = (inp["chunks"] as? List<*>) ?: emptyList<Any?>()
            val chunks = raw.map { r ->
                val cm = r as Map<*, *>
                val offset: Long = when (val o = cm["offset"]) {
                    is Long -> o
                    is Int -> o.toLong()
                    is Double -> o.toLong()
                    is String -> o.toLong()
                    else -> 0L
                }
                Records.Chunk(offset, Hex.decode(cm["data_hex"] as String))
            }
            return out("digest_hex", Hex.encode(Records.streamDigest(chunks)))
        }

        "stream.open" -> {
            var approval: ByteArray? = null
            val a = inp["approval_hex"]
            if (a is String && a.isNotEmpty()) approval = Hex.decode(a)
            return out("body_hex", Hex.encode(Records.streamOpenBody(hx(inp, "stream_id_hex"), u64(inp, "effect"), approval, u64(inp, "substream"))))
        }

        "stream.commit" ->
            return out("body_hex", Hex.encode(Records.streamCommitBody(hx(inp, "stream_id_hex"), hx(inp, "digest_hex"))))

        "stream.checkpoint" ->
            return out("body_hex", Hex.encode(Records.streamCheckpointBody(hx(inp, "stream_id_hex"), u64(inp, "through_offset"), hx(inp, "digest_so_far_hex"))))

        "transport.emit" ->
            return out("result", Records.transportEmit(str(inp, "transport"), boolVal(inp, "sensitive"), boolVal(inp, "require_peer_auth")))

        "carriage.body" ->
            return out(
                "body_hex",
                Hex.encode(
                    Records.carriageBody(
                        u64(inp, "protocol_id"), u64(inp, "class"), u64(inp, "content_type"),
                        hx(inp, "correlation_hex"), str(inp, "method"), hx(inp, "foreign_hex")
                    )
                )
            )

        "channels.lookup" -> {
            val ks = Channels.lookup(u64(inp, "channel"), u64(inp, "kind"))
            return out("name", ks.name, "effect", ks.effect, "variable", ks.variable)
        }

        "channels.effect_check" -> {
            Channels.checkEffect(u64(inp, "channel"), u64(inp, "kind"), u64(inp, "effect"))
            return out("ok", true)
        }

        "federation.reconcile" -> {
            val order = Graph.reconcile(nodesFrom(inp))
            val hexes = order.map { Hex.encode(it) }
            return out("order", hexes)
        }

        "federation.record" -> {
            val authRaw = (inp["authorities"] as? List<*>) ?: emptyList<Any?>()
            val auths = authRaw.map { it as String }
            val ordRaw = (inp["order"] as? List<*>) ?: emptyList<Any?>()
            val order = ordRaw.map { Hex.decode(it as String) }
            return out("body_hex", Hex.encode(Graph.reconcileRecord(auths, order)))
        }

        else -> return skipped("op not implemented: $op")
    }
}

private fun dispatch(body: ByteArray): Map<String, Any?> {
    return try {
        val req = Json.parse(String(body, Charsets.UTF_8))
        if (req !is Map<*, *>) return error("request is not a JSON object")
        @Suppress("UNCHECKED_CAST")
        val reqMap = req as Map<String, Any?>
        val op = reqMap["op"] as? String ?: ""
        val inObj = reqMap["in"]
        @Suppress("UNCHECKED_CAST")
        val inp = if (inObj is Map<*, *>) inObj as Map<String, Any?> else LinkedHashMap()
        handle(op, inp)
    } catch (e: NaalpException) {
        error(e.message ?: e.kind)
    } catch (e: Exception) {
        error("adapter exception: $e")
    }
}

// ---- framing loop ----

fun main() {
    val stdin = System.`in`
    val stdout = BufferedOutputStream(System.out)
    val lp = ByteArray(4)
    while (true) {
        val got = readFully(stdin, lp, 4)
        if (!got) return
        val n = (lp[0].toInt() and 0xFF) or
            ((lp[1].toInt() and 0xFF) shl 8) or
            ((lp[2].toInt() and 0xFF) shl 16) or
            ((lp[3].toInt() and 0xFF) shl 24)
        val body = ByteArray(n)
        if (!readFully(stdin, body, n)) return

        val resp = dispatch(body)
        val ob = Json.write(resp).toByteArray(Charsets.UTF_8)
        val olp = ByteArray(4)
        val len = ob.size
        olp[0] = (len and 0xFF).toByte()
        olp[1] = ((len ushr 8) and 0xFF).toByte()
        olp[2] = ((len ushr 16) and 0xFF).toByte()
        olp[3] = ((len ushr 24) and 0xFF).toByte()
        stdout.write(olp)
        stdout.write(ob)
        stdout.flush()
    }
}

/** Read exactly [n] bytes into [buf]; returns false at clean EOF before any byte of a new frame. */
private fun readFully(input: java.io.InputStream, buf: ByteArray, n: Int): Boolean {
    var off = 0
    while (off < n) {
        val r = input.read(buf, off, n - off)
        if (r < 0) return false
        off += r
    }
    return true
}

// ---------------------------------------------------------------------------
// A minimal, dependency-free JSON reader/writer for the adapter's wire protocol.
//
// Parses into Map<String,Any?> (objects), List<Any?> (arrays), String, Long/Double (integers vs
// reals), Boolean, and null. Integer tokens become Long so 64-bit counters survive without float
// rounding. The writer emits the same value shapes plus Int. A real recursive-descent parser (not a
// regex or a string match): it validates structure and raises on malformed input.
// ---------------------------------------------------------------------------

object Json {

    fun parse(s: String): Any? {
        val p = Parser(s)
        p.skipWs()
        val v = p.value()
        p.skipWs()
        if (p.pos != p.src.length) throw IllegalArgumentException("trailing content after JSON value")
        return v
    }

    private class Parser(val src: String) {
        var pos = 0

        fun skipWs() {
            while (pos < src.length) {
                val c = src[pos]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++ else break
            }
        }

        fun value(): Any? {
            skipWs()
            if (pos >= src.length) throw IllegalArgumentException("unexpected end of JSON")
            return when (src[pos]) {
                '{' -> obj()
                '[' -> array()
                '"' -> string()
                't', 'f' -> bool()
                'n' -> nullLit()
                else -> number()
            }
        }

        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            pos++ // {
            skipWs()
            if (peek() == '}') { pos++; return m }
            while (true) {
                skipWs()
                if (peek() != '"') throw IllegalArgumentException("expected string key at $pos")
                val key = string()
                skipWs()
                if (peek() != ':') throw IllegalArgumentException("expected ':' at $pos")
                pos++
                val v = value()
                m[key] = v
                skipWs()
                when (peek()) {
                    ',' -> { pos++; continue }
                    '}' -> { pos++; break }
                    else -> throw IllegalArgumentException("expected ',' or '}' at $pos")
                }
            }
            return m
        }

        fun array(): List<Any?> {
            val a = ArrayList<Any?>()
            pos++ // [
            skipWs()
            if (peek() == ']') { pos++; return a }
            while (true) {
                val v = value()
                a.add(v)
                skipWs()
                when (peek()) {
                    ',' -> { pos++; continue }
                    ']' -> { pos++; break }
                    else -> throw IllegalArgumentException("expected ',' or ']' at $pos")
                }
            }
            return a
        }

        fun string(): String {
            val sb = StringBuilder()
            pos++ // opening quote
            while (true) {
                if (pos >= src.length) throw IllegalArgumentException("unterminated string")
                val c = src[pos++]
                if (c == '"') break
                if (c == '\\') {
                    val e = src[pos++]
                    when (e) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val cp = src.substring(pos, pos + 4).toInt(16)
                            pos += 4
                            sb.append(cp.toChar())
                        }
                        else -> throw IllegalArgumentException("bad escape \\$e")
                    }
                } else {
                    sb.append(c)
                }
            }
            return sb.toString()
        }

        fun number(): Any {
            val start = pos
            if (peek() == '-') pos++
            while (pos < src.length) {
                val c = src[pos]
                if ((c in '0'..'9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') pos++ else break
            }
            val tok = src.substring(start, pos)
            if (tok.isEmpty()) throw IllegalArgumentException("invalid number at $start")
            if (tok.indexOf('.') < 0 && tok.indexOf('e') < 0 && tok.indexOf('E') < 0) {
                val asLong = tok.toLongOrNull()
                if (asLong != null) return asLong
            }
            return tok.toDouble()
        }

        fun bool(): Boolean {
            if (src.startsWith("true", pos)) { pos += 4; return true }
            if (src.startsWith("false", pos)) { pos += 5; return false }
            throw IllegalArgumentException("invalid literal at $pos")
        }

        fun nullLit(): Any? {
            if (src.startsWith("null", pos)) { pos += 4; return null }
            throw IllegalArgumentException("invalid literal at $pos")
        }

        fun peek(): Char {
            if (pos >= src.length) throw IllegalArgumentException("unexpected end of JSON")
            return src[pos]
        }
    }

    fun write(v: Any?): String {
        val sb = StringBuilder()
        writeInto(v, sb)
        return sb.toString()
    }

    private fun writeInto(v: Any?, sb: StringBuilder) {
        when (v) {
            null -> sb.append("null")
            is String -> writeString(v, sb)
            is Boolean -> sb.append(if (v) "true" else "false")
            is Long, is Int -> sb.append(v.toString())
            is Double -> {
                if (v == Math.floor(v) && !v.isInfinite()) sb.append(v.toLong().toString()) else sb.append(v.toString())
            }
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((key, value) in v) {
                    if (!first) sb.append(',')
                    first = false
                    writeString(key as String, sb)
                    sb.append(':')
                    writeInto(value, sb)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                var first = true
                for (e in v) {
                    if (!first) sb.append(',')
                    first = false
                    writeInto(e, sb)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("cannot serialize ${v.javaClass}")
        }
    }

    private fun writeString(s: String, sb: StringBuilder) {
        sb.append('"')
        for (element in s) {
            when (element) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (element < 0x20.toChar()) sb.append(String.format("\\u%04x", element.code)) else sb.append(element)
                }
            }
        }
        sb.append('"')
    }
}
