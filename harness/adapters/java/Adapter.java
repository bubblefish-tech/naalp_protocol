// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * naalp-adapter-java — the Java N-AALP conformance adapter.
 *
 * <p>Wraps the {@code sh.bubblefish.naalp} SDK behind the length-prefixed JSON op protocol the
 * naalp-conform runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON
 * {@code {"op","in"}} request on stdin, and a {@code {"out"|"error"|"skipped"}} response in the same
 * framing on stdout, flushed after each. Java has a deterministic ML-DSA (FIPS 204) library
 * (Bouncy Castle {@code MLDSASigner}, rnd=0) and Ed25519 (RFC 8032), so it implements every op
 * including the crypto leg — it skips none.
 */
public final class Adapter {

    // ---- input helpers ----

    private static byte[] hx(Map<String, Object> in, String k) {
        Object v = in.get(k);
        if (!(v instanceof String s)) {
            throw new NaalpException("Malformed", "missing hex field " + k);
        }
        return Hex.decode(s);
    }

    private static String str(Map<String, Object> in, String k) {
        Object v = in.get(k);
        return (v instanceof String s) ? s : "";
    }

    /** Parse a 64-bit counter from a JSON number or a decimal string. */
    private static long u64(Map<String, Object> in, String k) {
        Object v = in.get(k);
        if (v instanceof Long l) {
            return l;
        }
        if (v instanceof Double d) {
            return (long) (double) d;
        }
        if (v instanceof String s) {
            return Long.parseLong(s);
        }
        return 0;
    }

    private static int intVal(Map<String, Object> in, String k) {
        Object v = in.get(k);
        if (v instanceof Long l) {
            return (int) (long) l;
        }
        if (v instanceof Double d) {
            return (int) (double) d;
        }
        if (v instanceof String s) {
            return Integer.parseInt(s);
        }
        return 0;
    }

    private static boolean boolVal(Map<String, Object> in, String k) {
        Object v = in.get(k);
        return v instanceof Boolean b && b;
    }

    private static Map<String, Object> out(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("out", m);
        return resp;
    }

    private static Map<String, Object> error(String msg) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("error", msg);
        return resp;
    }

    private static Map<String, Object> skipped(String why) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("skipped", why);
        return resp;
    }

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- tagged-value -> Cbor.Value ----

    @SuppressWarnings("unchecked")
    private static Cbor.Value tagged(Object v) {
        if (!(v instanceof List<?> arr) || arr.size() != 2) {
            throw new NaalpException("Malformed", "tagged value must be [tag, payload]");
        }
        String tag = (String) arr.get(0);
        Object p = arr.get(1);
        switch (tag) {
            case "u": {
                long n;
                if (p instanceof Long l) {
                    n = l;
                } else if (p instanceof Double d) {
                    n = (long) (double) d;
                } else if (p instanceof String s) {
                    n = Long.parseUnsignedLong(s);
                } else {
                    throw new NaalpException("Malformed", "u payload not a number");
                }
                return new Cbor.U(n);
            }
            case "b":
                return new Cbor.B(Hex.decode((String) p));
            case "s":
                return new Cbor.T((String) p);
            case "arr": {
                List<Object> items = (List<Object>) p;
                List<Cbor.Value> out = new ArrayList<>(items.size());
                for (Object it : items) {
                    out.add(tagged(it));
                }
                return new Cbor.A(out);
            }
            case "map": {
                List<Object> pairs = (List<Object>) p;
                List<Cbor.Pair> out = new ArrayList<>(pairs.size());
                for (Object pr : pairs) {
                    List<Object> kv = (List<Object>) pr;
                    if (kv.size() != 2) {
                        throw new NaalpException("Malformed", "map pair must be [k, v]");
                    }
                    out.add(new Cbor.Pair(tagged(kv.get(0)), tagged(kv.get(1))));
                }
                return new Cbor.M(out);
            }
            default:
                throw new NaalpException("Malformed", "unknown tag " + tag);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Graph.Node> nodesFrom(Map<String, Object> in) {
        List<Object> raw = (List<Object>) in.getOrDefault("nodes", List.of());
        List<Graph.Node> nodes = new ArrayList<>(raw.size());
        for (Object r : raw) {
            Map<String, Object> nm = (Map<String, Object>) r;
            byte[] id = Hex.decode((String) nm.get("id_hex"));
            List<byte[]> causes = new ArrayList<>();
            Object cr = nm.get("causes_hex");
            if (cr instanceof List<?> cl) {
                for (Object c : cl) {
                    causes.add(Hex.decode((String) c));
                }
            }
            long pos = 0;
            Object p = nm.get("position");
            if (p instanceof Long l) {
                pos = l;
            } else if (p instanceof Double d) {
                pos = (long) (double) d;
            }
            nodes.add(new Graph.Node(id, causes, pos));
        }
        return nodes;
    }

    // ---- dispatch ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> handle(String op, Map<String, Object> in) {
        switch (op) {
            case "sha384":
                return out("digest_hex", Hex.encode(sha384(hx(in, "msg_hex"))));

            case "cbor.encode":
                return out("bytes_hex", Hex.encode(Cbor.encode(tagged(in.get("value")))));

            case "cbor.decode":
                Cbor.decode(hx(in, "bytes_hex")); // throws NonCanonical on a MUST-reject case
                return out("ok", Boolean.TRUE);

            case "content.id": {
                Cbor.Value v = Cbor.decode(hx(in, "body_hex"));
                return out("id_hex", Hex.encode(Cbor.contentId(Cbor.encode(v))));
            }

            case "cose.tbs":
                return out("tobesigned_hex",
                        Hex.encode(Cose.toBeSignedRaw(hx(in, "protected_hex"), hx(in, "payload_hex"))));

            case "mldsa.keygen": {
                String param = in.get("param") instanceof String s ? s : "ML-DSA-65";
                return out("pk_hex", Hex.encode(Cose.mldsaKeygen(param, hx(in, "seed_hex"))));
            }

            case "ed25519.sign":
                return out("sig_hex", Hex.encode(Cose.ed25519Sign(hx(in, "sk_hex"), hx(in, "msg_hex"))));

            case "cose.sign1": {
                byte[] obj = Cose.coseSign1(intVal(in, "alg"), hx(in, "seed_hex"),
                        hx(in, "protected_hex"), hx(in, "payload_hex"));
                return out("obj_hex", Hex.encode(obj));
            }

            case "cose.verify1":
                return out("valid", Cose.coseVerify1(intVal(in, "alg"), hx(in, "pubkey_hex"), hx(in, "obj_hex")));

            case "signerid":
                return out("signer_id", Identity.signerId(intVal(in, "alg"), hx(in, "pubkey_hex")));

            case "nfc.check":
                Identity.requireNfc(Identity.utf8(hx(in, "utf8_hex"))); // throws NonNFC on a reject case
                return out("ok", Boolean.TRUE);

            case "effect.normalize":
                return out("effect", Policy.normalizeEffect(u64(in, "value")));

            case "effect.authorize":
                return out("allow", Policy.authorizes(Policy.normalizeEffect(u64(in, "granted")), u64(in, "effect")));

            case "effect.safety_label":
                return out("cbor_hex", Hex.encode(Policy.safetyLabelBytes(str(in, "risk"), str(in, "scope"))));

            case "approval.body":
            case "approval.id": {
                byte[] approves = hx(in, "approves_hex");
                String approver = str(in, "approver");
                long grant = u64(in, "grant");
                byte[] nonce = hx(in, "nonce_hex");
                long notAfter = u64(in, "not_after");
                if (op.equals("approval.id")) {
                    return out("id_hex", Hex.encode(Records.approvalId(approves, approver, grant, nonce, notAfter)));
                }
                return out("body_hex", Hex.encode(Records.approvalBody(approves, approver, grant, nonce, notAfter)));
            }

            case "ledger.entry":
                return out("body_hex", Hex.encode(Records.ledgerEntry(
                        u64(in, "seq"), hx(in, "prev_hex"), hx(in, "approval_id_hex"), str(in, "by"))));

            case "receipt.body":
                return out("body_hex", Hex.encode(Records.receiptBody(
                        hx(in, "prev_hex"), hx(in, "obj_hex"), u64(in, "seq"), u64(in, "at"))));

            case "receipt.head":
                return out("head_hex", Hex.encode(Records.receiptHead(hx(in, "body_hex"))));

            case "causal.verify":
                Graph.verifyCausal(nodesFrom(in)); // throws CausalViolation on a reject case
                return out("valid", Boolean.TRUE);

            case "delivery.update":
                return out("body_hex", Hex.encode(Records.deliveryUpdate(
                        hx(in, "obj_hex"), u64(in, "stage"), u64(in, "at"))));

            case "stream.digest": {
                List<Object> raw = (List<Object>) in.getOrDefault("chunks", List.of());
                List<Records.Chunk> chunks = new ArrayList<>(raw.size());
                for (Object r : raw) {
                    Map<String, Object> cm = (Map<String, Object>) r;
                    long offset;
                    Object o = cm.get("offset");
                    if (o instanceof Long l) {
                        offset = l;
                    } else if (o instanceof Double d) {
                        offset = (long) (double) d;
                    } else if (o instanceof String s) {
                        offset = Long.parseLong(s);
                    } else {
                        offset = 0;
                    }
                    chunks.add(new Records.Chunk(offset, Hex.decode((String) cm.get("data_hex"))));
                }
                return out("digest_hex", Hex.encode(Records.streamDigest(chunks)));
            }

            case "stream.open": {
                byte[] approval = null;
                Object a = in.get("approval_hex");
                if (a instanceof String s && !s.isEmpty()) {
                    approval = Hex.decode(s);
                }
                return out("body_hex", Hex.encode(Records.streamOpenBody(
                        hx(in, "stream_id_hex"), u64(in, "effect"), approval, u64(in, "substream"))));
            }

            case "stream.commit":
                return out("body_hex", Hex.encode(Records.streamCommitBody(
                        hx(in, "stream_id_hex"), hx(in, "digest_hex"))));

            case "stream.checkpoint":
                return out("body_hex", Hex.encode(Records.streamCheckpointBody(
                        hx(in, "stream_id_hex"), u64(in, "through_offset"), hx(in, "digest_so_far_hex"))));

            case "transport.emit":
                return out("result", Records.transportEmit(
                        str(in, "transport"), boolVal(in, "sensitive"), boolVal(in, "require_peer_auth")));

            case "carriage.body":
                return out("body_hex", Hex.encode(Records.carriageBody(
                        u64(in, "protocol_id"), u64(in, "class"), u64(in, "content_type"),
                        hx(in, "correlation_hex"), str(in, "method"), hx(in, "foreign_hex"))));

            case "channels.lookup": {
                Channels.KindSpec ks = Channels.lookup(u64(in, "channel"), u64(in, "kind"));
                return out("name", ks.name, "effect", ks.effect, "variable", ks.variable);
            }

            case "channels.effect_check":
                Channels.checkEffect(u64(in, "channel"), u64(in, "kind"), u64(in, "effect"));
                return out("ok", Boolean.TRUE);

            case "federation.reconcile": {
                List<byte[]> order = Graph.reconcile(nodesFrom(in));
                List<Object> hexes = new ArrayList<>(order.size());
                for (byte[] o : order) {
                    hexes.add(Hex.encode(o));
                }
                return out("order", hexes);
            }

            case "federation.record": {
                List<Object> authRaw = (List<Object>) in.getOrDefault("authorities", List.of());
                List<String> auths = new ArrayList<>(authRaw.size());
                for (Object a : authRaw) {
                    auths.add((String) a);
                }
                List<Object> ordRaw = (List<Object>) in.getOrDefault("order", List.of());
                List<byte[]> order = new ArrayList<>(ordRaw.size());
                for (Object o : ordRaw) {
                    order.add(Hex.decode((String) o));
                }
                return out("body_hex", Hex.encode(Graph.reconcileRecord(auths, order)));
            }

            default:
                return skipped("op not implemented: " + op);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> dispatch(byte[] body) {
        try {
            Object req = Json.parse(new String(body, StandardCharsets.UTF_8));
            if (!(req instanceof Map<?, ?> m)) {
                return error("request is not a JSON object");
            }
            Map<String, Object> reqMap = (Map<String, Object>) m;
            String op = reqMap.get("op") instanceof String s ? s : "";
            Object inObj = reqMap.get("in");
            Map<String, Object> in = inObj instanceof Map<?, ?> mm ? (Map<String, Object>) mm : new LinkedHashMap<>();
            return handle(op, in);
        } catch (NaalpException e) {
            return error(e.getMessage());
        } catch (Exception e) {
            return error("adapter exception: " + e);
        }
    }

    // ---- framing loop ----

    public static void main(String[] args) throws Exception {
        DataInputStream stdin = new DataInputStream(new java.io.BufferedInputStream(System.in));
        OutputStream stdout = new BufferedOutputStream(System.out);
        byte[] lp = new byte[4];
        while (true) {
            try {
                stdin.readFully(lp);
            } catch (EOFException eof) {
                return;
            }
            long n = (lp[0] & 0xFFL) | ((lp[1] & 0xFFL) << 8) | ((lp[2] & 0xFFL) << 16) | ((lp[3] & 0xFFL) << 24);
            byte[] body = new byte[(int) n];
            stdin.readFully(body);

            Map<String, Object> resp = dispatch(body);
            byte[] ob = Json.write(resp).getBytes(StandardCharsets.UTF_8);
            byte[] olp = new byte[4];
            int len = ob.length;
            olp[0] = (byte) (len & 0xFF);
            olp[1] = (byte) ((len >>> 8) & 0xFF);
            olp[2] = (byte) ((len >>> 16) & 0xFF);
            olp[3] = (byte) ((len >>> 24) & 0xFF);
            stdout.write(olp);
            stdout.write(ob);
            stdout.flush();
        }
    }
}
