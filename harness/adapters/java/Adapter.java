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

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

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

    /** Like {@link #nodesFrom}, but for {@link Federation.CausalNode} (id + causes only, no
     * position — the federated tier's reconcile() always ties by content id, never by position). */
    @SuppressWarnings("unchecked")
    private static List<Federation.CausalNode> federationNodesFrom(Map<String, Object> in) {
        List<Object> raw = (List<Object>) in.getOrDefault("nodes", List.of());
        List<Federation.CausalNode> nodes = new ArrayList<>(raw.size());
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
            nodes.add(new Federation.CausalNode(id, causes));
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

            case "rotation.leg_tbs":
                return out("tbs_hex", Hex.encode(Cose.signatureToBeSigned(
                        hx(in, "body_protected_hex"), intVal(in, "leg_alg"), hx(in, "payload_hex"))));

            case "rotation.sign": {
                byte[] prot = hx(in, "protected_hex");
                byte[] payload = hx(in, "payload_hex");
                byte[][] oldLeg = Cose.signatureLeg(prot, intVal(in, "old_alg"), hx(in, "old_seed_hex"), payload);
                byte[][] newLeg = Cose.signatureLeg(prot, intVal(in, "new_alg"), hx(in, "new_seed_hex"), payload);
                return out("obj_hex", Hex.encode(Cose.assembleSignRaw(prot, payload, List.of(oldLeg, newLeg))));
            }

            case "rotation.verify": {
                byte[] robj = hx(in, "obj_hex");
                int oldAlg = intVal(in, "old_alg");
                int newAlg = intVal(in, "new_alg");
                int profile = intVal(in, "profile");
                byte[] oldPk = hx(in, "old_pubkey_hex");
                byte[] newPk = hx(in, "new_pubkey_hex");
                Envelope.KindValidator kindOk = (ch, k) -> ch == 3 && k == 0;
                // dispatch by COSE tag: tag-98 (0xd8 0x62) -> two-leg verifyRotationObject; a tag-18
                // single-sig object -> the general verify, which rejects a (3,0) single-sig rotation.
                try {
                    if (robj.length >= 2 && (robj[0] & 0xff) == 0xd8 && (robj[1] & 0xff) == 0x62) {
                        Envelope.verifyRotationObject(profile, oldAlg, oldPk, newAlg, newPk, kindOk, robj, null);
                    } else {
                        Envelope.verify(profile, newAlg, newPk, kindOk, robj, null);
                    }
                    return out("valid", true, "error", "");
                } catch (NaalpException e) {
                    return out("valid", false, "error", e.kind);
                }
            }

            case "object.decode": {
                // R7 decoder resource bounds: decode + bound-enforce an untrusted object; all four
                // object-level bounds fire BEFORE the COSE signature is checked, so no verifier is
                // needed. over_size materializes the octet-size bound (rejected on raw length before
                // any parse).
                byte[] obj;
                if (in.containsKey("over_size")) {
                    obj = new byte[intVal(in, "over_size")];
                } else {
                    obj = hx(in, "obj_hex");
                }
                Envelope.KindValidator kindOk = (ch, k) -> true;
                try {
                    Envelope.verify(1, 0, new byte[0], kindOk, obj, null); // never reached for a reject
                    return out("valid", true, "error", "");
                } catch (NaalpException e) {
                    return out("valid", false, "error", e.kind);
                }
            }

            case "stream.verify_commit": {
                int n = intVal(in, "chunk_count");
                List<Streaming.Chunk> chunks = new ArrayList<>(n); // n empty chunks
                for (int i = 0; i < n; i++) {
                    chunks.add(new Streaming.Chunk(0, new byte[0]));
                }
                Streaming.StreamCommit commit = new Streaming.StreamCommit(new byte[0], new byte[0]);
                try {
                    Streaming.verifyCommit(commit, chunks); // count check fires before digest
                    return out("valid", true, "error", "");
                } catch (NaalpException e) {
                    return out("valid", false, "error", e.kind);
                }
            }

            case "error.name_for_code": {
                // T3.3: the naalp-error registry table lookup (design.md §3.5). Grades the port's
                // embedded 119-entry name<->code table per-code, plus the unknown-code (opaque)
                // contract.
                NaalpError.Lookup l = NaalpError.nameForCode(u64(in, "code"));
                return out("name", l.name, "registered", l.registered);
            }

            case "error.encode": {
                // T3.3: deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail, ?4:subject}.
                byte[] subj = null;
                if (in.containsKey("subject_hex")) {
                    subj = hx(in, "subject_hex");
                }
                byte[] b = NaalpError.encode(u64(in, "code"), str(in, "name"), str(in, "detail"), subj);
                return out("body_hex", Hex.encode(b));
            }

            case "error.decode": {
                // T3.3: parse + dual-carriage validate a naalp-error body (registered code + wrong
                // name -> Malformed; unknown code -> opaque accept).
                byte[] body = hx(in, "body_hex");
                try {
                    NaalpError.Object eo = NaalpError.decode(body);
                    return out("valid", true, "code", eo.code, "name", eo.name);
                } catch (NaalpException e) {
                    return out("valid", false, "error", e.kind);
                }
            }

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

            case "approval.state": {
                // ietf draft "## Approval state machine" (# Object State Machines): build ONE signed
                // approval, then drive it through an ordered `events` list of consume attempts through
                // the REAL composed choke point Approval.consumeApproval on a fresh single-use ledger;
                // report the LAST event's {valid, error} plus the ledger length after it (the draft's
                // "ledger left untouched by a rejected request", observable via Ledger.len()). Graded
                // against the independent, non-circular tools/approval_state_oracle.py (F3). The
                // approver key is a deterministic Ed25519 test key -- the signature is verified, not
                // graded (bytes are not compared across ports for this op).
                Object amObj = in.get("approval");
                if (!(amObj instanceof Map)) {
                    return error("approval.state: missing approval object");
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> am = (Map<String, Object>) amObj;
                byte[] apprApproves = hx(am, "approves_hex");
                byte[] apprNonce = hx(am, "nonce_hex");
                Approval.ApprovalRecord apprA = new Approval.ApprovalRecord(
                        apprApproves, str(am, "approver"), u64(am, "grant"), apprNonce, u64(am, "not_after"));

                byte[] apprSeed = new byte[32]; // deterministic all-zero test approver seed
                byte[] apprPk = new Ed25519PrivateKeyParameters(apprSeed, 0).generatePublicKey().getEncoded();
                byte[] apprSig = Cose.ed25519Sign(apprSeed, apprA.bytes());

                java.io.File apprTf;
                try {
                    apprTf = java.io.File.createTempFile("naalp-approval-state-", ".wal");
                } catch (java.io.IOException e) {
                    return error(e.toString());
                }
                Approval.Ledger apprLedger = Approval.Ledger.open(apprTf.toPath());
                try {
                    @SuppressWarnings("unchecked")
                    List<Object> rawEvents = (List<Object>) in.getOrDefault("events", List.of());
                    NaalpException lastErr = null;
                    for (Object re : rawEvents) {
                        if (!(re instanceof Map)) {
                            return error("approval.state: event is not an object");
                        }
                        @SuppressWarnings("unchecked")
                        Map<String, Object> em = (Map<String, Object>) re;
                        if (!"consume".equals(str(em, "ev"))) {
                            return error("approval.state: unknown event " + str(em, "ev"));
                        }
                        byte[] presentCid = hx(em, "present_cid_hex");
                        lastErr = null;
                        try {
                            Approval.consumeApproval(apprA, Cose.ALG_ED25519, apprPk, apprSig, presentCid,
                                    u64(em, "pos_time"), u64(em, "required_effect"), apprLedger, str(em, "by"));
                        } catch (NaalpException e) {
                            lastErr = e;
                        }
                    }
                    return out(
                            "valid", lastErr == null,
                            "error", lastErr == null ? "" : lastErr.kind,
                            "ledger_len", apprLedger.len());
                } finally {
                    apprLedger.close();
                    apprTf.delete();
                }
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

            case "delivery.state": {
                // ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
                // through an ordered `events` list of signed delivery updates on a fresh WAL-backed
                // Tracker; report the LAST event's outcome plus the object's final stage name. A
                // rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
                // Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
                List<Object> rawEvents = (List<Object>) in.getOrDefault("events", List.of());
                java.io.File tf;
                try {
                    tf = java.io.File.createTempFile("naalp-delivery-state-", ".wal");
                } catch (java.io.IOException e) {
                    return error(e.toString());
                }
                Delivery.Tracker tr = Delivery.openTracker(tf.getAbsolutePath());
                try {
                    NaalpException lastErr = null;
                    byte[] lastObj = new byte[0];
                    for (Object re : rawEvents) {
                        Map<String, Object> em = (Map<String, Object>) re;
                        byte[] obj = hx(em, "obj_hex");
                        lastObj = obj;
                        if (!"update".equals(str(em, "ev"))) {
                            return error("delivery.state: unknown event " + str(em, "ev"));
                        }
                        lastErr = null;
                        try {
                            tr.advance(obj, u64(em, "stage"), 0);
                        } catch (NaalpException e) {
                            lastErr = e;
                        }
                    }
                    Delivery.StageResult sr = tr.stage(lastObj);
                    return out(
                            "valid", lastErr == null,
                            "error", lastErr == null ? "" : lastErr.kind,
                            "state", Delivery.stageName(sr.stage));
                } finally {
                    tr.close();
                    tf.delete();
                }
            }

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

            case "stream.state": {
                // design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream
                // through an ordered `events` list on a fresh Guard; report the LAST event's outcome
                // plus the stream's final state. Graded against the independent, non-circular
                // tools/streamstate_oracle.py (F3).
                List<Object> rawEvents = (List<Object>) in.getOrDefault("events", List.of());
                Streaming.Guard g = Streaming.Guard.newGuard();
                NaalpException lastErr = null;
                byte[] lastStream = new byte[0];
                for (Object re : rawEvents) {
                    Map<String, Object> em = (Map<String, Object>) re;
                    byte[] sid = hx(em, "stream_hex");
                    lastStream = sid;
                    lastErr = null;
                    try {
                        switch (str(em, "ev")) {
                            case "open": {
                                Streaming.StreamOpen o = new Streaming.StreamOpen(sid, u64(em, "effect"), null, 0);
                                g.open(o, u64(em, "granted"));
                                break;
                            }
                            case "chunk":
                                g.chunk(sid);
                                break;
                            case "checkpoint":
                                g.checkpoint(sid);
                                break;
                            case "commit": {
                                List<Object> rawChunks = (List<Object>) em.getOrDefault("chunks", List.of());
                                List<Streaming.Chunk> chunks = new ArrayList<>(rawChunks.size());
                                for (Object rc : rawChunks) {
                                    Map<String, Object> cm = (Map<String, Object>) rc;
                                    chunks.add(new Streaming.Chunk(u64(cm, "offset"), Hex.decode((String) cm.get("data_hex"))));
                                }
                                Streaming.StreamCommit c = new Streaming.StreamCommit(sid, hx(em, "digest_hex"));
                                g.commit(c, chunks);
                                break;
                            }
                            case "expire":
                                g.expire(sid);
                                break;
                            default:
                                return error("stream.state: unknown event " + str(em, "ev"));
                        }
                    } catch (NaalpException e) {
                        lastErr = e;
                    }
                }
                return out(
                        "valid", lastErr == null,
                        "error", lastErr == null ? "" : lastErr.kind,
                        "state", g.state(lastStream).toString());
            }

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

            case "reconcile.state": {
                // ietf draft "## Reconcile state machine" (# Object State Machines): drive the
                // machine through ONE event (add-chain | linearize | verify) on fresh state and
                // report {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe
                // pipeline (a `chain` that must independently pass Audit.verifyChain, plus an
                // optional `extra` receipt fed only to Auditor.observe — a chain array cannot
                // itself carry a duplicate seq without independently tripping ChainBroken, so
                // equivocation is exercised via the separate `extra` observation); linearize runs
                // Federation.reconcile (which verifies the causal graph internally, content-id
                // tie-break); verify runs Federation.verifyReconcileOrder, which MUST recompute via
                // Federation.reconcile (content-id tie-break), never Audit.topoOrder (position
                // tie-break). Graded against the independent, non-circular
                // tools/reconcile_state_oracle.py (F3). The authority key is a deterministic
                // all-zero-seed ML-DSA-65 test authority key — java's audit primitive is ML-DSA
                // (verifyChain(receipts, sigs, alg, pubkey)), per AuditKatTest's own pattern — the
                // signature is verified, not graded (bytes are not compared across ports for this
                // op). NOTE: Audit.Auditor.observe RETURNS a ForkProof on equivocation rather than
                // throwing; a non-null return here is treated as the Equivocation outcome.
                int rsAlg = Cose.ALG_MLDSA65;
                byte[] rsSeed = new byte[32]; // deterministic all-zero test authority seed
                byte[] rsPk = Cose.mldsaKeygen("ML-DSA-65", rsSeed);

                switch (str(in, "event")) {
                    case "add-chain": {
                        List<Object> rawChain = (List<Object>) in.getOrDefault("chain", List.of());
                        List<Audit.Receipt> receipts = new ArrayList<>(rawChain.size());
                        List<byte[]> sigs = new ArrayList<>(rawChain.size());
                        for (Object rc : rawChain) {
                            Map<String, Object> rm = (Map<String, Object>) rc;
                            Audit.Receipt r = new Audit.Receipt(
                                    hx(rm, "prev_hex"), hx(rm, "obj_hex"), u64(rm, "seq"), u64(rm, "at"));
                            receipts.add(r);
                            sigs.add(Cose.mldsaSign(rsAlg, rsSeed, r.bytes()));
                        }
                        Object corrupt = in.get("corrupt_sig_at");
                        int corruptIdx = -1;
                        if (corrupt instanceof Long l) {
                            corruptIdx = l.intValue();
                        } else if (corrupt instanceof Double d) {
                            corruptIdx = d.intValue();
                        }
                        if (corruptIdx >= 0) {
                            byte[] corrupted = sigs.get(corruptIdx).clone();
                            corrupted[0] ^= (byte) 0xFF;
                            sigs.set(corruptIdx, corrupted);
                        }
                        NaalpException lastErr = null;
                        try {
                            Audit.verifyChain(receipts, sigs, rsAlg, rsPk);
                        } catch (NaalpException e) {
                            lastErr = e;
                        }
                        if (lastErr == null) {
                            Audit.Auditor auditor = new Audit.Auditor(rsAlg, rsPk, rsPk);
                            for (int i = 0; i < receipts.size() && lastErr == null; i++) {
                                try {
                                    if (auditor.observe(receipts.get(i), sigs.get(i)) != null) {
                                        lastErr = new NaalpException("Equivocation", "equivocation detected");
                                    }
                                } catch (NaalpException e) {
                                    lastErr = e;
                                }
                            }
                            if (lastErr == null && in.get("extra") instanceof Map<?, ?> em) {
                                Map<String, Object> extraMap = (Map<String, Object>) em;
                                Audit.Receipt er = new Audit.Receipt(hx(extraMap, "prev_hex"),
                                        hx(extraMap, "obj_hex"), u64(extraMap, "seq"), u64(extraMap, "at"));
                                byte[] esig = Cose.mldsaSign(rsAlg, rsSeed, er.bytes());
                                try {
                                    if (auditor.observe(er, esig) != null) {
                                        lastErr = new NaalpException("Equivocation", "equivocation detected");
                                    }
                                } catch (NaalpException e) {
                                    lastErr = e;
                                }
                            }
                        }
                        return out("valid", lastErr == null, "error", lastErr == null ? "" : lastErr.kind);
                    }

                    case "linearize": {
                        List<Federation.CausalNode> nodes = federationNodesFrom(in);
                        NaalpException lastErr = null;
                        try {
                            Federation.reconcile(nodes);
                        } catch (NaalpException e) {
                            lastErr = e;
                        }
                        return out("valid", lastErr == null, "error", lastErr == null ? "" : lastErr.kind);
                    }

                    case "verify": {
                        List<Federation.CausalNode> nodes = federationNodesFrom(in);
                        List<Object> rawOrder = (List<Object>) in.getOrDefault("claimed_order_hex", List.of());
                        List<byte[]> order = new ArrayList<>(rawOrder.size());
                        for (Object o : rawOrder) {
                            order.add(Hex.decode((String) o));
                        }
                        Federation.ReconcileRecord rec = new Federation.ReconcileRecord(List.of(), order);
                        NaalpException lastErr = null;
                        try {
                            Federation.verifyReconcileOrder(rec, nodes);
                        } catch (NaalpException e) {
                            lastErr = e;
                        }
                        return out("valid", lastErr == null, "error", lastErr == null ? "" : lastErr.kind);
                    }

                    default:
                        return error("reconcile.state: unknown event " + str(in, "event"));
                }
            }

            // ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
            case "composite.mprime":
                return out("mprime_hex", Hex.encode(Cose.computeMprime(
                        "COMPSIG-MLDSA65-Ed25519-SHA512".getBytes(StandardCharsets.US_ASCII),
                        new byte[0], hx(in, "m_hex"))));

            case "composite.signerid":
                return out("signer_id", Identity.compositeSignerId(
                        intVal(in, "mldsa_alg"), hx(in, "mldsa_pubkey_hex"), hx(in, "ed_pubkey_hex")));

            case "composite.sign":
                return out("value_hex", Hex.encode(Cose.compositeSign(
                        hx(in, "mldsa_seed_hex"), hx(in, "ed_seed_hex"), hx(in, "tbs_hex"))));

            case "composite.verify":
                return out("valid", Cose.compositeVerify(
                        hx(in, "mldsa_pubkey_hex"), hx(in, "ed_pubkey_hex"), hx(in, "m_hex"), hx(in, "sig_hex")));

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
