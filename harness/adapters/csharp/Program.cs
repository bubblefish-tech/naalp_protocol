// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;

namespace Naalp.Adapter
{
    /// <summary>
    /// naalp-adapter-csharp — the C# N-AALP conformance adapter.
    ///
    /// <para>Wraps the <c>Naalp</c> SDK behind the length-prefixed JSON op protocol the naalp-conform
    /// runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON
    /// {"op","in"} request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on
    /// stdout, flushed after each. C# has a deterministic ML-DSA (FIPS 204) library (BouncyCastle
    /// <c>MLDsaSigner</c>, rnd=0) and Ed25519 (RFC 8032), so it implements every op including the crypto
    /// leg — it skips none.</para>
    /// </summary>
    public static class Program
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, false);

        // ---- input helpers (over the parsed JSON `in` object) ----

        private static byte[] Hx(JsonElement inn, string k)
        {
            if (inn.ValueKind == JsonValueKind.Object
                && inn.TryGetProperty(k, out JsonElement v)
                && v.ValueKind == JsonValueKind.String)
            {
                return Hex.Decode(v.GetString()!);
            }
            throw new NaalpException("Malformed", "missing hex field " + k);
        }

        private static string Str(JsonElement inn, string k)
        {
            if (inn.ValueKind == JsonValueKind.Object
                && inn.TryGetProperty(k, out JsonElement v)
                && v.ValueKind == JsonValueKind.String)
            {
                return v.GetString()!;
            }
            return "";
        }

        /// <summary>Parse a 64-bit counter from a JSON number or a decimal string.</summary>
        private static long U64(JsonElement inn, string k)
        {
            if (inn.ValueKind == JsonValueKind.Object && inn.TryGetProperty(k, out JsonElement v))
            {
                if (v.ValueKind == JsonValueKind.Number)
                {
                    return v.GetInt64();
                }
                if (v.ValueKind == JsonValueKind.String)
                {
                    return long.Parse(v.GetString()!, CultureInfo.InvariantCulture);
                }
            }
            return 0;
        }

        private static int IntVal(JsonElement inn, string k)
        {
            if (inn.ValueKind == JsonValueKind.Object && inn.TryGetProperty(k, out JsonElement v))
            {
                if (v.ValueKind == JsonValueKind.Number)
                {
                    return v.GetInt32();
                }
                if (v.ValueKind == JsonValueKind.String)
                {
                    return int.Parse(v.GetString()!, CultureInfo.InvariantCulture);
                }
            }
            return 0;
        }

        private static bool BoolVal(JsonElement inn, string k)
        {
            return inn.ValueKind == JsonValueKind.Object
                && inn.TryGetProperty(k, out JsonElement v)
                && v.ValueKind == JsonValueKind.True;
        }

        private static long NumOf(JsonElement e)
        {
            if (e.ValueKind == JsonValueKind.Number)
            {
                return e.GetInt64();
            }
            if (e.ValueKind == JsonValueKind.String)
            {
                return long.Parse(e.GetString()!, CultureInfo.InvariantCulture);
            }
            return 0;
        }

        // ---- response builders ----

        private static Dictionary<string, object?> Out(params object?[] kv)
        {
            var m = new Dictionary<string, object?>();
            for (int i = 0; i < kv.Length; i += 2)
            {
                m[(string)kv[i]!] = kv[i + 1];
            }
            return new Dictionary<string, object?> { ["out"] = m };
        }

        private static Dictionary<string, object?> Error(string msg)
            => new Dictionary<string, object?> { ["error"] = msg };

        private static Dictionary<string, object?> Skipped(string why)
            => new Dictionary<string, object?> { ["skipped"] = why };

        // ---- tagged-value -> Cbor.Value ----

        private static Cbor.Value Tagged(JsonElement v)
        {
            if (v.ValueKind != JsonValueKind.Array || v.GetArrayLength() != 2)
            {
                throw new NaalpException("Malformed", "tagged value must be [tag, payload]");
            }
            string tag = v[0].GetString()!;
            JsonElement p = v[1];
            switch (tag)
            {
                case "u":
                {
                    // A uint value can reach 2^64-1, beyond signed Int64; large uints are carried as JSON
                    // strings (they exceed the float64 safe range). Parse as ulong and reinterpret the bit
                    // pattern into the signed long Cbor.U holds (matching Long.parseUnsignedLong in the Java
                    // adapter); a bare JSON number is always within the Int64-safe range.
                    long n = p.ValueKind == JsonValueKind.String
                        ? unchecked((long)ulong.Parse(p.GetString()!, CultureInfo.InvariantCulture))
                        : p.GetInt64();
                    return new Cbor.U(n);
                }
                case "b":
                    return new Cbor.B(Hex.Decode(p.GetString()!));
                case "s":
                    return new Cbor.T(p.GetString()!);
                case "arr":
                {
                    var items = new List<Cbor.Value>(p.GetArrayLength());
                    foreach (JsonElement it in p.EnumerateArray())
                    {
                        items.Add(Tagged(it));
                    }
                    return new Cbor.A(items);
                }
                case "map":
                {
                    var pairs = new List<Cbor.Pair>(p.GetArrayLength());
                    foreach (JsonElement pr in p.EnumerateArray())
                    {
                        if (pr.ValueKind != JsonValueKind.Array || pr.GetArrayLength() != 2)
                        {
                            throw new NaalpException("Malformed", "map pair must be [k, v]");
                        }
                        pairs.Add(new Cbor.Pair(Tagged(pr[0]), Tagged(pr[1])));
                    }
                    return new Cbor.M(pairs);
                }
                default:
                    throw new NaalpException("Malformed", "unknown tag " + tag);
            }
        }

        private static List<Graph.Node> NodesFrom(JsonElement inn)
        {
            var nodes = new List<Graph.Node>();
            if (inn.ValueKind != JsonValueKind.Object
                || !inn.TryGetProperty("nodes", out JsonElement raw)
                || raw.ValueKind != JsonValueKind.Array)
            {
                return nodes;
            }
            foreach (JsonElement nm in raw.EnumerateArray())
            {
                byte[] id = Hex.Decode(nm.GetProperty("id_hex").GetString()!);
                var causes = new List<byte[]>();
                if (nm.TryGetProperty("causes_hex", out JsonElement cr) && cr.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement c in cr.EnumerateArray())
                    {
                        causes.Add(Hex.Decode(c.GetString()!));
                    }
                }
                long pos = 0;
                if (nm.TryGetProperty("position", out JsonElement pe) && pe.ValueKind == JsonValueKind.Number)
                {
                    pos = pe.GetInt64();
                }
                nodes.Add(new Graph.Node(id, causes, pos));
            }
            return nodes;
        }

        /// <summary>Same shape as <see cref="NodesFrom"/> but builds <c>Federation.CausalNode</c>s (the
        /// type <c>Federation.Reconcile</c>/<c>Federation.VerifyReconcileOrder</c> consume), for the
        /// reconcile.state op.</summary>
        private static List<Federation.CausalNode> FederationNodesFrom(JsonElement inn)
        {
            var nodes = new List<Federation.CausalNode>();
            if (inn.ValueKind != JsonValueKind.Object
                || !inn.TryGetProperty("nodes", out JsonElement raw)
                || raw.ValueKind != JsonValueKind.Array)
            {
                return nodes;
            }
            foreach (JsonElement nm in raw.EnumerateArray())
            {
                byte[] id = Hex.Decode(nm.GetProperty("id_hex").GetString()!);
                var causes = new List<byte[]>();
                if (nm.TryGetProperty("causes_hex", out JsonElement cr) && cr.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement c in cr.EnumerateArray())
                    {
                        causes.Add(Hex.Decode(c.GetString()!));
                    }
                }
                long pos = 0;
                if (nm.TryGetProperty("position", out JsonElement pe) && pe.ValueKind == JsonValueKind.Number)
                {
                    pos = pe.GetInt64();
                }
                nodes.Add(new Federation.CausalNode(id, causes, pos));
            }
            return nodes;
        }

        // ---- dispatch ----

        private static Dictionary<string, object?> Handle(string op, JsonElement inn)
        {
            switch (op)
            {
                case "sha384":
                {
                    byte[] d;
                    using (var sha = System.Security.Cryptography.SHA384.Create())
                    {
                        d = sha.ComputeHash(Hx(inn, "msg_hex"));
                    }
                    return Out("digest_hex", Hex.Encode(d));
                }

                case "cbor.encode":
                    return Out("bytes_hex", Hex.Encode(Cbor.Encode(Tagged(inn.GetProperty("value")))));

                case "cbor.decode":
                    Cbor.Decode(Hx(inn, "bytes_hex")); // throws NonCanonical on a MUST-reject case
                    return Out("ok", true);

                case "content.id":
                {
                    Cbor.Value v = Cbor.Decode(Hx(inn, "body_hex"));
                    return Out("id_hex", Hex.Encode(Cbor.ContentId(v)));
                }

                case "cose.tbs":
                    return Out("tobesigned_hex",
                        Hex.Encode(Cose.ToBeSignedRaw(Hx(inn, "protected_hex"), Hx(inn, "payload_hex"))));

                case "mldsa.keygen":
                {
                    string param = Str(inn, "param");
                    if (param == "")
                    {
                        param = "ML-DSA-65";
                    }
                    return Out("pk_hex", Hex.Encode(Cose.MldsaKeygen(param, Hx(inn, "seed_hex"))));
                }

                case "ed25519.sign":
                    return Out("sig_hex", Hex.Encode(Cose.Ed25519Sign(Hx(inn, "sk_hex"), Hx(inn, "msg_hex"))));

                case "cose.sign1":
                {
                    byte[] obj = Cose.CoseSign1(IntVal(inn, "alg"), Hx(inn, "seed_hex"),
                        Hx(inn, "protected_hex"), Hx(inn, "payload_hex"));
                    return Out("obj_hex", Hex.Encode(obj));
                }

                case "cose.verify1":
                    return Out("valid", Cose.CoseVerify1(IntVal(inn, "alg"), Hx(inn, "pubkey_hex"), Hx(inn, "obj_hex")));

                case "rotation.leg_tbs":
                    return Out("tbs_hex", Hex.Encode(Cose.SignatureToBeSigned(
                        Hx(inn, "body_protected_hex"), IntVal(inn, "leg_alg"), Hx(inn, "payload_hex"))));

                case "rotation.sign":
                {
                    byte[] prot = Hx(inn, "protected_hex");
                    byte[] payload = Hx(inn, "payload_hex");
                    byte[][] oldLeg = Cose.SignatureLeg(prot, IntVal(inn, "old_alg"), Hx(inn, "old_seed_hex"), payload);
                    byte[][] newLeg = Cose.SignatureLeg(prot, IntVal(inn, "new_alg"), Hx(inn, "new_seed_hex"), payload);
                    return Out("obj_hex", Hex.Encode(Cose.AssembleSignRaw(prot, payload, new List<byte[][]> { oldLeg, newLeg })));
                }

                case "rotation.verify":
                {
                    byte[] robj = Hx(inn, "obj_hex");
                    int oldAlg = IntVal(inn, "old_alg");
                    int newAlg = IntVal(inn, "new_alg");
                    int profile = IntVal(inn, "profile");
                    byte[] oldPk = Hx(inn, "old_pubkey_hex");
                    byte[] newPk = Hx(inn, "new_pubkey_hex");
                    // dispatch by COSE tag: tag-98 (0xd8 0x62) -> two-leg VerifyRotationObject; a tag-18
                    // single-sig object -> the general Verify, which rejects a (3,0) single-sig rotation.
                    try
                    {
                        if (robj.Length >= 2 && robj[0] == 0xd8 && robj[1] == 0x62)
                        {
                            Envelope.VerifyRotationObject(profile, oldAlg, oldPk, newAlg, newPk,
                                (ch, k) => ch == 3 && k == 0, robj);
                        }
                        else
                        {
                            Envelope.Verify(profile, newAlg, newPk, (ch, k) => ch == 3 && k == 0, robj);
                        }
                        return Out("valid", true, "error", "");
                    }
                    catch (NaalpException e)
                    {
                        return Out("valid", false, "error", e.Kind);
                    }
                }

                case "signerid":
                    return Out("signer_id", Identity.SignerId(IntVal(inn, "alg"), Hx(inn, "pubkey_hex")));

                case "nfc.check":
                    Identity.RequireNfc(Identity.Utf8(Hx(inn, "utf8_hex"))); // throws NonNFC on a reject case
                    return Out("ok", true);

                case "effect.normalize":
                    return Out("effect", Policy.NormalizeEffect(U64(inn, "value")));

                case "effect.authorize":
                    return Out("allow", Policy.Authorizes(Policy.NormalizeEffect(U64(inn, "granted")), U64(inn, "effect")));

                case "effect.safety_label":
                    return Out("cbor_hex", Hex.Encode(Policy.SafetyLabelBytes(Str(inn, "risk"), Str(inn, "scope"))));

                case "approval.body":
                case "approval.id":
                {
                    byte[] approves = Hx(inn, "approves_hex");
                    string approver = Str(inn, "approver");
                    long grant = U64(inn, "grant");
                    byte[] nonce = Hx(inn, "nonce_hex");
                    long notAfter = U64(inn, "not_after");
                    if (op == "approval.id")
                    {
                        return Out("id_hex", Hex.Encode(Records.ApprovalId(approves, approver, grant, nonce, notAfter)));
                    }
                    return Out("body_hex", Hex.Encode(Records.ApprovalBody(approves, approver, grant, nonce, notAfter)));
                }

                case "ledger.entry":
                    return Out("body_hex", Hex.Encode(Records.LedgerEntry(
                        U64(inn, "seq"), Hx(inn, "prev_hex"), Hx(inn, "approval_id_hex"), Str(inn, "by"))));

                case "approval.state":
                {
                    // ietf draft "## Approval state machine" (# Object State Machines): build ONE signed
                    // approval, then drive it through an ordered `events` list of consume attempts through
                    // the REAL composed choke point Approval.ConsumeApproval on a fresh single-use ledger;
                    // report the LAST event's {valid, error} plus the ledger length after it (the draft's
                    // "ledger left untouched by a rejected request", observable via Ledger.Len). Graded
                    // against the independent, non-circular tools/approval_state_oracle.py (F3). The
                    // approver key is a deterministic Ed25519 test key -- the signature is verified, not
                    // graded (bytes are not compared across ports for this op).
                    if (inn.ValueKind != JsonValueKind.Object || !inn.TryGetProperty("approval", out JsonElement am))
                    {
                        return Error("approval.state: missing approval object");
                    }
                    var a = new Approval.ApprovalRecord(
                        Hx(am, "approves_hex"), Str(am, "approver"), U64(am, "grant"),
                        Hx(am, "nonce_hex"), U64(am, "not_after"));
                    byte[] seed = new byte[32]; // deterministic all-zero test approver seed
                    byte[] pk = Cose.Ed25519PublicKeyFromSeed(seed);
                    byte[] sig = Cose.Ed25519Sign(seed, a.Bytes());

                    string path = Path.Combine(Path.GetTempPath(), "naalp-approval-state-" + Guid.NewGuid().ToString("N") + ".wal");
                    string lastErrKind = "";
                    int ledgerLen = 0;
                    try
                    {
                        using (Approval.Ledger ledger = Approval.OpenLedger(path))
                        {
                            if (inn.TryGetProperty("events", out JsonElement rawEvents) && rawEvents.ValueKind == JsonValueKind.Array)
                            {
                                foreach (JsonElement em in rawEvents.EnumerateArray())
                                {
                                    lastErrKind = "";
                                    string ev = Str(em, "ev");
                                    switch (ev)
                                    {
                                        case "consume":
                                            try
                                            {
                                                Approval.ConsumeApproval(a, Cose.ALG_ED25519, pk, sig,
                                                    Hx(em, "present_cid_hex"), U64(em, "pos_time"),
                                                    U64(em, "required_effect"), ledger, Str(em, "by"));
                                            }
                                            catch (NaalpException e)
                                            {
                                                lastErrKind = e.Kind;
                                            }
                                            break;
                                        default:
                                            return Error("approval.state: unknown event \"" + ev + "\"");
                                    }
                                }
                            }
                            ledgerLen = ledger.Len();
                        }
                    }
                    finally
                    {
                        if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    return Out("valid", lastErrKind == "", "error", lastErrKind, "ledger_len", ledgerLen);
                }

                case "receipt.body":
                    return Out("body_hex", Hex.Encode(Records.ReceiptBody(
                        Hx(inn, "prev_hex"), Hx(inn, "obj_hex"), U64(inn, "seq"), U64(inn, "at"))));

                case "receipt.head":
                    return Out("head_hex", Hex.Encode(Records.ReceiptHead(Hx(inn, "body_hex"))));

                case "causal.verify":
                    Graph.VerifyCausal(NodesFrom(inn)); // throws CausalViolation on a reject case
                    return Out("valid", true);

                case "delivery.update":
                    return Out("body_hex", Hex.Encode(Records.DeliveryUpdate(
                        Hx(inn, "obj_hex"), U64(inn, "stage"), U64(inn, "at"))));

                case "delivery.state":
                {
                    // ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
                    // through an ordered `events` list of signed delivery updates on a fresh WAL-backed
                    // Tracker; report the LAST event's outcome plus the object's final stage name. A
                    // rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
                    // Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
                    string path = Path.Combine(Path.GetTempPath(), "naalp-delivery-state-" + Guid.NewGuid().ToString("N") + ".wal");
                    string lastErrKind = "";
                    byte[] lastObj = Array.Empty<byte>();
                    long finalStage = 0;
                    try
                    {
                        using (Delivery.Tracker tr = Delivery.OpenTracker(path))
                        {
                            if (inn.ValueKind == JsonValueKind.Object
                                && inn.TryGetProperty("events", out JsonElement rawEvents)
                                && rawEvents.ValueKind == JsonValueKind.Array)
                            {
                                foreach (JsonElement em in rawEvents.EnumerateArray())
                                {
                                    byte[] obj = Hx(em, "obj_hex");
                                    lastObj = obj;
                                    lastErrKind = "";
                                    string ev = Str(em, "ev");
                                    switch (ev)
                                    {
                                        case "update":
                                            try
                                            {
                                                tr.Advance(obj, U64(em, "stage"), 0);
                                            }
                                            catch (NaalpException e)
                                            {
                                                lastErrKind = e.Kind;
                                            }
                                            break;
                                        default:
                                            return Error("delivery.state: unknown event \"" + ev + "\"");
                                    }
                                }
                            }
                            (finalStage, _) = tr.Stage(lastObj);
                        }
                    }
                    finally
                    {
                        if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                    return Out("valid", lastErrKind == "", "error", lastErrKind, "state", Delivery.StageName(finalStage));
                }

                case "stream.digest":
                {
                    var chunks = new List<Records.Chunk>();
                    if (inn.TryGetProperty("chunks", out JsonElement raw) && raw.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement cm in raw.EnumerateArray())
                        {
                            long offset = 0;
                            if (cm.TryGetProperty("offset", out JsonElement oe))
                            {
                                offset = NumOf(oe);
                            }
                            byte[] data = Hex.Decode(cm.GetProperty("data_hex").GetString()!);
                            chunks.Add(new Records.Chunk(offset, data));
                        }
                    }
                    return Out("digest_hex", Hex.Encode(Records.StreamDigest(chunks)));
                }

                case "stream.open":
                {
                    byte[]? approval = null;
                    if (inn.ValueKind == JsonValueKind.Object
                        && inn.TryGetProperty("approval_hex", out JsonElement a)
                        && a.ValueKind == JsonValueKind.String)
                    {
                        string s = a.GetString()!;
                        if (s.Length > 0)
                        {
                            approval = Hex.Decode(s);
                        }
                    }
                    return Out("body_hex", Hex.Encode(Records.StreamOpenBody(
                        Hx(inn, "stream_id_hex"), U64(inn, "effect"), approval, U64(inn, "substream"))));
                }

                case "stream.commit":
                    return Out("body_hex", Hex.Encode(Records.StreamCommitBody(
                        Hx(inn, "stream_id_hex"), Hx(inn, "digest_hex"))));

                case "stream.checkpoint":
                    return Out("body_hex", Hex.Encode(Records.StreamCheckpointBody(
                        Hx(inn, "stream_id_hex"), U64(inn, "through_offset"), Hx(inn, "digest_so_far_hex"))));

                case "stream.state":
                {
                    // design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream
                    // through an ordered `events` list on a fresh Guard; report the LAST event's outcome
                    // plus the stream's final state. Graded against the independent, non-circular
                    // tools/streamstate_oracle.py (F3).
                    var guard = new Streaming.Guard();
                    string lastErrKind = "";
                    byte[] lastStream = Array.Empty<byte>();
                    if (inn.ValueKind == JsonValueKind.Object
                        && inn.TryGetProperty("events", out JsonElement rawEvents)
                        && rawEvents.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement em in rawEvents.EnumerateArray())
                        {
                            byte[] sid = Hx(em, "stream_hex");
                            lastStream = sid;
                            string ev = Str(em, "ev");
                            lastErrKind = "";
                            try
                            {
                                switch (ev)
                                {
                                    case "open":
                                    {
                                        var o = new Streaming.StreamOpen(sid, U64(em, "effect"), null, 0);
                                        guard.Open(o, U64(em, "granted"));
                                        break;
                                    }
                                    case "chunk":
                                        guard.Chunk(sid);
                                        break;
                                    case "checkpoint":
                                        guard.Checkpoint(sid);
                                        break;
                                    case "commit":
                                    {
                                        var chunks = new List<Streaming.Chunk>();
                                        if (em.TryGetProperty("chunks", out JsonElement rawChunks)
                                            && rawChunks.ValueKind == JsonValueKind.Array)
                                        {
                                            foreach (JsonElement cm in rawChunks.EnumerateArray())
                                            {
                                                long offset = NumOf(cm.GetProperty("offset"));
                                                byte[] data = Hex.Decode(cm.GetProperty("data_hex").GetString()!);
                                                chunks.Add(new Streaming.Chunk(offset, data));
                                            }
                                        }
                                        byte[] digest = Hx(em, "digest_hex");
                                        guard.Commit(new Streaming.StreamCommit(sid, digest), chunks);
                                        break;
                                    }
                                    case "expire":
                                        guard.Expire(sid);
                                        break;
                                    default:
                                        return Error("stream.state: unknown event \"" + ev + "\"");
                                }
                            }
                            catch (NaalpException e)
                            {
                                lastErrKind = e.Kind;
                            }
                        }
                    }
                    return Out("valid", lastErrKind == "", "error", lastErrKind,
                        "state", Streaming.StateName(guard.GetState(lastStream)));
                }

                case "transport.emit":
                    return Out("result", Records.TransportEmit(
                        Str(inn, "transport"), BoolVal(inn, "sensitive"), BoolVal(inn, "require_peer_auth")));

                case "carriage.body":
                    return Out("body_hex", Hex.Encode(Records.CarriageBody(
                        U64(inn, "protocol_id"), U64(inn, "class"), U64(inn, "content_type"),
                        Hx(inn, "correlation_hex"), Str(inn, "method"), Hx(inn, "foreign_hex"))));

                case "channels.lookup":
                {
                    Channels.KindSpec ks = Channels.Lookup(U64(inn, "channel"), U64(inn, "kind"));
                    return Out("name", ks.Name, "effect", ks.Effect, "variable", ks.Variable);
                }

                case "channels.effect_check":
                    Channels.CheckEffect(U64(inn, "channel"), U64(inn, "kind"), U64(inn, "effect"));
                    return Out("ok", true);

                case "federation.reconcile":
                {
                    List<byte[]> order = Graph.Reconcile(NodesFrom(inn));
                    var hexes = new List<object?>(order.Count);
                    foreach (byte[] o in order)
                    {
                        hexes.Add(Hex.Encode(o));
                    }
                    return Out("order", hexes);
                }

                case "federation.record":
                {
                    var auths = new List<string>();
                    if (inn.TryGetProperty("authorities", out JsonElement authRaw) && authRaw.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement a in authRaw.EnumerateArray())
                        {
                            auths.Add(a.GetString()!);
                        }
                    }
                    var order = new List<byte[]>();
                    if (inn.TryGetProperty("order", out JsonElement ordRaw) && ordRaw.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement o in ordRaw.EnumerateArray())
                        {
                            order.Add(Hex.Decode(o.GetString()!));
                        }
                    }
                    return Out("body_hex", Hex.Encode(Graph.ReconcileRecord(auths, order)));
                }

                case "reconcile.state":
                {
                    // ietf draft "## Reconcile state machine" (# Object State Machines): drive the
                    // machine through ONE event (add-chain | linearize | verify) on fresh state and
                    // report {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe
                    // pipeline (a `chain` that must independently pass VerifyChain, plus an optional
                    // `extra` receipt fed only to Observe — a chain array cannot itself carry a
                    // duplicate seq without independently tripping ChainBroken, so equivocation is
                    // exercised via the separate `extra` observation); linearize runs
                    // Federation.Reconcile (which calls Federation.VerifyCausal internally); verify runs
                    // Federation.VerifyReconcileOrder, which MUST recompute via Reconcile (content-id
                    // tie-break), never Audit.TopoOrder (position tie-break). Graded against the
                    // independent, non-circular tools/reconcile_state_oracle.py (F3). The authority key
                    // is a deterministic all-zero-seed ML-DSA-65 test key — the signature is verified,
                    // not graded (bytes are not compared across ports for this op). Note:
                    // Audit.Auditor.Observe RETURNS a ForkProof on equivocation (it does not throw); a
                    // non-null return is the Equivocation outcome.
                    const int alg = Cose.ALG_MLDSA65;
                    byte[] seed = new byte[32]; // deterministic all-zero test authority seed
                    byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);

                    Audit.Receipt BuildReceipt(JsonElement rm)
                        => new Audit.Receipt(Hx(rm, "prev_hex"), Hx(rm, "obj_hex"), U64(rm, "seq"), U64(rm, "at"));

                    string lastErrKind = "";
                    switch (Str(inn, "event"))
                    {
                        case "add-chain":
                        {
                            var receipts = new List<Audit.Receipt>();
                            var sigs = new List<byte[]>();
                            if (inn.TryGetProperty("chain", out JsonElement rawChain) && rawChain.ValueKind == JsonValueKind.Array)
                            {
                                foreach (JsonElement rm in rawChain.EnumerateArray())
                                {
                                    Audit.Receipt r = BuildReceipt(rm);
                                    receipts.Add(r);
                                    sigs.Add(Cose.MldsaSign(alg, seed, r.Bytes()));
                                }
                            }
                            if (inn.TryGetProperty("corrupt_sig_at", out JsonElement ci) && ci.ValueKind == JsonValueKind.Number)
                            {
                                int idx = ci.GetInt32();
                                sigs[idx][0] ^= 0xFF;
                            }
                            try
                            {
                                Audit.VerifyChain(receipts, sigs, alg, pk);
                                var auditor = new Audit.Auditor(alg, pk, pk);
                                for (int i = 0; i < receipts.Count && lastErrKind == ""; i++)
                                {
                                    if (auditor.Observe(receipts[i], sigs[i]) != null)
                                    {
                                        lastErrKind = "Equivocation";
                                    }
                                }
                                if (lastErrKind == ""
                                    && inn.TryGetProperty("extra", out JsonElement em)
                                    && em.ValueKind == JsonValueKind.Object)
                                {
                                    Audit.Receipt er = BuildReceipt(em);
                                    byte[] esig = Cose.MldsaSign(alg, seed, er.Bytes());
                                    if (auditor.Observe(er, esig) != null)
                                    {
                                        lastErrKind = "Equivocation";
                                    }
                                }
                            }
                            catch (NaalpException e)
                            {
                                lastErrKind = e.Kind;
                            }
                            return Out("valid", lastErrKind == "", "error", lastErrKind);
                        }

                        case "linearize":
                        {
                            List<Federation.CausalNode> nodes = FederationNodesFrom(inn);
                            try
                            {
                                Federation.Reconcile(nodes);
                            }
                            catch (NaalpException e)
                            {
                                lastErrKind = e.Kind;
                            }
                            return Out("valid", lastErrKind == "", "error", lastErrKind);
                        }

                        case "verify":
                        {
                            List<Federation.CausalNode> nodes = FederationNodesFrom(inn);
                            var order = new List<byte[]>();
                            if (inn.TryGetProperty("claimed_order_hex", out JsonElement ordRaw) && ordRaw.ValueKind == JsonValueKind.Array)
                            {
                                foreach (JsonElement o in ordRaw.EnumerateArray())
                                {
                                    order.Add(Hex.Decode(o.GetString()!));
                                }
                            }
                            var rec = new Federation.ReconcileRecord(new List<string>(), order);
                            try
                            {
                                Federation.VerifyReconcileOrder(rec, nodes);
                            }
                            catch (NaalpException e)
                            {
                                lastErrKind = e.Kind;
                            }
                            return Out("valid", lastErrKind == "", "error", lastErrKind);
                        }

                        default:
                            return Error("reconcile.state: unknown event \"" + Str(inn, "event") + "\"");
                    }
                }

                case "object.decode":
                {
                    // R7 decoder resource bounds: decode + bound-enforce an untrusted object; all four
                    // object-level bounds fire BEFORE the COSE signature is checked, so NO verifier is
                    // needed. over_size materializes the octet-size bound (rejected on raw length before
                    // any parse).
                    byte[] obj;
                    if (inn.ValueKind == JsonValueKind.Object && inn.TryGetProperty("over_size", out JsonElement ov))
                    {
                        obj = new byte[IntVal(inn, "over_size")];
                    }
                    else
                    {
                        obj = Hx(inn, "obj_hex");
                    }
                    try
                    {
                        Envelope.Verify(1, 0, Array.Empty<byte>(), (ch, k) => true, obj);
                        return Out("valid", true, "error", "");
                    }
                    catch (NaalpException e)
                    {
                        return Out("valid", false, "error", e.Kind);
                    }
                }

                case "stream.verify_commit":
                {
                    int n = IntVal(inn, "chunk_count");
                    var chunks = new List<Streaming.Chunk>(n);
                    for (int i = 0; i < n; i++)
                    {
                        chunks.Add(new Streaming.Chunk(0, Array.Empty<byte>()));
                    }
                    try
                    {
                        Streaming.VerifyCommit(new Streaming.StreamCommit(Array.Empty<byte>(), Array.Empty<byte>()), chunks);
                        return Out("valid", true, "error", "");
                    }
                    catch (NaalpException e)
                    {
                        return Out("valid", false, "error", e.Kind);
                    }
                }

                // ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
                case "composite.mprime":
                    return Out("mprime_hex", Hex.Encode(Cose.ComputeMprime(
                        Encoding.ASCII.GetBytes("COMPSIG-MLDSA65-Ed25519-SHA512"), Array.Empty<byte>(), Hx(inn, "m_hex"))));

                case "composite.signerid":
                    return Out("signer_id", Identity.CompositeSignerId(
                        IntVal(inn, "mldsa_alg"), Hx(inn, "mldsa_pubkey_hex"), Hx(inn, "ed_pubkey_hex")));

                case "composite.sign":
                    return Out("value_hex", Hex.Encode(Cose.CompositeSign(
                        Hx(inn, "mldsa_seed_hex"), Hx(inn, "ed_seed_hex"), Hx(inn, "tbs_hex"))));

                case "composite.verify":
                    return Out("valid", Cose.CompositeVerify(
                        Hx(inn, "mldsa_pubkey_hex"), Hx(inn, "ed_pubkey_hex"), Hx(inn, "m_hex"), Hx(inn, "sig_hex")));

                case "error.name_for_code":
                {
                    // T3.3: the naalp-error registry table lookup (design.md §3.5). Grades the port's
                    // embedded 119-entry name<->code table per-code, plus the unknown-code (opaque)
                    // contract.
                    (string name, bool registered) = NaalpError.NameForCode(IntVal(inn, "code"));
                    return Out("name", name, "registered", registered);
                }

                case "error.encode":
                {
                    // T3.3: deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail,
                    // ?4:subject}.
                    byte[]? subj = null;
                    if (inn.ValueKind == JsonValueKind.Object && inn.TryGetProperty("subject_hex", out JsonElement _))
                    {
                        subj = Hx(inn, "subject_hex");
                    }
                    string detail = Str(inn, "detail");
                    string name = Str(inn, "name");
                    byte[] b = NaalpError.Encode(IntVal(inn, "code"), name, detail, subj);
                    return Out("body_hex", Hex.Encode(b));
                }

                case "error.decode":
                {
                    // T3.3: parse + dual-carriage validate a naalp-error body (registered code + wrong
                    // name -> Malformed; unknown code -> opaque accept).
                    byte[] body = Hx(inn, "body_hex");
                    try
                    {
                        NaalpError.Object eo = NaalpError.Decode(body);
                        return Out("valid", true, "code", eo.Code, "name", eo.Name);
                    }
                    catch (NaalpException e)
                    {
                        return Out("valid", false, "error", e.Kind);
                    }
                }

                default:
                    return Skipped("op not implemented: " + op);
            }
        }

        private static Dictionary<string, object?> Dispatch(byte[] body)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(body);
                JsonElement req = doc.RootElement;
                if (req.ValueKind != JsonValueKind.Object)
                {
                    return Error("request is not a JSON object");
                }
                string op = req.TryGetProperty("op", out JsonElement opE) && opE.ValueKind == JsonValueKind.String
                    ? opE.GetString()!
                    : "";
                JsonElement inn = req.TryGetProperty("in", out JsonElement inE) && inE.ValueKind == JsonValueKind.Object
                    ? inE
                    : default;
                return Handle(op, inn);
            }
            catch (NaalpException e)
            {
                return Error(e.Message);
            }
            catch (Exception e)
            {
                return Error("adapter exception: " + e);
            }
        }

        // ---- JSON output writer ----

        private static byte[] Serialize(Dictionary<string, object?> resp)
        {
            var sb = new StringBuilder();
            WriteValue(sb, resp);
            return Utf8.GetBytes(sb.ToString());
        }

        private static void WriteValue(StringBuilder sb, object? v)
        {
            switch (v)
            {
                case null:
                    sb.Append("null");
                    break;
                case bool b:
                    sb.Append(b ? "true" : "false");
                    break;
                case string s:
                    WriteString(sb, s);
                    break;
                case int i:
                    sb.Append(i.ToString(CultureInfo.InvariantCulture));
                    break;
                case long l:
                    sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    break;
                case Dictionary<string, object?> m:
                {
                    sb.Append('{');
                    bool first = true;
                    foreach (KeyValuePair<string, object?> kv in m)
                    {
                        if (!first)
                        {
                            sb.Append(',');
                        }
                        first = false;
                        WriteString(sb, kv.Key);
                        sb.Append(':');
                        WriteValue(sb, kv.Value);
                    }
                    sb.Append('}');
                    break;
                }
                case IEnumerable<object?> arr:
                {
                    sb.Append('[');
                    bool first = true;
                    foreach (object? item in arr)
                    {
                        if (!first)
                        {
                            sb.Append(',');
                        }
                        first = false;
                        WriteValue(sb, item);
                    }
                    sb.Append(']');
                    break;
                }
                default:
                    // Fallback: stringify unknown types (should not occur for the fixed out shapes).
                    WriteString(sb, v.ToString() ?? "");
                    break;
            }
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.Append("\\u");
                            sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }

        // ---- framing loop ----

        public static int Main()
        {
            using Stream stdin = Console.OpenStandardInput();
            using Stream stdout = Console.OpenStandardOutput();
            byte[] lp = new byte[4];
            while (true)
            {
                if (!ReadFully(stdin, lp, 4))
                {
                    return 0; // clean EOF
                }
                int n = (lp[0] & 0xFF) | ((lp[1] & 0xFF) << 8) | ((lp[2] & 0xFF) << 16) | ((lp[3] & 0xFF) << 24);
                byte[] body = new byte[n];
                if (n > 0 && !ReadFully(stdin, body, n))
                {
                    return 0; // truncated stream
                }
                Dictionary<string, object?> resp = Dispatch(body);
                byte[] ob = Serialize(resp);
                byte[] olp = new byte[4];
                int len = ob.Length;
                olp[0] = (byte)(len & 0xFF);
                olp[1] = (byte)((len >> 8) & 0xFF);
                olp[2] = (byte)((len >> 16) & 0xFF);
                olp[3] = (byte)((len >> 24) & 0xFF);
                stdout.Write(olp, 0, 4);
                stdout.Write(ob, 0, ob.Length);
                stdout.Flush();
            }
        }

        private static bool ReadFully(Stream s, byte[] buf, int len)
        {
            int off = 0;
            while (off < len)
            {
                int r = s.Read(buf, off, len - off);
                if (r <= 0)
                {
                    return false;
                }
                off += r;
            }
            return true;
        }
    }
}
