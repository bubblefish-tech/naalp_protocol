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
                    long n = p.ValueKind == JsonValueKind.String
                        ? long.Parse(p.GetString()!, CultureInfo.InvariantCulture)
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
