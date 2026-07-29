// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// naalp-adapter-rust — the second reference N-AALP conformance adapter.
//
// It wraps the `naalp` (impl/rust) crate behind the same length-prefixed JSON op protocol the
// naalp-conform runner drives (see harness/INSTRUCTIONS.md): a 4-byte little-endian length + a
// UTF-8 JSON {"op","in"} request on stdin, and a {"out"|"error"|"skipped"} response in the same
// framing on stdout, flushed after each. Grading the Rust adapter against the same corpus as the
// Go adapter is the harness proof that the two independent implementations agree byte-for-byte.
use std::io::{self, Read, Write};

use serde_json::{json, Value as J};

use fips204::traits::SerDes;
use naalp::cose::CoseSigner as _;
use naalp::{approval, audit, carriage, cbor, channels, cose, delivery, federation, identity, policy, streaming, transport};

// ---- input helpers ----

fn hx(inp: &J, k: &str) -> Result<Vec<u8>, String> {
    let s = inp.get(k).and_then(|v| v.as_str()).ok_or_else(|| format!("missing hex field {k}"))?;
    hex::decode(s).map_err(|e| e.to_string())
}

fn sf(inp: &J, k: &str) -> String {
    inp.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

// u64 tolerant of a JSON number or a decimal string
fn u(inp: &J, k: &str) -> u64 {
    match inp.get(k) {
        Some(J::Number(n)) => n.as_u64().unwrap_or(0),
        Some(J::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn iof(v: Option<&J>) -> i64 {
    match v {
        Some(J::Number(n)) => n.as_i64().unwrap_or(0),
        Some(J::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn bf(inp: &J, k: &str) -> bool {
    inp.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn hx_list(bs: &[Vec<u8>]) -> Vec<String> {
    bs.iter().map(hex::encode).collect()
}

// tagged value -> cbor::Value, so the encoder under test produces the bytes.
fn tagged(v: &J) -> Result<cbor::Value, String> {
    let arr = v.as_array().ok_or("tagged value must be [tag, payload]")?;
    if arr.len() != 2 {
        return Err("tagged value must be [tag, payload]".into());
    }
    let tag = arr[0].as_str().ok_or("tag must be a string")?;
    let p = &arr[1];
    match tag {
        "u" => {
            let n = match p {
                J::Number(nn) => nn.as_u64().ok_or("u payload not u64")?,
                J::String(s) => s.parse().map_err(|_| "u payload not u64")?,
                _ => return Err("u payload not a number".into()),
            };
            Ok(cbor::Value::Uint(n))
        }
        "b" => {
            let s = p.as_str().ok_or("b payload not a string")?;
            Ok(cbor::Value::Bstr(hex::decode(s).map_err(|e| e.to_string())?))
        }
        "s" => Ok(cbor::Value::Tstr(p.as_str().ok_or("s payload not a string")?.to_string())),
        "arr" => {
            let items = p.as_array().ok_or("arr payload not an array")?;
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(tagged(it)?);
            }
            Ok(cbor::Value::Arr(out))
        }
        "map" => {
            let pairs = p.as_array().ok_or("map payload not an array")?;
            let mut out = Vec::with_capacity(pairs.len());
            for pr in pairs {
                let kv = pr.as_array().ok_or("map pair must be [k, v]")?;
                if kv.len() != 2 {
                    return Err("map pair must be [k, v]".into());
                }
                out.push((tagged(&kv[0])?, tagged(&kv[1])?));
            }
            Ok(cbor::Value::Map(out))
        }
        other => Err(format!("unknown tag {other}")),
    }
}

fn nodes_from(inp: &J) -> Result<Vec<audit::CausalNode>, String> {
    let raw = inp.get("nodes").and_then(|v| v.as_array()).ok_or("missing nodes")?;
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let id = hex::decode(r.get("id_hex").and_then(|v| v.as_str()).ok_or("node id_hex")?)
            .map_err(|e| e.to_string())?;
        let mut causes = Vec::new();
        if let Some(cs) = r.get("causes_hex").and_then(|v| v.as_array()) {
            for c in cs {
                causes.push(hex::decode(c.as_str().ok_or("cause hex")?).map_err(|e| e.to_string())?);
            }
        }
        // position is authoritative only where supplied (the audit causal cases); federation
        // nodes omit it and it defaults to 0, exactly as impl/rust's own federation tests do.
        let position = r.get("position").and_then(|v| v.as_u64()).unwrap_or(0);
        out.push(audit::CausalNode { id, causes, position });
    }
    Ok(out)
}

fn mldsa_verifier(alg: i64, pk: &[u8]) -> Result<Box<dyn cose::CoseVerifier>, String> {
    match alg {
        -49 => {
            let arr: [u8; fips204::ml_dsa_65::PK_LEN] =
                pk.try_into().map_err(|_| "bad ml-dsa-65 pk length")?;
            let p = fips204::ml_dsa_65::PublicKey::try_from_bytes(arr).map_err(|e| e.to_string())?;
            Ok(Box::new(cose::MlDsa65Verifier(p)))
        }
        -50 => {
            let arr: [u8; fips204::ml_dsa_87::PK_LEN] =
                pk.try_into().map_err(|_| "bad ml-dsa-87 pk length")?;
            let p = fips204::ml_dsa_87::PublicKey::try_from_bytes(arr).map_err(|e| e.to_string())?;
            Ok(Box::new(cose::MlDsa87Verifier(p)))
        }
        -19 => {
            let arr: [u8; 32] = pk.try_into().map_err(|_| "bad ed25519 pk length")?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())?;
            Ok(Box::new(cose::Ed25519Verifier(vk)))
        }
        _ => Err(format!("unknown alg {alg}")),
    }
}

fn out(v: J) -> J {
    json!({ "out": v })
}
fn errj(s: impl Into<String>) -> J {
    json!({ "error": s.into() })
}

// ---- dispatch ----

fn handle(op: &str, inp: &J) -> J {
    match op {
        "sha384" => {
            let msg = match hx(inp, "msg_hex") { Ok(b) => b, Err(e) => return errj(e) };
            use sha2::{Digest, Sha384};
            let d = Sha384::digest(&msg);
            out(json!({ "digest_hex": hex::encode(d) }))
        }
        "cbor.encode" => {
            let vv = match inp.get("value") { Some(v) => v, None => return errj("missing value") };
            let val = match tagged(vv) { Ok(v) => v, Err(e) => return errj(e) };
            match cbor::encode(&val) {
                Ok(b) => out(json!({ "bytes_hex": hex::encode(b) })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "cbor.decode" => {
            let b = match hx(inp, "bytes_hex") { Ok(b) => b, Err(e) => return errj(e) };
            match cbor::decode(&b) {
                Ok(_) => out(json!({ "ok": true })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "content.id" => {
            let b = match hx(inp, "body_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let v = match cbor::decode(&b) { Ok(v) => v, Err(e) => return errj(format!("{}: {}", e.kind, e.msg)) };
            match cbor::content_id(&v) {
                Ok(id) => out(json!({ "id_hex": hex::encode(id) })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "cose.tbs" => {
            let prot = match hx(inp, "protected_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let payload = match hx(inp, "payload_hex") { Ok(b) => b, Err(e) => return errj(e) };
            out(json!({ "tobesigned_hex": hex::encode(cose::to_be_signed_raw(&prot, &payload)) }))
        }
        "mldsa.keygen" => {
            let seed = match hx(inp, "seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let arr: [u8; 32] = match seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("seed must be 32 bytes") };
            let pk = if sf(inp, "param") == "ML-DSA-87" {
                cose::mldsa87_keypair_from_seed(&arr).0.into_bytes().to_vec()
            } else {
                cose::mldsa65_keypair_from_seed(&arr).0.into_bytes().to_vec()
            };
            out(json!({ "pk_hex": hex::encode(pk) }))
        }
        "ed25519.sign" => {
            use ed25519_dalek::Signer;
            let sk = match hx(inp, "sk_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let msg = match hx(inp, "msg_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let arr: [u8; 32] = match sk.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("ed25519 sk must be a 32-byte seed") };
            let signing = ed25519_dalek::SigningKey::from_bytes(&arr);
            let sig = signing.sign(&msg).to_bytes().to_vec();
            out(json!({ "sig_hex": hex::encode(sig) }))
        }
        "cose.sign1" => {
            let alg = iof(inp.get("alg"));
            let seed = match hx(inp, "seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let prot = match hx(inp, "protected_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let payload = match hx(inp, "payload_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let arr: [u8; 32] = match seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("seed must be 32 bytes") };
            let tbs = cose::to_be_signed_raw(&prot, &payload);
            let sig = match alg {
                -49 => cose::MlDsa65Signer(cose::mldsa65_keypair_from_seed(&arr).1).sign(&tbs),
                -50 => cose::MlDsa87Signer(cose::mldsa87_keypair_from_seed(&arr).1).sign(&tbs),
                _ => return errj(format!("alg {alg} has no deterministic ml-dsa signer")),
            };
            let obj = cose::assemble_sign1_raw(&prot, &payload, &sig);
            out(json!({ "obj_hex": hex::encode(obj) }))
        }
        "cose.verify1" => {
            let alg = iof(inp.get("alg"));
            let pk = match hx(inp, "pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let obj = match hx(inp, "obj_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let v = match mldsa_verifier(alg, &pk) { Ok(v) => v, Err(e) => return errj(e) };
            let (prot, payload, sig) = match cose::parse_sign1_raw(&obj) {
                Ok(t) => t,
                Err(e) => return errj(format!("{}: {}", e.kind, e.msg)),
            };
            let tbs = cose::to_be_signed_raw(&prot, &payload);
            out(json!({ "valid": v.verify_raw(&tbs, &sig) }))
        }
        "signerid" => {
            let alg = iof(inp.get("alg"));
            let pk = match hx(inp, "pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            match identity::signer_id(alg, &pk) {
                Ok(id) => out(json!({ "signer_id": id })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "nfc.check" => {
            let b = match hx(inp, "utf8_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let s = match String::from_utf8(b) { Ok(s) => s, Err(_) => return errj("invalid utf-8") };
            match identity::require_nfc(&s) {
                Ok(()) => out(json!({ "ok": true })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "effect.normalize" => out(json!({ "effect": policy::normalize_effect(u(inp, "value")) })),
        "effect.authorize" => {
            let granted = policy::normalize_effect(u(inp, "granted"));
            let effect = u(inp, "effect") as u8;
            out(json!({ "allow": policy::authorizes(granted, effect) }))
        }
        "effect.safety_label" => {
            let sl = policy::SafetyLabel { risk: sf(inp, "risk"), scope: sf(inp, "scope") };
            out(json!({ "cbor_hex": hex::encode(sl.encode()) }))
        }
        "approval.body" | "approval.id" => {
            let approves = match hx(inp, "approves_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let nonce = match hx(inp, "nonce_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let a = approval::ApprovalRecord {
                approves, approver: sf(inp, "approver"), grant: u(inp, "grant"),
                nonce, not_after: u(inp, "not_after"),
            };
            if op == "approval.id" {
                out(json!({ "id_hex": hex::encode(a.id()) }))
            } else {
                out(json!({ "body_hex": hex::encode(a.bytes()) }))
            }
        }
        "ledger.entry" => {
            let prev = match hx(inp, "prev_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let aid = match hx(inp, "approval_id_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let e = approval::LedgerEntry { seq: u(inp, "seq"), prev, approval_id: aid, by: sf(inp, "by") };
            out(json!({ "body_hex": hex::encode(e.bytes()) }))
        }
        "receipt.body" => {
            let prev = match hx(inp, "prev_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let obj = match hx(inp, "obj_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let r = audit::Receipt { prev, obj, seq: u(inp, "seq"), at: u(inp, "at") };
            out(json!({ "body_hex": hex::encode(r.bytes()) }))
        }
        "receipt.head" => {
            let body = match hx(inp, "body_hex") { Ok(b) => b, Err(e) => return errj(e) };
            use sha2::{Digest, Sha384};
            out(json!({ "head_hex": hex::encode(Sha384::digest(&body)) }))
        }
        "causal.verify" => {
            let nodes = match nodes_from(inp) { Ok(n) => n, Err(e) => return errj(e) };
            match audit::verify_causal(&nodes) {
                Ok(()) => out(json!({ "valid": true })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "delivery.update" => {
            let obj = match hx(inp, "obj_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let d = delivery::DeliveryUpdate { obj, stage: u(inp, "stage"), at: u(inp, "at") };
            out(json!({ "body_hex": hex::encode(d.bytes()) }))
        }
        "stream.digest" => {
            let raw = inp.get("chunks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let mut chunks = Vec::with_capacity(raw.len());
            for r in &raw {
                let data = match hex::decode(r.get("data_hex").and_then(|v| v.as_str()).unwrap_or("")) {
                    Ok(d) => d,
                    Err(e) => return errj(e.to_string()),
                };
                chunks.push(streaming::Chunk { offset: u(r, "offset"), data });
            }
            out(json!({ "digest_hex": hex::encode(streaming::commit_digest(&chunks)) }))
        }
        "stream.open" => {
            let sid = match hx(inp, "stream_id_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let approval = match inp.get("approval_hex").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => match hex::decode(s) { Ok(b) => Some(b), Err(e) => return errj(e.to_string()) },
                _ => None,
            };
            let o = streaming::StreamOpen { stream_id: sid, effect: u(inp, "effect"), approval, substream: u(inp, "substream") };
            out(json!({ "body_hex": hex::encode(o.bytes()) }))
        }
        "stream.commit" => {
            let sid = match hx(inp, "stream_id_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let dg = match hx(inp, "digest_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let c = streaming::StreamCommit { stream_id: sid, digest: dg };
            out(json!({ "body_hex": hex::encode(c.bytes()) }))
        }
        "stream.checkpoint" => {
            let sid = match hx(inp, "stream_id_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let dg = match hx(inp, "digest_so_far_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let c = streaming::StreamCheckpoint { stream_id: sid, through_offset: u(inp, "through_offset"), digest_so_far: dg };
            out(json!({ "body_hex": hex::encode(c.bytes()) }))
        }
        "transport.emit" => {
            let t = match transport::by_name(&sf(inp, "transport")) {
                Some(t) => t,
                None => return errj(format!("unknown transport {}", sf(inp, "transport"))),
            };
            match transport::emit(&t, &[0u8], bf(inp, "sensitive"), bf(inp, "require_peer_auth")) {
                Ok(_) => out(json!({ "result": "ok" })),
                Err(e) => out(json!({ "result": e.kind })),
            }
        }
        "carriage.body" => {
            let corr = match hx(inp, "correlation_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let foreign = match hx(inp, "foreign_hex") { Ok(b) => b, Err(e) => return errj(e) };
            match carriage::carry(u(inp, "protocol_id"), u(inp, "class"), u(inp, "content_type"), corr, sf(inp, "method"), foreign) {
                Ok(cb) => out(json!({ "body_hex": hex::encode(cb.bytes()) })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "channels.lookup" => match channels::lookup(u(inp, "channel"), u(inp, "kind")) {
            Some(ks) => out(json!({ "name": ks.name, "effect": ks.effect, "variable": ks.variable })),
            None => errj("UnknownKind"),
        },
        "channels.effect_check" => match channels::check_effect(u(inp, "channel"), u(inp, "kind"), u(inp, "effect")) {
            Ok(()) => out(json!({ "ok": true })),
            Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
        },
        "federation.reconcile" => {
            let nodes = match nodes_from(inp) { Ok(n) => n, Err(e) => return errj(e) };
            match federation::reconcile(&nodes) {
                Ok(order) => out(json!({ "order": hx_list(&order) })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "federation.record" => {
            let auths: Vec<String> = inp.get("authorities").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let mut order = Vec::new();
            if let Some(o) = inp.get("order").and_then(|v| v.as_array()) {
                for x in o {
                    match hex::decode(x.as_str().unwrap_or("")) {
                        Ok(b) => order.push(b),
                        Err(e) => return errj(e.to_string()),
                    }
                }
            }
            let r = federation::ReconcileRecord { authorities: auths, order };
            out(json!({ "body_hex": hex::encode(r.bytes()) }))
        }
        other => json!({ "skipped": format!("op not implemented: {other}") }),
    }
}

// ---- framing loop ----

fn read_exact(stdin: &mut impl Read, buf: &mut [u8]) -> io::Result<()> {
    stdin.read_exact(buf)
}

fn main() {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut lp = [0u8; 4];
    loop {
        if read_exact(&mut stdin, &mut lp).is_err() {
            return; // EOF
        }
        let n = u32::from_le_bytes(lp) as usize;
        let mut body = vec![0u8; n];
        if read_exact(&mut stdin, &mut body).is_err() {
            return;
        }
        let resp = match serde_json::from_slice::<J>(&body) {
            Ok(req) => {
                let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
                let empty = json!({});
                let inp = req.get("in").unwrap_or(&empty);
                handle(op, inp)
            }
            Err(e) => errj(format!("bad request json: {e}")),
        };
        let ob = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{\"error\":\"marshal\"}".to_vec());
        let _ = stdout.write_all(&(ob.len() as u32).to_le_bytes());
        let _ = stdout.write_all(&ob);
        let _ = stdout.flush();
    }
}
