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
use naalp::{approval, audit, carriage, cbor, channels, cose, delivery, envelope, federation, identity, naalperror, policy, streaming, transport};

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

// A boxed deterministic ML-DSA signer for a seed, for the tag-98 rotation legs (#143).
fn mldsa_signer(alg: i64, seed: &[u8; 32]) -> Result<Box<dyn cose::CoseSigner>, String> {
    match alg {
        -49 => Ok(Box::new(cose::MlDsa65Signer(cose::mldsa65_keypair_from_seed(seed).1))),
        -50 => Ok(Box::new(cose::MlDsa87Signer(cose::mldsa87_keypair_from_seed(seed).1))),
        _ => Err(format!("alg {alg} has no deterministic ml-dsa signer")),
    }
}

// R7 decoder resource bounds (#object.decode, #stream.verify_commit): the four object-level
// bounds (octet-size, causes[] count, ext/cext count, nesting depth) all fire in
// envelope::verify BEFORE the COSE signature is ever checked, so a verifier passed to a
// rejected-object call is never consulted. envelope::verify still requires a &dyn CoseVerifier
// (not an Option), so this is a never-reached stand-in — never a working verifier.
struct NotReachedVerifier;
impl cose::CoseVerifier for NotReachedVerifier {
    fn alg(&self) -> i64 {
        0
    }
    fn verify_raw(&self, _msg: &[u8], _sig: &[u8]) -> bool {
        false
    }
    fn pub_key(&self) -> Vec<u8> {
        Vec::new()
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
        // ---- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) — #143 ----
        "rotation.leg_tbs" => {
            let prot = match hx(inp, "body_protected_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let alg = iof(inp.get("leg_alg"));
            let payload = match hx(inp, "payload_hex") { Ok(b) => b, Err(e) => return errj(e) };
            out(json!({ "tbs_hex": hex::encode(cose::signature_to_be_signed(&prot, alg, &payload)) }))
        }
        "rotation.sign" => {
            let old_alg = iof(inp.get("old_alg"));
            let old_seed = match hx(inp, "old_seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let new_alg = iof(inp.get("new_alg"));
            let new_seed = match hx(inp, "new_seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let prot = match hx(inp, "protected_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let payload = match hx(inp, "payload_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let oa: [u8; 32] = match old_seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("old seed must be 32 bytes") };
            let na: [u8; 32] = match new_seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("new seed must be 32 bytes") };
            let old_signer = match mldsa_signer(old_alg, &oa) { Ok(s) => s, Err(e) => return errj(e) };
            let new_signer = match mldsa_signer(new_alg, &na) { Ok(s) => s, Err(e) => return errj(e) };
            let old_leg = cose::signature_leg(&prot, old_signer.as_ref(), &payload);
            let new_leg = cose::signature_leg(&prot, new_signer.as_ref(), &payload);
            let obj = cose::assemble_sign_raw(&prot, &payload, &[old_leg, new_leg]);
            out(json!({ "obj_hex": hex::encode(obj) }))
        }
        "rotation.verify" => {
            let obj = match hx(inp, "obj_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let old_alg = iof(inp.get("old_alg"));
            let old_pk = match hx(inp, "old_pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let new_alg = iof(inp.get("new_alg"));
            let new_pk = match hx(inp, "new_pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let profile = iof(inp.get("profile")) as u32;
            let old_v = match mldsa_verifier(old_alg, &old_pk) { Ok(v) => v, Err(e) => return errj(e) };
            let new_v = match mldsa_verifier(new_alg, &new_pk) { Ok(v) => v, Err(e) => return errj(e) };
            let kind_ok = |ch: u64, k: u64| ch == 3 && k == 0;
            // Dispatch as a real receiver does: a tag-98 (0xd8 0x62) Rotation object -> two-leg
            // verify_rotation_object; a tag-18 single-signature object -> the general verify, which
            // rejects a channel-3/kind-0 single-sig rotation RotationUnauthorized (§5.2). The
            // go-forward (new) key is the tag-18 object's sole signer.
            let res = if obj.len() >= 2 && obj[0] == 0xd8 && obj[1] == 0x62 {
                envelope::verify_rotation_object(profile, old_v.as_ref(), new_v.as_ref(), &kind_ok, &[], &obj)
            } else {
                envelope::verify(profile, new_v.as_ref(), &kind_ok, &[], &obj)
            };
            match res {
                Ok(_) => out(json!({ "valid": true, "error": "" })),
                Err(e) => out(json!({ "valid": false, "error": e.kind })),
            }
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
                // OPTIONAL R-TDCS-5 audience; the approval corpus carries none (audience is graded by
                // the Go/Rust unit tests), so absent ("") — byte-identical to the Go adapter's zero value.
                audience: String::new(),
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
        "forkproof.preimage" => {
            // The draft-01 fork-proof framing witness (signatures elided): rebuild the two
            // conflicting receipts and encode the ForkProof body with empty sig fields. Graded
            // against the oracle.
            let signer = match hx(inp, "signer_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let prev = match hx(inp, "prev_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let obj_a = match hx(inp, "obj_a_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let obj_b = match hx(inp, "obj_b_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let (seq, at) = (u(inp, "seq"), u(inp, "at"));
            let a = audit::Receipt { prev: prev.clone(), obj: obj_a, seq, at };
            let b = audit::Receipt { prev, obj: obj_b, seq, at };
            let fp = audit::ForkProof::new(&signer, a, &[], b, &[], u(inp, "ext_counter"));
            out(json!({ "preimage_hex": hex::encode(fp.preimage()) }))
        }
        "forkproof.body" => {
            // The full draft-01 fork-proof body WITH the accused authority's two real (deterministic)
            // signatures over body-a and body-b, for the cross-implementation byte-parity check on
            // the complete signed object (Go == Rust); the corpus marks this "acceptable" (the
            // deterministic ML-DSA sigs have no committed KAT — see cose.sign1).
            let signer = match hx(inp, "signer_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let seed = match hx(inp, "seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let prev = match hx(inp, "prev_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let obj_a = match hx(inp, "obj_a_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let obj_b = match hx(inp, "obj_b_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let (seq, at) = (u(inp, "seq"), u(inp, "at"));
            let arr: [u8; 32] = match seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("seed must be 32 bytes") };
            let a = audit::Receipt { prev: prev.clone(), obj: obj_a, seq, at };
            let b = audit::Receipt { prev, obj: obj_b, seq, at };
            let signer_key = cose::MlDsa65Signer(cose::mldsa65_keypair_from_seed(&arr).1);
            let sig_a = signer_key.sign(&a.bytes());
            let sig_b = signer_key.sign(&b.bytes());
            let fp = audit::ForkProof::new(&signer, a, &sig_a, b, &sig_b, u(inp, "ext_counter"));
            out(json!({
                "body_hex": hex::encode(fp.bytes()),
                "preimage_hex": hex::encode(fp.preimage()),
                "sig_a_hex": hex::encode(&sig_a),
                "sig_b_hex": hex::encode(&sig_b),
            }))
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
        "stream.state" => {
            // design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream
            // through an ordered `events` list on a fresh Guard; report the LAST event's outcome
            // plus the stream's final state. Graded against the independent, non-circular
            // tools/streamstate_oracle.py (F3).
            let raw_events = match inp.get("events").and_then(|v| v.as_array()) {
                Some(a) => a,
                None => return errj("stream.state: missing events"),
            };
            let g = streaming::Guard::new();
            let mut last_err: Result<(), cose::Error> = Ok(());
            let mut last_stream: Vec<u8> = Vec::new();
            for em in raw_events {
                let sid = match hx(em, "stream_hex") { Ok(b) => b, Err(e) => return errj(e) };
                last_stream = sid.clone();
                let ev = em.get("ev").and_then(|v| v.as_str()).unwrap_or("");
                last_err = match ev {
                    "open" => {
                        let o = streaming::StreamOpen {
                            stream_id: sid.clone(),
                            effect: u(em, "effect"),
                            approval: None,
                            substream: 0,
                        };
                        g.open(&o, u(em, "granted") as u8)
                    }
                    "chunk" => g.chunk(&sid),
                    "checkpoint" => g.checkpoint(&sid),
                    "commit" => {
                        let raw_chunks = em.get("chunks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                        let mut chunks = Vec::with_capacity(raw_chunks.len());
                        for rc in &raw_chunks {
                            let data = match hex::decode(rc.get("data_hex").and_then(|v| v.as_str()).unwrap_or("")) {
                                Ok(d) => d,
                                Err(e) => return errj(e.to_string()),
                            };
                            chunks.push(streaming::Chunk { offset: u(rc, "offset"), data });
                        }
                        let digest = match hx(em, "digest_hex") { Ok(b) => b, Err(e) => return errj(e) };
                        let commit = streaming::StreamCommit { stream_id: sid.clone(), digest };
                        g.commit(&commit, &chunks)
                    }
                    "expire" => g.expire(&sid),
                    other => return errj(format!("stream.state: unknown event {other}")),
                };
            }
            let state = g.state(&last_stream).name();
            match last_err {
                Ok(()) => out(json!({ "valid": true, "error": "", "state": state })),
                Err(e) => out(json!({ "valid": false, "error": e.kind, "state": state })),
            }
        }
        "delivery.state" => {
            // ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
            // through an ordered `events` list of signed delivery updates on a fresh WAL-backed
            // tracker; report the LAST event's outcome plus the object's final stage name. A
            // rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
            // Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let raw_events = match inp.get("events").and_then(|v| v.as_array()) {
                Some(a) => a,
                None => return errj("delivery.state: missing events"),
            };
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp = std::env::temp_dir()
                .join(format!("naalp-delivery-state-{}-{}.wal", std::process::id(), n));
            let _ = std::fs::remove_file(&tmp);
            let mut tr = match delivery::open_tracker(&tmp) {
                Ok(t) => t,
                Err(_) => return errj("delivery.state: open_tracker failed".to_string()),
            };
            let mut last_kind: Option<String> = None;
            let mut last_obj: Vec<u8> = Vec::new();
            for em in raw_events {
                let obj = match hx(em, "obj_hex") { Ok(b) => b, Err(e) => return errj(e) };
                last_obj = obj.clone();
                let ev = em.get("ev").and_then(|v| v.as_str()).unwrap_or("");
                match ev {
                    "update" => match tr.advance(&obj, u(em, "stage"), 0) {
                        Ok(_) => last_kind = None,
                        Err(e) => last_kind = Some(e.cose_kind().unwrap_or("IoError").to_string()),
                    },
                    other => return errj(format!("delivery.state: unknown event {other}")),
                }
            }
            let st = tr.stage(&last_obj).unwrap_or(0);
            let state = delivery::stage_name(st);
            let _ = std::fs::remove_file(&tmp);
            match last_kind {
                None => out(json!({ "valid": true, "error": "", "state": state })),
                Some(k) => out(json!({ "valid": false, "error": k, "state": state })),
            }
        }
        "approval.state" => {
            // ietf draft "## Approval state machine" (# Object State Machines): build ONE signed
            // approval, then drive it through an ordered `events` list of consume attempts through the
            // REAL composed choke point approval::consume_approval on a fresh single-use ledger; report
            // the LAST event's {valid, error} plus the ledger length after it (the draft's "ledger left
            // untouched by a rejected request", observable via Ledger::len). Graded against the
            // independent, non-circular tools/approval_state_oracle.py (F3). The approver key is a
            // deterministic Ed25519 test key — the signature is verified, not graded across ports.
            use ed25519_dalek::Signer;
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let am = match inp.get("approval") {
                Some(v) if v.is_object() => v,
                _ => return errj("approval.state: missing approval object"),
            };
            let approves = match hx(am, "approves_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let nonce = match hx(am, "nonce_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let a = approval::ApprovalRecord {
                approves, approver: sf(am, "approver"), grant: u(am, "grant"),
                nonce, not_after: u(am, "not_after"), audience: String::new(),
            };
            let signing = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
            let verifier = cose::Ed25519Verifier(signing.verifying_key());
            let sig = signing.sign(&a.bytes()).to_bytes().to_vec();

            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp = std::env::temp_dir()
                .join(format!("naalp-approval-state-{}-{}.wal", std::process::id(), n));
            let _ = std::fs::remove_file(&tmp);
            let l = match approval::open_ledger(&tmp) {
                Ok(l) => l,
                Err(_) => return errj("approval.state: open_ledger failed".to_string()),
            };
            let raw_events = match inp.get("events").and_then(|v| v.as_array()) {
                Some(a) => a,
                None => return errj("approval.state: missing events"),
            };
            let mut last_kind: Option<String> = None;
            for em in raw_events {
                let ev = em.get("ev").and_then(|v| v.as_str()).unwrap_or("");
                match ev {
                    "consume" => {
                        let present = match hx(em, "present_cid_hex") { Ok(b) => b, Err(e) => return errj(e) };
                        match approval::consume_approval(&a, &verifier, &sig, &present,
                            u(em, "pos_time"), u(em, "required_effect") as u8, &l, &sf(em, "by")) {
                            Ok(_) => last_kind = None,
                            Err(e) => last_kind = Some(e.cose_kind().unwrap_or("IoError").to_string()),
                        }
                    }
                    other => return errj(format!("approval.state: unknown event {other}")),
                }
            }
            let len = l.len() as u64;
            let _ = std::fs::remove_file(&tmp);
            match last_kind {
                None => out(json!({ "valid": true, "error": "", "ledger_len": len })),
                Some(k) => out(json!({ "valid": false, "error": k, "ledger_len": len })),
            }
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
        "reconcile.state" => {
            // ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine
            // through ONE event (add-chain | linearize | verify) on fresh state and report
            // {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe pipeline
            // (a `chain` that must independently pass verify_chain, plus an optional `extra`
            // receipt fed only to observe — a chain array cannot itself carry a duplicate seq
            // without independently tripping ChainBroken, so equivocation is exercised via the
            // separate `extra` observation); linearize runs federation::reconcile (which calls
            // audit::verify_causal internally); verify runs federation::verify_reconcile_order, which
            // MUST recompute via reconcile (content-id tie-break), never a position tie-break.
            // Graded against the independent, non-circular tools/reconcile_state_oracle.py (F3).
            // The authority key is a deterministic all-zero Ed25519 test seed — the signature is
            // verified, not graded (bytes are not compared across ports for this op).
            use ed25519_dalek::Signer;
            let signing = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
            let verifier = cose::Ed25519Verifier(signing.verifying_key());
            let signer_id = signing.verifying_key().to_bytes().to_vec();

            fn build_receipt(rm: &J) -> Result<audit::Receipt, String> {
                let prev = hx(rm, "prev_hex")?;
                let obj = hx(rm, "obj_hex")?;
                Ok(audit::Receipt { prev, obj, seq: u(rm, "seq"), at: u(rm, "at") })
            }

            match sf(inp, "event").as_str() {
                "add-chain" => {
                    let raw_chain = inp.get("chain").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    let mut receipts = Vec::with_capacity(raw_chain.len());
                    let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(raw_chain.len());
                    for rc in &raw_chain {
                        let r = match build_receipt(rc) { Ok(r) => r, Err(e) => return errj(e) };
                        let sig = signing.sign(&r.bytes()).to_bytes().to_vec();
                        receipts.push(r);
                        sigs.push(sig);
                    }
                    if let Some(idx) = inp.get("corrupt_sig_at").and_then(|v| v.as_u64()) {
                        let idx = idx as usize;
                        sigs[idx][0] ^= 0xFF;
                    }
                    let mut last_err = audit::verify_chain(&receipts, &sigs, &verifier).err();
                    if last_err.is_none() {
                        let mut auditor = audit::Auditor::new(&signer_id);
                        for (i, r) in receipts.iter().enumerate() {
                            let (_, res) = auditor.observe(&verifier, r, &sigs[i]);
                            if let Err(e) = res {
                                last_err = Some(e);
                                break;
                            }
                        }
                        if last_err.is_none() {
                            if let Some(em) = inp.get("extra").filter(|v| v.is_object()) {
                                let er = match build_receipt(em) { Ok(r) => r, Err(e) => return errj(e) };
                                let esig = signing.sign(&er.bytes()).to_bytes().to_vec();
                                let (_, res) = auditor.observe(&verifier, &er, &esig);
                                if let Err(e) = res {
                                    last_err = Some(e);
                                }
                            }
                        }
                    }
                    match last_err {
                        None => out(json!({ "valid": true, "error": "" })),
                        Some(e) => out(json!({ "valid": false, "error": e.kind })),
                    }
                }
                "linearize" => {
                    let nodes = match nodes_from(inp) { Ok(n) => n, Err(e) => return errj(e) };
                    match federation::reconcile(&nodes) {
                        Ok(_) => out(json!({ "valid": true, "error": "" })),
                        Err(e) => out(json!({ "valid": false, "error": e.kind })),
                    }
                }
                "verify" => {
                    let nodes = match nodes_from(inp) { Ok(n) => n, Err(e) => return errj(e) };
                    let raw_order = inp.get("claimed_order_hex").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    let mut order = Vec::with_capacity(raw_order.len());
                    for o in &raw_order {
                        match hex::decode(o.as_str().unwrap_or("")) {
                            Ok(b) => order.push(b),
                            Err(e) => return errj(e.to_string()),
                        }
                    }
                    let rec = federation::ReconcileRecord { authorities: Vec::new(), order };
                    match federation::verify_reconcile_order(&rec, &nodes) {
                        Ok(()) => out(json!({ "valid": true, "error": "" })),
                        Err(e) => out(json!({ "valid": false, "error": e.kind })),
                    }
                }
                other => errj(format!("reconcile.state: unknown event {other}")),
            }
        }
        // ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
        "composite.mprime" => {
            let m = match hx(inp, "m_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let mp = cose::compute_mprime(b"COMPSIG-MLDSA65-Ed25519-SHA512", &[], &m);
            out(json!({ "mprime_hex": hex::encode(mp) }))
        }
        "composite.signerid" => {
            let ml_pub = match hx(inp, "mldsa_pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let ed_pub = match hx(inp, "ed_pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            match identity::composite_signer_id(iof(inp.get("mldsa_alg")), &ml_pub, &ed_pub) {
                Ok(id) => out(json!({ "signer_id": id })),
                Err(e) => errj(format!("{}: {}", e.kind, e.msg)),
            }
        }
        "composite.sign" => {
            let ml_seed = match hx(inp, "mldsa_seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let ed_seed = match hx(inp, "ed_seed_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let tbs = match hx(inp, "tbs_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let ml_arr: [u8; 32] = match ml_seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("mldsa seed must be 32 bytes") };
            let ed_arr: [u8; 32] = match ed_seed.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("ed25519 seed must be 32 bytes") };
            let ml65 = cose::mldsa65_keypair_from_seed(&ml_arr).1;
            let ed = ed25519_dalek::SigningKey::from_bytes(&ed_arr);
            let signer = cose::CompositeSigner { ml65, ed };
            let val = signer.sign(&tbs);
            out(json!({ "value_hex": hex::encode(val) }))
        }
        "composite.verify" => {
            let ml_pub = match hx(inp, "mldsa_pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let ed_pub = match hx(inp, "ed_pubkey_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let m = match hx(inp, "m_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let sig = match hx(inp, "sig_hex") { Ok(b) => b, Err(e) => return errj(e) };
            let ml_arr: [u8; fips204::ml_dsa_65::PK_LEN] = match ml_pub.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("bad ml-dsa-65 pk length") };
            let ml65 = match fips204::ml_dsa_65::PublicKey::try_from_bytes(ml_arr) { Ok(p) => p, Err(e) => return errj(e.to_string()) };
            let ed_arr: [u8; 32] = match ed_pub.as_slice().try_into() { Ok(a) => a, Err(_) => return errj("bad ed25519 pk length") };
            let ed = match ed25519_dalek::VerifyingKey::from_bytes(&ed_arr) { Ok(v) => v, Err(e) => return errj(e.to_string()) };
            let v = cose::CompositeVerifier { ml65, ed };
            out(json!({ "valid": cose::verify_composite(&v, &m, &sig).is_ok() }))
        }
        // ---- R7 decoder resource bounds (#object.decode, #stream.verify_commit) ----
        "object.decode" => {
            // Decode + bound-enforce an untrusted object; all four object-level bounds fire
            // BEFORE the COSE signature is checked, so NO working verifier is needed.
            // over_size materializes the octet-size bound (rejected on raw length before any
            // parse); otherwise the object comes from obj_hex.
            let obj = if inp.get("over_size").is_some() {
                vec![0u8; iof(inp.get("over_size")) as usize]
            } else {
                match hx(inp, "obj_hex") { Ok(b) => b, Err(e) => return errj(e) }
            };
            let kind_ok = |_ch: u64, _k: u64| true;
            let v = NotReachedVerifier;
            match envelope::verify(1, &v, &kind_ok, &[], &obj) {
                Ok(_) => out(json!({ "valid": true, "error": "" })),
                Err(e) => out(json!({ "valid": false, "error": e.kind })),
            }
        }
        "stream.verify_commit" => {
            let n = u(inp, "chunk_count") as usize;
            let chunks: Vec<streaming::Chunk> =
                (0..n).map(|_| streaming::Chunk { offset: 0, data: Vec::new() }).collect(); // n empty chunks
            let commit = streaming::StreamCommit { stream_id: Vec::new(), digest: Vec::new() };
            match streaming::verify_commit(&commit, &chunks) { // count check fires before digest
                Ok(()) => out(json!({ "valid": true, "error": "" })),
                Err(e) => out(json!({ "valid": false, "error": e.kind })),
            }
        }
        "error.name_for_code" => {
            // T3.3: naalp-error registry table lookup (design.md §3.5). Grades the embedded table
            // per-code + the unknown-code (opaque) contract.
            match naalperror::name_for_code(u(inp, "code")) {
                Some(n) => out(json!({ "name": n, "registered": true })),
                None => out(json!({ "name": "", "registered": false })),
            }
        }
        "error.encode" => {
            // T3.3: deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail, ?4:subject}.
            let subject: Option<Vec<u8>> = if inp.get("subject_hex").is_some() {
                match hx(inp, "subject_hex") { Ok(b) => Some(b), Err(e) => return errj(e) }
            } else {
                None
            };
            let name = sf(inp, "name");
            let detail = sf(inp, "detail");
            match naalperror::encode(u(inp, "code"), &name, &detail, subject.as_deref()) {
                Ok(b) => out(json!({ "body_hex": hex::encode(b) })),
                Err(e) => out(json!({ "valid": false, "error": e.kind })),
            }
        }
        "error.decode" => {
            // T3.3: parse + dual-carriage validate (registered code + wrong name -> Malformed;
            // unknown code -> opaque accept).
            let body = match hx(inp, "body_hex") { Ok(b) => b, Err(e) => return errj(e) };
            match naalperror::decode(&body) {
                Ok(o) => out(json!({ "valid": true, "code": o.code, "name": o.name })),
                Err(e) => out(json!({ "valid": false, "error": e.kind })),
            }
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
