// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C7 — the signed hash-chained receipt (baseline single-authority ordering), the equivocation
//! auditor, and the offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
//!
//! An ordering authority appends signed Receipts {prev, obj, seq, at}; the chain is
//! tamper-evident because reorder/omit/substitute breaks a `prev` link or a `seq` (§8.1). The
//! authority never mutates the origin object — ordering is an outer signed layer (§8.2). The
//! causal graph is the authority-independent foundation: an edge "A causes B" is proven by B's
//! signature over A's content id (envelope field 8), checkable offline (§8.2); a cause an effect
//! could not have seen (later position, or a cycle) is CausalViolation (§8.3). An auditor detects
//! equivocation — two receipts by one authority at one seq naming different objects — from the
//! signed receipts alone (§8.5). Federation (the higher tier) reconciles authorities over this
//! same causal graph with no wire change; built at T13.

use std::collections::HashMap;

use sha2::{Digest, Sha384};

use crate::cbor::{self, Value};
use crate::cose;

/// Width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.
pub const HEAD_SIZE: usize = 48;

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_chain_broken() -> cose::Error {
    err("ChainBroken", "receipt prev/seq does not chain to the previous receipt")
}
pub fn err_equivocation() -> cose::Error {
    err("Equivocation", "two receipts at one seq name different objects")
}
pub fn err_causal_violation() -> cose::Error {
    err("CausalViolation", "causal graph has a cycle or a future cause")
}
pub fn err_receipt_unsigned() -> cose::Error {
    err("ReceiptUnsigned", "receipt signature does not verify")
}

/// One signed append to an ordering authority's chain (design.md §8.1).
#[derive(Clone, Debug)]
pub struct Receipt {
    pub prev: Vec<u8>, // hash of the previous receipt body (HEAD_SIZE bytes; genesis zero)
    pub obj: Vec<u8>,  // content id of the accepted object (never the object — §8.2)
    pub seq: u64,      // monotonic sequence position within this authority's chain
    pub at: u64,       // authority time anchor, epoch ms (independent of the signer's clock, R-8.4)
}

impl Receipt {
    /// Deterministic-CBOR encoding {1: prev, 2: obj, 3: seq, 4: at}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.prev.clone())),
            (Value::Uint(2), Value::Bstr(self.obj.clone())),
            (Value::Uint(3), Value::Uint(self.seq)),
            (Value::Uint(4), Value::Uint(self.at)),
        ]))
        .expect("encode receipt")
    }

    /// The chain head after this receipt: SHA-384 of the receipt body.
    pub fn head(&self) -> Vec<u8> {
        Sha384::digest(&self.bytes()).to_vec()
    }
}

/// A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
/// content ids; it holds no object bodies and mutates none.
pub struct Authority {
    head: Vec<u8>,
    seq: u64,
}

impl Default for Authority {
    fn default() -> Self {
        Authority { head: vec![0u8; HEAD_SIZE], seq: 0 }
    }
}

impl Authority {
    pub fn new() -> Self {
        Authority::default()
    }

    /// Record acceptance of the object named by content id `obj` at time `at`, returning the
    /// signed receipt and its signature. Seq increases by one per append.
    pub fn append(&mut self, signer: &dyn cose::CoseSigner, obj: &[u8], at: u64) -> (Receipt, Vec<u8>) {
        let r = Receipt { prev: self.head.clone(), obj: obj.to_vec(), seq: self.seq, at };
        let sig = signer.sign(&r.bytes());
        self.head = r.head();
        self.seq += 1;
        (r, sig)
    }
}

/// Check a receipt chain offline against the authority's key: each receipt's seq is the next
/// expected value, its prev links to the previous receipt's head (genesis is zero), and its
/// signature verifies. Detects any reorder/omission/substitution (§8.1).
pub fn verify_chain(
    receipts: &[Receipt],
    sigs: &[Vec<u8>],
    v: &dyn cose::CoseVerifier,
) -> Result<(), cose::Error> {
    if receipts.len() != sigs.len() {
        return Err(err_chain_broken());
    }
    let mut head = vec![0u8; HEAD_SIZE];
    for (i, r) in receipts.iter().enumerate() {
        if r.seq != i as u64 || r.prev != head {
            return Err(err_chain_broken());
        }
        if !v.verify_raw(&r.bytes(), &sigs[i]) {
            return Err(err_receipt_unsigned());
        }
        head = r.head();
    }
    Ok(())
}

/// Whether an object's advisory `created` is consistent with the authority's independent time
/// anchor `at` (R-8.4): an object cannot be created after it was ordered, so created <= at.
pub fn consistent_with_anchor(created: u64, at: u64) -> bool {
    created <= at
}

/// Evidence of equivocation: two validly-signed receipts by one authority at the same seq naming
/// different objects (§8.5). Offline-verifiable by anyone.
#[derive(Clone, Debug)]
pub struct ForkProof {
    pub a: Receipt,
    pub b: Receipt,
}

/// Observes one authority's receipts and detects equivocation from the signed receipts alone
/// (§8.5). It cannot force delivery of withheld events — that residual is the authority's trust
/// property, not something the wire removes.
#[derive(Default)]
pub struct Auditor {
    seen: HashMap<u64, Receipt>,
}

impl Auditor {
    pub fn new() -> Self {
        Auditor::default()
    }

    /// Records a signed receipt. Returns `(None, Err(ReceiptUnsigned))` on a bad signature;
    /// `(Some(proof), Err(Equivocation))` when a previously-seen receipt at the same seq named a
    /// different object; and `(None, Ok(()))` otherwise (including a benign exact duplicate).
    pub fn observe(
        &mut self,
        v: &dyn cose::CoseVerifier,
        r: &Receipt,
        sig: &[u8],
    ) -> (Option<ForkProof>, Result<(), cose::Error>) {
        if !v.verify_raw(&r.bytes(), sig) {
            return (None, Err(err_receipt_unsigned()));
        }
        if let Some(prev) = self.seen.get(&r.seq) {
            if prev.obj != r.obj {
                return (Some(ForkProof { a: prev.clone(), b: r.clone() }), Err(err_equivocation()));
            }
            return (None, Ok(()));
        }
        self.seen.insert(r.seq, r.clone());
        (None, Ok(()))
    }
}

/// An object's place in the causal graph: its content id, the content ids of its causes
/// (envelope field 8), and its ordering position (authority seq, or `created` absent a receipt).
pub struct CausalNode {
    pub id: Vec<u8>,
    pub causes: Vec<Vec<u8>>,
    pub position: u64,
}

fn build_index(nodes: &[CausalNode]) -> HashMap<&[u8], usize> {
    nodes.iter().enumerate().map(|(i, n)| (n.id.as_slice(), i)).collect()
}

fn has_cycle(nodes: &[CausalNode], idx: &HashMap<&[u8], usize>, color: &mut [u8], i: usize) -> bool {
    color[i] = 1; // gray
    for c in &nodes[i].causes {
        if let Some(&j) = idx.get(c.as_slice()) {
            if color[j] == 1 {
                return true;
            }
            if color[j] == 0 && has_cycle(nodes, idx, color, j) {
                return true;
            }
        }
    }
    color[i] = 2; // black
    false
}

/// Check the signed partial order (§8.2, §8.3): no object names a present cause at a later
/// position than its own (a future cause), and the graph is acyclic. Either fault is
/// CausalViolation. Edges to causes not present in the set are ignored (external references).
/// Runs with no ordering authority present (R-8.5).
pub fn verify_causal(nodes: &[CausalNode]) -> Result<(), cose::Error> {
    let idx = build_index(nodes);
    for n in nodes {
        for c in &n.causes {
            if let Some(&j) = idx.get(c.as_slice()) {
                if nodes[j].position > n.position {
                    return Err(err_causal_violation());
                }
            }
        }
    }
    let mut color = vec![0u8; nodes.len()];
    for i in 0..nodes.len() {
        if color[i] == 0 && has_cycle(nodes, &idx, &mut color, i) {
            return Err(err_causal_violation());
        }
    }
    Ok(())
}

/// Return the causal nodes' content ids in a deterministic topological order (a cause before its
/// effects). Ties among ready nodes break by (position, input index). CausalViolation if the
/// graph does not verify.
pub fn topo_order(nodes: &[CausalNode]) -> Result<Vec<Vec<u8>>, cose::Error> {
    verify_causal(nodes)?;
    let idx = build_index(nodes);
    let mut indeg = vec![0usize; nodes.len()];
    let mut effects: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (i, n) in nodes.iter().enumerate() {
        for c in &n.causes {
            if let Some(&j) = idx.get(c.as_slice()) {
                effects[j].push(i);
                indeg[i] += 1;
            }
        }
    }
    let mut done = vec![false; nodes.len()];
    let mut order = Vec::with_capacity(nodes.len());
    while order.len() < nodes.len() {
        let mut pick: Option<usize> = None;
        for i in 0..nodes.len() {
            if done[i] || indeg[i] != 0 {
                continue;
            }
            match pick {
                Some(p) if nodes[p].position <= nodes[i].position => {}
                _ => pick = Some(i),
            }
        }
        let p = match pick {
            Some(p) => p,
            None => return Err(err_causal_violation()), // unreachable after verify_causal
        };
        done[p] = true;
        order.push(nodes[p].id.clone());
        for &e in &effects[p] {
            indeg[e] -= 1;
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::CoseSigner; // bring sign() into method scope
    use crate::envelope;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/audit/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn auth_key(seed: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk))
    }

    fn nodes(js: &J) -> Vec<CausalNode> {
        js.as_array()
            .unwrap()
            .iter()
            .map(|n| CausalNode {
                id: hexd(n["id_hex"].as_str().unwrap()),
                causes: n["causes_hex"].as_array().unwrap().iter().map(|c| hexd(c.as_str().unwrap())).collect(),
                position: n["position"].as_u64().unwrap(),
            })
            .collect()
    }

    #[test]
    fn receipt_chain_matches_oracle() {
        let c = load();
        let (v, s) = auth_key(20);
        let mut auth = Authority::new();
        assert_eq!(hex::encode(vec![0u8; HEAD_SIZE]), c["chain"]["genesis_prev_hex"].as_str().unwrap());
        let mut receipts = Vec::new();
        let mut sigs = Vec::new();
        for rj in c["chain"]["receipts"].as_array().unwrap() {
            let (r, sig) = auth.append(&s, &hexd(rj["obj_hex"].as_str().unwrap()), rj["at"].as_u64().unwrap());
            assert_eq!(r.seq, rj["seq"].as_u64().unwrap());
            assert_eq!(hex::encode(r.bytes()), rj["body_hex"].as_str().unwrap());
            assert_eq!(hex::encode(r.head()), rj["head_after_hex"].as_str().unwrap());
            receipts.push(r);
            sigs.push(sig);
        }
        assert_eq!(hex::encode(receipts.last().unwrap().head()), c["chain"]["final_head_hex"].as_str().unwrap());
        verify_chain(&receipts, &sigs, &v).expect("valid signed chain");
    }

    #[test]
    fn chain_broken_and_reorder() {
        let c = load();
        let (v, s) = auth_key(20);
        let mk = |rj: &J| -> (Receipt, Vec<u8>) {
            let r = Receipt {
                prev: hexd(rj["prev_hex"].as_str().unwrap()),
                obj: hexd(rj["obj_hex"].as_str().unwrap()),
                seq: rj["seq"].as_u64().unwrap(),
                at: rj["at"].as_u64().unwrap(),
            };
            assert_eq!(hex::encode(r.bytes()), rj["body_hex"].as_str().unwrap());
            let sig = s.sign(&r.bytes());
            (r, sig)
        };
        let br = c["chain_broken"]["receipts"].as_array().unwrap();
        let (r0, s0) = mk(&br[0]);
        let (r1, s1) = mk(&br[1]); // prev = genesis, but head(r0) != genesis
        assert_eq!(
            verify_chain(&[r0, r1], &[s0, s1], &v).unwrap_err().kind,
            "ChainBroken"
        );
        // A valid chain reordered is also ChainBroken.
        let (v2, s2) = auth_key(21);
        let mut auth = Authority::new();
        let (ra, sa) = auth.append(&s2, &hexd(c["chain"]["receipts"][0]["obj_hex"].as_str().unwrap()), 100);
        let (rb, sb) = auth.append(&s2, &hexd(c["chain"]["receipts"][1]["obj_hex"].as_str().unwrap()), 101);
        assert_eq!(verify_chain(&[rb, ra], &[sb, sa], &v2).unwrap_err().kind, "ChainBroken");
    }

    #[test]
    fn receipt_unsigned() {
        let (v, s) = auth_key(20);
        let mut auth = Authority::new();
        let (r, sig) = auth.append(&s, &[0x20, 0x30, 1, 2, 3], 100);
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert_eq!(verify_chain(&[r.clone()], &[bad.clone()], &v).unwrap_err().kind, "ReceiptUnsigned");
        let (_fp, res) = Auditor::new().observe(&v, &r, &bad);
        assert_eq!(res.unwrap_err().kind, "ReceiptUnsigned");
    }

    #[test]
    fn equivocation_detected() {
        let c = load();
        let (v, s) = auth_key(20);
        let head0 = hexd(c["chain"]["receipts"][0]["head_after_hex"].as_str().unwrap());
        let seq = c["equivocation"]["seq"].as_u64().unwrap();
        let ra = Receipt { prev: head0.clone(), obj: hexd(c["equivocation"]["receipt_a"]["obj_hex"].as_str().unwrap()), seq, at: 101 };
        let rb = Receipt { prev: head0, obj: hexd(c["equivocation"]["receipt_b"]["obj_hex"].as_str().unwrap()), seq, at: 101 };
        assert_eq!(hex::encode(ra.bytes()), c["equivocation"]["receipt_a"]["body_hex"].as_str().unwrap());
        assert_eq!(hex::encode(rb.bytes()), c["equivocation"]["receipt_b"]["body_hex"].as_str().unwrap());
        let (sa, sb) = (s.sign(&ra.bytes()), s.sign(&rb.bytes()));

        let mut aud = Auditor::new();
        assert!(aud.observe(&v, &ra, &sa).0.is_none());
        assert!(aud.observe(&v, &ra, &sa).0.is_none()); // exact duplicate is benign
        let (fp, res) = aud.observe(&v, &rb, &sb);
        let fp = fp.expect("equivocation not detected");
        assert_eq!(res.unwrap_err().kind, "Equivocation");
        assert_eq!(fp.a.obj, ra.obj);
        assert_eq!(fp.b.obj, rb.obj);
    }

    #[test]
    fn causal_graph() {
        let c = load();
        let valid = nodes(&c["causal_valid"]["nodes"]);
        verify_causal(&valid).expect("valid causal graph");
        let order = topo_order(&valid).expect("topo");
        let want: Vec<String> =
            c["causal_valid"]["topo_order_hex"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let got: Vec<String> = order.iter().map(hex::encode).collect();
        assert_eq!(got, want);
        assert_eq!(verify_causal(&nodes(&c["causal_cycle"]["nodes"])).unwrap_err().kind, "CausalViolation");
        assert_eq!(verify_causal(&nodes(&c["causal_future"]["nodes"])).unwrap_err().kind, "CausalViolation");
    }

    #[test]
    fn time_anchor() {
        assert!(consistent_with_anchor(100, 102));
        assert!(!consistent_with_anchor(200, 102));
    }

    fn mk_obj(signer: &[u8], causes: Vec<Vec<u8>>) -> envelope::Object {
        envelope::Object {
            id: vec![],
            kind: 0,
            channel: 0,
            tier: 0,
            signer: signer.to_vec(),
            created: 100,
            effect: 0,
            causes,
            profile: cose::PROFILE_PUBLIC as u64,
            body: Value::Uint(0),
            ext: None,
            cext: None,
        }
    }

    #[test]
    fn causal_edge_proven_by_signature() {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[30; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        let (v, s) = (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk));
        let kind_ok = |_c: u64, _k: u64| true;

        let obj_a = mk_obj(&pkb, vec![]);
        let cid_a = obj_a.content_id();
        let mut obj_b = mk_obj(&pkb, vec![cid_a.clone()]);
        let cid_b = obj_b.content_id();
        let signed_b = envelope::sign(&mut obj_b, &s);
        let ob = envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed_b).expect("verify b");
        assert_eq!(ob.causes, vec![cid_a.clone()], "B's signed body must carry the edge to A");

        verify_causal(&[
            CausalNode { id: cid_a.clone(), causes: vec![], position: 0 },
            CausalNode { id: cid_b, causes: vec![cid_a], position: 1 },
        ])
        .expect("offline causal check");
    }

    #[test]
    fn ordering_does_not_mutate_origin() {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[31; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        let (v, s) = (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk));
        let kind_ok = |_c: u64, _k: u64| true;

        let mut obj = mk_obj(&pkb, vec![]);
        let signed_o = envelope::sign(&mut obj, &s);
        let before = signed_o.clone();
        let oo = envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed_o).expect("verify o");

        let (_av, asig) = auth_key(40);
        let mut auth = Authority::new();
        let (r, _sig) = auth.append(&asig, &oo.id, 500);
        assert_eq!(signed_o, before, "ordering mutated the origin bytes");
        envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed_o).expect("origin still verifies");
        assert_eq!(r.obj, oo.id, "receipt must reference the object content id");
    }
}
