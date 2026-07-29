// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The Federation higher tier (tier 1) — federated ordering by a deterministic reconcile-merge
//! over the shared causal graph (design.md §8.4; design-channels.md §7; R-8.6, R-15A.2, R-15A.3).
//!
//! Multiple independent authorities each order their own scope; reconcile is a DETERMINISTIC
//! linearization of the union causal DAG — a topological sort tie-broken by object content id
//! (bytewise). It depends only on the causal graph, not on how scopes are split, so any split of
//! the same objects reconciles to the same order — federated ordering needs no wire change
//! (R-8.6). A higher tier adds capability without changing the baseline envelope (R-15A.2).

use crate::audit::{self, CausalNode};
use crate::cbor::{self, Value};
use crate::cose;

/// Federation's named error: overlapping authority scopes. At baseline an overlap is operator
/// error; at tier 1 the causal-graph reconcile resolves it (each object ordered once).
pub fn err_scope_overlap_conflict() -> cose::Error {
    cose::Error { kind: "ScopeOverlapConflict", msg: "authorities' scopes overlap" }
}

/// Deterministically merge the objects of a shared causal graph into one total order (design
/// §8.4): verify the partial order (audit::verify_causal), then Kahn's topological sort with a
/// content-id (bytewise) tie-break. Causally consistent, deterministic, scope-independent.
pub fn reconcile(nodes: &[CausalNode]) -> Result<Vec<Vec<u8>>, cose::Error> {
    audit::verify_causal(nodes)?;
    let present: std::collections::HashSet<&[u8]> = nodes.iter().map(|n| n.id.as_slice()).collect();
    let mut indeg: Vec<usize> = nodes
        .iter()
        .map(|n| n.causes.iter().filter(|c| present.contains(c.as_slice())).count())
        .collect();
    let mut done = vec![false; nodes.len()];
    let mut order: Vec<Vec<u8>> = Vec::with_capacity(nodes.len());
    while order.len() < nodes.len() {
        let mut pick: Option<usize> = None;
        for i in 0..nodes.len() {
            if done[i] || indeg[i] != 0 {
                continue;
            }
            match pick {
                Some(p) if nodes[p].id <= nodes[i].id => {}
                _ => pick = Some(i),
            }
        }
        let p = match pick {
            Some(p) => p,
            None => return Err(audit::err_causal_violation()), // unreachable after verify_causal
        };
        done[p] = true;
        order.push(nodes[p].id.clone());
        for j in 0..nodes.len() {
            if !done[j] && nodes[j].causes.iter().any(|c| c == &nodes[p].id) {
                indeg[j] -= 1;
            }
        }
    }
    Ok(order)
}

/// Whether an order places every object's (present) causes before it.
pub fn causally_valid(order: &[Vec<u8>], nodes: &[CausalNode]) -> bool {
    let pos: std::collections::HashMap<&[u8], usize> =
        order.iter().enumerate().map(|(k, id)| (id.as_slice(), k)).collect();
    for n in nodes {
        if let Some(&np) = pos.get(n.id.as_slice()) {
            for c in &n.causes {
                if let Some(&cp) = pos.get(c.as_slice()) {
                    if cp > np {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// The tier-1 Federation Reconcile object body (design-channels §7): the authorities reconciled
/// and the resulting deterministic total order (content ids). Signed with the C2 crypto.
pub struct ReconcileRecord {
    pub authorities: Vec<String>,
    pub order: Vec<Vec<u8>>,
}

impl ReconcileRecord {
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Arr(self.authorities.iter().map(|a| Value::Tstr(a.clone())).collect())),
            (Value::Uint(2), Value::Arr(self.order.iter().map(|o| Value::Bstr(o.clone())).collect())),
        ]))
        .expect("encode reconcile record")
    }
}

pub fn sign_reconcile(r: &ReconcileRecord, s: &dyn cose::CoseSigner) -> Vec<u8> {
    s.sign(&r.bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::envelope;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/federation/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus")).expect("parse")
    }

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    fn nodes_of(c: &J) -> Vec<CausalNode> {
        c["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| CausalNode {
                id: hexd(n["id_hex"].as_str().unwrap()),
                causes: n["causes_hex"].as_array().unwrap().iter().map(|x| hexd(x.as_str().unwrap())).collect(),
                position: 0,
            })
            .collect()
    }

    #[test]
    fn reconcile_matches_oracle() {
        let c = load();
        let nodes = nodes_of(&c);
        let order = reconcile(&nodes).expect("reconcile");
        let got: Vec<String> = order.iter().map(hex::encode).collect();
        let want: Vec<String> = c["reconcile_order_hex"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        assert_eq!(got, want);
        assert!(causally_valid(&order, &nodes));
        let auths: Vec<String> = c["authorities"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let rec = ReconcileRecord { authorities: auths, order };
        assert_eq!(hex::encode(rec.bytes()), c["record_hex"].as_str().unwrap());
    }

    #[test]
    fn naive_merge_fails_causality() {
        let c = load();
        let nodes = nodes_of(&c);
        let naive: Vec<Vec<u8>> = c["naive_content_id_sort_hex"].as_array().unwrap().iter().map(|x| hexd(x.as_str().unwrap())).collect();
        assert_eq!(causally_valid(&naive, &nodes), c["naive_causally_valid"].as_bool().unwrap());
        assert!(!c["naive_causally_valid"].as_bool().unwrap(), "graph's naive sort should violate causality");
    }

    #[test]
    fn scope_independence() {
        let c = load();
        let base = reconcile(&nodes_of(&c)).unwrap();
        let mut rev = nodes_of(&c);
        rev.reverse();
        let other = reconcile(&rev).unwrap();
        assert_eq!(base, other, "reconcile depends on input order");
    }

    fn signer(seed: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer, Vec<u8>) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk), pkb)
    }

    #[test]
    fn no_wire_change() {
        let (v, s, pkb) = signer(100);
        let kind_ok = |_c: u64, _k: u64| true;
        let mk = |causes: Vec<Vec<u8>>| -> (Vec<u8>, Vec<u8>) {
            let mut o = envelope::Object {
                id: vec![], kind: 0, channel: 0, tier: 0, signer: pkb.clone(), created: 100,
                effect: 0, causes, profile: cose::PROFILE_PUBLIC as u64, body: Value::Uint(0), ext: None, cext: None,
            };
            let cid = o.content_id();
            let signed = envelope::sign(&mut o, &s);
            (cid, signed)
        };
        let (cid1, s1) = mk(vec![]);
        let (cid2, s2) = mk(vec![cid1.clone()]);
        let (cid3, s3) = mk(vec![cid1.clone()]);
        let signed_by_id: std::collections::HashMap<Vec<u8>, Vec<u8>> =
            [(cid1.clone(), s1), (cid2.clone(), s2), (cid3.clone(), s3)].into_iter().collect();
        let nodes = vec![
            CausalNode { id: cid1.clone(), causes: vec![], position: 0 },
            CausalNode { id: cid2.clone(), causes: vec![cid1.clone()], position: 0 },
            CausalNode { id: cid3.clone(), causes: vec![cid1.clone()], position: 0 },
        ];
        // single authority orders all three; two authorities split then reconcile
        let (_av, asig, _ap) = signer(101);
        let (_bv, bsig, _bp) = signer(102);
        let mut single = audit::Authority::new();
        for id in [&cid1, &cid2, &cid3] {
            single.append(&asig, id, 500);
        }
        let mut a2 = audit::Authority::new();
        let mut b2 = audit::Authority::new();
        a2.append(&asig, &cid1, 500);
        b2.append(&bsig, &cid2, 501);
        a2.append(&asig, &cid3, 502);
        let order = reconcile(&nodes).expect("reconcile");
        assert!(causally_valid(&order, &nodes));
        for id in &order {
            envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed_by_id[id])
                .expect("object verifies after federated ordering");
        }
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn higher_tier_ext_mechanism() {
        let (v, s, pkb) = signer(103);
        let kind_ok = |_c: u64, _k: u64| true;
        // tier-1 object with a higher-tier NON-critical ext -> baseline ignores it
        let mut o1 = envelope::Object {
            id: vec![], kind: 0, channel: 0, tier: 1, signer: pkb.clone(), created: 100,
            effect: 0, causes: vec![], profile: cose::PROFILE_PUBLIC as u64, body: Value::Uint(0),
            ext: Some(vec![(Value::Uint(7), Value::Tstr("higher-tier-hint".into()))]), cext: None,
        };
        let signed1 = envelope::sign(&mut o1, &s);
        envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed1).expect("baseline accepts tier-1 spine");
        // tier-1 object with an unknown CRITICAL ext -> baseline rejects, fail-closed
        let mut o2 = envelope::Object {
            id: vec![], kind: 0, channel: 0, tier: 1, signer: pkb, created: 100,
            effect: 0, causes: vec![], profile: cose::PROFILE_PUBLIC as u64, body: Value::Uint(0),
            ext: None, cext: Some(vec![(Value::Uint(9), Value::Tstr("must-understand".into()))]),
        };
        let signed2 = envelope::sign(&mut o2, &s);
        match envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed2) {
            Err(e) => assert_eq!(e.kind, "UnknownCriticalExt"),
            Ok(_) => panic!("baseline accepted an unknown critical higher-tier extension"),
        }
    }
}
