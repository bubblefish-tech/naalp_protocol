// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C10 — the twenty channel surfaces, baseline tier (design-channels.md; R-11.1..11.4, R-15A).
//!
//! A channel surface is a thin body over the one spine: it adds only kind codes and their
//! declared effects (R-11.3). This module holds the frozen baseline registry for all twenty
//! channels (none omitted), the kind validator + effect binding, per-channel state transitions
//! and named errors, the channel-specific structural checks (CapExceedsParent, TransformCycle),
//! and the Workflow input gate whose crash test proves InputGateBypass cannot occur.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use crate::cose;
use crate::policy;

/// One baseline object kind of a channel.
#[derive(Clone, Copy)]
pub struct KindSpec {
    pub code: u64,
    pub name: &'static str,
    pub effect: u8,
    pub variable: bool,
}

/// One channel's frozen baseline surface.
pub struct ChannelSpec {
    pub id: u64,
    pub name: &'static str,
    pub kinds: Vec<KindSpec>,
    pub states: Vec<&'static str>,
    pub transitions: Vec<(&'static str, &'static str)>,
    pub errors: Vec<&'static str>,
}

fn k(code: u64, name: &'static str, effect: u8, variable: bool) -> KindSpec {
    KindSpec { code, name, effect, variable }
}

/// The frozen twenty-channel baseline registry (design-channels.md §1..§20).
pub fn table() -> Vec<ChannelSpec> {
    let ro = policy::READ_ONLY;
    let iw = policy::IDEMPOTENT_WRITE;
    let niw = policy::NON_IDEMPOTENT_WRITE;
    let de = policy::DESTRUCTIVE;
    vec![
        ChannelSpec { id: 0x0000, name: "Control",
            kinds: vec![k(0, "Hello", ro, false), k(1, "Bye", iw, false), k(2, "Ack", ro, false), k(3, "Error", ro, false)],
            states: vec!["open", "closing"], transitions: vec![("open", "closing")], errors: vec!["UnknownKind", "ProfileMismatch"] },
        ChannelSpec { id: 0x0001, name: "Memory",
            kinds: vec![k(0, "MemoryOffer", iw, false), k(1, "MemoryAccept", iw, false), k(2, "MemoryWrite", niw, false), k(3, "MemoryRead", ro, false), k(4, "MemoryExpire", de, false), k(5, "MemoryRevoke", de, false)],
            states: vec!["offered", "accepted", "live", "expired", "revoked"], transitions: vec![("offered", "accepted"), ("accepted", "live"), ("live", "expired"), ("live", "revoked")], errors: vec!["AccessDenied", "MemoryError"] },
        ChannelSpec { id: 0x0002, name: "Capability",
            kinds: vec![k(0, "CapIssue", niw, false), k(1, "CapDelegate", niw, false), k(2, "CapRevoke", de, false), k(3, "CapLookup", ro, false)],
            states: vec!["issued", "delegated", "revoked", "expired"], transitions: vec![("issued", "delegated"), ("delegated", "delegated"), ("issued", "revoked"), ("delegated", "revoked"), ("issued", "expired"), ("delegated", "expired")], errors: vec!["CapExceedsParent", "CapRevoked"] },
        ChannelSpec { id: 0x0003, name: "Identity",
            kinds: vec![k(0, "Rotation", niw, false), k(1, "Revocation", de, false), k(2, "ForeignLink", iw, false), k(3, "KeyAnnounce", ro, false)],
            states: vec!["active", "rotated", "revoked"], transitions: vec![("active", "rotated"), ("rotated", "rotated"), ("active", "revoked"), ("rotated", "revoked")], errors: vec!["RotationUnauthorized", "KeyRevoked", "SignerMismatch"] },
        ChannelSpec { id: 0x0004, name: "Governance",
            kinds: vec![k(0, "PolicyPublish", niw, false), k(1, "Approval", niw, false), k(2, "ApprovalHeld", ro, false), k(3, "Consume", niw, false)],
            states: vec!["requested", "held", "approved", "consumed", "expired"], transitions: vec![("requested", "held"), ("requested", "approved"), ("approved", "consumed"), ("held", "approved"), ("requested", "expired"), ("approved", "expired")], errors: vec!["ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"] },
        ChannelSpec { id: 0x0005, name: "Immune",
            kinds: vec![k(0, "AnomalyReport", ro, false), k(1, "Quarantine", de, false), k(2, "QuarantineLift", niw, false)],
            states: vec!["normal", "quarantined", "lifted", "permanent"], transitions: vec![("normal", "quarantined"), ("quarantined", "lifted"), ("quarantined", "permanent")], errors: vec!["AccessDenied"] },
        ChannelSpec { id: 0x0006, name: "Federation",
            kinds: vec![k(0, "AuthorityAnnounce", ro, false), k(1, "ScopeReceipt", niw, false)],
            states: vec!["announced", "ordering"], transitions: vec![("announced", "ordering")], errors: vec!["AuthorityUnknown", "ScopeOverlapConflict"] },
        ChannelSpec { id: 0x0007, name: "Settlement",
            kinds: vec![k(0, "SettleIntent", niw, false), k(1, "SettleReceipt", niw, false), k(2, "SettleReject", iw, false)],
            states: vec!["intent", "receipt", "reject"], transitions: vec![("intent", "receipt"), ("intent", "reject")], errors: vec!["ValueMismatch", "SettleExpired"] },
        ChannelSpec { id: 0x0008, name: "Compliance",
            kinds: vec![k(0, "ComplianceRecord", niw, false), k(1, "ComplianceQuery", ro, false), k(2, "ComplianceReport", ro, false)],
            states: vec!["appended"], transitions: vec![], errors: vec!["RecordUnsigned", "JurisdictionUnknown"] },
        ChannelSpec { id: 0x0009, name: "Sensory",
            kinds: vec![k(0, "Observation", ro, false), k(1, "Subscribe", iw, false), k(2, "Unsubscribe", iw, false)],
            states: vec!["active", "cancelled"], transitions: vec![("active", "cancelled")], errors: vec!["SubscriptionUnknown"] },
        ChannelSpec { id: 0x000A, name: "Telemetry",
            kinds: vec![k(0, "Metric", ro, false), k(1, "HealthReport", ro, false)],
            states: vec!["stateless"], transitions: vec![], errors: vec!["MetricMalformed"] },
        ChannelSpec { id: 0x000B, name: "Audit",
            kinds: vec![k(0, "Receipt", niw, false), k(1, "AuditQuery", ro, false), k(2, "ForkProof", ro, false)],
            states: vec!["appended"], transitions: vec![], errors: vec!["ChainBroken", "Equivocation", "ReceiptUnsigned"] },
        ChannelSpec { id: 0x000C, name: "Stream",
            kinds: vec![k(0, "StreamOpen", ro, true), k(1, "StreamCommit", ro, false), k(2, "StreamCheckpoint", ro, false)],
            states: vec!["open", "committed"], transitions: vec![("open", "committed")], errors: vec!["StreamDigestMismatch", "FlowControlError"] },
        ChannelSpec { id: 0x000D, name: "Bridge",
            kinds: vec![k(0, "Carriage", ro, true)],
            states: vec!["carried"], transitions: vec![], errors: vec!["EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"] },
        ChannelSpec { id: 0x000E, name: "Commerce",
            kinds: vec![k(0, "Offer", ro, false), k(1, "Order", niw, false), k(2, "Fulfil", niw, false), k(3, "Cancel", de, false)],
            states: vec!["offer", "order", "fulfil", "cancel"], transitions: vec![("offer", "order"), ("order", "fulfil"), ("order", "cancel")], errors: vec!["OfferExpired", "ApprovalRequired", "OrderMismatch"] },
        ChannelSpec { id: 0x000F, name: "Interaction",
            kinds: vec![k(0, "Elicit", ro, false), k(1, "Respond", iw, false), k(2, "Confirm", niw, false)],
            states: vec!["elicit", "respond", "confirm", "timeout"], transitions: vec![("elicit", "respond"), ("elicit", "confirm"), ("elicit", "timeout")], errors: vec!["InteractionTimeout", "ElicitUnauthorized"] },
        ChannelSpec { id: 0x0010, name: "Discovery",
            kinds: vec![k(0, "DiscoveryRecord", ro, false), k(1, "DiscoveryQuery", ro, false)],
            states: vec!["fresh", "stale"], transitions: vec![("fresh", "stale")], errors: vec!["RecordExpired", "TrustAnchorUnknown"] },
        ChannelSpec { id: 0x0011, name: "Workflow",
            kinds: vec![k(0, "TaskCreate", niw, false), k(1, "TaskInput", niw, false), k(2, "TaskCancel", de, false), k(3, "TaskResult", niw, false)],
            states: vec!["created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"],
            transitions: vec![("created", "awaiting-input"), ("created", "awaiting-approval"), ("awaiting-input", "running"), ("awaiting-approval", "running"), ("running", "result"), ("created", "cancelled"), ("awaiting-input", "cancelled"), ("awaiting-approval", "cancelled"), ("running", "cancelled")],
            errors: vec!["TaskStateError", "InputGateBypass", "ApprovalRequired"] },
        ChannelSpec { id: 0x0012, name: "Knowledge",
            kinds: vec![k(0, "Assert", niw, false), k(1, "Retract", de, false), k(2, "KnowledgeQuery", ro, false)],
            states: vec!["asserted", "retracted"], transitions: vec![("asserted", "retracted")], errors: vec!["FactUnsigned", "RetractUnknown"] },
        ChannelSpec { id: 0x0013, name: "Spatial",
            kinds: vec![k(0, "FrameDefine", iw, false), k(1, "Pose", ro, false), k(2, "StateUpdate", ro, false), k(3, "SnapshotQuery", ro, false)],
            states: vec!["defined", "observed"], transitions: vec![("defined", "observed")], errors: vec!["FrameUnknown", "TransformCycle"] },
    ]
}

pub fn err_effect_declaration_mismatch() -> cose::Error {
    cose::Error { kind: "EffectDeclarationMismatch", msg: "object effect does not match the kind's declared effect" }
}
pub fn err_unknown_kind() -> cose::Error {
    cose::Error { kind: "UnknownKind", msg: "kind/channel not in the baseline registry" }
}
pub fn err_cap_exceeds_parent() -> cose::Error {
    cose::Error { kind: "CapExceedsParent", msg: "a delegation may not grant more than its parent" }
}
pub fn err_transform_cycle() -> cose::Error {
    cose::Error { kind: "TransformCycle", msg: "coordinate frame tree contains a cycle" }
}
pub fn err_input_gate_bypass() -> cose::Error {
    cose::Error { kind: "InputGateBypass", msg: "a task reached running without passing the input/approval gate" }
}
pub fn err_task_state() -> cose::Error {
    cose::Error { kind: "TaskStateError", msg: "workflow task state transition not permitted" }
}

/// The kind spec for a (channel, kind) pair.
pub fn lookup(channel: u64, kind: u64) -> Option<KindSpec> {
    table().into_iter().find(|c| c.id == channel).and_then(|c| c.kinds.into_iter().find(|k| k.code == kind))
}

/// Accepts exactly the registered (channel, kind) pairs (the envelope kind validator).
pub fn kind_validator(channel: u64, kind: u64) -> bool {
    lookup(channel, kind).is_some()
}

/// Bind a kind to its declared effect (R-11.2): a fixed-effect kind's object must carry exactly
/// the declared effect; a variable-effect kind accepts any valid effect (0..3).
pub fn check_effect(channel: u64, kind: u64, effect: u64) -> Result<(), cose::Error> {
    match lookup(channel, kind) {
        None => Err(err_unknown_kind()),
        Some(k) if k.variable => {
            if effect > policy::DESTRUCTIVE as u64 {
                Err(err_effect_declaration_mismatch())
            } else {
                Ok(())
            }
        }
        Some(k) => {
            if effect != k.effect as u64 {
                Err(err_effect_declaration_mismatch())
            } else {
                Ok(())
            }
        }
    }
}

/// Whether a channel permits a state transition from -> to.
pub fn allowed_transition(channel: u64, from: &str, to: &str) -> bool {
    table()
        .into_iter()
        .find(|c| c.id == channel)
        .map(|c| c.transitions.iter().any(|(a, b)| *a == from && *b == to))
        .unwrap_or(false)
}

/// Capability CapExceedsParent: a delegated ceiling may not exceed its parent's.
pub fn check_delegation(parent_max: u8, child_max: u8) -> Result<(), cose::Error> {
    if !policy::authorizes(parent_max, child_max) {
        return Err(err_cap_exceeds_parent());
    }
    Ok(())
}

/// Spatial TransformCycle: the coordinate-frame child->parent links must be acyclic.
pub fn check_frame_tree(parent: &HashMap<String, String>) -> Result<(), cose::Error> {
    let mut color: HashMap<&str, u8> = HashMap::new();
    fn visit<'a>(f: &'a str, parent: &'a HashMap<String, String>, color: &mut HashMap<&'a str, u8>) -> bool {
        color.insert(f, 1);
        if let Some(p) = parent.get(f) {
            if !p.is_empty() {
                match color.get(p.as_str()).copied().unwrap_or(0) {
                    1 => return true,
                    0 => {
                        if visit(p.as_str(), parent, color) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        color.insert(f, 2);
        false
    }
    for f in parent.keys() {
        if color.get(f.as_str()).copied().unwrap_or(0) == 0 && visit(f.as_str(), parent, &mut color) {
            return Err(err_transform_cycle());
        }
    }
    Ok(())
}

/// Gate errors: an IO failure of the WAL or a protocol-level state error.
#[derive(Debug)]
pub enum GateError {
    Io(std::io::Error),
    Cose(cose::Error),
}

impl GateError {
    pub fn cose_kind(&self) -> Option<&str> {
        match self {
            GateError::Cose(c) => Some(c.kind),
            GateError::Io(_) => None,
        }
    }
}

/// A durable, WAL-backed Workflow task-status tracker (design-channels.md §18). A task's status
/// is fsynced before it is acknowledged, so a crash recovers to the last durable status and can
/// NEVER bypass the input/approval gate.
pub struct WorkflowGate {
    f: File,
    status: HashMap<String, String>,
}

pub fn open_workflow_gate(path: &std::path::Path) -> Result<WorkflowGate, GateError> {
    let mut f = OpenOptions::new().read(true).write(true).create(true).open(path).map_err(GateError::Io)?;
    let mut status = HashMap::new();
    f.seek(SeekFrom::Start(0)).map_err(GateError::Io)?;
    loop {
        let mut lb = [0u8; 4];
        match f.read_exact(&mut lb) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(GateError::Io(e)),
        }
        let n = u32::from_be_bytes(lb) as usize;
        let mut rec = vec![0u8; n];
        f.read_exact(&mut rec).map_err(GateError::Io)?;
        let nul = rec.iter().position(|&b| b == 0).ok_or_else(|| GateError::Cose(cose::Error { kind: "Malformed", msg: "workflow gate record" }))?;
        let task = String::from_utf8_lossy(&rec[..nul]).into_owned();
        let st = String::from_utf8_lossy(&rec[nul + 1..]).into_owned();
        status.insert(task, st);
    }
    Ok(WorkflowGate { f, status })
}

impl WorkflowGate {
    fn persist(&mut self, task: &str, status: &str) -> Result<(), GateError> {
        let mut rec = task.as_bytes().to_vec();
        rec.push(0);
        rec.extend_from_slice(status.as_bytes());
        self.f.seek(SeekFrom::End(0)).map_err(GateError::Io)?;
        self.f.write_all(&(rec.len() as u32).to_be_bytes()).map_err(GateError::Io)?;
        self.f.write_all(&rec).map_err(GateError::Io)?;
        self.f.sync_all().map_err(GateError::Io)?; // persist-before-ack (spine §9.2)
        self.status.insert(task.to_string(), status.to_string());
        Ok(())
    }

    /// TaskCreate lands in a non-terminal pre-gate status, never "running".
    pub fn create(&mut self, task: &str, needs_approval: bool) -> Result<(), GateError> {
        if self.status.contains_key(task) {
            return Err(GateError::Cose(err_task_state()));
        }
        self.persist(task, if needs_approval { "awaiting-approval" } else { "awaiting-input" })
    }

    /// Open the input/approval gate.
    pub fn supply_input(&mut self, task: &str) -> Result<(), GateError> {
        match self.status.get(task).map(String::as_str) {
            Some("awaiting-input") => self.persist(task, "input-supplied"),
            Some("awaiting-approval") => self.persist(task, "approved"),
            _ => Err(GateError::Cose(err_task_state())),
        }
    }

    /// Run only if the gate was passed; otherwise InputGateBypass.
    pub fn run(&mut self, task: &str) -> Result<(), GateError> {
        match self.status.get(task).map(String::as_str) {
            Some("input-supplied") | Some("approved") => self.persist(task, "running"),
            Some("awaiting-input") | Some("awaiting-approval") => Err(GateError::Cose(err_input_gate_bypass())),
            _ => Err(GateError::Cose(err_task_state())),
        }
    }

    pub fn status(&self, task: &str) -> Option<String> {
        self.status.get(task).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::envelope;
    use serde_json::Value as J;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn load_channel(dir: &str) -> J {
        let p = format!("../../vectors/channels/{}/cases.json", dir);
        serde_json::from_str(&std::fs::read_to_string(&p).expect("read")).expect("parse")
    }

    #[test]
    fn table_matches_oracle() {
        let t = table();
        assert_eq!(t.len(), 20);
        for ch in &t {
            let c = load_channel(&ch.name.to_lowercase());
            assert_eq!(c["channel_id"].as_u64().unwrap(), ch.id);
            assert_eq!(c["name"].as_str().unwrap(), ch.name);
            let ok = c["kinds"].as_array().unwrap();
            assert_eq!(ok.len(), ch.kinds.len(), "{} kinds", ch.name);
            for (i, kk) in ch.kinds.iter().enumerate() {
                assert_eq!(ok[i]["code"].as_u64().unwrap(), kk.code);
                assert_eq!(ok[i]["name"].as_str().unwrap(), kk.name);
                assert_eq!(ok[i]["effect"].as_u64().unwrap(), kk.effect as u64);
                assert_eq!(ok[i]["variable"].as_bool().unwrap(), kk.variable);
            }
            let ot = c["transitions"].as_array().unwrap();
            assert_eq!(ot.len(), ch.transitions.len(), "{} transitions", ch.name);
            for (i, (a, b)) in ch.transitions.iter().enumerate() {
                assert_eq!(ot[i]["from"].as_str().unwrap(), *a);
                assert_eq!(ot[i]["to"].as_str().unwrap(), *b);
            }
            let os: Vec<&str> = c["states"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
            assert_eq!(os, ch.states, "{} states", ch.name);
            let oe: Vec<&str> = c["errors"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
            assert_eq!(oe, ch.errors, "{} errors", ch.name);
        }
    }

    #[test]
    fn completeness() {
        let t = table();
        let mut seen = std::collections::HashSet::new();
        for ch in &t {
            assert!(!ch.kinds.is_empty(), "{} thinned", ch.name);
            for k in &ch.kinds {
                assert!(k.effect <= policy::DESTRUCTIVE, "{} bad effect", ch.name);
            }
            seen.insert(ch.id);
        }
        for id in 0u64..=0x0013 {
            assert!(seen.contains(&id), "channel {:#x} missing", id);
        }
    }

    fn signer(seed: u8) -> (cose::MlDsa65Verifier, cose::MlDsa65Signer, Vec<u8>) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk), pkb)
    }

    #[test]
    fn surface_over_spine() {
        let (v, s, pkb) = signer(90);
        let kind_ok = |ch: u64, k: u64| kind_validator(ch, k);
        for ch in table() {
            let kind = ch.kinds[0];
            let eff = kind.effect as u64;
            let mut o = envelope::Object {
                id: vec![], kind: kind.code, channel: ch.id, tier: 0, signer: pkb.clone(), created: 100,
                effect: eff, causes: vec![], profile: cose::PROFILE_PUBLIC as u64, body: Value::Uint(0), ext: None, cext: None,
            };
            let signed = envelope::sign(&mut o, &s);
            envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed)
                .unwrap_or_else(|_| panic!("{}: object does not verify over spine", ch.name));
            check_effect(ch.id, kind.code, eff).unwrap_or_else(|_| panic!("{} declared effect rejected", ch.name));
            if !kind.variable {
                let wrong = (eff + 1) % 4;
                assert!(check_effect(ch.id, kind.code, wrong).is_err(), "{} wrong effect accepted", ch.name);
            }
        }
        assert!(!kind_validator(0x0000, 99));
    }

    #[test]
    fn state_machine() {
        assert!(allowed_transition(0x0001, "offered", "accepted"));
        assert!(allowed_transition(0x0001, "live", "revoked"));
        assert!(!allowed_transition(0x0001, "revoked", "live"));
        assert!(allowed_transition(0x000E, "order", "fulfil"));
        assert!(!allowed_transition(0x000E, "offer", "fulfil"));
        assert!(allowed_transition(0x0011, "awaiting-input", "running"));
        assert!(!allowed_transition(0x0011, "created", "running"));
    }

    #[test]
    fn cap_exceeds_parent() {
        check_delegation(policy::NON_IDEMPOTENT_WRITE, policy::READ_ONLY).expect("valid attenuation");
        assert_eq!(check_delegation(policy::NON_IDEMPOTENT_WRITE, policy::DESTRUCTIVE).unwrap_err().kind, "CapExceedsParent");
    }

    #[test]
    fn transform_cycle() {
        let mut tree = HashMap::new();
        tree.insert("base".to_string(), String::new());
        tree.insert("arm".to_string(), "base".to_string());
        tree.insert("hand".to_string(), "arm".to_string());
        check_frame_tree(&tree).expect("valid tree");
        let mut cyclic = HashMap::new();
        cyclic.insert("a".to_string(), "b".to_string());
        cyclic.insert("b".to_string(), "c".to_string());
        cyclic.insert("c".to_string(), "a".to_string());
        assert_eq!(check_frame_tree(&cyclic).unwrap_err().kind, "TransformCycle");
    }

    fn tmp_gate() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!("naalp_wf_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn workflow_input_gate_bypass() {
        let path = tmp_gate();
        {
            let mut g = open_workflow_gate(&path).unwrap();
            g.create("t1", false).unwrap();
            assert_eq!(g.run("t1").unwrap_err().cose_kind(), Some("InputGateBypass"));
        } // crash right after create
        let mut g2 = open_workflow_gate(&path).unwrap();
        assert_eq!(g2.status("t1").as_deref(), Some("awaiting-input"), "crash bypassed the gate");
        assert_eq!(g2.run("t1").unwrap_err().cose_kind(), Some("InputGateBypass"));
        g2.supply_input("t1").unwrap();
        g2.run("t1").unwrap();
        assert_eq!(g2.status("t1").as_deref(), Some("running"));
        let _ = std::fs::remove_file(&path);
    }
}
