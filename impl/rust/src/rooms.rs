// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Collaboration / rooms membership surface (feature #64) — a Phase-3 ADDITIVE higher tier
//! (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It is
//! the Rust half of the two-implementation parity: every op/receipt/binding byte it produces
//! matches the independent oracle (tools/rooms_oracle.py), so Go == Rust.
//!
//! It introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3):
//! it reuses the spine and adds only tier-1 kinds on Governance (0x0004; membership ops) and
//! Identity (0x0003; the principal registry). It builds three recorded decisions:
//!   * #4a Membership carriage — a membership change is a first-class SIGNED object that is
//!     CURSOR-OCCUPYING (an ordered position in the per-room log), RECEIPT-CHAINED (the log IS
//!     the append-only audit receipt chain, §8.1), and EPOCH-BUMPING (a stale-epoch op is
//!     rejected).
//!   * #4b O2 ownership — multi-owner, ADD-ONLY: owners are added, never removed or demoted, so
//!     the owner count is monotonically >= 1 (no ownerless room).
//!   * #3  Delivery Model B — a PrincipalRegistry maps a stable semantic id to a durable Handle,
//!     resolved at send time; a rebind is authorised only by a verified rotation (R-1.4).
//! Every check is fail-closed.

use std::collections::HashMap;

use sha2::{Digest, Sha384};

use crate::audit;
use crate::cbor::{self, Value};
use crate::channels;
use crate::cose;
use crate::envelope;
use crate::identity;
use crate::policy;

/// Channel bindings (R-1.2) and the tier for this higher-tier surface.
pub const CHANNEL_GOVERNANCE: u64 = 0x0004;
pub const CHANNEL_IDENTITY: u64 = 0x0003;
pub const TIER: u64 = 1;

/// Room membership operation codes (naalp-room-op field 2).
pub const OP_CREATE: u64 = 0;
pub const OP_ADD_MEMBER: u64 = 1;
pub const OP_REMOVE_MEMBER: u64 = 2;
pub const OP_CHANGE_ROLE: u64 = 3;
pub const OP_ADD_OWNER: u64 = 4;

/// Role codes (naalp-room-op field 5).
pub const ROLE_MEMBER: u64 = 0;
pub const ROLE_ADMIN: u64 = 1;
pub const ROLE_OWNER: u64 = 2;

/// Tier-1 kind codes (Governance membership ops; Identity principal bind).
pub const KIND_ROOM_CREATE: u64 = 16;
pub const KIND_ROOM_ADD_MEMBER: u64 = 17;
pub const KIND_ROOM_REMOVE_MEMBER: u64 = 18;
pub const KIND_ROOM_CHANGE_ROLE: u64 = 19;
pub const KIND_ROOM_ADD_OWNER: u64 = 20;
pub const KIND_PRINCIPAL_BIND: u64 = 16; // on the Identity channel

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_stale_epoch() -> cose::Error {
    err(
        "StaleEpoch",
        "op epoch does not match the room's current membership epoch",
    )
}
pub fn err_unauthorized() -> cose::Error {
    err("Unauthorized", "actor is not an owner of the room")
}
pub fn err_owner_immutable() -> cose::Error {
    err(
        "OwnerImmutable",
        "an owner cannot be removed or demoted (ownership is add-only)",
    )
}
pub fn err_member_exists() -> cose::Error {
    err("MemberExists", "subject is already a member")
}
pub fn err_member_unknown() -> cose::Error {
    err("MemberUnknown", "subject is not a member of the room")
}
pub fn err_owner_exists() -> cose::Error {
    err("OwnerExists", "subject is already an owner")
}
pub fn err_role_invalid() -> cose::Error {
    err("RoleInvalid", "role is not valid for this operation")
}
pub fn err_room_op_mismatch() -> cose::Error {
    err(
        "RoomOpMismatch",
        "op room id, kind, or op code does not match this room/operation",
    )
}
pub fn err_op_unknown() -> cose::Error {
    err("OpUnknown", "unknown room op code")
}
pub fn err_non_nfc() -> cose::Error {
    err("NonNFC", "subject/principal string is not Unicode NFC")
}
pub fn err_principal_unknown() -> cose::Error {
    err(
        "PrincipalUnknown",
        "no binding for the semantic principal id",
    )
}
pub fn err_principal_exists() -> cose::Error {
    err("PrincipalExists", "principal already bound; use rebind")
}
pub fn err_rebind_unauthorized() -> cose::Error {
    err(
        "RebindUnauthorized",
        "a rebind requires a verified rotation from the current handle to the new handle",
    )
}

/// Content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body)).
fn content_id_of(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x20u8, 0x30u8];
    out.extend_from_slice(&Sha384::digest(body));
    out
}

// ---- the membership op ----------------------------------------------------------------

/// One membership operation body carried in envelope field 10.
#[derive(Clone)]
pub struct RoomOp {
    pub room: Vec<u8>,
    pub op: u64,
    pub epoch: u64,
    pub subject: String,
    pub role: u64,
}

impl RoomOp {
    fn to_map(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.room.clone())),
            (Value::Uint(2), Value::Uint(self.op)),
            (Value::Uint(3), Value::Uint(self.epoch)),
            (Value::Uint(4), Value::Tstr(self.subject.clone())),
            (Value::Uint(5), Value::Uint(self.role)),
        ])
    }

    /// Deterministic-CBOR encoding {1:room,2:op,3:epoch,4:subject,5:role}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_map()).expect("encode room op")
    }

    /// The op's content id (the room log orders this).
    pub fn content_id(&self) -> Vec<u8> {
        content_id_of(&self.bytes())
    }

    /// Build the (unsigned) envelope object that carries this op (tier 1, Governance channel,
    /// the op's kind + declared effect, the op body as field 10).
    pub fn envelope_object(
        &self,
        signer: &[u8],
        created: u64,
        profile: u64,
        causes: Vec<Vec<u8>>,
    ) -> Result<envelope::Object, cose::Error> {
        let (kind, eff) = kind_for_op(self.op).ok_or_else(err_op_unknown)?;
        identity::require_nfc(&self.subject).map_err(|_| err_non_nfc())?;
        Ok(envelope::Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind,
            channel: CHANNEL_GOVERNANCE,
            tier: TIER,
            signer: signer.to_vec(),
            created,
            effect: eff as u64,
            causes,
            profile,
            body: self.to_map(),
            ext: None,
            cext: None,
        })
    }
}

/// Map an op code to its tier-1 Governance kind and declared effect (design-channels.md §21).
pub fn kind_for_op(op: u64) -> Option<(u64, u8)> {
    match op {
        OP_CREATE => Some((KIND_ROOM_CREATE, policy::NON_IDEMPOTENT_WRITE)),
        OP_ADD_MEMBER => Some((KIND_ROOM_ADD_MEMBER, policy::NON_IDEMPOTENT_WRITE)),
        OP_REMOVE_MEMBER => Some((KIND_ROOM_REMOVE_MEMBER, policy::DESTRUCTIVE)),
        OP_CHANGE_ROLE => Some((KIND_ROOM_CHANGE_ROLE, policy::NON_IDEMPOTENT_WRITE)),
        OP_ADD_OWNER => Some((KIND_ROOM_ADD_OWNER, policy::NON_IDEMPOTENT_WRITE)),
        _ => None,
    }
}

/// Parse an envelope object body (field 10) back into a RoomOp; a malformed body is
/// RoomOpMismatch (fail-closed).
pub fn room_op_from_body(v: &Value) -> Result<RoomOp, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_room_op_mismatch()),
    };
    let mut room: Option<Vec<u8>> = None;
    let mut op: Option<u64> = None;
    let mut epoch: Option<u64> = None;
    let mut subject: Option<String> = None;
    let mut role: Option<u64> = None;
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => *u,
            _ => return Err(err_room_op_mismatch()),
        };
        match (key, val) {
            (1, Value::Bstr(b)) => room = Some(b.clone()),
            (2, Value::Uint(u)) => op = Some(*u),
            (3, Value::Uint(u)) => epoch = Some(*u),
            (4, Value::Tstr(s)) => subject = Some(s.clone()),
            (5, Value::Uint(u)) => role = Some(*u),
            _ => return Err(err_room_op_mismatch()),
        }
    }
    match (room, op, epoch, subject, role) {
        (Some(room), Some(op), Some(epoch), Some(subject), Some(role)) => Ok(RoomOp {
            room,
            op,
            epoch,
            subject,
            role,
        }),
        _ => Err(err_room_op_mismatch()),
    }
}

// ---- kind validation ------------------------------------------------------------------

/// Accepts exactly this surface's tier-1 kinds.
pub fn kind_validator(channel: u64, kind: u64) -> bool {
    match channel {
        CHANNEL_GOVERNANCE => (KIND_ROOM_CREATE..=KIND_ROOM_ADD_OWNER).contains(&kind),
        CHANNEL_IDENTITY => kind == KIND_PRINCIPAL_BIND,
        _ => false,
    }
}

/// Accepts the frozen baseline kinds OR this surface's tier-1 kinds — leaving the frozen
/// registry untouched; a baseline-only verifier rejects a room kind as UnknownKind.
pub fn composed_kind_validator(channel: u64, kind: u64) -> bool {
    channels::kind_validator(channel, kind) || kind_validator(channel, kind)
}

// ---- the room state machine -----------------------------------------------------------

/// A collaboration room's live membership state and its signed, append-only receipt-chained log.
pub struct Room {
    id: Vec<u8>,
    epoch: u64,
    members: HashMap<String, u64>,
    owners: HashMap<String, bool>,
    auth: audit::Authority,
    receipts: Vec<audit::Receipt>,
    sigs: Vec<Vec<u8>>,
}

/// Build a room from a verified create op signed by the creator. The creator (the subject)
/// becomes the first owner+member; the create op occupies cursor 0; the room advances to epoch 1.
pub fn create_room(
    op: &RoomOp,
    actor: &str,
    auth_signer: &dyn cose::CoseSigner,
    at: u64,
) -> Result<(Room, audit::Receipt, u64), cose::Error> {
    if op.op != OP_CREATE {
        return Err(err_room_op_mismatch());
    }
    if op.epoch != 0 {
        return Err(err_stale_epoch());
    }
    if op.subject.is_empty() {
        return Err(err_room_op_mismatch());
    }
    identity::require_nfc(&op.subject).map_err(|_| err_non_nfc())?;
    if actor != op.subject {
        return Err(err_unauthorized());
    }
    let mut members = HashMap::new();
    members.insert(op.subject.clone(), ROLE_OWNER);
    let mut owners = HashMap::new();
    owners.insert(op.subject.clone(), true);
    let mut auth = audit::Authority::new();
    let (rec, sig) = auth.append(auth_signer, &op.content_id(), at);
    let cursor = rec.seq;
    let room = Room {
        id: op.room.clone(),
        epoch: 1,
        members,
        owners,
        auth,
        receipts: vec![rec.clone()],
        sigs: vec![sig],
    };
    Ok((room, rec, cursor))
}

impl Room {
    /// Validate and apply one membership op (add_member/remove_member/change_role/add_owner) by
    /// an owner `actor`, order it into the log, and bump the epoch. Fail-closed throughout: any
    /// failure returns a named error and leaves the room unchanged.
    pub fn apply(
        &mut self,
        op: &RoomOp,
        actor: &str,
        auth_signer: &dyn cose::CoseSigner,
        at: u64,
    ) -> Result<(audit::Receipt, u64), cose::Error> {
        if op.room != self.id || op.op == OP_CREATE {
            return Err(err_room_op_mismatch());
        }
        if op.epoch != self.epoch {
            return Err(err_stale_epoch());
        }
        if op.subject.is_empty() {
            return Err(err_room_op_mismatch());
        }
        identity::require_nfc(&op.subject).map_err(|_| err_non_nfc())?;
        if !self.owners.contains_key(actor) {
            return Err(err_unauthorized());
        }
        // Per-op semantic validation — NO mutation yet.
        match op.op {
            OP_ADD_MEMBER => {
                if op.role != ROLE_MEMBER && op.role != ROLE_ADMIN {
                    return Err(err_role_invalid());
                }
                if self.members.contains_key(&op.subject) {
                    return Err(err_member_exists());
                }
            }
            OP_ADD_OWNER => {
                if op.role != ROLE_OWNER {
                    return Err(err_role_invalid());
                }
                if self.owners.contains_key(&op.subject) {
                    return Err(err_owner_exists());
                }
            }
            OP_REMOVE_MEMBER => {
                if !self.members.contains_key(&op.subject) {
                    return Err(err_member_unknown());
                }
                if self.owners.contains_key(&op.subject) {
                    return Err(err_owner_immutable());
                }
            }
            OP_CHANGE_ROLE => {
                let cur = match self.members.get(&op.subject) {
                    Some(r) => *r,
                    None => return Err(err_member_unknown()),
                };
                if op.role != ROLE_MEMBER && op.role != ROLE_ADMIN {
                    return Err(err_role_invalid());
                }
                if cur == ROLE_OWNER {
                    return Err(err_owner_immutable());
                }
            }
            _ => return Err(err_op_unknown()),
        }
        // Order the op into the log first; then mutate; then bump the epoch.
        let (rec, sig) = self.auth.append(auth_signer, &op.content_id(), at);
        match op.op {
            OP_ADD_MEMBER => {
                self.members.insert(op.subject.clone(), op.role);
            }
            OP_ADD_OWNER => {
                self.members.insert(op.subject.clone(), ROLE_OWNER);
                self.owners.insert(op.subject.clone(), true);
            }
            OP_REMOVE_MEMBER => {
                self.members.remove(&op.subject);
            }
            OP_CHANGE_ROLE => {
                self.members.insert(op.subject.clone(), op.role);
            }
            _ => unreachable!(),
        }
        let cursor = rec.seq;
        self.receipts.push(rec.clone());
        self.sigs.push(sig);
        self.epoch += 1;
        Ok((rec, cursor))
    }

    /// Behavioural end-to-end path: verify a signed membership object with real crypto, bind the
    /// claimed signer id to the verifying key (a self-asserted id confers no authority,
    /// R-1.3/R-5.1), confirm it is a tier-1 Governance room op whose kind+effect match its op
    /// code, then apply it with the authenticated signer id as the actor.
    pub fn apply_signed(
        &mut self,
        profile: u32,
        v: &dyn cose::CoseVerifier,
        pubkey: &[u8],
        signed_obj: &[u8],
        auth_signer: &dyn cose::CoseSigner,
        at: u64,
    ) -> Result<(audit::Receipt, u64), cose::Error> {
        let o = envelope::verify(
            profile,
            v,
            &|c, k| composed_kind_validator(c, k),
            &[],
            signed_obj,
        )?;
        if o.channel != CHANNEL_GOVERNANCE || o.tier != TIER {
            return Err(err_room_op_mismatch());
        }
        let actor = identity::signer_id(v.alg(), pubkey)?;
        if o.signer != actor.as_bytes() {
            return Err(err(
                "SignerMismatch",
                "signer id does not equal the recomputed id",
            ));
        }
        let op = room_op_from_body(&o.body)?;
        match kind_for_op(op.op) {
            Some((kind, eff)) if kind == o.kind && (eff as u64) == o.effect => {}
            _ => return Err(err_room_op_mismatch()),
        }
        self.apply(&op, &actor, auth_signer, at)
    }

    pub fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn role_of(&self, subject: &str) -> Option<u64> {
        self.members.get(subject).copied()
    }
    pub fn is_owner(&self, subject: &str) -> bool {
        self.owners.contains_key(subject)
    }
    pub fn owner_count(&self) -> usize {
        self.owners.len()
    }
    /// Returns the members and their roles (a copy) — mirrors Go Room.Members().
    pub fn members(&self) -> HashMap<String, u64> {
        self.members.clone()
    }
    pub fn owners(&self) -> Vec<String> {
        let mut v: Vec<String> = self.owners.keys().cloned().collect();
        v.sort();
        v
    }
    pub fn log(&self) -> (&[audit::Receipt], &[Vec<u8>]) {
        (&self.receipts, &self.sigs)
    }
}

// ---- Delivery Model B: the principal registry -----------------------------------------

/// One principal-registry binding record (semantic id -> durable Handle at a per-principal epoch).
#[derive(Clone)]
pub struct Binding {
    pub principal: String,
    pub handle: String,
    pub epoch: u64,
    pub prev: Vec<u8>,
}

impl Binding {
    fn to_map(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Tstr(self.principal.clone())),
            (Value::Uint(2), Value::Tstr(self.handle.clone())),
            (Value::Uint(3), Value::Uint(self.epoch)),
            (Value::Uint(4), Value::Bstr(self.prev.clone())),
        ])
    }
    /// Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_map()).expect("encode binding")
    }
    /// Per-principal chain head after this binding: SHA-384(binding body).
    pub fn head(&self) -> Vec<u8> {
        Sha384::digest(&self.bytes()).to_vec()
    }
}

/// The empty per-principal chain head (48 zero bytes).
pub fn genesis_head() -> Vec<u8> {
    vec![0u8; audit::HEAD_SIZE]
}

/// The durable semantic-naming layer of Delivery Model B.
#[derive(Default)]
pub struct PrincipalRegistry {
    chain: HashMap<String, Vec<Binding>>,
    head: HashMap<String, Vec<u8>>,
    current: HashMap<String, String>,
    epoch: HashMap<String, u64>,
}

impl PrincipalRegistry {
    pub fn new() -> Self {
        PrincipalRegistry::default()
    }

    /// Create the FIRST binding for a principal (epoch 0, prev = genesis).
    pub fn bind(&mut self, principal: &str, handle: &str) -> Result<Binding, cose::Error> {
        if principal.is_empty() || handle.is_empty() {
            return Err(err_room_op_mismatch());
        }
        identity::require_nfc(principal).map_err(|_| err_non_nfc())?;
        identity::require_nfc(handle).map_err(|_| err_non_nfc())?;
        if self.current.contains_key(principal) {
            return Err(err_principal_exists());
        }
        let b = Binding {
            principal: principal.into(),
            handle: handle.into(),
            epoch: 0,
            prev: genesis_head(),
        };
        self.chain.insert(principal.into(), vec![b.clone()]);
        self.head.insert(principal.into(), b.head());
        self.current.insert(principal.into(), handle.into());
        self.epoch.insert(principal.into(), 0);
        Ok(b)
    }

    /// Update a principal to a new durable Handle, REQUIRING a verified rotation from the current
    /// handle to the new handle (R-1.4); a rebind to an unrelated key is RebindUnauthorized.
    #[allow(clippy::too_many_arguments)]
    pub fn rebind(
        &mut self,
        principal: &str,
        new_handle: &str,
        rot: &identity::RotationRecord,
        old_v: &dyn cose::CoseVerifier,
        new_v: &dyn cose::CoseVerifier,
        old_pub: &[u8],
        new_pub: &[u8],
        old_sig: &[u8],
        new_sig: &[u8],
    ) -> Result<Binding, cose::Error> {
        let cur = match self.current.get(principal) {
            Some(h) => h.clone(),
            None => return Err(err_principal_unknown()),
        };
        if new_handle.is_empty() {
            return Err(err_room_op_mismatch());
        }
        identity::require_nfc(new_handle).map_err(|_| err_non_nfc())?;
        if rot.old != cur || rot.new != new_handle {
            return Err(err_rebind_unauthorized());
        }
        if identity::verify_rotation(rot, old_v, new_v, old_pub, new_pub, old_sig, new_sig).is_err()
        {
            return Err(err_rebind_unauthorized());
        }
        let ep = self.epoch[principal] + 1;
        let b = Binding {
            principal: principal.into(),
            handle: new_handle.into(),
            epoch: ep,
            prev: self.head[principal].clone(),
        };
        self.chain.get_mut(principal).unwrap().push(b.clone());
        self.head.insert(principal.into(), b.head());
        self.current.insert(principal.into(), new_handle.into());
        self.epoch.insert(principal.into(), ep);
        Ok(b)
    }

    /// Resolve a semantic principal id to its current durable Handle at send time (Delivery
    /// Model B). Unknown principal is PrincipalUnknown (fail-closed).
    pub fn resolve(&self, principal: &str) -> Result<String, cose::Error> {
        self.current
            .get(principal)
            .cloned()
            .ok_or_else(err_principal_unknown)
    }

    pub fn chain(&self, principal: &str) -> Option<&Vec<Binding>> {
        self.chain.get(principal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/rooms/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }
    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }
    fn key(seed: u8) -> (cose::MlDsa65Signer, cose::MlDsa65Verifier, Vec<u8>, String) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        let id = identity::signer_id(cose::ALG_MLDSA65, &pkb).unwrap();
        (cose::MlDsa65Signer(sk), cose::MlDsa65Verifier(pk), pkb, id)
    }

    // Every op body + content id is byte-identical to the oracle (⟹ Go == Rust).
    #[test]
    fn op_bodies_match_oracle() {
        let c = load();
        let room = hexd(c["rooms"]["room_id_hex"].as_str().unwrap());
        for oj in c["rooms"]["ops"].as_array().unwrap() {
            let op = RoomOp {
                room: room.clone(),
                op: oj["op"].as_u64().unwrap(),
                epoch: oj["epoch_at_build"].as_u64().unwrap(),
                subject: oj["subject"].as_str().unwrap().to_string(),
                role: oj["role"].as_u64().unwrap(),
            };
            assert_eq!(hex::encode(op.bytes()), oj["body_hex"].as_str().unwrap());
            assert_eq!(
                hex::encode(op.content_id()),
                oj["op_content_id_hex"].as_str().unwrap()
            );
        }
    }

    // Driving a real Room through the oracle's sequence reproduces the log chain (bodies+heads),
    // cursors, epoch progression, and final state (⟹ Go == Rust on the bytes).
    #[test]
    fn room_run_matches_oracle() {
        let c = load();
        let room = hexd(c["rooms"]["room_id_hex"].as_str().unwrap());
        let (auths, authv, _, _) = key(90);
        let ops = c["rooms"]["ops"].as_array().unwrap();
        let log = c["rooms"]["room_log"].as_array().unwrap();

        let create = &ops[0];
        let creator = create["subject"].as_str().unwrap().to_string();
        let cop = RoomOp {
            room: room.clone(),
            op: create["op"].as_u64().unwrap(),
            epoch: create["epoch_at_build"].as_u64().unwrap(),
            subject: creator.clone(),
            role: create["role"].as_u64().unwrap(),
        };
        let (mut rm, rec0, cursor0) =
            create_room(&cop, &creator, &auths, log[0]["at"].as_u64().unwrap()).unwrap();
        assert_eq!(cursor0, 0);
        assert_eq!(rm.epoch(), 1);
        check_receipt(&rec0, &log[0]);

        for i in 1..ops.len() {
            let oj = &ops[i];
            let op = RoomOp {
                room: room.clone(),
                op: oj["op"].as_u64().unwrap(),
                epoch: oj["epoch_at_build"].as_u64().unwrap(),
                subject: oj["subject"].as_str().unwrap().to_string(),
                role: oj["role"].as_u64().unwrap(),
            };
            assert_eq!(oj["epoch_at_build"].as_u64().unwrap(), rm.epoch());
            let (rec, cursor) = rm
                .apply(&op, &creator, &auths, log[i]["at"].as_u64().unwrap())
                .unwrap();
            assert_eq!(cursor, oj["seq"].as_u64().unwrap());
            assert_eq!(rm.epoch(), oj["epoch_after"].as_u64().unwrap());
            check_receipt(&rec, &log[i]);
        }

        assert_eq!(rm.epoch(), c["rooms"]["final_epoch"].as_u64().unwrap());
        let want_owners: Vec<String> = c["rooms"]["final_owners"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(rm.owners(), want_owners);
        for m in c["rooms"]["final_members"].as_array().unwrap() {
            let s = m["subject"].as_str().unwrap();
            assert_eq!(rm.role_of(s), Some(m["role"].as_u64().unwrap()));
        }
        // members() must equal the FULL membership set — no missing AND no extra members. The
        // per-subject role_of loop above can only prove no member is missing; it cannot catch an
        // extra one leaking in. Mutation: if members() aliased the internal map or leaked a
        // removed/stale subject, the length check or the per-subject check below would flip.
        let final_members = c["rooms"]["final_members"].as_array().unwrap();
        let got_members = rm.members();
        assert_eq!(
            got_members.len(),
            final_members.len(),
            "members() must have no extra members beyond the oracle's final set"
        );
        for m in final_members {
            let s = m["subject"].as_str().unwrap();
            assert_eq!(got_members.get(s).copied(), Some(m["role"].as_u64().unwrap()));
        }
        let (receipts, sigs) = rm.log();
        audit::verify_chain(receipts, sigs, &authv).expect("room log verifies");
        assert_eq!(
            hex::encode(receipts.last().unwrap().head()),
            c["rooms"]["final_log_head_hex"].as_str().unwrap()
        );
    }

    fn check_receipt(rec: &audit::Receipt, want: &J) {
        assert_eq!(hex::encode(rec.bytes()), want["body_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(rec.head()),
            want["head_after_hex"].as_str().unwrap()
        );
        assert_eq!(hex::encode(&rec.obj), want["obj_hex"].as_str().unwrap());
    }

    // A membership op is a first-class SIGNED object: verify through the spine (tier-1
    // Governance, real ML-DSA), the authenticated signer is the actor, and it is ordered.
    #[test]
    fn signed_membership_end_to_end() {
        let room = vec![0x20u8, 0x30, 1, 2, 3, 4];
        let (owner_s, owner_v, owner_pub, owner_id) = key(50);
        let (_, _, _, bob_id) = key(51);
        let (auths, _, _, _) = key(91);

        let create_op = RoomOp {
            room: room.clone(),
            op: OP_CREATE,
            epoch: 0,
            subject: owner_id.clone(),
            role: ROLE_OWNER,
        };
        let (mut rm, _, _) = create_room(&create_op, &owner_id, &auths, 1000).unwrap();

        let add = RoomOp {
            room: room.clone(),
            op: OP_ADD_MEMBER,
            epoch: rm.epoch(),
            subject: bob_id.clone(),
            role: ROLE_MEMBER,
        };
        let mut obj = add
            .envelope_object(
                owner_id.as_bytes(),
                1001,
                cose::PROFILE_PUBLIC as u64,
                vec![],
            )
            .unwrap();
        let signed = envelope::sign(&mut obj, &owner_s);
        rm.apply_signed(
            cose::PROFILE_PUBLIC,
            &owner_v,
            &owner_pub,
            &signed,
            &auths,
            1001,
        )
        .unwrap();
        assert_eq!(rm.role_of(&bob_id), Some(ROLE_MEMBER));

        // A baseline-only verifier rejects the tier-1 kind as UnknownKind.
        let baseline = |c: u64, k: u64| channels::kind_validator(c, k);
        match envelope::verify(cose::PROFILE_PUBLIC, &owner_v, &baseline, &[], &signed) {
            Err(e) => assert_eq!(e.kind, "UnknownKind"),
            Ok(_) => panic!("baseline verifier accepted a tier-1 room kind"),
        }
    }

    // EPOCH-BUMPING: two ops against the same epoch cannot both apply; the second is StaleEpoch.
    #[test]
    fn stale_epoch_rejected() {
        let room = vec![9u8, 9, 9];
        let (_, _, _, owner_id) = key(52);
        let (_, _, _, bob_id) = key(53);
        let (_, _, _, carol_id) = key(54);
        let (auths, _, _, _) = key(92);
        let create = RoomOp {
            room: room.clone(),
            op: OP_CREATE,
            epoch: 0,
            subject: owner_id.clone(),
            role: ROLE_OWNER,
        };
        let (mut rm, _, _) = create_room(&create, &owner_id, &auths, 1).unwrap();
        let e = rm.epoch();
        rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_ADD_MEMBER,
                epoch: e,
                subject: bob_id,
                role: ROLE_MEMBER,
            },
            &owner_id,
            &auths,
            2,
        )
        .unwrap();
        match rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_ADD_MEMBER,
                epoch: e,
                subject: carol_id.clone(),
                role: ROLE_MEMBER,
            },
            &owner_id,
            &auths,
            3,
        ) {
            Err(err) => assert_eq!(err.kind, "StaleEpoch"),
            Ok(_) => panic!("stale-epoch op accepted"),
        }
        assert_eq!(
            rm.role_of(&carol_id),
            None,
            "state changed on a rejected op"
        );
        // Rebuilt against the current epoch, it is accepted.
        rm.apply(
            &RoomOp {
                room,
                op: OP_ADD_MEMBER,
                epoch: rm.epoch(),
                subject: carol_id,
                role: ROLE_MEMBER,
            },
            &owner_id,
            &auths,
            4,
        )
        .unwrap();
    }

    // Only an owner may change membership (fail-closed); a non-owner is refused.
    #[test]
    fn unauthorized_actor_rejected() {
        let room = vec![7u8, 7];
        let (_, _, _, owner_id) = key(55);
        let (_, _, _, bob_id) = key(56);
        let (_, _, _, mallory_id) = key(57);
        let (auths, _, _, _) = key(93);
        let (mut rm, _, _) = create_room(
            &RoomOp {
                room: room.clone(),
                op: OP_CREATE,
                epoch: 0,
                subject: owner_id.clone(),
                role: ROLE_OWNER,
            },
            &owner_id,
            &auths,
            1,
        )
        .unwrap();
        rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_ADD_MEMBER,
                epoch: rm.epoch(),
                subject: bob_id.clone(),
                role: ROLE_MEMBER,
            },
            &owner_id,
            &auths,
            2,
        )
        .unwrap();
        match rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_ADD_OWNER,
                epoch: rm.epoch(),
                subject: mallory_id.clone(),
                role: ROLE_OWNER,
            },
            &mallory_id,
            &auths,
            3,
        ) {
            Err(e) => assert_eq!(e.kind, "Unauthorized"),
            Ok(_) => panic!("unauthorized actor accepted"),
        }
        // bob (a member, not an owner) also cannot change membership.
        assert!(rm
            .apply(
                &RoomOp {
                    room,
                    op: OP_ADD_MEMBER,
                    epoch: rm.epoch(),
                    subject: mallory_id,
                    role: ROLE_MEMBER
                },
                &bob_id,
                &auths,
                4
            )
            .is_err());
        assert_eq!(rm.owner_count(), 1);
    }

    // O2 ownership is add-only: owners grow, are never removed/demoted, count stays >= 1.
    #[test]
    fn add_only_ownership_no_ownerless() {
        let room = vec![5u8];
        let (_, _, _, alice_id) = key(58);
        let (_, _, _, bob_id) = key(59);
        let (auths, _, _, _) = key(94);
        let (mut rm, _, _) = create_room(
            &RoomOp {
                room: room.clone(),
                op: OP_CREATE,
                epoch: 0,
                subject: alice_id.clone(),
                role: ROLE_OWNER,
            },
            &alice_id,
            &auths,
            1,
        )
        .unwrap();
        assert_eq!(rm.owner_count(), 1);
        rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_ADD_OWNER,
                epoch: rm.epoch(),
                subject: bob_id.clone(),
                role: ROLE_OWNER,
            },
            &alice_id,
            &auths,
            2,
        )
        .unwrap();
        assert_eq!(rm.owner_count(), 2);
        assert!(rm.is_owner(&bob_id));
        match rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_REMOVE_MEMBER,
                epoch: rm.epoch(),
                subject: alice_id.clone(),
                role: ROLE_MEMBER,
            },
            &bob_id,
            &auths,
            3,
        ) {
            Err(e) => assert_eq!(e.kind, "OwnerImmutable"),
            Ok(_) => panic!("removed an owner"),
        }
        match rm.apply(
            &RoomOp {
                room: room.clone(),
                op: OP_CHANGE_ROLE,
                epoch: rm.epoch(),
                subject: alice_id,
                role: ROLE_MEMBER,
            },
            &bob_id,
            &auths,
            4,
        ) {
            Err(e) => assert_eq!(e.kind, "OwnerImmutable"),
            Ok(_) => panic!("demoted an owner"),
        }
        match rm.apply(
            &RoomOp {
                room,
                op: OP_ADD_OWNER,
                epoch: rm.epoch(),
                subject: bob_id,
                role: ROLE_OWNER,
            },
            &rm.owners()[0].clone(),
            &auths,
            5,
        ) {
            Err(e) => assert_eq!(e.kind, "OwnerExists"),
            Ok(_) => panic!("re-added an owner"),
        }
        assert!(rm.owner_count() >= 1);
    }

    // Principal-binding wire bodies + chain heads are byte-identical to the oracle.
    #[test]
    fn binding_bytes_match_oracle() {
        let c = load();
        for bj in c["registry"]["bindings"].as_array().unwrap() {
            let b = Binding {
                principal: bj["principal"].as_str().unwrap().to_string(),
                handle: bj["handle"].as_str().unwrap().to_string(),
                epoch: bj["epoch"].as_u64().unwrap(),
                prev: hexd(bj["prev_hex"].as_str().unwrap()),
            };
            assert_eq!(hex::encode(b.bytes()), bj["body_hex"].as_str().unwrap());
            assert_eq!(
                hex::encode(b.head()),
                bj["head_after_hex"].as_str().unwrap()
            );
        }
    }

    // Delivery Model B: a rebind is authorised only by a verified rotation; a hijack is refused.
    #[test]
    fn principal_registry_rebind_on_rotation() {
        let (v1s, v1v, v1p, v1id) = key(60);
        let (v2s, v2v, v2p, v2id) = key(61);
        let (_, _, _, evil_id) = key(62);
        let mut pr = PrincipalRegistry::new();
        pr.bind("agent:alice", &v1id).unwrap();
        assert_eq!(pr.resolve("agent:alice").unwrap(), v1id);

        let rot = identity::RotationRecord {
            old: v1id.clone(),
            new: v2id.clone(),
            not_before: 100,
        };
        let (osig, nsig) = identity::sign_rotation(&rot, &v1s, &v2s);
        pr.rebind(
            "agent:alice",
            &v2id,
            &rot,
            &v1v,
            &v2v,
            &v1p,
            &v2p,
            &osig,
            &nsig,
        )
        .unwrap();
        assert_eq!(
            pr.resolve("agent:alice").unwrap(),
            v2id,
            "durable Handle follows the rotation"
        );

        // Hijack: a rotation that does not name the current handle as `old` is refused.
        let bad = identity::RotationRecord {
            old: v2id.clone(),
            new: evil_id.clone(),
            not_before: 200,
        };
        let (bo, bn) = identity::sign_rotation(&bad, &v1s, &v2s); // signed by the wrong keys
        match pr.rebind(
            "agent:alice",
            &evil_id,
            &bad,
            &v1v,
            &v2v,
            &v1p,
            &v2p,
            &bo,
            &bn,
        ) {
            Err(e) => assert_eq!(e.kind, "RebindUnauthorized"),
            Ok(_) => panic!("hijack rebind accepted"),
        }
        assert_eq!(
            pr.resolve("agent:alice").unwrap(),
            v2id,
            "hijack must not change the binding"
        );
        match pr.resolve("agent:nobody") {
            Err(e) => assert_eq!(e.kind, "PrincipalUnknown"),
            Ok(_) => panic!("unknown principal resolved"),
        }
    }
}
