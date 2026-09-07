// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C15 — multi-hop AGENT delegation (design.md §18; requirements R-DEL-1..8), a Phase-3 draft-01
//! ADDITIVE tier-1 surface over the frozen spine (design.md §2..§10). It is the Rust half of the
//! two-implementation parity: every grant byte it produces matches the independent oracle
//! (tools/delegation_oracle.py) and every chain verdict matches the oracle's D3 model, so
//! Go == Rust == oracle.
//!
//! It introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): a
//! DelegationGrant is a normal N-AALP object (envelope §2) and the mechanism REUSES the -00
//! CapDelegate substrate — parent-by-content-id in `causes` (§8.2) and the `CapExceedsParent`
//! attenuation (§6.1 lattice) — rather than a parallel mechanism (D5). The only additions over
//! CapDelegate are the body's `subject`, `max_depth`, and validity window.
//!
//! Agent-delegation answers WHO may act on whose behalf, multi-hop, with a chain terminating at a
//! trust anchor — distinct from the -00 tier-0 CAPABILITY delegation (CapIssue/CapDelegate), which
//! answers WHAT a token may do in a single hop. Both share the one `CapExceedsParent` rule. Every
//! check is fail-closed (§15): an action failing any step is rejected whole, returns its named
//! error, and causes no state change.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha384};

use crate::approval;
use crate::cbor::{self, Value};
use crate::channels;
use crate::cose;
use crate::envelope;
use crate::identity;
use crate::policy;

/// Channel binding (R-1.2), the tier-1 kind code, and the tier for agent-delegation (design §18.1).
pub const CHANNEL_CAPABILITY: u64 = 0x0002;
pub const KIND_DELEGATION_GRANT: u64 = 4;
pub const TIER: u64 = 1;

/// The grant's OWN envelope effect (field 7): issuing a grant is a non_idempotent_write — separate
/// from the body's effect_cap, the ceiling it CONFERS on its subject (design §18.1).
pub const GRANT_EFFECT: u8 = policy::NON_IDEMPOTENT_WRITE;

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}
pub fn err_chain_broken() -> cose::Error {
    err(
        "ChainBroken",
        "a delegation-chain link is missing, ambiguous, or unverifiable",
    )
}
pub fn err_grant_expired() -> cose::Error {
    err(
        "GrantExpired",
        "grant is past its not_after at the action's ordering position",
    )
}
pub fn err_grant_not_yet_valid() -> cose::Error {
    err(
        "GrantNotYetValid",
        "grant is before its not_before at the action's ordering position",
    )
}
pub fn err_grant_revoked() -> cose::Error {
    err(
        "GrantRevoked",
        "grant is revoked at or before the action's ordering position",
    )
}
pub fn err_untrusted_chain_root() -> cose::Error {
    err(
        "UntrustedChainRoot",
        "the chain root's issuer is not in the trust-anchor set",
    )
}
pub fn err_delegation_depth_exceeded() -> cose::Error {
    err(
        "DelegationDepthExceeded",
        "declared or realized delegation depth exceeds max_depth",
    )
}
pub fn err_non_nfc() -> cose::Error {
    err("NonNFC", "subject/scope string is not Unicode NFC")
}
pub fn err_grant_malformed() -> cose::Error {
    err(
        "GrantMalformed",
        "delegation-grant body is not the {1..5,?6} shape or has an out-of-range field",
    )
}

// ---- the DelegationGrant object body (design.md §18.1, §18.5) --------------------------------

/// The signed body (envelope field 10) of a DelegationGrant. The ISSUER (agent A) is NOT a body
/// field — it is the verified envelope signer (R-DEL-3) — and the delegation PARENT is named by
/// content id in the envelope `causes` (§8.2), not here.
#[derive(Clone)]
pub struct Grant {
    pub subject: String, // delegatee agent id (agent B), signer-id form (§5.1); MUST be NFC
    pub effect_cap: u8,  // max effect conveyed (§6.1 lattice); child <= this else CapExceedsParent
    pub max_depth: u64,  // max FURTHER delegation hops below this grant (0 = act, not re-delegate)
    pub not_before: u64, // validity-window start, epoch ms (GrantNotYetValid before)
    pub not_after: u64,  // validity-window end, epoch ms (GrantExpired after)
    pub scope: String,   // OPTIONAL NFC resource scope; "" = absent (unconstrained)
}

impl Grant {
    fn to_map(&self) -> Value {
        let mut pairs = vec![
            (Value::Uint(1), Value::Tstr(self.subject.clone())),
            (Value::Uint(2), Value::Uint(self.effect_cap as u64)),
            (Value::Uint(3), Value::Uint(self.max_depth)),
            (Value::Uint(4), Value::Uint(self.not_before)),
            (Value::Uint(5), Value::Uint(self.not_after)),
        ];
        if !self.scope.is_empty() {
            // "" == absent (field 6 omitted); an empty scope is not a distinct value.
            pairs.push((Value::Uint(6), Value::Tstr(self.scope.clone())));
        }
        Value::Map(pairs)
    }

    /// Deterministic-CBOR encoding {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_map()).expect("encode delegation grant")
    }

    /// The grant body's content id (T1 framing, design §2.3): multihash(0x20, SHA-384(body)).
    pub fn content_id(&self) -> Vec<u8> {
        let mut out = vec![0x20u8, 0x30u8];
        out.extend_from_slice(&Sha384::digest(self.bytes()));
        out
    }

    /// Build the (unsigned) envelope object carrying this grant (tier 1, Capability channel, kind
    /// DelegationGrant, own effect non_idempotent_write, grant body as field 10, `causes` naming
    /// the parent). The signer BECOMES the issuer (R-DEL-3). Non-NFC subject/scope or an
    /// out-of-range effect_cap is rejected fail-closed.
    pub fn envelope_object(
        &self,
        issuer: &[u8],
        created: u64,
        profile: u64,
        causes: Vec<Vec<u8>>,
    ) -> Result<envelope::Object, cose::Error> {
        identity::require_nfc(&self.subject).map_err(|_| err_non_nfc())?;
        if !self.scope.is_empty() {
            identity::require_nfc(&self.scope).map_err(|_| err_non_nfc())?;
        }
        if self.effect_cap > policy::DESTRUCTIVE {
            return Err(err_grant_malformed());
        }
        Ok(envelope::Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind: KIND_DELEGATION_GRANT,
            channel: CHANNEL_CAPABILITY,
            tier: TIER,
            signer: issuer.to_vec(),
            created,
            effect: GRANT_EFFECT as u64,
            causes,
            profile,
            body: self.to_map(),
            ext: None,
            cext: None,
        })
    }
}

/// Parse an envelope object body (field 10) into a Grant. A body that is not exactly the
/// {1,2,3,4,5,?6} map with the right value types and an in-range effect_cap is an
/// unverifiable/malformed grant link -> ChainBroken (fail-closed, D3 step 3). An out-of-range
/// effect_cap is NEVER normalized up (that would widen a ceiling — fail-open); it is rejected.
pub fn grant_from_body(v: &Value) -> Result<Grant, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_chain_broken()),
    };
    let mut subject: Option<String> = None;
    let mut effect_cap: Option<u8> = None;
    let mut max_depth: Option<u64> = None;
    let mut not_before: Option<u64> = None;
    let mut not_after: Option<u64> = None;
    let mut scope: String = String::new();
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => *u,
            _ => return Err(err_chain_broken()),
        };
        match (key, val) {
            (1, Value::Tstr(s)) => subject = Some(s.clone()),
            (2, Value::Uint(u)) if *u <= policy::DESTRUCTIVE as u64 => effect_cap = Some(*u as u8),
            (3, Value::Uint(u)) => max_depth = Some(*u),
            (4, Value::Uint(u)) => not_before = Some(*u),
            (5, Value::Uint(u)) => not_after = Some(*u),
            (6, Value::Tstr(s)) => scope = s.clone(),
            _ => return Err(err_chain_broken()),
        }
    }
    match (subject, effect_cap, max_depth, not_before, not_after) {
        (Some(subject), Some(effect_cap), Some(max_depth), Some(not_before), Some(not_after)) => {
            Ok(Grant {
                subject,
                effect_cap,
                max_depth,
                not_before,
                not_after,
                scope,
            })
        }
        _ => Err(err_chain_broken()),
    }
}

// ---- kind validation -------------------------------------------------------------------------

/// Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant).
pub fn kind_validator(channel: u64, kind: u64) -> bool {
    channel == CHANNEL_CAPABILITY && kind == KIND_DELEGATION_GRANT
}

/// Accepts the frozen baseline kinds OR the tier-1 DelegationGrant; a baseline-only verifier using
/// channels::kind_validator alone rejects a DelegationGrant as UnknownKind (fail-closed).
pub fn composed_kind_validator(channel: u64, kind: u64) -> bool {
    channels::kind_validator(channel, kind) || kind_validator(channel, kind)
}

// ---- verified grants + trust/revocation inputs -----------------------------------------------

/// A DelegationGrant that has passed envelope verification and integrity binding (D3 step 3).
#[derive(Clone)]
pub struct Resolved {
    pub content_id: Vec<u8>, // the grant's envelope content id (§2.3)
    pub issuer: String,      // the verified envelope signer id (the grant's issuer)
    pub grant: Grant,        // the parsed grant body
    pub causes: Vec<Vec<u8>>,
}

/// Verify one signed grant object end-to-end with real crypto (D3 step 3): envelope.verify against
/// the composed validator, confirm it is a tier-1 Capability DelegationGrant whose own effect is
/// non_idempotent_write, bind the claimed issuer id to the verifying key (R-DEL-3/R-5.1), and parse
/// the body. Any failure is an unverifiable link, fail-closed.
pub fn verify_grant_object(
    profile: u32,
    v: &dyn cose::CoseVerifier,
    pubkey: &[u8],
    signed_obj: &[u8],
) -> Result<Resolved, cose::Error> {
    let o = envelope::verify(
        profile,
        v,
        &|c, k| composed_kind_validator(c, k),
        &[],
        signed_obj,
    )?;
    if o.channel != CHANNEL_CAPABILITY || o.kind != KIND_DELEGATION_GRANT || o.tier != TIER {
        return Err(err_chain_broken());
    }
    if o.effect != GRANT_EFFECT as u64 {
        return Err(err_chain_broken());
    }
    let issuer = identity::signer_id(v.alg(), pubkey)?;
    if o.signer != issuer.as_bytes() {
        return Err(err(
            "SignerMismatch",
            "signer id does not equal the recomputed id",
        ));
    }
    let g = grant_from_body(&o.body)?;
    Ok(Resolved {
        content_id: o.id.clone(),
        issuer,
        grant: g,
        causes: o.causes.clone(),
    })
}

/// Verified grants keyed by envelope content id.
pub type GrantSet = HashMap<Vec<u8>, Resolved>;

/// Build a GrantSet from verified grants, keyed by envelope content id.
pub fn new_grant_set(grants: Vec<Resolved>) -> GrantSet {
    let mut s = GrantSet::new();
    for g in grants {
        s.insert(g.content_id.clone(), g);
    }
    s
}

/// Whether the grant named by `cid` is revoked as of `now`: a CapRevoke naming it is ordered at or
/// before `now` (design §18.2 step 5). `revoked` maps a grant's envelope content id -> revoke pos.
pub fn revoked_at(revoked: &HashMap<Vec<u8>, u64>, cid: &[u8], now: u64) -> bool {
    matches!(revoked.get(cid), Some(&p) if p <= now)
}

/// The verified action whose delegated authority is checked (D3 step 1 — the action's own signature
/// — is graded by the caller verifying it).
#[derive(Clone)]
pub struct Action {
    pub signer: String, // agent B — the verified signer of the action object (R-DEL-2)
    pub effect: u8,     // the action's own effect (the leaf childEffect)
    pub scope: String,  // the action's resource scope ("" = unconstrained; the leaf childScope)
    pub causes: Vec<Vec<u8>>, // the action's envelope causes (to locate the unique leaf grant)
}

// ---- D2 scope containment (design.md §18.1) --------------------------------------------------

/// Whether `child` is contained in `parent` under the D2 path-prefix rule: an absent parent scope
/// ("") is unconstrained (any child, incl. "", is contained); otherwise the child must equal the
/// parent or begin with parent + "/". A missing child scope ("") under a scoped parent WIDENS
/// authority and is NOT contained.
pub fn scope_contained(child: &str, parent: &str) -> bool {
    if parent.is_empty() {
        return true;
    }
    if child.is_empty() {
        return false;
    }
    if child == parent {
        return true;
    }
    child.starts_with(&format!("{parent}/"))
}

/// The distinct verified grants named in `causes` whose subject equals `subject` (the parent/leaf
/// resolution predicate). Duplicate content ids are counted once.
fn matching_causes<'a>(
    causes: &[Vec<u8>],
    subject: &str,
    grants: &'a GrantSet,
) -> Vec<&'a Resolved> {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut out = Vec::new();
    for c in causes {
        if seen.contains(c.as_slice()) {
            continue;
        }
        if let Some(r) = grants.get(c) {
            if r.grant.subject == subject {
                seen.insert(c.as_slice());
                out.push(r);
            }
        }
    }
    out
}

// ---- D3 chain verification (design.md §18.2) -------------------------------------------------

/// Run the 12-step leaf->root delegation-chain walk (design §18.2), fail-closed with no partial
/// credit. `now` is the action's authoritative ordering position (§8.1), never the signer's clock.
/// Returns Ok(()) iff the chain terminates at a trusted root with every hop holding; otherwise the
/// specific named error and no authorization.
pub fn verify_chain(
    action: &Action,
    grants: &GrantSet,
    anchors: &HashSet<String>,
    revoked: &HashMap<Vec<u8>, u64>,
    now: u64,
) -> Result<(), cose::Error> {
    // step 2 — locate the unique leaf grant among the action's causes whose subject == B.
    let leaves = matching_causes(&action.causes, &action.signer, grants);
    let mut g = match leaves.len() {
        0 => return Err(policy::err_effect_not_authorized()), // no delegation authorizes this action
        1 => leaves[0],
        _ => return Err(err_chain_broken()), // more than one authorizing grant
    };
    let mut child_effect = action.effect;
    let mut child_scope = action.scope.clone();
    let mut pos: u64 = 0; // realized delegation hops beneath the current grant
    let mut visited: HashSet<Vec<u8>> = HashSet::new();

    loop {
        if !visited.insert(g.content_id.clone()) {
            return Err(err_chain_broken()); // a content-id cycle (infeasible for a real hash chain)
        }
        // step 4 — validity window at `now`.
        if now < g.grant.not_before {
            return Err(err_grant_not_yet_valid());
        }
        if now > g.grant.not_after {
            return Err(err_grant_expired());
        }
        // step 5 — revocation at `now`.
        if revoked_at(revoked, &g.content_id, now) {
            return Err(err_grant_revoked());
        }
        // step 6 — attenuation (the existing CapExceedsParent): effect ceiling AND scope containment.
        if !policy::authorizes(g.grant.effect_cap, child_effect) {
            return Err(channels::err_cap_exceeds_parent());
        }
        if !scope_contained(&child_scope, &g.grant.scope) {
            return Err(channels::err_cap_exceeds_parent());
        }
        // step 9 — realized-depth bound: `pos` grants sit beneath g, so pos must not exceed max_depth.
        if pos > g.grant.max_depth {
            return Err(err_delegation_depth_exceeded());
        }
        // step 7 — resolve g's delegation parent (the unique cause whose subject == g's issuer).
        let parents = matching_causes(&g.causes, &g.issuer, grants);
        if parents.len() > 1 {
            return Err(err_chain_broken()); // ambiguous parent
        }
        if parents.is_empty() {
            // steps 10 / 11 — root test: g has no delegation parent.
            if anchors.contains(&g.issuer) {
                return Ok(()); // terminated at a trusted root (steps 10, 12): authorized
            }
            return Err(err_untrusted_chain_root());
        }
        let p = parents[0];
        // step 8 — declared depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned
        // underflow; a parent with max_depth 0 admits no child grant).
        if p.grant.max_depth == 0 || g.grant.max_depth >= p.grant.max_depth {
            return Err(err_delegation_depth_exceeded());
        }
        child_effect = g.grant.effect_cap;
        child_scope = g.grant.scope.clone();
        g = p;
        pos += 1;
    }
}

// ---- D4 composition with per-action approval (design.md §18.3, R-DEL-8) -----------------------

/// Enforce the D4 two-gate composition: a destructive-effect action requires BOTH a valid
/// delegation chain (Gate 1, D3) whose leaf effect_cap admits the action's effect, AND a valid,
/// unconsumed, exact-bytes §7 approval over `args_content_id` whose granted effect covers the
/// action's effect, CONSUMED by the acting agent B (the ledger entry's `by` is `action.signer`), so
/// accountability binds to B. Required for `destructive`; MAY be used as a stricter policy for a
/// lower effect.
///
/// Precedence (design §18.3): the chain is checked first, so a broken chain denies with its D3
/// error even when an approval is present; a valid chain with no valid approval denies
/// ApprovalRequired (the §7.3 held outcome). The approval is CONSUMED (the single state change)
/// only when both gates hold; a rejected action makes no ledger append. A valid-but-already-consumed
/// approval denies AlreadyConsumed.
#[allow(clippy::too_many_arguments)]
pub fn authorize_destructive(
    action: &Action,
    grants: &GrantSet,
    anchors: &HashSet<String>,
    revoked: &HashMap<Vec<u8>, u64>,
    now: u64,
    appr: &approval::ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    appr_sig: &[u8],
    args_content_id: &[u8],
    ledger: &approval::Ledger,
) -> Result<(), cose::Error> {
    // Gate 1 — the delegation chain (D3). A broken chain denies with its named D3 error.
    verify_chain(action, grants, anchors, revoked, now)?;
    // Gate 2 — a valid, unconsumed, exact-bytes approval over the action's args, consumed by B.
    if approval::verify_approval(appr, approver_v, appr_sig, args_content_id, now).is_err() {
        return Err(approval::err_approval_required()); // no valid approval (held §7.3)
    }
    if !policy::authorizes(appr.grant as u8, action.effect) {
        return Err(approval::err_approval_required()); // granted effect does not cover the action
    }
    match ledger.consume(&appr.id(), &action.signer) {
        Ok(_) => Ok(()),
        Err(approval::LedgerError::Cose(c)) => Err(c), // AlreadyConsumed — fail-closed, no double-spend
        Err(approval::LedgerError::Io(_)) => Err(err("LedgerIo", "consume ledger write failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::SerDes;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/delegation/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    struct Ak {
        signer: cose::MlDsa65Signer,
        verifier: cose::MlDsa65Verifier,
        pubk: Vec<u8>,
        id: String,
    }
    fn mk_key(seed: u8) -> Ak {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        let pubk = pk.clone().into_bytes().to_vec();
        let id = identity::signer_id(cose::ALG_MLDSA65, &pubk).unwrap();
        Ak {
            signer: cose::MlDsa65Signer(sk),
            verifier: cose::MlDsa65Verifier(pk),
            pubk,
            id,
        }
    }

    fn content_id_of(b: &[u8]) -> Vec<u8> {
        let mut out = vec![0x20u8, 0x30u8];
        out.extend_from_slice(&Sha384::digest(b));
        out
    }

    // ---- byte + scope grading (Rust == oracle == Go) -------------------------------------

    // Every DelegationGrant body + content id is byte-identical to the independent oracle
    // (⟹ Go == Rust). Mutation: a constant/field-ignoring encoder or a wrong scope-omission
    // diverges from the pinned hex.
    #[test]
    fn grant_bytes_match_oracle() {
        let c = load();
        let grants = c["grants"].as_array().unwrap();
        assert!(!grants.is_empty(), "no grant byte vectors");
        for gj in grants {
            let g = Grant {
                subject: gj["subject"].as_str().unwrap().to_string(),
                effect_cap: gj["effect_cap"].as_u64().unwrap() as u8,
                max_depth: gj["max_depth"].as_u64().unwrap(),
                not_before: gj["not_before"].as_u64().unwrap(),
                not_after: gj["not_after"].as_u64().unwrap(),
                scope: gj["scope"].as_str().unwrap().to_string(),
            };
            assert_eq!(
                hex::encode(g.bytes()),
                gj["body_hex"].as_str().unwrap(),
                "grant {} body",
                gj["name"]
            );
            assert_eq!(
                hex::encode(g.content_id()),
                gj["content_id_hex"].as_str().unwrap(),
                "grant {} content-id",
                gj["name"]
            );
        }
    }

    // The D2 path-prefix containment rule matches the independent truth table (allows and denies).
    #[test]
    fn scope_containment_matches_oracle() {
        let c = load();
        let rows = c["scope_containment"].as_array().unwrap();
        assert!(!rows.is_empty(), "no scope-containment rows");
        for r in rows {
            let child = r["child"].as_str().unwrap();
            let parent = r["parent"].as_str().unwrap();
            let want = r["contained"].as_bool().unwrap();
            assert_eq!(
                scope_contained(child, parent),
                want,
                "ScopeContained({child:?}, {parent:?})"
            );
        }
    }

    // ---- chain-verdict grading over REAL signed chains (Rust == oracle == Go) -------------

    fn assign_keys(sc: &J) -> HashMap<String, Ak> {
        let mut m: HashMap<String, Ak> = HashMap::new();
        let mut seed: u8 = 100;
        let assign = |label: &str, m: &mut HashMap<String, Ak>, seed: &mut u8| {
            if !m.contains_key(label) {
                m.insert(label.to_string(), mk_key(*seed));
                *seed += 1;
            }
        };
        for g in sc["grants"].as_array().unwrap() {
            assign(g["issuer"].as_str().unwrap(), &mut m, &mut seed);
            assign(g["subject"].as_str().unwrap(), &mut m, &mut seed);
        }
        assign(sc["action"]["signer"].as_str().unwrap(), &mut m, &mut seed);
        for a in sc["anchors"].as_array().unwrap() {
            assign(a.as_str().unwrap(), &mut m, &mut seed);
        }
        m
    }

    fn build_action(signer: &Ak, effect: u64, scope: &str, causes: Vec<Vec<u8>>) -> Action {
        let mut obj = envelope::Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind: 2,
            channel: 0x0001,
            tier: 0,
            signer: signer.id.as_bytes().to_vec(),
            created: 1,
            effect,
            causes,
            profile: cose::PROFILE_PUBLIC as u64,
            body: Value::Tstr("action".into()),
            ext: None,
            cext: None,
        };
        let signed = envelope::sign(&mut obj, &signer.signer);
        let o = envelope::verify(
            cose::PROFILE_PUBLIC,
            &signer.verifier,
            &|c, k| composed_kind_validator(c, k),
            &[],
            &signed,
        )
        .expect("action verify (R-DEL-2, D3 step 1)");
        assert_eq!(
            o.signer,
            signer.id.as_bytes(),
            "action signer != authenticated id"
        );
        Action {
            signer: String::from_utf8(o.signer).unwrap(),
            effect: o.effect as u8,
            scope: scope.to_string(),
            causes: o.causes,
        }
    }

    fn assert_verdict(name: &str, res: Result<(), cose::Error>, expect: &str) {
        if expect == "authorized" {
            assert!(res.is_ok(), "{name}: want authorized, got {:?}", res.err());
        } else {
            match res {
                Err(e) => assert_eq!(e.kind, expect, "{name}: wrong error kind"),
                Ok(()) => panic!("{name}: want {expect}, got authorized"),
            }
        }
    }

    // Drive every oracle scenario as a REAL ML-DSA-65 signed grant chain and assert the verifier's
    // verdict equals the oracle's. Both authorized and every named deny are present, so a
    // constant-Ok verifier fails the denies and a constant-Err fails the allows (mutation-surviving).
    #[test]
    fn chain_scenarios_match_oracle() {
        let c = load();
        let scenarios = c["scenarios"].as_array().unwrap();
        assert!(!scenarios.is_empty(), "no scenarios");
        for sc in scenarios {
            let name = sc["name"].as_str().unwrap();
            let keys = assign_keys(sc);
            let mut set = GrantSet::new();
            let mut grant_cid: Vec<Vec<u8>> = Vec::new();
            for gj in sc["grants"].as_array().unwrap() {
                let ik = &keys[gj["issuer"].as_str().unwrap()];
                let sk = &keys[gj["subject"].as_str().unwrap()];
                let g = Grant {
                    subject: sk.id.clone(),
                    effect_cap: gj["effect_cap"].as_u64().unwrap() as u8,
                    max_depth: gj["max_depth"].as_u64().unwrap(),
                    not_before: gj["not_before"].as_u64().unwrap(),
                    not_after: gj["not_after"].as_u64().unwrap(),
                    scope: gj["scope"].as_str().unwrap().to_string(),
                };
                let causes: Vec<Vec<u8>> = gj["causes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|ci| grant_cid[ci.as_u64().unwrap() as usize].clone())
                    .collect();
                let mut obj = g
                    .envelope_object(ik.id.as_bytes(), 1, cose::PROFILE_PUBLIC as u64, causes)
                    .expect("grant build");
                let signed = envelope::sign(&mut obj, &ik.signer);
                let res =
                    verify_grant_object(cose::PROFILE_PUBLIC, &ik.verifier, &ik.pubk, &signed)
                        .expect("grant verify (D3 step 3)");
                grant_cid.push(res.content_id.clone());
                set.insert(res.content_id.clone(), res);
            }

            let action_signer = &keys[sc["action"]["signer"].as_str().unwrap()];
            let acauses: Vec<Vec<u8>> = sc["action"]["causes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|ci| grant_cid[ci.as_u64().unwrap() as usize].clone())
                .collect();
            let action = build_action(
                action_signer,
                sc["action"]["effect"].as_u64().unwrap(),
                sc["action"]["scope"].as_str().unwrap(),
                acauses,
            );

            let mut anchors: HashSet<String> = HashSet::new();
            for a in sc["anchors"].as_array().unwrap() {
                anchors.insert(keys[a.as_str().unwrap()].id.clone());
            }
            let mut revoked: HashMap<Vec<u8>, u64> = HashMap::new();
            for r in sc["revoked"].as_array().unwrap() {
                revoked.insert(
                    grant_cid[r["grant"].as_u64().unwrap() as usize].clone(),
                    r["pos"].as_u64().unwrap(),
                );
            }

            let res = verify_chain(
                &action,
                &set,
                &anchors,
                &revoked,
                sc["now"].as_u64().unwrap(),
            );
            assert_verdict(name, res, sc["expect"].as_str().unwrap());
        }
    }

    // ---- dedicated behavioural deny paths (real crypto) ----------------------------------

    struct BuiltChain {
        set: GrantSet,
        anchors: HashSet<String>,
        action: Action,
        leaf_signed: Vec<u8>,
        leaf_key: Ak, // M (the leaf grant's issuer)
    }

    fn build_valid_2hop(effect: u8) -> BuiltChain {
        let a = mk_key(10);
        let m = mk_key(11);
        let b = mk_key(12);
        let root_g = Grant {
            subject: m.id.clone(),
            effect_cap: policy::DESTRUCTIVE,
            max_depth: 2,
            not_before: 0,
            not_after: 1_000_000,
            scope: String::new(),
        };
        let mut root_obj = root_g
            .envelope_object(a.id.as_bytes(), 1, cose::PROFILE_PUBLIC as u64, vec![])
            .unwrap();
        let root_signed = envelope::sign(&mut root_obj, &a.signer);
        let root_res =
            verify_grant_object(cose::PROFILE_PUBLIC, &a.verifier, &a.pubk, &root_signed)
                .expect("root verify");
        let leaf_g = Grant {
            subject: b.id.clone(),
            effect_cap: policy::DESTRUCTIVE,
            max_depth: 1,
            not_before: 0,
            not_after: 1_000_000,
            scope: String::new(),
        };
        let mut leaf_obj = leaf_g
            .envelope_object(
                m.id.as_bytes(),
                1,
                cose::PROFILE_PUBLIC as u64,
                vec![root_res.content_id.clone()],
            )
            .unwrap();
        let leaf_signed = envelope::sign(&mut leaf_obj, &m.signer);
        let leaf_res =
            verify_grant_object(cose::PROFILE_PUBLIC, &m.verifier, &m.pubk, &leaf_signed)
                .expect("leaf verify");
        let mut anchors = HashSet::new();
        anchors.insert(a.id.clone());
        let action = build_action(&b, effect as u64, "", vec![leaf_res.content_id.clone()]);
        let set = new_grant_set(vec![root_res, leaf_res]);
        BuiltChain {
            set,
            anchors,
            action,
            leaf_signed,
            leaf_key: m,
        }
    }

    // Happy path with real crypto (independent of the vector loop).
    #[test]
    fn valid_2hop_authorized() {
        let bc = build_valid_2hop(policy::NON_IDEMPOTENT_WRITE);
        verify_chain(&bc.action, &bc.set, &bc.anchors, &HashMap::new(), 500)
            .expect("valid chain denied");
    }

    // A tampered grant signature is an unverifiable link (D3 step 3) -> BadSignature.
    #[test]
    fn tampered_grant_signature_rejected() {
        let bc = build_valid_2hop(policy::NON_IDEMPOTENT_WRITE);
        let mut tampered = bc.leaf_signed.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        match verify_grant_object(
            cose::PROFILE_PUBLIC,
            &bc.leaf_key.verifier,
            &bc.leaf_key.pubk,
            &tampered,
        ) {
            Err(e) => assert_eq!(e.kind, "BadSignature"),
            Ok(_) => panic!("tampered grant signature accepted"),
        }
    }

    // A grant claiming an issuer id not derived from the signing key -> SignerMismatch (R-DEL-3).
    #[test]
    fn forged_issuer_rejected() {
        let real_key = mk_key(20);
        let victim = mk_key(21);
        let subject = mk_key(22);
        let g = Grant {
            subject: subject.id,
            effect_cap: policy::NON_IDEMPOTENT_WRITE,
            max_depth: 1,
            not_before: 0,
            not_after: 1_000_000,
            scope: String::new(),
        };
        let mut obj = g
            .envelope_object(victim.id.as_bytes(), 1, cose::PROFILE_PUBLIC as u64, vec![])
            .unwrap();
        let signed = envelope::sign(&mut obj, &real_key.signer);
        match verify_grant_object(
            cose::PROFILE_PUBLIC,
            &real_key.verifier,
            &real_key.pubk,
            &signed,
        ) {
            Err(e) => assert_eq!(e.kind, "SignerMismatch"),
            Ok(_) => panic!("forged issuer accepted"),
        }
    }

    // A baseline verifier (no tier licensed) rejects the tier-1 DelegationGrant kind as UnknownKind.
    #[test]
    fn baseline_verifier_rejects_grant_kind() {
        let issuer = mk_key(30);
        let subject = mk_key(31);
        let g = Grant {
            subject: subject.id,
            effect_cap: policy::NON_IDEMPOTENT_WRITE,
            max_depth: 1,
            not_before: 0,
            not_after: 1_000_000,
            scope: String::new(),
        };
        let mut obj = g
            .envelope_object(issuer.id.as_bytes(), 1, cose::PROFILE_PUBLIC as u64, vec![])
            .unwrap();
        let signed = envelope::sign(&mut obj, &issuer.signer);
        let baseline = |c: u64, k: u64| channels::kind_validator(c, k);
        match envelope::verify(
            cose::PROFILE_PUBLIC,
            &issuer.verifier,
            &baseline,
            &[],
            &signed,
        ) {
            Err(e) => assert_eq!(e.kind, "UnknownKind"),
            Ok(_) => panic!("baseline verifier accepted a tier-1 DelegationGrant"),
        }
    }

    // A non-NFC subject is rejected at build (fail-closed).
    #[test]
    fn non_nfc_subject_rejected() {
        let issuer = mk_key(40);
        let non_nfc = "e\u{0301}"; // 'e' + combining acute (NFD, not NFC)
        let g = Grant {
            subject: non_nfc.to_string(),
            effect_cap: policy::READ_ONLY,
            max_depth: 0,
            not_before: 0,
            not_after: 1,
            scope: String::new(),
        };
        match g.envelope_object(issuer.id.as_bytes(), 1, cose::PROFILE_PUBLIC as u64, vec![]) {
            Err(e) => assert_eq!(e.kind, "NonNFC"),
            Ok(_) => panic!("non-NFC subject accepted"),
        }
    }

    // ---- D4 composition with per-action approval (R-DEL-8) -------------------------------

    struct DestructiveSetup {
        bc: BuiltChain,
        ledger: approval::Ledger,
        appr: approval::ApprovalRecord,
        approver_v: cose::MlDsa65Verifier,
        appr_sig: Vec<u8>,
        args_cid: Vec<u8>,
    }

    fn setup_destructive() -> DestructiveSetup {
        let bc = build_valid_2hop(policy::DESTRUCTIVE);
        let dir = std::env::temp_dir().join(format!("naalp-deleg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("consume-{}.log", rand_suffix()));
        let ledger = approval::open_ledger(&path).expect("open ledger");
        let approver = mk_key(50);
        let args_cid = content_id_of(b"the exact canonical action args");
        let appr = approval::ApprovalRecord {
            approves: args_cid.clone(),
            approver: approver.id.clone(),
            grant: policy::DESTRUCTIVE as u64,
            nonce: vec![1, 2, 3, 4],
            not_after: 1_000_000,
            audience: String::new(),
        };
        let appr_sig = approval::sign_approval(&appr, &approver.signer);
        DestructiveSetup {
            bc,
            ledger,
            appr,
            approver_v: approver.verifier,
            appr_sig,
            args_cid,
        }
    }

    // A per-test unique suffix so the WAL-backed ledger files never collide.
    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    // Both a valid chain and a valid approval -> authorized, and the approval is consumed once by B.
    #[test]
    fn composition_both_gates_authorize_and_consume() {
        let s = setup_destructive();
        authorize_destructive(
            &s.bc.action,
            &s.bc.set,
            &s.bc.anchors,
            &HashMap::new(),
            500,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &s.args_cid,
            &s.ledger,
        )
        .expect("both gates valid but denied");
        assert!(
            s.ledger.is_consumed(&s.appr.id()),
            "approval not consumed after authorization"
        );
    }

    // A valid chain but no matching approval -> ApprovalRequired, no ledger append (fail-closed).
    #[test]
    fn composition_chain_without_approval() {
        let s = setup_destructive();
        let other = content_id_of(b"some other args the approval does not bind");
        match authorize_destructive(
            &s.bc.action,
            &s.bc.set,
            &s.bc.anchors,
            &HashMap::new(),
            500,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &other,
            &s.ledger,
        ) {
            Err(e) => assert_eq!(e.kind, "ApprovalRequired"),
            Ok(()) => panic!("destructive action authorized with no matching approval"),
        }
        assert_eq!(s.ledger.len(), 0, "ledger appended on a rejected action");
    }

    // A valid approval but a broken chain -> the D3 error (chain checked first), no ledger append.
    #[test]
    fn composition_approval_with_broken_chain() {
        let s = setup_destructive();
        let no_anchors: HashSet<String> = HashSet::new();
        match authorize_destructive(
            &s.bc.action,
            &s.bc.set,
            &no_anchors,
            &HashMap::new(),
            500,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &s.args_cid,
            &s.ledger,
        ) {
            Err(e) => assert_eq!(e.kind, "UntrustedChainRoot"),
            Ok(()) => panic!("destructive action authorized on a broken chain"),
        }
        assert_eq!(
            s.ledger.len(),
            0,
            "ledger appended when the chain gate failed"
        );
    }

    // A single-use approval: a second destructive action consuming it -> AlreadyConsumed.
    #[test]
    fn composition_approval_replay_rejected() {
        let s = setup_destructive();
        authorize_destructive(
            &s.bc.action,
            &s.bc.set,
            &s.bc.anchors,
            &HashMap::new(),
            500,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &s.args_cid,
            &s.ledger,
        )
        .expect("first authorization denied");
        match authorize_destructive(
            &s.bc.action,
            &s.bc.set,
            &s.bc.anchors,
            &HashMap::new(),
            500,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &s.args_cid,
            &s.ledger,
        ) {
            Err(e) => assert_eq!(e.kind, "AlreadyConsumed"),
            Ok(()) => panic!("approval replayed on a second destructive action"),
        }
    }
}
