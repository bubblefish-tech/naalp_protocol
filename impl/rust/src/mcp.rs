// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! NAALP-MCP binding profile (design.md §19; Companion-Spec Program Requirement 6.1) — a draft-01 ADDITIVE tier-1 surface
//! over the frozen spine. It is the Rust half of the two-implementation parity: every wrapper byte,
//! annotation->effect mapping, more-severe resolution, and call-binding content id it produces
//! matches the independent oracle (tools/mcp_oracle.py, vectors/mcp/cases.json), so
//! Go == Rust == oracle.
//!
//! It introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): an MCP
//! tool call is a normal N-AALP object (envelope §2) on the Bridge channel, and it REUSES the closed
//! effect lattice (policy), the approval + single-use consume ledger (approval), and the T1 content-id
//! framing (§2.3) unchanged.
//!
//! What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that
//! a tool's annotations are unenforced hints a malicious server can lie about — "clients MUST consider
//! tool annotations to be untrusted unless they come from trusted servers". This profile turns that
//! anonymous, untrusted hint into a SIGNED effect claim by a named key:
//!
//!   - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are
//!     carried OCTET-FOR-OCTET (never re-serialized, canonicalized, or rewritten). A foreign identity
//!     inside them never becomes an N-AALP authorization identity — the wrapping signer is the
//!     authority (R-14.6).
//!   - PUBLISHED MAPPING TABLE. The tool's annotations are mapped to the closed four-effect lattice
//!     (read_only < idempotent_write < non_idempotent_write < destructive) by
//!     [`map_annotations_to_effect`], the table in vectors/registry/mcp.csv. Because the N-AALP spine
//!     carries no CBOR boolean (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT
//!     hint takes its MCP default. destructiveHint's default of TRUE is why an un-annotated write maps
//!     to destructive — the same fail-closed rule as "absent effect on a state-changing object =>
//!     destructive" (§6.1).
//!   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
//!     DECLARED effect, under the signer's ML-DSA signature. A verifier independently recomputes the
//!     annotation-derived effect and enforces the MORE SEVERE of the two ([`resolve_enforced_effect`]
//!     — the good-regulator attenuator: a disagreeing input collapses UP, never down). A signer that
//!     DECLARES BELOW its own carried annotations is rejected fail-closed (EffectUnderDeclared); an
//!     annotation set that maps outside the lattice is rejected (MalformedAnnotation), never defaulted
//!     to benign.
//!   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
//!     (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
//!     invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
//!
//! Every check is fail-closed (§15): an object failing any check is rejected whole, returns its named
//! error, and causes no state change.

use sha2::{Digest, Sha384};

use crate::approval;
use crate::cbor::{self, Value};
use crate::channels;
use crate::cose;
use crate::envelope;
use crate::policy;

/// Channel binding, the tier-1 kind code, and the tier for the MCP wrapper (design.md §6.1 / the
/// NAALP-MCP component). `KIND_MCP_TOOL_CALL` is kind 1 on the Bridge channel — a named escalation
/// over the frozen baseline Carriage kind (0), which stays untouched (R-15A.2).
pub const CHANNEL_BRIDGE: u64 = 0x000D; // Bridge channel (foreign carriage lives here)
pub const KIND_MCP_TOOL_CALL: u64 = 1; // tier-1 kind code (baseline Carriage is kind 0)
pub const TIER: u64 = 1; // a named escalation adding the governed MCP wrapper (R-15A.2)

/// Annotation CBOR keys inside a naalp-mcp-annotations map. These transcribe the MCP ToolAnnotations
/// field names; the value is the uint 1 (true) / 0 (false) — the N-AALP spine carries no CBOR boolean
/// (design §3.1).
pub const KEY_READ_ONLY: u64 = 1; // MCP readOnlyHint
pub const KEY_DESTRUCTIVE: u64 = 2; // MCP destructiveHint
pub const KEY_IDEMPOTENT: u64 = 3; // MCP idempotentHint
pub const KEY_OPEN_WORLD: u64 = 4; // MCP openWorldHint (ADVISORY — not an effect determinant)

/// The MCP documented defaults for an ABSENT hint (see tools/mcp_oracle.py mcp_annotation_contract).
/// destructiveHint defaults to TRUE, so an un-annotated write maps to destructive — the fail-closed
/// default.
pub const DEFAULT_READ_ONLY: bool = false; // readOnlyHint default false
pub const DEFAULT_DESTRUCTIVE: bool = true; // destructiveHint default true
pub const DEFAULT_IDEMPOTENT: bool = false; // idempotentHint default false

fn err(kind: &'static str, msg: &'static str) -> cose::Error {
    cose::Error { kind, msg }
}

/// An annotation hint value outside {0,1}, an annotation key outside the closed mapping, or a
/// non-map annotation set — it maps outside the lattice and is rejected, never defaulted to benign.
pub fn err_malformed_annotation() -> cose::Error {
    err(
        "MalformedAnnotation",
        "an annotation hint value is outside {0,1}, an annotation key is outside the closed mapping, or the annotation set is not a map — it maps outside the lattice and is rejected, never defaulted to benign",
    )
}

/// The wrapper's declared envelope effect is below the effect its own carried annotations map to; the
/// more-severe resolution requires declared >= annotation-mapped.
pub fn err_effect_under_declared() -> cose::Error {
    err(
        "EffectUnderDeclared",
        "the wrapper's declared envelope effect is below the effect its own carried annotations map to; the more-severe resolution requires declared >= annotation-mapped",
    )
}

/// A declared effect class outside the closed four-effect lattice is rejected, not defaulted to benign.
pub fn err_effect_outside_lattice() -> cose::Error {
    err(
        "EffectOutsideLattice",
        "a declared effect class outside the closed four-effect lattice is rejected, not defaulted to benign",
    )
}

/// The tool-call body is not {1:tool bstr, 2:args bstr, 3:annotations map} or the object is not a
/// tier-1 Bridge McpToolCall.
pub fn err_tool_call_malformed() -> cose::Error {
    err(
        "ToolCallMalformed",
        "mcp tool-call body is not {1:tool bstr, 2:args bstr, 3:annotations map} or the object is not a tier-1 Bridge McpToolCall",
    )
}

/// The T1 content-id framing over arbitrary bytes: multihash(0x20, SHA-384(b)). The 50-byte id is
/// `0x20 0x30 || digest` (design §2.3), identical to the spine's framing.
fn content_id(b: &[u8]) -> Vec<u8> {
    let mut out = vec![0x20u8, 0x30u8];
    out.extend_from_slice(&Sha384::digest(b));
    out
}

fn b2u(b: bool) -> u64 {
    if b {
        1
    } else {
        0
    }
}

// ---- the transcribed MCP annotation set (naalp-mcp-annotations) ------------------------------

/// The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL: `None`
/// means the hint was absent (the MCP default applies in the mapping), so an absent hint and a present
/// false are distinct on the wire though they may resolve to the same effect. `open_world` is carried
/// for accountability but never enters the effect mapping (design §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Annotations {
    pub read_only: Option<bool>,   // MCP readOnlyHint
    pub destructive: Option<bool>, // MCP destructiveHint
    pub idempotent: Option<bool>,  // MCP idempotentHint
    pub open_world: Option<bool>,  // MCP openWorldHint (advisory only)
}

impl Annotations {
    /// Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1. Keys are
    /// pushed in ascending order and the deterministic encoder sorts them (RFC 8949 §4.2.1).
    fn to_value(&self) -> Value {
        let mut pairs: Vec<(Value, Value)> = Vec::new();
        if let Some(v) = self.read_only {
            pairs.push((Value::Uint(KEY_READ_ONLY), Value::Uint(b2u(v))));
        }
        if let Some(v) = self.destructive {
            pairs.push((Value::Uint(KEY_DESTRUCTIVE), Value::Uint(b2u(v))));
        }
        if let Some(v) = self.idempotent {
            pairs.push((Value::Uint(KEY_IDEMPOTENT), Value::Uint(b2u(v))));
        }
        if let Some(v) = self.open_world {
            pairs.push((Value::Uint(KEY_OPEN_WORLD), Value::Uint(b2u(v))));
        }
        Value::Map(pairs)
    }

    /// Deterministic-CBOR bytes of the annotation map (keys sorted by the encoder).
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("encode annotations")
    }
}

/// Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a
/// non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a duplicate
/// key, or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map outside the
/// closed lattice, so it is rejected, never defaulted to benign (Requirement 6.1 / AC-6.1.2).
pub fn annotations_from_value(v: &Value) -> Result<Annotations, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_malformed_annotation()),
    };
    let mut a = Annotations::default();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => *u,
            _ => return Err(err_malformed_annotation()),
        };
        let u = match val {
            Value::Uint(u) => *u,
            _ => return Err(err_malformed_annotation()),
        };
        if u > 1 {
            // a hint value outside {0,1} maps outside the lattice
            return Err(err_malformed_annotation());
        }
        if !seen.insert(key) {
            return Err(err_malformed_annotation());
        }
        let val_b = u == 1;
        match key {
            KEY_READ_ONLY => a.read_only = Some(val_b),
            KEY_DESTRUCTIVE => a.destructive = Some(val_b),
            KEY_IDEMPOTENT => a.idempotent = Some(val_b),
            KEY_OPEN_WORLD => a.open_world = Some(val_b),
            _ => return Err(err_malformed_annotation()), // key outside the closed mapping
        }
    }
    Ok(a)
}

// ---- the published annotation -> effect mapping table (design §6.1) --------------------------

/// Map a tool's transcribed annotations to the closed four-effect lattice by the published table
/// (vectors/registry/mcp.csv), applying the MCP default for each absent hint:
///
/// - readOnlyHint true                                 -> read_only            (does not modify env)
/// - readOnlyHint false, destructiveHint true          -> destructive          (may destroy)
/// - readOnlyHint false, destructiveHint false, idem T -> idempotent_write     (additive, repeatable)
/// - readOnlyHint false, destructiveHint false, idem F -> non_idempotent_write (additive)
///
/// An absent readOnlyHint defaults to false (a write, never read_only); an absent destructiveHint
/// defaults to true (destructive) — so a tool with no annotations at all maps to destructive, the
/// fail-closed collapse to the most-severe. openWorldHint is never consulted (design §5). The result
/// is always in the closed lattice for a well-formed [`Annotations`] (malformed sets are rejected at
/// [`annotations_from_value`]), so this function does not fail.
pub fn map_annotations_to_effect(a: &Annotations) -> u8 {
    let ro = a.read_only.unwrap_or(DEFAULT_READ_ONLY);
    let de = a.destructive.unwrap_or(DEFAULT_DESTRUCTIVE);
    let idem = a.idempotent.unwrap_or(DEFAULT_IDEMPOTENT);
    if ro {
        return policy::READ_ONLY;
    }
    if de {
        return policy::DESTRUCTIVE;
    }
    if idem {
        return policy::IDEMPOTENT_WRITE;
    }
    policy::NON_IDEMPOTENT_WRITE
}

/// The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect and
/// the wrapping signer's declared effect, returns `Ok((enforced, mismatch))` where `enforced` is the
/// MORE SEVERE and `mismatch` is true iff the two disagreed (a mismatch attributable to the wrapping
/// signer). A declared value outside the closed lattice is EffectOutsideLattice; a declared value BELOW
/// the annotation-derived effect is EffectUnderDeclared (a wrapper's declared effect can never sit
/// under the effect its own carried annotations map to). On success the enforced effect equals the
/// declared effect (which is therefore >= the annotation-derived effect), so a downstream C5
/// authorization reading envelope field 7 sees the correct, most-severe value.
pub fn resolve_enforced_effect(
    annotation_mapped: u8,
    declared: u8,
) -> Result<(u8, bool), cose::Error> {
    if declared > policy::DESTRUCTIVE {
        return Err(err_effect_outside_lattice());
    }
    if declared < annotation_mapped {
        return Err(err_effect_under_declared());
    }
    // declared >= annotation_mapped: the enforced effect is the more severe, which is `declared`.
    Ok((declared, declared != annotation_mapped))
}

// ---- the wrapper body (naalp-mcp-tool-call) --------------------------------------------------

/// The wrapper body (envelope field 10). `tool` and `args` are the foreign MCP bytes, carried
/// octet-for-octet (carriage, not adoption); `annotations` is the wrapping signer's transcription of
/// the tool's hints, on which the mapping operates. The wrapper's OWN effect is the envelope field 7,
/// not a body field.
#[derive(Clone, Debug)]
pub struct ToolCall {
    pub tool: Vec<u8>,
    pub args: Vec<u8>,
    pub annotations: Annotations,
}

impl ToolCall {
    fn to_map(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.tool.clone())),
            (Value::Uint(2), Value::Bstr(self.args.clone())),
            (Value::Uint(3), self.annotations.to_value()),
        ])
    }

    /// Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_map()).expect("encode tool call")
    }

    /// The tool-call body's content id (T1 framing): multihash(0x20, SHA-384(body)).
    pub fn content_id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }

    /// The (tool_id, args_id) binding whose content id an approval binds for this call
    /// (Requirement 6.1). Computed from the carried tool and args bytes.
    pub fn call_binding(&self) -> CallBinding {
        CallBinding::new(&self.tool, &self.args)
    }

    /// Build the (unsigned) N-AALP envelope object that carries this tool call: tier 1, Bridge channel,
    /// kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as field
    /// 10, and `causes` (may be empty). The caller signs it with [`envelope::sign`]; the signer BECOMES
    /// accountable for the declared effect and the annotation transcription. A declared effect outside
    /// the closed lattice is rejected fail-closed. Under-declaration (declared below the
    /// annotation-derived effect) is NOT rejected here — it is a signed, attributable claim whose
    /// inconsistency [`verify_tool_call`] surfaces as EffectUnderDeclared at the enforcement point.
    pub fn envelope_object(
        &self,
        signer: &[u8],
        created: u64,
        profile: u64,
        declared: u8,
        causes: Vec<Vec<u8>>,
    ) -> Result<envelope::Object, cose::Error> {
        if declared > policy::DESTRUCTIVE {
            return Err(err_effect_outside_lattice());
        }
        Ok(envelope::Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind: KIND_MCP_TOOL_CALL,
            channel: CHANNEL_BRIDGE,
            tier: TIER,
            signer: signer.to_vec(),
            created,
            effect: declared as u64,
            causes,
            profile,
            body: self.to_map(),
            ext: None,
            cext: None,
        })
    }
}

/// Parse an envelope object body (field 10) into a [`ToolCall`]. A body that is not exactly
/// {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a
/// malformed annotation set is MalformedAnnotation. Fail-closed.
pub fn tool_call_from_body(v: &Value) -> Result<ToolCall, cose::Error> {
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(err_tool_call_malformed()),
    };
    let mut tool: Vec<u8> = Vec::new();
    let mut args: Vec<u8> = Vec::new();
    let mut annotations = Annotations::default();
    let (mut have_tool, mut have_args, mut have_ann) = (false, false, false);
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => *u,
            _ => return Err(err_tool_call_malformed()),
        };
        match key {
            1 => match val {
                Value::Bstr(b) => {
                    tool = b.clone();
                    have_tool = true;
                }
                _ => return Err(err_tool_call_malformed()),
            },
            2 => match val {
                Value::Bstr(b) => {
                    args = b.clone();
                    have_args = true;
                }
                _ => return Err(err_tool_call_malformed()),
            },
            3 => {
                annotations = annotations_from_value(val)?; // MalformedAnnotation
                have_ann = true;
            }
            _ => return Err(err_tool_call_malformed()),
        }
    }
    if have_tool && have_args && have_ann {
        Ok(ToolCall {
            tool,
            args,
            annotations,
        })
    } else {
        Err(err_tool_call_malformed())
    }
}

// ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

/// Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content id.
/// The approval binds the content id of THIS binding, so a changed tool description (new `tool_id`) OR
/// changed arguments (new `args_id`) yields a new call content id and invalidates a prior approval
/// bound to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
#[derive(Clone, Debug)]
pub struct CallBinding {
    pub tool_id: Vec<u8>, // multihash(0x20, SHA-384(tool bytes))
    pub args_id: Vec<u8>, // multihash(0x20, SHA-384(args bytes))
}

impl CallBinding {
    /// Compute the binding from the raw tool and args bytes.
    pub fn new(tool: &[u8], args: &[u8]) -> CallBinding {
        CallBinding {
            tool_id: content_id(tool),
            args_id: content_id(args),
        }
    }

    fn to_map(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Bstr(self.tool_id.clone())),
            (Value::Uint(2), Value::Bstr(self.args_id.clone())),
        ])
    }

    /// Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.
    pub fn bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_map()).expect("encode call binding")
    }

    /// The call content id an approval binds: multihash(0x20, SHA-384(binding)).
    pub fn content_id(&self) -> Vec<u8> {
        content_id(&self.bytes())
    }
}

// ---- kind validation (composes with the frozen baseline) -------------------------------------

/// Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).
pub fn kind_validator(channel: u64, kind: u64) -> bool {
    channel == CHANNEL_BRIDGE && kind == KIND_MCP_TOOL_CALL
}

/// Accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator an MCP-aware endpoint
/// passes to [`envelope::verify`]. A baseline-only endpoint using [`channels::kind_validator`] alone
/// correctly rejects an McpToolCall as UnknownKind (fail-closed).
pub fn composed_kind_validator(channel: u64, kind: u64) -> bool {
    channels::kind_validator(channel, kind) || kind_validator(channel, kind)
}

// ---- verified tool call --------------------------------------------------------------------

/// An MCP tool call that has passed envelope verification and the effect resolution. It carries the
/// enforced effect (the more-severe value C5 authorizes on), whether the annotation and the declared
/// effect disagreed (`mismatch` — attributable to `signer`), and the parsed tool call.
#[derive(Clone, Debug)]
pub struct Resolved {
    pub content_id: Vec<u8>,
    pub signer: Vec<u8>,
    pub tool_call: ToolCall,
    pub annotation_mapped: u8, // the effect the published table derives from the annotations
    pub declared: u8,          // the wrapping signer's declared envelope effect (field 7)
    pub enforced: u8,          // the enforced effect: max(annotation_mapped, declared) == declared
    pub mismatch: bool,        // annotation_mapped != declared (attributable to signer)
}

/// Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the signed
/// object with real crypto ([`envelope::verify`] against the composed validator — content id, ranges,
/// header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge McpToolCall; (3) parses
/// the tool-call body (rejecting a malformed annotation set); (4) recomputes the annotation-derived
/// effect from the CARRIED annotations, independent of the declared effect; (5) resolves the enforced
/// effect to the MORE SEVERE, rejecting under-declaration. The enforced effect equals the declared
/// envelope effect on success, so the object's field 7 is the correct C5 authorization input. Any
/// failure returns its named error and authorizes nothing (fail-closed).
pub fn verify_tool_call(
    profile: u32,
    v: &dyn cose::CoseVerifier,
    signed_obj: &[u8],
) -> Result<Resolved, cose::Error> {
    let o = envelope::verify(
        profile,
        v,
        &|c, k| composed_kind_validator(c, k),
        &[],
        signed_obj,
    )?;
    if o.channel != CHANNEL_BRIDGE || o.kind != KIND_MCP_TOOL_CALL || o.tier != TIER {
        return Err(err_tool_call_malformed());
    }
    let tc = tool_call_from_body(&o.body)?;
    let mapped = map_annotations_to_effect(&tc.annotations);
    let declared = o.effect as u8; // envelope::verify already range-checked field 7 to 0..3
    let (enforced, mismatch) = resolve_enforced_effect(mapped, declared)?;
    Ok(Resolved {
        content_id: o.id.clone(),
        signer: o.signer.clone(),
        tool_call: tc,
        annotation_mapped: mapped,
        declared,
        enforced,
        mismatch,
    })
}

// ---- the per-call approval gate (reuses §7 approval + consume ledger) ------------------------

/// Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
/// EXACT call binding content id (tool_id + args_id) — so it satisfies neither a call with different
/// arguments nor a call whose tool description changed (Requirement 6.1) — its granted effect must
/// cover the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it is consumed
/// single-use by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: a
/// non-matching or under-granting approval denies ApprovalRequired with no ledger append; an
/// already-spent approval denies AlreadyConsumed; the consume (the single state change) happens only
/// when every check holds.
#[allow(clippy::too_many_arguments)]
pub fn authorize_call(
    r: &Resolved,
    appr: &approval::ApprovalRecord,
    approver_v: &dyn cose::CoseVerifier,
    appr_sig: &[u8],
    by: &str,
    now: u64,
    ledger: &approval::Ledger,
) -> Result<(), cose::Error> {
    let call_cid = r.tool_call.call_binding().content_id();
    match approval::verify_approval(appr, approver_v, appr_sig, &call_cid, now) {
        Ok(()) => {}
        Err(e) => {
            // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
            if e.kind == "ApprovalMismatch" {
                return Err(approval::err_approval_required());
            }
            return Err(e);
        }
    }
    if !policy::authorizes(appr.grant as u8, r.enforced) {
        return Err(approval::err_approval_required()); // the approval's granted effect does not cover the call
    }
    match ledger.consume(&appr.id(), by) {
        Ok(_) => Ok(()),
        Err(approval::LedgerError::Cose(c)) => Err(c), // AlreadyConsumed — fail-closed, no double-spend
        Err(approval::LedgerError::Io(_)) => Err(err("LedgerIo", "consume ledger write failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/mcp/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    fn must_hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    // Build an Annotations from a corpus `hints` object mapping "1".."4" -> 0/1 (an absent key => None).
    fn build_annotations(h: &J) -> Annotations {
        let get = |k: &str| -> Option<bool> { h.get(k).and_then(|v| v.as_i64()).map(|v| v == 1) };
        Annotations {
            read_only: get("1"),
            destructive: get("2"),
            idempotent: get("3"),
            open_world: get("4"),
        }
    }

    // Turn a mapping-table cell ("true"/"false"/"any") into an optional hint.
    fn mapping_cell(s: &str) -> Option<bool> {
        match s {
            "true" => Some(true),
            "false" => Some(false),
            _ => None, // "any": the hint is not consulted for this row
        }
    }

    // ---- key material ------------------------------------------------------------------------

    struct Ak {
        signer: cose::MlDsa65Signer,
        verifier: cose::MlDsa65Verifier,
        id: String,
    }

    fn mk_key(seed: u8) -> Ak {
        use fips204::traits::SerDes;
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[seed; 32]);
        let pubk = pk.clone().into_bytes().to_vec();
        let id = identity::signer_id(cose::ALG_MLDSA65, &pubk).expect("signer id");
        Ak {
            signer: cose::MlDsa65Signer(sk),
            verifier: cose::MlDsa65Verifier(pk),
            id,
        }
    }

    // Build, sign, and return the wire bytes of a wrapper carrying `tc` with the wrapping signer's
    // declared envelope effect.
    fn sign_wrapper(tc: &ToolCall, k: &Ak, declared: u8) -> Vec<u8> {
        let mut obj = tc
            .envelope_object(
                k.id.as_bytes(),
                1,
                cose::PROFILE_PUBLIC as u64,
                declared,
                vec![],
            )
            .expect("build wrapper");
        envelope::sign(&mut obj, &k.signer)
    }

    fn new_ledger(tag: &str) -> approval::Ledger {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "naalp_mcp_{}_{}_{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_file(&p);
        approval::open_ledger(&p).expect("open ledger")
    }

    // ---- byte + mapping + resolution grading (Go == oracle == Rust) --------------------------

    // Every transcribed annotation set encodes byte-identical to the independent oracle, AND
    // map_annotations_to_effect reproduces the oracle's mapped effect. The vector set contains all four
    // effect outcomes, so a constant/field-ignoring mapper diverges (mutation-surviving).
    #[test]
    fn annotation_bytes_and_mapping_match_oracle() {
        let c = load();
        let anns = c["annotations"].as_array().unwrap();
        assert!(!anns.is_empty(), "no annotation vectors");
        for av in anns {
            let name = av["name"].as_str().unwrap();
            let a = build_annotations(&av["hints"]);
            assert_eq!(
                hex::encode(a.encode()),
                av["annotations_hex"].as_str().unwrap(),
                "annotation {name} bytes"
            );
            assert_eq!(
                map_annotations_to_effect(&a) as u64,
                av["mapped_effect"].as_u64().unwrap(),
                "annotation {name} effect"
            );
        }
    }

    // Grade the published mapping table directly: building the minimal annotation set for each canonical
    // row reproduces the row's effect. Both allows and all four outcomes appear.
    #[test]
    fn mapping_table_matches_oracle() {
        let c = load();
        let table = c["mapping_table"].as_array().unwrap();
        assert_eq!(
            table.len(),
            4,
            "mapping table has {} rows, want 4",
            table.len()
        );
        for r in table {
            let a = Annotations {
                read_only: mapping_cell(r["read_only_hint"].as_str().unwrap()),
                destructive: mapping_cell(r["destructive_hint"].as_str().unwrap()),
                idempotent: mapping_cell(r["idempotent_hint"].as_str().unwrap()),
                open_world: None,
            };
            assert_eq!(
                map_annotations_to_effect(&a) as u64,
                r["effect_value"].as_u64().unwrap(),
                "mapping row ro={} de={} idem={}",
                r["read_only_hint"].as_str().unwrap(),
                r["destructive_hint"].as_str().unwrap(),
                r["idempotent_hint"].as_str().unwrap()
            );
        }
    }

    // Every annotation set the oracle marks as mapping OUTSIDE the lattice is rejected
    // MalformedAnnotation — never defaulted to benign (Requirement 6.1 / AC-6.1.2). Mutation: a parser
    // that returned (Annotations::default(), Ok) — defaulting to benign — would fail here, because
    // map_annotations_to_effect of the default Annotations is destructive, not the rejection the vector
    // demands.
    #[test]
    fn malformed_annotations_rejected() {
        let c = load();
        let mvs = c["malformed_annotations"].as_array().unwrap();
        assert!(!mvs.is_empty(), "no malformed-annotation vectors");
        for mv in mvs {
            let name = mv["name"].as_str().unwrap();
            let raw = must_hex(mv["annotations_hex"].as_str().unwrap());
            // The malformed set must be structurally valid CBOR (the rejection is a profile rule, not a
            // codec rule).
            let v = cbor::decode(&raw).unwrap_or_else(|e| panic!("{name}: {:?}", e));
            match annotations_from_value(&v) {
                Ok(_) => panic!(
                    "{name}: malformed annotation set accepted (should be {})",
                    mv["expect"].as_str().unwrap()
                ),
                Err(e) => assert_eq!(e.kind, mv["expect"].as_str().unwrap(), "{name}"),
            }
        }
    }

    // Every wrapper body, its content id, its tool/args content ids, its call binding, and the call
    // content id are byte-identical to the oracle (⟹ Go == Rust on the wire). This is the byte-parity
    // proof: Rust == oracle, and since Go == oracle (auditor-validated), Go == Rust.
    #[test]
    fn tool_call_bytes_match_oracle() {
        let c = load();
        let tcs = c["tool_calls"].as_array().unwrap();
        assert!(!tcs.is_empty(), "no tool-call vectors");
        for tv in tcs {
            let name = tv["name"].as_str().unwrap();
            let tc = ToolCall {
                tool: must_hex(tv["tool_hex"].as_str().unwrap()),
                args: must_hex(tv["args_hex"].as_str().unwrap()),
                annotations: build_annotations(&tv["hints"]),
            };
            assert_eq!(
                hex::encode(tc.bytes()),
                tv["body_hex"].as_str().unwrap(),
                "{name} body"
            );
            assert_eq!(
                hex::encode(tc.content_id()),
                tv["content_id_hex"].as_str().unwrap(),
                "{name} content-id"
            );
            let cb = tc.call_binding();
            assert_eq!(
                hex::encode(&cb.tool_id),
                tv["tool_id_hex"].as_str().unwrap(),
                "{name} tool-id"
            );
            assert_eq!(
                hex::encode(&cb.args_id),
                tv["args_id_hex"].as_str().unwrap(),
                "{name} args-id"
            );
            assert_eq!(
                hex::encode(cb.bytes()),
                tv["call_binding_hex"].as_str().unwrap(),
                "{name} call-binding"
            );
            assert_eq!(
                hex::encode(cb.content_id()),
                tv["call_content_id_hex"].as_str().unwrap(),
                "{name} call-content-id"
            );
            assert_eq!(
                map_annotations_to_effect(&tc.annotations) as u64,
                tv["annotation_mapped_effect"].as_u64().unwrap(),
                "{name} annotation-mapped effect"
            );
        }
    }

    // Grade the more-severe resolution against the independent model: the enforced effect, the mismatch
    // flag, and the reject verdicts (EffectUnderDeclared) all match. Both accept and reject verdicts
    // appear, so a constant resolver fails.
    #[test]
    fn resolution_matches_oracle() {
        let c = load();
        let rvs = c["resolution"].as_array().unwrap();
        assert!(!rvs.is_empty(), "no resolution vectors");
        for rv in rvs {
            let name = rv["name"].as_str().unwrap();
            let mapped = rv["annotation_mapped"].as_u64().unwrap() as u8;
            let declared = rv["declared"].as_u64().unwrap() as u8;
            let verdict = rv["verdict"].as_str().unwrap();
            match resolve_enforced_effect(mapped, declared) {
                Ok((enforced, mismatch)) => {
                    assert_eq!(verdict, "accept", "{name}: want accept, got Ok");
                    assert_eq!(
                        enforced as u64,
                        rv["enforced"].as_u64().unwrap(),
                        "{name}: enforced"
                    );
                    assert_eq!(
                        mismatch,
                        rv["mismatch"].as_bool().unwrap(),
                        "{name}: mismatch"
                    );
                }
                Err(e) => {
                    assert_ne!(verdict, "accept", "{name}: want {verdict}, got Err");
                    assert_eq!(e.kind, verdict, "{name}");
                }
            }
        }
    }

    // The call binding content ids are byte-identical to the oracle, and the changed-args and
    // changed-tool-description calls produce DIFFERENT call content ids from the base (the property the
    // approval binding relies on).
    #[test]
    fn approval_binding_content_ids_match_oracle() {
        let c = load();
        let avs = c["approval_binding"].as_array().unwrap();
        assert!(
            avs.len() >= 3,
            "want >= 3 approval-binding vectors, got {}",
            avs.len()
        );
        let mut base_id = String::new();
        for av in avs {
            let name = av["name"].as_str().unwrap();
            let cb = CallBinding::new(
                &must_hex(av["tool_hex"].as_str().unwrap()),
                &must_hex(av["args_hex"].as_str().unwrap()),
            );
            let got = hex::encode(cb.content_id());
            assert_eq!(
                got,
                av["call_content_id_hex"].as_str().unwrap(),
                "{name} call-content-id"
            );
            if name == "base_T_A" {
                base_id = got;
            } else if !base_id.is_empty() {
                assert_ne!(
                    av["call_content_id_hex"].as_str().unwrap(),
                    base_id,
                    "{name}: perturbed call has the same content id as the base — the binding does not cover the change"
                );
            }
        }
    }

    // ---- (a) the lying tool: enforced as destructive, attributable to the wrapping signer -----

    // Checkpoint demo (a): a tool whose annotation SELF-DECLARES readOnlyHint=true (so the published
    // table derives read_only) but whose wrapping signer, accountable, declares the envelope effect
    // destructive. verify_tool_call enforces the MORE SEVERE (destructive), flags the mismatch, and
    // attributes it to the wrapping signer's key. This is the test the primary mutation (making
    // resolve_enforced_effect trust the annotation over the declared effect) flips pass->fail.
    #[test]
    fn lying_tool_enforced_as_destructive() {
        let k = mk_key(10);
        // The MCP tool lies: it claims read_only while its name says otherwise. The bytes are carried
        // verbatim; the annotation is transcribed faithfully (readOnlyHint=true).
        let tool = br#"{"name":"delete_everything","annotations":{"readOnlyHint":true}}"#.to_vec();
        let args = br#"{"confirm":true}"#.to_vec();
        let tc = ToolCall {
            tool,
            args,
            annotations: Annotations {
                read_only: Some(true),
                ..Default::default()
            },
        };
        let signed = sign_wrapper(&tc, &k, policy::DESTRUCTIVE); // the signer declares destructive

        let r = verify_tool_call(cose::PROFILE_PUBLIC, &k.verifier, &signed)
            .expect("verify lying-tool wrapper");
        assert_eq!(
            r.annotation_mapped,
            policy::READ_ONLY,
            "annotation-mapped effect: want read_only(0)"
        );
        assert_eq!(
            r.enforced,
            policy::DESTRUCTIVE,
            "enforced effect: want destructive(3) — the more-severe resolution failed"
        );
        assert!(
            r.mismatch,
            "mismatch not flagged: read_only annotation disagreed with destructive declared"
        );
        // The lie is attributable to the WRAPPING SIGNER's key — never to any foreign name in the tool
        // bytes (a foreign identity never becomes an N-AALP authorization identity).
        assert_eq!(
            r.signer,
            k.id.as_bytes(),
            "wrapper signer must be the wrapping signer id"
        );
    }

    // The mutation the checkpoint names, at the authorization boundary: an executor that "trusts the
    // annotation over the mapping" would authorize on r.annotation_mapped (read_only) instead of
    // r.enforced (destructive). Against an endpoint that grants only read_only, the correct enforcement
    // DENIES the destructive call while the mutation WRONGLY ALLOWS it — so the lying-tool case flips
    // pass->fail under the mutation.
    #[test]
    fn lying_tool_mutation_trust_annotation_flips() {
        let k = mk_key(11);
        let tool = br#"{"name":"wipe_disk","annotations":{"readOnlyHint":true}}"#.to_vec();
        let tc = ToolCall {
            tool,
            args: b"{}".to_vec(),
            annotations: Annotations {
                read_only: Some(true),
                ..Default::default()
            },
        };
        let r = verify_tool_call(
            cose::PROFILE_PUBLIC,
            &k.verifier,
            &sign_wrapper(&tc, &k, policy::DESTRUCTIVE),
        )
        .expect("verify");
        // An endpoint that grants this signer only read_only authority.
        let grant = policy::Grant {
            principal: k.id.clone(),
            max_effect: policy::READ_ONLY,
        };
        // CORRECT: authorize on the enforced (more-severe) effect -> the destructive call is DENIED.
        assert!(
            grant
                .authorize_object(policy::PrincipalSource::Signature, &k.id, r.enforced as u64)
                .is_err(),
            "enforced destructive was authorized under a read_only grant — fail-open"
        );
        // MUTATION: authorize on the annotation-derived effect (trust the tool's hint) -> WRONGLY ALLOWED.
        grant
            .authorize_object(
                policy::PrincipalSource::Signature,
                &k.id,
                r.annotation_mapped as u64,
            )
            .expect("sanity: the annotation-mapped read_only should pass a read_only grant");
        // The two outcomes differ, which is exactly why the mutation flips the safety result.
        assert_ne!(
            r.enforced, r.annotation_mapped,
            "enforced == annotation-mapped: the mutation would be indistinguishable (the case is not discriminating)"
        );
    }

    // The reverse lie. A tool whose annotations map to destructive (destructiveHint=true) whose
    // wrapping signer under-declares the envelope effect as read_only is rejected EffectUnderDeclared —
    // the signer cannot drag the enforced effect below the tool's own annotations. Mutation: a resolver
    // that took min() (or the declared value) would accept this.
    #[test]
    fn lying_signer_under_declared_rejected() {
        let k = mk_key(12);
        let tool = br#"{"name":"delete_file","annotations":{"readOnlyHint":false,"destructiveHint":true}}"#.to_vec();
        let tc = ToolCall {
            tool,
            args: br#"{"path":"x"}"#.to_vec(),
            annotations: Annotations {
                read_only: Some(false),
                destructive: Some(true),
                ..Default::default()
            },
        };
        let signed = sign_wrapper(&tc, &k, policy::READ_ONLY); // signer under-declares
        match verify_tool_call(cose::PROFILE_PUBLIC, &k.verifier, &signed) {
            Ok(_) => panic!("under-declared wrapper accepted"),
            Err(e) => assert_eq!(e.kind, "EffectUnderDeclared"),
        }
    }

    // ---- (b) an approval bound to args A does not satisfy a call with args B -----------------

    struct ApprovedCall {
        appr: approval::ApprovalRecord,
        approver_v: cose::MlDsa65Verifier,
        appr_sig: Vec<u8>,
        wrapper_key: Ak,
        r_a: Resolved,
        tool_t: Vec<u8>,
        args_a: Vec<u8>,
    }

    // Build a signed destructive transfer wrapper for (tool_T, args_A), an approver, and an approval
    // binding the call binding of (tool_T, args_A).
    fn setup_approved_call(seed: u8) -> ApprovedCall {
        let wrapper_key = mk_key(seed);
        let approver = mk_key(seed + 1);
        let tool_t =
            br#"{"name":"transfer","annotations":{"readOnlyHint":false,"destructiveHint":true}}"#
                .to_vec();
        let args_a = br#"{"to":"acct-1","amount":100}"#.to_vec();
        let tc_a = ToolCall {
            tool: tool_t.clone(),
            args: args_a.clone(),
            annotations: Annotations {
                read_only: Some(false),
                destructive: Some(true),
                ..Default::default()
            },
        };
        let r_a = verify_tool_call(
            cose::PROFILE_PUBLIC,
            &wrapper_key.verifier,
            &sign_wrapper(&tc_a, &wrapper_key, policy::DESTRUCTIVE),
        )
        .expect("verify A");
        let call_cid = CallBinding::new(&tool_t, &args_a).content_id();
        let appr = approval::ApprovalRecord {
            approves: call_cid,
            approver: approver.id.clone(),
            grant: policy::DESTRUCTIVE as u64,
            nonce: vec![1, 2, 3, 4],
            not_after: 1_000_000,
            audience: String::new(),
        };
        let appr_sig = approval::sign_approval(&appr, &approver.signer);
        ApprovedCall {
            appr,
            approver_v: approver.verifier,
            appr_sig,
            wrapper_key,
            r_a,
            tool_t,
            args_a,
        }
    }

    // The positive: the approval for (tool_T, args_A) authorizes the exact call and consumes the
    // approval once.
    #[test]
    fn approval_bound_to_args_a_authorizes_a() {
        let s = setup_approved_call(20);
        let ledger = new_ledger("authA");
        authorize_call(
            &s.r_a,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &s.wrapper_key.id,
            500,
            &ledger,
        )
        .expect("exact call denied");
        assert!(
            ledger.is_consumed(&s.appr.id()),
            "approval not consumed after authorization"
        );
    }

    // Checkpoint demo (b): the SAME approval (bound to args_A) does NOT satisfy a call with args_B —
    // different arguments yield a different call content id (ApprovalRequired), and nothing is consumed
    // (fail-closed).
    #[test]
    fn approval_bound_to_args_a_rejected_for_args_b() {
        let s = setup_approved_call(22);
        let args_b = br#"{"to":"acct-2","amount":100}"#.to_vec(); // a DIFFERENT recipient
        let tc_b = ToolCall {
            tool: s.tool_t.clone(),
            args: args_b,
            annotations: Annotations {
                read_only: Some(false),
                destructive: Some(true),
                ..Default::default()
            },
        };
        let r_b = verify_tool_call(
            cose::PROFILE_PUBLIC,
            &s.wrapper_key.verifier,
            &sign_wrapper(&tc_b, &s.wrapper_key, policy::DESTRUCTIVE),
        )
        .expect("verify B");
        let ledger = new_ledger("rejB");
        match authorize_call(
            &r_b,
            &s.appr,
            &s.approver_v,
            &s.appr_sig,
            &s.wrapper_key.id,
            500,
            &ledger,
        ) {
            Ok(()) => panic!("approval bound to args A satisfied a call with args B"),
            Err(e) => assert_eq!(e.kind, "ApprovalRequired"),
        }
        assert_eq!(
            ledger.len(),
            0,
            "ledger appended on a rejected (mismatched-args) call"
        );
    }

    // Checkpoint demo (c): a changed tool DESCRIPTION (same arguments) yields a new tool content id,
    // hence a new call content id, so a prior approval bound to the old tool description no longer
    // satisfies the call (ApprovalRequired).
    #[test]
    fn changed_tool_description_invalidates_approval() {
        let s = setup_approved_call(24);
        // Same tool name and annotations, but a changed DESCRIPTION -> different bytes -> different tool id.
        let tool_t2 =
            br#"{"name":"transfer","description":"now moves funds to any account","annotations":{"readOnlyHint":false,"destructiveHint":true}}"#
                .to_vec();
        let tc_a2 = ToolCall {
            tool: tool_t2,
            args: s.args_a.clone(),
            annotations: Annotations {
                read_only: Some(false),
                destructive: Some(true),
                ..Default::default()
            },
        };
        let r_a2 = verify_tool_call(
            cose::PROFILE_PUBLIC,
            &s.wrapper_key.verifier,
            &sign_wrapper(&tc_a2, &s.wrapper_key, policy::DESTRUCTIVE),
        )
        .expect("verify A2");
        let ledger = new_ledger("changedTool");
        match authorize_call(&r_a2, &s.appr, &s.approver_v, &s.appr_sig, &s.wrapper_key.id, 500, &ledger) {
            Ok(()) => panic!("approval for the old tool description satisfied a call with a changed tool description"),
            Err(e) => assert_eq!(e.kind, "ApprovalRequired"),
        }
        assert_eq!(
            ledger.len(),
            0,
            "ledger appended on a rejected (changed-tool) call"
        );
    }

    // ---- (d) an annotation set that maps outside the lattice is rejected, not benign ---------

    // Checkpoint demo (d): a wrapper carrying an annotation hint value outside {0,1} (here
    // readOnlyHint=2) maps outside the closed lattice and is rejected MalformedAnnotation at
    // verification — never defaulted to benign. The body is assembled directly so the out-of-lattice
    // value reaches the wire (the typed builder cannot produce it).
    #[test]
    fn annotation_outside_lattice_rejected() {
        let k = mk_key(30);
        let bad_body = Value::Map(vec![
            (Value::Uint(1), Value::Bstr(br#"{"name":"t"}"#.to_vec())),
            (Value::Uint(2), Value::Bstr(b"{}".to_vec())),
            (
                Value::Uint(3),
                Value::Map(vec![(Value::Uint(KEY_READ_ONLY), Value::Uint(2))]),
            ), // 2 is outside {0,1}
        ]);
        let mut obj = envelope::Object {
            audience: String::new(),
            suite: 0,
            id: vec![],
            kind: KIND_MCP_TOOL_CALL,
            channel: CHANNEL_BRIDGE,
            tier: TIER,
            signer: k.id.as_bytes().to_vec(),
            created: 1,
            effect: policy::DESTRUCTIVE as u64,
            causes: vec![],
            profile: cose::PROFILE_PUBLIC as u64,
            body: bad_body,
            ext: None,
            cext: None,
        };
        let signed = envelope::sign(&mut obj, &k.signer);
        match verify_tool_call(cose::PROFILE_PUBLIC, &k.verifier, &signed) {
            Ok(_) => panic!("annotation value outside {{0,1}} accepted (defaulted to benign?)"),
            Err(e) => assert_eq!(e.kind, "MalformedAnnotation"),
        }
    }

    // A declared envelope effect outside {0..3} is rejected at build (EffectOutsideLattice), never
    // normalized to benign.
    #[test]
    fn declared_effect_outside_lattice_rejected() {
        let k = mk_key(31);
        let tc = ToolCall {
            tool: br#"{"name":"t"}"#.to_vec(),
            args: b"{}".to_vec(),
            annotations: Annotations {
                read_only: Some(true),
                ..Default::default()
            },
        };
        match tc.envelope_object(k.id.as_bytes(), 1, cose::PROFILE_PUBLIC as u64, 4, vec![]) {
            Ok(_) => panic!("declared effect 4 accepted"),
            Err(e) => assert_eq!(e.kind, "EffectOutsideLattice"),
        }
    }

    // ---- tier + tamper + foreign-identity guards ---------------------------------------------

    // A frozen baseline verifier (no tier licensed) rejects the tier-1 McpToolCall kind as UnknownKind
    // (fail-closed), exactly as the tier model requires.
    #[test]
    fn baseline_verifier_rejects_mcp_kind() {
        let k = mk_key(40);
        let tc = ToolCall {
            tool: br#"{"name":"t"}"#.to_vec(),
            args: b"{}".to_vec(),
            annotations: Annotations {
                read_only: Some(true),
                ..Default::default()
            },
        };
        let signed = sign_wrapper(&tc, &k, policy::READ_ONLY);
        let baseline = |c: u64, kk: u64| channels::kind_validator(c, kk);
        match envelope::verify(cose::PROFILE_PUBLIC, &k.verifier, &baseline, &[], &signed) {
            Ok(_) => panic!("baseline verifier accepted a tier-1 McpToolCall"),
            Err(e) => assert_eq!(e.kind, "UnknownKind"),
        }
    }

    // Flipping a signature byte makes the wrapper unverifiable (BadSignature).
    #[test]
    fn tampered_wrapper_rejected() {
        let k = mk_key(41);
        let tc = ToolCall {
            tool: br#"{"name":"t","annotations":{"readOnlyHint":false,"destructiveHint":true}}"#
                .to_vec(),
            args: b"{}".to_vec(),
            annotations: Annotations {
                read_only: Some(false),
                destructive: Some(true),
                ..Default::default()
            },
        };
        let mut signed = sign_wrapper(&tc, &k, policy::DESTRUCTIVE);
        let n = signed.len();
        signed[n - 1] ^= 0x01;
        match verify_tool_call(cose::PROFILE_PUBLIC, &k.verifier, &signed) {
            Ok(_) => panic!("tampered wrapper accepted"),
            Err(e) => assert_eq!(e.kind, "BadSignature"),
        }
    }

    // Even when the carried MCP tool bytes name a foreign principal, the wrapper's authorizing signer is
    // the N-AALP wrapping signer id, never the foreign name (a foreign identity never becomes an N-AALP
    // authorization identity, R-14.6).
    #[test]
    fn foreign_identity_never_authorizes() {
        let k = mk_key(42);
        // The foreign bytes claim an "owner"/principal. It is carried verbatim and never promoted.
        let tool = br#"{"name":"t","_meta":{"owner":"attacker@evil"},"annotations":{"readOnlyHint":true}}"#.to_vec();
        let tc = ToolCall {
            tool: tool.clone(),
            args: b"{}".to_vec(),
            annotations: Annotations {
                read_only: Some(true),
                ..Default::default()
            },
        };
        let r = verify_tool_call(
            cose::PROFILE_PUBLIC,
            &k.verifier,
            &sign_wrapper(&tc, &k, policy::READ_ONLY),
        )
        .expect("verify");
        assert_eq!(
            r.signer,
            k.id.as_bytes(),
            "authorizing signer must be the wrapping signer id (foreign identity leaked)"
        );
        // The tool bytes are carried octet-for-octet: the verbatim foreign body round-trips unchanged.
        assert_eq!(
            r.tool_call.tool, tool,
            "carried tool bytes were altered (carriage must be octet-for-octet)"
        );
    }

    // ---- standard wire-format edge cases (Part 1) --------------------------------------------

    // Edge case #1: a tool-call body with top-level keys in DESCENDING order (3,2,1) is rejected
    // NonCanonical by the strict shared decoder every verify path routes through (RFC 8949 §4.2.1); the
    // canonical body decodes and parses.
    #[test]
    fn keys_out_of_order_rejected() {
        let c = load();
        let e = &c["edge_cases"]["keys_out_of_order"];
        let canon = must_hex(e["canonical_body_hex"].as_str().unwrap());
        let noncanon = must_hex(e["noncanonical_body_hex"].as_str().unwrap());
        let tc = ToolCall {
            tool: br#"{"name":"t"}"#.to_vec(),
            args: b"{}".to_vec(),
            annotations: Annotations {
                read_only: Some(true),
                ..Default::default()
            },
        };
        assert_eq!(
            hex::encode(tc.bytes()),
            e["canonical_body_hex"].as_str().unwrap(),
            "canonical tool-call body"
        );
        let v = cbor::decode(&canon).expect("canonical body should decode");
        tool_call_from_body(&v).expect("canonical body should parse as a tool-call");
        match cbor::decode(&noncanon) {
            Err(err) => assert_eq!(err.kind, "NonCanonical"),
            Ok(_) => panic!("descending-key tool-call body decoded (want NonCanonical)"),
        }
    }

    // Edge case #2: an empty annotations map is PRESENT and valid (all MCP defaults -> destructive) and
    // is DISTINCT on the wire from a tool-call whose annotations field is ABSENT (rejected). Mutation:
    // drop `have_ann` from tool_call_from_body's required-field check and the absent body wrongly parses.
    #[test]
    fn empty_vs_absent_annotations() {
        let c = load();
        let e = &c["edge_cases"]["empty_vs_absent"];
        let tc = ToolCall {
            tool: br#"{"name":"t"}"#.to_vec(),
            args: b"{}".to_vec(),
            annotations: Annotations::default(),
        };
        assert_eq!(
            hex::encode(tc.bytes()),
            e["empty_annotations"]["body_hex"].as_str().unwrap(),
            "empty-annotations body"
        );
        let ev = cbor::decode(&must_hex(
            e["empty_annotations"]["body_hex"].as_str().unwrap(),
        ))
        .expect("empty decode");
        let got = tool_call_from_body(&ev).expect("empty-annotations tool-call rejected");
        assert_eq!(
            map_annotations_to_effect(&got.annotations),
            policy::DESTRUCTIVE,
            "empty annotations must map to destructive"
        );
        assert_eq!(
            map_annotations_to_effect(&got.annotations) as u64,
            e["empty_annotations"]["mapped_effect"].as_u64().unwrap()
        );
        assert_ne!(
            e["empty_annotations"]["body_hex"].as_str().unwrap(),
            e["absent_annotations"]["body_hex"].as_str().unwrap(),
            "empty-present and absent annotations must be distinct on the wire"
        );
        let av = cbor::decode(&must_hex(
            e["absent_annotations"]["body_hex"].as_str().unwrap(),
        ))
        .expect("absent decode");
        match tool_call_from_body(&av) {
            Ok(_) => panic!(
                "a tool-call body missing its annotations field parsed (want ToolCallMalformed)"
            ),
            Err(err) => assert_eq!(err.kind, "ToolCallMalformed"),
        }
    }

    // Edge case #4: the smallest valid tool-call (empty tool, empty args, empty annotations) encodes,
    // has a stable content id, round-trips, and resolves to the fail-closed destructive default.
    #[test]
    fn minimal_tool_call() {
        let c = load();
        let e = &c["edge_cases"]["minimal"];
        let tc = ToolCall {
            tool: vec![],
            args: vec![],
            annotations: Annotations::default(),
        };
        assert_eq!(
            hex::encode(tc.bytes()),
            e["body_hex"].as_str().unwrap(),
            "minimal tool-call body"
        );
        assert_eq!(
            hex::encode(tc.content_id()),
            e["content_id_hex"].as_str().unwrap(),
            "minimal content-id"
        );
        let v = cbor::decode(&tc.bytes()).expect("minimal decode");
        let got = tool_call_from_body(&v).expect("parse minimal");
        assert_eq!(
            map_annotations_to_effect(&got.annotations),
            policy::DESTRUCTIVE
        );
    }

    // Edge case #5: a call-binding {1:tool_id,2:args_id} (a sibling kind, 2 fields) fed to the tool-call
    // parser is rejected ToolCallMalformed — a tool-call is 3 fields. Mutation: drop `have_ann` and the
    // call-binding wrongly parses.
    #[test]
    fn look_alike_rejected() {
        let c = load();
        let e = &c["edge_cases"]["look_alike"];
        let cb = CallBinding::new(
            &must_hex(e["tool_hex"].as_str().unwrap()),
            &must_hex(e["args_hex"].as_str().unwrap()),
        );
        assert_eq!(
            hex::encode(cb.bytes()),
            e["call_binding_body_hex"].as_str().unwrap(),
            "call-binding body"
        );
        let v = cbor::decode(&must_hex(e["call_binding_body_hex"].as_str().unwrap()))
            .expect("call-binding decode");
        match tool_call_from_body(&v) {
            Ok(_) => panic!("call-binding body parsed as a tool-call (want ToolCallMalformed)"),
            Err(err) => assert_eq!(err.kind, "ToolCallMalformed"),
        }
    }
}
