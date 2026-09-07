// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! The N-AALP error object and the numeric error-code registry (design.md §3.5, R3.3/R3.4, T3.3).
//!
//! The naalp-error object is the Control/Error body (channel 0x0000, kind 3, effect read_only) that
//! carries one fail-closed rejection reason as `{1:code, 2:name, ?3:detail, ?4:subject}`. The
//! registry is the ordered 132-entry name<->code table [`NAMES`] (the code for `NAMES[i]` is `i+1`;
//! 0 is reserved). `NAMES` is the single source the machine-readable registry
//! (`vectors/registry/error-codes.csv`) and the CDDL `naalp-error-code` enum are generated to match;
//! `scripts/registry_drift.py` asserts the three agree, and the table is graded against the
//! non-circular oracle by the `error.name_for_code` conformance op.
//!
//! Two dual-carriage rules keep the code/name pair unambiguous: a registered code whose name
//! disagrees with the registry is rejected `Malformed` (the code is authoritative — the strengthening
//! direction); a code outside the registry is opaque and non-fatal (name diagnostic only), so a
//! receiver interoperates with a peer emitting a later-registered code.

use crate::cbor::{self, Value};
use crate::cose::Error;

/// Top of the RFC-Required standards range; codes >= 0x8000 are private-use.
pub const STANDARDS_MAX: u64 = 0x7FFF;

/// The ordered error-code registry: the code for `NAMES[i]` is `i+1` (0 reserved). Order is the
/// fields-of-record authority for every code (§3.5).
pub const NAMES: [&str; 132] = [
    "NonCanonical", "DepthExceeded", "Malformed", "ContentIdMismatch", "HeaderBodyMismatch",
    "UnsupportedVersion", "UnknownCriticalExt", "UnknownKind", "RangeError", "NonNFC",
    "WrongAudience", "TooLarge", "TooManyCauses", "TooManyExtensions", "TooManyChunks",
    "UnknownAlg", "KeyAlgMismatch", "ProfileDowngrade", "HybridIncomplete", "SuiteMismatch",
    "CompositeRefused", "BadSignature", "SignerMismatch", "RotationUnauthorized", "KeyRevoked",
    "EffectNotAuthorized", "UnauthenticatedPrincipal", "MalformedSafetyLabel", "ApprovalRequired",
    "ApprovalMismatch", "ApprovalExpired", "AlreadyConsumed", "ConsumeFork", "ConsumeForkInvalid",
    "ConsumeReceiptUnsigned", "LedgerCorrupt", "LedgerUnsigned", "AudienceMismatch",
    "FreshnessSelfAsserted", "UnknownRefusalOutcome", "RefusalDetailLeak", "ChainBroken",
    "Equivocation", "CausalViolation", "ReceiptUnsigned", "ForkProofInvalid", "StageOutOfOrder",
    "StreamDigestMismatch", "StreamStateError", "ConfidentialTransportRequired", "PeerUnauthenticated",
    "NotDelivered", "MappingError", "EffectDeclarationMismatch", "StateTransitionError",
    "CapExceedsParent", "TransformCycle", "InputGateBypass", "TaskStateError", "ScopeOverlapConflict",
    "ReconcileMismatch", "WrongFlow", "SeqGap", "AboveCeiling", "GapDetected", "CommitMismatch",
    "ContMalformed", "GrantExpired", "GrantNotYetValid", "GrantRevoked", "UntrustedChainRoot",
    "DelegationDepthExceeded", "GrantMalformed", "NameMalformed", "NameChainBroken",
    "NameForkProofInvalid", "IllegalTransition", "TaskChainBroken", "ForeignCard", "DescMalformed",
    "MalformedApprovalFlag", "DirForkProofInvalid", "ImporterMismatch", "UnknownDescriptionFormat",
    "VerifierKeyMismatch", "NegMalformed", "UnknownRole", "UnknownProfile", "NotDescended",
    "NotOffer", "NotAccept", "MalformedCriticalFlag", "UnknownCriticalRisk", "ReferenceMismatch",
    "MalformedAnnotation", "EffectUnderDeclared", "EffectOutsideLattice", "ToolCallMalformed",
    "PayMalformed", "UnknownPaymentFormat", "GwMalformed", "UnknownGatewayDecision", "UIMalformed",
    "UIChainBroken", "UnknownUIEventKind", "ActionSubstituted", "UINoConsent", "StaleEpoch",
    "Unauthorized", "OwnerImmutable", "MemberExists", "MemberUnknown", "OwnerExists", "RoleInvalid",
    "RoomOpMismatch", "OpUnknown", "PrincipalUnknown", "PrincipalExists", "RebindUnauthorized",
    // Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
    "EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
    "TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed",
    // Manufacturing physical-hazard (Mfg-F), codes 130-132.
    "HazardMalformed", "HazardNotCovered", "HazardUnknown",
];

fn malformed() -> Error {
    Error { kind: "Malformed", msg: "malformed naalp-error object" }
}

/// Registered name for a code, or `None` when the code is unregistered (0, or past the range).
pub fn name_for_code(code: u64) -> Option<&'static str> {
    if code >= 1 && (code as usize) <= NAMES.len() {
        Some(NAMES[(code - 1) as usize])
    } else {
        None
    }
}

/// Registered code for a name, or `None` when the name is unregistered.
pub fn code_for_name(name: &str) -> Option<u64> {
    NAMES.iter().position(|&n| n == name).map(|i| (i + 1) as u64)
}

/// A decoded naalp-error body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorObj {
    pub code: u64,
    pub name: String,
    pub detail: Option<String>,
    pub subject: Option<Vec<u8>>,
}

/// Deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body `{1:code, 2:name, ?3:detail,
/// ?4:subject}`. `detail == ""` omits field 3; `subject == None` omits field 4. Keys 1..4 are
/// already in canonical ascending order.
pub fn encode(code: u64, name: &str, detail: &str, subject: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut pairs = vec![
        (Value::Uint(1), Value::Uint(code)),
        (Value::Uint(2), Value::Tstr(name.to_string())),
    ];
    if !detail.is_empty() {
        pairs.push((Value::Uint(3), Value::Tstr(detail.to_string())));
    }
    if let Some(s) = subject {
        pairs.push((Value::Uint(4), Value::Bstr(s.to_vec())));
    }
    cbor::encode(&Value::Map(pairs)).map_err(|_| malformed())
}

/// Parse a naalp-error body and enforce the dual-carriage rules. A structurally malformed body, a
/// registered code whose name disagrees with the registry, is rejected `Malformed`. An unregistered
/// code is accepted opaque (name diagnostic only).
pub fn decode(data: &[u8]) -> Result<ErrorObj, Error> {
    let v = cbor::decode(data).map_err(|_| malformed())?;
    let m = match v {
        Value::Map(m) => m,
        _ => return Err(malformed()),
    };
    let mut code: Option<u64> = None;
    let mut name: Option<String> = None;
    let mut detail: Option<String> = None;
    let mut subject: Option<Vec<u8>> = None;
    for (k, val) in m {
        let key = match k {
            Value::Uint(u) => u,
            _ => return Err(malformed()),
        };
        match (key, val) {
            (1, Value::Uint(u)) => code = Some(u),
            (2, Value::Tstr(s)) => name = Some(s),
            (3, Value::Tstr(s)) => detail = Some(s),
            (4, Value::Bstr(b)) => subject = Some(b),
            _ => return Err(malformed()), // wrong-typed or unknown field key -> closed grammar
        }
    }
    let (code, name) = match (code, name) {
        (Some(c), Some(n)) => (c, n),
        _ => return Err(malformed()),
    };
    if let Some(reg) = name_for_code(code) {
        if reg != name {
            return Err(malformed()); // registered code + disagreeing name
        }
    }
    Ok(ErrorObj { code, name, detail, subject })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_size_and_index() {
        assert_eq!(NAMES.len(), 132);
        for (i, n) in NAMES.iter().enumerate() {
            assert_eq!(code_for_name(n), Some((i + 1) as u64));
        }
    }

    #[test]
    fn encode_kat() {
        // hand-computed canonical CBOR of {1:code, 2:name}, independent of the oracle and impl/go.
        assert_eq!(hex::encode(encode(1, "NonCanonical", "", None).unwrap()),
                   "a20101026c4e6f6e43616e6f6e6963616c");
        assert_eq!(hex::encode(encode(52, "NotDelivered", "", None).unwrap()),
                   "a2011834026c4e6f7444656c697665726564");
    }

    #[test]
    fn dual_carriage_mismatch_is_malformed() {
        let b = encode(22, "NotDelivered", "", None).unwrap(); // code 22=BadSignature, wrong name
        assert_eq!(decode(&b).unwrap_err().kind, "Malformed");
    }

    #[test]
    fn unknown_code_is_opaque() {
        let b = encode(60000, "SomeFutureError", "", None).unwrap();
        let o = decode(&b).unwrap();
        assert_eq!(o.code, 60000);
        assert_eq!(o.name, "SomeFutureError");
    }

    #[test]
    fn full_grammar_round_trip() {
        let subj = vec![0u8; 50];
        let b = encode(22, "BadSignature", "reason", Some(&subj)).unwrap();
        let o = decode(&b).unwrap();
        assert_eq!(o.detail.as_deref(), Some("reason"));
        assert_eq!(o.subject.map(|s| s.len()), Some(50));
    }
}
