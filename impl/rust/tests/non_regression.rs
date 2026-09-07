// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP non-regression guard (T2.1; coding-instructions §2), Rust half of the
// two-implementation parity. N-AALP is built to hold three core properties, and each can
// quietly regress. These tests NAME the three regression modes and FAIL if any occurs. Every test
// is mutation-surviving: reintroducing a session-token-accepts path, a classical-only
// governed selection, or a JSON canonicalizer on a signing path flips its test pass->fail.

use std::fs;
use std::path::Path;

use naalp::cbor::{self, Value};
use naalp::{cose, policy};

// A verifier whose verify_raw always fails; it lets verify1/verify_hybrid be exercised for
// the profile-floor decision, which is checked BEFORE any signature.
struct DummyV {
    alg: i64,
}
impl cose::CoseVerifier for DummyV {
    fn alg(&self) -> i64 {
        self.alg
    }
    fn verify_raw(&self, _msg: &[u8], _sig: &[u8]) -> bool {
        false
    }
    fn pub_key(&self) -> Vec<u8> {
        Vec::new()
    }
}

// -------------------------------------------------------------------------------------
// (1) SESSION-TOKEN-CANNOT-AUTHORIZE
// -------------------------------------------------------------------------------------
//
// Fails if any object authorization can be satisfied by a transport/session token (or any
// self-asserted, non-signature identity) instead of the required signature-derived
// credential. Each non-signature source names the EXACT grant principal and an in-ceiling
// effect (where a naive check would wave it through), yet must be refused with
// UnauthenticatedPrincipal. Mutation: let resolve_auth_principal accept a transport source
// and the non-signature loop flips reject->allow.
#[test]
fn session_token_cannot_authorize() {
    use policy::PrincipalSource as PS;
    // Maximally permissive grant: only the source-of-identity gate can deny.
    let g = policy::Grant {
        principal: "signer-A".into(),
        max_effect: policy::DESTRUCTIVE,
    };

    // Positive control: the signature-derived principal, in-ceiling, IS authorized.
    assert!(
        g.authorize_object(PS::Signature, "signer-A", policy::READ_ONLY as u64)
            .is_ok(),
        "positive control: signature-derived principal must authorize"
    );

    for (name, src) in [
        ("transport/session token", PS::TransportMetadata),
        ("foreign X-Agent-ID header", PS::ForeignHeader),
        ("self-asserted clientInfo.name", PS::ClientName),
    ] {
        match g.authorize_object(src, "signer-A", policy::READ_ONLY as u64) {
            Ok(()) => panic!("MOAT EROSION: {name} authorized an object (authority collapsed to a session token)"),
            Err(e) => assert_eq!(e.kind, "UnauthenticatedPrincipal", "{name}: wrong error kind"),
        }
        // The resolver itself must refuse the source, before any grant matching.
        assert_eq!(
            policy::resolve_auth_principal(src, "signer-A")
                .unwrap_err()
                .kind,
            "UnauthenticatedPrincipal",
            "{name}: resolve_auth_principal must refuse it"
        );
    }

    // A signature source with an EMPTY id is still not a principal (no anonymous authority).
    assert_eq!(
        policy::resolve_auth_principal(PS::Signature, "")
            .unwrap_err()
            .kind,
        "UnauthenticatedPrincipal"
    );
}

// -------------------------------------------------------------------------------------
// (2) NO-CLASSICAL-ONLY-ON-GOVERNED-TIER
// -------------------------------------------------------------------------------------
//
// Fails if a downgrade can select a classical-only signature suite on a governed N-AALP
// profile. Every profile is a governed tier with a post-quantum floor (level >= 3;
// Sovereign requires level 5); classical Ed25519 (level 0) is below the floor everywhere.
// Mutation: raise alg_level(Ed25519) to a PQC level, or drop profile_min_level below 3.
#[test]
fn no_classical_only_on_governed_tier() {
    let profiles = [
        ("Public", cose::PROFILE_PUBLIC),
        ("Enterprise", cose::PROFILE_ENTERPRISE),
        ("Sovereign", cose::PROFILE_SOVEREIGN),
    ];
    let payload = [0xa1u8, 0x07, 0x00];

    // Structural: Ed25519 is a registered classical (level 0) suite, below every floor.
    let ed_level =
        cose::alg_level_of(cose::ALG_ED25519).expect("Ed25519 must be registered as a hybrid leg");
    assert_eq!(ed_level, 0, "Ed25519 must be classical level 0");
    for (name, p) in profiles {
        assert!(
            ed_level < cose::profile_min_level_of(p),
            "MOAT EROSION: classical Ed25519 (level {ed_level}) meets the {name} floor"
        );
    }

    // A real post-quantum key: positive control + the verifier the downgrade path is offered.
    let mut seed = [0u8; 32];
    seed[0] = 0x11;
    let (pk, sk) = cose::mldsa65_keypair_from_seed(&seed);
    let pq_obj = cose::sign1(&cose::MlDsa65Signer(sk), &payload);
    cose::verify1(cose::PROFILE_PUBLIC, &cose::MlDsa65Verifier(pk), &pq_obj)
        .expect("positive control: post-quantum signature must verify at Public");

    // Behavioral downgrade #1: a classical-only Ed25519 COSE_Sign1 is refused at every profile.
    let ed_prot = cbor::encode(&Value::Map(vec![(
        Value::Uint(1),
        Value::Nint(cose::ALG_ED25519),
    )]))
    .expect("encode ed25519 protected header");
    let ed_obj = cose::assemble_sign1_raw(&ed_prot, &payload, &[0u8; 64]);
    for (name, p) in profiles {
        match cose::verify1(
            p,
            &DummyV {
                alg: cose::ALG_MLDSA65,
            },
            &ed_obj,
        ) {
            Err(e) if e.kind == "ProfileDowngrade" => {}
            other => {
                panic!("MOAT EROSION: {name} accepted a classical-only COSE_Sign1 (got {other:?})")
            }
        }
    }

    // Behavioral downgrade #2: a hybrid stripped to only its classical Ed25519 leg is refused
    // (HybridIncomplete — the PQC leg is missing), never accepted as classical-only.
    let ed_only_hybrid = cbor::encode(&Value::Tag(
        cose::TAG_SIGN,
        Box::new(Value::Arr(vec![
            Value::Bstr(vec![]),
            Value::Map(vec![]),
            Value::Bstr(payload.to_vec()),
            Value::Arr(vec![Value::Arr(vec![
                Value::Bstr(ed_prot.clone()),
                Value::Map(vec![]),
                Value::Bstr(vec![0u8; 64]),
            ])]),
        ])),
    ))
    .expect("encode ed-only hybrid");
    match cose::verify_hybrid(
        cose::PROFILE_PUBLIC,
        &DummyV {
            alg: cose::ALG_ED25519,
        },
        &DummyV {
            alg: cose::ALG_MLDSA65,
        },
        &ed_only_hybrid,
    ) {
        Err(e) if e.kind == "HybridIncomplete" => {}
        other => panic!("MOAT EROSION: a classical-only hybrid was not refused (got {other:?})"),
    }

    // Behavioral downgrade #3: a hybrid whose PQC leg is below the governed top tier's floor
    // (ML-DSA-65 leg at Sovereign, which requires level 5) is refused ProfileDowngrade.
    let ml_prot = cbor::encode(&Value::Map(vec![(
        Value::Uint(1),
        Value::Nint(cose::ALG_MLDSA65),
    )]))
    .expect("encode ml-dsa-65 protected header");
    let sub_floor_hybrid = cbor::encode(&Value::Tag(
        cose::TAG_SIGN,
        Box::new(Value::Arr(vec![
            Value::Bstr(vec![]),
            Value::Map(vec![]),
            Value::Bstr(payload.to_vec()),
            Value::Arr(vec![Value::Arr(vec![
                Value::Bstr(ml_prot),
                Value::Map(vec![]),
                Value::Bstr(vec![0u8; 64]),
            ])]),
        ])),
    ))
    .expect("encode sub-floor hybrid");
    match cose::verify_hybrid(
        cose::PROFILE_SOVEREIGN,
        &DummyV {
            alg: cose::ALG_ED25519,
        },
        &DummyV {
            alg: cose::ALG_MLDSA65,
        },
        &sub_floor_hybrid,
    ) {
        Err(e) if e.kind == "ProfileDowngrade" => {}
        other => {
            panic!("MOAT EROSION: Sovereign accepted a sub-floor PQC hybrid leg (got {other:?})")
        }
    }
}

// -------------------------------------------------------------------------------------
// (3) NO-JSON-CANONICALIZER-ON-SIGNING-PATH
// -------------------------------------------------------------------------------------

// Source markers of a JSON / JSON-LD canonicalizer or serializer. None may appear in the
// production (pre-`#[cfg(test)]`) portion of any signing-path source file. The bare word
// "json" is intentionally NOT forbidden — only a serializer/canonicalizer symbol is.
const JSON_CANONICALIZER_TOKENS: &[&str] = &[
    "serde_json",
    "jcs",
    "canonicaljson",
    "canonical_json",
    "JSON-LD",
    "jsonld",
    "URDNA2015",
    "to_string_pretty",
    "RFC 8785",
    "RFC8785",
];

// Fails if any signing path invokes a JSON canonicalizer. Proven two ways: (a) the
// COSE_Sign1 ToBeSigned input is deterministic CBOR — a CBOR array whose first element is
// the tstr "Signature1" (RFC 9052 §4.4) — that re-encodes byte-identically; a JSON document
// could not satisfy this. (b) no signing-path source file's production portion contains a
// JSON/JSON-LD canonicalizer marker. Mutation: use serde_json (or a JCS/URDNA2015
// canonicalizer) in a signing-path module's production code and the source scan below fails.
#[test]
fn no_json_canonicalizer_on_signing_path() {
    // (a) the signing input is canonical CBOR, first element the tstr "Signature1".
    let payload = [0xa1u8, 0x07, 0x00];
    let tbs = cose::to_be_signed(cose::ALG_MLDSA65, &payload);
    let v =
        cbor::decode(&tbs).expect("the signed input is not valid CBOR (JSON on the signing path?)");
    match &v {
        Value::Arr(a) => {
            assert!(!a.is_empty(), "empty Sig_structure");
            match &a[0] {
                Value::Tstr(s) => assert_eq!(
                    s, "Signature1",
                    "first Sig_structure element must be \"Signature1\""
                ),
                other => panic!("first Sig_structure element must be a tstr, got {other:?}"),
            }
        }
        other => panic!("the COSE Sig_structure must be a CBOR array, got {other:?}"),
    }
    assert_eq!(
        cbor::encode(&v).unwrap(),
        tbs,
        "the signing input is not canonical CBOR (re-encode differs)"
    );

    // (b) no signing-path source file's production portion carries a canonicalizer marker.
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0usize;
    for entry in fs::read_dir(&src_dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = fs::read_to_string(&path).expect("read source file");
        // Scan only the production portion (everything before the first `#[cfg(test)]`),
        // so vector-reading test modules (which use serde_json) are not the signing path.
        let production = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src[..],
        };
        for tok in JSON_CANONICALIZER_TOKENS {
            assert!(
                !production.contains(tok),
                "MOAT EROSION: signing-path file {} references JSON-canonicalizer marker {:?}",
                path.file_name().unwrap().to_string_lossy(),
                tok
            );
        }
        scanned += 1;
    }
    assert!(scanned > 0, "found no signing-path source files to scan");
}
