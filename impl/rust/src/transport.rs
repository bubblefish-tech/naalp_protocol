// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! C11 — the four transport bindings (design.md §12; R-13.1..13.4).
//!
//! A binding carries exactly one signed object as one message unit, with identical object
//! semantics across N-PAMP, QUIC, WebSocket, and HTTP (R-13.1). The object is self-secured by
//! C2..C8; the binding adds only framing plus, from the transport, confidentiality and
//! connection authentication (R-13.2, R-13.3). Media type application/naalp+cbor. The
//! confidentiality boundary is normative: a sensitive object MUST NOT be emitted in cleartext
//! over a non-confidential transport — the binding refuses it (ConfidentialTransportRequired,
//! R-13.4). A transport lacking peer authentication where policy requires it is
//! PeerUnauthenticated (§12.4).

use crate::cose;

/// One-object-per-representation media type (§12.1).
pub const MEDIA_TYPE: &str = "application/naalp+cbor";

pub fn err_confidential_transport_required() -> cose::Error {
    cose::Error {
        kind: "ConfidentialTransportRequired",
        msg: "a sensitive object may not be emitted in cleartext over a non-confidential transport",
    }
}
pub fn err_peer_unauthenticated() -> cose::Error {
    cose::Error { kind: "PeerUnauthenticated", msg: "transport peer is not authenticated where policy requires it" }
}
pub fn err_malformed() -> cose::Error {
    cose::Error { kind: "Malformed", msg: "message unit is not application/naalp+cbor" }
}

/// One binding and the two conditional guarantees it provides (§12.3). Object-level guarantees
/// are always present regardless of the transport.
#[derive(Clone, Copy)]
pub struct Transport {
    pub name: &'static str,
    pub confidential: bool,
    pub peer_authenticated: bool,
}

// The four binding types (§12.2); WebSocket/HTTP have confidential (wss/https) and cleartext
// (ws/http) variants.
pub const NPAMP: Transport = Transport { name: "npamp", confidential: true, peer_authenticated: true };
pub const QUIC: Transport = Transport { name: "quic", confidential: true, peer_authenticated: true };
pub const WEBSOCKET_WSS: Transport = Transport { name: "websocket+wss", confidential: true, peer_authenticated: false };
pub const WEBSOCKET_WS: Transport = Transport { name: "websocket+ws", confidential: false, peer_authenticated: false };
pub const HTTPS: Transport = Transport { name: "https", confidential: true, peer_authenticated: false };
pub const HTTP: Transport = Transport { name: "http", confidential: false, peer_authenticated: false };

/// Every transport variant.
pub const ALL: [Transport; 6] = [NPAMP, QUIC, WEBSOCKET_WSS, WEBSOCKET_WS, HTTPS, HTTP];

/// The transport variant with the given name.
pub fn by_name(name: &str) -> Option<Transport> {
    ALL.into_iter().find(|t| t.name == name)
}

/// One signed object framed for a transport: one object per unit (§12.1); the payload is the
/// object bytes verbatim (R-13.2).
#[derive(Debug)]
pub struct MessageUnit {
    pub transport: String,
    pub media_type: String,
    pub payload: Vec<u8>,
}

impl MessageUnit {
    /// Recover the object bytes, rejecting a wrong media type.
    pub fn object(&self) -> Result<Vec<u8>, cose::Error> {
        if self.media_type != MEDIA_TYPE {
            return Err(err_malformed());
        }
        Ok(self.payload.clone())
    }
}

/// Carry one signed object as one message unit, adding only framing.
pub fn frame(t: &Transport, obj: &[u8]) -> MessageUnit {
    MessageUnit { transport: t.name.to_string(), media_type: MEDIA_TYPE.to_string(), payload: obj.to_vec() }
}

/// Apply the confidentiality boundary (§12.3) and peer-auth rule (§12.4) before framing: a
/// sensitive object over a non-confidential transport is refused
/// (ConfidentialTransportRequired); a transport lacking peer authentication where policy
/// requires it is refused (PeerUnauthenticated). Otherwise the object is framed unchanged.
pub fn emit(t: &Transport, obj: &[u8], sensitive: bool, require_peer_auth: bool) -> Result<MessageUnit, cose::Error> {
    if sensitive && !t.confidential {
        return Err(err_confidential_transport_required());
    }
    if require_peer_auth && !t.peer_authenticated {
        return Err(err_peer_unauthenticated());
    }
    Ok(frame(t, obj))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::envelope;
    use serde_json::Value as J;

    const VECTOR_PATH: &str = "../../vectors/transport/cases.json";

    fn load() -> J {
        serde_json::from_str(&std::fs::read_to_string(VECTOR_PATH).expect("read corpus"))
            .expect("parse corpus")
    }

    #[test]
    fn transport_table_matches_oracle() {
        let c = load();
        assert_eq!(MEDIA_TYPE, c["media_type"].as_str().unwrap());
        for tr in c["transports"].as_array().unwrap() {
            let got = by_name(tr["name"].as_str().unwrap()).expect("known transport");
            assert_eq!(got.confidential, tr["confidential"].as_bool().unwrap());
            assert_eq!(got.peer_authenticated, tr["peer_authenticated"].as_bool().unwrap());
        }
    }

    #[test]
    fn emit_matrix() {
        let c = load();
        let obj = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let (mut conf_refusals, mut auth_refusals) = (0, 0);
        for r in c["emit_matrix"].as_array().unwrap() {
            let tr = by_name(r["transport"].as_str().unwrap()).unwrap();
            let res = emit(&tr, &obj, r["sensitive"].as_bool().unwrap(), r["require_peer_auth"].as_bool().unwrap());
            match r["result"].as_str().unwrap() {
                "ok" => {
                    let mu = res.expect("ok");
                    assert_eq!(mu.payload, obj);
                }
                "ConfidentialTransportRequired" => {
                    conf_refusals += 1;
                    assert_eq!(res.unwrap_err().kind, "ConfidentialTransportRequired");
                }
                "PeerUnauthenticated" => {
                    auth_refusals += 1;
                    assert_eq!(res.unwrap_err().kind, "PeerUnauthenticated");
                }
                other => panic!("unknown result {}", other),
            }
        }
        assert!(conf_refusals > 0 && auth_refusals > 0);
    }

    fn signer() -> (cose::MlDsa65Verifier, cose::MlDsa65Signer, Vec<u8>) {
        let (pk, sk) = cose::mldsa65_keypair_from_seed(&[70; 32]);
        use fips204::traits::SerDes;
        let pkb = pk.clone().into_bytes().to_vec();
        (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk), pkb)
    }

    fn obj(pkb: &[u8]) -> envelope::Object {
        envelope::Object {
            id: vec![], kind: 0, channel: 0, tier: 0, signer: pkb.to_vec(), created: 100,
            effect: 0, causes: vec![], profile: cose::PROFILE_PUBLIC as u64,
            body: Value::Uint(0), ext: None, cext: None,
        }
    }

    #[test]
    fn cross_binding_identity() {
        let (v, s, pkb) = signer();
        let kind_ok = |_c: u64, _k: u64| true;
        let mut o = obj(&pkb);
        let signed = envelope::sign(&mut o, &s);
        for tr in [NPAMP, QUIC, WEBSOCKET_WSS, HTTPS] {
            let mu = emit(&tr, &signed, false, false).expect("emit");
            let payload = mu.object().expect("object");
            assert_eq!(payload, signed, "{} framing changed the object", tr.name);
            envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &payload)
                .unwrap_or_else(|_| panic!("{}: object does not verify after binding", tr.name));
        }
    }

    #[test]
    fn mutation_breaks_verification() {
        let (v, s, pkb) = signer();
        let kind_ok = |_c: u64, _k: u64| true;
        let mut o = obj(&pkb);
        let signed = envelope::sign(&mut o, &s);
        let mut mu = frame(&QUIC, &signed);
        let mid = mu.payload.len() / 2;
        mu.payload[mid] ^= 0x01;
        let payload = mu.object().expect("object");
        assert!(
            envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &payload).is_err(),
            "a mutated object body still verified"
        );
    }

    #[test]
    fn media_type_rejected() {
        let mu = MessageUnit { transport: "http".into(), media_type: "application/json".into(), payload: vec![1, 2, 3] };
        assert_eq!(mu.object().unwrap_err().kind, "Malformed");
    }
}
