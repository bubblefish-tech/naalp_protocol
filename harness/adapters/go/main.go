// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// naalp-adapter-go — the reference N-AALP conformance adapter.
//
// It wraps the impl/go SDK behind the length-prefixed JSON op protocol the naalp-conform runner
// drives (see harness/INSTRUCTIONS.md). It reads {"op","in"} requests framed as a 4-byte
// little-endian length + UTF-8 JSON on stdin, dispatches each op to the real SDK, and writes
// {"out"|"error"|"skipped"} responses in the same framing on stdout, flushing after each.
//
// Being the reference adapter over the Go implementation that the corpus already grades
// (Go == oracle in impl/go's own tests), it implements every op and skips none; it is the
// yardstick against which the eight additional-language SDKs are measured.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/approval"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/audit"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/carriage"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/delivery"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/envelope"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalperror"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/federation"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/streaming"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/transport"
)

type request struct {
	Op string                 `json:"op"`
	In map[string]interface{} `json:"in"`
}

type response struct {
	Out     map[string]interface{} `json:"out,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Skipped string                 `json:"skipped,omitempty"`
}

func out(m map[string]interface{}) response { return response{Out: m} }
func errf(format string, a ...interface{}) response {
	return response{Error: fmt.Sprintf(format, a...)}
}

// ---- input helpers ----

func hx(in map[string]interface{}, k string) ([]byte, error) {
	s, ok := in[k].(string)
	if !ok {
		return nil, fmt.Errorf("missing hex field %q", k)
	}
	return hex.DecodeString(s)
}

func str(in map[string]interface{}, k string) string {
	s, _ := in[k].(string)
	return s
}

// u64 accepts a JSON number or a decimal string (64-bit counters travel as strings when they
// exceed 2^53).
func u64(in map[string]interface{}, k string) uint64 {
	switch v := in[k].(type) {
	case float64:
		return uint64(v)
	case string:
		n, _ := strconv.ParseUint(v, 10, 64)
		return n
	default:
		return 0
	}
}

func toHex(b []byte) string { return hex.EncodeToString(b) }

// taggedToValue converts a language-neutral tagged value into a cbor.Value, so the encoder under
// test (not the corpus author's language) produces the bytes. Tags: u, b, s, arr, map.
func taggedToValue(v interface{}) (cbor.Value, error) {
	arr, ok := v.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("tagged value must be [tag, payload]")
	}
	tag, _ := arr[0].(string)
	p := arr[1]
	switch tag {
	case "u":
		f, ok := p.(float64)
		if !ok {
			if s, ok := p.(string); ok {
				n, err := strconv.ParseUint(s, 10, 64)
				if err != nil {
					return nil, err
				}
				return cbor.Uint(n), nil
			}
			return nil, fmt.Errorf("u payload not a number")
		}
		return cbor.Uint(uint64(f)), nil
	case "b":
		s, _ := p.(string)
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return cbor.Bstr(b), nil
	case "s":
		s, _ := p.(string)
		return cbor.Tstr(s), nil
	case "arr":
		items, _ := p.([]interface{})
		a := make(cbor.Arr, 0, len(items))
		for _, it := range items {
			cv, err := taggedToValue(it)
			if err != nil {
				return nil, err
			}
			a = append(a, cv)
		}
		return a, nil
	case "map":
		pairs, _ := p.([]interface{})
		m := make(cbor.Map, 0, len(pairs))
		for _, pr := range pairs {
			kv, _ := pr.([]interface{})
			if len(kv) != 2 {
				return nil, fmt.Errorf("map pair must be [k, v]")
			}
			kc, err := taggedToValue(kv[0])
			if err != nil {
				return nil, err
			}
			vc, err := taggedToValue(kv[1])
			if err != nil {
				return nil, err
			}
			m = append(m, cbor.Pair{K: kc, V: vc})
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unknown tag %q", tag)
	}
}

func mldsaKeyFromSeed(alg int, seed []byte) (cose.Signer, []byte, error) {
	if len(seed) != 32 {
		return nil, nil, fmt.Errorf("seed must be 32 bytes")
	}
	var s [32]byte
	copy(s[:], seed)
	switch alg {
	case cose.AlgMLDSA65:
		pk, sk := mldsa65.NewKeyFromSeed(&s)
		return cose.MLDSA65Signer{SK: sk}, pk.Bytes(), nil
	case cose.AlgMLDSA87:
		pk, sk := mldsa87.NewKeyFromSeed(&s)
		return cose.MLDSA87Signer{SK: sk}, pk.Bytes(), nil
	default:
		return nil, nil, fmt.Errorf("alg %d has no seed keygen", alg)
	}
}

func verifierFor(alg int, pub []byte) (cose.Verifier, error) {
	switch alg {
	case cose.AlgMLDSA65:
		pk := new(mldsa65.PublicKey)
		if err := pk.UnmarshalBinary(pub); err != nil {
			return nil, err
		}
		return cose.MLDSA65Verifier{PK: pk}, nil
	case cose.AlgMLDSA87:
		pk := new(mldsa87.PublicKey)
		if err := pk.UnmarshalBinary(pub); err != nil {
			return nil, err
		}
		return cose.MLDSA87Verifier{PK: pk}, nil
	case cose.AlgEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad ed25519 public key length")
		}
		return cose.Ed25519Verifier{PK: ed25519.PublicKey(pub)}, nil
	default:
		return nil, fmt.Errorf("unknown alg %d", alg)
	}
}

func nodesFrom(in map[string]interface{}) ([]audit.CausalNode, error) {
	raw, _ := in["nodes"].([]interface{})
	nodes := make([]audit.CausalNode, 0, len(raw))
	for _, r := range raw {
		nm, _ := r.(map[string]interface{})
		id, err := hex.DecodeString(str(nm, "id_hex"))
		if err != nil {
			return nil, err
		}
		var causes [][]byte
		cr, _ := nm["causes_hex"].([]interface{})
		for _, c := range cr {
			cb, err := hex.DecodeString(c.(string))
			if err != nil {
				return nil, err
			}
			causes = append(causes, cb)
		}
		// Position is authoritative only where the corpus supplies it (the audit causal cases);
		// federation nodes omit it, and Reconcile/VerifyCausal treat a 0 position as "unordered",
		// exactly as impl/go's own federation tests construct their nodes.
		var pos uint64
		if p, ok := nm["position"].(float64); ok {
			pos = uint64(p)
		}
		nodes = append(nodes, audit.CausalNode{ID: id, Causes: causes, Position: pos})
	}
	return nodes, nil
}

func hexList(bs [][]byte) []interface{} {
	out := make([]interface{}, len(bs))
	for i, b := range bs {
		out[i] = toHex(b)
	}
	return out
}

// ---- dispatch ----

func handle(req request) response {
	in := req.In
	switch req.Op {
	case "sha384":
		msg, err := hx(in, "msg_hex")
		if err != nil {
			return errf("%v", err)
		}
		d := sha512.Sum384(msg)
		return out(map[string]interface{}{"digest_hex": toHex(d[:])})

	case "cbor.encode":
		cv, err := taggedToValue(in["value"])
		if err != nil {
			return errf("%v", err)
		}
		b, err := cbor.Encode(cv)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"bytes_hex": toHex(b)})

	case "cbor.decode":
		b, err := hx(in, "bytes_hex")
		if err != nil {
			return errf("%v", err)
		}
		if _, err := cbor.Decode(b); err != nil {
			return errf("%v", err) // a non-canonical / malformed input is rejected
		}
		return out(map[string]interface{}{"ok": true})

	case "content.id":
		b, err := hx(in, "body_hex")
		if err != nil {
			return errf("%v", err)
		}
		v, err := cbor.Decode(b)
		if err != nil {
			return errf("%v", err)
		}
		m, ok := v.(cbor.Map)
		if !ok {
			return errf("body is not a CBOR map")
		}
		id, err := cbor.ContentID(m)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"id_hex": toHex(id)})

	case "cose.tbs":
		prot, err := hx(in, "protected_hex")
		if err != nil {
			return errf("%v", err)
		}
		payload, err := hx(in, "payload_hex")
		if err != nil {
			return errf("%v", err)
		}
		tbs, err := cose.ToBeSignedRaw(prot, payload)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"tobesigned_hex": toHex(tbs)})

	case "mldsa.keygen":
		seed, err := hx(in, "seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		alg := cose.AlgMLDSA65
		if str(in, "param") == "ML-DSA-87" {
			alg = cose.AlgMLDSA87
		}
		_, pk, err := mldsaKeyFromSeed(alg, seed)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"pk_hex": toHex(pk)})

	case "ed25519.sign":
		sk, err := hx(in, "sk_hex")
		if err != nil {
			return errf("%v", err)
		}
		msg, err := hx(in, "msg_hex")
		if err != nil {
			return errf("%v", err)
		}
		if len(sk) != ed25519.SeedSize {
			return errf("ed25519 sk must be a 32-byte seed")
		}
		priv := ed25519.NewKeyFromSeed(sk)
		sig := ed25519.Sign(priv, msg)
		return out(map[string]interface{}{"sig_hex": toHex(sig)})

	case "cose.sign1":
		alg := int(u64(in, "alg"))
		if alg == 0 {
			if f, ok := in["alg"].(float64); ok {
				alg = int(f)
			}
		}
		seed, err := hx(in, "seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		prot, err := hx(in, "protected_hex")
		if err != nil {
			return errf("%v", err)
		}
		payload, err := hx(in, "payload_hex")
		if err != nil {
			return errf("%v", err)
		}
		signer, _, err := mldsaKeyFromSeed(alg, seed)
		if err != nil {
			return errf("%v", err)
		}
		tbs, err := cose.ToBeSignedRaw(prot, payload)
		if err != nil {
			return errf("%v", err)
		}
		sig, err := signer.Sign(tbs)
		if err != nil {
			return errf("%v", err)
		}
		obj, err := cose.AssembleSign1Raw(prot, payload, sig)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"obj_hex": toHex(obj)})

	case "cose.verify1":
		alg := int(intOf(in["alg"]))
		pub, err := hx(in, "pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		obj, err := hx(in, "obj_hex")
		if err != nil {
			return errf("%v", err)
		}
		v, err := verifierFor(alg, pub)
		if err != nil {
			return errf("%v", err)
		}
		prot, payload, sig, err := cose.ParseSign1Raw(obj)
		if err != nil {
			return errf("%v", err)
		}
		tbs, err := cose.ToBeSignedRaw(prot, payload)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"valid": v.VerifyRaw(tbs, sig)})

	case "signerid":
		alg := int(intOf(in["alg"]))
		pub, err := hx(in, "pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		id, err := identity.SignerID(alg, pub)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"signer_id": id})

	case "nfc.check":
		b, err := hx(in, "utf8_hex")
		if err != nil {
			return errf("%v", err)
		}
		if err := identity.RequireNFC(string(b)); err != nil {
			return errf("%v", err) // NonNFC -> rejected
		}
		return out(map[string]interface{}{"ok": true})

	case "effect.normalize":
		e := policy.NormalizeEffect(u64(in, "value"))
		return out(map[string]interface{}{"effect": int(e)})

	case "effect.authorize":
		granted := policy.NormalizeEffect(u64(in, "granted"))
		effect := policy.Effect(u64(in, "effect"))
		return out(map[string]interface{}{"allow": granted.Authorizes(effect)})

	case "effect.safety_label":
		sl := policy.SafetyLabel{Risk: str(in, "risk"), Scope: str(in, "scope")}
		b, err := sl.Encode()
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"cbor_hex": toHex(b)})

	case "approval.body", "approval.id":
		approves, err := hx(in, "approves_hex")
		if err != nil {
			return errf("%v", err)
		}
		nonce, err := hx(in, "nonce_hex")
		if err != nil {
			return errf("%v", err)
		}
		a := approval.ApprovalRecord{
			Approves: approves, Approver: str(in, "approver"),
			Grant: u64(in, "grant"), Nonce: nonce, NotAfter: u64(in, "not_after"),
		}
		if req.Op == "approval.id" {
			return out(map[string]interface{}{"id_hex": toHex(a.ID())})
		}
		return out(map[string]interface{}{"body_hex": toHex(a.Bytes())})

	case "ledger.entry":
		prev, err := hx(in, "prev_hex")
		if err != nil {
			return errf("%v", err)
		}
		aid, err := hx(in, "approval_id_hex")
		if err != nil {
			return errf("%v", err)
		}
		e := approval.LedgerEntry{Seq: u64(in, "seq"), Prev: prev, ApprovalID: aid, By: str(in, "by")}
		return out(map[string]interface{}{"body_hex": toHex(e.Bytes())})

	case "receipt.body":
		prev, err := hx(in, "prev_hex")
		if err != nil {
			return errf("%v", err)
		}
		obj, err := hx(in, "obj_hex")
		if err != nil {
			return errf("%v", err)
		}
		r := audit.Receipt{Prev: prev, Obj: obj, Seq: u64(in, "seq"), At: u64(in, "at")}
		return out(map[string]interface{}{"body_hex": toHex(r.Bytes())})

	case "receipt.head":
		body, err := hx(in, "body_hex")
		if err != nil {
			return errf("%v", err)
		}
		d := sha512.Sum384(body)
		return out(map[string]interface{}{"head_hex": toHex(d[:])})

	case "forkproof.preimage":
		// The draft-01 fork-proof framing witness (signatures elided): rebuild the two conflicting
		// receipts and encode the ForkProof body with empty sig fields. Graded against the oracle.
		signer, err := hx(in, "signer_hex")
		if err != nil {
			return errf("%v", err)
		}
		prev, err := hx(in, "prev_hex")
		if err != nil {
			return errf("%v", err)
		}
		objA, err := hx(in, "obj_a_hex")
		if err != nil {
			return errf("%v", err)
		}
		objB, err := hx(in, "obj_b_hex")
		if err != nil {
			return errf("%v", err)
		}
		seq, at := u64(in, "seq"), u64(in, "at")
		a := audit.Receipt{Prev: prev, Obj: objA, Seq: seq, At: at}
		b := audit.Receipt{Prev: prev, Obj: objB, Seq: seq, At: at}
		fp := audit.NewForkProof(signer, a, nil, b, nil, u64(in, "ext_counter"))
		return out(map[string]interface{}{"preimage_hex": toHex(fp.Preimage())})

	case "forkproof.body":
		// The full draft-01 fork-proof body WITH the accused authority's two real (deterministic)
		// signatures over body-a and body-b. Used for the cross-implementation byte-parity check on
		// the complete signed object (Go == Rust); the deterministic ML-DSA sigs have no committed
		// KAT (see cose.sign1), so the corpus marks this "acceptable" and consensus grades it.
		seed, err := hx(in, "seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		signer, err := hx(in, "signer_hex")
		if err != nil {
			return errf("%v", err)
		}
		prev, err := hx(in, "prev_hex")
		if err != nil {
			return errf("%v", err)
		}
		objA, err := hx(in, "obj_a_hex")
		if err != nil {
			return errf("%v", err)
		}
		objB, err := hx(in, "obj_b_hex")
		if err != nil {
			return errf("%v", err)
		}
		seq, at := u64(in, "seq"), u64(in, "at")
		a := audit.Receipt{Prev: prev, Obj: objA, Seq: seq, At: at}
		b := audit.Receipt{Prev: prev, Obj: objB, Seq: seq, At: at}
		signer1, _, err := mldsaKeyFromSeed(cose.AlgMLDSA65, seed)
		if err != nil {
			return errf("%v", err)
		}
		sigA, err := signer1.Sign(a.Bytes())
		if err != nil {
			return errf("%v", err)
		}
		sigB, err := signer1.Sign(b.Bytes())
		if err != nil {
			return errf("%v", err)
		}
		fp := audit.NewForkProof(signer, a, sigA, b, sigB, u64(in, "ext_counter"))
		return out(map[string]interface{}{
			"body_hex":     toHex(fp.Bytes()),
			"preimage_hex": toHex(fp.Preimage()),
			"sig_a_hex":    toHex(sigA),
			"sig_b_hex":    toHex(sigB),
		})

	case "causal.verify":
		nodes, err := nodesFrom(in)
		if err != nil {
			return errf("%v", err)
		}
		if err := audit.VerifyCausal(nodes); err != nil {
			return errf("%v", err) // CausalViolation -> rejected
		}
		return out(map[string]interface{}{"valid": true})

	case "delivery.update":
		obj, err := hx(in, "obj_hex")
		if err != nil {
			return errf("%v", err)
		}
		d := delivery.DeliveryUpdate{Obj: obj, Stage: u64(in, "stage"), At: u64(in, "at")}
		return out(map[string]interface{}{"body_hex": toHex(d.Bytes())})

	case "stream.digest":
		raw, _ := in["chunks"].([]interface{})
		chunks := make([]streaming.Chunk, 0, len(raw))
		for _, r := range raw {
			cm, _ := r.(map[string]interface{})
			data, err := hex.DecodeString(str(cm, "data_hex"))
			if err != nil {
				return errf("%v", err)
			}
			chunks = append(chunks, streaming.Chunk{Offset: u64(cm, "offset"), Data: data})
		}
		return out(map[string]interface{}{"digest_hex": toHex(streaming.CommitDigest(chunks))})

	case "stream.open":
		sid, err := hx(in, "stream_id_hex")
		if err != nil {
			return errf("%v", err)
		}
		var approvalID []byte
		if s, ok := in["approval_hex"].(string); ok && s != "" {
			if approvalID, err = hex.DecodeString(s); err != nil {
				return errf("%v", err)
			}
		}
		o := streaming.StreamOpen{StreamID: sid, Effect: u64(in, "effect"), Approval: approvalID, SubStream: u64(in, "substream")}
		return out(map[string]interface{}{"body_hex": toHex(o.Bytes())})

	case "stream.commit":
		sid, err := hx(in, "stream_id_hex")
		if err != nil {
			return errf("%v", err)
		}
		dg, err := hx(in, "digest_hex")
		if err != nil {
			return errf("%v", err)
		}
		c := streaming.StreamCommit{StreamID: sid, Digest: dg}
		return out(map[string]interface{}{"body_hex": toHex(c.Bytes())})

	case "stream.checkpoint":
		sid, err := hx(in, "stream_id_hex")
		if err != nil {
			return errf("%v", err)
		}
		dg, err := hx(in, "digest_so_far_hex")
		if err != nil {
			return errf("%v", err)
		}
		c := streaming.StreamCheckpoint{StreamID: sid, ThroughOffset: u64(in, "through_offset"), DigestSoFar: dg}
		return out(map[string]interface{}{"body_hex": toHex(c.Bytes())})

	case "stream.state":
		// design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream
		// through an ordered `events` list on a fresh Guard; report the LAST event's outcome
		// plus the stream's final state. Graded against the independent, non-circular
		// tools/streamstate_oracle.py (F3).
		rawEvents, _ := in["events"].([]interface{})
		g := streaming.NewGuard()
		var lastErr error
		var lastStream []byte
		for _, re := range rawEvents {
			em, ok := re.(map[string]interface{})
			if !ok {
				return errf("stream.state: event is not an object")
			}
			sid, err := hx(em, "stream_hex")
			if err != nil {
				return errf("%v", err)
			}
			lastStream = sid
			switch str(em, "ev") {
			case "open":
				o := streaming.StreamOpen{StreamID: sid, Effect: u64(em, "effect"), SubStream: 0}
				lastErr = g.Open(o, policy.Effect(u64(em, "granted")))
			case "chunk":
				lastErr = g.Chunk(sid)
			case "checkpoint":
				lastErr = g.Checkpoint(sid)
			case "commit":
				rawChunks, _ := em["chunks"].([]interface{})
				chunks := make([]streaming.Chunk, 0, len(rawChunks))
				for _, rc := range rawChunks {
					cm, _ := rc.(map[string]interface{})
					data, derr := hex.DecodeString(str(cm, "data_hex"))
					if derr != nil {
						return errf("%v", derr)
					}
					chunks = append(chunks, streaming.Chunk{Offset: u64(cm, "offset"), Data: data})
				}
				digest, err := hx(em, "digest_hex")
				if err != nil {
					return errf("%v", err)
				}
				lastErr = g.Commit(streaming.StreamCommit{StreamID: sid, Digest: digest}, chunks)
			case "expire":
				lastErr = g.Expire(sid)
			default:
				return errf("stream.state: unknown event %q", str(em, "ev"))
			}
		}
		return out(map[string]interface{}{
			"valid": lastErr == nil,
			"error": errKind(lastErr),
			"state": g.State(lastStream).String(),
		})

	case "delivery.state":
		// ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
		// through an ordered `events` list of signed delivery updates on a fresh WAL-backed
		// Tracker; report the LAST event's outcome plus the object's final stage name. A
		// rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
		// Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
		rawEvents, _ := in["events"].([]interface{})
		tf, terr := os.CreateTemp("", "naalp-delivery-state-*.wal")
		if terr != nil {
			return errf("%v", terr)
		}
		tf.Close()
		defer os.Remove(tf.Name())
		tr, terr := delivery.OpenTracker(tf.Name())
		if terr != nil {
			return errf("%v", terr)
		}
		defer tr.Close()
		var lastErr error
		var lastObj []byte
		for _, re := range rawEvents {
			em, ok := re.(map[string]interface{})
			if !ok {
				return errf("delivery.state: event is not an object")
			}
			obj, err := hx(em, "obj_hex")
			if err != nil {
				return errf("%v", err)
			}
			lastObj = obj
			switch str(em, "ev") {
			case "update":
				_, lastErr = tr.Advance(obj, u64(em, "stage"), 0)
			default:
				return errf("delivery.state: unknown event %q", str(em, "ev"))
			}
		}
		st, _ := tr.Stage(lastObj)
		return out(map[string]interface{}{
			"valid": lastErr == nil,
			"error": errKind(lastErr),
			"state": delivery.StageName(st),
		})

	case "approval.state":
		// ietf draft "## Approval state machine" (# Object State Machines): build ONE signed approval,
		// then drive it through an ordered `events` list of consume attempts through the REAL composed
		// choke point approval.ConsumeApproval on a fresh single-use ledger; report the LAST event's
		// {valid, error} plus the ledger length after it (the draft's "ledger left untouched by a
		// rejected request", observable via Ledger.Len). Graded against the independent, non-circular
		// tools/approval_state_oracle.py (F3). The approver key is a deterministic Ed25519 test key —
		// the signature is verified, not graded (bytes are not compared across ports for this op).
		am, ok := in["approval"].(map[string]interface{})
		if !ok {
			return errf("approval.state: missing approval object")
		}
		approves, err := hx(am, "approves_hex")
		if err != nil {
			return errf("%v", err)
		}
		nonce, err := hx(am, "nonce_hex")
		if err != nil {
			return errf("%v", err)
		}
		a := approval.ApprovalRecord{
			Approves: approves, Approver: str(am, "approver"),
			Grant: u64(am, "grant"), Nonce: nonce, NotAfter: u64(am, "not_after"),
		}
		seed := make([]byte, ed25519.SeedSize) // deterministic all-zero test approver seed
		priv := ed25519.NewKeyFromSeed(seed)
		verifier := cose.Ed25519Verifier{PK: priv.Public().(ed25519.PublicKey)}
		sig := ed25519.Sign(priv, a.Bytes())

		tf, terr := os.CreateTemp("", "naalp-approval-state-*.wal")
		if terr != nil {
			return errf("%v", terr)
		}
		tf.Close()
		defer os.Remove(tf.Name())
		ledger, terr := approval.OpenLedger(tf.Name())
		if terr != nil {
			return errf("%v", terr)
		}
		defer ledger.Close()

		rawEvents, _ := in["events"].([]interface{})
		var lastErr error
		for _, re := range rawEvents {
			em, ok := re.(map[string]interface{})
			if !ok {
				return errf("approval.state: event is not an object")
			}
			switch str(em, "ev") {
			case "consume":
				presentCID, err := hx(em, "present_cid_hex")
				if err != nil {
					return errf("%v", err)
				}
				_, lastErr = approval.ConsumeApproval(a, verifier, sig, presentCID,
					u64(em, "pos_time"), policy.Effect(u64(em, "required_effect")), ledger, str(em, "by"))
			default:
				return errf("approval.state: unknown event %q", str(em, "ev"))
			}
		}
		return out(map[string]interface{}{
			"valid":      lastErr == nil,
			"error":      errKind(lastErr),
			"ledger_len": ledger.Len(),
		})

	case "transport.emit":
		t, ok := transport.ByName(str(in, "transport"))
		if !ok {
			return errf("unknown transport %q", str(in, "transport"))
		}
		sensitive, _ := in["sensitive"].(bool)
		requirePeer, _ := in["require_peer_auth"].(bool)
		_, err := transport.Emit(t, []byte{0x00}, sensitive, requirePeer)
		if err == nil {
			return out(map[string]interface{}{"result": "ok"})
		}
		if ce, ok := err.(*cose.Error); ok {
			return out(map[string]interface{}{"result": ce.Kind})
		}
		return out(map[string]interface{}{"result": err.Error()})

	case "carriage.body":
		corr, err := hx(in, "correlation_hex")
		if err != nil {
			return errf("%v", err)
		}
		foreign, err := hx(in, "foreign_hex")
		if err != nil {
			return errf("%v", err)
		}
		cb, err := carriage.Carry(u64(in, "protocol_id"), u64(in, "class"), u64(in, "content_type"), corr, str(in, "method"), foreign)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"body_hex": toHex(cb.Bytes())})

	case "channels.lookup":
		ks, ok := channels.Lookup(u64(in, "channel"), u64(in, "kind"))
		if !ok {
			return errf("UnknownKind")
		}
		return out(map[string]interface{}{"name": ks.Name, "effect": int(ks.Effect), "variable": ks.Variable})

	case "channels.effect_check":
		if err := channels.CheckEffect(u64(in, "channel"), u64(in, "kind"), u64(in, "effect")); err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"ok": true})

	case "federation.reconcile":
		nodes, err := nodesFrom(in)
		if err != nil {
			return errf("%v", err)
		}
		order, err := federation.Reconcile(nodes)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"order": hexList(order)})

	case "federation.record":
		authRaw, _ := in["authorities"].([]interface{})
		auths := make([]string, 0, len(authRaw))
		for _, a := range authRaw {
			auths = append(auths, a.(string))
		}
		ordRaw, _ := in["order"].([]interface{})
		order := make([][]byte, 0, len(ordRaw))
		for _, o := range ordRaw {
			b, err := hex.DecodeString(o.(string))
			if err != nil {
				return errf("%v", err)
			}
			order = append(order, b)
		}
		r := federation.ReconcileRecord{Authorities: auths, Order: order}
		return out(map[string]interface{}{"body_hex": toHex(r.Bytes())})

	case "reconcile.state":
		// ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine
		// through ONE event (add-chain | linearize | verify) on fresh state and report
		// {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe pipeline
		// (a `chain` that must independently pass VerifyChain, plus an optional `extra` receipt
		// fed only to Observe — a chain array cannot itself carry a duplicate seq without
		// independently tripping ChainBroken, so equivocation is exercised via the separate
		// `extra` observation); linearize runs federation.Reconcile (which calls
		// audit.VerifyCausal internally); verify runs federation.VerifyReconcileOrder, which MUST
		// recompute via Reconcile (content-id tie-break), never audit.TopoOrder (position
		// tie-break). Graded against the independent, non-circular
		// tools/reconcile_state_oracle.py (F3). The authority key is a deterministic all-zero
		// Ed25519 test seed — the signature is verified, not graded (bytes are not compared
		// across ports for this op).
		seed := make([]byte, ed25519.SeedSize) // deterministic all-zero test authority seed
		priv := ed25519.NewKeyFromSeed(seed)
		signerID := priv.Public().(ed25519.PublicKey)
		verifier := cose.Ed25519Verifier{PK: signerID}

		buildReceipt := func(rm map[string]interface{}) (audit.Receipt, error) {
			prev, err := hx(rm, "prev_hex")
			if err != nil {
				return audit.Receipt{}, err
			}
			obj, err := hx(rm, "obj_hex")
			if err != nil {
				return audit.Receipt{}, err
			}
			return audit.Receipt{Prev: prev, Obj: obj, Seq: u64(rm, "seq"), At: u64(rm, "at")}, nil
		}

		switch str(in, "event") {
		case "add-chain":
			rawChain, _ := in["chain"].([]interface{})
			receipts := make([]audit.Receipt, 0, len(rawChain))
			sigs := make([][]byte, 0, len(rawChain))
			for _, rc := range rawChain {
				rm, _ := rc.(map[string]interface{})
				r, err := buildReceipt(rm)
				if err != nil {
					return errf("%v", err)
				}
				receipts = append(receipts, r)
				sigs = append(sigs, ed25519.Sign(priv, r.Bytes()))
			}
			if ci, ok := in["corrupt_sig_at"].(float64); ok {
				idx := int(ci)
				corrupted := append([]byte(nil), sigs[idx]...)
				corrupted[0] ^= 0xFF
				sigs[idx] = corrupted
			}
			lastErr := audit.VerifyChain(receipts, sigs, verifier)
			if lastErr == nil {
				auditor := audit.NewAuditor(verifier, signerID)
				for i, r := range receipts {
					if _, oerr := auditor.Observe(r, sigs[i]); oerr != nil {
						lastErr = oerr
						break
					}
				}
				if lastErr == nil {
					if em, ok := in["extra"].(map[string]interface{}); ok {
						er, err := buildReceipt(em)
						if err != nil {
							return errf("%v", err)
						}
						esig := ed25519.Sign(priv, er.Bytes())
						if _, oerr := auditor.Observe(er, esig); oerr != nil {
							lastErr = oerr
						}
					}
				}
			}
			return out(map[string]interface{}{"valid": lastErr == nil, "error": errKind(lastErr)})

		case "linearize":
			nodes, err := nodesFrom(in)
			if err != nil {
				return errf("%v", err)
			}
			_, lastErr := federation.Reconcile(nodes)
			return out(map[string]interface{}{"valid": lastErr == nil, "error": errKind(lastErr)})

		case "verify":
			nodes, err := nodesFrom(in)
			if err != nil {
				return errf("%v", err)
			}
			rawOrder, _ := in["claimed_order_hex"].([]interface{})
			order := make([][]byte, 0, len(rawOrder))
			for _, o := range rawOrder {
				b, err := hex.DecodeString(o.(string))
				if err != nil {
					return errf("%v", err)
				}
				order = append(order, b)
			}
			rec := federation.ReconcileRecord{Order: order}
			lastErr := federation.VerifyReconcileOrder(rec, nodes)
			return out(map[string]interface{}{"valid": lastErr == nil, "error": errKind(lastErr)})

		default:
			return errf("reconcile.state: unknown event %q", str(in, "event"))
		}

	// ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
	case "composite.mprime":
		m, err := hx(in, "m_hex")
		if err != nil {
			return errf("%v", err)
		}
		mp := cose.ComputeMprime([]byte("COMPSIG-MLDSA65-Ed25519-SHA512"), nil, m)
		return out(map[string]interface{}{"mprime_hex": toHex(mp)})

	case "composite.signerid":
		mlPub, err := hx(in, "mldsa_pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		edPub, err := hx(in, "ed_pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		id, err := identity.CompositeSignerID(int(intOf(in["mldsa_alg"])), mlPub, edPub)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"signer_id": id})

	case "composite.sign":
		mlSeed, err := hx(in, "mldsa_seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		edSeed, err := hx(in, "ed_seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		tbs, err := hx(in, "tbs_hex")
		if err != nil {
			return errf("%v", err)
		}
		if len(mlSeed) != 32 || len(edSeed) != ed25519.SeedSize {
			return errf("composite seeds must be 32 bytes")
		}
		var s [32]byte
		copy(s[:], mlSeed)
		_, sk := mldsa65.NewKeyFromSeed(&s)
		signer := cose.CompositeSigner{ML65: sk, Ed: ed25519.NewKeyFromSeed(edSeed)}
		val, err := signer.Sign(tbs)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"value_hex": toHex(val)})

	case "composite.verify":
		mlPub, err := hx(in, "mldsa_pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		edPub, err := hx(in, "ed_pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		m, err := hx(in, "m_hex")
		if err != nil {
			return errf("%v", err)
		}
		sig, err := hx(in, "sig_hex")
		if err != nil {
			return errf("%v", err)
		}
		mlPK := new(mldsa65.PublicKey)
		if err := mlPK.UnmarshalBinary(mlPub); err != nil {
			return errf("%v", err)
		}
		if len(edPub) != ed25519.PublicKeySize {
			return errf("bad ed25519 public key length")
		}
		v := cose.CompositeVerifier{ML65: mlPK, Ed: ed25519.PublicKey(edPub)}
		return out(map[string]interface{}{"valid": cose.VerifyComposite(v, m, sig) == nil})

	// ---- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) — #143 ----
	case "rotation.leg_tbs":
		// committed KAT: the per-leg "Signature" Sig_structure ToBeSigned (RFC 9052 §4.4).
		prot, err := hx(in, "body_protected_hex")
		if err != nil {
			return errf("%v", err)
		}
		alg := int(intOf(in["leg_alg"]))
		payload, err := hx(in, "payload_hex")
		if err != nil {
			return errf("%v", err)
		}
		tbs, err := cose.SignatureToBeSigned(prot, alg, payload)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"tbs_hex": toHex(tbs)})

	case "rotation.sign":
		// build the tag-98 object over the supplied body protected header + payload with the
		// old-then-new legs (low-level multi-leg COSE_Sign primitive; consensus + oracle pin).
		oldAlg := int(intOf(in["old_alg"]))
		oldSeed, err := hx(in, "old_seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		newAlg := int(intOf(in["new_alg"]))
		newSeed, err := hx(in, "new_seed_hex")
		if err != nil {
			return errf("%v", err)
		}
		prot, err := hx(in, "protected_hex")
		if err != nil {
			return errf("%v", err)
		}
		payload, err := hx(in, "payload_hex")
		if err != nil {
			return errf("%v", err)
		}
		oldSigner, _, err := mldsaKeyFromSeed(oldAlg, oldSeed)
		if err != nil {
			return errf("%v", err)
		}
		newSigner, _, err := mldsaKeyFromSeed(newAlg, newSeed)
		if err != nil {
			return errf("%v", err)
		}
		oldLeg, err := cose.SignatureLeg(prot, oldSigner, payload)
		if err != nil {
			return errf("%v", err)
		}
		newLeg, err := cose.SignatureLeg(prot, newSigner, payload)
		if err != nil {
			return errf("%v", err)
		}
		obj, err := cose.AssembleSignRaw(prot, payload, []cose.CoseSignLeg{oldLeg, newLeg})
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"obj_hex": toHex(obj)})

	case "rotation.verify":
		// run the full envelope VerifyRotationObject and report the verdict (valid + error kind).
		obj, err := hx(in, "obj_hex")
		if err != nil {
			return errf("%v", err)
		}
		oldAlg := int(intOf(in["old_alg"]))
		oldPub, err := hx(in, "old_pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		newAlg := int(intOf(in["new_alg"]))
		newPub, err := hx(in, "new_pubkey_hex")
		if err != nil {
			return errf("%v", err)
		}
		profile := int(intOf(in["profile"]))
		oldV, err := verifierFor(oldAlg, oldPub)
		if err != nil {
			return errf("%v", err)
		}
		newV, err := verifierFor(newAlg, newPub)
		if err != nil {
			return errf("%v", err)
		}
		kindOK := func(ch, k uint64) bool { return ch == 3 && k == 0 }
		// Dispatch as a real receiver does — parse the COSE tag: a tag-98 (0xd8 0x62) Rotation
		// object goes to the two-leg VerifyRotationObject; a tag-18 (single-signature) object goes
		// to the general Verify, which rejects a channel-3/kind-0 single-sig rotation
		// RotationUnauthorized (the single-Sign1 rotation-gap fix, §5.2). The go-forward (new) key
		// is the tag-18 object's sole signer.
		var verr error
		if len(obj) >= 2 && obj[0] == 0xd8 && obj[1] == 0x62 {
			_, verr = envelope.VerifyRotationObject(profile, oldV, newV, kindOK, nil, obj)
		} else {
			_, verr = envelope.Verify(profile, newV, kindOK, nil, obj)
		}
		return out(map[string]interface{}{"valid": verr == nil, "error": errKind(verr)})

	case "object.decode":
		// R7 decoder resource bounds (design.md §3.4): decode + bound-enforce an untrusted object
		// and report the verdict (valid + named error kind). All four object-level bounds fire
		// before the COSE signature is checked, so no verifier is needed; over_size materializes
		// the object octet-size bound locally (rejected on raw length before any parse).
		var obj []byte
		if _, ok := in["over_size"]; ok {
			obj = make([]byte, int(intOf(in["over_size"])))
		} else {
			var err error
			obj, err = hx(in, "obj_hex")
			if err != nil {
				return errf("%v", err)
			}
		}
		kindOK := func(ch, k uint64) bool { return true }
		_, verr := envelope.Verify(1, nil, kindOK, nil, obj)
		return out(map[string]interface{}{"valid": verr == nil, "error": errKind(verr)})

	case "stream.verify_commit":
		// R7 stream chunk-count bound: materialize the over-limit chunk set and verify the commit;
		// the count check fires before the digest check, so the reject is TooManyChunks.
		n := int(intOf(in["chunk_count"]))
		chunks := make([]streaming.Chunk, n)
		verr := streaming.VerifyCommit(streaming.StreamCommit{}, chunks)
		return out(map[string]interface{}{"valid": verr == nil, "error": errKind(verr)})

	case "error.name_for_code":
		// T3.3: the naalp-error registry table lookup (design.md §3.5). Grades the port's embedded
		// 119-entry name<->code table per-code, plus the unknown-code (opaque) contract.
		name, reg := naalperror.NameForCode(uint64(intOf(in["code"])))
		return out(map[string]interface{}{"name": name, "registered": reg})

	case "error.encode":
		// T3.3: deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail, ?4:subject}.
		var subj []byte
		if _, ok := in["subject_hex"]; ok {
			s, err := hx(in, "subject_hex")
			if err != nil {
				return errf("%v", err)
			}
			subj = s
		}
		detail, _ := in["detail"].(string)
		name, _ := in["name"].(string)
		b, err := naalperror.Encode(uint64(intOf(in["code"])), name, detail, subj)
		if err != nil {
			return errf("%v", err)
		}
		return out(map[string]interface{}{"body_hex": hex.EncodeToString(b)})

	case "error.decode":
		// T3.3: parse + dual-carriage validate a naalp-error body (registered code + wrong name ->
		// Malformed; unknown code -> opaque accept).
		body, err := hx(in, "body_hex")
		if err != nil {
			return errf("%v", err)
		}
		eo, derr := naalperror.Decode(body)
		if derr != nil {
			return out(map[string]interface{}{"valid": false, "error": errKind(derr)})
		}
		return out(map[string]interface{}{"valid": true, "code": eo.Code, "name": eo.Name})

	default:
		return response{Skipped: "op not implemented: " + req.Op}
	}
}

// errKind returns the canonical error kind (the cose.Error.Kind used across the registry) for a
// rotation verify failure, or "" for success.
func errKind(err error) string {
	if err == nil {
		return ""
	}
	if ce, ok := err.(*cose.Error); ok {
		return ce.Kind
	}
	return err.Error()
}

func intOf(v interface{}) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	default:
		return 0
	}
}

// ---- framing loop ----

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	var lp [4]byte
	for {
		if _, err := io.ReadFull(r, lp[:]); err != nil {
			if err == io.EOF {
				return
			}
			fmt.Fprintln(os.Stderr, "read len:", err)
			return
		}
		n := binary.LittleEndian.Uint32(lp[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			fmt.Fprintln(os.Stderr, "read body:", err)
			return
		}
		var req request
		var resp response
		if err := json.Unmarshal(body, &req); err != nil {
			resp = errf("bad request json: %v", err)
		} else {
			resp = handle(req)
		}
		ob, err := json.Marshal(resp)
		if err != nil {
			ob, _ = json.Marshal(errf("marshal response: %v", err))
		}
		binary.LittleEndian.PutUint32(lp[:], uint32(len(ob)))
		w.Write(lp[:])
		w.Write(ob)
		w.Flush()
	}
}
