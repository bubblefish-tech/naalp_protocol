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

	default:
		return response{Skipped: "op not implemented: " + req.Op}
	}
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
