// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// checkpoint.go implements S3 — naalp-checkpoint-root, naalp-witness-cosign, and
// naalp-inclusion-proof: the neither-party anchor for the BINDING-FIXED-BY-T leg of the
// accountability triple (design.md §26.5; spec/naalp-draft-01.cddl `naalp-checkpoint-root` /
// `naalp-witness-cosign` / `naalp-inclusion-proof`).
//
// Tree construction follows RFC 9162 (https://www.rfc-editor.org/rfc/rfc9162.html) §2.1 EXACTLY,
// SHA-384-profiled: leaf hash = HASH(0x00 || leaf); interior node hash = HASH(0x01 || left ||
// right); MTH({}) = HASH() (the empty hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) =
// NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest power of two k < n. §2.1.2's PATH(m, D[n])
// recursion (leaf-to-root sibling order: PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) when m < k,
// else PATH(m-k, D[k:n]) : MTH(D[0:k])) generates the audit path; §2.1.3.1's inverse recursion
// recomputes the root from (leaf, index, size, path) and compares against the named root
// (InclusionProofInvalid on mismatch, fail-closed).
//
// naalp-checkpoint-root is a log operator's signed Merkle tree head over a leaf set of record
// content ids, chaining by `prev` (genesis = HeadSize zero bytes) exactly as the C7 audit chain
// (§8.1). naalp-witness-cosign carries the wire hook for an independent countersignature over one
// exact checkpoint by content id; naalp-inclusion-proof proves one record's content id was a leaf
// under a named checkpoint. Two witness-cosigned roots at one (log, size) carrying different root
// values are fork evidence — the log has signed two incompatible histories.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error,
// and causes no state change — no ledger append, no checkpoint update.
package gateway

import (
	"bytes"
	"errors"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
)

// Named, fail-closed errors (§26.8). A bad signature is the existing cose.ErrBadSignature reused
// unchanged.
var (
	ErrCheckpointMalformed     = &cose.Error{Kind: "CheckpointMalformed", Msg: "object is not a well-formed N-AALP checkpoint-root body"}
	ErrWitnessCosignMalformed  = &cose.Error{Kind: "CheckpointMalformed", Msg: "object is not a well-formed N-AALP witness-cosign body"}
	ErrInclusionProofMalformed = &cose.Error{Kind: "CheckpointMalformed", Msg: "object is not a well-formed N-AALP inclusion-proof body"}
	ErrWitnessRootMismatch     = &cose.Error{Kind: "WitnessRootMismatch", Msg: "witness-cosign names a root content id that does not match the checkpoint it accompanies"}
	ErrInclusionProofInvalid   = &cose.Error{Kind: "InclusionProofInvalid", Msg: "inclusion audit path does not recompute to the named root"}
)

// errPathLengthMismatch is an internal sentinel: the recursive root recomputation ran out of path
// entries (or had entries left over) before reaching the single-leaf base case. Always surfaced to
// callers as ErrInclusionProofInvalid — never exported.
var errPathLengthMismatch = errors.New("inclusion path length does not match the claimed tree size")

// ---- naalp-checkpoint-root ---------------------------------------------------------------------

// CheckpointRoot is a log operator's signed Merkle tree head over a leaf set of record content ids
// (design.md §26.5).
type CheckpointRoot struct {
	Log  []byte // the log operator's signer id
	Size uint64 // leaf count at this checkpoint
	Root []byte // the Merkle tree head over the leaf set (HeadSize bytes)
	Prev []byte // the prior checkpoint root value (HeadSize bytes; genesis is GenesisPrev())
	At   uint64 // the log's time anchor, epoch ms (advisory)
}

// GenesisPrev is the HeadSize all-zero prev value a log's first checkpoint chains from.
func GenesisPrev() []byte { return make([]byte, HeadSize) }

// Bytes is the deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}.
func (c CheckpointRoot) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(c.Log)},
		{K: cbor.Uint(2), V: cbor.Uint(c.Size)},
		{K: cbor.Uint(3), V: cbor.Bstr(c.Root)},
		{K: cbor.Uint(4), V: cbor.Bstr(c.Prev)},
		{K: cbor.Uint(5), V: cbor.Uint(c.At)},
	})
	return b
}

// Head is the checkpoint's SHA-384 head (48 octets) — the `prev` the NEXT checkpoint chains from.
func (c CheckpointRoot) Head() []byte { return head(c.Bytes()) }

// ID is the checkpoint's T1 content-id (50 octets) — what an inclusion proof's `root` field and a
// witness-cosign's `root` field both name.
func (c CheckpointRoot) ID() []byte { return contentID(c.Bytes()) }

// ParseCheckpointRoot reconstructs a CheckpointRoot from its body bytes alone. Fail-closed on any
// malformed shape (CheckpointMalformed): every one of the five fields is mandatory.
func ParseCheckpointRoot(b []byte) (CheckpointRoot, error) {
	m, ok := decodeMap(b)
	if !ok {
		return CheckpointRoot{}, ErrCheckpointMalformed
	}
	log, ok1 := bstrField(m, 1)
	size, ok2 := uintField(m, 2)
	root, ok3 := bstrField(m, 3)
	prev, ok4 := bstrField(m, 4)
	at, ok5 := uintField(m, 5)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return CheckpointRoot{}, ErrCheckpointMalformed
	}
	return CheckpointRoot{Log: log, Size: size, Root: root, Prev: prev, At: at}, nil
}

// SignCheckpointRoot produces the tagged COSE_Sign1 object over the checkpoint body, signed by the
// log operator.
func SignCheckpointRoot(c CheckpointRoot, s cose.Signer) ([]byte, error) { return cose.Sign1(s, c.Bytes()) }

// ---- naalp-witness-cosign -----------------------------------------------------------------------

// WitnessCosign is a witness's countersignature over one exact checkpoint by content id
// (design.md §26.5). Whether the witness's observational domain is genuinely distinct from both
// parties to the decisions the checkpoint covers is a structural deployment fact checkable in
// substance at T+n — the wire supplies the hook; it does not manufacture the independence itself.
type WitnessCosign struct {
	Witness []byte // the witness's signer id
	Root    []byte // content id of the exact naalp-checkpoint-root cosigned
	At      uint64 // the witness's own time anchor, epoch ms (advisory)
}

// Bytes is the deterministic-CBOR encoding {1:witness, 2:root, 3:at}.
func (w WitnessCosign) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(w.Witness)},
		{K: cbor.Uint(2), V: cbor.Bstr(w.Root)},
		{K: cbor.Uint(3), V: cbor.Uint(w.At)},
	})
	return b
}

// Head is the cosign's SHA-384 head (48 octets).
func (w WitnessCosign) Head() []byte { return head(w.Bytes()) }

// ID is the cosign's T1 content-id (50 octets).
func (w WitnessCosign) ID() []byte { return contentID(w.Bytes()) }

// ParseWitnessCosign reconstructs a WitnessCosign from its body bytes alone. Fail-closed on any
// malformed shape: every one of the three fields is mandatory.
func ParseWitnessCosign(b []byte) (WitnessCosign, error) {
	m, ok := decodeMap(b)
	if !ok {
		return WitnessCosign{}, ErrWitnessCosignMalformed
	}
	witness, ok1 := bstrField(m, 1)
	root, ok2 := bstrField(m, 2)
	at, ok3 := uintField(m, 3)
	if !ok1 || !ok2 || !ok3 {
		return WitnessCosign{}, ErrWitnessCosignMalformed
	}
	return WitnessCosign{Witness: witness, Root: root, At: at}, nil
}

// SignWitnessCosign produces the tagged COSE_Sign1 object over the cosign body, signed by the
// witness.
func SignWitnessCosign(w WitnessCosign, s cose.Signer) ([]byte, error) { return cose.Sign1(s, w.Bytes()) }

// ValidateWitnessCosign checks that w names the EXACT checkpoint it accompanies
// (WitnessRootMismatch, §26.5/§26.8): w.Root must equal accompaniedCheckpointID, the content id of
// the naalp-checkpoint-root object w claims to cosign. Fail-closed.
func ValidateWitnessCosign(w WitnessCosign, accompaniedCheckpointID []byte) error {
	if !bytes.Equal(w.Root, accompaniedCheckpointID) {
		return ErrWitnessRootMismatch
	}
	return nil
}

// ---- naalp-inclusion-proof ----------------------------------------------------------------------

// InclusionProof proves one record's content id existed as a leaf under a named checkpoint
// (design.md §26.5, RFC 9162 §2.1.3.1).
type InclusionProof struct {
	Root  []byte   // content id of the naalp-checkpoint-root proven against
	Leaf  []byte   // the included record's content id (the leaf value)
	Index uint64   // the leaf's 0-based position in the tree
	Path  [][]byte // the audit path, leaf-to-root sibling hashes (HeadSize bytes each)
}

// Bytes is the deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}.
func (p InclusionProof) Bytes() []byte {
	arr := make(cbor.Arr, len(p.Path))
	for i, s := range p.Path {
		arr[i] = cbor.Bstr(s)
	}
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(p.Root)},
		{K: cbor.Uint(2), V: cbor.Bstr(p.Leaf)},
		{K: cbor.Uint(3), V: cbor.Uint(p.Index)},
		{K: cbor.Uint(4), V: arr},
	})
	return b
}

// Head is the proof's SHA-384 head (48 octets).
func (p InclusionProof) Head() []byte { return head(p.Bytes()) }

// ID is the proof's T1 content-id (50 octets).
func (p InclusionProof) ID() []byte { return contentID(p.Bytes()) }

// ParseInclusionProof reconstructs an InclusionProof from its body bytes alone. Fail-closed on any
// malformed shape: every one of the four fields is mandatory.
func ParseInclusionProof(b []byte) (InclusionProof, error) {
	m, ok := decodeMap(b)
	if !ok {
		return InclusionProof{}, ErrInclusionProofMalformed
	}
	root, ok1 := bstrField(m, 1)
	leaf, ok2 := bstrField(m, 2)
	index, ok3 := uintField(m, 3)
	pathV, ok4 := field(m, 4)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return InclusionProof{}, ErrInclusionProofMalformed
	}
	arr, ok := pathV.(cbor.Arr)
	if !ok {
		return InclusionProof{}, ErrInclusionProofMalformed
	}
	path := make([][]byte, len(arr))
	for i, e := range arr {
		bs, ok := e.(cbor.Bstr)
		if !ok {
			return InclusionProof{}, ErrInclusionProofMalformed
		}
		path[i] = []byte(bs)
	}
	return InclusionProof{Root: root, Leaf: leaf, Index: index, Path: path}, nil
}

// ---- RFC 9162 §2.1 Merkle tree math (SHA-384-profiled) ------------------------------------------

// leafHash = HASH(0x00 || leaf) (RFC 9162 §2.1's LEAF_HASH, leaf/interior domain separation).
func leafHash(leaf []byte) []byte {
	b := make([]byte, 0, 1+len(leaf))
	b = append(b, 0x00)
	b = append(b, leaf...)
	return head(b)
}

// nodeHash = HASH(0x01 || left || right) (RFC 9162 §2.1's NODE_HASH).
func nodeHash(l, r []byte) []byte {
	b := make([]byte, 0, 1+len(l)+len(r))
	b = append(b, 0x01)
	b = append(b, l...)
	b = append(b, r...)
	return head(b)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n (n > 1), per RFC
// 9162 §2.1's k = "the largest power of two smaller than n" (2^k < n <= 2^(k+1) in the RFC's own
// terms, i.e. the split point).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for 2*k < n {
		k *= 2
	}
	return k
}

// MerkleRoot computes MTH(leaves) per RFC 9162 §2.1: MTH({}) = HASH() (SHA-384 of the empty
// string); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the
// largest power of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied
// internally — callers never hash a leaf before calling MerkleRoot.
func MerkleRoot(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return head(nil) // MTH({}) = HASH(""), the empty-list base case (RFC 9162 §2.1.1)
	}
	if n == 1 {
		return leafHash(leaves[0])
	}
	k := largestPowerOfTwoLessThan(n)
	return nodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// GenerateInclusionProofPath computes the RFC 9162 §2.1.2 PATH(index, leaves) audit path
// (leaf-to-root sibling order — the array's FIRST entry is the leaf's immediate sibling, the LAST
// is closest to the root, exactly the order naalp-inclusion-proof's `path` field carries).
func GenerateInclusionProofPath(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, ErrInclusionProofInvalid
	}
	return genPath(leaves, index), nil
}

func genPath(leaves [][]byte, index int) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil // PATH(0, {d0}) = {} — the single-leaf base case
	}
	k := largestPowerOfTwoLessThan(n)
	if index < k {
		sub := genPath(leaves[:k], index)
		out := make([][]byte, len(sub)+1)
		copy(out, sub)
		out[len(sub)] = MerkleRoot(leaves[k:])
		return out
	}
	sub := genPath(leaves[k:], index-k)
	out := make([][]byte, len(sub)+1)
	copy(out, sub)
	out[len(sub)] = MerkleRoot(leaves[:k])
	return out
}

// VerifyInclusionProof recomputes the audit path bottom-up (RFC 9162 §2.1.3.1, the inverse of
// PATH()) from (leaf, index, size, path) and compares the result against root. size is the tree
// size the proof is checked against — the resolved naalp-checkpoint-root's own `size` field, NOT
// carried inside naalp-inclusion-proof itself (the proof names the checkpoint by content id; the
// verifier is expected to already hold the resolved checkpoint to learn its size). Fail-closed: any
// mismatch, out-of-range index, or path-length mismatch is InclusionProofInvalid.
func VerifyInclusionProof(leaf []byte, index, size uint64, path [][]byte, root []byte) error {
	if size == 0 || index >= size {
		return ErrInclusionProofInvalid
	}
	got, err := recomputeRoot(leafHash(leaf), int(index), int(size), path)
	if err != nil {
		return ErrInclusionProofInvalid
	}
	if !bytes.Equal(got, root) {
		return ErrInclusionProofInvalid
	}
	return nil
}

// recomputeRoot is the exact structural inverse of genPath: at each level it consumes the LAST
// remaining path entry (closest to the root) as this level's sibling and recurses into the
// appropriate half with the entries that remain.
func recomputeRoot(leafH []byte, index, size int, path [][]byte) ([]byte, error) {
	if size == 1 {
		if len(path) != 0 {
			return nil, errPathLengthMismatch
		}
		return leafH, nil
	}
	if len(path) == 0 {
		return nil, errPathLengthMismatch
	}
	k := largestPowerOfTwoLessThan(size)
	last := path[len(path)-1]
	rest := path[:len(path)-1]
	if index < k {
		left, err := recomputeRoot(leafH, index, k, rest)
		if err != nil {
			return nil, err
		}
		return nodeHash(left, last), nil
	}
	right, err := recomputeRoot(leafH, index-k, size-k, rest)
	if err != nil {
		return nil, err
	}
	return nodeHash(last, right), nil
}
