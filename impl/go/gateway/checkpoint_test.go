// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package gateway_test

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/gateway"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const checkpointVectorPath = "../../../vectors/checkpoint/cases.json"

type cpCheckpointVec struct {
	LogHex  string `json:"log_hex"`
	Size    uint64 `json:"size"`
	RootHex string `json:"root_hex"`
	PrevHex string `json:"prev_hex"`
	AtStr   string `json:"at_str"`
	BodyHex string `json:"body_hex"`
	HeadHex string `json:"head_hex"`
	IDHex   string `json:"id_hex"`
}

type cpWitnessVec struct {
	WitnessHex string `json:"witness_hex"`
	RootHex    string `json:"root_hex"`
	AtStr      string `json:"at_str"`
	BodyHex    string `json:"body_hex"`
	HeadHex    string `json:"head_hex"`
	IDHex      string `json:"id_hex"`
}

type cpInclusionVec struct {
	RootHex string   `json:"root_hex"`
	LeafHex string   `json:"leaf_hex"`
	Index   uint64   `json:"index"`
	PathHex []string `json:"path_hex"`
	BodyHex string   `json:"body_hex"`
	HeadHex string   `json:"head_hex"`
	IDHex   string   `json:"id_hex"`
}

type cpVec struct {
	RFC9162FidelityCheck struct {
		LeafCountsChecked          int `json:"leaf_counts_checked"`
		TotalLeafPositionsChecked int `json:"total_leaf_positions_checked"`
	} `json:"rfc9162_fidelity_check"`
	Genesis struct {
		PrevHex string `json:"prev_hex"`
	} `json:"genesis"`
	Checkpoints     map[string]cpCheckpointVec `json:"checkpoints"`
	WitnessCosigns  map[string]cpWitnessVec    `json:"witness_cosigns"`
	ForkEvidence    struct {
		LogHex        string `json:"log_hex"`
		Size          uint64 `json:"size"`
		CheckpointA   struct {
			RootHex       string       `json:"root_hex"`
			IDHex         string       `json:"id_hex"`
			WitnessCosign cpWitnessVec `json:"witness_cosign"`
		} `json:"checkpoint_a"`
		CheckpointB struct {
			RootHex       string       `json:"root_hex"`
			IDHex         string       `json:"id_hex"`
			WitnessCosign cpWitnessVec `json:"witness_cosign"`
		} `json:"checkpoint_b"`
	} `json:"fork_evidence"`
	InclusionProofs map[string]cpInclusionVec `json:"inclusion_proofs"`
	EmptyTreeKAT    struct {
		RootHex string `json:"root_hex"`
	} `json:"empty_tree_kat"`
	Negative struct {
		WitnessRootMismatch struct {
			CheckpointAccompaniedIDHex string `json:"checkpoint_accompanied_id_hex"`
			CosignBodyHex              string `json:"cosign_body_hex"`
			CosignNamesRootHex         string `json:"cosign_names_root_hex"`
			Reject                     string `json:"reject"`
		} `json:"witness_root_mismatch"`
		InclusionWrongIndex struct {
			RootHex      string   `json:"root_hex"`
			LeafHex      string   `json:"leaf_hex"`
			ClaimedIndex uint64   `json:"claimed_index"`
			PathHex      []string `json:"path_hex"`
			Reject       string   `json:"reject"`
		} `json:"inclusion_wrong_index"`
		InclusionWrongPath struct {
			RootHex string   `json:"root_hex"`
			LeafHex string   `json:"leaf_hex"`
			Index   uint64   `json:"index"`
			PathHex []string `json:"path_hex"`
			Reject  string   `json:"reject"`
		} `json:"inclusion_wrong_path"`
		CheckpointKeysOutOfOrder struct {
			CanonicalBodyHex    string `json:"canonical_body_hex"`
			NoncanonicalBodyHex string `json:"noncanonical_body_hex"`
			Reject              string `json:"reject"`
		} `json:"checkpoint_keys_out_of_order"`
		CheckpointMissingField struct {
			BodyHex string `json:"body_hex"`
			Reject  string `json:"reject"`
		} `json:"checkpoint_missing_field"`
	} `json:"negative"`
}

func loadCPVec(t *testing.T) cpVec {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(checkpointVectorPath))
	if err != nil {
		t.Fatalf("read checkpoint vectors: %v", err)
	}
	var v cpVec
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse checkpoint vectors: %v", err)
	}
	return v
}

func cpFrom(t *testing.T, cv cpCheckpointVec) gateway.CheckpointRoot {
	return gateway.CheckpointRoot{Log: hb(t, cv.LogHex), Size: cv.Size, Root: hb(t, cv.RootHex), Prev: hb(t, cv.PrevHex), At: atU64(t, cv.AtStr)}
}

func wcFrom(t *testing.T, wv cpWitnessVec) gateway.WitnessCosign {
	return gateway.WitnessCosign{Witness: hb(t, wv.WitnessHex), Root: hb(t, wv.RootHex), At: atU64(t, wv.AtStr)}
}

// TestCheckpointByteParityAgainstOracle proves Go's encoding of every checkpoint case matches the
// independent RFC-9162 Python oracle byte-for-byte, and that GenesisPrev() is the same 48-zero-byte
// value the oracle's genesis prev uses.
func TestCheckpointByteParityAgainstOracle(t *testing.T) {
	v := loadCPVec(t)
	if got := hex.EncodeToString(gateway.GenesisPrev()); got != v.Genesis.PrevHex {
		t.Fatalf("GenesisPrev() got %s want %s", got, v.Genesis.PrevHex)
	}
	for name, cv := range v.Checkpoints {
		c := cpFrom(t, cv)
		if got := hex.EncodeToString(c.Bytes()); got != cv.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, cv.BodyHex)
		}
		if got := hex.EncodeToString(c.Head()); got != cv.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, cv.HeadHex)
		}
		if got := hex.EncodeToString(c.ID()); got != cv.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, cv.IDHex)
		}
		parsed, err := gateway.ParseCheckpointRoot(c.Bytes())
		if err != nil {
			t.Fatalf("%s ParseCheckpointRoot: %v", name, err)
		}
		if got := hex.EncodeToString(parsed.Bytes()); got != cv.BodyHex {
			t.Fatalf("%s round-trip Bytes\n got %s\nwant %s", name, got, cv.BodyHex)
		}
	}
}

// TestWitnessCosignByteParity proves Go's encoding of every witness-cosign case matches the oracle.
func TestWitnessCosignByteParity(t *testing.T) {
	v := loadCPVec(t)
	for name, wv := range v.WitnessCosigns {
		w := wcFrom(t, wv)
		if got := hex.EncodeToString(w.Bytes()); got != wv.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, wv.BodyHex)
		}
		if got := hex.EncodeToString(w.Head()); got != wv.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, wv.HeadHex)
		}
		if got := hex.EncodeToString(w.ID()); got != wv.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, wv.IDHex)
		}
	}
}

// TestForkEvidence proves two witness-cosigned checkpoints at the SAME (log, size) carrying
// DIFFERENT root values byte-parity-match the oracle, and that each cosign validates cleanly
// against ITS OWN accompanying checkpoint while cross-validating against the OTHER fails
// WitnessRootMismatch — the wire-level shape of fork evidence (design.md §26.5).
func TestForkEvidence(t *testing.T) {
	v := loadCPVec(t)
	fe := v.ForkEvidence

	if fe.CheckpointA.RootHex == fe.CheckpointB.RootHex {
		t.Fatal("fork evidence fixture must carry two DIFFERENT root values")
	}
	if fe.CheckpointA.IDHex == fe.CheckpointB.IDHex {
		t.Fatal("fork evidence fixture must carry two DIFFERENT checkpoint content ids")
	}

	wcA := wcFrom(t, fe.CheckpointA.WitnessCosign)
	wcB := wcFrom(t, fe.CheckpointB.WitnessCosign)
	if got := hex.EncodeToString(wcA.Bytes()); got != fe.CheckpointA.WitnessCosign.BodyHex {
		t.Fatalf("checkpoint_a cosign Bytes\n got %s\nwant %s", got, fe.CheckpointA.WitnessCosign.BodyHex)
	}
	if got := hex.EncodeToString(wcB.Bytes()); got != fe.CheckpointB.WitnessCosign.BodyHex {
		t.Fatalf("checkpoint_b cosign Bytes\n got %s\nwant %s", got, fe.CheckpointB.WitnessCosign.BodyHex)
	}

	idA := hb(t, fe.CheckpointA.IDHex)
	idB := hb(t, fe.CheckpointB.IDHex)
	if err := gateway.ValidateWitnessCosign(wcA, idA); err != nil {
		t.Fatalf("checkpoint_a cosign against its OWN checkpoint: %v, want nil", err)
	}
	if err := gateway.ValidateWitnessCosign(wcB, idB); err != nil {
		t.Fatalf("checkpoint_b cosign against its OWN checkpoint: %v, want nil", err)
	}
	if err := gateway.ValidateWitnessCosign(wcA, idB); err != gateway.ErrWitnessRootMismatch {
		t.Fatalf("checkpoint_a cosign against checkpoint_b's id got %v, want WitnessRootMismatch", err)
	}
	if err := gateway.ValidateWitnessCosign(wcB, idA); err != gateway.ErrWitnessRootMismatch {
		t.Fatalf("checkpoint_b cosign against checkpoint_a's id got %v, want WitnessRootMismatch", err)
	}
}

func hexSliceToBytes(t *testing.T, hs []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i] = hb(t, h)
	}
	return out
}

// TestInclusionProofByteParityAndVerify proves Go's encoding of every inclusion-proof case matches
// the oracle, and that VerifyInclusionProof recomputes each named root exactly, using the SIZE from
// the checkpoint the proof's `root` field names (size is not itself carried in
// naalp-inclusion-proof — see checkpoint.go's VerifyInclusionProof doc).
func TestInclusionProofByteParityAndVerify(t *testing.T) {
	v := loadCPVec(t)
	// naalp-inclusion-proof's OWN `root` field is a 50-byte CONTENT-ID reference to the checkpoint
	// proven against (confirmed: it equals that checkpoint's id_hex, e.g. leaf3_of7's root_hex ==
	// checkpoint0_size7's id_hex) — NOT the 48-byte Merkle tree root value itself. Verification
	// recomputes the 48-byte tree root and compares against the NAMED CHECKPOINT'S OWN `root` field
	// (design.md §26.5: "the verifier is expected to already hold the resolved checkpoint"), so the
	// test resolves each proof's checkpoint by name and pulls the 48-byte root + size from there.
	checkpointFor := map[string]string{
		"leaf3_of7":                   "checkpoint0_size7",
		"leaf7_of8_newly_appended":    "checkpoint1_size8",
		"single_leaf_tree_empty_path": "checkpoint_single_leaf",
	}
	for name, iv := range v.InclusionProofs {
		cpName, ok := checkpointFor[name]
		if !ok {
			t.Fatalf("unhandled inclusion-proof name %q — add its resolved checkpoint above", name)
		}
		cp, ok := v.Checkpoints[cpName]
		if !ok {
			t.Fatalf("%s: resolved checkpoint %q not found in oracle", name, cpName)
		}
		if got := hex.EncodeToString(gateway.CheckpointRoot{Log: hb(t, cp.LogHex), Size: cp.Size, Root: hb(t, cp.RootHex), Prev: hb(t, cp.PrevHex), At: atU64(t, cp.AtStr)}.ID()); got != iv.RootHex {
			t.Fatalf("%s: resolved checkpoint %q id %s != proof's own root field %s", name, cpName, got, iv.RootHex)
		}

		p := gateway.InclusionProof{Root: hb(t, iv.RootHex), Leaf: hb(t, iv.LeafHex), Index: iv.Index, Path: hexSliceToBytes(t, iv.PathHex)}
		if got := hex.EncodeToString(p.Bytes()); got != iv.BodyHex {
			t.Fatalf("%s Bytes\n got %s\nwant %s", name, got, iv.BodyHex)
		}
		if got := hex.EncodeToString(p.Head()); got != iv.HeadHex {
			t.Fatalf("%s Head got %s want %s", name, got, iv.HeadHex)
		}
		if got := hex.EncodeToString(p.ID()); got != iv.IDHex {
			t.Fatalf("%s ID got %s want %s", name, got, iv.IDHex)
		}
		parsed, err := gateway.ParseInclusionProof(p.Bytes())
		if err != nil {
			t.Fatalf("%s ParseInclusionProof: %v", name, err)
		}
		if err := gateway.VerifyInclusionProof(parsed.Leaf, parsed.Index, cp.Size, parsed.Path, hb(t, cp.RootHex)); err != nil {
			t.Fatalf("%s VerifyInclusionProof: %v, want nil", name, err)
		}
	}
}

// TestInclusionProofNegative exercises the two named inclusion-proof rejections: a claimed index
// that does not match the audit path (InclusionProofInvalid) and a corrupted path entry
// (InclusionProofInvalid).
func TestInclusionProofNegative(t *testing.T) {
	v := loadCPVec(t)
	// Both negative fixtures' root_hex fields are checkpoint0_size7's CONTENT-ID (50 bytes, the
	// proof's own reference field), not the 48-byte Merkle root VerifyInclusionProof recomputes
	// against — see TestInclusionProofByteParityAndVerify's comment. Resolve checkpoint0's actual
	// root.
	cp0 := v.Checkpoints["checkpoint0_size7"]
	root0 := hb(t, cp0.RootHex)

	wi := v.Negative.InclusionWrongIndex
	if err := gateway.VerifyInclusionProof(hb(t, wi.LeafHex), wi.ClaimedIndex, cp0.Size, hexSliceToBytes(t, wi.PathHex), root0); err != gateway.ErrInclusionProofInvalid {
		t.Fatalf("wrong-index: got %v, want InclusionProofInvalid", err)
	}
	wp := v.Negative.InclusionWrongPath
	if err := gateway.VerifyInclusionProof(hb(t, wp.LeafHex), wp.Index, cp0.Size, hexSliceToBytes(t, wp.PathHex), root0); err != gateway.ErrInclusionProofInvalid {
		t.Fatalf("wrong-path: got %v, want InclusionProofInvalid", err)
	}
}

// TestWitnessRootMismatch exercises the negative.witness_root_mismatch vector directly: a cosign
// naming a DIFFERENT checkpoint's content id than the one it accompanies is rejected.
func TestWitnessRootMismatch(t *testing.T) {
	v := loadCPVec(t)
	wm := v.Negative.WitnessRootMismatch
	w, err := gateway.ParseWitnessCosign(hb(t, wm.CosignBodyHex))
	if err != nil {
		t.Fatalf("ParseWitnessCosign: %v", err)
	}
	if got := hex.EncodeToString(w.Root); got != wm.CosignNamesRootHex {
		t.Fatalf("parsed cosign root %s != oracle %s", got, wm.CosignNamesRootHex)
	}
	if err := gateway.ValidateWitnessCosign(w, hb(t, wm.CheckpointAccompaniedIDHex)); err != gateway.ErrWitnessRootMismatch {
		t.Fatalf("got %v, want %s", err, wm.Reject)
	}
}

// TestCheckpointNegative exercises the two named checkpoint-root shape rejections: a descending-key
// (NonCanonical) body and a body missing its mandatory `root` field (CheckpointMalformed).
func TestCheckpointNegative(t *testing.T) {
	v := loadCPVec(t)
	koo := v.Negative.CheckpointKeysOutOfOrder
	if _, err := gateway.ParseCheckpointRoot(hb(t, koo.CanonicalBodyHex)); err != nil {
		t.Fatalf("canonical checkpoint body should parse: %v", err)
	}
	if _, err := cbor.Decode(hb(t, koo.NoncanonicalBodyHex)); err == nil {
		t.Fatal("descending-key checkpoint body decoded (want NonCanonical)")
	} else if ce, ok := err.(*cbor.Error); !ok || ce.Kind != koo.Reject {
		t.Fatalf("descending-key body got %v, want %s", err, koo.Reject)
	}
	if _, err := gateway.ParseCheckpointRoot(hb(t, koo.NoncanonicalBodyHex)); err != gateway.ErrCheckpointMalformed {
		t.Fatalf("ParseCheckpointRoot(noncanon) got %v, want CheckpointMalformed", err)
	}

	mf := v.Negative.CheckpointMissingField
	if _, err := gateway.ParseCheckpointRoot(hb(t, mf.BodyHex)); err != gateway.ErrCheckpointMalformed {
		t.Fatalf("missing-field checkpoint got %v, want %s", err, mf.Reject)
	}
}

// TestEmptyTreeKAT proves MerkleRoot({}) == HASH() == SHA-384(""), the RFC 9162 §2.1.1 empty-list
// base case, matching the oracle's known-answer value exactly.
func TestEmptyTreeKAT(t *testing.T) {
	v := loadCPVec(t)
	if got := hex.EncodeToString(gateway.MerkleRoot(nil)); got != v.EmptyTreeKAT.RootHex {
		t.Fatalf("MerkleRoot(nil) got %s want %s", got, v.EmptyTreeKAT.RootHex)
	}
	if got := hex.EncodeToString(gateway.MerkleRoot([][]byte{})); got != v.EmptyTreeKAT.RootHex {
		t.Fatalf("MerkleRoot({}) got %s want %s", got, v.EmptyTreeKAT.RootHex)
	}
}

// TestRFC9162SelfFidelity independently re-derives the oracle's own claimed property ("for every n
// in 1..12 and every leaf index m in range(n), PATH()+recompute_root() reproduces MTH() exactly")
// using Go's OWN Merkle construction over synthetic leaves — never the oracle's numbers — so this
// test would catch a Go-side algorithmic defect the byte-parity vectors above (which only exercise
// n in {1,7,8}) do not reach.
func TestRFC9162SelfFidelity(t *testing.T) {
	const maxN = 12
	total := 0
	for n := 1; n <= maxN; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte("synthetic-leaf-" + strconv.Itoa(i))
		}
		root := gateway.MerkleRoot(leaves)
		for m := 0; m < n; m++ {
			path, err := gateway.GenerateInclusionProofPath(leaves, m)
			if err != nil {
				t.Fatalf("n=%d m=%d GenerateInclusionProofPath: %v", n, m, err)
			}
			if err := gateway.VerifyInclusionProof(leaves[m], uint64(m), uint64(n), path, root); err != nil {
				t.Fatalf("n=%d m=%d VerifyInclusionProof: %v, want nil", n, m, err)
			}
			total++
		}
	}
	if total != 78 { // sum(1..12) == 78, matching the oracle's own total_leaf_positions_checked
		t.Fatalf("checked %d leaf positions, want 78", total)
	}

	// A tampered leaf must NOT verify against the untouched root — the proof binds the exact leaf.
	leaves := make([][]byte, 5)
	for i := range leaves {
		leaves[i] = []byte("synthetic-leaf-" + strconv.Itoa(i))
	}
	root := gateway.MerkleRoot(leaves)
	path, err := gateway.GenerateInclusionProofPath(leaves, 2)
	if err != nil {
		t.Fatalf("GenerateInclusionProofPath: %v", err)
	}
	if err := gateway.VerifyInclusionProof([]byte("tampered-leaf"), 2, 5, path, root); err != gateway.ErrInclusionProofInvalid {
		t.Fatalf("tampered leaf got %v, want InclusionProofInvalid", err)
	}
}

// crossLangPinnedSignedCheckpointRootSHA384 is the pinned SHA-384 of the deterministic COSE_Sign1
// object obtained by signing checkpoint0_size7 with the shared all-0x11 32-byte ML-DSA-65 seed.
// Left as PIN_ME: this Go-only build has no Rust counterpart run to cross-check against yet.
const crossLangPinnedSignedCheckpointRootSHA384 = "PIN_ME"

func TestCrossLangSignedCheckpointRootPin(t *testing.T) {
	v := loadCPVec(t)
	var seed [mldsa65.SeedSize]byte
	for i := range seed {
		seed[i] = 0x11
	}
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	s := cose.MLDSA65Signer{SK: sk}
	c := cpFrom(t, v.Checkpoints["checkpoint0_size7"])
	obj, err := gateway.SignCheckpointRoot(c, s)
	if err != nil {
		t.Fatalf("SignCheckpointRoot: %v", err)
	}
	dg := sha512.Sum384(obj)
	got := hex.EncodeToString(dg[:])
	t.Logf("CROSS-LANG signed checkpoint-root SHA-384 (seed=0x11*32): %s", got)
	if crossLangPinnedSignedCheckpointRootSHA384 != "PIN_ME" && got != crossLangPinnedSignedCheckpointRootSHA384 {
		t.Fatalf("cross-lang signed-checkpoint-root digest %s != pinned %s", got, crossLangPinnedSignedCheckpointRootSHA384)
	}
}
