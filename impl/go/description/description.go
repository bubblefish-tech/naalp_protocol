// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package description implements C18 — the signed description / directory primitive (design.md §21;
// requirement R-DESC-1..8).
//
// C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
// object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the
// connection or the host that served them: the same signed Description re-verifies byte-identically
// when an unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority.
// It introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each
// object is an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice
// (policy) and the T1 content-id framing (§2.3) unchanged.
//
// Three wire objects:
//
//   - Description {1: service, 2: operations[]} lists a service's operations, each Operation
//     {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
//     A verifier reconstructs the operation table from the Description bytes ALONE (ParseDescription),
//     so knowing what a service offers — and at what effect — needs no live fetch.
//   - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are
//     content-ids (the same list-of-content-ids shape the §8.2 causal partial order uses). Two
//     conflicting versions from ONE signer — same directory and version but different members — are a
//     FORK, detected at the FIRST-DIFFERING member POSITION, the same way the §8.5 audit fork-proof
//     reports the position of an equivocation.
//   - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description
//     format (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet
//     (carriage, not adoption) as a signed N-AALP attestation binding the foreign bytes' content-id
//     AND an N-AALP effect mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly
//     from the verifying key) is the SOLE authorization identity; a foreign identity embedded in the
//     `foreign` bytes never becomes an N-AALP authorization identity — the confused-deputy rule of
//     the MCP profile §19 and foreign carriage R-14.6, enforced normatively here.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.
package description

import (
	"bytes"
	"crypto/sha512"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/cose"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/identity"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/policy"
)

// HeadSize is the width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit
// chain (audit.HeadSize).
const HeadSize = 48

// Foreign description format codes (design.md §21; machine-readable naalp-description-format
// registry). These name the foreign FORMAT carried octet-for-octet — not an adopted schema.
const (
	FormatA2ACard        uint64 = 1 // A2A Agent Card
	FormatANPDescription uint64 = 2 // ANP Agent Description
	FormatAGNTCYBadge    uint64 = 3 // AGNTCY Agent Badge
)

// Named, fail-closed errors. A failing object is rejected whole and causes no state change (§15).
var (
	ErrMalformed           = &cose.Error{Kind: "DescMalformed", Msg: "object is not a well-formed N-AALP description/directory/import body"}
	ErrApprovalFlag        = &cose.Error{Kind: "MalformedApprovalFlag", Msg: "requires_approval is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted"}
	ErrForkProofInvalid    = &cose.Error{Kind: "DirForkProofInvalid", Msg: "directory fork proof does not prove equivocation (not one signer, not the same directory+version, or identical members)"}
	ErrImporterMismatch    = &cose.Error{Kind: "ImporterMismatch", Msg: "the attested importer does not match the verifying key's self-certifying signer id — a foreign identity never authorizes"}
	ErrUnknownFormat       = &cose.Error{Kind: "UnknownDescriptionFormat", Msg: "import format is outside the closed naalp-description-format set {1,2,3}"}
	ErrVerifierKeyMismatch = &cose.Error{Kind: "VerifierKeyMismatch", Msg: "the (alg, pubkey) the authority id is derived from is not the key that verified the signature"}
)

// isKnownFormat reports whether fmtCode is a registered foreign-description format (the closed
// naalp-description-format set {1,2,3}). A code outside the set is rejected fail-closed — the CDDL
// types field 2 as the closed enum, not an open uint.
func isKnownFormat(fmtCode uint64) bool {
	return fmtCode == FormatA2ACard || fmtCode == FormatANPDescription || fmtCode == FormatAGNTCYBadge
}

// head is SHA-384 over a body — a 48-octet digest (the same construction as audit.Receipt.Head).
func head(b []byte) []byte {
	d := sha512.Sum384(b)
	return d[:]
}

// contentID is the T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
func contentID(b []byte) []byte {
	h := head(b)
	return append([]byte{0x20, 0x30}, h...)
}

// ---- Operation: one listed operation with its effect + approval declaration (design.md §21.2) ----

// Operation is one entry of a Description or an Import mapping: a named operation, its C5 effect
// class, and whether it requires an approval. RequiresApproval is the uint 1 (yes) / 0 (no) — the
// N-AALP spine carries no CBOR boolean (design §3.1).
type Operation struct {
	Name             string // operation name (advisory routing key)
	Effect           uint64 // the operation's effect class (C5 lattice)
	RequiresApproval uint64 // 1 if this operation requires an approval, 0 otherwise
}

// toMap encodes the operation as its CBOR map {1: name, 2: effect, 3: requires_approval}.
func (op Operation) toMap() cbor.Map {
	return cbor.Map{
		{K: cbor.Uint(1), V: cbor.Tstr(op.Name)},
		{K: cbor.Uint(2), V: cbor.Uint(op.Effect)},
		{K: cbor.Uint(3), V: cbor.Uint(op.RequiresApproval)},
	}
}

// Bytes is the deterministic-CBOR encoding of the operation body.
func (op Operation) Bytes() []byte {
	b, _ := cbor.Encode(op.toMap())
	return b
}

// EffectClass is the per-operation effect accessor, normalized fail-closed: a value the evaluator
// does not recognize is treated as destructive (R-6.2), never as a weaker class.
func (op Operation) EffectClass() policy.Effect { return policy.NormalizeEffect(op.Effect) }

// RequiresApprovalFlag is the per-operation approval-declaration accessor: true iff the operation
// declares that it requires an approval.
func (op Operation) RequiresApprovalFlag() bool { return op.RequiresApproval == 1 }

// operationFromValue parses one operation map, rejecting a malformed shape (ErrMalformed) or an
// approval flag outside {0,1} (ErrApprovalFlag). Fail-closed.
func operationFromValue(v cbor.Value) (Operation, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return Operation{}, ErrMalformed
	}
	name, ok1 := tstrField(m, 1)
	effect, ok2 := uintField(m, 2)
	req, ok3 := uintField(m, 3)
	if !ok1 || !ok2 || !ok3 {
		return Operation{}, ErrMalformed
	}
	if req > 1 {
		return Operation{}, ErrApprovalFlag
	}
	return Operation{Name: name, Effect: effect, RequiresApproval: req}, nil
}

// operationsFromValue parses the operations array.
func operationsFromValue(v cbor.Value) ([]Operation, error) {
	arr, ok := v.(cbor.Arr)
	if !ok {
		return nil, ErrMalformed
	}
	ops := make([]Operation, len(arr))
	for i, e := range arr {
		op, err := operationFromValue(e)
		if err != nil {
			return nil, err
		}
		ops[i] = op
	}
	return ops, nil
}

// operationsValue encodes an operations slice as a CBOR array of operation maps.
func operationsValue(ops []Operation) cbor.Arr {
	arr := make(cbor.Arr, len(ops))
	for i, op := range ops {
		arr[i] = op.toMap()
	}
	return arr
}

// findOperation returns the first operation with the given name.
func findOperation(ops []Operation, name string) (Operation, bool) {
	for _, op := range ops {
		if op.Name == name {
			return op, true
		}
	}
	return Operation{}, false
}

// ---- Description: a service's signed operation table (design.md §21.2) ------------------------

// Description is a signed N-AALP object listing a service's operations. Its authority is in the
// signed bytes: ParseDescription reconstructs the whole operation table (with each operation's
// effect and approval declaration) from the bytes alone, so an unrelated host serving the same bytes
// yields a byte-identical verification (offline-verifiable, not fetch-authenticated).
type Description struct {
	Service    []byte      // opaque service id
	Operations []Operation // the listed operations
}

// Bytes is the deterministic-CBOR encoding {1: service, 2: operations[]}.
func (d Description) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(d.Service)},
		{K: cbor.Uint(2), V: operationsValue(d.Operations)},
	})
	return b
}

// Head is the Description's SHA-384 head (48 octets).
func (d Description) Head() []byte { return head(d.Bytes()) }

// ID is the Description's T1 content-id (50 octets).
func (d Description) ID() []byte { return contentID(d.Bytes()) }

// Operation returns the named operation and whether it is listed (the per-operation
// effect+approval-declaration accessor: the returned Operation exposes EffectClass and
// RequiresApprovalFlag).
func (d Description) Operation(name string) (Operation, bool) {
	return findOperation(d.Operations, name)
}

// ParseDescription reconstructs a Description from its body bytes ALONE — the offline-verifiable
// property: a verifier holding the bytes (and having checked the signature) knows every operation and
// its effect with no live fetch or host state.
func ParseDescription(b []byte) (Description, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Description{}, ErrMalformed
	}
	svc, ok1 := bstrField(m, 1)
	opsV, ok2 := field(m, 2)
	if !ok1 || !ok2 {
		return Description{}, ErrMalformed
	}
	ops, err := operationsFromValue(opsV)
	if err != nil {
		return Description{}, err
	}
	return Description{Service: svc, Operations: ops}, nil
}

// SignDescription produces the tagged COSE_Sign1 object over the Description body.
func SignDescription(d Description, s cose.Signer) ([]byte, error) { return cose.Sign1(s, d.Bytes()) }

// VerifyDescription verifies the Description's full signature under the profile, then reconstructs
// the operation table from the signed body bytes. Because the authority is the signature over the
// bytes, this returns the identical Description regardless of which host served `obj` — the
// offline-verification property (R-DESC-1).
func VerifyDescription(obj []byte, profile int, v cose.Verifier) (Description, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return Description{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return Description{}, err
	}
	return ParseDescription(payload)
}

// ---- Directory: a signed collection of content-ids, with fork detection (design.md §21.3) --------

// Directory is a signed collection object whose members are content-ids (the same shape the causal
// partial order uses for `causes`). It carries a monotonic per-signer version so two versions can be
// compared for equivocation.
type Directory struct {
	Directory []byte   // opaque directory id
	Version   uint64   // monotonic per-signer version
	Members   [][]byte // content-ids of the member objects
}

// Bytes is the deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}.
func (d Directory) Bytes() []byte {
	arr := make(cbor.Arr, len(d.Members))
	for i, m := range d.Members {
		arr[i] = cbor.Bstr(m)
	}
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(d.Directory)},
		{K: cbor.Uint(2), V: cbor.Uint(d.Version)},
		{K: cbor.Uint(3), V: arr},
	})
	return b
}

// Head is the Directory's SHA-384 head (48 octets).
func (d Directory) Head() []byte { return head(d.Bytes()) }

// ID is the Directory's T1 content-id (50 octets).
func (d Directory) ID() []byte { return contentID(d.Bytes()) }

// ParseDirectory reconstructs a Directory from its body bytes alone.
func ParseDirectory(b []byte) (Directory, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Directory{}, ErrMalformed
	}
	did, ok1 := bstrField(m, 1)
	ver, ok2 := uintField(m, 2)
	memV, ok3 := field(m, 3)
	if !ok1 || !ok2 || !ok3 {
		return Directory{}, ErrMalformed
	}
	arr, ok := memV.(cbor.Arr)
	if !ok {
		return Directory{}, ErrMalformed
	}
	members := make([][]byte, len(arr))
	for i, e := range arr {
		bs, ok := e.(cbor.Bstr)
		if !ok {
			return Directory{}, ErrMalformed
		}
		members[i] = []byte(bs)
	}
	return Directory{Directory: did, Version: ver, Members: members}, nil
}

// SignDirectory produces the tagged COSE_Sign1 object over the Directory body.
func SignDirectory(d Directory, s cose.Signer) ([]byte, error) { return cose.Sign1(s, d.Bytes()) }

// VerifyDirectory verifies the Directory's full signature under the profile, then reconstructs it
// from the signed body bytes.
func VerifyDirectory(obj []byte, profile int, v cose.Verifier) (Directory, error) {
	if err := cose.Verify1(profile, v, obj); err != nil {
		return Directory{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return Directory{}, err
	}
	return ParseDirectory(payload)
}

// firstMemberDifference returns the first index at which two member lists differ, and whether they
// differ at all. If the lists share a common prefix and one is longer, the difference is reported at
// the length of the shorter list. Identical lists return (0, false).
func firstMemberDifference(a, b [][]byte) (int, bool) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(a[i], b[i]) {
			return i, true
		}
	}
	if len(a) != len(b) {
		return n, true
	}
	return 0, false
}

// DetectFork compares two directory versions from ONE signer and reports whether they equivocate —
// the SAME directory id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING member
// POSITION (as the §8.5 audit fork-proof reports the position of an equivocation). A different
// directory id or version is a legitimate distinct object/succession, not a fork; identical members
// are a benign duplicate. In both non-fork cases it returns (0, false). The caller establishes the
// "one signer" precondition by verifying both objects under the same key (DirectoryForkProof.Verify).
func DetectFork(a, b Directory) (position int, fork bool) {
	if !bytes.Equal(a.Directory, b.Directory) || a.Version != b.Version {
		return 0, false // different directory or version — not a conflicting pair
	}
	return firstMemberDifference(a.Members, b.Members)
}

// DirectoryForkProof is the non-repudiable evidence of a directory fork: two validly-signed Directory
// objects by ONE signer at the SAME (directory, version) listing DIFFERENT members, carried as the
// accused signer's OWN two signed objects (the tagged COSE_Sign1 bytes). It mirrors the draft-01
// audit ForkProof: because a single verifier checks BOTH signed objects, the proof is self-contained
// — any third party confirms both signatures against the accused key with no further evidence and no
// repudiation.
type DirectoryForkProof struct {
	Signer  []byte // accused signer id (both signed objects verify under its key)
	SignedA []byte // the accused's first signed Directory (tagged COSE_Sign1)
	SignedB []byte // the accused's second signed Directory at the same (directory, version)
}

// Verify checks that fp is a genuine directory fork by the signer whose key is v, and returns the
// FIRST-DIFFERING member POSITION. It accepts iff ALL hold: (1) the signer id is present; (2) BOTH
// signed objects verify under v (which, because a single verifier checks both, proves one signer);
// (3) the two directories share one directory id and version; and (4) their member lists differ. Any
// failure rejects the whole proof (fail-closed) with a named error and reports nothing partial: an
// unnamed signer, a different directory/version, or identical members is DirForkProofInvalid, and a
// signature that does not verify propagates from cose.Verify1 (BadSignature). v MUST be the verifier
// resolved for fp.Signer.
func (fp DirectoryForkProof) Verify(profile int, v cose.Verifier) (position int, err error) {
	if len(fp.Signer) == 0 {
		return 0, ErrForkProofInvalid // an unnamed accused is not evidence
	}
	a, err := VerifyDirectory(fp.SignedA, profile, v)
	if err != nil {
		return 0, err
	}
	b, err := VerifyDirectory(fp.SignedB, profile, v)
	if err != nil {
		return 0, err
	}
	pos, fork := DetectFork(a, b)
	if !fork {
		return 0, ErrForkProofInvalid // same directory+version identical members, or not the same versioned directory
	}
	return pos, nil
}

// ---- Import: foreign description carried as a signed attestation (design.md §21.4) ---------------

// Import carries a foreign description format octet-for-octet (carriage, not adoption) as a signed
// N-AALP attestation. Importer is the wrapping signer id (the sole authorization identity); Foreign
// is the foreign bytes verbatim; Operations is the N-AALP effect mapping the importer attests for the
// described operations. The foreign bytes' content-id is bound by ForeignID.
type Import struct {
	Importer   []byte      // the importing (wrapping) signer id — the SOLE authorization identity (R-14.6)
	Format     uint64      // the foreign description format code (FormatA2ACard / FormatANPDescription / FormatAGNTCYBadge)
	Foreign    []byte      // the foreign description bytes, carried octet-for-octet (carriage, not adoption)
	Operations []Operation // the N-AALP effect mapping the importer attests for the described operations
}

// Bytes is the deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}.
func (im Import) Bytes() []byte {
	b, _ := cbor.Encode(cbor.Map{
		{K: cbor.Uint(1), V: cbor.Bstr(im.Importer)},
		{K: cbor.Uint(2), V: cbor.Uint(im.Format)},
		{K: cbor.Uint(3), V: cbor.Bstr(im.Foreign)},
		{K: cbor.Uint(4), V: operationsValue(im.Operations)},
	})
	return b
}

// Head is the Import's SHA-384 head (48 octets).
func (im Import) Head() []byte { return head(im.Bytes()) }

// ID is the Import attestation's own T1 content-id (50 octets).
func (im Import) ID() []byte { return contentID(im.Bytes()) }

// ForeignID is the T1 content-id of the carried foreign bytes — the hash the attestation binds
// (design §21.4). A changed foreign document yields a different ForeignID, so an attestation binds
// the exact bytes it attested.
func (im Import) ForeignID() []byte { return contentID(im.Foreign) }

// Operation returns the named operation from the attested mapping and whether it is listed.
func (im Import) Operation(name string) (Operation, bool) { return findOperation(im.Operations, name) }

// ParseImport reconstructs an Import from its body bytes alone.
func ParseImport(b []byte) (Import, error) {
	m, ok := decodeMap(b)
	if !ok {
		return Import{}, ErrMalformed
	}
	imp, ok1 := bstrField(m, 1)
	fmtV, ok2 := uintField(m, 2)
	foreign, ok3 := bstrField(m, 3)
	opsV, ok4 := field(m, 4)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return Import{}, ErrMalformed
	}
	// The CDDL types field 2 as the closed naalp-description-format enum {1,2,3}; a code outside the
	// set is rejected on decode (fail-closed), never carried as an unknown format.
	if !isKnownFormat(fmtV) {
		return Import{}, ErrUnknownFormat
	}
	ops, err := operationsFromValue(opsV)
	if err != nil {
		return Import{}, err
	}
	return Import{Importer: imp, Format: fmtV, Foreign: foreign, Operations: ops}, nil
}

// SignImport produces the tagged COSE_Sign1 object over the Import body.
func SignImport(im Import, s cose.Signer) ([]byte, error) { return cose.Sign1(s, im.Bytes()) }

// ResolvedImport is an Import that has passed signature verification and the confused-deputy check.
// AuthorityID is the self-certifying signer id RECOMPUTED from the verifying key (identity §5.1) — the
// wrapping signer, and the only authorization identity. It is never any identity parsed from the
// foreign bytes.
type ResolvedImport struct {
	AuthorityID string      // the wrapping signer id, recomputed from the key (the sole authority)
	Format      uint64      // the foreign format code
	ForeignID   []byte      // the content-id the attestation binds
	Operations  []Operation // the attested N-AALP effect mapping
}

// VerifyImport verifies a foreign-description import end-to-end and enforces the confused-deputy rule
// normatively. It (1) verifies the signed object under the profile with real crypto (cose.Verify1 —
// signature, alg registry, profile floor); (2) recomputes the wrapping signer's SELF-CERTIFYING id
// from the verifying key (alg + pubkey, identity.SignerID); and (3) requires the attestation's
// `importer` field to equal that recomputed id (ImporterMismatch otherwise). The returned AuthorityID
// is that recomputed key id — the wrapping signer — so no field inside the carried foreign bytes,
// including any foreign identity claim, can ever become the N-AALP authorization identity (R-14.6).
// Any failure returns its named error and authorizes nothing (fail-closed).
func VerifyImport(obj []byte, profile int, alg int, pubkey []byte, v cose.Verifier) (ResolvedImport, error) {
	// Confused-deputy containment: the authority id is derived from (alg, pubkey), but the signature
	// is checked with v. If those are not the SAME key, a caller could verify with key A yet mint an
	// authority id for key B. Bind them to the verifying key BEFORE any authority is derived: alg MUST
	// equal v.Alg() and pubkey MUST equal v.PubKey() (VerifierKeyMismatch otherwise). Fail-closed.
	if alg != v.Alg() || !bytes.Equal(pubkey, v.PubKey()) {
		return ResolvedImport{}, ErrVerifierKeyMismatch
	}
	if err := cose.Verify1(profile, v, obj); err != nil {
		return ResolvedImport{}, err
	}
	_, payload, _, err := cose.ParseSign1Raw(obj)
	if err != nil {
		return ResolvedImport{}, err
	}
	im, err := ParseImport(payload)
	if err != nil {
		return ResolvedImport{}, err
	}
	keyID, err := identity.SignerID(alg, pubkey)
	if err != nil {
		return ResolvedImport{}, err
	}
	// The authorization identity is the wrapping key's own id. The attestation's declared importer
	// MUST match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
	if string(im.Importer) != keyID {
		return ResolvedImport{}, ErrImporterMismatch
	}
	return ResolvedImport{
		AuthorityID: keyID,
		Format:      im.Format,
		ForeignID:   im.ForeignID(),
		Operations:  im.Operations,
	}, nil
}

// ---- small deterministic-CBOR field accessors ------------------------------------------------

func decodeMap(b []byte) (cbor.Map, bool) {
	v, err := cbor.Decode(b)
	if err != nil {
		return nil, false
	}
	m, ok := v.(cbor.Map)
	return m, ok
}

func field(m cbor.Map, k uint64) (cbor.Value, bool) {
	for _, p := range m {
		if p.K == cbor.Uint(k) {
			return p.V, true
		}
	}
	return nil, false
}

func bstrField(m cbor.Map, k uint64) ([]byte, bool) {
	v, ok := field(m, k)
	if !ok {
		return nil, false
	}
	bs, ok := v.(cbor.Bstr)
	return []byte(bs), ok
}

func tstrField(m cbor.Map, k uint64) (string, bool) {
	v, ok := field(m, k)
	if !ok {
		return "", false
	}
	ts, ok := v.(cbor.Tstr)
	return string(ts), ok
}

func uintField(m cbor.Map, k uint64) (uint64, bool) {
	v, ok := field(m, k)
	if !ok {
		return 0, false
	}
	u, ok := v.(cbor.Uint)
	return uint64(u), ok
}
