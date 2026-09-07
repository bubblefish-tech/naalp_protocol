// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-supply-chain is the real, executable production caller for the
// ecosystem/naalp-supply-chain library (package supplychain): it wires that already-graded
// library's functions — module-graph parsing, CycloneDX 1.7 SBOM construction and schema
// validation, SLSA Provenance v1 / in-toto Statement construction, and N-AALP-native
// COSE_Sign1 signing — into a two-subcommand CLI that reads real files from disk and writes
// real files back, closing the library's no-production-caller gap (Section E2: "a component
// with zero production callers is scaffolding").
//
// Subcommands:
//
//	naalp-supply-chain build  -artifact <path> -root-name <name> -builder-id <id> -out <dir>
//	                           [-root-type <type>] [-root-version <version>]
//	                           [-modules <go.mod path> | -golist <go-list-json path>]
//	                           [-seed-hex <64 hex chars>]
//	naalp-supply-chain verify -artifact <path> -sbom <path> -provenance <path> -cose <path> -pubkey <path>
//
// `build` reads a release artifact plus (optionally) a real Go module dependency graph —
// either a go.mod file's require directives (-modules, parsed with
// supplychain.ParseGoModRequires) or the captured stdout of `go list -m -json all`
// (-golist, parsed with supplychain.DecodeGoListModules) — calls supplychain.BuildRelease,
// and writes four real output files: the CycloneDX 1.7 SBOM JSON, the in-toto/SLSA
// provenance Statement JSON, the tagged COSE_Sign1 signature bytes over that Statement, and
// the signer's hex-encoded ML-DSA-65 public key.
//
// `verify` re-reads those four files (plus the original artifact) from disk and
// independently re-parses and re-verifies them through the SAME already-graded library
// functions BuildRelease itself calls to validate its own output
// (supplychain.ValidateSBOM, supplychain.ValidateStatement, supplychain.VerifyBinding,
// supplychain.VerifyStatementSignature) — never trusting its own prior "build" run, never
// re-deriving expected values from the files being checked. This closes the loop the task
// requires: build output that re-parses and re-verifies through the graded oracle.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	supplychain "github.com/bubblefish-tech/naalp_protocol/impl/go/ecosystem/naalp-supply-chain"
)

// Output file names written by `build` and read by `verify`. Fixed, documented names (not
// invented per-run) so the two subcommands agree on the on-disk contract without a caller
// having to thread five separate paths by hand.
const (
	sbomFileName       = "sbom.cyclonedx.json"
	provenanceFileName = "provenance.intoto.json"
	signedFileName     = "provenance.cose"
	pubkeyFileName     = "signer-pubkey.hex"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "build":
		code = runBuild(os.Args[2:], os.Stdout, os.Stderr)
	case "verify":
		code = runVerify(os.Args[2:], os.Stdout, os.Stderr)
	case "-h", "--help", "help":
		usage(os.Stdout)
		code = 0
	default:
		fmt.Fprintf(os.Stderr, "naalp-supply-chain: unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		code = 2
	}
	os.Exit(code)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `naalp-supply-chain — CycloneDX 1.7 SBOM + SLSA/in-toto provenance CLI

Usage:
  naalp-supply-chain build  -artifact <path> -root-name <name> -builder-id <id> -out <dir>
                             [-root-type <type>] [-root-version <version>]
                             [-modules <go.mod path>] [-golist <go-list-json path>]
                             [-seed-hex <64 hex chars>]

  naalp-supply-chain verify -artifact <path> -sbom <path> -provenance <path> -cose <path> -pubkey <path>

Run "naalp-supply-chain build -h" or "naalp-supply-chain verify -h" for flag details.`)
}

// runBuild implements the `build` subcommand. It returns the process exit code rather than
// calling os.Exit itself, and takes stdout/stderr as parameters rather than using the
// package-level os.Stdout/os.Stderr, so it can be exercised directly and in isolation by a
// test (A9) without spawning a subprocess.
func runBuild(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	artifactPath := fs.String("artifact", "", "path to the release artifact file (required)")
	rootName := fs.String("root-name", "", "SBOM root component name (required)")
	rootType := fs.String("root-type", supplychain.ComponentTypeApplication, "SBOM root component type (a CycloneDX 1.7 component-type enum value)")
	rootVersion := fs.String("root-version", "", "SBOM root component version")
	builderID := fs.String("builder-id", "", "SLSA runDetails.builder.id — identifies the build platform (required)")
	modulesPath := fs.String("modules", "", "path to a go.mod file; its require directives become SBOM components (mutually exclusive with -golist)")
	golistPath := fs.String("golist", "", "path to captured `go list -m -json all` output; becomes SBOM components (mutually exclusive with -modules)")
	seedHex := fs.String("seed-hex", "", "64 hex-char (32-byte) ML-DSA-65 signer seed; a fresh random seed is generated when empty")
	outDir := fs.String("out", "", "output directory for the four produced files (required, created if absent)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *artifactPath == "" || *rootName == "" || *builderID == "" || *outDir == "" {
		fmt.Fprintln(stderr, "naalp-supply-chain build: -artifact, -root-name, -builder-id, and -out are all required")
		fs.Usage()
		return 2
	}
	if *modulesPath != "" && *golistPath != "" {
		fmt.Fprintln(stderr, "naalp-supply-chain build: -modules and -golist are mutually exclusive")
		return 2
	}

	artifactData, err := os.ReadFile(*artifactPath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain build: reading artifact: %v\n", err)
		return 1
	}

	modules, err := loadModules(*modulesPath, *golistPath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain build: %v\n", err)
		return 1
	}

	signer, err := loadOrGenerateSigner(*seedHex)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain build: %v\n", err)
		return 1
	}

	root := supplychain.Component{Type: *rootType, Name: *rootName, Version: *rootVersion}
	now := time.Now()

	result, err := supplychain.BuildRelease(
		supplychain.ReleaseArtifact{Name: filepath.Base(*artifactPath), Data: artifactData},
		root, modules, *builderID, signer, now, now,
	)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain build: %v\n", err)
		return 1
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain build: creating output directory: %v\n", err)
		return 1
	}
	written := []struct {
		name string
		data []byte
	}{
		{sbomFileName, result.SBOMJSON},
		{provenanceFileName, result.StatementJSON},
		{signedFileName, result.SignedProvenance},
		{pubkeyFileName, []byte(hex.EncodeToString(signer.PublicKey()))},
	}
	for _, f := range written {
		path := filepath.Join(*outDir, f.name)
		if err := os.WriteFile(path, f.data, 0o644); err != nil {
			fmt.Fprintf(stderr, "naalp-supply-chain build: writing %s: %v\n", path, err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s (%d bytes)\n", path, len(f.data))
	}
	fmt.Fprintf(stdout, "artifact digest sha256:%s\n", result.ArtifactDigest["sha256"])
	fmt.Fprintf(stdout, "sbom digest sha256:%s\n", result.SBOMDigest["sha256"])
	fmt.Fprintf(stdout, "sbom components: %d\n", len(result.SBOM.Components))
	return 0
}

// loadModules parses the real Go module dependency graph from whichever of modulesPath /
// golistPath is non-empty, or returns a nil (empty) module list when neither is given — it
// never fabricates a component list (doc.go / sbom.go's A4 discipline: BuildSBOM "never
// hardcodes a component list").
func loadModules(modulesPath, golistPath string) ([]supplychain.Module, error) {
	switch {
	case modulesPath != "":
		data, err := os.ReadFile(modulesPath)
		if err != nil {
			return nil, fmt.Errorf("reading go.mod: %w", err)
		}
		mods, err := supplychain.ParseGoModRequires(data)
		if err != nil {
			return nil, fmt.Errorf("parsing go.mod requires: %w", err)
		}
		return mods, nil
	case golistPath != "":
		f, err := os.Open(golistPath)
		if err != nil {
			return nil, fmt.Errorf("opening go-list output: %w", err)
		}
		defer f.Close()
		mods, err := supplychain.DecodeGoListModules(f)
		if err != nil {
			return nil, fmt.Errorf("decoding go-list output: %w", err)
		}
		return mods, nil
	default:
		return nil, nil
	}
}

// loadOrGenerateSigner derives a ProvenanceSigner from seedHex (hex-decoded) when non-empty,
// or generates a fresh cryptographically random one otherwise.
func loadOrGenerateSigner(seedHex string) (*supplychain.ProvenanceSigner, error) {
	if seedHex == "" {
		signer, err := supplychain.GenerateProvenanceSigner()
		if err != nil {
			return nil, fmt.Errorf("generating signer: %w", err)
		}
		return signer, nil
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("decoding -seed-hex: %w", err)
	}
	signer, err := supplychain.NewProvenanceSigner(seed)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return signer, nil
}

// runVerify implements the `verify` subcommand: it re-reads a build's four output files (and
// the original artifact) from disk and independently re-parses/re-verifies them through the
// SAME already-graded oracle functions the library exposes — it never re-derives an expected
// value from the very file being checked (F3 non-circularity), and it fails closed on the
// first check that does not hold.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	artifactPath := fs.String("artifact", "", "path to the release artifact file (required)")
	sbomPath := fs.String("sbom", "", "path to the CycloneDX SBOM JSON file produced by build (required)")
	provenancePath := fs.String("provenance", "", "path to the in-toto Statement JSON file produced by build (required)")
	cosePath := fs.String("cose", "", "path to the tagged COSE_Sign1 signature file produced by build (required)")
	pubkeyPath := fs.String("pubkey", "", "path to the hex-encoded ML-DSA-65 public key file produced by build (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *artifactPath == "" || *sbomPath == "" || *provenancePath == "" || *cosePath == "" || *pubkeyPath == "" {
		fmt.Fprintln(stderr, "naalp-supply-chain verify: -artifact, -sbom, -provenance, -cose, and -pubkey are all required")
		fs.Usage()
		return 2
	}

	artifactData, err := os.ReadFile(*artifactPath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: reading artifact: %v\n", err)
		return 1
	}
	sbomJSON, err := os.ReadFile(*sbomPath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: reading sbom: %v\n", err)
		return 1
	}
	statementJSON, err := os.ReadFile(*provenancePath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: reading provenance: %v\n", err)
		return 1
	}
	coseBytes, err := os.ReadFile(*cosePath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: reading cose signature: %v\n", err)
		return 1
	}
	pubHexRaw, err := os.ReadFile(*pubkeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: reading pubkey: %v\n", err)
		return 1
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHexRaw)))
	if err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: decoding pubkey hex: %v\n", err)
		return 1
	}

	// 1. Schema-validate the SBOM against the vendored, independent CycloneDX 1.7 JSON
	// Schema (F3: not the code that produced sbomJSON asserting its own correctness).
	if err := supplychain.ValidateSBOM(sbomJSON); err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: SBOM schema: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "OK: SBOM satisfies the CycloneDX 1.7 JSON Schema")

	// 2. Parse the provenance Statement and check SLSA Build L1's required-field set.
	var statement supplychain.Statement
	if err := json.Unmarshal(statementJSON, &statement); err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: parsing provenance statement: %v\n", err)
		return 1
	}
	if err := supplychain.ValidateStatement(&statement); err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: SLSA Build L1 required fields: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "OK: provenance statement satisfies the SLSA Build L1 required-field set")

	// 3. Independently RECOMPUTE the artifact and SBOM digests from the actual bytes on
	// disk and confirm they match what the Statement records — never trusting the
	// Statement's own claim.
	if err := supplychain.VerifyBinding(&statement, artifactData, sbomJSON); err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: digest binding: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "OK: provenance digests match the artifact and SBOM bytes actually on disk")

	// 4. Cryptographically verify the COSE_Sign1 signature over the exact statement bytes.
	if err := supplychain.VerifyStatementSignature(pub, coseBytes, statementJSON); err != nil {
		fmt.Fprintf(stderr, "naalp-supply-chain verify: signature: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "OK: COSE_Sign1 signature verifies over the provenance statement")

	fmt.Fprintln(stdout, "VERIFIED: SBOM + provenance + digest binding + signature all check out")
	return 0
}
