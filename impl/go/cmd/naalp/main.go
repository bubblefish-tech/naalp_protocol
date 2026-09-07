// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp is a small command-line tool for the N-AALP core loop: generate an identity,
// sign an object, and verify an object offline. It is a thin front end over the naalp
// convenience layer (which delegates to the cose/envelope/identity/channels spine packages);
// it performs no cryptography of its own.
//
// Subcommands:
//
//	naalp keygen  [-seed <hex32>]
//	    Print an ML-DSA-65 key: the 32-byte seed (secret), the packed public key, and the
//	    derived self-certifying signer id. With no -seed, a fresh random seed is drawn.
//
//	naalp sign    -seed <hex32> -channel <n> -kind <n> -text <msg> [-created <ms>]
//	    Sign an N-AALP object carrying the UTF-8 message on (channel, kind); print the signed
//	    object as hex to stdout. The effect is taken from the kind's declared effect.
//
//	naalp verify  -pubkey <hex> [-env <hex>]
//	    Verify a signed object (hex from -env, or from stdin) under the public key. On success
//	    print the decoded object and exit 0; on any failure print the named error and exit 1.
//
// Every bad input is fail-closed: a malformed flag or key exits 2, a failed verification exits
// 1, and success exits 0.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalp"
)

// seedSize is the ML-DSA-65 seed length in bytes (FIPS 204).
const seedSize = 32

const usage = `naalp — N-AALP command-line tool

usage:
  naalp keygen [-seed <hex32>]
  naalp sign   -seed <hex32> -channel <n> -kind <n> -text <msg> [-created <ms>]
  naalp verify -pubkey <hex> [-env <hex>]      (envelope hex read from stdin if -env omitted)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "sign":
		cmdSign(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "naalp: unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

// argErr prints a usage-style error to stderr and exits 2 (bad input, fail-closed).
func argErr(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "naalp: "+format+"\n", a...)
	os.Exit(2)
}

// cmdKeygen prints a fresh (or seed-derived) ML-DSA-65 key: seed, public key, signer id. The
// seed is minted locally (not via naalp.GenerateSigner) so that a random seed can be printed
// for reuse with `naalp sign -seed`.
func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	seedHex := fs.String("seed", "", "32-byte seed as hex (default: random)")
	_ = fs.Parse(args)

	var seed []byte
	var err error
	if *seedHex != "" {
		seed, err = hex.DecodeString(strings.TrimSpace(*seedHex))
		if err != nil {
			argErr("keygen: -seed is not valid hex: %v", err)
		}
	} else {
		seed = make([]byte, seedSize)
		if _, err = rand.Read(seed); err != nil {
			argErr("keygen: reading random seed: %v", err)
		}
	}
	signer, err := naalp.NewSigner(seed)
	if err != nil {
		argErr("keygen: %v", err)
	}
	fmt.Printf("seed_hex %s\n", hex.EncodeToString(seed))
	fmt.Printf("pubkey_hex %s\n", hex.EncodeToString(signer.PublicKey()))
	fmt.Printf("signer_id %s\n", signer.SignerID())
}

// cmdSign signs an N-AALP object carrying a UTF-8 message and prints the signed bytes as hex.
func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	seedHex := fs.String("seed", "", "32-byte signing seed as hex (required)")
	channel := fs.Uint64("channel", 0, "channel id (required, e.g. 15 for Interaction)")
	kind := fs.Uint64("kind", 0, "kind code within the channel (required)")
	text := fs.String("text", "", "UTF-8 message to carry as the object body (required)")
	created := fs.Uint64("created", 0, "created timestamp in unix milliseconds (required)")
	channelSet, kindSet, createdSet := false, false, false
	_ = fs.Parse(args)
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "channel":
			channelSet = true
		case "kind":
			kindSet = true
		case "created":
			createdSet = true
		}
	})

	if *seedHex == "" {
		argErr("sign: -seed is required")
	}
	if !channelSet {
		argErr("sign: -channel is required")
	}
	if !kindSet {
		argErr("sign: -kind is required")
	}
	if *text == "" {
		argErr("sign: -text is required")
	}
	if !createdSet {
		argErr("sign: -created (unix milliseconds) is required for a reproducible object")
	}
	seed, err := hex.DecodeString(strings.TrimSpace(*seedHex))
	if err != nil {
		argErr("sign: -seed is not valid hex: %v", err)
	}
	signer, err := naalp.NewSigner(seed)
	if err != nil {
		argErr("sign: %v", err)
	}
	env, err := signer.Sign(*channel, *kind, *created, cbor.Tstr(*text))
	if err != nil {
		// An unregistered (channel, kind) or an encoding failure is fail-closed input.
		argErr("sign: %v", err)
	}
	fmt.Println(hex.EncodeToString(env))
}

// cmdVerify verifies a signed object offline and prints the decoded object, or fails closed.
func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubHex := fs.String("pubkey", "", "signer public key as hex (required)")
	envHex := fs.String("env", "", "signed object as hex (default: read from stdin)")
	_ = fs.Parse(args)

	if *pubHex == "" {
		argErr("verify: -pubkey is required")
	}
	pub, err := hex.DecodeString(strings.TrimSpace(*pubHex))
	if err != nil {
		argErr("verify: -pubkey is not valid hex: %v", err)
	}
	envText := *envHex
	if envText == "" {
		b, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			argErr("verify: reading envelope from stdin: %v", err)
		}
		envText = strings.TrimSpace(string(b))
	}
	if envText == "" {
		argErr("verify: no envelope provided (use -env or pipe hex on stdin)")
	}
	env, err := hex.DecodeString(strings.TrimSpace(envText))
	if err != nil {
		argErr("verify: envelope is not valid hex: %v", err)
	}

	obj, err := naalp.Verify(pub, env)
	if err != nil {
		// A failed verification is the tool's headline fail-closed outcome: exit non-zero.
		fmt.Fprintf(os.Stderr, "verify: REJECTED: %v\n", err)
		os.Exit(1)
	}

	chName := "unknown"
	if c, ok := channels.Channel(obj.Channel); ok {
		chName = c.Name
	}
	kindName := "unknown"
	effect := ""
	if k, ok := channels.Lookup(obj.Channel, obj.Kind); ok {
		kindName = k.Name
		effect = k.Effect.SafetyLabelName()
	}
	fmt.Println("VERIFIED")
	fmt.Printf("  signer   %s\n", string(obj.Signer))
	fmt.Printf("  channel  0x%04X (%s)\n", obj.Channel, chName)
	fmt.Printf("  kind     %d (%s)\n", obj.Kind, kindName)
	fmt.Printf("  effect   %d (%s)\n", obj.Effect, effect)
	if body, ok := obj.Body.(cbor.Tstr); ok {
		fmt.Printf("  body     %q\n", string(body))
	} else {
		fmt.Printf("  body     (non-text CBOR value)\n")
	}
}
