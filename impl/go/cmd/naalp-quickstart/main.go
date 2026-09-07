// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command naalp-quickstart runs the N-AALP two-agent core loop end-to-end with no hand-rolled
// crypto, printing each step:
//
//	agent A generates a fresh ML-DSA-65 identity;
//	agent A builds and signs a real N-AALP object — an Interaction-surface message — producing a
//	  post-quantum signature over the deterministic object body;
//	the object bytes plus agent A's public key cross "the wire" to agent B;
//	agent B verifies the object OFFLINE (object + key + spec, no network) and reads its body;
//	a one-byte tamper of the same object is presented, and agent B rejects it fail-closed.
//
// Every step uses the reference SDK through the naalp convenience layer, which delegates to the
// cose/envelope/identity/channels spine packages. The program is self-checking: it exits
// non-zero if the genuine object fails to verify, if the round-tripped body differs, or if the
// tampered object is NOT rejected — so a broken verify path fails the run rather than printing a
// false success.
//
//	go run ./cmd/naalp-quickstart
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bubblefish-tech/naalp_protocol/impl/go/cbor"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/channels"
	"github.com/bubblefish-tech/naalp_protocol/impl/go/naalp"
)

// N-AALP Interaction surface (design-channels.md §16): channel 0x000F. The opening message of
// an interaction is the Elicit kind (code 0), whose declared effect is read_only.
const (
	channelInteraction = 0x000F
	kindElicit         = 0
	message            = "hello from agent A"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "naalp-quickstart:", err)
		os.Exit(1)
	}
}

// run performs the two-agent loop, writing each step to out, and returns a non-nil error if any
// invariant is violated (genuine object must verify and round-trip; tampered object must be
// rejected). Returning the error here — rather than only printing — is what makes the tamper
// check mutation-surviving: a verify path that failed to reject a tamper makes run return an
// error, which the test asserts is nil for the genuine flow and which main turns into a non-zero
// exit.
func run(out io.Writer) error {
	// Step 1 — agent A generates a fresh identity.
	agentA, err := naalp.GenerateSigner()
	if err != nil {
		return fmt.Errorf("agent A key generation: %w", err)
	}
	pubA := agentA.PublicKey()
	fmt.Fprintf(out, "[1] agent A generated an identity\n")
	fmt.Fprintf(out, "    signer id : %s\n", agentA.SignerID())
	fmt.Fprintf(out, "    public key: %d bytes (ML-DSA-65)\n", len(pubA))

	// Step 2 — agent A builds and signs a real N-AALP Interaction message.
	spec, _ := channels.Lookup(channelInteraction, kindElicit)
	env, err := agentA.Sign(channelInteraction, kindElicit, 1785000000000, cbor.Tstr(message))
	if err != nil {
		return fmt.Errorf("agent A sign: %w", err)
	}
	fmt.Fprintf(out, "[2] agent A signed an object\n")
	fmt.Fprintf(out, "    channel   : 0x%04X (Interaction)  kind: %d (%s)  effect: %s\n",
		channelInteraction, kindElicit, spec.Name, spec.Effect.SafetyLabelName())
	fmt.Fprintf(out, "    body      : %q\n", message)
	fmt.Fprintf(out, "    signed obj: %d bytes (deterministic CBOR + COSE_Sign1 ML-DSA-65)\n", len(env))

	// Step 3 — the object and agent A's public key cross the wire to agent B.
	fmt.Fprintf(out, "[3] over the wire to agent B: %d object bytes + %d public-key bytes\n", len(env), len(pubA))

	// Step 4 — agent B verifies OFFLINE and reads the message.
	obj, err := naalp.Verify(pubA, env)
	if err != nil {
		return fmt.Errorf("agent B failed to verify a genuine object: %w", err)
	}
	body, ok := obj.Body.(cbor.Tstr)
	if !ok {
		return fmt.Errorf("agent B: verified body was not text as expected")
	}
	if string(body) != message {
		return fmt.Errorf("agent B: body round-trip mismatch: got %q want %q", string(body), message)
	}
	if string(obj.Signer) != agentA.SignerID() {
		return fmt.Errorf("agent B: verified signer id %q does not match agent A's id %q", string(obj.Signer), agentA.SignerID())
	}
	fmt.Fprintf(out, "[4] agent B VERIFIED the object offline (no network)\n")
	fmt.Fprintf(out, "    from      : %s\n", string(obj.Signer))
	fmt.Fprintf(out, "    read      : %q\n", string(body))

	// Step 5 — a one-byte tamper must be rejected fail-closed.
	tampered := append([]byte(nil), env...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := naalp.Verify(pubA, tampered); err == nil {
		return fmt.Errorf("agent B accepted a TAMPERED object; it must be rejected fail-closed")
	} else {
		fmt.Fprintf(out, "[5] agent B REJECTED a tampered copy, fail-closed: %v\n", err)
	}

	fmt.Fprintln(out, "OK: two-agent sign -> verify -> read succeeded and tamper was rejected")
	return nil
}
