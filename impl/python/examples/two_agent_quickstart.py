# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
examples/two_agent_quickstart.py — the N-AALP core loop between two agents, end to end.

Agent A generates a post-quantum identity, builds a message on the Interaction surface, and signs
it into one self-describing N-AALP object. Only those object bytes (and Agent A's public key) cross
to Agent B. Agent B verifies the object offline — real ML-DSA signature, content-id rebind, channel
registry, profile floor — and reads the message. Finally a single flipped byte is shown to be
rejected. There is no hand-rolled crypto here: every step calls the reference SDK through the
ergonomic naalp.ez surface.

Run:  python examples/two_agent_quickstart.py
"""
import os
import sys

# Run in-tree without an install (a pip-installed `naalp` still takes precedence if present).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from naalp import channels, cose, ez            # noqa: E402
from naalp.cbor import U, T, M                   # noqa: E402
from naalp.envelope import EnvelopeError         # noqa: E402

# The Interaction surface (design-channels.md §16): channel 0x000F, kind 1 "Respond" — a posted
# message. The SDK derives the declared effect (idempotent_write) from the registry.
INTERACTION = 0x000F
RESPOND = 1


def main():
    # --- Agent A: generate an identity -------------------------------------------------
    agent_a = ez.Signer.generate(alg=cose.ALG_MLDSA65)
    print("[A] generated ML-DSA-65 identity")
    print("    signer id :", agent_a.signer_id)
    print("    public key:", agent_a.public_key[:8].hex() + "..%d bytes" % len(agent_a.public_key))

    # --- Agent A: build + sign a message on the Interaction surface ---------------------
    name, effect, _var = channels.lookup(INTERACTION, RESPOND)
    text = "Hello Agent B - this object is signed, not the connection."
    body = M([(U(1), T(text))])
    envelope_bytes = agent_a.sign(INTERACTION, RESPOND, body)
    print("[A] signed a %s object on channel 0x%04x (%s), effect=%d"
          % (name, INTERACTION, channels.TABLE[INTERACTION][0], effect))
    print("    object    :", "%d bytes, %s.." % (len(envelope_bytes), envelope_bytes[:6].hex()))

    # --- the wire: only the object bytes + A's public key reach B -----------------------
    wire = bytes(envelope_bytes)
    a_pubkey = agent_a.public_key
    print("[.] transmitted %d object bytes to Agent B (any transport)" % len(wire))

    # --- Agent B: verify offline and read ----------------------------------------------
    obj = ez.verify(a_pubkey, wire)
    got_name, _e, _v = channels.lookup(obj.channel, obj.kind)
    read_text = next((v.v for k, v in obj.body.pairs
                      if isinstance(k, U) and k.v == 1 and isinstance(v, T)), None)
    print("[B] verified OK: channel 0x%04x kind %d (%s), signer %s.."
          % (obj.channel, obj.kind, got_name, obj.signer.decode("utf-8")[:12]))
    print('[B] read message: "%s"' % read_text)
    assert read_text == text, "verified message did not round-trip"

    # --- tamper: one flipped byte must be rejected (fail-closed) ------------------------
    tampered = bytearray(wire)
    tampered[-1] ^= 0x01
    try:
        ez.verify(a_pubkey, bytes(tampered))
    except EnvelopeError as e:
        print("[B] tamper rejected:", e.kind)
    else:
        # If verify ever accepted a tampered object, the core guarantee is broken — fail loudly.
        print("[B] FAILURE: tampered object was accepted")
        raise SystemExit(1)

    print("\nOK - signed by A, verified by B, tamper rejected.")


if __name__ == "__main__":
    main()
