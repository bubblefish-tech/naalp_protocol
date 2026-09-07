# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp.cli — a small command-line tool over the N-AALP SDK.

Three subcommands, each delegating to the reference primitives (no crypto or encoding of its own):

    naalp keygen [--alg ml-dsa-65|ml-dsa-87] [--seed-hex HEX]
        Derive (or generate) a key seed, print its public key and self-certifying signer id.

    naalp sign --seed-hex HEX --channel N --kind N --message TEXT [--effect N] [--profile N] [--out FILE]
        Build a message body {1: TEXT}, sign a full N-AALP object on (channel, kind), and emit the
        self-describing object bytes to --out (or stdout).

    naalp verify --pubkey-hex HEX [--profile N] [--in FILE]
        Read a signed object from --in (or stdin), verify it offline, print the decoded object and
        exit 0; on any failure print the named error and exit non-zero (fail-closed).

Run as `python -m naalp.cli ...` or, once installed, as `naalp ...`.
"""
import argparse
import sys

from . import channels, cose, ez
from .cbor import U, T, M

_ALGS = {
    "ml-dsa-65": cose.ALG_MLDSA65,
    "ml-dsa-87": cose.ALG_MLDSA87,
}
_KEYGEN_PARAM = {cose.ALG_MLDSA65: "ML-DSA-65", cose.ALG_MLDSA87: "ML-DSA-87"}

_MSG_FIELD = 1  # the message-text field of the CLI's interaction body


def _err(msg):
    sys.stderr.write("naalp: " + msg + "\n")


def _read_hex(label, s):
    try:
        return bytes.fromhex(s.strip())
    except ValueError:
        raise SystemExit("naalp: %s is not valid hex" % label)


def _cmd_keygen(args):
    alg = _ALGS[args.alg]
    if args.seed_hex is not None:
        seed = _read_hex("--seed-hex", args.seed_hex)
        if len(seed) != 32:
            _err("--seed-hex must decode to exactly 32 bytes")
            return 2
    else:
        import os
        seed = os.urandom(32)
    pk = cose.mldsa_keygen(_KEYGEN_PARAM[alg], seed)
    sid = ez.Signer(seed, alg=alg).signer_id
    out = sys.stdout
    out.write("alg       %s\n" % args.alg)
    out.write("seed      %s\n" % seed.hex())
    out.write("pubkey    %s\n" % pk.hex())
    out.write("signer-id %s\n" % sid)
    return 0


def _cmd_sign(args):
    alg = _ALGS[args.alg]
    seed = _read_hex("--seed-hex", args.seed_hex)
    try:
        signer = ez.Signer(seed, alg=alg, profile=args.profile)
    except ValueError as e:
        _err(str(e))
        return 2
    payload = M([(U(_MSG_FIELD), T(args.message))])
    try:
        signed = signer.sign(args.channel, args.kind, payload, effect=args.effect)
    except channels.UnknownKind as e:
        _err("unknown channel/kind: %s" % e)
        return 2
    except (channels.EffectDeclarationMismatch, ValueError) as e:
        _err("cannot sign: %s" % e)
        return 2
    if args.out:
        with open(args.out, "wb") as f:
            f.write(signed)
        _err("signed %d bytes -> %s  (signer %s)" % (len(signed), args.out, signer.signer_id))
    else:
        sys.stdout.buffer.write(signed)
        _err("signed %d bytes  (signer %s)" % (len(signed), signer.signer_id))
    return 0


def _decode_message(body):
    """Return the object's message text if the body is {1: text}, else None."""
    if isinstance(body, M):
        for k, v in body.pairs:
            if isinstance(k, U) and k.v == _MSG_FIELD and isinstance(v, T):
                return v.v
    return None


def _cmd_verify(args):
    pubkey = _read_hex("--pubkey-hex", args.pubkey_hex)
    if args.in_path:
        with open(args.in_path, "rb") as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()
    try:
        obj = ez.verify(pubkey, data, profile=args.profile)
    except Exception as e:  # envelope.EnvelopeError / cose / cbor errors all carry a .kind or a message
        _err("verify FAILED: %s" % getattr(e, "kind", type(e).__name__))
        return 2
    name, _effect, _var = channels.lookup(obj.channel, obj.kind)
    ch_name = channels.TABLE[obj.channel][0]
    out = sys.stdout
    out.write("verify OK\n")
    out.write("  channel   0x%04x %s\n" % (obj.channel, ch_name))
    out.write("  kind      %d %s\n" % (obj.kind, name))
    out.write("  effect    %d\n" % obj.effect)
    out.write("  profile   %d\n" % obj.profile)
    out.write("  signer    %s\n" % obj.signer.decode("utf-8", "replace"))
    out.write("  id        %s\n" % (obj.id.hex() if obj.id else "(none)"))
    msg = _decode_message(obj.body)
    if msg is not None:
        out.write("  message   %s\n" % msg)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="naalp", description="Sign and verify N-AALP objects.")
    sub = p.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="derive/generate a key and print pubkey + signer id")
    kg.add_argument("--alg", choices=sorted(_ALGS), default="ml-dsa-65")
    kg.add_argument("--seed-hex", default=None, help="32-byte seed as hex (random if omitted)")
    kg.set_defaults(func=_cmd_keygen)

    sg = sub.add_parser("sign", help="sign a message object and emit its bytes")
    sg.add_argument("--seed-hex", required=True, help="32-byte key seed as hex")
    sg.add_argument("--alg", choices=sorted(_ALGS), default="ml-dsa-65")
    sg.add_argument("--channel", type=int, required=True, help="channel code 0..19")
    sg.add_argument("--kind", type=int, required=True, help="kind code within the channel")
    sg.add_argument("--effect", type=int, default=None, help="effect 0..3 (required for variable kinds)")
    sg.add_argument("--profile", type=int, default=cose.PROFILE_PUBLIC, help="1 public, 2 enterprise, 3 sovereign")
    sg.add_argument("--message", required=True, help="the message text (object body field 1)")
    sg.add_argument("--out", default=None, help="write object bytes here (default: stdout)")
    sg.set_defaults(func=_cmd_sign)

    vf = sub.add_parser("verify", help="verify a signed object; exit 0 ok, non-zero on failure")
    vf.add_argument("--pubkey-hex", required=True, help="signer public key as hex")
    vf.add_argument("--profile", type=int, default=cose.PROFILE_PUBLIC, help="minimum profile the verifier requires")
    vf.add_argument("--in", dest="in_path", default=None, help="read object bytes here (default: stdin)")
    vf.set_defaults(func=_cmd_verify)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
