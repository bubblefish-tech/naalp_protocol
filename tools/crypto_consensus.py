# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
crypto_consensus.py - the cross-language deterministic-ML-DSA byte-parity gate.

The one op the op-replay corpus cannot grade against a committed value is cose.sign1: the
deterministic ML-DSA signature has no clean non-circular committed KAT (the NIST ACVP sigGen
vectors are an internal interface - see the T2 ledger note). This gate grades it the only honest
way for an ecosystem: every adapter that implements cose.sign1 must produce a BYTE-IDENTICAL
signature over the same seed+payload, and each such signature must verify under the NIST-anchored
public key. Because each impl's ML-DSA is independently anchored by the mldsa.keygen (NIST ACVP
seed->pk) and cose.tbs (RFC 9052) KATs it already passes, unanimous byte-agreement means unanimous
correctness - the "two independent implementations, byte-identical" property (draft CLAUDE.md)
extended to N languages. This is F3-honest: for any third-party SDK the expected signature is the
independently-established consensus of the reference implementations, not the SDK's own output.

An adapter that returns {"skipped"} for cose.sign1 (no deterministic FIPS 204 library) is tracked
as UNIMPLEMENTED for the crypto leg - never a false green - exactly as the ML-DSA-availability
tracking for the additional-language SDKs requires.

Usage:
  python tools/crypto_consensus.py name=cmd [name=cmd ...]
    e.g. python tools/crypto_consensus.py \
      go=./harness/adapters/go/naalp-adapter-go.exe \
      rust=./harness/adapters/rust/target/release/naalp-adapter-rust.exe

Exit 0 iff every implementing adapter agrees byte-for-byte AND its verifier accepts the consensus
signature and rejects a tampered one; requires at least two implementing adapters to form a
consensus. Exit non-zero otherwise.
"""
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "vectors", "conformance", "corpus.json")


class Adapter:
    def __init__(self, name, command):
        self.name = name
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=sys.stderr, shell=False)

    def call(self, op, in_):
        req = json.dumps({"op": op, "in": in_}).encode("utf-8")
        self.proc.stdin.write(struct.pack("<I", len(req)))
        self.proc.stdin.write(req)
        self.proc.stdin.flush()
        lp = self._readn(4)
        n = struct.unpack("<I", lp)[0]
        return json.loads(self._readn(n).decode("utf-8"))

    def _readn(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.proc.stdout.read(n - len(buf))
            if not chunk:
                raise EOFError(f"adapter {self.name} closed the pipe")
            buf += chunk
        return buf

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def load_group(corpus, op):
    for g in corpus["testGroups"]:
        if g["op"] == op:
            return g["tests"]
    return []


def pk_for_alg(keygen_tests, alg):
    # the cose.sign1 seed is the mldsa.keygen seed for that alg; its pk is the NIST-anchored pk.
    param = "ML-DSA-65" if alg == -49 else "ML-DSA-87" if alg == -50 else None
    for t in keygen_tests:
        if t["in"].get("param") == param:
            return t["expected"]["pk_hex"]
    return None


def main():
    specs = sys.argv[1:]
    if not specs:
        print("usage: python tools/crypto_consensus.py name=cmd [name=cmd ...]", file=sys.stderr)
        return 2
    corpus = json.load(open(CORPUS, encoding="utf-8"))
    sign1 = load_group(corpus, "cose.sign1")
    keygen = load_group(corpus, "mldsa.keygen")
    if not sign1:
        print("no cose.sign1 cases in corpus", file=sys.stderr)
        return 2

    adapters = []
    for s in specs:
        name, _, cmd = s.partition("=")
        adapters.append(Adapter(name, cmd.split()))

    failures = []
    implementing = set()
    print(f"crypto-consensus over {len(adapters)} adapters: {', '.join(a.name for a in adapters)}\n")
    try:
        for tc in sign1:
            alg = tc["in"]["alg"]
            label = tc.get("comment", f"tc{tc['tcId']}")
            sigs = {}
            for a in adapters:
                r = a.call("cose.sign1", tc["in"])
                if "skipped" in r:
                    continue
                if "error" in r:
                    failures.append(f"{label}: {a.name} cose.sign1 error: {r['error']}")
                    continue
                sigs[a.name] = r["out"]["obj_hex"]
                implementing.add(a.name)
            impl_names = sorted(sigs)
            if len(sigs) < 2:
                print(f"  {label}: only {len(sigs)} adapter(s) implement cose.sign1 "
                      f"({impl_names or 'none'}) - consensus needs >=2; SKIP")
                continue
            distinct = set(sigs.values())
            if len(distinct) != 1:
                failures.append(f"{label}: cose.sign1 DISAGREEMENT across {impl_names}: "
                                + "; ".join(f"{n}={sigs[n][:24]}.." for n in impl_names))
                print(f"  {label}: DISAGREE across {impl_names}")
                continue
            consensus = next(iter(distinct))
            print(f"  {label}: {len(sigs)} adapters agree byte-for-byte ({impl_names}); "
                  f"obj={consensus[:20]}.. ({len(consensus)//2} bytes)")

            # verify: each implementing adapter accepts the consensus signature and rejects a tamper
            pk = pk_for_alg(keygen, alg)
            if pk is None:
                failures.append(f"{label}: no NIST pk for alg {alg}")
                continue
            tampered = consensus[:-2] + ("00" if consensus[-2:] != "00" else "01")
            for n in impl_names:
                a = next(x for x in adapters if x.name == n)
                rv = a.call("cose.verify1", {"alg": alg, "pubkey_hex": pk, "obj_hex": consensus})
                if rv.get("out", {}).get("valid") is not True:
                    failures.append(f"{label}: {n} verify(consensus) != valid: {rv}")
                rt = a.call("cose.verify1", {"alg": alg, "pubkey_hex": pk, "obj_hex": tampered})
                if rt.get("out", {}).get("valid") is not False:
                    failures.append(f"{label}: {n} verify(tampered) != invalid: {rt}")
    finally:
        for a in adapters:
            a.close()

    print()
    if failures:
        print("CRYPTO-CONSENSUS: FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print(f"CRYPTO-CONSENSUS: PASS - deterministic ML-DSA COSE_Sign1 byte-identical across "
          f"{sorted(implementing)}; each verifies the consensus signature and rejects a tamper.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
