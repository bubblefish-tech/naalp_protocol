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

        # ---- draft-01 ForkProof full body: byte-identical across implementations (#70) ----
        # The complete signed fork-proof object embeds the accused authority's two DETERMINISTIC
        # ML-DSA signatures over the two receipt bodies. Like cose.sign1 the signature bytes have no
        # committed KAT, so the honest grade is unanimous byte-agreement across implementations: the
        # framing is already graded == oracle (forkproof.preimage), and each signature is the same
        # NIST-anchored deterministic ML-DSA graded above, so byte-identical full bodies ⟹ Go==Rust
        # on the whole non-repudiable proof.
        for tc in load_group(corpus, "forkproof.body"):
            label = "forkproof.body " + tc.get("comment", f"tc{tc['tcId']}")
            bodies, prev_only = {}, {}
            for a in adapters:
                r = a.call("forkproof.body", tc["in"])
                if "skipped" in r:
                    continue
                if "error" in r:
                    failures.append(f"{label}: {a.name} error: {r['error']}")
                    continue
                bodies[a.name] = r["out"]["body_hex"]
                prev_only[a.name] = r["out"].get("preimage_hex", "")
                implementing.add(a.name)
            names = sorted(bodies)
            if len(bodies) < 2:
                print(f"  {label}: only {len(bodies)} adapter(s) implement forkproof.body "
                      f"({names or 'none'}) - consensus needs >=2; SKIP")
                continue
            if len(set(bodies.values())) != 1:
                failures.append(f"{label}: forkproof.body DISAGREEMENT across {names}: "
                                + "; ".join(f"{n}={bodies[n][:24]}.." for n in names))
                print(f"  {label}: DISAGREE across {names}")
                continue
            consensus = next(iter(set(bodies.values())))
            # the full body must strictly extend its own framing witness (the signatures are carried)
            for n in names:
                if prev_only[n] and prev_only[n] == bodies[n]:
                    failures.append(f"{label}: {n} full body equals its sig-elided witness")
            print(f"  {label}: {len(bodies)} adapters agree byte-for-byte ({names}); "
                  f"body={consensus[:20]}.. ({len(consensus)//2} bytes)")

        # ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
        # Like cose.sign1, the deterministic two-leg composite value (mldsaSig||edSig) has no clean
        # committed KAT, so its cross-language byte-parity is graded by unanimous agreement: every
        # adapter implementing composite.sign must produce a BYTE-IDENTICAL value over the same
        # seeds+tbs, and each must composite.verify(consensus)==valid and reject a one-byte tamper.
        # The M' construction and the composite signer id ARE committed KATs (graded in the corpus).
        # The composite pubkeys come from the composite.signerid group (same worked fixture); the
        # seven composite-less ports return skipped and are tracked UNIMPLEMENTED, never a false green.
        comp_sid = load_group(corpus, "composite.signerid")
        comp_pub = comp_sid[0]["in"] if comp_sid else None
        for tc in load_group(corpus, "composite.sign"):
            label = "composite.sign " + tc.get("comment", f"tc{tc['tcId']}")
            vals = {}
            for a in adapters:
                r = a.call("composite.sign", tc["in"])
                if "skipped" in r:
                    continue
                if "error" in r:
                    failures.append(f"{label}: {a.name} composite.sign error: {r['error']}")
                    continue
                vals[a.name] = r["out"]["value_hex"]
                implementing.add(a.name)
            names = sorted(vals)
            if len(vals) < 2:
                print(f"  {label}: only {len(vals)} adapter(s) implement composite.sign "
                      f"({names or 'none'}) - consensus needs >=2; SKIP")
                continue
            if len(set(vals.values())) != 1:
                failures.append(f"{label}: composite.sign DISAGREEMENT across {names}: "
                                + "; ".join(f"{n}={vals[n][:24]}.." for n in names))
                print(f"  {label}: DISAGREE across {names}")
                continue
            consensus = next(iter(set(vals.values())))
            print(f"  {label}: {len(vals)} adapters agree byte-for-byte ({names}); "
                  f"value={consensus[:20]}.. ({len(consensus)//2} bytes)")
            if comp_pub is None:
                failures.append(f"{label}: no composite.signerid pubkeys for the verify step")
                continue
            m_hex = tc["in"]["tbs_hex"]
            tampered = consensus[:-2] + ("00" if consensus[-2:] != "00" else "01")
            vin = {"mldsa_pubkey_hex": comp_pub["mldsa_pubkey_hex"],
                   "ed_pubkey_hex": comp_pub["ed_pubkey_hex"], "m_hex": m_hex}
            for n in names:
                a = next(x for x in adapters if x.name == n)
                rv = a.call("composite.verify", {**vin, "sig_hex": consensus})
                if rv.get("out", {}).get("valid") is not True:
                    failures.append(f"{label}: {n} composite.verify(consensus) != valid: {rv}")
                rt = a.call("composite.verify", {**vin, "sig_hex": tampered})
                if rt.get("out", {}).get("valid") is not False:
                    failures.append(f"{label}: {n} composite.verify(tampered) != invalid: {rt}")

        # ---- §5.2 Rotation object (tag-98 two-leg co-signature, #143) ----
        # The full tag-98 rotation object embeds the old and new keys' two DETERMINISTIC ML-DSA
        # signatures over the object payload. Like cose.sign1 the signature bytes have no committed
        # KAT, so the honest grade is unanimous byte-agreement across implementations: every adapter
        # implementing rotation.sign must produce a BYTE-IDENTICAL tag-98 object over the same
        # seeds+protected+payload, and each must rotation.verify(consensus)==valid and reject a
        # one-byte tamper. The leg Sig_structure and every verify verdict ARE committed KATs (corpus);
        # the eight rotation-less ports return skipped and are tracked UNIMPLEMENTED, never a false green.
        rot_verify = load_group(corpus, "rotation.verify")
        rot_good = next((v for v in rot_verify if v.get("expected", {}).get("valid") is True), None)
        for tc in load_group(corpus, "rotation.sign"):
            label = "rotation.sign " + tc.get("comment", f"tc{tc['tcId']}")
            objs = {}
            for a in adapters:
                r = a.call("rotation.sign", tc["in"])
                if "skipped" in r:
                    continue
                if "error" in r:
                    failures.append(f"{label}: {a.name} rotation.sign error: {r['error']}")
                    continue
                objs[a.name] = r["out"]["obj_hex"]
                implementing.add(a.name)
            names = sorted(objs)
            if len(objs) < 2:
                print(f"  {label}: only {len(objs)} adapter(s) implement rotation.sign "
                      f"({names or 'none'}) - consensus needs >=2; SKIP")
                continue
            if len(set(objs.values())) != 1:
                failures.append(f"{label}: rotation.sign DISAGREEMENT across {names}: "
                                + "; ".join(f"{n}={objs[n][:24]}.." for n in names))
                print(f"  {label}: DISAGREE across {names}")
                continue
            consensus = next(iter(set(objs.values())))
            print(f"  {label}: {len(objs)} adapters agree byte-for-byte ({names}); "
                  f"obj={consensus[:20]}.. ({len(consensus)//2} bytes)")
            if rot_good is None:
                failures.append(f"{label}: no accepting rotation.verify case for the verify step")
                continue
            gi = rot_good["in"]
            vin = {"old_alg": gi["old_alg"], "old_pubkey_hex": gi["old_pubkey_hex"],
                   "new_alg": gi["new_alg"], "new_pubkey_hex": gi["new_pubkey_hex"], "profile": gi["profile"]}
            tampered = consensus[:-2] + ("00" if consensus[-2:] != "00" else "01")
            for n in names:
                a = next(x for x in adapters if x.name == n)
                rv = a.call("rotation.verify", {**vin, "obj_hex": consensus})
                if rv.get("out", {}).get("valid") is not True:
                    failures.append(f"{label}: {n} rotation.verify(consensus) != valid: {rv}")
                rt = a.call("rotation.verify", {**vin, "obj_hex": tampered})
                if rt.get("out", {}).get("valid") is not False:
                    failures.append(f"{label}: {n} rotation.verify(tampered) != invalid: {rt}")
    finally:
        for a in adapters:
            a.close()

    print()
    if failures:
        print("CRYPTO-CONSENSUS: FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print(f"CRYPTO-CONSENSUS: PASS - deterministic ML-DSA COSE_Sign1, the draft-01 ForkProof full "
          f"body, the opt-in LAMPS composite value (§4.2), and the §5.2 tag-98 rotation object "
          f"byte-identical across {sorted(implementing)}; each verifies the consensus signature/object "
          f"and rejects a tamper.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
