# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
D10 / #241 -- concurrency regression test for the dilithium-py SHAKE thread-safety patch
(naalp._dilithium_thread_safety).

Mutation-surviving property: dilithium_py.shake.shake_wrapper exposes exactly two
process-wide singleton Shake instances (shake128, shake256). Before the patch, concurrent
ML-DSA keygen/sign/verify calls from multiple threads corrupt each other's XOF read cursor
mid-absorb/read, at the scale reported in the isolated repro (8 threads, 65/160 verify
failures). This test reproduces that scale: MUTATING the fix (reverting
naalp._dilithium_thread_safety to a no-op, or restoring the original shared-state
absorb/read on Shake) MUST flip test_concurrent_sign_verify_matches_sequential_baseline
from PASS to FAIL -- see the D10/#241 build report for the reverted-patch run.

Run:  python -m unittest -v tests.test_dilithium_thread_safety   (from impl/python/)
"""
import os
import threading
import unittest

from naalp import cose

THREADS = 8
ITERS_PER_THREAD = 20  # 8 * 20 = 160, matching the reported isolated repro scale


def _inputs():
    """(thread_idx, iter_idx) -> (seed, tbs), each unique so cross-thread contamination
    would produce a WRONG (but structurally valid) signature/pk, not just a crash."""
    out = {}
    for t in range(THREADS):
        for i in range(ITERS_PER_THREAD):
            seed = bytes([t, i]) + os.urandom(30)
            tbs = ("thread-safety-tbs-%d-%d" % (t, i)).encode()
            out[(t, i)] = (seed, tbs)
    return out


def _one(seed, tbs):
    """keygen -> sign -> verify for a single (seed, tbs) pair; returns (pk, sig, ok)."""
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    sig = cose.mldsa_sign(cose.ALG_MLDSA65, seed, tbs)
    ok = cose.mldsa_verify(cose.ALG_MLDSA65, pk, tbs, sig)
    return pk, sig, ok


class DilithiumThreadSafetyTest(unittest.TestCase):
    def test_concurrent_sign_verify_matches_sequential_baseline(self):
        inputs = _inputs()

        # Sequential baseline: no concurrency in play, so this defines "correct" independent
        # of whether the patch is applied.
        expected = {key: _one(*args) for key, args in inputs.items()}
        self.assertTrue(all(ok for _pk, _sig, ok in expected.values()),
                         "sequential baseline itself failed to verify -- broken test, not a race")

        # Concurrent run: THREADS threads, each doing ITERS_PER_THREAD keygen+sign+verify
        # cycles on DISTINCT inputs, all hammering the shared shake128/shake256 singletons
        # at once.
        actual = {}
        lock = threading.Lock()
        errors = []

        def worker(t):
            for i in range(ITERS_PER_THREAD):
                key = (t, i)
                seed, tbs = inputs[key]
                try:
                    result = _one(seed, tbs)
                except Exception as exc:  # noqa: BLE001 -- a corrupted XOF can also raise
                    with lock:
                        errors.append((key, exc))
                    continue
                with lock:
                    actual[key] = result

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(THREADS)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [], "concurrent ML-DSA op raised (corrupted XOF cursor): %r" % (errors,))
        self.assertEqual(len(actual), len(inputs), "some concurrent worker never recorded a result")

        mismatches = []
        verify_failures = []
        for key, (exp_pk, exp_sig, _exp_ok) in expected.items():
            act_pk, act_sig, act_ok = actual[key]
            if not act_ok:
                verify_failures.append(key)
            if act_pk != exp_pk or act_sig != exp_sig:
                mismatches.append(key)

        self.assertEqual(
            verify_failures, [],
            "%d/%d concurrent verify() calls failed under threading (shared-singleton XOF race): %r"
            % (len(verify_failures), len(inputs), verify_failures[:10]))
        self.assertEqual(
            mismatches, [],
            "%d/%d concurrent pk/sig results diverged from the sequential baseline "
            "(cross-thread XOF cursor corruption -- non-determinism, not just a failed verify): %r"
            % (len(mismatches), len(inputs), mismatches[:10]))


if __name__ == "__main__":
    unittest.main()
