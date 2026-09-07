# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
D10 / #241 — thread-safety patch for dilithium-py's module-level SHAKE singletons.

`dilithium-py` is a PyPI dependency (pyproject.toml: `dilithium-py>=1.4.0`), not vendored
in-tree, so this patch is applied at RUNTIME from tree code rather than by editing the
installed package -- editing site-packages directly would pass locally and silently vanish
the moment CI does a fresh `pip install` (design.md addendum D10/#241).

The bug (isolated 8-thread repro: 65/160 verify failures): dilithium_py.shake.shake_wrapper
(the pure-Python fallback used whenever the optional `xoflib` C-extension is NOT installed --
true in this environment, and true wherever `xoflib` is not a declared/installed dependency)
exposes exactly two module-level singleton `Shake` INSTANCES:

    shake128 = Shake(shake_128, 168)
    shake256 = Shake(shake_256, 136)

`Shake.absorb()`/`Shake.read()` mutate `self.index`, `self.xof_read`, `self.buf`, and
`self.len_buf` -- ordinary instance attributes on those two SHARED objects. Three call
sites (dilithium.py, ml_dsa.py, polynomials.py) do `xof = shake256(seed)` then read from
`xof` later; because `xof` IS the shared singleton, two threads mid-keygen/sign/verify at
once step on each other's absorb-then-read sequence and corrupt each other's output.

Fix: replace the shared MUTABLE STATE with per-thread state, keyed by `id(self)` in a
`threading.local()`. `algorithm` and `block_length` are set once at __init__ and never
mutated, so they stay as ordinary (safely shared, read-only) instance attributes; only the
absorb/read cursor state moves off `self` and into thread-local storage. The arithmetic is
byte-for-byte unchanged -- SHAKE output is a pure function of the absorbed input bytes only
(no cross-call state affects output), so this preserves byte-parity BY CONSTRUCTION: the
frozen conformance corpus (Go == Rust == Python) does not need to change and does not.

Applied once, at `naalp.cose` import time (idempotent -- re-import is a no-op), before any
ML-DSA operation runs. If `xoflib` is installed (not true today: it is not a declared
dependency and is absent from this environment), the three call sites above bind their
`shake128`/`shake256` names from `xoflib` instead of this module, and this patch is inert
by construction (it only ever touches `dilithium_py.shake.shake_wrapper.Shake`).
"""
import threading

from dilithium_py.shake.shake_wrapper import Shake

_PATCH_MARKER = "_naalp_thread_local_shake"

# Guard against double-patching (e.g. two `naalp` submodules importing this module) --
# harmless either way since the replacement functions are idempotent, but keep it explicit.
if not getattr(Shake, _PATCH_MARKER, False):
    _tls = threading.local()

    def _state(self):
        """This thread's private absorb/read cursor for a (possibly process-shared) Shake
        instance, keyed by id(self) so the two module-level singletons (shake128, shake256)
        each get independent per-thread state without touching `self.__dict__`."""
        store = getattr(_tls, "by_id", None)
        if store is None:
            store = {}
            _tls.by_id = store
        st = store.get(id(self))
        if st is None:
            st = {"index": 0, "xof_read": None, "buf": b"", "len_buf": 0}
            store[id(self)] = st
        return st

    def _absorb(self, input_bytes):
        """Initialise the XOF with the seed (identical algorithm to the original; only the
        cursor storage moved from `self` to thread-local state)."""
        st = _state(self)
        st["index"] = 0
        st["xof_read"] = self.algorithm(input_bytes).digest
        st["buf"] = st["xof_read"](5 * self.block_length)
        st["len_buf"] = 5 * self.block_length

    def _read(self, n):
        """Read n bytes from the XOF (identical algorithm to the original)."""
        st = _state(self)
        while st["index"] + n > st["len_buf"]:
            st["len_buf"] *= 2
            st["buf"] = st["xof_read"](st["len_buf"])
        send = st["buf"][st["index"]: st["index"] + n]
        st["index"] += n
        return send

    Shake.absorb = _absorb
    Shake.read = _read
    setattr(Shake, _PATCH_MARKER, True)
