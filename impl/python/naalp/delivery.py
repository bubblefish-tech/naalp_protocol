# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C8 delivery for the Python SDK -- delivery as four signed monotonic stages, the
persist-before-acknowledge discipline, the live full-duplex switchboard, and the content-free
relay (design.md §9; R-9.1..9.4).

Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
target object's content id and the stage reached -- there is no single "sent" boolean (§9.1):
persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
(§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
switchboard holds two connections open and passes objects through both directions concurrently
(§9.3); a relay that holds objects only in transit writes an audit trail over content ids while
retaining no payload (§9.4, R-9.4).

Ported from impl/go/delivery. The delivery.update SIGNATURE is a RAW deterministic ML-DSA
signature over the update body (cose.mldsa_sign / cose.mldsa_verify). The content-id framing and
the relay's retained trail reuse the shared naalp.cbor and naalp.audit. Graded against the shared
vectors/delivery/cases.json.
"""
import os
import queue
import struct
import threading
from dataclasses import dataclass

from . import audit, cbor, cose
from .cbor import U, B, M

# Delivery stages (design §9.1), monotonic in this order.
STAGE_PERSISTED_ORIGIN = 0
STAGE_ACCEPTED_RELAY = 1
STAGE_PERSISTED_TARGET = 2
STAGE_PRESENTED = 3

_STAGE_NAMES = ("persisted_origin", "accepted_relay", "persisted_target", "presented")


def stage_name(stage):
    """The name of a stage value (0..3), or 'unknown'."""
    if 0 <= stage < len(_STAGE_NAMES):
        return _STAGE_NAMES[stage]
    return "unknown"


class DeliveryError(ValueError):
    """A named, fail-closed delivery error; .kind is the stable error kind."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def content_id(b):
    """T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets),
    identical to the spine framing (naalp.cbor.content_id over raw bytes)."""
    return cbor.content_id(bytes(b))


@dataclass(frozen=True)
class DeliveryUpdate:
    """One signed delivery-stage notification (design §9.1)."""

    obj: bytes    # content id of the object whose delivery this reports
    stage: int    # the stage reached (0..3)
    at: int       # observer time, epoch ms

    def bytes(self):
        """Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}."""
        return cbor.encode(M([(U(1), B(self.obj)), (U(2), U(self.stage)), (U(3), U(self.at))]))


def sign_update(update, alg, seed):
    """Sign a delivery.update with the observer's key: a RAW deterministic signature over the
    update body."""
    return cose.mldsa_sign(alg, seed, update.bytes())


def verify_update(update, alg, pubkey, sig):
    """Verify a raw delivery.update signature under the observer's public key."""
    return cose.mldsa_verify(alg, pubkey, update.bytes(), sig)


def _parse_update(rec):
    """Reconstruct a DeliveryUpdate from a WAL record body; fail-closed on a malformed shape."""
    try:
        v = cbor.decode(rec)
    except cbor.NonCanonical as e:
        raise DeliveryError("Malformed", "delivery update is not canonical: %s" % e)
    if not isinstance(v, M):
        raise DeliveryError("Malformed", "delivery update is not a map")
    obj = stage = at = None
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise DeliveryError("Malformed", "non-uint key")
        if k.v == 1 and isinstance(val, B):
            obj = val.v
        elif k.v == 2 and isinstance(val, U):
            stage = val.v
        elif k.v == 3 and isinstance(val, U):
            at = val.v
        else:
            raise DeliveryError("Malformed", "unknown or mistyped delivery-update field %d" % k.v)
    if obj is None or stage is None or at is None:
        raise DeliveryError("Malformed", "delivery update missing a mandatory field")
    return DeliveryUpdate(obj, stage, at)


class Tracker:
    """A durable, per-object delivery-stage tracker enforcing monotonic stages and
    persist-before-acknowledge. Each advance persists to the write-ahead log and fsyncs before
    returning the acknowledging update, so a crash after the ack loses nothing (§9.2). WAL records
    are length-prefixed (4-byte big-endian) deterministic-CBOR update bodies."""

    def __init__(self, f):
        self._lock = threading.Lock()
        self._f = f
        self._current = {}  # object-id (bytes) -> highest stage reached
        self._replay()

    def _replay(self):
        self._f.seek(0)
        while True:
            len_buf = self._f.read(4)
            if len_buf == b"":
                break
            if len(len_buf) != 4:
                raise DeliveryError("Malformed", "truncated WAL length prefix")
            (n,) = struct.unpack(">I", len_buf)
            rec = self._f.read(n)
            if len(rec) != n:
                raise DeliveryError("Malformed", "truncated WAL record")
            u = _parse_update(rec)
            self._current[bytes(u.obj)] = u.stage  # last durable stage wins (monotonic on write)

    def advance(self, obj, stage, at):
        """Record that obj reached stage at time at, returning the acknowledging update. A stage
        earlier than the one already reached is StageOutOfOrder (no state change); re-reporting the
        current stage is an idempotent no-op; a later stage is persisted (WAL fsync) before the update
        is returned. Skipping ahead is permitted; only regression is an error."""
        key = bytes(obj)
        with self._lock:
            cur = self._current.get(key)
            if cur is not None:
                if stage < cur:
                    raise DeliveryError("StageOutOfOrder", "a delivery stage regressed to an earlier stage")
                if stage == cur:
                    return DeliveryUpdate(key, stage, at)
            u = DeliveryUpdate(key, stage, at)
            rec = u.bytes()
            self._f.write(struct.pack(">I", len(rec)) + rec)
            self._f.flush()
            os.fsync(self._f.fileno())  # persist-before-ack (R-9.2)
            self._current[key] = stage
            return u

    def stage(self, obj):
        """The highest stage reached for obj and whether it has been seen."""
        with self._lock:
            s = self._current.get(bytes(obj))
            return (s, True) if s is not None else (0, False)

    def close(self):
        """Flush and close the WAL file."""
        with self._lock:
            self._f.close()


def open_tracker(path):
    """Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable
    stage for every object."""
    f = open(path, "r+b") if os.path.exists(path) else open(path, "w+b")
    return Tracker(f)


class Endpoint:
    """One side of a switchboard connection: objects written to send are relayed to the peer's recv,
    concurrently with the reverse direction."""

    def __init__(self, send_q, recv_q):
        self._send = send_q
        self._recv = recv_q

    def send(self, obj):
        """Submit an object into the switchboard toward the peer."""
        self._send.put(bytes(obj))

    def recv(self, timeout=None):
        """Receive the next object relayed from the peer (blocks until one arrives)."""
        return self._recv.get(timeout=timeout)


class Switchboard:
    """Holds two connections open and relays objects through in both directions concurrently
    (design §9.3) -- a live full-duplex relay, not a one-object mailbox. Two pump threads forward
    left->right and right->left simultaneously; a pump retains nothing (content-free in transit)."""

    _SENTINEL = object()

    def __init__(self, capacity):
        self._l_send = queue.Queue(capacity)
        self._l_recv = queue.Queue(capacity)
        self._r_send = queue.Queue(capacity)
        self._r_recv = queue.Queue(capacity)
        self._left = Endpoint(self._l_send, self._l_recv)
        self._right = Endpoint(self._r_send, self._r_recv)
        # left.send -> right.recv, and right.send -> left.recv, concurrently.
        self._t1 = threading.Thread(target=self._pump, args=(self._l_send, self._r_recv), daemon=True)
        self._t2 = threading.Thread(target=self._pump, args=(self._r_send, self._l_recv), daemon=True)
        self._t1.start()
        self._t2.start()

    def _pump(self, in_q, out_q):
        while True:
            obj = in_q.get()
            if obj is self._SENTINEL:
                return
            out_q.put(obj)  # forwarded in transit; the pump retains nothing

    def left(self):
        return self._left

    def right(self):
        return self._right

    def close(self):
        """Stop both pumps and wait for them to exit."""
        self._l_send.put(self._SENTINEL)
        self._r_send.put(self._SENTINEL)
        self._t1.join()
        self._t2.join()


class ContentFreeRelay:
    """Routes objects while retaining no payload at rest: for each routed object it appends a C7
    audit receipt over the object's content id and returns the object for immediate forwarding,
    keeping only the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained
    audit trail alone verifies as a valid chain."""

    def __init__(self, alg, seed):
        self._auth = audit.Authority(alg, seed)
        self._receipts = []
        self._sigs = []

    def route(self, obj, at):
        """Record an audit receipt over obj's content id and return obj for forwarding. The relay
        keeps the receipt only; it does not store obj."""
        rec, sig = self._auth.append(content_id(obj), at)
        self._receipts.append(rec)
        self._sigs.append(sig)
        return bytes(obj)

    def audit_trail(self):
        """The receipts and signatures the relay retained (its only persistent state), for offline
        chain verification."""
        return list(self._receipts), list(self._sigs)
