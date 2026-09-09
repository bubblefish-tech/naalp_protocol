# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The `naalp-mcp-guard` CLI (Group 6, Tasks A.1/A.2): `wrap <server-cmd...>` stands the guard in
front of a real MCP server over its own stdio transport; `verify <receipt>` offline-verifies one
receipt file.

Wire framing: MCP's stdio transport is newline-delimited JSON-RPC 2.0 -- confirmed against the
INSTALLED `mcp` SDK's own client reader this session (`mcp/client/stdio/__init__.py`:
`TextReceiveStream(...)` accumulated then `.split("\\n")`), not assumed from memory. This module
implements that framing directly (a synchronous line-oriented relay) rather than depending on the
`mcp` package's own async client/server machinery, because the guard's downstream connection
needs the tool definitions' RAW annotation values (for `naalp_mcp_bridge`'s effect classification)
and a purely synchronous request/response model that is simple to reason about and test -- the
`mcp` SDK is a real, optional dependency for callers who want to build agents against
`naalp_mcp_bridge`/`naalp_hitl` directly, not a dependency of this relay.

Known limitation (stated honestly, not swept under the rug): when this guard is launched as a
subprocess by an MCP host with no allocated controlling terminal (a "headless" launch), there is
no side channel to prompt a human for approval -- every approval-requiring call is refused
fail-closed (`_AutoDenyInterface`, never a silent approve). A real host-integrated approval UI
(a local socket, a companion app, or the host's own elicitation flow) is `compose mode` work
(Task A.4, deferred; see README "Known limitations")."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup)

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from typing import Any, List, Optional

from naalp import approval, cose

from naalp_hitl.frontend import TerminalFrontend
from naalp_hitl.interceptor import HumanInterface
from naalp_hitl.refusal_log import JsonlRefusalLog

from . import receipt as receipt_mod
from .effect_gate import EffectGate
from .identity import load_or_create_seed
from .proxy import GuardProxy

DEFAULT_STATE_DIR = os.path.join(".", ".naalp-mcp-guard")


class _AutoDenyInterface(HumanInterface):
    """The fail-closed default approval channel when no human-approval side channel exists (a
    headless launch with no controlling terminal). EVERY approval request is declined -- an
    effect that requires approval never executes just because nobody could be asked."""

    def request_approval(self, request):
        return None


# ---- the downstream connection to the real, wrapped MCP server ---------------------------------

class _DownstreamServer:
    """A synchronous JSON-RPC-over-stdio client for the wrapped MCP server subprocess. A
    background thread reads newline-delimited JSON-RPC messages from the child's stdout; `call()`
    blocks the caller until a message naming the SAME id arrives. Any message with no matching
    pending id (a server-initiated notification, or a server-initiated REQUEST such as
    `sampling/createMessage`) is queued in `unsolicited` for the caller to relay upstream
    untouched -- this class never interprets or gates message content; that is the proxy's job."""

    def __init__(self, argv: List[str]):
        self._proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
            text=True, encoding="utf-8", bufsize=1,
        )
        self._pending = {}
        self._lock = threading.Lock()
        self.unsolicited: "queue.Queue[dict]" = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        stdout = self._proc.stdout
        if stdout is None:
            return
        while True:
            line = stdout.readline()
            if line == "":
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            mid = msg.get("id") if isinstance(msg, dict) else None
            slot = None
            if mid is not None:
                with self._lock:
                    slot = self._pending.pop(mid, None)
            if slot is not None:
                slot["response"] = msg
                slot["event"].set()
            else:
                self.unsolicited.put(msg)

    def call(self, request: dict, timeout: float = 120.0) -> dict:
        """Send `request` downstream and block until a response naming the same id arrives."""
        mid = request.get("id")
        event = threading.Event()
        slot = {"event": event, "response": None}
        with self._lock:
            self._pending[mid] = slot
        self._write(request)
        if not event.wait(timeout):
            with self._lock:
                self._pending.pop(mid, None)
            raise TimeoutError("no response from the wrapped server for request id %r" % (mid,))
        return slot["response"]

    def send(self, msg: dict) -> None:
        """Write `msg` downstream with no correlation -- for notifications, and for the client's
        own replies to a server-initiated request (the reply completes the SERVER's request; it
        is not a call this proxy itself issued)."""
        self._write(msg)

    def _write(self, msg: dict) -> None:
        stdin = self._proc.stdin
        if stdin is None:
            raise IOError("wrapped server's stdin is closed")
        stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        stdin.flush()

    def drain_unsolicited(self) -> List[dict]:
        out = []
        while True:
            try:
                out.append(self.unsolicited.get_nowait())
            except queue.Empty:
                break
        return out

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self._proc.terminate()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            if self._proc.stdout:
                self._proc.stdout.close()
        except (OSError, ValueError):
            pass


def _open_controlling_tty():
    """Open the process's controlling terminal directly for the human-approval prompt, so
    stdin/stdout stay reserved for the JSON-RPC wire to whatever launched this guard -- the same
    reason `sudo`/`ssh-add`/`gpg-agent` read/write the controlling tty rather than their own
    stdio. Raises OSError when no controlling terminal exists (a headless launch); the caller
    falls back to `_AutoDenyInterface` in that case, never to reading/writing the wire streams."""
    if os.name == "nt":
        tty_in = open("CON", "r", encoding="utf-8")
        tty_out = open("CON", "w", encoding="utf-8")
    else:
        tty_in = open("/dev/tty", "r", encoding="utf-8")
        tty_out = open("/dev/tty", "w", encoding="utf-8")
    return tty_in, tty_out


def _tty_prompt(tty_in, tty_out, prompt: str) -> str:
    tty_out.write(prompt)
    tty_out.flush()
    line = tty_in.readline()
    return line.rstrip("\n") if line else ""


def _route_client_message(msg: dict, downstream: _DownstreamServer, proxy: GuardProxy,
                           out) -> None:
    """Route ONE message read from the real client (whatever launched this guard). A
    `tools/call` request is gated by `proxy`; a `tools/list` request/response pair is forwarded
    and its result cached; every other request/notification/reply is passed through untouched --
    Requirement 6.1 gates the effecting tool-call path, nothing wider."""
    if not isinstance(msg, dict):
        return
    method = msg.get("method")
    if method is None:
        # A response FROM the client to something the server asked it (e.g. an elicitation or
        # sampling reply): relay it downstream verbatim, uncorrelated (it completes the
        # server's own pending request, not one this proxy issued).
        downstream.send(msg)
        return

    if method == "tools/call":
        response = proxy.handle_tools_call(msg, forward=lambda: downstream.call(msg))
        if "id" in msg:
            _write_message(out, response)
        return

    if "id" in msg:
        response = downstream.call(msg)
        if method == "tools/list":
            proxy.note_tools_list_response(response)
        _write_message(out, response)
    else:
        downstream.send(msg)


def _write_message(stream, msg: dict) -> None:
    stream.write(json.dumps(msg, separators=(",", ":")) + "\n")
    stream.flush()


# ---- subcommands ---------------------------------------------------------------------------

def cmd_wrap(args: argparse.Namespace) -> int:
    state_dir = args.state_dir
    os.makedirs(state_dir, exist_ok=True)

    guard_seed = load_or_create_seed(os.path.join(state_dir, "guard.seed"))
    approver_seed = load_or_create_seed(os.path.join(state_dir, "approver.seed"))
    approver_pubkey = cose.mldsa_keygen("ML-DSA-65", approver_seed)

    ledger = approval.open_ledger(os.path.join(state_dir, "approval-ledger.wal"), authority=args.audience)
    refusal_log = JsonlRefusalLog(os.path.join(state_dir, "refusals.jsonl"))
    receipts_dir = os.path.join(state_dir, "receipts")

    tty_in = tty_out = None
    try:
        tty_in, tty_out = _open_controlling_tty()
    except OSError:
        pass

    if tty_out is not None:
        human_interface = TerminalFrontend(
            args.approver_id, approver_seed,
            input_fn=lambda prompt: _tty_prompt(tty_in, tty_out, prompt),
            output_fn=lambda s: (tty_out.write(str(s) + "\n"), tty_out.flush()),
        )
    else:
        human_interface = _AutoDenyInterface()

    gate = EffectGate(
        guard_seed=guard_seed, guard_identity=args.identity, audience=args.audience,
        approver_alg=cose.ALG_MLDSA65, approver_pubkey=approver_pubkey,
        human_interface=human_interface, refusal_log=refusal_log, ledger=ledger,
    )
    proxy = GuardProxy(gate, receipts_dir=receipts_dir)
    downstream = _DownstreamServer(args.server_cmd)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            _route_client_message(msg, downstream, proxy, sys.stdout)
            for pending in downstream.drain_unsolicited():
                _write_message(sys.stdout, pending)
    finally:
        downstream.close()
        if tty_in is not None:
            tty_in.close()
        if tty_out is not None:
            tty_out.close()
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.receipt, "rb") as f:
        data = f.read()
    ok = receipt_mod.verify_receipt_bytes(data)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="naalp-mcp-guard")
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("wrap", help="stand the guard in front of an MCP server (stdio)")
    w.add_argument("server_cmd", nargs=argparse.REMAINDER,
                    help="the wrapped MCP server's command and arguments")
    w.add_argument("--state-dir", default=DEFAULT_STATE_DIR,
                    help="local per-deployment state dir (identity seeds, ledger, refusal log, receipts)")
    w.add_argument("--audience", default="naalp-mcp-guard",
                    help="the audience this guard's approvals must bind (R-TDCS-5)")
    w.add_argument("--identity", default="naalp-mcp-guard",
                    help="this guard instance's identity string (D6 'where')")
    w.add_argument("--approver-id", default="operator",
                    help="the local human approver's signer id")
    w.set_defaults(func=cmd_wrap)

    v = sub.add_parser("verify", help="offline-verify one receipt file (no network, <1s)")
    v.add_argument("receipt", help="path to a receipt JSON file written by `wrap`")
    v.set_defaults(func=cmd_verify)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
