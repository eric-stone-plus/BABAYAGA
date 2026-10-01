"Framed stdio host adapter: the babayaga/1 supervisor protocol.\n\nFrame contract: newline-delimited JSON frames of at most 64 KiB, at most 32\nsequential requests per process, numeric request-id correlation,\nduplicate-key / non-finite / unknown-field rejection, a 64 KiB response\ncap, disconnect-cancels, and diagnostics never on protocol stdout. The\nprotocol token names the engine's operation vocabulary; the frame contract\nitself is engine-independent, so one host-side client library shape can\ndrive any engine that speaks it.\n\nEvery op dispatches into the SAME cmd_* function the CLI subcommand runs\n(stdout captured under --json semantics) — the adapter adds framing, never\na second source of gate semantics.\n"
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import select
import signal
import sys
import threading
from dataclasses import dataclass
from typing import Any

PROTOCOL = "babayaga/1"
MAX_FRAME_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUESTS = 32
WALL_TIMEOUT_S = 90
READ_OPERATIONS = frozenset(
    {"capabilities", "doctor", "status", "roe-check", "seal-verify", "export-access"})
REFUSED_OPERATIONS = frozenset({"run", "amend"})
OPERATIONS = READ_OPERATIONS


class AdapterError(ValueError):
    """A request is invalid; values must never be interpolated in its message."""


class AdapterRefused(AdapterError):
    """The operation exists but is policy-refused through the adapter."""


class AdapterStopped(BaseException):
    """Unwind all engine finally blocks on timeout or host cancellation."""

    def __init__(self, code: int):
        self.code = code


@dataclass(frozen=True)
class AdapterRequest:
    operation: str
    # This engine addresses campaigns via options, so a non-null
    # engagement_id is always refused by validate().
    engagement_id: str | None = None
    options: dict[str, Any] | None = None


def _int(value, minimum=0, maximum=10_000_000):
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _path_option(options, key):
    value = options.get(key)
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise AdapterError("missing or invalid path option")
    return value


def validate(request: AdapterRequest) -> dict:
    op = request.operation
    if isinstance(op, str) and op in REFUSED_OPERATIONS:
        raise AdapterRefused("operation is never exposed through the adapter")
    if not isinstance(op, str) or op not in OPERATIONS:
        raise AdapterError("unsupported operation")
    if request.engagement_id is not None:
        raise AdapterError("this engine's protocol does not address engagements")
    if request.options is not None and not isinstance(request.options, dict):
        raise AdapterError("options must be an object")
    options = dict(request.options or {})
    allowed = {
        "capabilities": set(), "doctor": set(), "status": set(),
        "roe-check": {"roe_path"}, "seal-verify": {"target"},
        "export-access": {"campaign"},
    }[op]
    if set(options) - allowed:
        raise AdapterError("unsupported option")
    for key in allowed:  # every allowed option here is a required path/name string
        options[key] = _path_option(options, key)
    return options


def _capabilities() -> dict:
    return {"operations": sorted(OPERATIONS), "transport": "stdio",
            "max_request_bytes": MAX_FRAME_BYTES, "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_requests_per_process": MAX_REQUESTS,
            "refused_operations": sorted(REFUSED_OPERATIONS),
            "disconnect_cancels": True}


def _invoke(fn, **fields):
    """Run a CLI cmd_* function in-process and capture its --json payload.

    Same function, same gates, same exit contract as the CLI subcommand;
    a non-JSON or non-object emission is an engine failure, not a refusal.
    """
    args = argparse.Namespace(json=True, **fields)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = int(fn(args))
    try:
        payload = json.loads(buf.getvalue())
    except ValueError as exc:
        raise RuntimeError("engine command did not emit a JSON payload") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("engine command emitted a non-object payload")
    return code, payload


def dispatch(request: AdapterRequest) -> dict:
    options = validate(request)
    op = request.operation
    if op == "capabilities":
        code, data = 0, _capabilities()
    else:
        from . import cli
        if op == "doctor":
            code, data = _invoke(cli.cmd_doctor)
        elif op == "status":
            code, data = _invoke(cli.cmd_status)
        elif op == "roe-check":
            code, data = _invoke(cli.cmd_roe_check, roe_file=options["roe_path"])
        elif op == "seal-verify":
            code, data = _invoke(cli.cmd_seal, target=options["target"], verify=True)
        else:  # export-access
            code, data = _invoke(cli.cmd_export_access, campaign=options["campaign"], out=None)
    return {"protocol": PROTOCOL, "operation": op, "ok": code == 0,
            "exit_code": code, "result": data}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(value):
    raise AdapterError("non-finite JSON number")


def parse_request(raw, *, require_version=False):
    if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > MAX_FRAME_BYTES:
        raise AdapterError("request too large")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    payload = json.loads(raw, object_pairs_hook=_object, parse_constant=_bad_constant)
    if not isinstance(payload, dict) or set(payload) - {"protocol", "request_id", "operation", "engagement_id", "options"}:
        raise AdapterError("invalid request fields")
    if payload.get("protocol", None if require_version else PROTOCOL) != PROTOCOL:
        raise AdapterError("unsupported protocol version")
    request_id = payload.get("request_id")
    # IDs are correlation integers, never caller-supplied free text.
    if (require_version or "request_id" in payload) and not _int(request_id, 0, 2**53 - 1):
        raise AdapterError("invalid request id")
    request = AdapterRequest(payload.get("operation"), payload.get("engagement_id"), payload.get("options"))
    validate(request)
    return request, request_id


@contextlib.contextmanager
def _deadline(seconds):
    """CLI main-thread boundary: let engine finally blocks reap their state."""
    def stop(signum, _frame):
        raise AdapterStopped(124 if signum == signal.SIGALRM else 130)
    signals = [signal.SIGTERM, signal.SIGINT, signal.SIGALRM]
    # Pipe transports commonly deliver SIGHUP when the host disconnects.
    # Treat it like cancellation so engine finally blocks run before exit.
    if hasattr(signal, "SIGHUP"):
        signals.append(signal.SIGHUP)
    saved = {s: signal.signal(s, stop) for s in signals}
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        for sig, handler in saved.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def _connection_lease(fd):
    """Watch pipe closure without consuming input or requiring the transport
    to send HUP. Requires the supervisor to keep stdin open until the
    response. Plain JSONL pipelines remain available without the lease flag.
    The monitor ends before the main thread restores its signal handlers.
    """
    if fd is None:
        yield
        return
    finished = threading.Event()
    poll = select.poll()
    poll.register(fd, select.POLLHUP | select.POLLERR | getattr(select, "POLLRDHUP", 0))

    def watch():
        while not finished.is_set():
            if poll.poll(50) and not finished.is_set():
                os.kill(os.getpid(), signal.SIGTERM)
                return

    monitor = threading.Thread(target=watch, name="babayaga-connection-lease", daemon=True)
    monitor.start()
    try:
        yield
    finally:
        finished.set()
        monitor.join()


def handle_frame(raw, *, require_version=False, disconnect_fd=None):
    request_id = None
    try:
        request, request_id = parse_request(raw, require_version=require_version)
        with _deadline(WALL_TIMEOUT_S), _connection_lease(disconnect_fd), \
                contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
            response = dispatch(request)
    except AdapterRefused:
        response = {"ok": False, "exit_code": 2, "error": "operation_refused"}
    except (AdapterError, ValueError, TypeError, UnicodeError, RecursionError):
        response = {"ok": False, "exit_code": 2, "error": "invalid_request_or_result"}
    except (AdapterStopped, KeyboardInterrupt) as exc:
        code = getattr(exc, "code", 130)
        response = {"ok": False, "exit_code": code,
                    "error": {124: "deadline_exceeded", 130: "cancelled"}.get(code, "response_too_large")}
    except Exception:
        response = {"ok": False, "exit_code": 3, "error": "engine_unavailable"}
    response.update(protocol=PROTOCOL, request_id=request_id)
    if len(json.dumps(response, ensure_ascii=True, allow_nan=False).encode()) + 1 > MAX_RESPONSE_BYTES:
        return {"protocol": PROTOCOL, "request_id": request_id, "ok": False,
                "exit_code": 3, "error": "response_too_large"}
    return response


def serve_lines(instream=None, outstream=None, *, disconnect_cancels=False):
    """Sequential JSONL; oversize frames close the pipe without draining input."""
    instream = instream if instream is not None else sys.stdin.buffer
    outstream = outstream if outstream is not None else sys.stdout
    overall = 0
    for _ in range(MAX_REQUESTS):
        try:
            with _deadline(30):
                raw = instream.readline(MAX_FRAME_BYTES + 1)
        except (AdapterStopped, KeyboardInterrupt) as exc:
            code = getattr(exc, "code", 130)
            raw = b""
            response = {"protocol": PROTOCOL, "request_id": None, "ok": False,
                        "exit_code": code, "error": "deadline_exceeded" if code == 124 else "cancelled"}
        else:
            if not raw:
                break
            response = handle_frame(raw if raw.endswith(b"\n") else b"", require_version=True,
                                    disconnect_fd=instream.fileno() if disconnect_cancels else None)
        try:
            outstream.write(json.dumps(response, ensure_ascii=True, allow_nan=False) + "\n")
            outstream.flush()
        except BrokenPipeError:
            return 130
        overall = max(overall, response["exit_code"])
        if len(raw) > MAX_FRAME_BYTES or response["exit_code"] in {124, 130}:
            break
    return overall


class _Discard(io.TextIOBase):
    """Keep incidental engine diagnostics out of the protocol without buffering."""

    def write(self, value):
        return len(value)
