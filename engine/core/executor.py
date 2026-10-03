'Slim native executor: bounded spawn of an instrument binary.'

from __future__ import annotations

import contextlib
import math
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

PAIR_LIST_TOKEN = "{pair_list}"

DEFAULT_TIMEOUT_S = 300.0
DEFAULT_KILL_GRACE_S = 5.0
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024


class ExecutorError(Exception):
    """The process never started (setup or spawn failure)."""


@dataclass(frozen=True)
class ExecResult:
    """What the run did. killed/timed_out/output_capped mark executor-forced
    endings; exit_code is the child's own code (negative on signal death)."""

    exit_code: int
    duration_s: float
    stream_paths: dict[str, Path]
    killed: bool
    timed_out: bool
    output_capped: bool


def run(argv: list[str], *, run_dir, timeout_s: float = DEFAULT_TIMEOUT_S,
        kill_grace_s: float = DEFAULT_KILL_GRACE_S,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        credential_pairs=None) -> ExecResult:
    """Spawn argv bounded by timeout and output caps; return the result.

    credential_pairs is an iterable of (principal, password) tuples; argv
    must carry PAIR_LIST_TOKEN where the instrument expects the list path.
    The pairs ride an unnamed fd (never argv, never a named leftover file).
    """
    argv_list = _validate_argv(argv)
    timeout_s = _positive_finite("timeout_s", timeout_s)
    kill_grace_s = _non_negative_finite("kill_grace_s", kill_grace_s)
    if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) \
            or max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be a positive int")

    has_token = PAIR_LIST_TOKEN in argv_list
    if credential_pairs is None and has_token:
        raise ValueError(f"{PAIR_LIST_TOKEN} in argv but no credential_pairs given")
    if credential_pairs is not None and not has_token:
        raise ValueError(f"credential_pairs given but argv has no {PAIR_LIST_TOKEN} slot")

    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "stdout"
    err_path = run_dir / "stderr"
    cwd = Path(tempfile.mkdtemp(prefix="babayaga-exec-"))
    os.chmod(cwd, 0o700)

    proc = None
    reason = None
    started = time.monotonic()
    try:
        transport = (_pair_list_path(credential_pairs)
                     if credential_pairs is not None
                     else contextlib.nullcontext(None))
        with transport as pair_path:
            if pair_path is not None:
                argv_list = [pair_path if a == PAIR_LIST_TOKEN else a
                             for a in argv_list]
            try:
                with open(out_path, "wb", opener=_owner_only) as out_f, \
                        open(err_path, "wb", opener=_owner_only) as err_f:
                    proc = subprocess.Popen(
                        argv_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL, cwd=str(cwd),
                        start_new_session=True,
                    )
                    reason = _capture(proc, out_f, err_f, timeout_s,
                                      max_output_bytes, kill_grace_s)
            except OSError as exc:
                raise ExecutorError(f"spawn failed: {exc}") from exc
        return ExecResult(
            exit_code=proc.returncode,
            duration_s=round(time.monotonic() - started, 3),
            stream_paths={"stdout": out_path, "stderr": err_path},
            killed=reason is not None,
            timed_out=reason == "timeout",
            output_capped=reason == "output_limit",
        )
    finally:
        if proc is not None and proc.poll() is None:
            _stop_group(proc, kill_grace_s)
        shutil.rmtree(cwd, ignore_errors=True)


def _serialize_pairs(pairs) -> bytes:
    """Colon-pair lines (the hydra -C convention): one 'principal:password'
    per line. Ambiguous or injectable material refuses — never best-guess."""
    rows = []
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("credential pairs must be (principal, password) tuples")
        user, password = pair
        if not isinstance(user, str) or not isinstance(password, str):
            raise ValueError("credential pair fields must be strings")
        if any(c in user + password for c in "\r\n\x00"):
            raise ValueError("credential material contains forbidden bytes")
        if ":" in user:
            raise ValueError("principal must not contain ':' (list is colon-joined)")
        rows.append(f"{user}:{password}")
    if not rows:
        raise ValueError("empty credential pair list — nothing to transport")
    return ("\n".join(rows) + "\n").encode()


def _write_all(fd: int, blob: bytes) -> None:
    view = memoryview(blob)
    while view:
        view = view[os.write(fd, view):]


@contextlib.contextmanager
def _pair_list_path(pairs):
    'Yield the path an instrument can read the serialized pair list from.'
    blob = _serialize_pairs(pairs)
    fd = None
    fallback_dir: Path | None = None
    try:
        try:
            fd = os.open(tempfile.gettempdir(), os.O_RDWR | os.O_TMPFILE, 0o600)
            path = f"/proc/{os.getpid()}/fd/{fd}"
        except OSError:
            fallback_dir = Path(tempfile.mkdtemp(prefix="babayaga-pairs-"))
            os.chmod(fallback_dir, 0o700)
            fd = os.open(fallback_dir / "pairs",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            path = str(fallback_dir / "pairs")
        try:
            _write_all(fd, blob)
            os.lseek(fd, 0, os.SEEK_SET)
            yield path
        finally:
            os.close(fd)
            fd = None
            if fallback_dir is not None:
                target = fallback_dir / "pairs"
                try:
                    shred_fd = os.open(target, os.O_WRONLY)
                    try:
                        _write_all(shred_fd, b"\x00" * target.stat().st_size)
                        os.fsync(shred_fd)
                    finally:
                        os.close(shred_fd)
                    target.unlink()
                except OSError:
                    pass
                try:
                    fallback_dir.rmdir()
                except OSError:
                    pass
    except OSError as exc:
        raise ExecutorError(f"pair-list transport setup failed: {exc}") from exc


def _validate_argv(argv) -> list[str]:
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a non-empty list of strings")
    if not all(isinstance(a, str) for a in argv):
        raise ValueError("argv contains non-string elements")
    if not argv[0]:
        raise ValueError("argv[0] is empty")
    return list(argv)


def _positive_finite(name: str, value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)


def _non_negative_finite(name: str, value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a non-negative finite number")
    return float(value)


def _owner_only(path, flags: int) -> int:
    """Stream captures can carry target-discovered material; the containment
    is the mode (0600), not the content."""
    return os.open(path, flags, 0o600)


def _capture(proc, out_f, err_f, timeout_s: float, limit: int,
             grace: float) -> str | None:
    """Drain both pipes to their files; return 'timeout'/'output_limit'/None.

    Bounded nonblocking reads: arbitrary instrument output never parks in
    RAM, and a descendant holding a pipe open cannot outlive the deadline.
    """
    deadline = time.monotonic() + timeout_s
    sizes = {out_f: 0, err_f: 0}
    with selectors.DefaultSelector() as sel:
        for stream, dest in ((proc.stdout, out_f), (proc.stderr, err_f)):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, dest)
        try:
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "timeout"
                if proc.poll() is not None:
                    # The leader is gone; descendants may still hold the pipes.
                    _stop_group(proc, grace)
                for key, _ in sel.select(min(0.05, remaining)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        continue
                    dest = key.data
                    room = max(0, limit - sizes[dest])
                    dest.write(chunk[:room])
                    sizes[dest] += min(room, len(chunk))
                    if len(chunk) > room:
                        return "output_limit"
            try:
                proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                return "timeout"
        finally:
            if proc.poll() is None:
                _stop_group(proc, grace)
            proc.stdout.close()
            proc.stderr.close()
    return None


def _stop_group(proc, grace: float) -> None:
    """TERM the process group, wait the grace window, then KILL the group."""
    if proc.pid <= 0:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        proc.wait()
        return
    except PermissionError:
        return
    try:
        proc.wait(timeout=max(0.01, grace))
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait()
