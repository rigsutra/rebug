"""Cancellable subprocess execution.

Stages call `run_cmd` instead of subprocess.run so a running test can be stopped: the whole
process tree is killed (npx -> node, schemathesis workers, docker client).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable


class Cancelled(Exception):
    """Raised inside a stage when the user stopped the run."""


def check(cfg) -> None:
    ev = getattr(cfg, "cancel", None)
    if ev is not None and ev.is_set():
        raise Cancelled()


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


def _kill_tree(p: subprocess.Popen) -> None:
    if p.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()


def run_cmd(cmd: list[str], *, cancel: threading.Event | None = None, timeout: float = 3600,
            env: dict | None = None, on_cancel: Callable[[], None] | None = None) -> Result:
    # Output goes to temp files, not pipes, so a chatty process can't block on a full pipe
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        kw = {"start_new_session": True} if sys.platform != "win32" else {}
        p = subprocess.Popen(cmd, stdout=out, stderr=err, stdin=subprocess.DEVNULL, env=env, **kw)
        deadline = time.time() + timeout
        while p.poll() is None:
            if cancel is not None and cancel.is_set():
                _kill_tree(p)
                if on_cancel:
                    on_cancel()
                raise Cancelled()
            if time.time() > deadline:
                _kill_tree(p)
                raise subprocess.TimeoutExpired(cmd, timeout)
            time.sleep(0.25)
        out.seek(0)
        err.seek(0)
        return Result(p.returncode, out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace"))
