from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class ProcessResult:
    """Complete, structured outcome of an external tool invocation."""

    command: tuple[str, ...]
    cwd: Path
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.exit_code == 0


def run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
) -> ProcessResult:
    """Run a tool without a shell and preserve output even when it times out."""

    started = time.monotonic()

    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return ProcessResult(
            command=tuple(str(item) for item in command),
            cwd=cwd,
            exit_code=None,
            timed_out=True,
            duration_seconds=time.monotonic() - started,
            stdout=stdout,
            stderr=stderr,
        )

    return ProcessResult(
        command=tuple(str(item) for item in command),
        cwd=cwd,
        exit_code=completed.returncode,
        timed_out=False,
        duration_seconds=time.monotonic() - started,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
