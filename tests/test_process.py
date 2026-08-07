import sys
from pathlib import Path

from locklab.process import run_process


def test_run_process_records_success(tmp_path: Path) -> None:
    result = run_process(
        (sys.executable, "-c", "print('ok')"),
        cwd=tmp_path,
        timeout_seconds=5,
    )

    assert result.succeeded
    assert result.exit_code == 0
    assert result.stdout == "ok\n"
    assert not result.timed_out


def test_run_process_records_timeout(tmp_path: Path) -> None:
    result = run_process(
        (sys.executable, "-c", "import time; time.sleep(1)"),
        cwd=tmp_path,
        timeout_seconds=0.01,
    )

    assert not result.succeeded
    assert result.exit_code is None
    assert result.timed_out
