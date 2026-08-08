import json
import shutil
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
C17_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.bench"


def test_cli_locks_and_validates_bench(tmp_path: Path) -> None:
    locked_path = tmp_path / "outputs/c17_locked.bench"
    lock_command = (
        sys.executable,
        "-m",
        "locklab",
        "lock",
        str(C17_BENCH),
        "--scheme",
        "rll",
        "--key-size",
        "2",
        "--seed",
        "42",
    )

    locked = subprocess.run(
        lock_command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert locked.returncode == 0, locked.stderr
    assert "Validation: PASS" in locked.stdout
    metadata_path = locked_path.with_suffix(".lock.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    if shutil.which("yices-sat") is not None:
        validated = subprocess.run(
            (
                sys.executable,
                "-m",
                "locklab",
                "validate",
                str(C17_BENCH),
                str(locked_path),
                "--key",
                metadata["key"],
            ),
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        assert validated.returncode == 0, validated.stderr
        assert "PASS: exact planted key is formally equivalent" in validated.stdout
        assert "Proof: SAT miter is UNSAT" in validated.stdout

        attacked = subprocess.run(
            (
                sys.executable,
                "-m",
                "locklab",
                "attack",
                "sat",
                str(locked_path),
                str(C17_BENCH),
            ),
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert attacked.returncode == 0, attacked.stderr
        assert "Recovered key:" in attacked.stdout
        assert "Validation: PASS (formal SAT miter UNSAT)" in attacked.stdout
