import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from locklab.__main__ import _attack_key_classification


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
C17_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.bench"


@pytest.mark.parametrize(
    "scheme",
    ("rll", "mux", "antisat", "rll-antisat", "sfll-hd0"),
)
def test_cli_locks_and_validates_bench(tmp_path: Path, scheme: str) -> None:
    locked_path = tmp_path / "outputs/c17_locked.bench"
    lock_command = (
        sys.executable,
        "-m",
        "locklab",
        "lock",
        str(C17_BENCH),
        "--scheme",
        scheme,
        "--key-size",
        "8" if scheme == "rll-antisat" else "4" if scheme == "antisat" else "2",
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
    assert metadata["scheme"] == scheme
    if scheme == "mux":
        assert all("decoy_signal" in item for item in metadata["insertions"])
    if scheme == "rll-antisat":
        assert metadata["components"] == {
            "rll_key_size": 4,
            "antisat_key_size": 4,
        }
        assert {item["component"] for item in metadata["insertions"]} == {
            "rll",
            "antisat",
        }

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
        assert "Classification:" in attacked.stdout
        assert "Validation: PASS (formal SAT miter UNSAT)" in attacked.stdout


def test_attack_classification_reports_exact_key(tmp_path: Path) -> None:
    locked_path = tmp_path / "locked.bench"
    locked_path.with_suffix(".lock.json").write_text(
        json.dumps({"key": "101"}),
        encoding="utf-8",
    )

    result = _attack_key_classification(locked_path, (1, 0, 1))

    assert result == ("Classification: exact planted key",)


def test_attack_classification_reports_changed_insertions(tmp_path: Path) -> None:
    locked_path = tmp_path / "locked.bench"
    locked_path.with_suffix(".lock.json").write_text(
        json.dumps(
            {
                "key": "101",
                "insertions": [
                    {
                        "key_index": 0,
                        "key_input": "keyinput_0",
                        "protected_signal": "G10",
                    },
                    {
                        "key_index": 2,
                        "key_input": "keyinput_2",
                        "protected_signal": "G30",
                        "decoy_signal": "G5",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    result = _attack_key_classification(locked_path, (0, 0, 0))

    assert result == (
        "Classification: functionally equivalent alternative key",
        "Hamming distance: 2",
        "Changed key bits (zero-based): 0, 2",
        "Changed insertions:",
        "  bit 0: keyinput_0 protects G10",
        "  bit 2: keyinput_2 protects G30, decoy G5",
    )


def test_attack_classification_handles_missing_metadata(tmp_path: Path) -> None:
    result = _attack_key_classification(tmp_path / "external.bench", (0,))

    assert result == ("Classification: unavailable (no lock metadata)",)


def test_attack_classification_reports_compound_component_distances(
    tmp_path: Path,
) -> None:
    locked_path = tmp_path / "locked.bench"
    locked_path.with_suffix(".lock.json").write_text(
        json.dumps(
            {
                "key": "10100110",
                "components": {
                    "rll_key_size": 4,
                    "antisat_key_size": 4,
                },
            }
        ),
        encoding="utf-8",
    )

    result = _attack_key_classification(locked_path, (0, 0, 1, 0, 0, 0, 0, 0))

    assert result == (
        "Classification: functionally equivalent alternative key",
        "Hamming distance: 3",
        "Component Hamming distance: RLL 1, Anti-SAT 2",
        "Changed key bits (zero-based): 0, 5, 6",
    )


def test_cli_runs_appsat_on_antisat_locked_circuit(tmp_path: Path) -> None:
    if shutil.which("yices-sat") is None:
        pytest.skip("Yices SAT is required for AppSAT")

    locked_path = tmp_path / "outputs/c17_locked.bench"
    locked = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "lock",
            str(C17_BENCH),
            "--scheme",
            "antisat",
            "--key-size",
            "10",
            "--seed",
            "42",
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert locked.returncode == 0, locked.stderr

    attacked = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "appsat",
            str(locked_path),
            str(C17_BENCH),
            "--samples",
            "32",
            "--threshold",
            "0",
            "--seed",
            "7",
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert attacked.returncode == 0, attacked.stderr
    assert "Termination: approximate error threshold" in attacked.stdout
    assert "Estimated input error: 0.0000%" in attacked.stdout
    assert "Formal equivalence: PASS" in attacked.stdout
