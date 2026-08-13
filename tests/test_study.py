from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from locklab.circuit import CircuitError
from locklab.study import (
    SUMMARY_FIELDS,
    expand_study_cases,
    load_study_configuration,
    run_comparative_study,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = REPOSITORY_ROOT / "benchmarks/sources/iscas85"
SMOKE_CONFIGURATION = REPOSITORY_ROOT / "configs/comparative_smoke.json"
FULL_CONFIGURATION = REPOSITORY_ROOT / "configs/comparative_matrix.json"


def _write_configuration(
    path: Path,
    *,
    name: str,
    scheme: str = "rll",
    key_size: int = 2,
    exact_sat: bool = False,
) -> None:
    path.write_text(
        json.dumps(
            {
                "name": name,
                "benchmark_root": str(BENCHMARK_ROOT),
                "benchmarks": ["c17"],
                "seeds": [1],
                "schemes": [
                    {
                        "name": scheme,
                        "key_sizes": [key_size],
                    }
                ],
                "exact_sat": exact_sat,
                "appsat": {"enabled": False},
                "solver_timeout_seconds": 30,
            }
        ),
        encoding="utf-8",
    )


def test_tracked_study_configurations_expand_deterministically() -> None:
    smoke = load_study_configuration(SMOKE_CONFIGURATION)
    full = load_study_configuration(FULL_CONFIGURATION)

    first_smoke = expand_study_cases(smoke)
    second_smoke = expand_study_cases(smoke)
    full_cases = expand_study_cases(full)

    assert first_smoke == second_smoke
    assert len(first_smoke) == 7
    assert len({case.identifier for case in first_smoke}) == 7
    assert len(full_cases) == 312
    assert full.benchmark_root == BENCHMARK_ROOT


def test_study_configuration_rejects_hd_without_distances(tmp_path: Path) -> None:
    configuration_path = tmp_path / "invalid.json"
    _write_configuration(
        configuration_path,
        name="invalid",
        scheme="sfll-hd",
    )

    with pytest.raises(CircuitError, match="requires hamming_distances"):
        load_study_configuration(configuration_path)


def test_study_configuration_accepts_sarlock(tmp_path: Path) -> None:
    configuration_path = tmp_path / "sarlock.json"
    _write_configuration(
        configuration_path,
        name="sarlock",
        scheme="sarlock",
    )

    configuration = load_study_configuration(configuration_path)
    cases = expand_study_cases(configuration)

    assert len(cases) == 1
    assert cases[0].scheme == "sarlock"


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for study execution",
)
def test_study_runs_sarlock_case(tmp_path: Path) -> None:
    configuration_path = tmp_path / "sarlock.json"
    _write_configuration(
        configuration_path,
        name="sarlock",
        scheme="sarlock",
    )

    result = run_comparative_study(
        configuration_path,
        output_directory=tmp_path / "runs",
    )
    record = json.loads(result.raw_path.read_text(encoding="utf-8"))

    assert result.status_counts == {"completed": 1}
    assert record["case"]["scheme"] == "sarlock"
    assert record["metrics"]["formal_equivalent"] is True


def test_study_records_unsupported_cases_without_solver(tmp_path: Path) -> None:
    configuration_path = tmp_path / "unsupported.json"
    _write_configuration(
        configuration_path,
        name="unsupported",
        key_size=100,
    )

    result = run_comparative_study(
        configuration_path,
        output_directory=tmp_path / "runs",
    )
    record = json.loads(result.raw_path.read_text(encoding="utf-8"))

    assert result.status_counts == {"unsupported": 1}
    assert record["status"] == "unsupported"
    assert record["phase"] == "locking"
    assert record["anomalies"][0]["type"] == "CircuitError"
    assert "exceeds" in record["anomalies"][0]["message"]


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for study execution",
)
def test_study_resume_does_not_repeat_completed_case(tmp_path: Path) -> None:
    configuration_path = tmp_path / "resume.json"
    _write_configuration(configuration_path, name="resume")
    output_directory = tmp_path / "runs"

    first = run_comparative_study(
        configuration_path,
        output_directory=output_directory,
    )
    raw_before = first.raw_path.read_bytes()
    second = run_comparative_study(
        configuration_path,
        output_directory=output_directory,
    )

    assert first.executed_cases == 1
    assert first.status_counts == {"completed": 1}
    assert second.executed_cases == 0
    assert second.skipped_existing == 1
    assert second.raw_path.read_bytes() == raw_before

    with second.summary_path.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    assert tuple(rows[0]) == SUMMARY_FIELDS
    assert len(rows) == 1
    assert rows[0]["benchmark"] == "c17"
    assert rows[0]["study"] == "resume"
    assert len(rows[0]["benchmark_sha256"]) == 64
    assert len(rows[0]["configuration_sha256"]) == 64
    assert rows[0]["scheme"] == "rll"
    assert rows[0]["formal_equivalent"] == "True"
    assert rows[0]["exact_status"] == "not-requested"


def test_study_cli_dry_run_creates_no_files(tmp_path: Path) -> None:
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "study",
            str(SMOKE_CONFIGURATION),
            "--dry-run",
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Study: comparative_smoke" in result.stdout
    assert "Expanded cases: 7" in result.stdout
    assert "scheme=sfll-hd" in result.stdout
    assert not (tmp_path / "runs").exists()


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for study execution",
)
def test_study_rejects_resume_after_configuration_changes(tmp_path: Path) -> None:
    configuration_path = tmp_path / "changed.json"
    _write_configuration(configuration_path, name="changed")
    output_directory = tmp_path / "runs"
    run_comparative_study(
        configuration_path,
        output_directory=output_directory,
    )
    payload = json.loads(configuration_path.read_text(encoding="utf-8"))
    payload["solver_timeout_seconds"] = 31
    configuration_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CircuitError, match="different configuration"):
        run_comparative_study(
            configuration_path,
            output_directory=output_directory,
        )
