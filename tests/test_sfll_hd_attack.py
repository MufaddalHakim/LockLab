from __future__ import annotations

import shutil
import subprocess
import sys
from math import comb
from pathlib import Path

import pytest

from locklab.bench import load_bench, write_bench
from locklab.circuit import Circuit, Gate
from locklab.formats import load_circuit
from locklab.locking import (
    lock_antisat,
    lock_rll,
    lock_sfll_hd,
)
from locklab.sfll_hd_analysis import find_sfll_hd_candidates
from locklab.validation import prove_key_equivalence
from locklab.verilog import write_verilog


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = REPOSITORY_ROOT / "benchmarks/sources/iscas85"


def _rename_internal_signals(circuit: Circuit) -> Circuit:
    ordered = circuit.topological_gates()
    renamed = {
        gate.output: f"wire_{index}"
        for index, gate in enumerate(ordered)
        if gate.output not in circuit.outputs
    }
    result = Circuit(
        name="renamed_sfll_hd",
        inputs=circuit.inputs,
        outputs=circuit.outputs,
        gates=tuple(
            Gate(
                name=f"cell_{index}",
                kind=gate.kind,
                inputs=tuple(renamed.get(signal, signal) for signal in gate.inputs),
                output=renamed.get(gate.output, gate.output),
            )
            for index, gate in enumerate(ordered)
        ),
    )
    result.validate()
    return result


@pytest.mark.parametrize(
    ("benchmark", "key_size", "hamming_distance"),
    (
        ("c17", 4, 1),
        ("c432", 4, 1),
        ("c432", 8, 2),
        ("c880", 8, 2),
        ("c1908", 8, 2),
    ),
)
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for FALL SAT queries",
)
def test_fall_recovers_documented_sfll_hd_attack_cases(
    benchmark: str,
    key_size: int,
    hamming_distance: int,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sfll_hd(
        original,
        key_size=key_size,
        hamming_distance=hamming_distance,
        seed=42,
    )

    candidates = find_sfll_hd_candidates(
        locked.circuit,
        hamming_distance=hamming_distance,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.recovery_method == "distance2h"
    assert candidate.inferred_key == locked.key
    assert candidate.protected_cube_count == comb(
        key_size,
        hamming_distance,
    )
    assert prove_key_equivalence(
        original,
        locked.circuit,
        key_inputs=candidate.key_inputs,
        key=candidate.inferred_key,
    ).passed


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for FALL SAT queries",
)
def test_fall_is_metadata_and_name_independent() -> None:
    original = load_bench(BENCHMARK_ROOT / "c432.bench")
    locked = lock_sfll_hd(
        original,
        key_size=8,
        hamming_distance=2,
        seed=42,
    )
    renamed = _rename_internal_signals(locked.circuit)

    candidate = find_sfll_hd_candidates(
        renamed,
        hamming_distance=2,
    )[0]

    assert candidate.inferred_key == locked.key
    assert "sfll" not in candidate.strip_match_signal
    assert "sfll" not in candidate.restore_match_signal


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for FALL SAT queries",
)
def test_fall_uses_sliding_window_when_distance2h_is_not_applicable() -> None:
    """Exercise the paper's second recovery procedure (6-bit key, h=2)."""

    original = load_bench(BENCHMARK_ROOT / "c432.bench")
    locked = lock_sfll_hd(
        original,
        key_size=6,
        hamming_distance=2,
        seed=42,
    )

    # For m=6 and h=2, 4h <= m is false but h < floor(m/2) is true.
    candidate = find_sfll_hd_candidates(
        locked.circuit,
        hamming_distance=2,
    )[0]

    assert candidate.recovery_method == "sliding-window"
    assert candidate.inferred_key == locked.key
    # Only the 2h differing positions need Lemma 3 trials.
    assert candidate.solver_calls == 1 + 2 * (2 * 2)
    assert prove_key_equivalence(
        original,
        locked.circuit,
        key_inputs=candidate.key_inputs,
        key=candidate.inferred_key,
    ).passed


@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for Verilog FALL testing",
)
def test_fall_reads_verilog_round_trip_without_writing_results(
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / "c432.bench")
    locked = lock_sfll_hd(
        original,
        key_size=8,
        hamming_distance=2,
        seed=42,
    )
    locked_path = tmp_path / "c432_locked.v"
    write_verilog(locked.circuit, locked_path)
    files_before = set(tmp_path.rglob("*"))

    reloaded = load_circuit(locked_path)
    candidates = find_sfll_hd_candidates(
        reloaded,
        hamming_distance=2,
    )

    assert len(candidates) == 1
    assert candidates[0].inferred_key == locked.key
    assert set(tmp_path.rglob("*")) == files_before


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for FALL negative controls",
)
def test_fall_has_no_candidate_on_unlocked_benchmarks(benchmark: str) -> None:
    circuit = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")

    assert find_sfll_hd_candidates(circuit, hamming_distance=1) == ()


@pytest.mark.parametrize("scheme", ("rll", "antisat"))
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for FALL negative controls",
)
def test_fall_does_not_claim_other_locking_schemes(scheme: str) -> None:
    original = load_bench(BENCHMARK_ROOT / "c17.bench")
    locked = (
        lock_rll(original, key_size=4, seed=42)
        if scheme == "rll"
        else lock_antisat(original, key_size=8, seed=42)
    )

    assert find_sfll_hd_candidates(locked.circuit, hamming_distance=1) == ()


def test_fall_rejects_parameters_outside_paper_applicability() -> None:
    original = load_bench(BENCHMARK_ROOT / "c17.bench")
    locked = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=2,
        seed=42,
    )

    assert find_sfll_hd_candidates(
        locked.circuit,
        hamming_distance=2,
    ) == ()


def test_fall_cli_is_read_only_and_reports_recovery(tmp_path: Path) -> None:
    original = load_bench(BENCHMARK_ROOT / "c17.bench")
    locked = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=1,
        seed=42,
    )
    locked_path = tmp_path / "c17_locked.bench"
    write_bench(locked.circuit, locked_path)
    files_before = set(tmp_path.rglob("*"))

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "sfll-fall",
            str(locked_path),
            "--hamming-distance",
            "1",
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "FALL SFLL-HDh candidates: 1" in result.stdout
    assert "Recovery method: distance2h" in result.stdout
    assert f"Recovered key: {locked.key_string}" in result.stdout
    assert not locked_path.with_suffix(".lock.json").exists()
    assert set(tmp_path.rglob("*")) == files_before
