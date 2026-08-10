import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from locklab.analysis import find_antisat_candidates, remove_antisat
from locklab.bench import load_bench, write_bench
from locklab.circuit import CircuitError
from locklab.formats import load_circuit
from locklab.locking import lock_antisat, lock_rll_antisat
from locklab.sat_attack import sat_attack
from locklab.validation import validate_key
from locklab.verilog import write_verilog


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = REPOSITORY_ROOT / "benchmarks/sources/iscas85"
C17_BENCH = BENCHMARK_ROOT / "c17.bench"


def test_finds_standalone_antisat_without_metadata_or_signal_names() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_antisat(original, key_size=8, seed=42)

    candidates = find_antisat_candidates(locked.circuit)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.branch_size == 4
    assert candidate.key_size == 8
    assert candidate.key_inputs == tuple(
        insertion.key_input for insertion in locked.insertions
    )
    assert set(candidate.data_inputs) <= set(original.inputs)
    assert candidate.protected_output in original.outputs


def test_compound_analysis_excludes_rll_key_inputs() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll_antisat(original, key_size=8, seed=42)

    candidate = find_antisat_candidates(locked.circuit)[0]

    assert candidate.key_inputs == tuple(
        insertion.key_input for insertion in locked.insertions[4:]
    )
    assert not set(candidate.key_inputs) & {
        insertion.key_input for insertion in locked.insertions[:4]
    }


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
def test_unlocked_benchmarks_have_no_antisat_candidate(benchmark: str) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")

    assert find_antisat_candidates(original) == ()


@pytest.mark.skipif(shutil.which("yosys") is None, reason="Yosys is required")
def test_finds_yosys_lowered_verilog_antisat_tree(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_antisat(original, key_size=8, seed=42)
    verilog_path = tmp_path / "locked.v"
    write_verilog(locked.circuit, verilog_path)

    lowered = load_circuit(verilog_path)
    candidates = find_antisat_candidates(lowered)

    assert len(candidates) == 1
    assert candidates[0].branch_size == 4
    assert candidates[0].key_size == 8

    removal = remove_antisat(lowered)
    validation = validate_key(
        original,
        removal.circuit,
        key_inputs=(),
        key=(),
    )
    assert validation.passed


def test_cli_reports_structural_candidate_without_creating_files(
    tmp_path: Path,
) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll_antisat(original, key_size=8, seed=42)
    locked_path = tmp_path / "locked.bench"
    write_bench(locked.circuit, locked_path)
    files_before = set(tmp_path.iterdir())

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "antisat-structural",
            str(locked_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Anti-SAT structural candidates: 1" in result.stdout
    assert "Branch size: 2" in result.stdout
    assert "Suspected key size: 4" in result.stdout
    assert "keyinput_4" in result.stdout
    assert set(tmp_path.iterdir()) == files_before


def test_remove_standalone_antisat_restores_original_function() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_antisat(original, key_size=8, seed=42)

    removal = remove_antisat(locked.circuit)
    validation = validate_key(
        original,
        removal.circuit,
        key_inputs=(),
        key=(),
    )

    assert validation.passed
    assert removal.circuit.inputs == original.inputs
    assert removal.removed_inputs == tuple(
        insertion.key_input for insertion in locked.insertions
    )
    assert removal.removed_gate_count > 0
    assert find_antisat_candidates(removal.circuit) == ()


def test_remove_compound_antisat_preserves_rll_component() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll_antisat(original, key_size=8, seed=42)
    rll_insertions = locked.insertions[:4]

    removal = remove_antisat(locked.circuit)
    validation = validate_key(
        original,
        removal.circuit,
        key_inputs=tuple(insertion.key_input for insertion in rll_insertions),
        key=locked.key[:4],
    )

    assert validation.passed
    assert removal.circuit.inputs == (
        *original.inputs,
        *(insertion.key_input for insertion in rll_insertions),
    )
    assert removal.removed_inputs == tuple(
        insertion.key_input for insertion in locked.insertions[4:]
    )


def test_remove_rejects_circuit_without_antisat() -> None:
    original = load_bench(C17_BENCH)

    with pytest.raises(CircuitError, match="no matching type-0 Anti-SAT"):
        remove_antisat(original)


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices SAT is required for the post-removal SAT test",
)
def test_sat_attack_recovers_remaining_rll_after_antisat_removal() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll_antisat(original, key_size=8, seed=42)
    removal = remove_antisat(locked.circuit)

    result = sat_attack(removal.circuit, original)

    assert result.validation.passed
    assert len(result.key) == 4


def test_cli_removes_antisat_to_outputs_without_metadata(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll_antisat(original, key_size=8, seed=42)
    locked_path = tmp_path / "c17_locked.bench"
    write_bench(locked.circuit, locked_path)

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "antisat-remove",
            str(locked_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    output = tmp_path / "outputs/c17_antisat_removed.bench"
    assert result.returncode == 0, result.stderr
    assert f"Recovered circuit: {output}" in result.stdout
    assert "Removed Anti-SAT blocks: 1" in result.stdout
    assert "Removed suspected key inputs: 4" in result.stdout
    assert output.is_file()
    assert not output.with_suffix(".lock.json").exists()
    assert find_antisat_candidates(load_bench(output)) == ()
