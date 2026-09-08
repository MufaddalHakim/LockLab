from __future__ import annotations

import json
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
from locklab.process import run_process
from locklab.sfll_hd_analysis import (
    confirm_sfll_hd_candidates,
    find_sfll_hd_candidates,
)
from locklab.validation import prove_key_equivalence
from locklab.verilog import circuit_from_yosys_json, write_verilog


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


def _change_first_gate(circuit: Circuit) -> Circuit:
    first, *remaining = circuit.topological_gates()
    changed = Gate(
        name=first.name,
        kind="AND" if first.kind != "AND" else "NAND",
        inputs=first.inputs,
        output=first.output,
    )
    result = Circuit(
        name=f"{circuit.name}_changed",
        inputs=circuit.inputs,
        outputs=circuit.outputs,
        gates=(changed, *remaining),
    )
    result.validate()
    return result


def _synthesize_with_abc(
    circuit: Circuit,
    tmp_path: Path,
    *,
    gate_library: str,
    preserve_signals: tuple[str, ...] = (),
) -> Circuit:
    source = tmp_path / "pre_synthesis.v"
    output = tmp_path / "synthesized.json"
    write_verilog(circuit, source)
    preserve = (
        f"setattr -set keep 1 {' '.join(preserve_signals)}; "
        if preserve_signals
        else ""
    )
    script = (
        f"read_verilog {source}; "
        f"hierarchy -top {circuit.name}; "
        f"proc; flatten; opt; {preserve}techmap; opt; "
        f"abc -g {gate_library}; "
        f"opt; clean; write_json {output}"
    )
    result = run_process(
        ("yosys", "-Q", "-p", script),
        cwd=tmp_path,
        timeout_seconds=30.0,
    )
    assert result.succeeded, result.stderr
    return circuit_from_yosys_json(json.loads(output.read_text(encoding="utf-8")))


def _map_primary_input_xors_to_nands(circuit: Circuit) -> Circuit:
    """Apply a standard NAND implementation to runtime XOR comparisons."""

    inputs = set(circuit.inputs)
    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_names = {gate.name for gate in circuit.gates}

    def unique(base: str, used: set[str]) -> str:
        suffix = 0
        name = base
        while name in used:
            suffix += 1
            name = f"{base}_{suffix}"
        used.add(name)
        return name

    mapped: list[Gate] = []
    for gate in circuit.topological_gates():
        if gate.kind != "XOR" or not set(gate.inputs) <= inputs:
            mapped.append(gate)
            continue
        first, second = gate.inputs
        nand_ab = unique(f"{gate.output}_nand_ab", used_signals)
        nand_first = unique(f"{gate.output}_nand_first", used_signals)
        nand_second = unique(f"{gate.output}_nand_second", used_signals)
        mapped.extend(
            (
                Gate(unique(f"{gate.name}_nand_ab", used_names), "NAND", (first, second), nand_ab),
                Gate(unique(f"{gate.name}_nand_first", used_names), "NAND", (first, nand_ab), nand_first),
                Gate(unique(f"{gate.name}_nand_second", used_names), "NAND", (second, nand_ab), nand_second),
                Gate(gate.name, "NAND", (nand_first, nand_second), gate.output),
            )
        )
    result = Circuit(
        name=f"{circuit.name}_nand_mapped",
        inputs=circuit.inputs,
        outputs=circuit.outputs,
        gates=tuple(mapped),
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
    shutil.which("yices-sat") is None,
    reason="Yices is required for FALL key confirmation",
)
def test_fall_oracle_confirmation_accepts_only_whole_circuit_equivalence() -> None:
    original = load_bench(BENCHMARK_ROOT / "c17.bench")
    locked = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=1,
        seed=42,
    )
    candidate = find_sfll_hd_candidates(
        locked.circuit,
        hamming_distance=1,
    )[0]

    accepted = confirm_sfll_hd_candidates(
        original,
        locked.circuit,
        (candidate,),
    )[0]

    changed = _change_first_gate(original)
    changed_locked = lock_sfll_hd(
        changed,
        key_size=4,
        hamming_distance=1,
        seed=42,
    )
    changed_candidate = find_sfll_hd_candidates(
        changed_locked.circuit,
        hamming_distance=1,
    )[0]
    rejected = confirm_sfll_hd_candidates(
        original,
        changed_locked.circuit,
        (changed_candidate,),
    )[0]

    assert accepted.validation.passed
    assert not rejected.validation.passed
    assert len(rejected.validation.mismatches) == 1


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


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for functional FALL testing",
)
@pytest.mark.parametrize(
    ("benchmark", "key_size", "hamming_distance", "method"),
    (
        ("c17", 4, 1, "distance2h"),
        ("c432", 8, 2, "distance2h"),
        ("c880", 8, 2, "distance2h"),
        ("c1908", 8, 2, "distance2h"),
        ("c432", 6, 2, "sliding-window"),
    ),
)
def test_fall_recovers_functional_candidate_after_nand_mapping(
    benchmark: str,
    key_size: int,
    hamming_distance: int,
    method: str,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sfll_hd(
        original,
        key_size=key_size,
        hamming_distance=hamming_distance,
        seed=42,
    )
    mapped = _map_primary_input_xors_to_nands(locked.circuit)

    candidates = find_sfll_hd_candidates(
        mapped,
        hamming_distance=hamming_distance,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.match_type == "functional candidate"
    assert candidate.recovery_method == method
    expected_key = {
        insertion.key_input: insertion.correct_bit
        for insertion in locked.insertions
    }
    assert dict(zip(candidate.key_inputs, candidate.inferred_key)) == expected_key
    assert candidate.protected_source is None
    assert candidate.stripped_output is None
    assert prove_key_equivalence(
        original,
        mapped,
        key_inputs=candidate.key_inputs,
        key=candidate.inferred_key,
    ).passed


@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for synthesized FALL testing",
)
def test_fall_does_not_claim_candidate_when_synthesis_absorbs_cones(
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / "c17.bench")
    locked = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=1,
        seed=42,
    )
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library="AND,NAND",
    )

    assert find_sfll_hd_candidates(synthesized, hamming_distance=1) == ()


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
    oracle_path = tmp_path / "c17.bench"
    write_bench(locked.circuit, locked_path)
    write_bench(original, oracle_path)
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
            "--oracle",
            str(oracle_path),
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
    assert "Oracle confirmation: PASS" in result.stdout
    assert not locked_path.with_name(locked_path.name + ".lock.json").exists()
    assert set(tmp_path.rglob("*")) == files_before
