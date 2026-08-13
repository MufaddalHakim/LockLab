import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from locklab.analysis import (
    find_antisat_candidates,
    find_sarlock_candidates,
    find_sfll_hd0_candidates,
    remove_antisat,
    remove_sarlock,
    signal_probability_scores,
)
from locklab.bench import load_bench, write_bench
from locklab.circuit import Circuit, CircuitError, Gate
from locklab.formats import load_circuit
from locklab.locking import (
    lock_antisat,
    lock_mux,
    lock_rll,
    lock_rll_antisat,
    lock_sarlock,
    lock_sfll_hd,
    lock_sfll_hd0,
)
from locklab.process import run_process
from locklab.sat_attack import sat_attack
from locklab.sfll_analysis import assess_sfll_hd0
from locklab.validation import prove_key_equivalence, validate_key
from locklab.verilog import write_verilog


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = REPOSITORY_ROOT / "benchmarks/sources/iscas85"
C17_BENCH = BENCHMARK_ROOT / "c17.bench"


def _rename_internal_signals(circuit: Circuit) -> Circuit:
    ordered_gates = circuit.topological_gates()
    renamed_signals = {
        gate.output: f"wire_{index}"
        for index, gate in enumerate(ordered_gates)
        if gate.output not in circuit.outputs
    }
    renamed = Circuit(
        name="renamed_circuit",
        inputs=circuit.inputs,
        outputs=circuit.outputs,
        gates=tuple(
            Gate(
                name=f"cell_{index}",
                kind=gate.kind,
                inputs=tuple(
                    renamed_signals.get(signal, signal) for signal in gate.inputs
                ),
                output=renamed_signals.get(gate.output, gate.output),
            )
            for index, gate in enumerate(ordered_gates)
        ),
    )
    renamed.validate()
    return renamed


def _synthesize_with_abc(
    circuit: Circuit,
    tmp_path: Path,
    *,
    gate_library: str,
) -> Circuit:
    source = tmp_path / "pre_synthesis.v"
    output = tmp_path / "synthesized.v"
    write_verilog(circuit, source)
    script = (
        f"read_verilog {source}; "
        f"hierarchy -top {circuit.name}; "
        "proc; flatten; opt; techmap; opt; "
        f"abc -g {gate_library}; "
        f"opt; clean; write_verilog -noattr {output}"
    )
    result = run_process(
        ("yosys", "-Q", "-p", script),
        cwd=tmp_path,
        timeout_seconds=30.0,
    )
    assert result.succeeded, result.stderr
    return load_circuit(output)


def test_signal_probability_scores_cover_supported_gate_types() -> None:
    circuit = Circuit(
        name="probability_example",
        inputs=("a", "b", "select"),
        outputs=(
            "mixed_out",
            "or_out",
            "nor_out",
            "xor_out",
            "xnor_out",
            "mux_out",
            "buf_out",
            "not_out",
        ),
        gates=(
            Gate("and_gate", "AND", ("a", "b"), "and_out"),
            Gate("nand_gate", "NAND", ("a", "b"), "nand_out"),
            Gate("or_gate", "OR", ("a", "b"), "or_out"),
            Gate("nor_gate", "NOR", ("a", "b"), "nor_out"),
            Gate("xor_gate", "XOR", ("a", "b"), "xor_out"),
            Gate("xnor_gate", "XNOR", ("a", "b"), "xnor_out"),
            Gate("mux_gate", "MUX", ("a", "b", "select"), "mux_out"),
            Gate("buf_gate", "BUF", ("a",), "buf_out"),
            Gate("not_gate", "NOT", ("a",), "not_out"),
            Gate("mixed_gate", "AND", ("and_out", "nand_out"), "mixed_out"),
        ),
    )

    scores = signal_probability_scores(circuit)
    by_signal = {score.signal: score for score in scores}

    assert by_signal["and_out"].probability_one == pytest.approx(0.25)
    assert by_signal["nand_out"].probability_one == pytest.approx(0.75)
    assert by_signal["or_out"].probability_one == pytest.approx(0.75)
    assert by_signal["nor_out"].probability_one == pytest.approx(0.25)
    assert by_signal["xor_out"].probability_one == pytest.approx(0.5)
    assert by_signal["xnor_out"].probability_one == pytest.approx(0.5)
    assert by_signal["mux_out"].probability_one == pytest.approx(0.5)
    assert by_signal["buf_out"].probability_one == pytest.approx(0.5)
    assert by_signal["not_out"].probability_one == pytest.approx(0.5)
    assert by_signal["mixed_out"].probability_one == pytest.approx(0.1875)
    assert by_signal["mixed_out"].input_skews == pytest.approx((-0.25, 0.25))
    assert by_signal["mixed_out"].ads == pytest.approx(0.5)
    assert scores[0].signal == "mixed_out"


def test_sps_ranks_standalone_antisat_convergence_gate_first() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_antisat(original, key_size=8, seed=42)
    block_signal = find_antisat_candidates(locked.circuit)[0].block_signal

    first_run = signal_probability_scores(locked.circuit)
    second_run = signal_probability_scores(locked.circuit)

    assert first_run == second_run
    assert first_run[0].signal == block_signal
    assert first_run[0].gate_kind == "AND"
    assert first_run[0].ads == pytest.approx(0.875)


def test_cli_reports_sps_ranking_without_creating_files(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_antisat(original, key_size=8, seed=42)
    locked_path = tmp_path / "locked.bench"
    write_bench(locked.circuit, locked_path)
    files_before = set(tmp_path.iterdir())

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "antisat-sps",
            str(locked_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Probability model: independent primary/key inputs" in result.stdout
    assert "Highest ADS: 0.875000" in result.stdout
    assert "1. antisat_block [AND]" in result.stdout
    assert set(tmp_path.iterdir()) == files_before


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


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
@pytest.mark.parametrize("representation", ("bench", "verilog"))
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices SAT is required to prove the inferred SFLL key",
)
def test_finds_sfll_hd0_and_formally_checks_inferred_key(
    benchmark: str,
    representation: str,
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sfll_hd0(original, key_size=4, seed=1)
    suffix = ".bench" if representation == "bench" else ".v"
    locked_path = tmp_path / f"{benchmark}_locked{suffix}"
    if representation == "bench":
        write_bench(locked.circuit, locked_path)
    else:
        if shutil.which("yosys") is None:
            pytest.skip("Yosys is required")
        write_verilog(locked.circuit, locked_path)
    reloaded = load_circuit(locked_path)

    candidates = find_sfll_hd0_candidates(reloaded)

    assert len(candidates) == 1
    candidate = candidates[0]
    expected_mappings = {
        insertion.key_input: (insertion.source_signal, insertion.correct_bit)
        for insertion in locked.insertions
    }
    recovered_mappings = {
        mapping.key_input: (mapping.protected_input, mapping.protected_bit)
        for mapping in candidate.mappings
    }
    assert recovered_mappings == expected_mappings
    assert candidate.protected_output == locked.insertions[0].protected_signal
    assert candidate.inferred_cube == "".join(map(str, candidate.inferred_key))

    proof = prove_key_equivalence(
        original,
        reloaded,
        key_inputs=candidate.key_inputs,
        key=candidate.inferred_key,
    )
    assert proof.passed


def test_sfll_hd0_analysis_uses_neither_metadata_nor_internal_names() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=4, seed=1)
    renamed = _rename_internal_signals(locked.circuit)

    candidates = find_sfll_hd0_candidates(renamed)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.inferred_key == locked.key
    assert candidate.key_inputs == tuple(
        insertion.key_input for insertion in locked.insertions
    )
    assert candidate.protected_inputs == tuple(
        insertion.source_signal for insertion in locked.insertions
    )
    assert "sfll" not in candidate.strip_match_signal
    assert "sfll" not in candidate.restore_match_signal


def test_sfll_hd0_analysis_supports_one_bit_cube() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=1, seed=42)

    candidates = find_sfll_hd0_candidates(locked.circuit)

    assert len(candidates) == 1
    assert candidates[0].key_size == 1
    assert candidates[0].inferred_key == locked.key


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
def test_unlocked_benchmarks_have_no_sfll_hd0_candidate(benchmark: str) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")

    assert find_sfll_hd0_candidates(original) == ()


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for functional negative controls",
)
def test_unlocked_benchmarks_have_no_functional_sfll_candidate(
    benchmark: str,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")

    assert assess_sfll_hd0(original) == ()


def test_cli_reports_sfll_cube_without_metadata_or_files(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=4, seed=1)
    locked_path = tmp_path / "locked.bench"
    write_bench(locked.circuit, locked_path)
    files_before = set(tmp_path.rglob("*"))

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "sfll-structural",
            str(locked_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "SFLL-HD0 structural candidates: 1" in result.stdout
    assert f"Inferred protected cube: {locked.key_string}" in result.stdout
    for insertion in locked.insertions:
        expected = (
            f"{insertion.key_input} -> {insertion.source_signal} "
            f"(cube bit {insertion.correct_bit})"
        )
        assert expected in result.stdout
    assert not locked_path.with_suffix(".lock.json").exists()
    assert set(tmp_path.rglob("*")) == files_before


def test_sfll_functional_assessment_labels_exact_topology() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=4, seed=1)

    assessments = assess_sfll_hd0(locked.circuit)

    assert len(assessments) == 1
    assert assessments[0].match_type == "exact topology"
    assert assessments[0].inferred_key == locked.key


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for functional SFLL negative controls",
)
def test_hd0_analyzers_do_not_misclassify_general_sfll_hd() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd(
        original,
        key_size=3,
        hamming_distance=1,
        seed=1,
    )

    assert find_sfll_hd0_candidates(locked.circuit) == ()
    assert assess_sfll_hd0(locked.circuit) == ()


@pytest.mark.parametrize(
    "gate_library",
    (
        "AND,NAND,OR,NOR,XOR,XNOR",
        "AND,NAND",
        "AND,OR,NAND,NOR",
    ),
)
@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for synthesized functional analysis",
)
def test_sfll_functional_assessment_handles_multiple_synthesis_mappings(
    gate_library: str,
    tmp_path: Path,
) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=4, seed=1)
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library=gate_library,
    )

    assert find_sfll_hd0_candidates(synthesized) == ()
    assessments = assess_sfll_hd0(synthesized)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.match_type == "functional candidate"
    assert assessment.inferred_key == locked.key
    assert set(assessment.strip_unateness) == {"positive", "negative"}
    expected_mappings = {
        insertion.key_input: insertion.source_signal
        for insertion in locked.insertions
    }
    assert dict(zip(assessment.key_inputs, assessment.protected_inputs)) == (
        expected_mappings
    )
    proof = prove_key_equivalence(
        original,
        synthesized,
        key_inputs=assessment.key_inputs,
        key=assessment.inferred_key,
    )
    assert proof.passed


@pytest.mark.parametrize("benchmark", ("c432", "c880", "c1908"))
@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for synthesized functional analysis",
)
def test_sfll_functional_assessment_benchmark_matrix(
    benchmark: str,
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sfll_hd0(original, key_size=4, seed=1)
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library="AND,NAND",
    )

    assessments = assess_sfll_hd0(synthesized)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.match_type == "functional candidate"
    assert assessment.inferred_key == locked.key
    proof = prove_key_equivalence(
        original,
        synthesized,
        key_inputs=assessment.key_inputs,
        key=assessment.inferred_key,
    )
    assert proof.passed


@pytest.mark.parametrize("benchmark", ("c432", "c880"))
@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for synthesized functional analysis",
)
def test_sfll_functional_assessment_recovers_sixteen_bit_cube(
    benchmark: str,
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sfll_hd0(original, key_size=16, seed=42)
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library="AND,NAND",
    )

    assessments = assess_sfll_hd0(synthesized)

    assert len(assessments) == 1
    assessment = assessments[0]
    assert assessment.inferred_key == locked.key
    proof = prove_key_equivalence(
        original,
        synthesized,
        key_inputs=assessment.key_inputs,
        key=assessment.inferred_key,
    )
    assert proof.passed


@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for synthesized functional analysis",
)
def test_functional_assessment_does_not_claim_absorbed_strip_cube(
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / "c1908.bench")
    locked = lock_sfll_hd0(original, key_size=16, seed=42)
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library="AND,NAND",
    )

    assert find_sfll_hd0_candidates(synthesized) == ()
    assert assess_sfll_hd0(synthesized) == ()


@pytest.mark.parametrize(
    "locked_circuit",
    (
        pytest.param("rll", id="rll"),
        pytest.param("mux", id="mux"),
        pytest.param("antisat", id="antisat"),
        pytest.param("rll-antisat", id="rll-antisat"),
    ),
)
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for functional negative controls",
)
def test_other_locking_schemes_are_functional_negative_controls(
    locked_circuit: str,
) -> None:
    original = load_bench(C17_BENCH)
    if locked_circuit == "rll":
        candidate = lock_rll(original, key_size=4, seed=1).circuit
    elif locked_circuit == "mux":
        candidate = lock_mux(original, key_size=4, seed=1).circuit
    elif locked_circuit == "antisat":
        candidate = lock_antisat(original, key_size=8, seed=1).circuit
    else:
        candidate = lock_rll_antisat(original, key_size=8, seed=1).circuit

    assert assess_sfll_hd0(candidate) == ()


@pytest.mark.skipif(
    shutil.which("yosys") is None or shutil.which("yices-sat") is None,
    reason="Yosys and Yices are required for synthesized functional analysis",
)
def test_cli_reports_synthesized_sfll_function_without_files(
    tmp_path: Path,
) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=4, seed=1)
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library="AND,NAND",
    )
    synthesized_path = tmp_path / "synthesized.bench"
    write_bench(synthesized, synthesized_path)
    files_before = set(tmp_path.rglob("*"))

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "sfll-functional",
            str(synthesized_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "SFLL-HD0 assessment candidates: 1" in result.stdout
    assert "Exact topology matches: 0" in result.stdout
    assert "Functional candidates: 1" in result.stdout
    assert "Match type: functional candidate" in result.stdout
    assert f"Inferred protected cube: {locked.key_string}" in result.stdout
    assert set(tmp_path.rglob("*")) == files_before


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


def test_finds_sarlock_without_metadata_or_signal_names() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sarlock(original, key_size=4, seed=42)
    renamed = _rename_internal_signals(locked.circuit)

    candidates = find_sarlock_candidates(renamed)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.key_size == 4
    assert candidate.inferred_key == locked.key
    assert candidate.key_inputs == tuple(
        insertion.key_input for insertion in locked.insertions
    )
    assert candidate.protected_inputs == tuple(
        insertion.source_signal for insertion in locked.insertions
    )
    assert candidate.protected_output == locked.insertions[0].protected_signal
    assert "sarlock" not in candidate.flip_signal


def test_sarlock_analysis_supports_one_bit_key() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sarlock(original, key_size=1, seed=42)

    candidates = find_sarlock_candidates(locked.circuit)

    assert len(candidates) == 1
    assert candidates[0].key_size == 1
    assert candidates[0].inferred_key == locked.key


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
@pytest.mark.parametrize("representation", ("bench", "verilog"))
def test_finds_and_removes_sarlock_on_benchmark_serializations(
    benchmark: str,
    representation: str,
    tmp_path: Path,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sarlock(original, key_size=4, seed=42)
    suffix = ".bench" if representation == "bench" else ".v"
    locked_path = tmp_path / f"{benchmark}_locked{suffix}"
    if representation == "bench":
        write_bench(locked.circuit, locked_path)
    else:
        if shutil.which("yosys") is None:
            pytest.skip("Yosys is required")
        write_verilog(locked.circuit, locked_path)
    reloaded = load_circuit(locked_path)

    candidates = find_sarlock_candidates(reloaded)
    removal = remove_sarlock(reloaded)

    assert len(candidates) == 1
    assert candidates[0].inferred_key == locked.key
    assert removal.circuit.inputs == original.inputs
    assert removal.removed_inputs == candidates[0].key_inputs
    assert find_sarlock_candidates(removal.circuit) == ()
    validation = validate_key(
        original,
        removal.circuit,
        key_inputs=(),
        key=(),
    )
    assert validation.passed


@pytest.mark.parametrize(
    ("benchmark", "key_size"),
    (("c17", 4), ("c432", 16), ("c880", 16), ("c1908", 16)),
)
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for formal SARLock removal validation",
)
def test_sarlock_removal_formally_restores_benchmarks(
    benchmark: str,
    key_size: int,
) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")
    locked = lock_sarlock(original, key_size=key_size, seed=42)
    removal = remove_sarlock(locked.circuit)

    proof = prove_key_equivalence(
        original,
        removal.circuit,
        key_inputs=(),
        key=(),
    )

    assert proof.passed


@pytest.mark.parametrize("benchmark", ("c17", "c432", "c880", "c1908"))
def test_unlocked_benchmarks_have_no_sarlock_candidate(benchmark: str) -> None:
    original = load_bench(BENCHMARK_ROOT / f"{benchmark}.bench")

    assert find_sarlock_candidates(original) == ()


@pytest.mark.parametrize("scheme", ("antisat", "sfll-hd0", "sfll-hd"))
def test_other_point_function_schemes_are_not_sarlock_candidates(
    scheme: str,
) -> None:
    original = load_bench(C17_BENCH)
    if scheme == "antisat":
        locked = lock_antisat(original, key_size=4, seed=42)
    elif scheme == "sfll-hd0":
        locked = lock_sfll_hd0(original, key_size=4, seed=42)
    else:
        locked = lock_sfll_hd(
            original,
            key_size=4,
            hamming_distance=1,
            seed=42,
        )

    assert find_sarlock_candidates(locked.circuit) == ()


def test_remove_sarlock_rejects_unmatched_circuit() -> None:
    original = load_bench(C17_BENCH)

    with pytest.raises(CircuitError, match="no matching explicit SARLock"):
        remove_sarlock(original)


@pytest.mark.skipif(shutil.which("yosys") is None, reason="Yosys is required")
def test_sarlock_exact_detector_does_not_overclaim_after_abc_synthesis(
    tmp_path: Path,
) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sarlock(original, key_size=4, seed=42)
    synthesized = _synthesize_with_abc(
        locked.circuit,
        tmp_path,
        gate_library="aig",
    )

    assert find_sarlock_candidates(synthesized) == ()
    with pytest.raises(CircuitError, match="no matching explicit SARLock"):
        remove_sarlock(synthesized)


def test_cli_reports_sarlock_candidate_without_metadata_or_files(
    tmp_path: Path,
) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sarlock(original, key_size=4, seed=42)
    locked_path = tmp_path / "locked.bench"
    write_bench(locked.circuit, locked_path)
    files_before = set(tmp_path.rglob("*"))

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "sarlock-structural",
            str(locked_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "SARLock structural candidates: 1" in result.stdout
    assert f"Inferred planted key: {locked.key_string}" in result.stdout
    for insertion in locked.insertions:
        expected = (
            f"{insertion.key_input} -> {insertion.source_signal} "
            f"(planted bit {insertion.correct_bit})"
        )
        assert expected in result.stdout
    assert set(tmp_path.rglob("*")) == files_before


def test_cli_removes_sarlock_to_outputs_without_metadata(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sarlock(original, key_size=4, seed=42)
    locked_path = tmp_path / "c17_locked.bench"
    write_bench(locked.circuit, locked_path)

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "attack",
            "sarlock-remove",
            str(locked_path),
        ),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    output = tmp_path / "outputs/c17_sarlock_removed.bench"
    assert result.returncode == 0, result.stderr
    assert f"Recovered circuit: {output}" in result.stdout
    assert "Removed SARLock blocks: 1" in result.stdout
    assert "Removed suspected key inputs: 4" in result.stdout
    assert output.is_file()
    assert not output.with_suffix(".lock.json").exists()
    recovered = load_bench(output)
    assert find_sarlock_candidates(recovered) == ()
    validation = validate_key(
        original,
        recovered,
        key_inputs=(),
        key=(),
    )
    assert validation.passed
