from pathlib import Path

from locklab.bench import load_bench, write_bench
from locklab.locking import lock_mux, lock_rll
from locklab.validation import validate_key


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
C17_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.bench"


def test_rll_is_deterministic_for_same_seed() -> None:
    circuit = load_bench(C17_BENCH)

    first = lock_rll(circuit, key_size=3, seed=42)
    second = lock_rll(circuit, key_size=3, seed=42)

    assert first == second


def test_rll_correct_key_passes_and_wrong_key_fails() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll(original, key_size=2, seed=7)
    key_inputs = tuple(item.key_input for item in locked.insertions)

    correct = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=locked.key,
    )
    wrong_key = (1 - locked.key[0], *locked.key[1:])
    wrong = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=wrong_key,
    )

    assert correct.passed
    assert correct.method == "exhaustive"
    assert correct.vectors_checked == 32
    assert not wrong.passed


def test_locked_bench_round_trip_validates(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll(original, key_size=2, seed=9)
    output = tmp_path / "locked.bench"
    write_bench(locked.circuit, output)

    reloaded = load_bench(output)
    key_inputs = tuple(item.key_input for item in locked.insertions)
    result = validate_key(
        original,
        reloaded,
        key_inputs=key_inputs,
        key=locked.key,
    )

    assert result.passed


def test_mux_locking_is_deterministic_and_cycle_safe() -> None:
    original = load_bench(C17_BENCH)

    first = lock_mux(original, key_size=3, seed=42)
    second = lock_mux(original, key_size=3, seed=42)

    assert first == second
    first.circuit.validate()
    output_positions = {
        gate.output: index
        for index, gate in enumerate(original.topological_gates())
    }
    for insertion in first.insertions:
        assert insertion.decoy_signal is not None
        assert (
            insertion.decoy_signal in original.inputs
            or output_positions[insertion.decoy_signal]
            < output_positions[insertion.protected_signal]
        )


def test_mux_correct_key_passes_and_wrong_key_fails() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_mux(original, key_size=3, seed=0)
    key_inputs = tuple(item.key_input for item in locked.insertions)

    correct = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=locked.key,
    )
    wrong = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=tuple(1 - bit for bit in locked.key),
    )

    assert correct.passed
    assert not wrong.passed


def test_mux_locked_bench_round_trip_validates(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_mux(original, key_size=3, seed=9)
    output = tmp_path / "locked-mux.bench"
    write_bench(locked.circuit, output)

    reloaded = load_bench(output)
    key_inputs = tuple(item.key_input for item in locked.insertions)
    result = validate_key(
        original,
        reloaded,
        key_inputs=key_inputs,
        key=locked.key,
    )

    assert result.passed
