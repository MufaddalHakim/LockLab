from pathlib import Path

import pytest

from locklab.bench import load_bench, write_bench
from locklab.circuit import CircuitError
from locklab.locking import (
    lock_antisat,
    lock_mux,
    lock_rll,
    lock_rll_antisat,
    lock_sfll_hd0,
)
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


def test_antisat_is_deterministic_and_uses_matching_key_halves() -> None:
    original = load_bench(C17_BENCH)

    first = lock_antisat(original, key_size=4, seed=42)
    second = lock_antisat(original, key_size=4, seed=42)

    assert first == second
    assert first.key[:2] == first.key[2:]
    assert len(first.circuit.inputs) == len(original.inputs) + 4


def test_antisat_correct_key_passes_and_unequal_halves_fail() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_antisat(original, key_size=4, seed=7)
    key_inputs = tuple(item.key_input for item in locked.insertions)

    correct = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=locked.key,
    )
    wrong_key = (*locked.key[:2], 1 - locked.key[2], locked.key[3])
    wrong = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=wrong_key,
    )

    assert correct.passed
    assert not wrong.passed


@pytest.mark.parametrize("key_size", (1, 2, 3, 5))
def test_antisat_rejects_invalid_key_size(key_size: int) -> None:
    original = load_bench(C17_BENCH)

    with pytest.raises(CircuitError, match="even and at least 4"):
        lock_antisat(original, key_size=key_size, seed=0)


def test_rll_antisat_is_deterministic_and_splits_the_key_evenly() -> None:
    original = load_bench(C17_BENCH)

    first = lock_rll_antisat(original, key_size=8, seed=42)
    second = lock_rll_antisat(original, key_size=8, seed=42)

    assert first == second
    assert len(first.key) == 8
    assert first.key[4:6] == first.key[6:8]
    assert tuple(item.key_index for item in first.insertions) == tuple(range(8))


def test_rll_antisat_correct_key_passes_and_both_components_enforce_keys() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_rll_antisat(original, key_size=8, seed=7)
    key_inputs = tuple(item.key_input for item in locked.insertions)

    correct = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=locked.key,
    )
    wrong_rll_key = (1 - locked.key[0], *locked.key[1:])
    wrong_rll = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=wrong_rll_key,
    )
    wrong_antisat_key = (
        *locked.key[:6],
        1 - locked.key[6],
        locked.key[7],
    )
    wrong_antisat = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=wrong_antisat_key,
    )

    assert correct.passed
    assert not wrong_rll.passed
    assert not wrong_antisat.passed


@pytest.mark.parametrize("key_size", (4, 6, 10))
def test_rll_antisat_rejects_invalid_total_key_size(key_size: int) -> None:
    original = load_bench(C17_BENCH)

    with pytest.raises(CircuitError, match="divisible by 4 and at least 8"):
        lock_rll_antisat(original, key_size=key_size, seed=0)


def test_sfll_hd0_is_deterministic_and_uses_primary_input_cube() -> None:
    original = load_bench(C17_BENCH)

    first = lock_sfll_hd0(original, key_size=3, seed=42)
    second = lock_sfll_hd0(original, key_size=3, seed=42)

    assert first == second
    assert len(first.key) == 3
    assert len(first.circuit.inputs) == len(original.inputs) + 3
    selected_inputs = tuple(item.source_signal for item in first.insertions)
    assert len(set(selected_inputs)) == 3
    assert set(selected_inputs) <= set(original.inputs)
    assert len({item.protected_signal for item in first.insertions}) == 1


def test_sfll_hd0_correct_key_passes_and_wrong_key_has_two_error_cubes() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=3, seed=42)
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

    expected_wrong_vectors = 2 * (1 << (len(original.inputs) - len(locked.key)))
    assert correct.passed
    assert correct.method == "exhaustive"
    assert not wrong.passed
    assert len(wrong.mismatches) == expected_wrong_vectors


def test_sfll_hd0_supports_a_one_bit_protected_cube() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd0(original, key_size=1, seed=7)
    key_inputs = tuple(item.key_input for item in locked.insertions)

    result = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=locked.key,
    )

    assert result.passed


@pytest.mark.parametrize("key_size", (0, 6))
def test_sfll_hd0_rejects_invalid_key_size(key_size: int) -> None:
    original = load_bench(C17_BENCH)

    with pytest.raises(CircuitError, match="SFLL-HD0 key size"):
        lock_sfll_hd0(original, key_size=key_size, seed=0)
