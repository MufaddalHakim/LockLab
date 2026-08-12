import shutil
from math import comb
from pathlib import Path

import pytest

from locklab.bench import load_bench, write_bench
from locklab.circuit import Circuit, CircuitError
from locklab.locking import (
    lock_antisat,
    lock_mux,
    lock_rll,
    lock_rll_antisat,
    lock_sfll_hd,
    lock_sfll_hd0,
)
from locklab.validation import prove_key_equivalence, validate_key


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


def test_sfll_hd_is_deterministic_and_records_distance() -> None:
    original = load_bench(C17_BENCH)

    first = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=2,
        seed=42,
    )
    second = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=2,
        seed=42,
    )

    assert first == second
    assert first.hamming_distance == 2
    assert first.protected_cube_count == comb(4, 2)
    assert first.strip_match_signal is not None
    assert first.restore_match_signal is not None
    assert len(first.circuit.inputs) == len(original.inputs) + 4


@pytest.mark.parametrize(
    ("key_size", "hamming_distance"),
    ((1, 1), (3, 1), (3, 2), (3, 3), (5, 2)),
)
def test_sfll_hd_correct_key_passes_and_strip_has_binomial_cubes(
    key_size: int,
    hamming_distance: int,
) -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd(
        original,
        key_size=key_size,
        hamming_distance=hamming_distance,
        seed=1,
    )
    key_inputs = tuple(item.key_input for item in locked.insertions)

    correct = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=locked.key,
    )

    assert correct.passed
    assert locked.protected_cube_count == comb(key_size, hamming_distance)
    assert locked.strip_match_signal is not None
    strip_circuit = Circuit(
        name="sfll_strip_probe",
        inputs=locked.circuit.inputs,
        outputs=(locked.strip_match_signal,),
        gates=locked.circuit.gates,
    )
    active_vectors = 0
    for vector in range(1 << len(original.inputs)):
        bits = f"{vector:0{len(original.inputs)}b}"
        values = dict(zip(original.inputs, map(int, bits)))
        values.update(dict.fromkeys(key_inputs, 0))
        active_vectors += strip_circuit.evaluate(values)[
            locked.strip_match_signal
        ]
    expected_vectors = comb(key_size, hamming_distance) * (
        1 << (len(original.inputs) - key_size)
    )
    assert active_vectors == expected_vectors


def test_sfll_hd_representative_wrong_key_changes_function() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd(
        original,
        key_size=3,
        hamming_distance=1,
        seed=1,
    )
    key_inputs = tuple(item.key_input for item in locked.insertions)
    wrong_key = (1 - locked.key[0], *locked.key[1:])

    wrong = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=wrong_key,
    )

    assert not wrong.passed


def test_sfll_hd_half_distance_has_complementary_equivalent_key() -> None:
    original = load_bench(C17_BENCH)
    locked = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=2,
        seed=1,
    )
    key_inputs = tuple(item.key_input for item in locked.insertions)
    complement_key = tuple(1 - bit for bit in locked.key)

    equivalent = validate_key(
        original,
        locked.circuit,
        key_inputs=key_inputs,
        key=complement_key,
    )

    assert complement_key != locked.key
    assert equivalent.passed


def test_sfll_hd_zero_is_the_existing_hd0_construction() -> None:
    original = load_bench(C17_BENCH)

    general = lock_sfll_hd(
        original,
        key_size=3,
        hamming_distance=0,
        seed=42,
    )
    specialized = lock_sfll_hd0(original, key_size=3, seed=42)

    assert general == specialized


@pytest.mark.parametrize(
    ("benchmark", "key_size", "hamming_distance"),
    (
        ("c17", 4, 1),
        ("c432", 16, 2),
        ("c880", 16, 2),
        ("c1908", 16, 2),
    ),
)
@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices is required for formal SFLL-HD validation",
)
def test_sfll_hd_formally_validates_benchmarks(
    benchmark: str,
    key_size: int,
    hamming_distance: int,
) -> None:
    original = load_bench(
        REPOSITORY_ROOT / f"benchmarks/sources/iscas85/{benchmark}.bench"
    )
    locked = lock_sfll_hd(
        original,
        key_size=key_size,
        hamming_distance=hamming_distance,
        seed=42,
    )

    result = prove_key_equivalence(
        original,
        locked.circuit,
        key_inputs=tuple(item.key_input for item in locked.insertions),
        key=locked.key,
    )

    assert result.passed


@pytest.mark.parametrize(
    ("key_size", "hamming_distance", "message"),
    (
        (0, 0, "key size"),
        (6, 1, "key size"),
        (3, -1, "Hamming distance"),
        (3, 4, "Hamming distance"),
    ),
)
def test_sfll_hd_rejects_invalid_parameters(
    key_size: int,
    hamming_distance: int,
    message: str,
) -> None:
    original = load_bench(C17_BENCH)

    with pytest.raises(CircuitError, match=message):
        lock_sfll_hd(
            original,
            key_size=key_size,
            hamming_distance=hamming_distance,
            seed=0,
        )
