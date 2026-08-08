import shutil
from pathlib import Path

import pytest

from locklab.bench import load_bench
from locklab.locking import lock_antisat, lock_mux, lock_rll
from locklab.sat_attack import appsat_attack, sat_attack


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
C17_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.bench"


pytestmark = pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices SAT is required for attack tests",
)


@pytest.mark.parametrize(
    ("key_size", "seed"),
    ((1, 0), (2, 7), (3, 42), (4, 99)),
)
def test_sat_attack_recovers_functionality_for_locked_c17(
    key_size: int,
    seed: int,
) -> None:
    oracle = load_bench(C17_BENCH)
    locked = lock_rll(oracle, key_size=key_size, seed=seed)

    result = sat_attack(locked.circuit, oracle)

    assert result.validation.passed
    assert result.validation.vectors_checked == 32
    assert len(result.key) == key_size
    assert result.observations
    assert result.solver_calls == len(result.observations) + 2


def test_sat_attack_recovers_functionality_for_mux_locked_c17() -> None:
    oracle = load_bench(C17_BENCH)
    locked = lock_mux(oracle, key_size=3, seed=0)

    result = sat_attack(locked.circuit, oracle)

    assert result.validation.passed
    assert len(result.key) == 3
    assert result.observations
    assert result.solver_calls == len(result.observations) + 2


def test_antisat_requires_exponential_distinguishing_inputs() -> None:
    oracle = load_bench(C17_BENCH)
    locked = lock_antisat(oracle, key_size=8, seed=42)

    result = sat_attack(locked.circuit, oracle)

    assert result.validation.passed
    assert len(result.observations) == 16


def test_appsat_stops_before_exact_antisat_convergence() -> None:
    oracle = load_bench(C17_BENCH)
    locked = lock_antisat(oracle, key_size=10, seed=42)

    result = appsat_attack(
        locked.circuit,
        oracle,
        samples=32,
        error_threshold=0.0,
        seed=7,
        check_interval=2,
        settled_checks=1,
    )

    assert result.termination == "approximate error threshold"
    assert result.distinguishing_inputs < 32
    assert result.estimated_error == 0.0
    assert result.validation.passed


def test_appsat_reports_exact_convergence_before_first_error_check() -> None:
    oracle = load_bench(C17_BENCH)
    locked = lock_antisat(oracle, key_size=4, seed=42)

    result = appsat_attack(
        locked.circuit,
        oracle,
        samples=32,
        error_threshold=0.0,
        seed=7,
    )

    assert result.termination == "exact SAT convergence"
    assert result.distinguishing_inputs == 4
    assert result.estimated_error == 0.0
    assert result.validation.passed


def test_appsat_can_return_a_non_equivalent_approximate_key() -> None:
    oracle = load_bench(C17_BENCH)
    locked = lock_rll(oracle, key_size=4, seed=0)

    result = appsat_attack(
        locked.circuit,
        oracle,
        samples=1,
        error_threshold=1.0,
        seed=0,
        check_interval=1,
        settled_checks=1,
    )

    assert result.termination == "approximate error threshold"
    assert result.distinguishing_inputs == 1
    assert result.sampled_vectors == 1
    assert result.sampled_mismatches == 1
    assert result.reinforced_observations == 1
    assert not result.validation.passed
