import shutil
from pathlib import Path

import pytest

from locklab.bench import load_bench
from locklab.locking import lock_mux, lock_rll
from locklab.sat_attack import sat_attack


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
