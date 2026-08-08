import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from locklab.bench import write_bench
from locklab.circuit import Circuit, Gate
from locklab.validation import prove_key_equivalence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


pytestmark = pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices SAT is required for formal validation tests",
)


def _equivalent_key_circuits() -> tuple[Circuit, Circuit]:
    reference = Circuit(
        name="reference",
        inputs=("a",),
        outputs=("y",),
        gates=(Gate("g0", "BUF", ("a",), "y"),),
    )
    candidate = Circuit(
        name="candidate",
        inputs=("a", "key_0", "key_1"),
        outputs=("y",),
        gates=(
            Gate("g0", "XOR", ("a", "key_0"), "protected"),
            Gate("g1", "XOR", ("protected", "key_1"), "y"),
        ),
    )
    return reference, candidate


@pytest.mark.parametrize("key", ((0, 0), (1, 1)))
def test_formal_validation_accepts_functionally_equivalent_keys(
    key: tuple[int, ...],
) -> None:
    reference, candidate = _equivalent_key_circuits()

    result = prove_key_equivalence(
        reference,
        candidate,
        key_inputs=("key_0", "key_1"),
        key=key,
    )

    assert result.passed
    assert result.method == "formal SAT"
    assert result.vectors_checked == 2
    assert not result.mismatches


def test_formal_validation_returns_a_counterexample_for_an_incorrect_key() -> None:
    reference, candidate = _equivalent_key_circuits()

    result = prove_key_equivalence(
        reference,
        candidate,
        key_inputs=("key_0", "key_1"),
        key=(0, 1),
    )

    assert not result.passed
    assert len(result.mismatches) == 1
    mismatch = result.mismatches[0]
    assert mismatch.inputs in {"0", "1"}
    assert mismatch.reference_output != mismatch.candidate_output


@pytest.mark.parametrize(
    ("key", "return_code", "message"),
    (
        ("00", 0, "PASS: exact planted key is formally equivalent"),
        ("11", 0, "PASS: alternative key is formally equivalent"),
        ("01", 1, "FAIL: key is not functionally equivalent"),
    ),
)
def test_validate_cli_classifies_key_outcomes(
    tmp_path: Path,
    key: str,
    return_code: int,
    message: str,
) -> None:
    reference, candidate = _equivalent_key_circuits()
    reference_path = tmp_path / "reference.bench"
    candidate_path = tmp_path / "locked.bench"
    write_bench(reference, reference_path)
    write_bench(candidate, candidate_path)
    candidate_path.with_suffix(".lock.json").write_text(
        json.dumps({"key": "00"}),
        encoding="utf-8",
    )

    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "locklab",
            "validate",
            str(reference_path),
            str(candidate_path),
            "--key",
            key,
        ),
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == return_code, result.stderr
    assert message in result.stdout
    assert "Counterexample:" in result.stdout if return_code else "UNSAT" in result.stdout
