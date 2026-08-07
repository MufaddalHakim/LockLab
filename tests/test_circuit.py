import pytest

from locklab.circuit import Circuit, CircuitError, Gate


def test_circuit_evaluates_combinational_logic() -> None:
    circuit = Circuit(
        name="and_not",
        inputs=("a", "b"),
        outputs=("y",),
        gates=(
            Gate("g0", "AND", ("a", "b"), "n0"),
            Gate("g1", "NOT", ("n0",), "y"),
        ),
    )

    circuit.validate()

    assert circuit.evaluate({"a": 0, "b": 0}) == {"y": 1}
    assert circuit.evaluate({"a": 1, "b": 1}) == {"y": 0}


def test_circuit_detects_combinational_cycle() -> None:
    circuit = Circuit(
        name="cycle",
        inputs=("a",),
        outputs=("y",),
        gates=(
            Gate("g0", "AND", ("a", "n1"), "y"),
            Gate("g1", "NOT", ("y",), "n1"),
        ),
    )

    with pytest.raises(CircuitError, match="combinational cycle"):
        circuit.validate()
