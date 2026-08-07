import itertools
import shutil

import pytest

from locklab.circuit import Circuit, Gate
from locklab.cnf import CNF, encode_gate
from locklab.sat_solver import solve_cnf


@pytest.mark.parametrize(
    ("kind", "input_count"),
    (
        ("BUF", 1),
        ("NOT", 1),
        ("AND", 2),
        ("NAND", 2),
        ("OR", 2),
        ("NOR", 2),
        ("XOR", 3),
        ("XNOR", 3),
        ("MUX", 3),
    ),
)
def test_gate_cnf_matches_truth_table(kind: str, input_count: int) -> None:
    input_names = tuple(f"i{index}" for index in range(input_count))
    gate = Gate("g0", kind, input_names, "y")
    circuit = Circuit("gate", input_names, ("y",), (gate,))

    cnf = CNF()
    input_variables = tuple(cnf.new_variable() for _ in input_names)
    output_variable = cnf.new_variable()
    encode_gate(cnf, gate, inputs=input_variables, output=output_variable)

    for input_values in itertools.product((0, 1), repeat=input_count):
        expected = circuit.evaluate(dict(zip(input_names, input_values)))["y"]
        for candidate_output in (0, 1):
            fixed = {
                **dict(zip(input_variables, input_values)),
                output_variable: candidate_output,
            }
            assert _is_satisfiable(cnf, fixed) is (candidate_output == expected)


@pytest.mark.skipif(
    shutil.which("yices-sat") is None,
    reason="Yices SAT is required for the solver integration test",
)
def test_yices_solver_returns_model_and_unsat() -> None:
    satisfiable = CNF()
    value = satisfiable.new_variable()
    satisfiable.add_clause(value)

    sat_result = solve_cnf(satisfiable)

    assert sat_result.satisfiable
    assert sat_result.model[value] is True

    unsatisfiable = CNF()
    value = unsatisfiable.new_variable()
    unsatisfiable.add_clause(value)
    unsatisfiable.add_clause(-value)

    assert not solve_cnf(unsatisfiable).satisfiable


def _is_satisfiable(cnf: CNF, fixed: dict[int, int]) -> bool:
    remaining = [
        variable
        for variable in range(1, cnf.variable_count + 1)
        if variable not in fixed
    ]
    for values in itertools.product((0, 1), repeat=len(remaining)):
        assignment = {**fixed, **dict(zip(remaining, values))}
        if all(
            any(
                assignment[abs(literal)] == int(literal > 0)
                for literal in clause
            )
            for clause in cnf.clauses
        ):
            return True
    return False
