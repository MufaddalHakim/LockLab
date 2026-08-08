from __future__ import annotations

from dataclasses import dataclass

from locklab.circuit import Circuit, CircuitError, Gate
from locklab.cnf import CNF, encode_circuit, encode_gate
from locklab.sat_solver import solve_cnf
from locklab.validation import ValidationResult, prove_key_equivalence


@dataclass(frozen=True)
class Observation:
    inputs: tuple[int, ...]
    outputs: tuple[int, ...]

    @property
    def input_string(self) -> str:
        return "".join(map(str, self.inputs))

    @property
    def output_string(self) -> str:
        return "".join(map(str, self.outputs))


@dataclass(frozen=True)
class SatAttackResult:
    key_inputs: tuple[str, ...]
    key: tuple[int, ...]
    observations: tuple[Observation, ...]
    solver_calls: int
    validation: ValidationResult

    @property
    def key_string(self) -> str:
        return "".join(map(str, self.key))


def sat_attack(
    locked: Circuit,
    oracle: Circuit,
    *,
    solver_timeout_seconds: float = 30.0,
) -> SatAttackResult:
    """Recover a functionally correct key with an oracle-guided SAT attack."""

    locked.validate()
    oracle.validate()
    key_inputs = tuple(name for name in locked.inputs if name not in oracle.inputs)
    if not key_inputs:
        raise CircuitError("locked circuit has no identifiable key inputs")

    data_inputs = tuple(name for name in locked.inputs if name not in key_inputs)
    if set(data_inputs) != set(oracle.inputs):
        raise CircuitError("locked circuit and oracle data inputs differ")
    if set(locked.outputs) != set(oracle.outputs):
        raise CircuitError("locked circuit and oracle outputs differ")

    observations: list[Observation] = []
    solver_calls = 0
    maximum_observations = 1 << len(oracle.inputs)

    while True:
        miter, data_variables = _build_miter(
            locked,
            oracle,
            key_inputs,
            tuple(observations),
        )
        miter_result = solve_cnf(miter, timeout_seconds=solver_timeout_seconds)
        solver_calls += 1
        if not miter_result.satisfiable:
            break

        dip = tuple(
            int(miter_result.model.get(data_variables[name], False))
            for name in oracle.inputs
        )
        if any(observation.inputs == dip for observation in observations):
            raise CircuitError("SAT attack produced a repeated distinguishing input")

        oracle_values = oracle.evaluate(dict(zip(oracle.inputs, dip)))
        oracle_output = tuple(oracle_values[name] for name in oracle.outputs)
        observations.append(Observation(inputs=dip, outputs=oracle_output))
        if len(observations) > maximum_observations:
            raise CircuitError("SAT attack exceeded the possible input-vector count")

    key_cnf, key_variables = _build_key_problem(
        locked,
        oracle,
        key_inputs,
        tuple(observations),
    )
    key_result = solve_cnf(key_cnf, timeout_seconds=solver_timeout_seconds)
    solver_calls += 1
    if not key_result.satisfiable:
        raise CircuitError("oracle observations are inconsistent with the locked circuit")

    key = tuple(
        int(key_result.model.get(key_variables[name], False))
        for name in key_inputs
    )
    validation = prove_key_equivalence(
        oracle,
        locked,
        key_inputs=key_inputs,
        key=key,
    )
    if not validation.passed:
        raise CircuitError("SAT attack candidate key failed functional validation")

    return SatAttackResult(
        key_inputs=key_inputs,
        key=key,
        observations=tuple(observations),
        solver_calls=solver_calls,
        validation=validation,
    )


def _build_miter(
    locked: Circuit,
    oracle: Circuit,
    key_inputs: tuple[str, ...],
    observations: tuple[Observation, ...],
) -> tuple[CNF, dict[str, int]]:
    cnf = CNF()
    data_variables = {
        name: cnf.new_variable(f"miter:data:{name}") for name in oracle.inputs
    }
    key_a = {
        name: cnf.new_variable(f"miter:key-a:{name}") for name in key_inputs
    }
    key_b = {
        name: cnf.new_variable(f"miter:key-b:{name}") for name in key_inputs
    }

    copy_a = encode_circuit(
        cnf,
        locked,
        namespace="miter:a",
        input_variables={**data_variables, **key_a},
    )
    copy_b = encode_circuit(
        cnf,
        locked,
        namespace="miter:b",
        input_variables={**data_variables, **key_b},
    )

    differences: list[int] = []
    for index, output_name in enumerate(oracle.outputs):
        difference = cnf.new_variable(f"miter:difference:{index}")
        encode_gate(
            cnf,
            Gate(f"difference_{index}", "XOR", ("a", "b"), "y"),
            inputs=(
                copy_a.output_variables[output_name],
                copy_b.output_variables[output_name],
            ),
            output=difference,
        )
        differences.append(difference)
    cnf.add_clause(*differences)

    for index, observation in enumerate(observations):
        _add_observation(
            cnf,
            locked,
            oracle,
            key_a,
            observation,
            namespace=f"observation:{index}:a",
        )
        _add_observation(
            cnf,
            locked,
            oracle,
            key_b,
            observation,
            namespace=f"observation:{index}:b",
        )

    return cnf, data_variables


def _build_key_problem(
    locked: Circuit,
    oracle: Circuit,
    key_inputs: tuple[str, ...],
    observations: tuple[Observation, ...],
) -> tuple[CNF, dict[str, int]]:
    cnf = CNF()
    key_variables = {
        name: cnf.new_variable(f"candidate:{name}") for name in key_inputs
    }
    for variable in key_variables.values():
        cnf.add_clause(variable, -variable)
    for index, observation in enumerate(observations):
        _add_observation(
            cnf,
            locked,
            oracle,
            key_variables,
            observation,
            namespace=f"candidate:observation:{index}",
        )
    return cnf, key_variables


def _add_observation(
    cnf: CNF,
    locked: Circuit,
    oracle: Circuit,
    key_variables: dict[str, int],
    observation: Observation,
    *,
    namespace: str,
) -> None:
    data_variables: dict[str, int] = {}
    for name, value in zip(oracle.inputs, observation.inputs):
        variable = cnf.new_variable(f"{namespace}:data:{name}")
        cnf.add_clause(variable if value else -variable)
        data_variables[name] = variable

    encoding = encode_circuit(
        cnf,
        locked,
        namespace=namespace,
        input_variables={**data_variables, **key_variables},
    )
    for name, value in zip(oracle.outputs, observation.outputs):
        variable = encoding.output_variables[name]
        cnf.add_clause(variable if value else -variable)
