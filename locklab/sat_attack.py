from __future__ import annotations

import random
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


@dataclass(frozen=True)
class AppSatAttackResult:
    key_inputs: tuple[str, ...]
    key: tuple[int, ...]
    observations: tuple[Observation, ...]
    distinguishing_inputs: int
    random_queries: int
    reinforced_observations: int
    solver_calls: int
    sampled_vectors: int
    sampled_mismatches: int
    estimated_error: float
    termination: str
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

    key_inputs = _identify_key_inputs(locked, oracle)

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

    key = _solve_candidate_key(
        locked,
        oracle,
        key_inputs,
        tuple(observations),
        solver_timeout_seconds=solver_timeout_seconds,
    )
    solver_calls += 1
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


def appsat_attack(
    locked: Circuit,
    oracle: Circuit,
    *,
    samples: int = 256,
    error_threshold: float = 0.01,
    seed: int = 0,
    check_interval: int = 5,
    settled_checks: int = 2,
    solver_timeout_seconds: float = 30.0,
) -> AppSatAttackResult:
    """Recover an approximate key using SAT queries and sampled error checks."""

    key_inputs = _identify_key_inputs(locked, oracle)
    if samples <= 0:
        raise CircuitError("AppSAT sample count must be greater than zero")
    if not 0.0 <= error_threshold <= 1.0:
        raise CircuitError("AppSAT error threshold must be between 0 and 1")
    if check_interval <= 0:
        raise CircuitError("AppSAT check interval must be greater than zero")
    if settled_checks <= 0:
        raise CircuitError("AppSAT settled-check count must be greater than zero")

    random_source = random.Random(seed)
    observations: list[Observation] = []
    distinguishing_inputs = 0
    random_queries = 0
    reinforced_observations = 0
    solver_calls = 0
    settled = 0
    maximum_observations = 1 << len(oracle.inputs)
    key: tuple[int, ...] | None = None
    sampled_vectors = 0
    sampled_mismatches = 0
    estimated_error = 1.0
    termination = ""

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
            key = _solve_candidate_key(
                locked,
                oracle,
                key_inputs,
                tuple(observations),
                solver_timeout_seconds=solver_timeout_seconds,
            )
            solver_calls += 1
            (
                sampled_vectors,
                sampled_mismatches,
                estimated_error,
                _,
            ) = _estimate_key_error(
                locked,
                oracle,
                key_inputs,
                key,
                samples=samples,
                random_source=random_source,
            )
            random_queries += sampled_vectors
            termination = "exact SAT convergence"
            break

        dip = tuple(
            int(miter_result.model.get(data_variables[name], False))
            for name in oracle.inputs
        )
        if any(observation.inputs == dip for observation in observations):
            raise CircuitError("AppSAT produced a repeated distinguishing input")

        oracle_values = oracle.evaluate(dict(zip(oracle.inputs, dip)))
        oracle_output = tuple(oracle_values[name] for name in oracle.outputs)
        observations.append(Observation(inputs=dip, outputs=oracle_output))
        distinguishing_inputs += 1
        if len(observations) > maximum_observations:
            raise CircuitError("AppSAT exceeded the possible input-vector count")
        if distinguishing_inputs % check_interval:
            continue

        candidate = _solve_candidate_key(
            locked,
            oracle,
            key_inputs,
            tuple(observations),
            solver_timeout_seconds=solver_timeout_seconds,
        )
        solver_calls += 1
        (
            sampled_vectors,
            sampled_mismatches,
            estimated_error,
            mismatches,
        ) = _estimate_key_error(
            locked,
            oracle,
            key_inputs,
            candidate,
            samples=samples,
            random_source=random_source,
        )
        random_queries += sampled_vectors

        known_inputs = {observation.inputs for observation in observations}
        for mismatch in mismatches:
            if mismatch.inputs in known_inputs:
                continue
            observations.append(mismatch)
            known_inputs.add(mismatch.inputs)
            reinforced_observations += 1
        if len(observations) > maximum_observations:
            raise CircuitError("AppSAT exceeded the possible input-vector count")

        settled = settled + 1 if estimated_error <= error_threshold else 0
        if settled >= settled_checks:
            key = candidate
            termination = "approximate error threshold"
            break

    if key is None:
        raise CircuitError("AppSAT terminated without a candidate key")
    validation = prove_key_equivalence(
        oracle,
        locked,
        key_inputs=key_inputs,
        key=key,
    )
    return AppSatAttackResult(
        key_inputs=key_inputs,
        key=key,
        observations=tuple(observations),
        distinguishing_inputs=distinguishing_inputs,
        random_queries=random_queries,
        reinforced_observations=reinforced_observations,
        solver_calls=solver_calls,
        sampled_vectors=sampled_vectors,
        sampled_mismatches=sampled_mismatches,
        estimated_error=estimated_error,
        termination=termination,
        validation=validation,
    )


def _identify_key_inputs(locked: Circuit, oracle: Circuit) -> tuple[str, ...]:
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
    return key_inputs


def _solve_candidate_key(
    locked: Circuit,
    oracle: Circuit,
    key_inputs: tuple[str, ...],
    observations: tuple[Observation, ...],
    *,
    solver_timeout_seconds: float,
) -> tuple[int, ...]:
    key_cnf, key_variables = _build_key_problem(
        locked,
        oracle,
        key_inputs,
        observations,
    )
    result = solve_cnf(key_cnf, timeout_seconds=solver_timeout_seconds)
    if not result.satisfiable:
        raise CircuitError("oracle observations are inconsistent with the locked circuit")
    return tuple(
        int(result.model.get(key_variables[name], False)) for name in key_inputs
    )


def _estimate_key_error(
    locked: Circuit,
    oracle: Circuit,
    key_inputs: tuple[str, ...],
    key: tuple[int, ...],
    *,
    samples: int,
    random_source: random.Random,
) -> tuple[int, int, float, tuple[Observation, ...]]:
    input_width = len(oracle.inputs)
    vector_count = 1 << input_width
    if samples >= vector_count:
        vectors = tuple(range(vector_count))
    else:
        selected: set[int] = set()
        while len(selected) < samples:
            selected.add(random_source.getrandbits(input_width))
        vectors = tuple(sorted(selected))

    key_values = dict(zip(key_inputs, key))
    mismatches: list[Observation] = []
    for vector in vectors:
        bits = tuple(int(bit) for bit in f"{vector:0{input_width}b}")
        oracle_inputs = dict(zip(oracle.inputs, bits))
        locked_inputs = {name: oracle_inputs[name] for name in oracle.inputs}
        locked_inputs.update(key_values)
        oracle_values = oracle.evaluate(oracle_inputs)
        locked_values = locked.evaluate(locked_inputs)
        oracle_output = tuple(oracle_values[name] for name in oracle.outputs)
        locked_output = tuple(locked_values[name] for name in oracle.outputs)
        if locked_output != oracle_output:
            mismatches.append(Observation(inputs=bits, outputs=oracle_output))

    error = len(mismatches) / len(vectors)
    return len(vectors), len(mismatches), error, tuple(mismatches)


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
