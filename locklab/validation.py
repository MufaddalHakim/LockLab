from __future__ import annotations

import random
from dataclasses import dataclass

from locklab.circuit import Circuit, CircuitError, Gate
from locklab.cnf import CNF, encode_circuit, encode_gate
from locklab.sat_solver import solve_cnf


@dataclass(frozen=True)
class Mismatch:
    inputs: str
    reference_output: str
    candidate_output: str


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    method: str
    vectors_checked: int
    mismatches: tuple[Mismatch, ...]


def validate_key(
    reference: Circuit,
    candidate: Circuit,
    *,
    key_inputs: tuple[str, ...],
    key: tuple[int, ...],
    exhaustive_input_limit: int = 16,
    random_vectors: int = 1000,
    seed: int = 0,
) -> ValidationResult:
    """Compare an unlocked circuit with a keyed candidate over test vectors."""

    data_inputs = _check_key_and_circuits(
        reference,
        candidate,
        key_inputs=key_inputs,
        key=key,
    )

    if len(reference.inputs) <= exhaustive_input_limit:
        method = "exhaustive"
        vectors = tuple(range(1 << len(reference.inputs)))
    else:
        if random_vectors <= 0:
            raise CircuitError("random vector count must be greater than zero")
        method = "random"
        random_source = random.Random(seed)
        vectors = tuple(
            random_source.getrandbits(len(reference.inputs))
            for _ in range(random_vectors)
        )

    key_values = dict(zip(key_inputs, key))
    mismatches: list[Mismatch] = []
    for vector in vectors:
        bits = f"{vector:0{len(reference.inputs)}b}"
        reference_inputs = {
            name: int(bit) for name, bit in zip(reference.inputs, bits)
        }
        candidate_inputs = {
            name: reference_inputs[name] for name in data_inputs
        }
        candidate_inputs.update(key_values)

        reference_values = reference.evaluate(reference_inputs)
        candidate_values = candidate.evaluate(candidate_inputs)
        reference_output = "".join(
            str(reference_values[name]) for name in reference.outputs
        )
        candidate_output = "".join(
            str(candidate_values[name]) for name in reference.outputs
        )
        if reference_output != candidate_output and len(mismatches) < 20:
            mismatches.append(
                Mismatch(
                    inputs=bits,
                    reference_output=reference_output,
                    candidate_output=candidate_output,
                )
            )

    return ValidationResult(
        passed=not mismatches,
        method=method,
        vectors_checked=len(vectors),
        mismatches=tuple(mismatches),
    )


def prove_key_equivalence(
    reference: Circuit,
    candidate: Circuit,
    *,
    key_inputs: tuple[str, ...],
    key: tuple[int, ...],
    solver_timeout_seconds: float = 30.0,
) -> ValidationResult:
    """Formally prove a keyed circuit equivalent or return one counterexample."""

    data_inputs = _check_key_and_circuits(
        reference,
        candidate,
        key_inputs=key_inputs,
        key=key,
    )
    vectors_covered = 1 << len(reference.inputs)
    if not reference.outputs:
        return ValidationResult(
            passed=True,
            method="formal SAT",
            vectors_checked=vectors_covered,
            mismatches=(),
        )

    cnf = CNF()
    data_variables = {
        name: cnf.new_variable(f"formal:data:{name}")
        for name in reference.inputs
    }
    key_variables = {
        name: cnf.new_variable(f"formal:key:{name}") for name in key_inputs
    }
    for name, bit in zip(key_inputs, key):
        variable = key_variables[name]
        cnf.add_clause(variable if bit else -variable)

    reference_encoding = encode_circuit(
        cnf,
        reference,
        namespace="formal:reference",
        input_variables=data_variables,
    )
    candidate_encoding = encode_circuit(
        cnf,
        candidate,
        namespace="formal:candidate",
        input_variables={**data_variables, **key_variables},
    )

    differences: list[int] = []
    for index, output_name in enumerate(reference.outputs):
        difference = cnf.new_variable(f"formal:difference:{index}")
        encode_gate(
            cnf,
            Gate(f"formal_difference_{index}", "XOR", ("a", "b"), "y"),
            inputs=(
                reference_encoding.output_variables[output_name],
                candidate_encoding.output_variables[output_name],
            ),
            output=difference,
        )
        differences.append(difference)
    cnf.add_clause(*differences)

    result = solve_cnf(cnf, timeout_seconds=solver_timeout_seconds)
    if not result.satisfiable:
        return ValidationResult(
            passed=True,
            method="formal SAT",
            vectors_checked=vectors_covered,
            mismatches=(),
        )

    input_bits = tuple(
        int(result.model.get(data_variables[name], False))
        for name in reference.inputs
    )
    reference_inputs = dict(zip(reference.inputs, input_bits))
    candidate_inputs = {name: reference_inputs[name] for name in data_inputs}
    candidate_inputs.update(dict(zip(key_inputs, key)))
    reference_values = reference.evaluate(reference_inputs)
    candidate_values = candidate.evaluate(candidate_inputs)
    mismatch = Mismatch(
        inputs="".join(map(str, input_bits)),
        reference_output="".join(
            str(reference_values[name]) for name in reference.outputs
        ),
        candidate_output="".join(
            str(candidate_values[name]) for name in reference.outputs
        ),
    )
    return ValidationResult(
        passed=False,
        method="formal SAT",
        vectors_checked=vectors_covered,
        mismatches=(mismatch,),
    )


def _check_key_and_circuits(
    reference: Circuit,
    candidate: Circuit,
    *,
    key_inputs: tuple[str, ...],
    key: tuple[int, ...],
) -> tuple[str, ...]:
    reference.validate()
    candidate.validate()
    if len(key_inputs) != len(key):
        raise CircuitError("key length does not match the number of key inputs")
    if len(key_inputs) != len(set(key_inputs)):
        raise CircuitError("key input names must be unique")
    if any(bit not in {0, 1} for bit in key):
        raise CircuitError("key must contain only zero and one bits")
    if not set(key_inputs) <= set(candidate.inputs):
        raise CircuitError("one or more key inputs do not exist in the candidate")

    data_inputs = tuple(name for name in candidate.inputs if name not in key_inputs)
    if set(data_inputs) != set(reference.inputs):
        raise CircuitError("reference and candidate data inputs differ")
    if set(candidate.outputs) != set(reference.outputs):
        raise CircuitError("reference and candidate outputs differ")
    return data_inputs
