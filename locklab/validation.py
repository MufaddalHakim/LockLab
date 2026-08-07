from __future__ import annotations

import random
from dataclasses import dataclass

from locklab.circuit import Circuit, CircuitError


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

    reference.validate()
    candidate.validate()
    if len(key_inputs) != len(key):
        raise CircuitError("key length does not match the number of key inputs")
    if any(bit not in {0, 1} for bit in key):
        raise CircuitError("key must contain only zero and one bits")
    if not set(key_inputs) <= set(candidate.inputs):
        raise CircuitError("one or more key inputs do not exist in the candidate")

    data_inputs = tuple(name for name in candidate.inputs if name not in key_inputs)
    if set(data_inputs) != set(reference.inputs):
        raise CircuitError("reference and candidate data inputs differ")
    if set(candidate.outputs) != set(reference.outputs):
        raise CircuitError("reference and candidate outputs differ")

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
