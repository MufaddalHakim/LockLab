from __future__ import annotations

from dataclasses import dataclass

from locklab.circuit import Circuit, Gate


@dataclass(frozen=True)
class AntiSatCandidate:
    """One circuit region matching LockLab's type-0 Anti-SAT structure."""

    protected_output: str
    protected_source: str
    block_signal: str
    function_signal: str
    complement_signal: str
    data_inputs: tuple[str, ...]
    key_inputs: tuple[str, ...]

    @property
    def branch_size(self) -> int:
        return len(self.data_inputs)

    @property
    def key_size(self) -> int:
        return len(self.key_inputs)


def find_antisat_candidates(circuit: Circuit) -> tuple[AntiSatCandidate, ...]:
    """Find exact type-0 Anti-SAT topology without using names or metadata."""

    circuit.validate()
    drivers = {gate.output: gate for gate in circuit.gates}
    candidates: list[AntiSatCandidate] = []

    for injection_gate in circuit.topological_gates():
        if (
            injection_gate.kind != "XOR"
            or len(injection_gate.inputs) != 2
            or injection_gate.output not in circuit.outputs
        ):
            continue

        for block_index, block_signal in enumerate(injection_gate.inputs):
            block_gate = drivers.get(block_signal)
            if block_gate is None or block_gate.kind != "AND":
                continue
            if len(block_gate.inputs) != 2:
                continue

            branches = _identify_branches(block_gate, drivers)
            if branches is None:
                continue
            function_signal, complement_signal, function_gates, complement_gates = (
                branches
            )

            matched_inputs = _match_branch_inputs(
                function_gates,
                complement_gates,
                primary_inputs=set(circuit.inputs),
            )
            if matched_inputs is None:
                continue
            data_inputs, function_keys, complement_keys = matched_inputs

            candidates.append(
                AntiSatCandidate(
                    protected_output=injection_gate.output,
                    protected_source=injection_gate.inputs[1 - block_index],
                    block_signal=block_signal,
                    function_signal=function_signal,
                    complement_signal=complement_signal,
                    data_inputs=data_inputs,
                    key_inputs=(*function_keys, *complement_keys),
                )
            )

    return tuple(candidates)


def _identify_branches(
    block_gate: Gate,
    drivers: dict[str, Gate],
) -> tuple[str, str, tuple[Gate, ...], tuple[Gate, ...]] | None:
    for function_index in range(2):
        function_signal = block_gate.inputs[function_index]
        complement_signal = block_gate.inputs[1 - function_index]
        function_gate = drivers.get(function_signal)
        complement_gate = drivers.get(complement_signal)
        if function_gate is None or function_gate.kind != "AND":
            continue
        if complement_gate is None:
            continue

        function_leaves = _and_tree_xor_leaves(function_gate.inputs, drivers)
        if function_leaves is None:
            continue

        if complement_gate.kind == "NAND":
            complement_leaves = _and_tree_xor_leaves(
                complement_gate.inputs,
                drivers,
            )
        elif complement_gate.kind == "NOT" and len(complement_gate.inputs) == 1:
            complement_root = drivers.get(complement_gate.inputs[0])
            if complement_root is None or complement_root.kind != "AND":
                continue
            complement_leaves = _and_tree_xor_leaves(
                complement_root.inputs,
                drivers,
            )
        else:
            continue

        if (
            complement_leaves is not None
            and len(function_leaves) == len(complement_leaves)
            and len(function_leaves) >= 2
        ):
            return (
                function_signal,
                complement_signal,
                function_leaves,
                complement_leaves,
            )
    return None


def _and_tree_xor_leaves(
    signals: tuple[str, ...],
    drivers: dict[str, Gate],
) -> tuple[Gate, ...] | None:
    pending = list(reversed(signals))
    leaves: list[Gate] = []
    visited: set[str] = set()

    while pending:
        signal = pending.pop()
        if signal in visited:
            return None
        visited.add(signal)
        gate = drivers.get(signal)
        if gate is None:
            return None
        if gate.kind == "XOR" and len(gate.inputs) == 2:
            leaves.append(gate)
            continue
        if gate.kind == "AND":
            pending.extend(reversed(gate.inputs))
            continue
        return None

    return tuple(leaves)


def _match_branch_inputs(
    function_gates: tuple[Gate, ...],
    complement_gates: tuple[Gate, ...],
    *,
    primary_inputs: set[str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]] | None:
    remaining_complement = set(range(len(complement_gates)))
    data_inputs: list[str] = []
    function_keys: list[str] = []
    complement_keys: list[str] = []

    for function_gate in function_gates:
        function_inputs = set(function_gate.inputs)
        if len(function_inputs) != 2:
            return None
        matches = [
            index
            for index in remaining_complement
            if len(function_inputs & set(complement_gates[index].inputs)) == 1
        ]
        if len(matches) != 1:
            return None

        complement_index = matches[0]
        complement_inputs = set(complement_gates[complement_index].inputs)
        if len(complement_inputs) != 2:
            return None
        shared_input = next(iter(function_inputs & complement_inputs))
        function_key = next(iter(function_inputs - {shared_input}))
        complement_key = next(iter(complement_inputs - {shared_input}))

        data_inputs.append(shared_input)
        function_keys.append(function_key)
        complement_keys.append(complement_key)
        remaining_complement.remove(complement_index)

    all_inputs = (*data_inputs, *function_keys, *complement_keys)
    if remaining_complement or not set(all_inputs) <= primary_inputs:
        return None
    if len(set(data_inputs)) != len(data_inputs):
        return None
    if len(set(function_keys + complement_keys)) != 2 * len(data_inputs):
        return None
    if set(data_inputs) & set(function_keys + complement_keys):
        return None

    return tuple(data_inputs), tuple(function_keys), tuple(complement_keys)
