from __future__ import annotations

from dataclasses import dataclass
from math import prod

from locklab.circuit import Circuit, CircuitError, Gate


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


@dataclass(frozen=True)
class AntiSatRemoval:
    """Circuit and summary produced by bypassing structural Anti-SAT matches."""

    circuit: Circuit
    candidates: tuple[AntiSatCandidate, ...]
    removed_gate_count: int
    removed_inputs: tuple[str, ...]


@dataclass(frozen=True)
class SignalProbabilityScore:
    """Signal probability skew and gate-input ADS for one gate output."""

    signal: str
    gate_kind: str
    probability_one: float
    skew: float
    input_skews: tuple[float, ...]
    ads: float


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


def signal_probability_scores(
    circuit: Circuit,
) -> tuple[SignalProbabilityScore, ...]:
    """Rank gates by ADS using independent-input probability propagation."""

    circuit.validate()
    probabilities = {"0": 0.0, "1": 1.0}
    probabilities.update({name: 0.5 for name in circuit.inputs})
    scores: list[SignalProbabilityScore] = []

    for gate in circuit.topological_gates():
        input_probabilities = tuple(
            probabilities[signal] for signal in gate.inputs
        )
        probability_one = _gate_probability(gate.kind, input_probabilities)
        input_skews = tuple(value - 0.5 for value in input_probabilities)
        ads = (
            max(input_skews) - min(input_skews)
            if len(input_skews) >= 2
            else 0.0
        )
        probabilities[gate.output] = probability_one
        scores.append(
            SignalProbabilityScore(
                signal=gate.output,
                gate_kind=gate.kind,
                probability_one=probability_one,
                skew=probability_one - 0.5,
                input_skews=input_skews,
                ads=ads,
            )
        )

    return tuple(sorted(scores, key=lambda score: score.ads, reverse=True))


def _gate_probability(kind: str, values: tuple[float, ...]) -> float:
    if kind == "BUF":
        probability = values[0]
    elif kind == "NOT":
        probability = 1.0 - values[0]
    elif kind == "AND":
        probability = prod(values)
    elif kind == "NAND":
        probability = 1.0 - prod(values)
    elif kind == "OR":
        probability = 1.0 - prod(1.0 - value for value in values)
    elif kind == "NOR":
        probability = prod(1.0 - value for value in values)
    elif kind in {"XOR", "XNOR"}:
        xor_probability = (
            1.0 - prod(1.0 - 2.0 * value for value in values)
        ) / 2.0
        probability = (
            xor_probability if kind == "XOR" else 1.0 - xor_probability
        )
    elif kind == "MUX":
        data_a, data_b, select = values
        probability = (1.0 - select) * data_a + select * data_b
    else:
        raise CircuitError(f"unsupported gate type: {kind}")
    return min(1.0, max(0.0, probability))


def remove_antisat(circuit: Circuit) -> AntiSatRemoval:
    """Bypass exact Anti-SAT matches and prune their unreachable logic."""

    circuit.validate()
    candidates = find_antisat_candidates(circuit)
    if not candidates:
        raise CircuitError("no matching type-0 Anti-SAT structure found")

    candidates_by_output = {
        candidate.protected_output: candidate for candidate in candidates
    }
    if len(candidates_by_output) != len(candidates):
        raise CircuitError("multiple Anti-SAT candidates drive the same output")

    rewritten_gates: list[Gate] = []
    replaced_outputs: set[str] = set()
    for gate in circuit.topological_gates():
        candidate = candidates_by_output.get(gate.output)
        if (
            candidate is not None
            and gate.kind == "XOR"
            and set(gate.inputs)
            == {candidate.protected_source, candidate.block_signal}
        ):
            rewritten_gates.append(
                Gate(
                    name=gate.name,
                    kind="BUF",
                    inputs=(candidate.protected_source,),
                    output=gate.output,
                )
            )
            replaced_outputs.add(gate.output)
        else:
            rewritten_gates.append(gate)

    if replaced_outputs != set(candidates_by_output):
        raise CircuitError("could not bypass every Anti-SAT candidate")

    retained_gates, needed_signals = _prune_to_outputs(
        tuple(rewritten_gates),
        circuit.outputs,
    )
    suspected_key_inputs = {
        key_input for candidate in candidates for key_input in candidate.key_inputs
    }
    retained_inputs = tuple(
        name
        for name in circuit.inputs
        if name not in suspected_key_inputs or name in needed_signals
    )
    removed_inputs = tuple(
        name for name in circuit.inputs if name not in retained_inputs
    )

    recovered = Circuit(
        name=f"{circuit.name}_antisat_removed",
        inputs=retained_inputs,
        outputs=circuit.outputs,
        gates=retained_gates,
    )
    recovered.validate()
    return AntiSatRemoval(
        circuit=recovered,
        candidates=candidates,
        removed_gate_count=len(circuit.gates) - len(recovered.gates),
        removed_inputs=removed_inputs,
    )


def _prune_to_outputs(
    gates: tuple[Gate, ...],
    outputs: tuple[str, ...],
) -> tuple[tuple[Gate, ...], set[str]]:
    needed_signals = set(outputs)
    retained_reversed: list[Gate] = []
    for gate in reversed(gates):
        if gate.output not in needed_signals:
            continue
        retained_reversed.append(gate)
        needed_signals.update(gate.inputs)
    return tuple(reversed(retained_reversed)), needed_signals


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
