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
class SfllHd0Mapping:
    """One recovered runtime-key comparison and protected-cube literal."""

    key_input: str
    protected_input: str
    protected_bit: int
    comparator_signal: str
    strip_literal_signal: str


@dataclass(frozen=True)
class SfllHd0Candidate:
    """One circuit region matching LockLab's explicit SFLL-HD0 topology."""

    protected_output: str
    protected_source: str
    stripped_output: str
    strip_match_signal: str
    restore_match_signal: str
    mappings: tuple[SfllHd0Mapping, ...]

    @property
    def key_size(self) -> int:
        return len(self.mappings)

    @property
    def key_inputs(self) -> tuple[str, ...]:
        return tuple(mapping.key_input for mapping in self.mappings)

    @property
    def protected_inputs(self) -> tuple[str, ...]:
        return tuple(mapping.protected_input for mapping in self.mappings)

    @property
    def inferred_key(self) -> tuple[int, ...]:
        return tuple(mapping.protected_bit for mapping in self.mappings)

    @property
    def inferred_cube(self) -> str:
        return "".join(str(bit) for bit in self.inferred_key)


@dataclass(frozen=True)
class SarLockMapping:
    """One SARLock runtime comparison and its planted-key mask literal."""

    key_input: str
    protected_input: str
    correct_bit: int
    comparator_signal: str
    mask_literal_signal: str


@dataclass(frozen=True)
class SarLockCandidate:
    """One circuit region matching LockLab's explicit SARLock topology."""

    protected_output: str
    protected_source: str
    flip_signal: str
    input_match_signal: str
    key_mask_signal: str
    mappings: tuple[SarLockMapping, ...]

    @property
    def key_size(self) -> int:
        return len(self.mappings)

    @property
    def key_inputs(self) -> tuple[str, ...]:
        return tuple(mapping.key_input for mapping in self.mappings)

    @property
    def protected_inputs(self) -> tuple[str, ...]:
        return tuple(mapping.protected_input for mapping in self.mappings)

    @property
    def inferred_key(self) -> tuple[int, ...]:
        return tuple(mapping.correct_bit for mapping in self.mappings)

    @property
    def inferred_key_string(self) -> str:
        return "".join(str(bit) for bit in self.inferred_key)


@dataclass(frozen=True)
class SarLockRemoval:
    """Circuit and summary produced by bypassing structural SARLock matches."""

    circuit: Circuit
    candidates: tuple[SarLockCandidate, ...]
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


def find_sfll_hd0_candidates(circuit: Circuit) -> tuple[SfllHd0Candidate, ...]:
    """Find explicit SFLL-HD0 strip-and-restore topology without names or metadata."""

    circuit.validate()
    drivers = {gate.output: gate for gate in circuit.gates}
    primary_inputs = set(circuit.inputs)
    candidates: list[SfllHd0Candidate] = []

    for injection_gate in circuit.topological_gates():
        if (
            injection_gate.kind != "XOR"
            or len(injection_gate.inputs) != 2
            or injection_gate.output not in circuit.outputs
        ):
            continue

        for restore_index, restore_signal in enumerate(injection_gate.inputs):
            comparisons = _runtime_equality_comparisons(
                restore_signal,
                drivers,
                primary_inputs=primary_inputs,
            )
            if comparisons is None:
                continue

            stripped_output = injection_gate.inputs[1 - restore_index]
            strip_injection = drivers.get(stripped_output)
            if (
                strip_injection is None
                or strip_injection.kind != "XOR"
                or len(strip_injection.inputs) != 2
            ):
                continue

            for strip_index, strip_signal in enumerate(strip_injection.inputs):
                strip_literals = _strip_match_literals(
                    strip_signal,
                    drivers,
                    primary_inputs=primary_inputs,
                )
                if strip_literals is None:
                    continue
                mappings = _map_sfll_comparisons(comparisons, strip_literals)
                if mappings is None:
                    continue

                candidates.append(
                    SfllHd0Candidate(
                        protected_output=injection_gate.output,
                        protected_source=strip_injection.inputs[1 - strip_index],
                        stripped_output=stripped_output,
                        strip_match_signal=strip_signal,
                        restore_match_signal=restore_signal,
                        mappings=mappings,
                    )
                )

    return tuple(candidates)


def find_sarlock_candidates(circuit: Circuit) -> tuple[SarLockCandidate, ...]:
    """Find explicit SARLock comparator/mask topology without names or metadata."""

    circuit.validate()
    drivers = {gate.output: gate for gate in circuit.gates}
    primary_inputs = set(circuit.inputs)
    candidates: list[SarLockCandidate] = []

    for injection_gate in circuit.topological_gates():
        if (
            injection_gate.kind != "XOR"
            or len(injection_gate.inputs) != 2
            or injection_gate.output not in circuit.outputs
        ):
            continue

        for flip_index, flip_signal in enumerate(injection_gate.inputs):
            flip_gate = drivers.get(flip_signal)
            if (
                flip_gate is None
                or flip_gate.kind != "AND"
                or len(flip_gate.inputs) != 2
            ):
                continue

            for match_index, input_match_signal in enumerate(flip_gate.inputs):
                comparisons = _runtime_equality_comparisons(
                    input_match_signal,
                    drivers,
                    primary_inputs=primary_inputs,
                )
                if comparisons is None:
                    continue

                key_mask_signal = flip_gate.inputs[1 - match_index]
                mask_literals = _sarlock_mask_literals(
                    key_mask_signal,
                    drivers,
                    primary_inputs=primary_inputs,
                )
                if mask_literals is None:
                    continue
                mappings = _map_sarlock_comparisons(
                    comparisons,
                    mask_literals,
                )
                if mappings is None:
                    continue

                candidates.append(
                    SarLockCandidate(
                        protected_output=injection_gate.output,
                        protected_source=injection_gate.inputs[1 - flip_index],
                        flip_signal=flip_signal,
                        input_match_signal=input_match_signal,
                        key_mask_signal=key_mask_signal,
                        mappings=mappings,
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


@dataclass(frozen=True)
class _EqualityComparison:
    signal: str
    inputs: tuple[str, str]


@dataclass(frozen=True)
class _StripLiteral:
    signal: str
    data_input: str
    protected_bit: int


@dataclass(frozen=True)
class _SarLockMaskLiteral:
    signal: str
    key_input: str
    correct_bit: int


def _runtime_equality_comparisons(
    signal: str,
    drivers: dict[str, Gate],
    *,
    primary_inputs: set[str],
) -> tuple[_EqualityComparison, ...] | None:
    visited: set[str] = set()

    def visit(current: str) -> tuple[_EqualityComparison, ...] | None:
        if current in visited:
            return None
        visited.add(current)

        comparison_inputs = _equality_comparison_inputs(
            current,
            drivers,
            primary_inputs=primary_inputs,
        )
        if comparison_inputs is not None:
            return (_EqualityComparison(current, comparison_inputs),)

        gate = drivers.get(current)
        if gate is None or gate.kind != "AND":
            return None
        comparisons: list[_EqualityComparison] = []
        for gate_input in gate.inputs:
            branch = visit(gate_input)
            if branch is None:
                return None
            comparisons.extend(branch)
        return tuple(comparisons)

    comparisons = visit(signal)
    if comparisons is None or not comparisons:
        return None
    if len({comparison.signal for comparison in comparisons}) != len(comparisons):
        return None
    return comparisons


def _equality_comparison_inputs(
    signal: str,
    drivers: dict[str, Gate],
    *,
    primary_inputs: set[str],
) -> tuple[str, str] | None:
    gate = drivers.get(signal)
    if gate is None:
        return None
    if gate.kind == "XNOR" and len(gate.inputs) == 2:
        comparison_inputs = gate.inputs
    elif gate.kind == "NOT" and len(gate.inputs) == 1:
        xor_gate = drivers.get(gate.inputs[0])
        if xor_gate is None or xor_gate.kind != "XOR" or len(xor_gate.inputs) != 2:
            return None
        comparison_inputs = xor_gate.inputs
    else:
        return None

    if (
        comparison_inputs[0] == comparison_inputs[1]
        or not set(comparison_inputs) <= primary_inputs
    ):
        return None
    return comparison_inputs


def _strip_match_literals(
    signal: str,
    drivers: dict[str, Gate],
    *,
    primary_inputs: set[str],
) -> tuple[_StripLiteral, ...] | None:
    visited: set[str] = set()

    def visit(current: str) -> tuple[_StripLiteral, ...] | None:
        if current in visited:
            return None
        visited.add(current)

        if current in primary_inputs:
            return (_StripLiteral(current, current, 1),)

        gate = drivers.get(current)
        if gate is None:
            return None
        if (
            gate.kind in {"BUF", "NOT"}
            and len(gate.inputs) == 1
            and gate.inputs[0] in primary_inputs
        ):
            return (
                _StripLiteral(
                    signal=current,
                    data_input=gate.inputs[0],
                    protected_bit=1 if gate.kind == "BUF" else 0,
                ),
            )
        if gate.kind != "AND":
            return None

        literals: list[_StripLiteral] = []
        for gate_input in gate.inputs:
            branch = visit(gate_input)
            if branch is None:
                return None
            literals.extend(branch)
        return tuple(literals)

    literals = visit(signal)
    if literals is None or not literals:
        return None
    if len({literal.data_input for literal in literals}) != len(literals):
        return None
    return literals


def _map_sfll_comparisons(
    comparisons: tuple[_EqualityComparison, ...],
    strip_literals: tuple[_StripLiteral, ...],
) -> tuple[SfllHd0Mapping, ...] | None:
    if len(comparisons) != len(strip_literals):
        return None

    literals_by_input = {
        literal.data_input: literal for literal in strip_literals
    }
    mappings: list[SfllHd0Mapping] = []
    matched_data_inputs: set[str] = set()
    key_inputs: set[str] = set()

    for comparison in comparisons:
        protected_sides = [
            signal for signal in comparison.inputs if signal in literals_by_input
        ]
        if len(protected_sides) != 1:
            return None
        protected_input = protected_sides[0]
        key_input = next(
            signal for signal in comparison.inputs if signal != protected_input
        )
        literal = literals_by_input[protected_input]
        if protected_input in matched_data_inputs or key_input in key_inputs:
            return None
        matched_data_inputs.add(protected_input)
        key_inputs.add(key_input)
        mappings.append(
            SfllHd0Mapping(
                key_input=key_input,
                protected_input=protected_input,
                protected_bit=literal.protected_bit,
                comparator_signal=comparison.signal,
                strip_literal_signal=literal.signal,
            )
        )

    if matched_data_inputs != set(literals_by_input):
        return None
    if matched_data_inputs & key_inputs:
        return None
    return tuple(mappings)


def _sarlock_mask_literals(
    signal: str,
    drivers: dict[str, Gate],
    *,
    primary_inputs: set[str],
) -> tuple[_SarLockMaskLiteral, ...] | None:
    visited: set[str] = set()

    def visit(current: str) -> tuple[_SarLockMaskLiteral, ...] | None:
        if current in visited:
            return None
        visited.add(current)

        if current in primary_inputs:
            return (_SarLockMaskLiteral(current, current, 0),)

        gate = drivers.get(current)
        if gate is None:
            return None
        if (
            gate.kind in {"BUF", "NOT"}
            and len(gate.inputs) == 1
            and gate.inputs[0] in primary_inputs
        ):
            return (
                _SarLockMaskLiteral(
                    signal=current,
                    key_input=gate.inputs[0],
                    correct_bit=1 if gate.kind == "NOT" else 0,
                ),
            )
        if gate.kind != "OR":
            return None

        literals: list[_SarLockMaskLiteral] = []
        for gate_input in gate.inputs:
            branch = visit(gate_input)
            if branch is None:
                return None
            literals.extend(branch)
        return tuple(literals)

    literals = visit(signal)
    if literals is None or not literals:
        return None
    if len({literal.key_input for literal in literals}) != len(literals):
        return None
    return literals


def _map_sarlock_comparisons(
    comparisons: tuple[_EqualityComparison, ...],
    mask_literals: tuple[_SarLockMaskLiteral, ...],
) -> tuple[SarLockMapping, ...] | None:
    if len(comparisons) != len(mask_literals):
        return None

    literals_by_key = {
        literal.key_input: literal for literal in mask_literals
    }
    mappings: list[SarLockMapping] = []
    protected_inputs: set[str] = set()
    matched_keys: set[str] = set()

    for comparison in comparisons:
        key_sides = [
            signal for signal in comparison.inputs if signal in literals_by_key
        ]
        if len(key_sides) != 1:
            return None
        key_input = key_sides[0]
        protected_input = next(
            signal for signal in comparison.inputs if signal != key_input
        )
        literal = literals_by_key[key_input]
        if protected_input in protected_inputs or key_input in matched_keys:
            return None
        protected_inputs.add(protected_input)
        matched_keys.add(key_input)
        mappings.append(
            SarLockMapping(
                key_input=key_input,
                protected_input=protected_input,
                correct_bit=literal.correct_bit,
                comparator_signal=comparison.signal,
                mask_literal_signal=literal.signal,
            )
        )

    if matched_keys != set(literals_by_key):
        return None
    if protected_inputs & matched_keys:
        return None
    return tuple(mappings)


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


def remove_sarlock(circuit: Circuit) -> SarLockRemoval:
    """Bypass exact SARLock matches and prune their unreachable logic."""

    circuit.validate()
    candidates = find_sarlock_candidates(circuit)
    if not candidates:
        raise CircuitError("no matching explicit SARLock structure found")

    candidates_by_output = {
        candidate.protected_output: candidate for candidate in candidates
    }
    if len(candidates_by_output) != len(candidates):
        raise CircuitError("multiple SARLock candidates drive the same output")

    rewritten_gates: list[Gate] = []
    replaced_outputs: set[str] = set()
    for gate in circuit.topological_gates():
        candidate = candidates_by_output.get(gate.output)
        if (
            candidate is not None
            and gate.kind == "XOR"
            and set(gate.inputs)
            == {candidate.protected_source, candidate.flip_signal}
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
        raise CircuitError("could not bypass every SARLock candidate")

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
        name=f"{circuit.name}_sarlock_removed",
        inputs=retained_inputs,
        outputs=circuit.outputs,
        gates=retained_gates,
    )
    recovered.validate()
    return SarLockRemoval(
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
