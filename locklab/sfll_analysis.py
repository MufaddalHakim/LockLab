from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from locklab.analysis import SfllHd0Mapping, find_sfll_hd0_candidates
from locklab.circuit import Circuit, Gate
from locklab.cnf import CNF, encode_circuit, encode_gate
from locklab.sat_solver import solve_cnf


@dataclass(frozen=True)
class SfllHd0Assessment:
    """An exact or formally checked functional SFLL-HD0 candidate."""

    match_type: str
    protected_output: str
    strip_match_signal: str
    restore_match_signal: str
    mappings: tuple[SfllHd0Mapping, ...]
    strip_active_value: int
    restore_active_value: int
    strip_unateness: tuple[str, ...]

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
class _RestoreSignature:
    signal: str
    active_value: int
    pairs: tuple[tuple[str, str, str], ...]
    observable_outputs: frozenset[str]

    @property
    def key_inputs(self) -> frozenset[str]:
        return frozenset(key_input for key_input, _, _ in self.pairs)


@dataclass(frozen=True)
class _PointSignature:
    signal: str
    active_value: int
    bits: tuple[tuple[str, int], ...]
    unateness: tuple[tuple[str, str], ...]


def assess_sfll_hd0(
    circuit: Circuit,
    *,
    max_key_size: int = 32,
    solver_timeout_seconds: float = 30.0,
) -> tuple[SfllHd0Assessment, ...]:
    """Find exact matches or formally prove synthesized SFLL-HD0 candidates."""

    circuit.validate()
    if max_key_size <= 0:
        raise ValueError("maximum SFLL key size must be greater than zero")

    exact_candidates = find_sfll_hd0_candidates(circuit)
    if exact_candidates:
        return tuple(
            SfllHd0Assessment(
                match_type="exact topology",
                protected_output=candidate.protected_output,
                strip_match_signal=candidate.strip_match_signal,
                restore_match_signal=candidate.restore_match_signal,
                mappings=candidate.mappings,
                strip_active_value=1,
                restore_active_value=1,
                strip_unateness=tuple(
                    "positive" if mapping.protected_bit else "negative"
                    for mapping in candidate.mappings
                ),
            )
            for candidate in exact_candidates
        )

    supports = _fanin_supports(circuit)
    observable_outputs = _observable_outputs(circuit)
    postdominators = _postdominators(circuit)
    polarities = _syntactic_polarities(circuit)
    restore_signatures = _find_restore_signatures(
        circuit,
        supports=supports,
        observable_outputs=observable_outputs,
        postdominators=postdominators,
        max_key_size=max_key_size,
        solver_timeout_seconds=solver_timeout_seconds,
    )

    assessments: list[SfllHd0Assessment] = []
    for restore in restore_signatures:
        data_inputs = tuple(data_input for _, data_input, _ in restore.pairs)
        data_support = frozenset(data_inputs)
        point_signatures: list[_PointSignature] = []
        for gate in circuit.topological_gates():
            signal = gate.output
            if supports[signal] != data_support:
                continue
            if not (observable_outputs[signal] & restore.observable_outputs):
                continue
            point = _point_function_signature(
                circuit,
                signal,
                data_inputs=data_inputs,
                polarities=polarities[signal],
                solver_timeout_seconds=solver_timeout_seconds,
            )
            if point is not None:
                point_signatures.append(point)

        for point in _prefer_active_high_points(point_signatures):
            bits_by_input = dict(point.bits)
            unateness_by_input = dict(point.unateness)
            mappings = tuple(
                SfllHd0Mapping(
                    key_input=key_input,
                    protected_input=data_input,
                    protected_bit=bits_by_input[data_input],
                    comparator_signal=comparator_signal,
                    strip_literal_signal=point.signal,
                )
                for key_input, data_input, comparator_signal in restore.pairs
            )
            for protected_output in sorted(
                observable_outputs[point.signal] & restore.observable_outputs
            ):
                assessments.append(
                    SfllHd0Assessment(
                        match_type="functional candidate",
                        protected_output=protected_output,
                        strip_match_signal=point.signal,
                        restore_match_signal=restore.signal,
                        mappings=mappings,
                        strip_active_value=point.active_value,
                        restore_active_value=restore.active_value,
                        strip_unateness=tuple(
                            unateness_by_input[mapping.protected_input]
                            for mapping in mappings
                        ),
                    )
                )

    return _deduplicate_assessments(assessments)


def _fanin_supports(circuit: Circuit) -> dict[str, frozenset[str]]:
    supports = {"0": frozenset(), "1": frozenset()}
    supports.update({name: frozenset((name,)) for name in circuit.inputs})
    for gate in circuit.topological_gates():
        supports[gate.output] = frozenset().union(
            *(supports[signal] for signal in gate.inputs)
        )
    return supports


def _observable_outputs(circuit: Circuit) -> dict[str, frozenset[str]]:
    outputs_by_signal: dict[str, set[str]] = defaultdict(set)
    for output in circuit.outputs:
        outputs_by_signal[output].add(output)
    for gate in reversed(circuit.topological_gates()):
        reached_outputs = outputs_by_signal[gate.output]
        for gate_input in gate.inputs:
            outputs_by_signal[gate_input].update(reached_outputs)
    return {
        signal: frozenset(outputs)
        for signal, outputs in outputs_by_signal.items()
    }


def _postdominators(circuit: Circuit) -> dict[str, frozenset[str]]:
    sink = "<primary-output-sink>"
    consumers: dict[str, set[str]] = defaultdict(set)
    for gate in circuit.gates:
        for gate_input in gate.inputs:
            consumers[gate_input].add(gate.output)

    postdominators: dict[str, frozenset[str]] = {sink: frozenset((sink,))}

    def calculate(signal: str) -> None:
        successors = set(consumers[signal])
        if signal in circuit.outputs:
            successors.add(sink)
        if not successors:
            postdominators[signal] = frozenset((signal,))
            return
        successor_sets = [postdominators[successor] for successor in successors]
        common = set(successor_sets[0])
        for successor_set in successor_sets[1:]:
            common.intersection_update(successor_set)
        postdominators[signal] = frozenset((signal, *common))

    for gate in reversed(circuit.topological_gates()):
        calculate(gate.output)
    for primary_input in circuit.inputs:
        calculate(primary_input)
    return postdominators


def _syntactic_polarities(
    circuit: Circuit,
) -> dict[str, dict[str, frozenset[int]]]:
    polarities: dict[str, dict[str, frozenset[int]]] = {
        "0": {},
        "1": {},
    }
    polarities.update(
        {name: {name: frozenset((1,))} for name in circuit.inputs}
    )

    for gate in circuit.topological_gates():
        merged: dict[str, set[int]] = defaultdict(set)
        if gate.kind in {"XOR", "XNOR", "MUX"}:
            for gate_input in gate.inputs:
                for primary_input in polarities[gate_input]:
                    merged[primary_input].update((-1, 1))
        else:
            invert = gate.kind in {"NOT", "NAND", "NOR"}
            for gate_input in gate.inputs:
                for primary_input, signs in polarities[gate_input].items():
                    merged[primary_input].update(
                        -sign if invert else sign for sign in signs
                    )
        polarities[gate.output] = {
            primary_input: frozenset(signs)
            for primary_input, signs in merged.items()
        }
    return polarities


def _find_restore_signatures(
    circuit: Circuit,
    *,
    supports: dict[str, frozenset[str]],
    observable_outputs: dict[str, frozenset[str]],
    postdominators: dict[str, frozenset[str]],
    max_key_size: int,
    solver_timeout_seconds: float,
) -> tuple[_RestoreSignature, ...]:
    possible: list[_RestoreSignature] = []
    for gate in circuit.topological_gates():
        signal = gate.output
        support = supports[signal]
        if not observable_outputs[signal] or len(support) < 2:
            continue
        exclusive_inputs = tuple(
            primary_input
            for primary_input in circuit.inputs
            if primary_input in support
            and signal in postdominators[primary_input]
        )
        data_inputs = tuple(
            primary_input
            for primary_input in circuit.inputs
            if primary_input in support and primary_input not in exclusive_inputs
        )
        if (
            len(exclusive_inputs) < 2
            or len(exclusive_inputs) != len(data_inputs)
            or len(exclusive_inputs) > max_key_size
        ):
            continue

        signature = _restore_signature(
            circuit,
            signal,
            key_inputs=exclusive_inputs,
            data_inputs=data_inputs,
            supports=supports,
            observable_outputs=observable_outputs[signal],
            solver_timeout_seconds=solver_timeout_seconds,
        )
        if signature is not None:
            possible.append(signature)

    maximal = [
        candidate
        for candidate in possible
        if not any(
            candidate.key_inputs < other.key_inputs
            and candidate.observable_outputs & other.observable_outputs
            for other in possible
        )
    ]
    return tuple(maximal)


def _restore_signature(
    circuit: Circuit,
    signal: str,
    *,
    key_inputs: tuple[str, ...],
    data_inputs: tuple[str, ...],
    supports: dict[str, frozenset[str]],
    observable_outputs: frozenset[str],
    solver_timeout_seconds: float,
) -> _RestoreSignature | None:
    cone_signals = _fanin_signals(circuit, signal)
    comparator_signals: dict[tuple[str, str], str] = {}
    pairing_options: dict[str, tuple[str, ...]] = {}
    topological_index = {
        gate.output: index
        for index, gate in enumerate(circuit.topological_gates())
    }

    for key_input in key_inputs:
        options: list[str] = []
        for data_input in data_inputs:
            pair_support = frozenset((key_input, data_input))
            matching_signals = [
                candidate_signal
                for candidate_signal in cone_signals
                if supports[candidate_signal] == pair_support
            ]
            if not matching_signals:
                continue
            options.append(data_input)
            comparator_signals[(key_input, data_input)] = max(
                matching_signals,
                key=lambda candidate_signal: topological_index.get(
                    candidate_signal,
                    -1,
                ),
            )
        if not options:
            return None
        pairing_options[key_input] = tuple(options)

    for pairing in _perfect_matchings(key_inputs, pairing_options):
        pairs = tuple(
            (
                key_input,
                data_input,
                comparator_signals[(key_input, data_input)],
            )
            for key_input, data_input in pairing
        )
        active_value = _sample_restore_relation(circuit, signal, pairs)
        if active_value is None:
            continue
        if _prove_restore_relation(
            circuit,
            signal,
            pairs,
            active_value=active_value,
            solver_timeout_seconds=solver_timeout_seconds,
        ):
            return _RestoreSignature(
                signal=signal,
                active_value=active_value,
                pairs=pairs,
                observable_outputs=observable_outputs,
            )
    return None


def _perfect_matchings(
    key_inputs: tuple[str, ...],
    options: dict[str, tuple[str, ...]],
    *,
    limit: int = 64,
) -> Iterable[tuple[tuple[str, str], ...]]:
    ordered_keys = tuple(sorted(key_inputs, key=lambda key: len(options[key])))
    found = 0

    def visit(
        index: int,
        used_data: set[str],
        pairs: list[tuple[str, str]],
    ) -> Iterable[tuple[tuple[str, str], ...]]:
        nonlocal found
        if found >= limit:
            return
        if index == len(ordered_keys):
            found += 1
            yield tuple(pairs)
            return
        key_input = ordered_keys[index]
        for data_input in options[key_input]:
            if data_input in used_data:
                continue
            used_data.add(data_input)
            pairs.append((key_input, data_input))
            yield from visit(index + 1, used_data, pairs)
            pairs.pop()
            used_data.remove(data_input)

    yield from visit(0, set(), [])


def _sample_restore_relation(
    circuit: Circuit,
    signal: str,
    pairs: tuple[tuple[str, str, str], ...],
) -> int | None:
    support = tuple(
        primary_input
        for primary_input in circuit.inputs
        if primary_input
        in {
            item
            for key_input, data_input, _ in pairs
            for item in (key_input, data_input)
        }
    )
    cone = _cone_circuit(circuit, signal, support=support)
    patterns = (
        tuple(0 for _ in pairs),
        tuple(1 for _ in pairs),
        tuple(index % 2 for index in range(len(pairs))),
    )
    active_value: int | None = None
    for pattern in patterns:
        matched = {}
        for bit, (key_input, data_input, _) in zip(pattern, pairs):
            matched[key_input] = bit
            matched[data_input] = bit
        value = cone.evaluate(matched)[signal]
        if active_value is None:
            active_value = value
        elif value != active_value:
            return None
        for key_input, _, _ in pairs:
            mismatched = dict(matched)
            mismatched[key_input] ^= 1
            if cone.evaluate(mismatched)[signal] == active_value:
                return None
    return active_value


def _point_function_signature(
    circuit: Circuit,
    signal: str,
    *,
    data_inputs: tuple[str, ...],
    polarities: dict[str, frozenset[int]],
    solver_timeout_seconds: float,
) -> _PointSignature | None:
    syntactically_unate = set(polarities) == set(data_inputs) and all(
        len(polarities[data_input]) == 1 for data_input in data_inputs
    )
    signs = (
        {
            data_input: next(iter(polarities[data_input]))
            for data_input in data_inputs
        }
        if syntactically_unate
        else None
    )

    for active_value in (1, 0):
        if signs is None:
            bits = _find_active_assignment(
                circuit,
                signal,
                data_inputs=data_inputs,
                active_value=active_value,
                solver_timeout_seconds=solver_timeout_seconds,
            )
            if bits is None:
                continue
        else:
            bits = tuple(
                (
                    data_input,
                    int((signs[data_input] == 1) == (active_value == 1)),
                )
                for data_input in data_inputs
            )
        if _prove_point_function(
            circuit,
            signal,
            bits,
            active_value=active_value,
            solver_timeout_seconds=solver_timeout_seconds,
        ):
            return _PointSignature(
                signal=signal,
                active_value=active_value,
                bits=bits,
                unateness=tuple(
                    (
                        data_input,
                        "positive"
                        if bit == active_value
                        else "negative",
                    )
                    for data_input, bit in bits
                ),
            )
    return None


def _find_active_assignment(
    circuit: Circuit,
    signal: str,
    *,
    data_inputs: tuple[str, ...],
    active_value: int,
    solver_timeout_seconds: float,
) -> tuple[tuple[str, int], ...] | None:
    cone = _cone_circuit(circuit, signal, support=data_inputs)
    cnf, variables, actual = _encode_cone(cone, signal)
    cnf.add_clause(actual if active_value else -actual)
    result = solve_cnf(cnf, timeout_seconds=solver_timeout_seconds)
    if not result.satisfiable:
        return None
    return tuple(
        (
            data_input,
            int(result.model.get(variables[data_input], False)),
        )
        for data_input in data_inputs
    )


def _prove_restore_relation(
    circuit: Circuit,
    signal: str,
    pairs: tuple[tuple[str, str, str], ...],
    *,
    active_value: int,
    solver_timeout_seconds: float,
) -> bool:
    support = tuple(
        primary_input
        for primary_input in circuit.inputs
        if any(
            primary_input in {key_input, data_input}
            for key_input, data_input, _ in pairs
        )
    )
    cone = _cone_circuit(circuit, signal, support=support)
    cnf, variables, actual = _encode_cone(cone, signal)
    comparisons: list[int] = []
    for index, (key_input, data_input, _) in enumerate(pairs):
        comparison = cnf.new_variable(f"assessment:restore-comparison:{index}")
        encode_gate(
            cnf,
            Gate(f"restore_comparison_{index}", "XNOR", ("a", "b"), "y"),
            inputs=(variables[key_input], variables[data_input]),
            output=comparison,
        )
        comparisons.append(comparison)
    expected = _encode_and(cnf, comparisons, name="assessment:restore-match")
    if active_value == 0:
        expected = _encode_not(cnf, expected, name="assessment:restore-invert")
    return _prove_equal(
        cnf,
        actual,
        expected,
        timeout_seconds=solver_timeout_seconds,
    )


def _prove_point_function(
    circuit: Circuit,
    signal: str,
    bits: tuple[tuple[str, int], ...],
    *,
    active_value: int,
    solver_timeout_seconds: float,
) -> bool:
    support = tuple(data_input for data_input, _ in bits)
    cone = _cone_circuit(circuit, signal, support=support)
    cnf, variables, actual = _encode_cone(cone, signal)
    literals: list[int] = []
    for index, (data_input, bit) in enumerate(bits):
        variable = variables[data_input]
        if bit == 0:
            variable = _encode_not(
                cnf,
                variable,
                name=f"assessment:strip-literal:{index}",
            )
        literals.append(variable)
    expected = _encode_and(cnf, literals, name="assessment:strip-match")
    if active_value == 0:
        expected = _encode_not(cnf, expected, name="assessment:strip-invert")
    return _prove_equal(
        cnf,
        actual,
        expected,
        timeout_seconds=solver_timeout_seconds,
    )


def _encode_cone(
    cone: Circuit,
    output_signal: str,
) -> tuple[CNF, dict[str, int], int]:
    cnf = CNF()
    variables = {
        primary_input: cnf.new_variable(
            f"assessment:input:{primary_input}"
        )
        for primary_input in cone.inputs
    }
    encoding = encode_circuit(
        cnf,
        cone,
        namespace="assessment:cone",
        input_variables=variables,
    )
    return cnf, variables, encoding.output_variables[output_signal]


def _encode_and(cnf: CNF, inputs: list[int], *, name: str) -> int:
    if len(inputs) == 1:
        return inputs[0]
    output = cnf.new_variable(name)
    encode_gate(
        cnf,
        Gate("assessment_and", "AND", tuple("x" for _ in inputs), "y"),
        inputs=tuple(inputs),
        output=output,
    )
    return output


def _encode_not(cnf: CNF, value: int, *, name: str) -> int:
    output = cnf.new_variable(name)
    encode_gate(
        cnf,
        Gate("assessment_not", "NOT", ("x",), "y"),
        inputs=(value,),
        output=output,
    )
    return output


def _prove_equal(
    cnf: CNF,
    actual: int,
    expected: int,
    *,
    timeout_seconds: float,
) -> bool:
    difference = cnf.new_variable("assessment:difference")
    encode_gate(
        cnf,
        Gate("assessment_difference", "XOR", ("a", "b"), "y"),
        inputs=(actual, expected),
        output=difference,
    )
    cnf.add_clause(difference)
    return not solve_cnf(cnf, timeout_seconds=timeout_seconds).satisfiable


def _cone_circuit(
    circuit: Circuit,
    signal: str,
    *,
    support: tuple[str, ...],
) -> Circuit:
    needed = {signal}
    retained_reversed: list[Gate] = []
    for gate in reversed(circuit.topological_gates()):
        if gate.output not in needed:
            continue
        retained_reversed.append(gate)
        needed.update(gate.inputs)
    cone = Circuit(
        name="sfll_analysis_cone",
        inputs=support,
        outputs=(signal,),
        gates=tuple(reversed(retained_reversed)),
    )
    cone.validate()
    return cone


def _fanin_signals(circuit: Circuit, signal: str) -> frozenset[str]:
    needed = {signal}
    for gate in reversed(circuit.topological_gates()):
        if gate.output in needed:
            needed.update(gate.inputs)
    return frozenset(needed)


def _prefer_active_high_points(
    points: list[_PointSignature],
) -> tuple[_PointSignature, ...]:
    grouped: dict[tuple[tuple[str, int], ...], list[_PointSignature]] = defaultdict(
        list
    )
    for point in points:
        grouped[point.bits].append(point)
    return tuple(
        next(
            (
                point
                for point in candidates
                if point.active_value == 1
            ),
            candidates[0],
        )
        for candidates in grouped.values()
    )


def _deduplicate_assessments(
    assessments: list[SfllHd0Assessment],
) -> tuple[SfllHd0Assessment, ...]:
    unique: dict[
        tuple[str, tuple[tuple[str, str, int], ...]],
        SfllHd0Assessment,
    ] = {}
    for assessment in assessments:
        identity = (
            assessment.protected_output,
            tuple(
                sorted(
                    (
                        mapping.key_input,
                        mapping.protected_input,
                        mapping.protected_bit,
                    )
                    for mapping in assessment.mappings
                )
            ),
        )
        existing = unique.get(identity)
        if existing is None or (
            assessment.strip_active_value > existing.strip_active_value
        ):
            unique[identity] = assessment
    return tuple(unique.values())
