from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import comb
from typing import Iterable

from locklab.circuit import Circuit, Gate
from locklab.cnf import CNF, encode_circuit, encode_gate
from locklab.sat_solver import solve_cnf
from locklab.validation import ValidationResult, prove_key_equivalence


@dataclass(frozen=True)
class SfllHdMapping:
    """One comparator found by FALL comparator and support-set analysis."""

    key_input: str
    protected_input: str
    comparator_signal: str


@dataclass(frozen=True)
class SfllHdCandidate:
    """A FALL-recovered SFLL-HDh cube-stripping candidate.

    ``recovery_method`` is either ``distance2h`` or ``sliding-window``. Both
    methods recover a candidate cube using only the locked netlist. The final
    strip-function equivalence proof rejects any candidate not equal to
    ``HD(inputs, key) == h``.
    """

    protected_output: str
    protected_source: str | None
    stripped_output: str | None
    strip_match_signal: str
    restore_match_signal: str
    match_type: str
    hamming_distance: int
    recovery_method: str
    mappings: tuple[SfllHdMapping, ...]
    inferred_key: tuple[int, ...]
    solver_calls: int

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
    def inferred_key_string(self) -> str:
        return "".join(str(bit) for bit in self.inferred_key)

    @property
    def protected_cube_count(self) -> int:
        return comb(self.key_size, self.hamming_distance)


@dataclass(frozen=True)
class SfllHdConfirmation:
    """Whole-circuit oracle confirmation for one FALL-recovered key."""

    candidate: SfllHdCandidate
    validation: ValidationResult


@dataclass(frozen=True)
class _Comparator:
    signal: str
    inputs: tuple[str, str]


@dataclass(frozen=True)
class _Recovery:
    method: str
    key: tuple[int, ...]
    solver_calls: int


@dataclass(frozen=True)
class _FunctionalRestore:
    signal: str
    pairs: tuple[tuple[str, str, str], ...]
    observable_outputs: frozenset[str]

    @property
    def key_size(self) -> int:
        return len(self.pairs)


def find_sfll_hd_candidates(
    circuit: Circuit,
    *,
    hamming_distance: int,
    max_key_size: int = 32,
    solver_timeout_seconds: float = 30.0,
) -> tuple[SfllHdCandidate, ...]:
    """Implement FALL's oracle-less functional analysis for explicit SFLL-HDh.

    This implements the ``Distance2H`` and ``SlidingWindow`` procedures from
    Sirone and Subramanyan, *Functional Analysis Attacks on Logic Locking*
    (DATE 2019). As in that paper's threat model, the attack parameter ``h`` is
    known to the attacker. It does not use metadata, internal signal names, or
    an unlocked oracle.

    The candidate search handles LockLab's explicit strip-and-restore topology.
    The functional recovery itself is SAT based: it finds two active strip
    assignments at distance ``2h``, derives key bits using Lemmas 2 and 3, then
    formally proves the proposed exact-distance strip and restore functions.
    """

    circuit.validate()
    if hamming_distance <= 0:
        raise ValueError("FALL SFLL-HDh analysis requires hamming distance above zero")
    if max_key_size <= 0:
        raise ValueError("maximum SFLL-HD key size must be greater than zero")
    if solver_timeout_seconds <= 0:
        raise ValueError("FALL SAT solver timeout must be greater than zero")

    drivers = {gate.output: gate for gate in circuit.gates}
    primary_inputs = set(circuit.inputs)
    supports = _fanin_supports(circuit)
    consumers = _consumers(circuit)
    results: list[SfllHdCandidate] = []

    # The two output XORs identify the LockLab reference injection boundary.
    # Comparator/support-set analysis and the FALL queries below are independent
    # of names and are the attack's actual key-recovery stage.
    for restore_injection in circuit.topological_gates():
        if (
            restore_injection.kind != "XOR"
            or len(restore_injection.inputs) != 2
            or restore_injection.output not in circuit.outputs
        ):
            continue

        for restore_index, restore_signal in enumerate(
            restore_injection.inputs
        ):
            comparators = _find_comparators(
                circuit,
                restore_signal,
                supports=supports,
                primary_inputs=primary_inputs,
            )
            if comparators is None or len(comparators) > max_key_size:
                continue

            stripped_output = restore_injection.inputs[1 - restore_index]
            strip_injection = drivers.get(stripped_output)
            if (
                strip_injection is None
                or strip_injection.kind != "XOR"
                or len(strip_injection.inputs) != 2
            ):
                continue

            for strip_index, strip_signal in enumerate(strip_injection.inputs):
                protected_source = strip_injection.inputs[1 - strip_index]
                mappings = _match_support_set(
                    comparators,
                    strip_support=supports[strip_signal],
                    protected_source_support=supports[protected_source],
                    consumers=consumers,
                )
                if mappings is None:
                    continue

                recovery = _recover_key_with_fall(
                    circuit,
                    strip_signal,
                    mappings,
                    hamming_distance=hamming_distance,
                    solver_timeout_seconds=solver_timeout_seconds,
                )
                if recovery is None:
                    continue

                if not _prove_restore_exact_distance(
                    circuit,
                    restore_signal,
                    pairs=tuple(
                        (mapping.protected_input, mapping.key_input, mapping.comparator_signal)
                        for mapping in mappings
                    ),
                    hamming_distance=hamming_distance,
                    solver_timeout_seconds=solver_timeout_seconds,
                ):
                    continue

                candidate = SfllHdCandidate(
                    protected_output=restore_injection.output,
                    protected_source=protected_source,
                    stripped_output=stripped_output,
                    strip_match_signal=strip_signal,
                    restore_match_signal=restore_signal,
                    match_type="exact topology",
                    hamming_distance=hamming_distance,
                    recovery_method=recovery.method,
                    mappings=mappings,
                    inferred_key=recovery.key,
                    solver_calls=recovery.solver_calls,
                )
                if candidate not in results:
                    results.append(candidate)

    if results:
        return tuple(results)
    return _find_functional_candidates(
        circuit,
        hamming_distance=hamming_distance,
        max_key_size=max_key_size,
        solver_timeout_seconds=solver_timeout_seconds,
    )


def confirm_sfll_hd_candidates(
    reference: Circuit,
    locked: Circuit,
    candidates: tuple[SfllHdCandidate, ...],
    *,
    solver_timeout_seconds: float = 30.0,
) -> tuple[SfllHdConfirmation, ...]:
    """Run FALL's oracle-backed key-confirmation stage on each candidate.

    A confirmation passes only when a formal whole-circuit miter proves that
    the locked circuit under the recovered key is equivalent to the supplied
    unlocked reference. A failing result includes a distinguishing input.
    """

    if solver_timeout_seconds <= 0:
        raise ValueError("FALL SAT solver timeout must be greater than zero")
    return tuple(
        SfllHdConfirmation(
            candidate=candidate,
            validation=prove_key_equivalence(
                reference,
                locked,
                key_inputs=candidate.key_inputs,
                key=candidate.inferred_key,
                solver_timeout_seconds=solver_timeout_seconds,
            ),
        )
        for candidate in candidates
    )


def _find_functional_candidates(
    circuit: Circuit,
    *,
    hamming_distance: int,
    max_key_size: int,
    solver_timeout_seconds: float,
) -> tuple[SfllHdCandidate, ...]:
    """Recover SFLL-HDh after synthesis when both functional cones survive.

    The construction first proves a pairwise-comparison restore cone is an
    exact Hamming-distance function, then seeks an observable data-only cone
    that chooses one input from every compared pair. FALL is run on that strip
    cone and its recovered key is formally checked again. This intentionally
    returns no candidate when synthesis absorbs the strip function into
    unrelated original logic.
    """

    supports = _fanin_supports(circuit)
    observable_outputs = _observable_outputs(circuit)
    results: list[SfllHdCandidate] = []

    for restore in _find_functional_restores(
        circuit,
        hamming_distance=hamming_distance,
        max_key_size=max_key_size,
        supports=supports,
        observable_outputs=observable_outputs,
        solver_timeout_seconds=solver_timeout_seconds,
    ):
        for gate in circuit.topological_gates():
            strip_signal = gate.output
            strip_support = supports[strip_signal]
            if len(strip_support) != restore.key_size or any(
                len(strip_support & frozenset((first, second))) != 1
                for first, second, _ in restore.pairs
            ):
                continue
            reachable_outputs = (
                observable_outputs[strip_signal] & restore.observable_outputs
            )
            if not reachable_outputs:
                continue
            mappings = tuple(
                SfllHdMapping(
                    key_input=(
                        second if first in strip_support else first
                    ),
                    protected_input=(
                        first if first in strip_support else second
                    ),
                    comparator_signal=comparator_signal,
                )
                for first, second, comparator_signal in restore.pairs
            )
            recovery = _recover_key_with_fall(
                circuit,
                strip_signal,
                mappings,
                hamming_distance=hamming_distance,
                solver_timeout_seconds=solver_timeout_seconds,
            )
            if recovery is None:
                continue
            for protected_output in sorted(reachable_outputs):
                candidate = SfllHdCandidate(
                    protected_output=protected_output,
                    protected_source=None,
                    stripped_output=None,
                    strip_match_signal=strip_signal,
                    restore_match_signal=restore.signal,
                    match_type="functional candidate",
                    hamming_distance=hamming_distance,
                    recovery_method=recovery.method,
                    mappings=mappings,
                    inferred_key=recovery.key,
                    solver_calls=recovery.solver_calls,
                )
                if candidate not in results:
                    results.append(candidate)

    return tuple(results)


def _find_functional_restores(
    circuit: Circuit,
    *,
    hamming_distance: int,
    max_key_size: int,
    supports: dict[str, frozenset[str]],
    observable_outputs: dict[str, frozenset[str]],
    solver_timeout_seconds: float,
) -> tuple[_FunctionalRestore, ...]:
    possible: list[_FunctionalRestore] = []
    ordered = circuit.topological_gates()
    topological_index = {
        gate.output: index for index, gate in enumerate(ordered)
    }
    for gate in ordered:
        signal = gate.output
        support = supports[signal]
        outputs = observable_outputs[signal]
        if not outputs or len(support) < 4 or len(support) % 2:
            continue
        inputs = tuple(
            primary_input
            for primary_input in circuit.inputs
            if primary_input in support
        )
        if (
            len(inputs) // 2 > max_key_size
            or hamming_distance >= len(inputs) // 2
        ):
            continue
        pairs = _match_functional_restore_support(
            circuit,
            signal,
            inputs=inputs,
            supports=supports,
            topological_index=topological_index,
            hamming_distance=hamming_distance,
            solver_timeout_seconds=solver_timeout_seconds,
        )
        if pairs is None:
            continue
        possible.append(
            _FunctionalRestore(
                signal=signal,
                pairs=pairs,
                observable_outputs=outputs,
            )
        )

    maximal = [
        candidate
        for candidate in possible
        if not any(
            candidate.key_size < other.key_size
            and candidate.observable_outputs & other.observable_outputs
            for other in possible
        )
    ]
    return tuple(maximal)


def _match_functional_restore_support(
    circuit: Circuit,
    signal: str,
    *,
    inputs: tuple[str, ...],
    supports: dict[str, frozenset[str]],
    topological_index: dict[str, int],
    hamming_distance: int,
    solver_timeout_seconds: float,
) -> tuple[tuple[str, str, str], ...] | None:
    """Find pairwise comparators, then prove an exact-distance restore cone."""

    cone_signals = _fanin_signals(circuit, signal)
    comparator_signals: dict[tuple[str, str], str] = {}
    for first_index, first in enumerate(inputs):
        for second in inputs[first_index + 1 :]:
            pair_support = frozenset((first, second))
            signals = [
                candidate_signal
                for candidate_signal in cone_signals
                if supports[candidate_signal] == pair_support
            ]
            if not signals:
                continue
            comparator_signals[(first, second)] = max(
                signals,
                key=lambda candidate_signal: topological_index.get(
                    candidate_signal,
                    -1,
                ),
            )
    for pairing in _pair_matchings(inputs, comparator_signals):
        if _prove_restore_exact_distance(
            circuit,
            signal,
            pairs=pairing,
            hamming_distance=hamming_distance,
            solver_timeout_seconds=solver_timeout_seconds,
        ):
            return pairing
    return None


def _pair_matchings(
    inputs: tuple[str, ...],
    comparator_signals: dict[tuple[str, str], str],
    *,
    limit: int = 64,
) -> Iterable[tuple[tuple[str, str, str], ...]]:
    found = 0

    def visit(
        remaining: tuple[str, ...],
        pairs: list[tuple[str, str, str]],
    ) -> Iterable[tuple[tuple[str, str, str], ...]]:
        nonlocal found
        if found >= limit:
            return
        if not remaining:
            found += 1
            yield tuple(pairs)
            return
        first = remaining[0]
        for index, second in enumerate(remaining[1:], start=1):
            comparison = comparator_signals.get((first, second))
            if comparison is None:
                continue
            pairs.append((first, second, comparison))
            yield from visit(
                remaining[1:index] + remaining[index + 1 :],
                pairs,
            )
            pairs.pop()

    yield from visit(inputs, [])


def _prove_restore_exact_distance(
    circuit: Circuit,
    signal: str,
    *,
    pairs: tuple[tuple[str, str, str], ...],
    hamming_distance: int,
    solver_timeout_seconds: float,
) -> bool:
    support = tuple(
        primary_input
        for primary_input in circuit.inputs
        if primary_input
        in {
            item
            for first, second, _ in pairs
            for item in (first, second)
        }
    )
    cone = _cone_circuit(circuit, signal, support=support)
    cnf, variables, actual = _encode_cone(cone, signal)
    mismatches = [
        _encode_binary(
            cnf,
            "XOR",
            variables[first],
            variables[second],
            name=f"fall:restore-mismatch:{index}",
        )
        for index, (first, second, _) in enumerate(pairs)
    ]
    expected = _encode_exact_weight(
        cnf,
        mismatches,
        hamming_distance=hamming_distance,
        prefix="fall:restore-distance",
    )
    return _prove_equal(
        cnf,
        actual,
        expected,
        solver_timeout_seconds=solver_timeout_seconds,
    )


def _find_comparators(
    circuit: Circuit,
    restore_signal: str,
    *,
    supports: dict[str, frozenset[str]],
    primary_inputs: set[str],
) -> tuple[_Comparator, ...] | None:
    """FALL comparator identification for LockLab's XOR mismatch comparators."""

    cone_signals = _fanin_signals(circuit, restore_signal)
    comparators = tuple(
        _Comparator(gate.output, (gate.inputs[0], gate.inputs[1]))
        for gate in circuit.topological_gates()
        if gate.output in cone_signals
        and gate.kind == "XOR"
        and len(gate.inputs) == 2
        and set(gate.inputs) <= primary_inputs
        and gate.inputs[0] != gate.inputs[1]
    )
    if not comparators:
        return None

    comparator_inputs = tuple(
        primary_input
        for comparator in comparators
        for primary_input in comparator.inputs
    )
    if len(comparator_inputs) != len(set(comparator_inputs)):
        return None
    if frozenset(comparator_inputs) != supports[restore_signal]:
        return None
    return comparators


def _match_support_set(
    comparators: tuple[_Comparator, ...],
    *,
    strip_support: frozenset[str],
    protected_source_support: frozenset[str],
    consumers: dict[str, frozenset[str]],
) -> tuple[SfllHdMapping, ...] | None:
    """Implement FALL support-set matching for a candidate strip node."""

    if len(strip_support) != len(comparators):
        return None

    mappings: list[SfllHdMapping] = []
    protected_inputs: set[str] = set()
    key_inputs: set[str] = set()
    for comparator in comparators:
        protected_sides = [
            signal for signal in comparator.inputs if signal in strip_support
        ]
        if len(protected_sides) != 1:
            return None
        protected_input = protected_sides[0]
        key_input = next(
            signal for signal in comparator.inputs if signal != protected_input
        )
        if key_input in protected_source_support:
            return None
        # In the reference construction a runtime key input feeds exactly one
        # comparator. This prevents arbitrary data inputs from being presented as
        # key inputs in the absence of external key-port annotations.
        if consumers.get(key_input, frozenset()) != frozenset(
            (comparator.signal,)
        ):
            return None
        protected_inputs.add(protected_input)
        key_inputs.add(key_input)
        mappings.append(
            SfllHdMapping(
                key_input=key_input,
                protected_input=protected_input,
                comparator_signal=comparator.signal,
            )
        )

    if protected_inputs != set(strip_support):
        return None
    if len(key_inputs) != len(comparators):
        return None
    if protected_inputs & key_inputs:
        return None
    return tuple(mappings)


def _recover_key_with_fall(
    circuit: Circuit,
    strip_signal: str,
    mappings: tuple[SfllHdMapping, ...],
    *,
    hamming_distance: int,
    solver_timeout_seconds: float,
) -> _Recovery | None:
    protected_inputs = tuple(mapping.protected_input for mapping in mappings)
    cone = _cone_circuit(circuit, strip_signal, support=protected_inputs)
    key_size = len(protected_inputs)
    if hamming_distance >= key_size:
        return None

    # Distance2H has the tighter applicability condition. Prefer it when valid
    # because its second SAT query recovers all remaining key bits at once.
    recovery = _distance2h(
        cone,
        strip_signal,
        hamming_distance=hamming_distance,
        solver_timeout_seconds=solver_timeout_seconds,
    )
    if recovery is None:
        recovery = _sliding_window(
            cone,
            strip_signal,
            hamming_distance=hamming_distance,
            solver_timeout_seconds=solver_timeout_seconds,
        )
    if recovery is None:
        return None

    if not _prove_strip_exact_distance(
        cone,
        strip_signal,
        key=recovery.key,
        hamming_distance=hamming_distance,
        solver_timeout_seconds=solver_timeout_seconds,
    ):
        return None
    return recovery


def _distance2h(
    cone: Circuit,
    output_signal: str,
    *,
    hamming_distance: int,
    solver_timeout_seconds: float,
) -> _Recovery | None:
    """FALL Algorithm 3 (Distance2H), applicable when ``4h <= m``."""

    key_size = len(cone.inputs)
    if 4 * hamming_distance > key_size:
        return None

    query = _build_active_pair_query(cone, output_signal, hamming_distance)
    result = solve_cnf(query.cnf, timeout_seconds=solver_timeout_seconds)
    solver_calls = 1
    if not result.satisfiable:
        return None
    first, second = _pair_model(query, result.model)
    key: dict[str, int] = {
        name: first[name]
        for name in cone.inputs
        if first[name] == second[name]
    }

    # Algorithm 3 forces the bits that differed in the first pair to be equal
    # and obtains the remaining key bits from a second active pair.
    for name in cone.inputs:
        if first[name] != second[name]:
            _add_equal(
                query.cnf,
                query.first_variables[name],
                query.second_variables[name],
            )
    second_result = solve_cnf(
        query.cnf,
        timeout_seconds=solver_timeout_seconds,
    )
    solver_calls += 1
    if not second_result.satisfiable:
        return None
    first_again, second_again = _pair_model(query, second_result.model)
    for name in cone.inputs:
        if first_again[name] == second_again[name]:
            existing = key.get(name)
            if existing is not None and existing != first_again[name]:
                return None
            key[name] = first_again[name]
    if len(key) != key_size:
        return None
    return _Recovery(
        method="distance2h",
        key=tuple(key[name] for name in cone.inputs),
        solver_calls=solver_calls,
    )


def _sliding_window(
    cone: Circuit,
    output_signal: str,
    *,
    hamming_distance: int,
    solver_timeout_seconds: float,
) -> _Recovery | None:
    """FALL Algorithm 2 (SlidingWindow) for ``h < floor(m / 2)``."""

    key_size = len(cone.inputs)
    if hamming_distance >= key_size // 2:
        return None

    seed_query = _build_active_pair_query(cone, output_signal, hamming_distance)
    seed_result = solve_cnf(
        seed_query.cnf,
        timeout_seconds=solver_timeout_seconds,
    )
    solver_calls = 1
    if not seed_result.satisfiable:
        return None
    first, second = _pair_model(seed_query, seed_result.model)
    key: dict[str, int] = {}

    for name in cone.inputs:
        if first[name] == second[name]:
            key[name] = first[name]
            continue

        # Lemma 3: with the bit forced equal in a second active pair, exactly
        # one of its two first-pair values remains satisfiable, and that value
        # is the corresponding protected-key bit.
        satisfiable_values: list[int] = []
        for value in (first[name], second[name]):
            query = _build_active_pair_query(
                cone,
                output_signal,
                hamming_distance,
            )
            _add_equal(
                query.cnf,
                query.first_variables[name],
                query.second_variables[name],
            )
            variable = query.first_variables[name]
            query.cnf.add_clause(variable if value else -variable)
            trial = solve_cnf(
                query.cnf,
                timeout_seconds=solver_timeout_seconds,
            )
            solver_calls += 1
            if trial.satisfiable:
                satisfiable_values.append(value)
        if len(satisfiable_values) != 1:
            return None
        key[name] = satisfiable_values[0]

    return _Recovery(
        method="sliding-window",
        key=tuple(key[name] for name in cone.inputs),
        solver_calls=solver_calls,
    )


@dataclass(frozen=True)
class _ActivePairQuery:
    cnf: CNF
    first_variables: dict[str, int]
    second_variables: dict[str, int]


def _build_active_pair_query(
    cone: Circuit,
    output_signal: str,
    hamming_distance: int,
) -> _ActivePairQuery:
    cnf = CNF()
    first_variables = {
        name: cnf.new_variable(f"fall:first:{name}") for name in cone.inputs
    }
    second_variables = {
        name: cnf.new_variable(f"fall:second:{name}") for name in cone.inputs
    }
    first = encode_circuit(
        cnf,
        cone,
        namespace="fall:first-cone",
        input_variables=first_variables,
    )
    second = encode_circuit(
        cnf,
        cone,
        namespace="fall:second-cone",
        input_variables=second_variables,
    )
    cnf.add_clause(first.output_variables[output_signal])
    cnf.add_clause(second.output_variables[output_signal])
    differences = [
        _encode_binary(
            cnf,
            "XOR",
            first_variables[name],
            second_variables[name],
            name=f"fall:pair-difference:{index}",
        )
        for index, name in enumerate(cone.inputs)
    ]
    exact_distance = _encode_exact_weight(
        cnf,
        differences,
        hamming_distance=2 * hamming_distance,
        prefix="fall:pair-distance",
    )
    cnf.add_clause(exact_distance)
    return _ActivePairQuery(cnf, first_variables, second_variables)


def _pair_model(
    query: _ActivePairQuery,
    model: dict[int, bool],
) -> tuple[dict[str, int], dict[str, int]]:
    first = {
        name: int(model.get(variable, False))
        for name, variable in query.first_variables.items()
    }
    second = {
        name: int(model.get(variable, False))
        for name, variable in query.second_variables.items()
    }
    return first, second


def _prove_strip_exact_distance(
    cone: Circuit,
    output_signal: str,
    *,
    key: tuple[int, ...],
    hamming_distance: int,
    solver_timeout_seconds: float,
) -> bool:
    cnf, variables, actual = _encode_cone(cone, output_signal)
    mismatches: list[int] = []
    for index, (name, bit) in enumerate(zip(cone.inputs, key)):
        value = variables[name]
        if bit:
            value = _encode_not(
                cnf,
                value,
                name=f"fall:strip-mismatch:{index}",
            )
        mismatches.append(value)
    expected = _encode_exact_weight(
        cnf,
        mismatches,
        hamming_distance=hamming_distance,
        prefix="fall:strip-distance",
    )
    difference = _encode_binary(
        cnf,
        "XOR",
        actual,
        expected,
        name="fall:strip-difference",
    )
    cnf.add_clause(difference)
    return not solve_cnf(cnf, timeout_seconds=solver_timeout_seconds).satisfiable


def _encode_exact_weight(
    cnf: CNF,
    inputs: list[int],
    *,
    hamming_distance: int,
    prefix: str,
) -> int:
    if hamming_distance > len(inputs):
        raise ValueError("Hamming distance exceeds the number of inputs")
    states = [cnf.true_variable]
    for position, value in enumerate(inputs):
        not_value = _encode_not(
            cnf,
            value,
            name=f"{prefix}:not:{position}",
        )
        next_states: list[int] = []
        for weight in range(min(position + 1, hamming_distance) + 1):
            terms: list[int] = []
            if weight < len(states):
                terms.append(
                    _encode_binary(
                        cnf,
                        "AND",
                        states[weight],
                        not_value,
                        name=f"{prefix}:same:{position}:{weight}",
                    )
                )
            if weight > 0 and weight - 1 < len(states):
                terms.append(
                    _encode_binary(
                        cnf,
                        "AND",
                        states[weight - 1],
                        value,
                        name=f"{prefix}:increment:{position}:{weight}",
                    )
                )
            next_states.append(
                terms[0]
                if len(terms) == 1
                else _encode_binary(
                    cnf,
                    "OR",
                    terms[0],
                    terms[1],
                    name=f"{prefix}:state:{position}:{weight}",
                )
            )
        states = next_states
    return states[hamming_distance]


def _encode_cone(
    cone: Circuit,
    output_signal: str,
) -> tuple[CNF, dict[str, int], int]:
    cnf = CNF()
    variables = {
        name: cnf.new_variable(f"fall:input:{name}") for name in cone.inputs
    }
    encoding = encode_circuit(
        cnf,
        cone,
        namespace="fall:cone",
        input_variables=variables,
    )
    return cnf, variables, encoding.output_variables[output_signal]


def _encode_binary(
    cnf: CNF,
    kind: str,
    first: int,
    second: int,
    *,
    name: str,
) -> int:
    output = cnf.new_variable(name)
    encode_gate(
        cnf,
        Gate("fall_binary", kind, ("a", "b"), "y"),
        inputs=(first, second),
        output=output,
    )
    return output


def _encode_not(cnf: CNF, value: int, *, name: str) -> int:
    output = cnf.new_variable(name)
    encode_gate(
        cnf,
        Gate("fall_not", "NOT", ("a",), "y"),
        inputs=(value,),
        output=output,
    )
    return output


def _add_equal(cnf: CNF, first: int, second: int) -> None:
    cnf.add_clause(-first, second)
    cnf.add_clause(first, -second)


def _prove_equal(
    cnf: CNF,
    actual: int,
    expected: int,
    *,
    solver_timeout_seconds: float,
) -> bool:
    difference = _encode_binary(
        cnf,
        "XOR",
        actual,
        expected,
        name="fall:function-difference",
    )
    cnf.add_clause(difference)
    return not solve_cnf(
        cnf,
        timeout_seconds=solver_timeout_seconds,
    ).satisfiable


def _fanin_supports(circuit: Circuit) -> dict[str, frozenset[str]]:
    supports = {"0": frozenset(), "1": frozenset()}
    supports.update(
        {name: frozenset((name,)) for name in circuit.inputs}
    )
    for gate in circuit.topological_gates():
        supports[gate.output] = frozenset().union(
            *(supports[signal] for signal in gate.inputs)
        )
    return supports


def _consumers(circuit: Circuit) -> dict[str, frozenset[str]]:
    mutable: dict[str, set[str]] = defaultdict(set)
    for gate in circuit.gates:
        for signal in gate.inputs:
            mutable[signal].add(gate.output)
    return {signal: frozenset(outputs) for signal, outputs in mutable.items()}


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
        name="fall_sfll_hd_cone",
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
