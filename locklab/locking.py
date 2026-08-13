from __future__ import annotations

import random
from dataclasses import dataclass
from math import comb

from locklab.circuit import Circuit, CircuitError, Gate


@dataclass(frozen=True)
class LockInsertion:
    key_index: int
    key_input: str
    correct_bit: int
    gate_kind: str
    protected_signal: str
    source_signal: str
    decoy_signal: str | None = None


@dataclass(frozen=True)
class LockResult:
    circuit: Circuit
    key: tuple[int, ...]
    seed: int
    insertions: tuple[LockInsertion, ...]
    hamming_distance: int | None = None
    protected_cube_count: int | None = None
    strip_match_signal: str | None = None
    restore_match_signal: str | None = None
    sarlock_input_match_signal: str | None = None
    sarlock_key_mask_signal: str | None = None
    sarlock_flip_signal: str | None = None
    wrong_key_error_vectors: int | None = None

    @property
    def key_string(self) -> str:
        return "".join(str(bit) for bit in self.key)


def lock_rll(circuit: Circuit, *, key_size: int, seed: int) -> LockResult:
    """Insert seeded XOR/XNOR random-logic-locking gates."""

    circuit.validate()
    if key_size <= 0:
        raise CircuitError("key size must be greater than zero")

    candidates = list(circuit.observable_gate_outputs())
    if key_size > len(candidates):
        raise CircuitError(
            f"key size {key_size} exceeds {len(candidates)} observable gate outputs"
        )

    random_source = random.Random(seed)
    selected_signals = random_source.sample(candidates, key_size)
    key = tuple(random_source.randint(0, 1) for _ in range(key_size))

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs: list[str] = []
    insertions: list[LockInsertion] = []

    for key_index, (signal, correct_bit) in enumerate(zip(selected_signals, key)):
        key_input = _unique_name(f"keyinput_{key_index}", used_signals)
        source_signal = _unique_name(f"{signal}_locksrc_{key_index}", used_signals)
        gate_kind = "XOR" if correct_bit == 0 else "XNOR"
        key_inputs.append(key_input)
        insertions.append(
            LockInsertion(
                key_index=key_index,
                key_input=key_input,
                correct_bit=correct_bit,
                gate_kind=gate_kind,
                protected_signal=signal,
                source_signal=source_signal,
            )
        )

    insertion_by_signal = {
        insertion.protected_signal: insertion for insertion in insertions
    }
    locked_gates: list[Gate] = []
    for gate in circuit.gates:
        insertion = insertion_by_signal.get(gate.output)
        locked_gates.append(
            Gate(
                name=gate.name,
                kind=gate.kind,
                inputs=gate.inputs,
                output=insertion.source_signal if insertion else gate.output,
            )
        )

    for insertion in insertions:
        gate_name = _unique_name(
            f"lock_gate_{insertion.key_index}",
            used_gate_names,
        )
        locked_gates.append(
            Gate(
                name=gate_name,
                kind=insertion.gate_kind,
                inputs=(insertion.source_signal, insertion.key_input),
                output=insertion.protected_signal,
            )
        )

    locked = Circuit(
        name=f"{circuit.name}_rll",
        inputs=(*circuit.inputs, *key_inputs),
        outputs=circuit.outputs,
        gates=tuple(locked_gates),
    )
    locked.validate()
    return LockResult(
        circuit=locked,
        key=key,
        seed=seed,
        insertions=tuple(insertions),
    )


def lock_mux(circuit: Circuit, *, key_size: int, seed: int) -> LockResult:
    """Insert seeded MUX locks using topologically earlier decoy signals."""

    circuit.validate()
    if key_size <= 0:
        raise CircuitError("key size must be greater than zero")

    topological_gates = circuit.topological_gates()
    observable = set(circuit.observable_gate_outputs())
    earlier_signals = list(circuit.inputs)
    decoys_by_signal: dict[str, tuple[str, ...]] = {}
    for gate in topological_gates:
        if gate.output in observable and earlier_signals:
            decoys_by_signal[gate.output] = tuple(earlier_signals)
        earlier_signals.append(gate.output)

    candidates = list(decoys_by_signal)
    if key_size > len(candidates):
        raise CircuitError(
            f"key size {key_size} exceeds {len(candidates)} cycle-safe "
            "MUX insertion points"
        )

    random_source = random.Random(seed)
    selected_signals = random_source.sample(candidates, key_size)
    key = tuple(random_source.randint(0, 1) for _ in range(key_size))

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs: list[str] = []
    insertions: list[LockInsertion] = []

    for key_index, (signal, correct_bit) in enumerate(zip(selected_signals, key)):
        key_input = _unique_name(f"keyinput_{key_index}", used_signals)
        source_signal = _unique_name(f"{signal}_locksrc_{key_index}", used_signals)
        decoy_signal = random_source.choice(decoys_by_signal[signal])
        key_inputs.append(key_input)
        insertions.append(
            LockInsertion(
                key_index=key_index,
                key_input=key_input,
                correct_bit=correct_bit,
                gate_kind="MUX",
                protected_signal=signal,
                source_signal=source_signal,
                decoy_signal=decoy_signal,
            )
        )

    insertion_by_signal = {
        insertion.protected_signal: insertion for insertion in insertions
    }
    locked_gates: list[Gate] = []
    for gate in circuit.gates:
        insertion = insertion_by_signal.get(gate.output)
        locked_gates.append(
            Gate(
                name=gate.name,
                kind=gate.kind,
                inputs=gate.inputs,
                output=insertion.source_signal if insertion else gate.output,
            )
        )

    for insertion in insertions:
        gate_name = _unique_name(
            f"lock_gate_{insertion.key_index}",
            used_gate_names,
        )
        if insertion.decoy_signal is None:
            raise CircuitError("MUX insertion is missing its decoy signal")
        data_inputs = (
            (insertion.source_signal, insertion.decoy_signal)
            if insertion.correct_bit == 0
            else (insertion.decoy_signal, insertion.source_signal)
        )
        locked_gates.append(
            Gate(
                name=gate_name,
                kind="MUX",
                inputs=(*data_inputs, insertion.key_input),
                output=insertion.protected_signal,
            )
        )

    locked = Circuit(
        name=f"{circuit.name}_mux",
        inputs=(*circuit.inputs, *key_inputs),
        outputs=circuit.outputs,
        gates=tuple(locked_gates),
    )
    locked.validate()
    return LockResult(
        circuit=locked,
        key=key,
        seed=seed,
        insertions=tuple(insertions),
    )


def lock_antisat(circuit: Circuit, *, key_size: int, seed: int) -> LockResult:
    """Insert a seeded type-0 Anti-SAT point-function block."""

    return _add_antisat_block(
        circuit,
        key_size=key_size,
        seed=seed,
        data_inputs=circuit.inputs,
        key_index_offset=0,
    )


def lock_sarlock(circuit: Circuit, *, key_size: int, seed: int) -> LockResult:
    """Insert a seeded SARLock point-function block.

    The injected flip is ``(selected inputs == runtime key) AND
    (runtime key != planted key)``.  Consequently the planted key never
    changes the circuit, while every wrong key flips exactly one selected-input
    cube at a seeded gate-driven primary output.
    """

    circuit.validate()
    if key_size <= 0:
        raise CircuitError("SARLock key size must be greater than zero")
    if key_size > len(circuit.inputs):
        raise CircuitError(
            f"SARLock key size {key_size} exceeds "
            f"{len(circuit.inputs)} primary inputs"
        )

    driven_outputs = tuple(
        output
        for output in circuit.outputs
        if any(gate.output == output for gate in circuit.gates)
    )
    if not driven_outputs:
        raise CircuitError("SARLock requires a gate-driven primary output")

    random_source = random.Random(seed)
    selected_inputs = tuple(random_source.sample(circuit.inputs, key_size))
    protected_output = random_source.choice(driven_outputs)
    key = tuple(random_source.randint(0, 1) for _ in range(key_size))

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs = tuple(
        _unique_name(f"keyinput_{index}", used_signals)
        for index in range(key_size)
    )
    protected_source = _unique_name(
        f"{protected_output}_locksrc_sarlock",
        used_signals,
    )
    locked_gates = [
        Gate(
            name=gate.name,
            kind=gate.kind,
            inputs=gate.inputs,
            output=(
                protected_source
                if gate.output == protected_output
                else gate.output
            ),
        )
        for gate in circuit.gates
    ]

    input_comparisons: list[str] = []
    key_mismatches: list[str] = []
    insertions: list[LockInsertion] = []
    for index, (data_input, correct_bit, key_input) in enumerate(
        zip(selected_inputs, key, key_inputs)
    ):
        input_comparison = _unique_name(
            f"sarlock_input_compare_{index}",
            used_signals,
        )
        key_mismatch = _unique_name(
            f"sarlock_key_mismatch_{index}",
            used_signals,
        )
        locked_gates.extend(
            (
                Gate(
                    name=_unique_name(
                        f"sarlock_input_compare_gate_{index}",
                        used_gate_names,
                    ),
                    kind="XNOR",
                    inputs=(data_input, key_input),
                    output=input_comparison,
                ),
                Gate(
                    name=_unique_name(
                        f"sarlock_key_mismatch_gate_{index}",
                        used_gate_names,
                    ),
                    kind="NOT" if correct_bit else "BUF",
                    inputs=(key_input,),
                    output=key_mismatch,
                ),
            )
        )
        input_comparisons.append(input_comparison)
        key_mismatches.append(key_mismatch)
        insertions.append(
            LockInsertion(
                key_index=index,
                key_input=key_input,
                correct_bit=correct_bit,
                gate_kind="XNOR",
                protected_signal=protected_output,
                source_signal=data_input,
            )
        )

    if key_size == 1:
        input_match = input_comparisons[0]
        key_mask = key_mismatches[0]
    else:
        input_match = _unique_name("sarlock_input_match", used_signals)
        key_mask = _unique_name("sarlock_key_mask", used_signals)
        locked_gates.extend(
            (
                Gate(
                    name=_unique_name(
                        "sarlock_input_match_gate",
                        used_gate_names,
                    ),
                    kind="AND",
                    inputs=tuple(input_comparisons),
                    output=input_match,
                ),
                Gate(
                    name=_unique_name(
                        "sarlock_key_mask_gate",
                        used_gate_names,
                    ),
                    kind="OR",
                    inputs=tuple(key_mismatches),
                    output=key_mask,
                ),
            )
        )

    flip_signal = _unique_name("sarlock_flip", used_signals)
    locked_gates.extend(
        (
            Gate(
                name=_unique_name("sarlock_flip_gate", used_gate_names),
                kind="AND",
                inputs=(input_match, key_mask),
                output=flip_signal,
            ),
            Gate(
                name=_unique_name("sarlock_output_gate", used_gate_names),
                kind="XOR",
                inputs=(protected_source, flip_signal),
                output=protected_output,
            ),
        )
    )

    locked = Circuit(
        name=f"{circuit.name}_sarlock",
        inputs=(*circuit.inputs, *key_inputs),
        outputs=circuit.outputs,
        gates=tuple(locked_gates),
    )
    locked.validate()
    return LockResult(
        circuit=locked,
        key=key,
        seed=seed,
        insertions=tuple(insertions),
        sarlock_input_match_signal=input_match,
        sarlock_key_mask_signal=key_mask,
        sarlock_flip_signal=flip_signal,
        wrong_key_error_vectors=1 << (len(circuit.inputs) - key_size),
    )


def lock_rll_antisat(circuit: Circuit, *, key_size: int, seed: int) -> LockResult:
    """Combine equal-sized RLL and Anti-SAT key components."""

    circuit.validate()
    if key_size < 8 or key_size % 4:
        raise CircuitError(
            "RLL+Anti-SAT key size must be divisible by 4 and at least 8"
        )

    component_size = key_size // 2
    rll_result = lock_rll(circuit, key_size=component_size, seed=seed)
    antisat_result = _add_antisat_block(
        rll_result.circuit,
        key_size=component_size,
        seed=seed + 1,
        data_inputs=circuit.inputs,
        key_index_offset=component_size,
    )
    return LockResult(
        circuit=antisat_result.circuit,
        key=(*rll_result.key, *antisat_result.key),
        seed=seed,
        insertions=(*rll_result.insertions, *antisat_result.insertions),
    )


def lock_sfll_hd0(circuit: Circuit, *, key_size: int, seed: int) -> LockResult:
    """Insert a seeded SFLL-HD0 strip-and-restore block."""

    circuit.validate()
    if key_size <= 0:
        raise CircuitError("SFLL-HD0 key size must be greater than zero")
    if key_size > len(circuit.inputs):
        raise CircuitError(
            f"SFLL-HD0 key size {key_size} exceeds "
            f"{len(circuit.inputs)} primary inputs"
        )

    driven_outputs = tuple(
        output
        for output in circuit.outputs
        if any(gate.output == output for gate in circuit.gates)
    )
    if not driven_outputs:
        raise CircuitError("SFLL-HD0 requires a gate-driven primary output")

    random_source = random.Random(seed)
    selected_inputs = tuple(random_source.sample(circuit.inputs, key_size))
    protected_output = random_source.choice(driven_outputs)
    key = tuple(random_source.randint(0, 1) for _ in range(key_size))

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs = tuple(
        _unique_name(f"keyinput_{index}", used_signals)
        for index in range(key_size)
    )
    protected_source = _unique_name(
        f"{protected_output}_locksrc_sfll_hd0",
        used_signals,
    )
    locked_gates = [
        Gate(
            name=gate.name,
            kind=gate.kind,
            inputs=gate.inputs,
            output=protected_source if gate.output == protected_output else gate.output,
        )
        for gate in circuit.gates
    ]

    strip_literals: list[str] = []
    restore_comparisons: list[str] = []
    insertions: list[LockInsertion] = []
    for index, (data_input, correct_bit, key_input) in enumerate(
        zip(selected_inputs, key, key_inputs)
    ):
        strip_literal = _unique_name(
            f"sfll_strip_literal_{index}",
            used_signals,
        )
        restore_comparison = _unique_name(
            f"sfll_restore_compare_{index}",
            used_signals,
        )
        locked_gates.extend(
            (
                Gate(
                    name=_unique_name(
                        f"sfll_strip_literal_gate_{index}",
                        used_gate_names,
                    ),
                    kind="BUF" if correct_bit else "NOT",
                    inputs=(data_input,),
                    output=strip_literal,
                ),
                Gate(
                    name=_unique_name(
                        f"sfll_restore_compare_gate_{index}",
                        used_gate_names,
                    ),
                    kind="XNOR",
                    inputs=(data_input, key_input),
                    output=restore_comparison,
                ),
            )
        )
        strip_literals.append(strip_literal)
        restore_comparisons.append(restore_comparison)
        insertions.append(
            LockInsertion(
                key_index=index,
                key_input=key_input,
                correct_bit=correct_bit,
                gate_kind="XNOR",
                protected_signal=protected_output,
                source_signal=data_input,
            )
        )

    if key_size == 1:
        strip_match = strip_literals[0]
        restore_match = restore_comparisons[0]
    else:
        strip_match = _unique_name("sfll_strip_match", used_signals)
        restore_match = _unique_name("sfll_restore_match", used_signals)
        locked_gates.extend(
            (
                Gate(
                    name=_unique_name("sfll_strip_match_gate", used_gate_names),
                    kind="AND",
                    inputs=tuple(strip_literals),
                    output=strip_match,
                ),
                Gate(
                    name=_unique_name(
                        "sfll_restore_match_gate",
                        used_gate_names,
                    ),
                    kind="AND",
                    inputs=tuple(restore_comparisons),
                    output=restore_match,
                ),
            )
        )

    stripped_output = _unique_name(
        f"{protected_output}_sfll_stripped",
        used_signals,
    )
    locked_gates.extend(
        (
            Gate(
                name=_unique_name("sfll_strip_output_gate", used_gate_names),
                kind="XOR",
                inputs=(protected_source, strip_match),
                output=stripped_output,
            ),
            Gate(
                name=_unique_name("sfll_restore_output_gate", used_gate_names),
                kind="XOR",
                inputs=(stripped_output, restore_match),
                output=protected_output,
            ),
        )
    )

    locked = Circuit(
        name=f"{circuit.name}_sfll_hd0",
        inputs=(*circuit.inputs, *key_inputs),
        outputs=circuit.outputs,
        gates=tuple(locked_gates),
    )
    locked.validate()
    return LockResult(
        circuit=locked,
        key=key,
        seed=seed,
        insertions=tuple(insertions),
        hamming_distance=0,
        protected_cube_count=1,
        strip_match_signal=strip_match,
        restore_match_signal=restore_match,
    )


def lock_sfll_hd(
    circuit: Circuit,
    *,
    key_size: int,
    hamming_distance: int,
    seed: int,
) -> LockResult:
    """Insert SFLL-HD with exact-distance strip and restore functions."""

    circuit.validate()
    if key_size <= 0:
        raise CircuitError("SFLL-HD key size must be greater than zero")
    if key_size > len(circuit.inputs):
        raise CircuitError(
            f"SFLL-HD key size {key_size} exceeds "
            f"{len(circuit.inputs)} primary inputs"
        )
    if hamming_distance < 0 or hamming_distance > key_size:
        raise CircuitError(
            "SFLL-HD Hamming distance must be between zero and the key size"
        )
    if hamming_distance == 0:
        return lock_sfll_hd0(circuit, key_size=key_size, seed=seed)

    driven_outputs = tuple(
        output
        for output in circuit.outputs
        if any(gate.output == output for gate in circuit.gates)
    )
    if not driven_outputs:
        raise CircuitError("SFLL-HD requires a gate-driven primary output")

    random_source = random.Random(seed)
    selected_inputs = tuple(random_source.sample(circuit.inputs, key_size))
    protected_output = random_source.choice(driven_outputs)
    key = tuple(random_source.randint(0, 1) for _ in range(key_size))

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs = tuple(
        _unique_name(f"keyinput_{index}", used_signals)
        for index in range(key_size)
    )
    protected_source = _unique_name(
        f"{protected_output}_locksrc_sfll_hd{hamming_distance}",
        used_signals,
    )
    locked_gates = [
        Gate(
            name=gate.name,
            kind=gate.kind,
            inputs=gate.inputs,
            output=(
                protected_source
                if gate.output == protected_output
                else gate.output
            ),
        )
        for gate in circuit.gates
    ]

    strip_mismatches: list[str] = []
    restore_mismatches: list[str] = []
    insertions: list[LockInsertion] = []
    for index, (data_input, correct_bit, key_input) in enumerate(
        zip(selected_inputs, key, key_inputs)
    ):
        strip_mismatch = _unique_name(
            f"sfll_hd_strip_mismatch_{index}",
            used_signals,
        )
        restore_mismatch = _unique_name(
            f"sfll_hd_restore_mismatch_{index}",
            used_signals,
        )
        locked_gates.extend(
            (
                Gate(
                    name=_unique_name(
                        f"sfll_hd_strip_mismatch_gate_{index}",
                        used_gate_names,
                    ),
                    kind="NOT" if correct_bit else "BUF",
                    inputs=(data_input,),
                    output=strip_mismatch,
                ),
                Gate(
                    name=_unique_name(
                        f"sfll_hd_restore_mismatch_gate_{index}",
                        used_gate_names,
                    ),
                    kind="XOR",
                    inputs=(data_input, key_input),
                    output=restore_mismatch,
                ),
            )
        )
        strip_mismatches.append(strip_mismatch)
        restore_mismatches.append(restore_mismatch)
        insertions.append(
            LockInsertion(
                key_index=index,
                key_input=key_input,
                correct_bit=correct_bit,
                gate_kind="XOR",
                protected_signal=protected_output,
                source_signal=data_input,
            )
        )

    strip_match = _add_exact_hamming_match(
        locked_gates,
        tuple(strip_mismatches),
        hamming_distance=hamming_distance,
        prefix="sfll_hd_strip",
        used_signals=used_signals,
        used_gate_names=used_gate_names,
    )
    restore_match = _add_exact_hamming_match(
        locked_gates,
        tuple(restore_mismatches),
        hamming_distance=hamming_distance,
        prefix="sfll_hd_restore",
        used_signals=used_signals,
        used_gate_names=used_gate_names,
    )
    stripped_output = _unique_name(
        f"{protected_output}_sfll_hd{hamming_distance}_stripped",
        used_signals,
    )
    locked_gates.extend(
        (
            Gate(
                name=_unique_name("sfll_hd_strip_output_gate", used_gate_names),
                kind="XOR",
                inputs=(protected_source, strip_match),
                output=stripped_output,
            ),
            Gate(
                name=_unique_name("sfll_hd_restore_output_gate", used_gate_names),
                kind="XOR",
                inputs=(stripped_output, restore_match),
                output=protected_output,
            ),
        )
    )

    locked = Circuit(
        name=f"{circuit.name}_sfll_hd{hamming_distance}",
        inputs=(*circuit.inputs, *key_inputs),
        outputs=circuit.outputs,
        gates=tuple(locked_gates),
    )
    locked.validate()
    return LockResult(
        circuit=locked,
        key=key,
        seed=seed,
        insertions=tuple(insertions),
        hamming_distance=hamming_distance,
        protected_cube_count=comb(key_size, hamming_distance),
        strip_match_signal=strip_match,
        restore_match_signal=restore_match,
    )


def _add_exact_hamming_match(
    gates: list[Gate],
    mismatch_signals: tuple[str, ...],
    *,
    hamming_distance: int,
    prefix: str,
    used_signals: set[str],
    used_gate_names: set[str],
) -> str:
    """Build a one-hot dynamic program whose output means weight == h."""

    states: tuple[str, ...] = ("1",)
    for position, mismatch in enumerate(mismatch_signals):
        inverted_mismatch = _unique_name(
            f"{prefix}_not_mismatch_{position}",
            used_signals,
        )
        gates.append(
            Gate(
                name=_unique_name(
                    f"{prefix}_not_mismatch_gate_{position}",
                    used_gate_names,
                ),
                kind="NOT",
                inputs=(mismatch,),
                output=inverted_mismatch,
            )
        )

        new_states: list[str] = []
        maximum_weight = min(position + 1, hamming_distance)
        for weight in range(maximum_weight + 1):
            terms: list[str] = []
            if weight < len(states):
                unchanged = _unique_name(
                    f"{prefix}_state_{position + 1}_{weight}_same",
                    used_signals,
                )
                gates.append(
                    Gate(
                        name=_unique_name(
                            f"{prefix}_state_{position + 1}_{weight}_same_gate",
                            used_gate_names,
                        ),
                        kind="AND",
                        inputs=(states[weight], inverted_mismatch),
                        output=unchanged,
                    )
                )
                terms.append(unchanged)
            if weight > 0 and weight - 1 < len(states):
                incremented = _unique_name(
                    f"{prefix}_state_{position + 1}_{weight}_incremented",
                    used_signals,
                )
                gates.append(
                    Gate(
                        name=_unique_name(
                            f"{prefix}_state_{position + 1}_{weight}_incremented_gate",
                            used_gate_names,
                        ),
                        kind="AND",
                        inputs=(states[weight - 1], mismatch),
                        output=incremented,
                    )
                )
                terms.append(incremented)

            state = _unique_name(
                f"{prefix}_state_{position + 1}_{weight}",
                used_signals,
            )
            gates.append(
                Gate(
                    name=_unique_name(
                        f"{prefix}_state_{position + 1}_{weight}_gate",
                        used_gate_names,
                    ),
                    kind="BUF" if len(terms) == 1 else "OR",
                    inputs=tuple(terms),
                    output=state,
                )
            )
            new_states.append(state)
        states = tuple(new_states)

    return states[hamming_distance]


def _add_antisat_block(
    circuit: Circuit,
    *,
    key_size: int,
    seed: int,
    data_inputs: tuple[str, ...],
    key_index_offset: int,
) -> LockResult:
    circuit.validate()
    if key_size < 4 or key_size % 2:
        raise CircuitError("Anti-SAT key size must be even and at least 4")
    if len(data_inputs) != len(set(data_inputs)):
        raise CircuitError("Anti-SAT data inputs must be unique")
    if not set(data_inputs) <= set(circuit.inputs):
        raise CircuitError("Anti-SAT data inputs do not exist in the circuit")

    branch_size = key_size // 2
    if branch_size > len(data_inputs):
        raise CircuitError(
            f"Anti-SAT key size {key_size} requires {branch_size} data inputs, "
            f"but the circuit has {len(data_inputs)}"
        )

    driven_outputs = tuple(
        output
        for output in circuit.outputs
        if any(gate.output == output for gate in circuit.gates)
    )
    if not driven_outputs:
        raise CircuitError("Anti-SAT requires a gate-driven primary output")

    random_source = random.Random(seed)
    selected_inputs = tuple(random_source.sample(data_inputs, branch_size))
    protected_output = random_source.choice(driven_outputs)
    branch_key = tuple(random_source.randint(0, 1) for _ in range(branch_size))
    key = (*branch_key, *branch_key)

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs = [
        _unique_name(f"keyinput_{key_index_offset + index}", used_signals)
        for index in range(key_size)
    ]
    protected_source = _unique_name(
        f"{protected_output}_locksrc_antisat",
        used_signals,
    )

    locked_gates = [
        Gate(
            name=gate.name,
            kind=gate.kind,
            inputs=gate.inputs,
            output=protected_source if gate.output == protected_output else gate.output,
        )
        for gate in circuit.gates
    ]

    branch_signals: list[list[str]] = [[], []]
    insertions: list[LockInsertion] = []
    for branch in range(2):
        for position, data_input in enumerate(selected_inputs):
            local_key_index = branch * branch_size + position
            key_index = key_index_offset + local_key_index
            signal = _unique_name(
                f"antisat_branch_{branch}_{position}",
                used_signals,
            )
            gate_name = _unique_name(
                f"antisat_key_gate_{key_index}",
                used_gate_names,
            )
            locked_gates.append(
                Gate(
                    name=gate_name,
                    kind="XOR",
                    inputs=(data_input, key_inputs[local_key_index]),
                    output=signal,
                )
            )
            branch_signals[branch].append(signal)
            insertions.append(
                LockInsertion(
                    key_index=key_index,
                    key_input=key_inputs[local_key_index],
                    correct_bit=key[local_key_index],
                    gate_kind="XOR",
                    protected_signal=protected_output,
                    source_signal=data_input,
                )
            )

    function_signal = _unique_name("antisat_function", used_signals)
    complement_signal = _unique_name("antisat_complement", used_signals)
    block_signal = _unique_name("antisat_block", used_signals)
    locked_gates.extend(
        (
            Gate(
                name=_unique_name("antisat_function_gate", used_gate_names),
                kind="AND",
                inputs=tuple(branch_signals[0]),
                output=function_signal,
            ),
            Gate(
                name=_unique_name("antisat_complement_gate", used_gate_names),
                kind="NAND",
                inputs=tuple(branch_signals[1]),
                output=complement_signal,
            ),
            Gate(
                name=_unique_name("antisat_block_gate", used_gate_names),
                kind="AND",
                inputs=(function_signal, complement_signal),
                output=block_signal,
            ),
            Gate(
                name=_unique_name("antisat_output_gate", used_gate_names),
                kind="XOR",
                inputs=(protected_source, block_signal),
                output=protected_output,
            ),
        )
    )

    locked = Circuit(
        name=f"{circuit.name}_antisat",
        inputs=(*circuit.inputs, *key_inputs),
        outputs=circuit.outputs,
        gates=tuple(locked_gates),
    )
    locked.validate()
    return LockResult(
        circuit=locked,
        key=key,
        seed=seed,
        insertions=tuple(insertions),
    )


def _unique_name(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 1
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate
