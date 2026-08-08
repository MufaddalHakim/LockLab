from __future__ import annotations

import random
from dataclasses import dataclass

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

    circuit.validate()
    if key_size < 4 or key_size % 2:
        raise CircuitError("Anti-SAT key size must be even and at least 4")

    branch_size = key_size // 2
    if branch_size > len(circuit.inputs):
        raise CircuitError(
            f"Anti-SAT key size {key_size} requires {branch_size} data inputs, "
            f"but the circuit has {len(circuit.inputs)}"
        )

    driven_outputs = tuple(
        output
        for output in circuit.outputs
        if any(gate.output == output for gate in circuit.gates)
    )
    if not driven_outputs:
        raise CircuitError("Anti-SAT requires a gate-driven primary output")

    random_source = random.Random(seed)
    selected_inputs = tuple(random_source.sample(circuit.inputs, branch_size))
    protected_output = random_source.choice(driven_outputs)
    branch_key = tuple(random_source.randint(0, 1) for _ in range(branch_size))
    key = (*branch_key, *branch_key)

    used_signals = set(circuit.inputs) | set(circuit.outputs)
    used_signals.update(gate.output for gate in circuit.gates)
    used_gate_names = {gate.name for gate in circuit.gates}
    key_inputs = [
        _unique_name(f"keyinput_{index}", used_signals)
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
            key_index = branch * branch_size + position
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
                    inputs=(data_input, key_inputs[key_index]),
                    output=signal,
                )
            )
            branch_signals[branch].append(signal)
            insertions.append(
                LockInsertion(
                    key_index=key_index,
                    key_input=key_inputs[key_index],
                    correct_bit=key[key_index],
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
