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


def _unique_name(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 1
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate
