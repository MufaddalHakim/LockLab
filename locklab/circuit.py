from __future__ import annotations

import heapq
import re
from dataclasses import dataclass
from functools import reduce
from operator import xor


VERILOG_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
CONSTANTS = {"0", "1"}
SUPPORTED_GATES = {
    "BUF",
    "NOT",
    "AND",
    "NAND",
    "OR",
    "NOR",
    "XOR",
    "XNOR",
    "MUX",
}


class CircuitError(ValueError):
    """Raised when a circuit is malformed or cannot be evaluated."""


@dataclass(frozen=True)
class Gate:
    name: str
    kind: str
    inputs: tuple[str, ...]
    output: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", self.kind.upper())


@dataclass(frozen=True)
class Circuit:
    name: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    gates: tuple[Gate, ...]

    def validate(self) -> None:
        """Reject ambiguous wiring, unsupported gates, and combinational cycles."""

        identifiers = (self.name, *self.inputs, *self.outputs)
        if any(VERILOG_IDENTIFIER.fullmatch(name) is None for name in identifiers):
            raise CircuitError("circuit and port names must be simple Verilog identifiers")
        if len(self.inputs) != len(set(self.inputs)):
            raise CircuitError("circuit contains duplicate inputs")
        if len(self.outputs) != len(set(self.outputs)):
            raise CircuitError("circuit contains duplicate outputs")
        if set(self.inputs) & set(self.outputs):
            raise CircuitError("a signal cannot be both an input and an output port")

        drivers: dict[str, Gate] = {}
        gate_names: set[str] = set()
        for gate in self.gates:
            if gate.kind not in SUPPORTED_GATES:
                raise CircuitError(f"unsupported gate type: {gate.kind}")
            if VERILOG_IDENTIFIER.fullmatch(gate.name) is None:
                raise CircuitError(f"invalid gate name: {gate.name}")
            if gate.name in gate_names:
                raise CircuitError(f"duplicate gate name: {gate.name}")
            gate_names.add(gate.name)
            if VERILOG_IDENTIFIER.fullmatch(gate.output) is None:
                raise CircuitError(f"invalid gate output: {gate.output}")
            if gate.output in self.inputs:
                raise CircuitError(f"gate drives primary input: {gate.output}")
            if gate.output in drivers:
                raise CircuitError(f"multiple gates drive signal: {gate.output}")
            drivers[gate.output] = gate

            if gate.kind in {"BUF", "NOT"} and len(gate.inputs) != 1:
                raise CircuitError(f"{gate.kind} gate requires one input")
            if gate.kind == "MUX" and len(gate.inputs) != 3:
                raise CircuitError("MUX gate requires A, B, and select inputs")
            if gate.kind not in {"BUF", "NOT", "MUX"} and len(gate.inputs) < 2:
                raise CircuitError(f"{gate.kind} gate requires at least two inputs")

        known_signals = set(self.inputs) | set(drivers) | CONSTANTS
        for gate in self.gates:
            unknown = set(gate.inputs) - known_signals
            if unknown:
                raise CircuitError(
                    f"gate {gate.name} uses undriven signals: "
                    + ", ".join(sorted(unknown))
                )

        undriven_outputs = set(self.outputs) - known_signals
        if undriven_outputs:
            raise CircuitError(
                "undriven outputs: " + ", ".join(sorted(undriven_outputs))
            )

        self.topological_gates()

    def topological_gates(self) -> tuple[Gate, ...]:
        """Return gates in dependency order and detect combinational cycles."""

        driver_index = {gate.output: index for index, gate in enumerate(self.gates)}
        dependencies: list[set[int]] = []
        consumers: dict[int, set[int]] = {
            index: set() for index in range(len(self.gates))
        }

        for index, gate in enumerate(self.gates):
            gate_dependencies = {
                driver_index[signal]
                for signal in gate.inputs
                if signal in driver_index
            }
            dependencies.append(gate_dependencies)
            for dependency in gate_dependencies:
                consumers[dependency].add(index)

        ready = [
            index for index, gate_dependencies in enumerate(dependencies)
            if not gate_dependencies
        ]
        heapq.heapify(ready)
        ordered: list[Gate] = []

        while ready:
            index = heapq.heappop(ready)
            ordered.append(self.gates[index])
            for consumer in sorted(consumers[index]):
                dependencies[consumer].discard(index)
                if not dependencies[consumer]:
                    heapq.heappush(ready, consumer)

        if len(ordered) != len(self.gates):
            raise CircuitError("circuit contains a combinational cycle")

        return tuple(ordered)

    def observable_gate_outputs(self) -> tuple[str, ...]:
        """Return gate outputs that contribute to at least one primary output."""

        needed = set(self.outputs)
        observable: set[str] = set()
        for gate in reversed(self.topological_gates()):
            if gate.output in needed:
                observable.add(gate.output)
                needed.update(gate.inputs)

        return tuple(
            gate.output for gate in self.topological_gates()
            if gate.output in observable
        )

    def evaluate(self, input_values: dict[str, int | bool]) -> dict[str, int]:
        """Evaluate a combinational circuit for one complete input assignment."""

        missing = set(self.inputs) - set(input_values)
        extra = set(input_values) - set(self.inputs)
        if missing:
            raise CircuitError("missing input values: " + ", ".join(sorted(missing)))
        if extra:
            raise CircuitError("unknown input values: " + ", ".join(sorted(extra)))

        values = {"0": 0, "1": 1}
        values.update({name: int(bool(value)) for name, value in input_values.items()})

        for gate in self.topological_gates():
            gate_inputs = tuple(values[signal] for signal in gate.inputs)
            values[gate.output] = _evaluate_gate(gate.kind, gate_inputs)

        return {name: values[name] for name in self.outputs}


def _evaluate_gate(kind: str, values: tuple[int, ...]) -> int:
    if kind == "BUF":
        return values[0]
    if kind == "NOT":
        return 1 - values[0]
    if kind == "AND":
        return int(all(values))
    if kind == "NAND":
        return int(not all(values))
    if kind == "OR":
        return int(any(values))
    if kind == "NOR":
        return int(not any(values))
    if kind == "XOR":
        return reduce(xor, values)
    if kind == "XNOR":
        return 1 - reduce(xor, values)
    if kind == "MUX":
        data_a, data_b, select = values
        return data_b if select else data_a
    raise CircuitError(f"unsupported gate type: {kind}")
