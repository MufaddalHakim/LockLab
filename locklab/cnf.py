from __future__ import annotations

from dataclasses import dataclass, field

from locklab.circuit import Circuit, CircuitError, Gate


@dataclass
class CNF:
    """Small in-memory DIMACS CNF builder."""

    variable_count: int = 0
    clauses: list[tuple[int, ...]] = field(default_factory=list)
    _names: dict[str, int] = field(default_factory=dict)
    _false_variable: int | None = None
    _true_variable: int | None = None

    def new_variable(self, name: str | None = None) -> int:
        if name is not None and name in self._names:
            raise CircuitError(f"duplicate CNF variable name: {name}")
        self.variable_count += 1
        if name is not None:
            self._names[name] = self.variable_count
        return self.variable_count

    def add_clause(self, *literals: int) -> None:
        if not literals:
            raise CircuitError("CNF clause cannot be empty")
        if any(literal == 0 or abs(literal) > self.variable_count for literal in literals):
            raise CircuitError("CNF clause references an invalid variable")
        self.clauses.append(tuple(literals))

    @property
    def false_variable(self) -> int:
        if self._false_variable is None:
            self._false_variable = self.new_variable("constant:false")
            self.add_clause(-self._false_variable)
        return self._false_variable

    @property
    def true_variable(self) -> int:
        if self._true_variable is None:
            self._true_variable = self.new_variable("constant:true")
            self.add_clause(self._true_variable)
        return self._true_variable

    def to_dimacs(self) -> str:
        lines = [f"p cnf {self.variable_count} {len(self.clauses)}"]
        lines.extend(" ".join(map(str, clause)) + " 0" for clause in self.clauses)
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class CircuitEncoding:
    signal_variables: dict[str, int]
    output_variables: dict[str, int]


def encode_circuit(
    cnf: CNF,
    circuit: Circuit,
    *,
    namespace: str,
    input_variables: dict[str, int] | None = None,
) -> CircuitEncoding:
    """Add one circuit instance, optionally sharing its primary-input variables."""

    circuit.validate()
    provided = input_variables or {}
    missing = set(provided) - set(circuit.inputs)
    if missing:
        raise CircuitError(
            "CNF input mapping contains unknown signals: " + ", ".join(sorted(missing))
        )

    signals = {
        "0": cnf.false_variable,
        "1": cnf.true_variable,
    }
    for name in circuit.inputs:
        signals[name] = provided.get(name) or cnf.new_variable(
            f"{namespace}:input:{name}"
        )

    for gate in circuit.topological_gates():
        output = cnf.new_variable(f"{namespace}:signal:{gate.output}")
        inputs = tuple(signals[name] for name in gate.inputs)
        encode_gate(cnf, gate, inputs=inputs, output=output)
        signals[gate.output] = output

    return CircuitEncoding(
        signal_variables=signals,
        output_variables={name: signals[name] for name in circuit.outputs},
    )


def encode_gate(
    cnf: CNF,
    gate: Gate,
    *,
    inputs: tuple[int, ...],
    output: int,
) -> None:
    """Constrain ``output`` to exactly match one supported Boolean gate."""

    kind = gate.kind
    if kind == "BUF":
        _encode_buffer(cnf, inputs[0], output)
    elif kind == "NOT":
        _encode_not(cnf, inputs[0], output)
    elif kind == "AND":
        _encode_and(cnf, inputs, output)
    elif kind == "NAND":
        _encode_nand(cnf, inputs, output)
    elif kind == "OR":
        _encode_or(cnf, inputs, output)
    elif kind == "NOR":
        _encode_nor(cnf, inputs, output)
    elif kind == "XOR":
        _encode_xor(cnf, inputs, output)
    elif kind == "XNOR":
        xor_output = cnf.new_variable()
        _encode_xor(cnf, inputs, xor_output)
        _encode_not(cnf, xor_output, output)
    elif kind == "MUX":
        data_a, data_b, select = inputs
        _encode_mux(cnf, data_a, data_b, select, output)
    else:
        raise CircuitError(f"unsupported gate type for CNF: {kind}")


def _encode_buffer(cnf: CNF, value: int, output: int) -> None:
    cnf.add_clause(-value, output)
    cnf.add_clause(value, -output)


def _encode_not(cnf: CNF, value: int, output: int) -> None:
    cnf.add_clause(value, output)
    cnf.add_clause(-value, -output)


def _encode_and(cnf: CNF, inputs: tuple[int, ...], output: int) -> None:
    for value in inputs:
        cnf.add_clause(-output, value)
    cnf.add_clause(output, *(-value for value in inputs))


def _encode_nand(cnf: CNF, inputs: tuple[int, ...], output: int) -> None:
    for value in inputs:
        cnf.add_clause(output, value)
    cnf.add_clause(-output, *(-value for value in inputs))


def _encode_or(cnf: CNF, inputs: tuple[int, ...], output: int) -> None:
    cnf.add_clause(-output, *inputs)
    for value in inputs:
        cnf.add_clause(-value, output)


def _encode_nor(cnf: CNF, inputs: tuple[int, ...], output: int) -> None:
    cnf.add_clause(output, *inputs)
    for value in inputs:
        cnf.add_clause(-value, -output)


def _encode_xor(cnf: CNF, inputs: tuple[int, ...], output: int) -> None:
    current = inputs[0]
    for index, value in enumerate(inputs[1:], start=1):
        target = output if index == len(inputs) - 1 else cnf.new_variable()
        _encode_xor2(cnf, current, value, target)
        current = target


def _encode_xor2(cnf: CNF, first: int, second: int, output: int) -> None:
    cnf.add_clause(-first, -second, -output)
    cnf.add_clause(first, second, -output)
    cnf.add_clause(first, -second, output)
    cnf.add_clause(-first, second, output)


def _encode_mux(
    cnf: CNF,
    data_a: int,
    data_b: int,
    select: int,
    output: int,
) -> None:
    cnf.add_clause(select, -data_a, output)
    cnf.add_clause(select, data_a, -output)
    cnf.add_clause(-select, -data_b, output)
    cnf.add_clause(-select, data_b, -output)
