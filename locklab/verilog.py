from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from locklab.circuit import Circuit, CircuitError, Gate, VERILOG_IDENTIFIER
from locklab.process import run_process


CELL_TYPES = {
    "$_BUF_": ("BUF", ("A",), "Y"),
    "$_NOT_": ("NOT", ("A",), "Y"),
    "$_AND_": ("AND", ("A", "B"), "Y"),
    "$_NAND_": ("NAND", ("A", "B"), "Y"),
    "$_OR_": ("OR", ("A", "B"), "Y"),
    "$_NOR_": ("NOR", ("A", "B"), "Y"),
    "$_XOR_": ("XOR", ("A", "B"), "Y"),
    "$_XNOR_": ("XNOR", ("A", "B"), "Y"),
    "$_MUX_": ("MUX", ("A", "B", "S"), "Y"),
}


class VerilogError(CircuitError):
    """Raised when Yosys cannot lower Verilog into LockLab's gate subset."""


def load_verilog(
    path: Path,
    *,
    top: str | None = None,
    timeout_seconds: float = 30.0,
) -> Circuit:
    """Use Yosys as a Verilog frontend and convert its JSON to a Circuit."""

    source = path.expanduser().resolve()
    if not source.is_file():
        raise VerilogError(f"Verilog file not found: {path}")
    if top is not None and VERILOG_IDENTIFIER.fullmatch(top) is None:
        raise VerilogError(f"invalid top-module name: {top}")

    yosys = shutil.which("yosys")
    if yosys is None:
        raise VerilogError("Yosys is required to read Verilog files")

    hierarchy = f"hierarchy -check -top {top}" if top else "hierarchy -check -auto-top"
    script = f"""read_verilog -sv {json.dumps(str(source))}
{hierarchy}
proc
flatten
opt
techmap
opt
clean
write_json circuit.json
"""

    with tempfile.TemporaryDirectory(prefix="locklab-yosys-") as temporary:
        workdir = Path(temporary)
        (workdir / "load.ys").write_text(script, encoding="utf-8")
        result = run_process(
            (yosys, "-Q", "-s", "load.ys"),
            cwd=workdir,
            timeout_seconds=timeout_seconds,
        )
        if not result.succeeded:
            if result.timed_out:
                raise VerilogError("Yosys timed out while reading the circuit")
            diagnostic = result.stderr.strip() or result.stdout.strip()
            raise VerilogError("Yosys could not read the circuit:\n" + diagnostic)

        try:
            payload = json.loads((workdir / "circuit.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise VerilogError(f"Yosys produced invalid JSON: {error}") from error

    return circuit_from_yosys_json(payload)


def circuit_from_yosys_json(payload: dict[str, Any]) -> Circuit:
    modules = payload.get("modules")
    if not isinstance(modules, dict) or not modules:
        raise VerilogError("Yosys JSON does not contain any modules")

    top_modules = [
        name
        for name, module in modules.items()
        if isinstance(module, dict) and _truthy_attribute(module.get("attributes", {}).get("top"))
    ]
    if len(top_modules) == 1:
        module_name = top_modules[0]
    elif len(modules) == 1:
        module_name = next(iter(modules))
    else:
        raise VerilogError("could not identify one top module in Yosys JSON")

    module = modules[module_name]
    ports = module.get("ports")
    cells = module.get("cells")
    netnames = module.get("netnames", {})
    if not isinstance(ports, dict) or not isinstance(cells, dict):
        raise VerilogError("Yosys top module is missing ports or cells")

    bit_names: dict[int, str] = {}
    inputs: list[str] = []
    outputs: list[str] = []
    constant_outputs: list[tuple[str, str]] = []
    aliased_outputs: list[tuple[str, str]] = []

    for port_name, details in ports.items():
        if VERILOG_IDENTIFIER.fullmatch(port_name) is None:
            raise VerilogError(f"unsupported port name: {port_name}")
        if not isinstance(details, dict) or len(details.get("bits", [])) != 1:
            raise VerilogError("vector and malformed ports are not supported yet")
        bit = details["bits"][0]
        direction = details.get("direction")
        if direction == "input":
            if not isinstance(bit, int):
                raise VerilogError(f"input port {port_name} is tied to a constant")
            inputs.append(port_name)
            bit_names[bit] = port_name

    for port_name, details in ports.items():
        direction = details.get("direction")
        bit = details["bits"][0]
        if direction == "output":
            outputs.append(port_name)
            if isinstance(bit, int):
                existing_name = bit_names.get(bit)
                if existing_name is None:
                    bit_names[bit] = port_name
                elif existing_name != port_name:
                    aliased_outputs.append((port_name, existing_name))
            elif bit in {"0", "1"}:
                constant_outputs.append((port_name, bit))
            else:
                raise VerilogError(f"output port {port_name} has an unknown value")
        elif direction != "input":
            raise VerilogError("inout ports are not supported yet")

    if isinstance(netnames, dict):
        for net_name, details in sorted(netnames.items()):
            if (
                VERILOG_IDENTIFIER.fullmatch(net_name)
                and isinstance(details, dict)
                and len(details.get("bits", [])) == 1
                and isinstance(details["bits"][0], int)
            ):
                bit_names.setdefault(details["bits"][0], net_name)

    used_signal_names = set(bit_names.values())

    def signal_name(bit: int | str) -> str:
        if bit in {"0", "1"}:
            return str(bit)
        if bit in {"x", "z"}:
            raise VerilogError("unknown and high-impedance signals are not supported")
        if not isinstance(bit, int):
            raise VerilogError(f"unsupported Yosys signal value: {bit!r}")
        existing_name = bit_names.get(bit)
        if existing_name is not None:
            return existing_name

        base_name = f"_bit_{bit}"
        generated_name = base_name
        suffix = 1
        while generated_name in used_signal_names:
            generated_name = f"{base_name}_{suffix}"
            suffix += 1
        bit_names[bit] = generated_name
        used_signal_names.add(generated_name)
        return generated_name

    gates: list[Gate] = []
    for cell_name, cell in sorted(cells.items()):
        if not isinstance(cell, dict):
            raise VerilogError(f"malformed Yosys cell: {cell_name}")
        cell_type = cell.get("type")
        if cell_type not in CELL_TYPES:
            raise VerilogError(f"unsupported Yosys cell type: {cell_type}")
        kind, input_ports, output_port = CELL_TYPES[cell_type]
        connections = cell.get("connections")
        if not isinstance(connections, dict):
            raise VerilogError(f"cell {cell_name} has no connections")

        def one_bit(port: str) -> int | str:
            bits = connections.get(port)
            if not isinstance(bits, list) or len(bits) != 1:
                raise VerilogError(f"cell {cell_name} port {port} is not scalar")
            return bits[0]

        gates.append(
            Gate(
                name=f"g{len(gates)}",
                kind=kind,
                inputs=tuple(signal_name(one_bit(port)) for port in input_ports),
                output=signal_name(one_bit(output_port)),
            )
        )

    for output_name, constant in constant_outputs:
        gates.append(
            Gate(
                name=f"g{len(gates)}",
                kind="BUF",
                inputs=(constant,),
                output=output_name,
            )
        )

    for output_name, source_name in aliased_outputs:
        gates.append(
            Gate(
                name=f"g{len(gates)}",
                kind="BUF",
                inputs=(source_name,),
                output=output_name,
            )
        )

    circuit_name = module_name if VERILOG_IDENTIFIER.fullmatch(module_name) else "circuit"
    circuit = Circuit(
        name=circuit_name,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        gates=tuple(gates),
    )
    circuit.validate()
    return circuit


def write_verilog(circuit: Circuit, path: Path) -> None:
    circuit.validate()
    port_lines = [f"    input wire {_verilog_token(name)}" for name in circuit.inputs]
    port_lines.extend(f"    output wire {_verilog_token(name)}" for name in circuit.outputs)
    ports = ",\n".join(port_lines)

    internal_wires = [
        gate.output
        for gate in circuit.topological_gates()
        if gate.output not in circuit.outputs and gate.output not in circuit.inputs
    ]
    wire_lines = "\n".join(f"    wire {_verilog_token(name)};" for name in internal_wires)

    gate_lines: list[str] = []
    for index, gate in enumerate(circuit.topological_gates()):
        if gate.kind == "MUX":
            data_a, data_b, select = map(_verilog_token, gate.inputs)
            gate_lines.append(
                f"    assign {_verilog_token(gate.output)} = {select} ? {data_b} : {data_a};"
            )
        else:
            arguments = ", ".join(
                _verilog_token(signal) for signal in (gate.output, *gate.inputs)
            )
            gate_lines.append(f"    {gate.kind.lower()} g{index}({arguments});")

    sections = [
        "`default_nettype none",
        "",
        f"module {_verilog_token(circuit.name)}(",
        ports,
        ");",
    ]
    if wire_lines:
        sections.extend((wire_lines, ""))
    sections.extend(gate_lines)
    sections.extend(("endmodule", "", "`default_nettype wire", ""))
    path.write_text("\n".join(sections), encoding="utf-8")


def _verilog_token(name: str) -> str:
    """Escape identifiers (including keywords), leaving constants as literals."""

    if name in {"0", "1"}:
        return name
    # Whitespace terminates a Verilog escaped identifier before punctuation.
    return f"\\{name} "


def _truthy_attribute(value: Any) -> bool:
    if value in {1, True}:
        return True
    if isinstance(value, str) and value and set(value) <= {"0", "1"}:
        return int(value, 2) != 0
    return False
