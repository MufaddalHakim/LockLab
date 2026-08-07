from __future__ import annotations

from pathlib import Path

from locklab.bench import load_bench, write_bench
from locklab.circuit import Circuit, CircuitError
from locklab.verilog import load_verilog, write_verilog


VERILOG_SUFFIXES = {".v", ".sv"}


class FormatError(CircuitError):
    """Raised when a circuit file extension is not supported."""


def load_circuit(path: Path, *, top: str | None = None) -> Circuit:
    suffix = path.suffix.lower()
    if suffix == ".bench":
        if top is not None:
            raise FormatError("--top applies only to Verilog input")
        return load_bench(path)
    if suffix in VERILOG_SUFFIXES:
        return load_verilog(path, top=top)
    raise FormatError("supported circuit formats are .v, .sv, and .bench")


def write_circuit(circuit: Circuit, path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix == ".bench":
        write_bench(circuit, path)
        return
    if suffix in VERILOG_SUFFIXES:
        write_verilog(circuit, path)
        return
    raise FormatError("output extension must be .v, .sv, or .bench")
