from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from locklab.circuit import CircuitError
from locklab.cnf import CNF
from locklab.process import run_process


class SatSolverError(CircuitError):
    """Raised when the configured SAT solver is missing or fails."""


@dataclass(frozen=True)
class SatResult:
    satisfiable: bool
    model: dict[int, bool]


def solve_cnf(cnf: CNF, *, timeout_seconds: float = 30.0) -> SatResult:
    """Solve CNF with the Yices DIMACS frontend bundled in OSS CAD Suite."""

    solver = shutil.which("yices-sat")
    if solver is None:
        raise SatSolverError(
            "yices-sat was not found; activate the OSS CAD Suite environment"
        )

    with tempfile.TemporaryDirectory(prefix="locklab-sat-") as temporary:
        workdir = Path(temporary)
        problem = workdir / "problem.cnf"
        problem.write_text(cnf.to_dimacs(), encoding="utf-8")
        process = run_process(
            (solver, "--model", problem.name),
            cwd=workdir,
            timeout_seconds=timeout_seconds,
        )

    if process.timed_out:
        raise SatSolverError("SAT solver timed out")
    if process.exit_code != 0:
        diagnostic = process.stderr.strip() or process.stdout.strip()
        raise SatSolverError("SAT solver failed: " + diagnostic)

    lines = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    status_index = next(
        (index for index, line in enumerate(lines) if line in {"sat", "unsat", "unknown"}),
        None,
    )
    if status_index is None:
        raise SatSolverError("SAT solver returned no status")
    status = lines[status_index]
    if status == "unknown":
        raise SatSolverError("SAT solver returned unknown")
    if status == "unsat":
        return SatResult(satisfiable=False, model={})

    model: dict[int, bool] = {}
    for line in lines[status_index + 1 :]:
        for token in line.split():
            literal = int(token)
            if literal != 0:
                model[abs(literal)] = literal > 0
    return SatResult(satisfiable=True, model=model)
