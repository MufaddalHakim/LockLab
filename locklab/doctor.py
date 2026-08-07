from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    command: str
    version_args: tuple[str, ...] = ("--version",)
    required: bool = False


TOOLS = (
    Tool("Git", "git"),
    Tool("Yosys", "yosys", ("-V",), required=True),
    Tool("Icarus Verilog compiler", "iverilog", ("-V",)),
    Tool("Icarus Verilog runtime", "vvp", ("-V",)),
    Tool("EQY", "eqy"),
    Tool("SBY", "sby"),
)


def get_version(tool: Tool) -> str:
    executable = shutil.which(tool.command)

    if executable is None:
        return "NOT FOUND"

    try:
        result = subprocess.run(
            [executable, *tool.version_args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"ERROR: {error}"

    output = result.stdout.strip() or result.stderr.strip()

    if not output:
        return f"installed at {executable}"

    return output.splitlines()[0]


def run_doctor() -> int:
    print("LockLab environment check")
    print("=" * 50)
    print(f"Python:   {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")
    print()

    missing_required: list[str] = []
    missing_optional: list[str] = []

    for tool in TOOLS:
        version = get_version(tool)
        if version == "NOT FOUND":
            status = "MISSING"
        elif version.startswith("ERROR:"):
            status = "ERROR"
        else:
            status = "PASS"

        print(f"[{status:7}] {tool.name}: {version}")

        if status != "PASS" and tool.required:
            missing_required.append(tool.name)
        elif status != "PASS":
            missing_optional.append(tool.name)

    print()

    if missing_required:
        print("Required tools are missing:", ", ".join(missing_required))
        return 1

    print("All required tools were found.")
    if missing_optional:
        print("Optional tools not found:", ", ".join(missing_optional))
    return 0
