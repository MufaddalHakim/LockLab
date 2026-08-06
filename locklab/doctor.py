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


TOOLS = (
    Tool("Git", "git"),
    Tool("Yosys", "yosys", ("-V",)),
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

    missing_tools: list[str] = []

    for tool in TOOLS:
        version = get_version(tool)
        status = "PASS" if version != "NOT FOUND" else "MISSING"

        print(f"[{status:7}] {tool.name}: {version}")

        if version == "NOT FOUND":
            missing_tools.append(tool.name)

    print()

    if missing_tools:
        print("Some tools are missing.")
        print("This is expected at the beginning of the project.")
        print("Missing:", ", ".join(missing_tools))
        return 1

    print("All required tools were found.")
    return 0