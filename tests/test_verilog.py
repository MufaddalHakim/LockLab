import shutil
from pathlib import Path

import pytest

from locklab.bench import load_bench
from locklab.verilog import load_verilog, write_verilog


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
C17_VERILOG = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.v"
C17_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.bench"


pytestmark = pytest.mark.skipif(
    shutil.which("yosys") is None,
    reason="Yosys is required for Verilog tests",
)


def test_verilog_and_bench_c17_agree() -> None:
    verilog = load_verilog(C17_VERILOG)
    bench = load_bench(C17_BENCH)

    for vector in range(32):
        bits = f"{vector:05b}"
        values = dict(zip(bench.inputs, map(int, bits)))
        assert verilog.evaluate(values) == bench.evaluate(values)


def test_verilog_round_trip_preserves_behavior(tmp_path: Path) -> None:
    original = load_verilog(C17_VERILOG)
    output = tmp_path / "c17-copy.v"

    write_verilog(original, output)
    copied = load_verilog(output)

    for vector in range(32):
        bits = f"{vector:05b}"
        values = dict(zip(original.inputs, map(int, bits)))
        assert copied.evaluate(values) == original.evaluate(values)


def test_verilog_direct_input_to_output_connection(tmp_path: Path) -> None:
    source = tmp_path / "passthrough.v"
    source.write_text(
        "module passthrough(input wire a, output wire y); assign y = a; endmodule\n",
        encoding="utf-8",
    )

    circuit = load_verilog(source)

    assert circuit.evaluate({"a": 0}) == {"y": 0}
    assert circuit.evaluate({"a": 1}) == {"y": 1}
