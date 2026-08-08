from pathlib import Path

import pytest

from locklab.bench import BenchError, load_bench, parse_bench, write_bench


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
C17_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c17.bench"
C432_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c432.bench"
C880_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c880.bench"
C1908_BENCH = REPOSITORY_ROOT / "benchmarks/sources/iscas85/c1908.bench"


def test_load_c17_bench() -> None:
    circuit = load_bench(C17_BENCH)

    assert circuit.inputs == ("N1", "N2", "N3", "N6", "N7")
    assert circuit.outputs == ("N22", "N23")
    assert len(circuit.gates) == 6
    assert {gate.kind for gate in circuit.gates} == {"NAND"}


def test_load_c432_bench() -> None:
    circuit = load_bench(C432_BENCH)

    assert len(circuit.inputs) == 36
    assert len(circuit.outputs) == 7
    assert len(circuit.gates) == 232


def test_load_c880_bench() -> None:
    circuit = load_bench(C880_BENCH)

    assert len(circuit.inputs) == 60
    assert len(circuit.outputs) == 26
    assert len(circuit.gates) == 383


def test_load_c1908_bench() -> None:
    circuit = load_bench(C1908_BENCH)

    assert len(circuit.inputs) == 33
    assert len(circuit.outputs) == 25
    assert len(circuit.gates) == 880


def test_bench_round_trip_preserves_behavior(tmp_path: Path) -> None:
    original = load_bench(C17_BENCH)
    output = tmp_path / "c17-copy.bench"

    write_bench(original, output)
    copied = load_bench(output)

    for vector in range(32):
        bits = f"{vector:05b}"
        values = dict(zip(original.inputs, map(int, bits)))
        assert copied.evaluate(values) == original.evaluate(values)


def test_bench_rejects_sequential_gate() -> None:
    with pytest.raises(BenchError, match="sequential DFF"):
        parse_bench("INPUT(a)\nOUTPUT(q)\nq = DFF(a)\n")
