import shutil
from pathlib import Path

import pytest

from locklab.bench import load_bench
from locklab.locking import lock_mux, lock_sfll_hd, lock_sfll_hd0
from locklab.validation import validate_key
from locklab.verilog import circuit_from_yosys_json, load_verilog, write_verilog


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


def test_mux_locked_verilog_round_trip_validates(tmp_path: Path) -> None:
    original = load_verilog(C17_VERILOG)
    locked = lock_mux(original, key_size=3, seed=9)
    output = tmp_path / "c17-mux-locked.v"

    write_verilog(locked.circuit, output)
    reloaded = load_verilog(output)
    result = validate_key(
        original,
        reloaded,
        key_inputs=tuple(item.key_input for item in locked.insertions),
        key=locked.key,
    )

    assert result.passed


def test_sfll_hd0_locked_verilog_round_trip_validates(tmp_path: Path) -> None:
    original = load_verilog(C17_VERILOG)
    locked = lock_sfll_hd0(original, key_size=3, seed=9)
    output = tmp_path / "c17-sfll-hd0-locked.v"

    write_verilog(locked.circuit, output)
    reloaded = load_verilog(output)
    result = validate_key(
        original,
        reloaded,
        key_inputs=tuple(item.key_input for item in locked.insertions),
        key=locked.key,
    )

    assert result.passed


def test_sfll_hd_locked_verilog_round_trip_validates(tmp_path: Path) -> None:
    original = load_verilog(C17_VERILOG)
    locked = lock_sfll_hd(
        original,
        key_size=4,
        hamming_distance=2,
        seed=9,
    )
    output = tmp_path / "c17-sfll-hd2-locked.v"

    write_verilog(locked.circuit, output)
    reloaded = load_verilog(output)
    result = validate_key(
        original,
        reloaded,
        key_inputs=tuple(item.key_input for item in locked.insertions),
        key=locked.key,
    )

    assert result.passed


def test_yosys_fallback_bit_names_do_not_collide_with_named_nets() -> None:
    payload = {
        "modules": {
            "top": {
                "attributes": {"top": 1},
                "ports": {
                    "a": {"direction": "input", "bits": [2]},
                    "b": {"direction": "input", "bits": [3]},
                    "result": {"direction": "output", "bits": [20]},
                },
                "netnames": {
                    "_bit_12": {"bits": [13]},
                },
                "cells": {
                    "and_unnamed": {
                        "type": "$_AND_",
                        "connections": {"A": [2], "B": [3], "Y": [12]},
                    },
                    "or_named": {
                        "type": "$_OR_",
                        "connections": {"A": [2], "B": [3], "Y": [13]},
                    },
                    "xor_result": {
                        "type": "$_XOR_",
                        "connections": {"A": [12], "B": [13], "Y": [20]},
                    },
                },
            }
        }
    }

    circuit = circuit_from_yosys_json(payload)

    internal_outputs = {
        gate.output for gate in circuit.gates if gate.output not in circuit.outputs
    }
    assert internal_outputs == {"_bit_12", "_bit_12_1"}
    assert circuit.evaluate({"a": 0, "b": 1}) == {"result": 1}
