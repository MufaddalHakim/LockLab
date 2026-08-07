# LockLab

LockLab is a command-line tool for experimenting with combinational logic
locking. It reads Verilog or BENCH circuits, shows circuit information, inserts
logic-locking gates, and validates candidate keys.

The current version implements Random Logic Locking (RLL). Oracle-guided SAT
attacks and additional locking schemes will be added on top of the same small
circuit model.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Activate OSS CAD Suite before the virtual environment when working with
Verilog:

```bash
source "${HOME}/Tools/oss-cad-suite/environment"
source .venv/bin/activate
```

Check the available tools:

```bash
locklab doctor
```

Yosys is required for Verilog input. Icarus, EQY, and SBY are reported by the
doctor but are optional for the currently implemented commands. BENCH input
does not require Yosys.

## Inspect a circuit

```bash
locklab info benchmarks/sources/iscas85/c17.v
locklab info benchmarks/sources/iscas85/c17.bench
```

Use `--top MODULE` when a Verilog file contains multiple possible top modules.

## Lock a circuit

```bash
locklab lock benchmarks/sources/iscas85/c17.v \
  --scheme rll \
  --key-size 2 \
  --seed 42
```

The command creates only two files:

- `outputs/c17_locked.v`: the locked circuit;
- `outputs/c17_locked.lock.json`: the correct key, seed, and inserted key gates.

The `outputs/` directory is used by default so generated circuits do not
clutter the repository root. Rerunning the command replaces the previous
locked circuit and metadata for the same input filename.

The generated file is reloaded and validated with its correct key before the
command reports success. Small circuits are checked exhaustively; circuits with
more than 16 data inputs use deterministic random simulation.

BENCH input and output use the same command:

```bash
locklab lock benchmarks/sources/iscas85/c17.bench \
  --scheme rll \
  --key-size 2 \
  --seed 42
```

## Validate a key

```bash
locklab validate benchmarks/sources/iscas85/c17.v \
  outputs/c17_locked.v \
  --key 01
```

The command exits with status 0 when the key passes and status 1 when a
mismatch is found.

## Tests

```bash
pytest
```
