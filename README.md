# LockLab

LockLab is a command-line tool for experimenting with combinational logic
locking. It reads Verilog or BENCH circuits, shows circuit information, inserts
logic-locking gates, and validates candidate keys.

The current version implements Random Logic Locking (RLL), MUX-based locking,
and an oracle-guided SAT attack. Both locking schemes use the same circuit
model, formal validator, and attack command.

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

Yosys is required for Verilog input. Yices is required for formal key
validation and the SAT attack. Icarus, EQY, and SBY are reported by the doctor
but are optional for the currently implemented commands. BENCH input itself
does not require Yosys.

## Inspect a circuit

```bash
locklab info benchmarks/sources/iscas85/c17.v
locklab info benchmarks/sources/iscas85/c17.bench
locklab info benchmarks/sources/iscas85/c432.bench
locklab info benchmarks/sources/iscas85/c880.bench
locklab info benchmarks/sources/iscas85/c1908.bench
```

Use `--top MODULE` when a Verilog file contains multiple possible top modules.
The included ISCAS-85 BENCH files come from the
[University of Toronto ECE 1767 benchmark archive](https://www.eecg.utoronto.ca/~ece1767/project/iscas.html).

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

MUX locking uses the same command with a different scheme:

```bash
locklab lock benchmarks/sources/iscas85/c17.v \
  --scheme mux \
  --key-size 2 \
  --seed 42
```

Each inserted MUX selects between the protected signal and a seeded decoy. A
decoy is chosen only from primary inputs or earlier gates, preventing the
insertion from creating a combinational cycle. The metadata records the decoy
used for each key bit.

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

Activate OSS CAD Suite so `yices-sat` is available before validating. LockLab
builds a formal miter between the reference and keyed circuit. It exits with
status 0 when the miter is UNSAT, proving that no input can distinguish the two
circuits. It reports whether the key exactly matches the planted key in the
adjacent `.lock.json` metadata or is a different but functionally equivalent
key. An incorrect key exits with status 1 and prints a concrete input where the
outputs differ.

## Run a SAT attack

Activate OSS CAD Suite so `yices-sat` is available, then provide the locked
circuit and its unlocked oracle:

```bash
locklab attack sat \
  outputs/c17_locked.v \
  benchmarks/sources/iscas85/c17.v
```

LockLab automatically identifies the extra key inputs. It repeatedly finds a
distinguishing input, evaluates that input on the oracle, and eliminates keys
that disagree with the oracle. A final formal SAT miter validates the recovered
key before it is printed. When adjacent lock metadata is available, the command
also classifies the recovery as the exact planted key or a functionally
equivalent alternative. Alternative results include the changed key-bit indices
and their protected signals. Solver CNF files are temporary and no attack-result
files are created.

## Tests

```bash
pytest
```
