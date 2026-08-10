# LockLab

LockLab is a command-line tool for experimenting with combinational logic
locking. It reads Verilog or BENCH circuits, shows circuit information, inserts
logic-locking gates, and validates candidate keys.

The current version implements Random Logic Locking (RLL), MUX-based locking,
a type-0 Anti-SAT defense, exact and approximate oracle-guided SAT attacks, and
structural and signal-probability Anti-SAT analysis. All commands use the same
circuit model and parsers.

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

Anti-SAT locking inserts a point-function block whose output is XORed into a
seeded primary output:

```bash
locklab lock benchmarks/sources/iscas85/c17.bench \
  --scheme antisat \
  --key-size 4 \
  --seed 42
```

The total Anti-SAT key size must be even and at least 4. Its two key halves are
applied to complementary AND and NAND functions. Matching halves make the
Anti-SAT block output constant zero, preserving the original circuit; unequal
halves corrupt at least one input pattern. Standalone Anti-SAT has deliberately
low output corruption and recognizable structure, so it is a research defense
for studying SAT behavior rather than a complete production protection scheme.
The implementation follows the type-0 construction described in the original
[Anti-SAT paper](https://eprint.iacr.org/2017/761).

The compound scheme combines RLL's higher wrong-key corruption with Anti-SAT's
point-function behavior:

```bash
locklab lock benchmarks/sources/iscas85/c1908.bench \
  --scheme rll-antisat \
  --key-size 32 \
  --seed 42
```

`--key-size` is the total key size and must be divisible by 4 and at least 8.
LockLab assigns half of the bits to RLL and half to Anti-SAT. The metadata marks
each insertion's component and records both component sizes.

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

## Run an approximate SAT attack

AppSAT can stop before exact SAT convergence when sampled functional error stays
below a requested threshold:

```bash
locklab attack appsat \
  outputs/c17_locked.bench \
  benchmarks/sources/iscas85/c17.bench \
  --samples 32 \
  --threshold 0.01 \
  --seed 7
```

The command reports distinguishing inputs, random oracle queries, reinforced
observations, estimated input error, and a final formal-equivalence check. A
formal-equivalence failure is an expected possible outcome: AppSAT intentionally
accepts an approximate key when its sampled error meets the threshold. LockLab
checks error after every five distinguishing inputs and stops after two
consecutive estimates at or below the threshold. Sampling is deterministic for
a fixed seed, and no attack-result files are created.
The stopping and query-reinforcement design follows the original
[AppSAT paper](https://www.cerc.utexas.edu/utda/publications/C209.pdf).

## Run structural Anti-SAT analysis

The structural command locates the recognizable type-0 Anti-SAT topology
without an oracle or lock metadata:

```bash
locklab attack antisat-structural outputs/c1908_locked.bench
```

It reports the protected output, the two complementary branches, the branch
width, the shared data inputs, and the suspected Anti-SAT key inputs. It handles
both the multi-input gates written to BENCH and the equivalent two-input gate
trees produced when Yosys reads Verilog. The command is read-only and writes no
result files.

This is an exact structural-signature experiment for LockLab's type-0
construction, not a general signal-probability-skew implementation. An
obfuscated or synthesized implementation may not retain the same topology, so
zero candidates does not prove that a circuit contains no Anti-SAT logic.

The signal-probability-skew (SPS) command provides a topology-independent
ranking of suspicious gates:

```bash
locklab attack antisat-sps outputs/c1908_locked.bench
```

It assumes every primary and key input is independently one with probability
0.5, then propagates one-probabilities through the combinational circuit. For a
signal `x`, skew is `P(x=1) - 0.5`. A gate's absolute-difference-of-skews (ADS)
score is the largest difference between its input skews. The command prints the
five highest-scoring gates, including each output probability, output skew, and
input skews. It needs no oracle or lock metadata and creates no files.

This analytical propagation is deterministic and inexpensive, but it treats
gate inputs as independent. Probabilities can therefore be approximate in
reconvergent logic, where two gate inputs depend on the same earlier signal.
The ranking follows the SPS/ADS method described in
[Removal Attacks on Logic Locking and Camouflaging Techniques](https://eprint.iacr.org/2017/348).

After locating the block, the removal command bypasses its output-injection XOR
and prunes the now-unreachable Anti-SAT gates and key inputs:

```bash
locklab attack antisat-remove outputs/c1908_locked.bench
```

The recovered circuit is saved as `outputs/c1908_antisat_removed.bench`; no
metadata or result log is created. For a compound RLL+Anti-SAT circuit, this
removes only Anti-SAT and deliberately leaves the RLL gates and RLL key inputs.
The reduced circuit can then be passed to the existing SAT attack:

```bash
locklab attack sat \
  outputs/c1908_antisat_removed.bench \
  benchmarks/sources/iscas85/c1908.bench
```

## Tests

```bash
pytest
```
