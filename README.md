# LockLab

LockLab is a command-line tool for experimenting with combinational logic
locking. It reads Verilog or BENCH circuits, shows circuit information, inserts
logic-locking gates, and validates candidate keys.

The current version implements Random Logic Locking (RLL), MUX-based locking,
type-0 Anti-SAT, SFLL-HD0, and general SFLL-HDh defenses; exact and approximate
oracle-guided SAT attacks; structural and functional SFLL-HD0 analysis; and
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

SFLL-HD0 uses a protected primary-input cube as its secret key:

```bash
locklab lock benchmarks/sources/iscas85/c432.bench \
  --scheme sfll-hd0 \
  --key-size 16 \
  --seed 42
```

The key size must be at least one and cannot exceed the circuit's number of
primary inputs. LockLab selects that many primary inputs and one gate-driven
primary output using the seed. A hardcoded equality function strips the
selected output's functionality on the protected cube. A second equality
function compares the same primary inputs with the runtime key and restores the
output. With the correct key, the two inversions cancel for every input. A wrong
key corrupts both the protected cube and the cube represented by the wrong key;
each cube contains `2^(n-k)` complete input vectors for `n` circuit
inputs and `k` selected inputs.

This is an explicit, deterministic gate-level implementation of the SFLL-HD0
Boolean architecture. It does not yet perform security-aware synthesis to merge
the stripped function into the original logic cone, so the protection logic
retains a clear structural boundary. The construction and its one-protected-cube
behavior follow the original
[SFLL paper](https://acmccs.github.io/papers/p1601-yasinA.pdf).

General SFLL-HDh protects every selected-input cube at exactly distance `h`
from the planted key:

```bash
locklab lock benchmarks/sources/iscas85/c432.bench \
  --scheme sfll-hd \
  --key-size 16 \
  --hamming-distance 2 \
  --seed 42
```

The distance must satisfy `0 <= h <= key-size`. LockLab forms one mismatch bit
per selected input, computes whether the mismatch weight is exactly `h`, and
uses the result for both the hardcoded strip function and runtime-key restore
function. The exact-weight network uses a one-hot dynamic program with
`O(key-size * h)` gates rather than explicitly enumerating protected cubes.
With the planted key, strip and restore are identical and formally cancel.

For key size `k`, the protected set contains exactly `C(k,h)` selected-input
cubes, representing `C(k,h) * 2^(n-k)` complete vectors when the original
circuit has `n` inputs. The adjacent metadata records `k`, `h`, selected inputs,
and this cube count. `--scheme sfll-hd --hamming-distance 0` uses the existing
HD0 construction; the `sfll-hd0` scheme remains available for compatibility.

An important interpretation caveat is that a wrong key need not always produce
a different exact-distance set. When `k` is even and `h = k/2`, a key and its
bitwise complement define the same protected set and are therefore functionally
equivalent. Validation reports such a key as an equivalent alternative rather
than incorrectly treating every non-planted key as a failure.

The current formal benchmark check uses 16-bit keys at `h=2` on the larger
circuits:

| Benchmark | Original gates | Locked gates | Added gates | Protected cubes | Formal result |
|---|---:|---:|---:|---:|---|
| c432 | 232 | 544 | 312 | 120 | equivalent |
| c880 | 383 | 695 | 312 | 120 | equivalent |
| c1908 | 880 | 1192 | 312 | 120 | equivalent |

These counts describe the explicit unsynthesized reference construction and
are deterministic for the shown `key-size=16`, `h=2`, and `seed=42` setup.

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

## Run structural SFLL-HD0 analysis

The SFLL structural command recovers the protected cube from LockLab's explicit
strip-and-restore topology without an oracle, metadata, or signal-name
conventions:

```bash
locklab attack sfll-structural outputs/c432_locked.bench
```

It locates the hardcoded strip matcher and runtime equality comparator, maps
each suspected key input to its protected primary input, infers every protected
cube bit from literal polarity, and reports the protected output. It recognizes
both multi-input BENCH gates and the two-input AND and XNOR decomposition emitted
when Yosys lowers Verilog. The command is read-only and creates no files.

This is an exact topology match for LockLab's deliberately visible reference
implementation. General synthesized or security-aware SFLL netlists may merge
or rewrite these cones and require functional candidate analysis; zero exact
matches is therefore not evidence that SFLL protection is absent.

For synthesized netlists, the functional assessment follows key-input fanout
instead of requiring XNOR and XOR gate shapes:

```bash
locklab attack sfll-functional synthesized/c432_locked.v
```

The assessment computes fan-in supports and post-dominators to locate restore
cones that exclusively collect suspected key inputs. It recovers key-to-data
pairings from two-input support sets, checks that the restore cone is an equality
function, and uses unateness to identify a matching or complemented strip point
function. SAT proofs reject candidates unless both Boolean properties hold. The
report labels unchanged circuits as `exact topology` and rewritten circuits as
`functional candidate`; it remains read-only and creates no files. Functional
proofs require Yices, and `--max-key-size` limits the largest restore cone
considered (32 by default).

The functional mode deliberately reports no complete candidate if synthesis
fully absorbs the strip point function into the original logic cone. The restore
cone may still be recognizable, but the planted cube is not generally
identifiable without a surviving strip function, an oracle, or an unlocked
reference. Functional synthesized one-bit candidates are also excluded because
ordinary two-input circuit logic produces too many ambiguous matches; the exact
mode continues to support one-bit SFLL-HD0.

Current whole-circuit ABC results are:

| Benchmark | Key size | ABC library | Assessment | Formal inferred-key result |
|---|---:|---|---|---|
| c17 | 4 | mixed, AIG, DeMorgan | recovered in all three | equivalent |
| c432 | 4 and 16 | AIG | recovered | equivalent |
| c880 | 4 and 16 | AIG | recovered | equivalent |
| c1908 | 4 | AIG | recovered | equivalent |
| c1908 | 16 | AIG | no complete candidate; strip absorbed | not applicable |

The formal result in this table comes from test-only miters against the unlocked
benchmarks. The read-only command itself has no oracle: it formally proves the
local restore-equality and strip-point-function properties, then reports the
inferred cube for independent validation.

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

## Run the comparative benchmark study

The tracked study configurations apply the same measurement pipeline to RLL,
MUX locking, Anti-SAT, compound RLL + Anti-SAT, SFLL-HD0, and SFLL-HDh. Inspect
the seven-case c17 smoke matrix without executing it:

```bash
locklab study configs/comparative_smoke.json --dry-run
```

Run the smoke matrix, followed by the full 312-case matrix:

```bash
locklab study configs/comparative_smoke.json
locklab study configs/comparative_matrix.json
```

Activate OSS CAD Suite first because each supported case formally checks the
planted key and runs Yices-backed attacks. The full matrix covers c17, c432,
c880, and c1908; three seeds; multiple key sizes; SFLL distances one and two;
and AppSAT error thresholds 0.01 and 0.05. The JSON configuration is the
experiment specification, including the sample count and per-solver-call
timeout.

Each completed case records locking overhead, formal equivalence, exact-SAT
distinguishing inputs and solver calls, AppSAT sampled error, structural
detections, SPS/ADS rank, runtime, seed, tool versions, Git provenance, and a
Material Passport. Each record also hashes the exact benchmark and study
configuration used. Raw append-only records are written to
`runs/<study-name>.jsonl`; a normalized summary is rebuilt at
`runs/<study-name>.csv`. Both generated files are ignored by Git.

Execution is resumable by default. A repeated command skips existing cases,
while `--retry-failures` reruns only failed, partial, timed-out, or unsupported
records. `--limit N` is useful for a short pilot. LockLab refuses to mix records
when the configuration file's SHA-256 digest changes. Invalid scheme/benchmark
combinations remain visible as `unsupported` rows instead of disappearing from
the dataset.

Runtime values are meaningful only within a controlled environment. AppSAT's
reported error is a seeded sample estimate and must not be interpreted as a
formal proof; the separate formal-equivalence field provides that distinction.

## Tests

```bash
pytest
```
