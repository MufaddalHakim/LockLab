# LockLab

LockLab is a command-line tool for experimenting with combinational logic
locking. It reads Verilog or BENCH circuits, shows circuit information, inserts
logic-locking gates, and validates candidate keys.

The current version implements Random Logic Locking (RLL), MUX-based locking,
type-0 Anti-SAT, SARLock, SFLL-HD0, and general SFLL-HDh defenses; exact and
approximate oracle-guided SAT attacks; structural and functional SFLL-HD0
analysis; structural SARLock analysis and removal; and structural and
signal-probability Anti-SAT analysis. All commands use the same circuit model
and parsers.

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
- `outputs/c17_locked.v.lock.json`: the correct key, seed, and inserted key gates.

The `outputs/` directory is used by default so generated circuits do not
clutter the repository root. Rerunning the command replaces the previous
locked circuit and metadata for the same input filename.

Metadata filenames keep the circuit extension: BENCH output uses
`c17_locked.bench.lock.json`, so it can coexist with the Verilog output.
Legacy names such as `c17_locked.lock.json` are no longer read because they
could belong to either format. Rerun the original lock command to regenerate
metadata under the new name; existing circuits can still be formally validated
without metadata.

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

SARLock inserts a masked point function at a seeded gate-driven primary output:

```bash
locklab lock benchmarks/sources/iscas85/c432.bench \
  --scheme sarlock \
  --key-size 16 \
  --seed 42
```

The key size must be at least one and cannot exceed the number of primary
inputs. LockLab uses the seed to choose `k` distinct primary inputs, one output,
and the planted key. If `X` is the selected-input vector, `K` is the runtime
key, and `Kc` is the planted key, the injected signal is:

```text
flip = (X == K) AND (K != Kc)
locked_output = original_output XOR flip
```

The mask `(K != Kc)` makes the flip permanently zero under the planted key.
Every wrong key instead corrupts exactly the one selected-input cube `X == K`.
For a circuit with `n` primary inputs, that cube represents `2^(n-k)` complete
input vectors because the unselected inputs remain free. Thus one oracle query
can distinguish at most one wrong key in the ideal point-function model. The
metadata records the selected inputs, protected output, comparator/mask/flip
signals, and the number of complete error vectors per wrong key.

This is a deterministic, explicit gate-level reference implementation of the
construction in the original [SARLock paper](https://doi.org/10.1109/HST.2016.7495588).
It intentionally preserves a recognizable comparator and mask boundary for
reproducible experiments. SARLock's low corruptibility and exposed standalone
structure make it vulnerable to approximate and removal-style analysis, so it
should not be interpreted as a complete production defense.

Run the SARLock behavioral, serialization, CLI, and formal checks—including all
bundled ISCAS-85 benchmark circuits—with:

```bash
pytest -q -k sarlock
```

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

For SAT and AppSAT, reported solver-call counts cover key recovery and exclude
the final equivalence proof. The configured per-call solver timeout also applies
to that proof.

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

## Run structural SARLock analysis and removal

The structural command locates LockLab's explicit SARLock comparator, planted-
key mask, flip gate, and output-injection XOR without reading lock metadata:

```bash
locklab attack sarlock-structural outputs/c432_locked.bench
```

It reports the protected output and source, selected primary inputs, suspected
key inputs, and key-to-input mapping. Because each mask literal explicitly
tests whether one runtime key bit differs from its planted value, the command
also infers the planted key. The analysis uses connectivity and gate polarity,
not internal signal names. It is read-only and creates no files.

The removal command replaces only a confidently matched output-injection XOR
with the original protected source, then prunes unreachable SARLock gates and
key inputs:

```bash
locklab attack sarlock-remove outputs/c432_locked.bench
```

For this input, the recovered circuit is written to
`outputs/c432_sarlock_removed.bench`. No metadata or attack-result log is
created. Tests formally compare the recovered circuits with every bundled
ISCAS-85 benchmark.

These commands demonstrate the standalone removal limitation identified in the
[original SARLock paper](https://doi.org/10.1109/HST.2016.7495588). They match
LockLab's explicit reference topology and its ordinary two-input decomposition
after Verilog loading. Aggressive synthesis such as whole-circuit ABC may absorb
or rewrite the boundary; in that case the commands deliberately report no
candidate instead of claiming a removal. Zero matches therefore do not prove
that SARLock is absent.

To compare exact SAT, AppSAT, structural recognition, and formally checked
removal across the larger bundled benchmarks, first inspect and then run the
dedicated matrix:

```bash
locklab study configs/sarlock_comparison.json --dry-run
locklab study configs/sarlock_comparison.json
```

Use `--limit N` for a bounded pilot. The configuration covers c432, c880, and
c1908 with 4- and 8-bit keys, three seeds, and two AppSAT thresholds. Its JSONL
and CSV records include exact/AppSAT solver measurements plus
`sarlock_structural_candidates`, removed gate/input counts, and formal
equivalence of the recovered circuit. The smaller c17 circuit is covered by the
SARLock test suite because it has only five primary inputs and cannot support
the matrix's 8-bit key.

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

## Run the FALL attack on SFLL-HDh

LockLab also implements the SFLL-HDh portion of the published FALL attack:

[Functional Analysis Attacks on Logic Locking](https://cse.iitk.ac.in/users/spramod/papers/fall19.pdf)

The attack uses comparator analysis, support-set matching, and the paper's
SAT-based `Distance2H` and `SlidingWindow` procedures to recover the protected
cube from the locked netlist. It does not use lock metadata or internal signal
names. The attack parameter `h` is required because it is part of the published
attacker model. The final candidate is formally checked against the exact
SFLL-HDh strip function.

For a documented `Distance2H` case:

```bash
locklab lock benchmarks/sources/iscas85/c432.bench \
  --scheme sfll-hd \
  --key-size 8 \
  --hamming-distance 2 \
  --seed 42

locklab attack sfll-fall outputs/c432_locked.bench \
  --hamming-distance 2
```

To perform FALL's oracle-backed key-confirmation stage, add the unlocked
benchmark as an oracle:

```bash
locklab attack sfll-fall outputs/c432_locked.bench \
  --hamming-distance 2 \
  --oracle benchmarks/sources/iscas85/c432.bench
```

The command is read-only and prints a candidate summary similar to:

```text
FALL SFLL-HDh candidates: 1
Known Hamming distance: 2
Candidate 1:
  Recovery method: distance2h
  Key size: 8
  Recovered key: 01000000
  Protected cubes: 28
  FALL SAT solver calls: 2
```

With `--oracle`, a confirmed candidate additionally prints:

```text
  Oracle confirmation: PASS (formal SAT miter UNSAT)
```

`Distance2H` applies when `4h <= m`, where `m` is the protected key-input
count. `SlidingWindow` applies when `h < floor(m/2)`. A case outside those
conditions is reported as having no FALL candidate; that is an algorithmic
applicability result, not evidence that SFLL is secure. The implementation
supports LockLab's explicit construction and functionally equivalent netlists
where pairwise comparison and strip cones survive synthesis. A synthesized
netlist that completely absorbs those cones cannot be identified from the
locked netlist alone and is reported without a candidate.

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

From the repository root, activate OSS CAD Suite and the project environment:

```bash
source "${HOME}/Tools/oss-cad-suite/environment"
source .venv/bin/activate
locklab doctor
```

If `.venv` does not exist yet, complete the [Setup](#setup) steps first. Inspect
the smoke-study cases without executing them:

```bash
locklab study configs/comparative_smoke.json --dry-run
```

Execute the smoke study first. If it completes successfully, run the full
comparative matrix:

```bash
locklab study configs/comparative_smoke.json
locklab study configs/comparative_matrix.json
```

Use a bounded pilot when testing a configuration change:

```bash
locklab study configs/comparative_matrix.json --limit 12
```

Every raw record is flushed immediately. Rerunning the same command skips
recorded cases and resumes at the first missing one. Before resuming, LockLab
checks the saved benchmark hashes against the current files. Changed or missing
benchmarks stop the run without altering existing results; use a new study name
when changing benchmark contents. This check also applies with `--limit` and
`--retry-failures`. To rerun only non-completed records, use:

```bash
locklab study configs/comparative_matrix.json --retry-failures
```

The repository may already contain ignored local results from an earlier run.
In that case the command reports those rows as skipped. For an independent run
without overwriting them, copy the configuration, change its JSON `name` to a
new value such as `comparative_matrix_manual`, and execute the copy:

```bash
cp configs/comparative_matrix.json configs/comparative_matrix_manual.json
# Edit "name" in the copied file to "comparative_matrix_manual".
locklab study configs/comparative_matrix_manual.json
```

This writes `runs/comparative_matrix_manual.jsonl` and
`runs/comparative_matrix_manual.csv`.

The commands print a summary similar to this illustrative example:

```text
Study: comparative_smoke
Planned cases: 7
Executed cases: 7
Skipped existing cases: 0
Statuses: completed=7
Raw records: /path/to/LockLab/runs/comparative_smoke.jsonl
CSV summary: /path/to/LockLab/runs/comparative_smoke.csv
```

Raw records and CSV summaries are written to:

```text
runs/comparative_smoke.jsonl
runs/comparative_smoke.csv
runs/comparative_matrix.jsonl
runs/comparative_matrix.csv
```

The generated files are ignored by Git. Use JSONL for the complete records and
CSV for spreadsheets or plotting. The command records unsupported, failed,
partial, and timed-out cases instead of silently omitting them.

## Tests

```bash
pytest
```
