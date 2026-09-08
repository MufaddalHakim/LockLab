from __future__ import annotations

import argparse
import json
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from locklab.analysis import (
    find_antisat_candidates,
    find_sarlock_candidates,
    find_sfll_hd0_candidates,
    remove_antisat,
    remove_sarlock,
    signal_probability_scores,
)
from locklab.circuit import CircuitError
from locklab.doctor import run_doctor
from locklab.formats import load_circuit, write_circuit
from locklab.locking import (
    LockResult,
    lock_antisat,
    lock_mux,
    lock_rll,
    lock_rll_antisat,
    lock_sarlock,
    lock_sfll_hd,
    lock_sfll_hd0,
)
from locklab.sat_attack import appsat_attack, sat_attack
from locklab.sfll_analysis import assess_sfll_hd0
from locklab.sfll_hd_analysis import (
    confirm_sfll_hd_candidates,
    find_sfll_hd_candidates,
)
from locklab.study import (
    expand_study_cases,
    load_study_configuration,
    run_comparative_study,
)
from locklab.validation import ValidationResult, prove_key_equivalence, validate_key


def package_version() -> str:
    try:
        return version("locklab")
    except PackageNotFoundError:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="locklab",
        description="Lock and analyze combinational logic circuits",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {package_version()}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor", help="Check available EDA tools")

    info_parser = subparsers.add_parser("info", help="Show circuit information")
    info_parser.add_argument("circuit", type=Path)
    info_parser.add_argument("--top", help="Top module for Verilog input")

    lock_parser = subparsers.add_parser("lock", help="Lock a circuit")
    lock_parser.add_argument("circuit", type=Path)
    lock_parser.add_argument("--top", help="Top module for Verilog input")
    lock_parser.add_argument(
        "--scheme",
        choices=(
            "rll",
            "mux",
            "antisat",
            "sarlock",
            "rll-antisat",
            "sfll-hd0",
            "sfll-hd",
        ),
        default="rll",
        help="Logic-locking scheme (default: rll)",
    )
    lock_parser.add_argument("--key-size", type=int, required=True)
    lock_parser.add_argument(
        "--hamming-distance",
        type=int,
        help="Protected Hamming distance for --scheme sfll-hd",
    )
    lock_parser.add_argument("--seed", type=int, default=0)

    attack_parser = subparsers.add_parser("attack", help="Attack a locked circuit")
    attack_subparsers = attack_parser.add_subparsers(
        dest="attack_kind",
        required=True,
    )
    sat_parser = attack_subparsers.add_parser(
        "sat",
        help="Run an oracle-guided SAT attack",
    )
    sat_parser.add_argument("locked", type=Path)
    sat_parser.add_argument("oracle", type=Path)
    appsat_parser = attack_subparsers.add_parser(
        "appsat",
        help="Run an approximate oracle-guided SAT attack",
    )
    appsat_parser.add_argument("locked", type=Path)
    appsat_parser.add_argument("oracle", type=Path)
    appsat_parser.add_argument("--samples", type=int, default=256)
    appsat_parser.add_argument("--threshold", type=float, default=0.01)
    appsat_parser.add_argument("--seed", type=int, default=0)
    structural_parser = attack_subparsers.add_parser(
        "antisat-structural",
        help="Locate a type-0 Anti-SAT block by its gate topology",
    )
    structural_parser.add_argument("locked", type=Path)
    structural_parser.add_argument("--top", help="Top module for Verilog input")
    sarlock_structural_parser = attack_subparsers.add_parser(
        "sarlock-structural",
        help="Locate an explicit SARLock block by its gate topology",
    )
    sarlock_structural_parser.add_argument("locked", type=Path)
    sarlock_structural_parser.add_argument(
        "--top",
        help="Top module for Verilog input",
    )
    sfll_structural_parser = attack_subparsers.add_parser(
        "sfll-structural",
        help="Locate an explicit SFLL-HD0 block by its gate topology",
    )
    sfll_structural_parser.add_argument("locked", type=Path)
    sfll_structural_parser.add_argument(
        "--top",
        help="Top module for Verilog input",
    )
    sfll_functional_parser = attack_subparsers.add_parser(
        "sfll-functional",
        help="Assess exact and synthesized SFLL-HD0 candidates",
    )
    sfll_functional_parser.add_argument("locked", type=Path)
    sfll_functional_parser.add_argument(
        "--top",
        help="Top module for Verilog input",
    )
    sfll_functional_parser.add_argument(
        "--max-key-size",
        type=int,
        default=32,
        help="Largest functional restore cone to assess (default: 32)",
    )
    sfll_fall_parser = attack_subparsers.add_parser(
        "sfll-fall",
        help="Run the FALL functional attack on explicit SFLL-HDh",
    )
    sfll_fall_parser.add_argument("locked", type=Path)
    sfll_fall_parser.add_argument(
        "--hamming-distance",
        type=int,
        required=True,
        help="Known SFLL-HDh distance parameter",
    )
    sfll_fall_parser.add_argument(
        "--top",
        help="Top module for Verilog input",
    )
    sfll_fall_parser.add_argument(
        "--oracle",
        type=Path,
        help="Unlocked reference circuit for formal key confirmation",
    )
    sfll_fall_parser.add_argument(
        "--oracle-top",
        help="Top module for a Verilog oracle",
    )
    sfll_fall_parser.add_argument(
        "--max-key-size",
        type=int,
        default=32,
        help="Largest SFLL key support to analyze (default: 32)",
    )
    sfll_fall_parser.add_argument(
        "--solver-timeout",
        type=float,
        default=30.0,
        help="Timeout for each FALL SAT query (default: 30 seconds)",
    )
    removal_parser = attack_subparsers.add_parser(
        "antisat-remove",
        help="Bypass a structurally recognized type-0 Anti-SAT block",
    )
    removal_parser.add_argument("locked", type=Path)
    removal_parser.add_argument("--top", help="Top module for Verilog input")
    sarlock_removal_parser = attack_subparsers.add_parser(
        "sarlock-remove",
        help="Bypass a structurally recognized SARLock block",
    )
    sarlock_removal_parser.add_argument("locked", type=Path)
    sarlock_removal_parser.add_argument(
        "--top",
        help="Top module for Verilog input",
    )
    sps_parser = attack_subparsers.add_parser(
        "antisat-sps",
        help="Rank Anti-SAT candidates using signal probability skew",
    )
    sps_parser.add_argument("locked", type=Path)
    sps_parser.add_argument("--top", help="Top module for Verilog input")

    validate_parser = subparsers.add_parser(
        "validate",
        help="Check a key against an unlocked reference circuit",
    )
    validate_parser.add_argument("reference", type=Path)
    validate_parser.add_argument("candidate", type=Path)
    validate_parser.add_argument("--key", required=True)
    validate_parser.add_argument("--reference-top")
    validate_parser.add_argument("--candidate-top")

    study_parser = subparsers.add_parser(
        "study",
        help="Run or resume a configured comparative benchmark study",
    )
    study_parser.add_argument("configuration", type=Path)
    study_parser.add_argument(
        "--retry-failures",
        action="store_true",
        help="Retry recorded failed, partial, unsupported, or timed-out cases",
    )
    study_parser.add_argument(
        "--limit",
        type=int,
        help="Run only the first N expanded cases",
    )
    study_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the expanded matrix without creating files",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "doctor":
            raise SystemExit(run_doctor())
        if args.command == "info":
            _run_info(args.circuit, top=args.top)
            return
        if args.command == "lock":
            _run_lock(args)
            return
        if args.command == "attack" and args.attack_kind == "sat":
            _run_sat_attack(args.locked, args.oracle)
            return
        if args.command == "attack" and args.attack_kind == "appsat":
            _run_appsat_attack(args)
            return
        if args.command == "attack" and args.attack_kind == "antisat-structural":
            _run_antisat_structural_attack(args.locked, top=args.top)
            return
        if args.command == "attack" and args.attack_kind == "sarlock-structural":
            _run_sarlock_structural_attack(args.locked, top=args.top)
            return
        if args.command == "attack" and args.attack_kind == "sfll-structural":
            _run_sfll_structural_attack(args.locked, top=args.top)
            return
        if args.command == "attack" and args.attack_kind == "sfll-functional":
            _run_sfll_functional_attack(
                args.locked,
                top=args.top,
                max_key_size=args.max_key_size,
            )
            return
        if args.command == "attack" and args.attack_kind == "sfll-fall":
            confirmed = _run_sfll_fall_attack(
                args.locked,
                hamming_distance=args.hamming_distance,
                top=args.top,
                oracle_path=args.oracle,
                oracle_top=args.oracle_top,
                max_key_size=args.max_key_size,
                solver_timeout_seconds=args.solver_timeout,
            )
            if args.oracle is not None:
                raise SystemExit(0 if confirmed else 1)
            return
        if args.command == "attack" and args.attack_kind == "antisat-remove":
            _run_antisat_removal_attack(args.locked, top=args.top)
            return
        if args.command == "attack" and args.attack_kind == "sarlock-remove":
            _run_sarlock_removal_attack(args.locked, top=args.top)
            return
        if args.command == "attack" and args.attack_kind == "antisat-sps":
            _run_antisat_sps_attack(args.locked, top=args.top)
            return
        if args.command == "validate":
            passed = _run_validate(args)
            raise SystemExit(0 if passed else 1)
        if args.command == "study":
            _run_study(args)
            return
    except (CircuitError, OSError, ValueError) as error:
        parser.exit(1, f"locklab: error: {error}\n")

    parser.error(f"unknown command: {args.command}")


def _run_info(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    gate_counts = Counter(gate.kind for gate in circuit.gates)
    print(f"Circuit: {circuit.name}")
    print(f"Inputs ({len(circuit.inputs)}): {', '.join(circuit.inputs)}")
    print(f"Outputs ({len(circuit.outputs)}): {', '.join(circuit.outputs)}")
    print(f"Gates: {len(circuit.gates)}")
    for kind, count in sorted(gate_counts.items()):
        print(f"  {kind}: {count}")


def _run_study(args: argparse.Namespace) -> None:
    configuration = load_study_configuration(args.configuration)
    cases = expand_study_cases(configuration)
    if args.limit is not None:
        if args.limit <= 0:
            raise CircuitError("study case limit must be greater than zero")
        cases = cases[: args.limit]
    if args.dry_run:
        print(f"Study: {configuration.name}")
        print(f"Expanded cases: {len(cases)}")
        for case in cases:
            distance = (
                "-" if case.hamming_distance is None else case.hamming_distance
            )
            threshold = (
                "-" if case.appsat_threshold is None else case.appsat_threshold
            )
            print(
                f"  {case.identifier}: benchmark={case.benchmark} "
                f"scheme={case.scheme} key={case.key_size} h={distance} "
                f"seed={case.seed} appsat-threshold={threshold}"
            )
        return

    result = run_comparative_study(
        args.configuration,
        retry_failures=args.retry_failures,
        limit=args.limit,
    )
    print(f"Study: {configuration.name}")
    print(f"Planned cases: {result.planned_cases}")
    print(f"Executed cases: {result.executed_cases}")
    print(f"Skipped existing cases: {result.skipped_existing}")
    statuses = ", ".join(
        f"{status}={count}"
        for status, count in sorted(result.status_counts.items())
    )
    print(f"Statuses: {statuses or 'none'}")
    print(f"Raw records: {result.raw_path}")
    print(f"CSV summary: {result.summary_path}")


def _run_lock(args: argparse.Namespace) -> None:
    output = _default_lock_output(args.circuit)
    metadata = output.with_name(output.name + ".lock.json")

    if args.scheme == "sfll-hd" and args.hamming_distance is None:
        raise CircuitError(
            "--hamming-distance is required with --scheme sfll-hd"
        )
    if args.scheme != "sfll-hd" and args.hamming_distance is not None:
        raise CircuitError(
            "--hamming-distance is only valid with --scheme sfll-hd"
        )

    source = load_circuit(args.circuit, top=args.top)
    if args.scheme == "rll":
        lock_result = lock_rll(source, key_size=args.key_size, seed=args.seed)
    elif args.scheme == "mux":
        lock_result = lock_mux(source, key_size=args.key_size, seed=args.seed)
    elif args.scheme == "antisat":
        lock_result = lock_antisat(source, key_size=args.key_size, seed=args.seed)
    elif args.scheme == "sarlock":
        lock_result = lock_sarlock(source, key_size=args.key_size, seed=args.seed)
    elif args.scheme == "rll-antisat":
        lock_result = lock_rll_antisat(
            source,
            key_size=args.key_size,
            seed=args.seed,
        )
    elif args.scheme == "sfll-hd0":
        lock_result = lock_sfll_hd0(
            source,
            key_size=args.key_size,
            seed=args.seed,
        )
    elif args.scheme == "sfll-hd":
        lock_result = lock_sfll_hd(
            source,
            key_size=args.key_size,
            hamming_distance=args.hamming_distance,
            seed=args.seed,
        )
    else:
        raise CircuitError(f"unsupported locking scheme: {args.scheme}")

    output.parent.mkdir(parents=True, exist_ok=True)
    metadata.parent.mkdir(parents=True, exist_ok=True)
    write_circuit(lock_result.circuit, output)

    written_circuit = load_circuit(output)
    key_inputs = tuple(insertion.key_input for insertion in lock_result.insertions)
    validation = validate_key(
        source,
        written_circuit,
        key_inputs=key_inputs,
        key=lock_result.key,
    )
    if not validation.passed:
        raise CircuitError("generated locked circuit failed correct-key validation")

    _write_lock_metadata(metadata, args.scheme, lock_result, validation)
    print(f"Locked circuit: {output}")
    print(f"Scheme: {args.scheme}")
    print(f"Correct key: {lock_result.key_string}")
    if lock_result.hamming_distance is not None:
        print(f"Hamming distance: {lock_result.hamming_distance}")
        print(f"Protected cubes: {lock_result.protected_cube_count}")
    if lock_result.wrong_key_error_vectors is not None:
        print("Wrong-key error cubes: 1")
        print(
            "Complete input vectors per wrong key: "
            f"{lock_result.wrong_key_error_vectors}"
        )
    print(f"Metadata: {metadata}")
    print(
        f"Validation: PASS ({validation.method}, "
        f"{validation.vectors_checked} vectors)"
    )


def _default_lock_output(source: Path) -> Path:
    source = source.expanduser()
    filename = f"{source.stem}_locked{source.suffix.lower()}"
    return (Path.cwd() / "outputs" / filename).resolve()


def _run_sat_attack(locked_path: Path, oracle_path: Path) -> None:
    locked = load_circuit(locked_path)
    oracle = load_circuit(oracle_path)
    result = sat_attack(locked, oracle)
    print(f"Recovered key: {result.key_string}")
    for line in _attack_key_classification(locked_path, result.key):
        print(line)
    print(f"Distinguishing inputs: {len(result.observations)}")
    print(f"SAT solver calls: {result.solver_calls}")
    print("Validation: PASS (formal SAT miter UNSAT)")


def _run_appsat_attack(args: argparse.Namespace) -> None:
    locked = load_circuit(args.locked)
    oracle = load_circuit(args.oracle)
    result = appsat_attack(
        locked,
        oracle,
        samples=args.samples,
        error_threshold=args.threshold,
        seed=args.seed,
    )
    print(f"Recovered key: {result.key_string}")
    if result.validation.passed:
        for line in _attack_key_classification(args.locked, result.key):
            print(line)
    else:
        print("Classification: approximate key (not formally equivalent)")
        metadata = _read_lock_metadata(args.locked)
        if metadata is not None:
            planted_key = _parse_key(metadata["key"])
        else:
            planted_key = None
        if planted_key is not None and len(planted_key) == len(result.key):
            hamming_distance = sum(
                planted_bit != recovered_bit
                for planted_bit, recovered_bit in zip(planted_key, result.key)
            )
            print(f"Hamming distance from planted key: {hamming_distance}")
            component_line = _component_hamming_line(
                metadata,
                planted_key,
                result.key,
            )
            if component_line is not None:
                print(component_line)
    print(f"Termination: {result.termination}")
    print(f"Distinguishing inputs: {result.distinguishing_inputs}")
    print(f"Random oracle queries: {result.random_queries}")
    print(f"Reinforced observations: {result.reinforced_observations}")
    print(f"SAT solver calls: {result.solver_calls}")
    print(
        f"Estimated input error: {result.estimated_error:.4%} "
        f"({result.sampled_mismatches}/{result.sampled_vectors} samples)"
    )
    if result.validation.passed:
        print("Formal equivalence: PASS (SAT miter UNSAT)")
    else:
        print("Formal equivalence: FAIL (approximate result)")


def _run_antisat_structural_attack(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    candidates = find_antisat_candidates(circuit)
    print(f"Anti-SAT structural candidates: {len(candidates)}")
    if not candidates:
        print("No matching type-0 Anti-SAT structure found")
        return

    for index, candidate in enumerate(candidates, start=1):
        print(f"Candidate {index}:")
        print(f"  Protected output: {candidate.protected_output}")
        print(f"  Protected source: {candidate.protected_source}")
        print(f"  Block signal: {candidate.block_signal}")
        print(f"  Function branch: {candidate.function_signal}")
        print(f"  Complement branch: {candidate.complement_signal}")
        print(f"  Branch size: {candidate.branch_size}")
        print(f"  Suspected key size: {candidate.key_size}")
        print(f"  Data inputs: {', '.join(candidate.data_inputs)}")
        print(f"  Suspected key inputs: {', '.join(candidate.key_inputs)}")


def _run_sarlock_structural_attack(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    candidates = find_sarlock_candidates(circuit)
    print(f"SARLock structural candidates: {len(candidates)}")
    if not candidates:
        print("No matching explicit SARLock structure found")
        return

    for index, candidate in enumerate(candidates, start=1):
        print(f"Candidate {index}:")
        print(f"  Protected output: {candidate.protected_output}")
        print(f"  Protected source: {candidate.protected_source}")
        print(f"  Flip signal: {candidate.flip_signal}")
        print(f"  Input equality comparator: {candidate.input_match_signal}")
        print(f"  Planted-key mask: {candidate.key_mask_signal}")
        print(f"  Suspected key size: {candidate.key_size}")
        print(f"  Protected inputs: {', '.join(candidate.protected_inputs)}")
        print(f"  Inferred planted key: {candidate.inferred_key_string}")
        print(f"  Suspected key inputs: {', '.join(candidate.key_inputs)}")
        print("  Key-to-input mapping:")
        for mapping in candidate.mappings:
            print(
                f"    {mapping.key_input} -> {mapping.protected_input} "
                f"(planted bit {mapping.correct_bit})"
            )


def _run_sfll_structural_attack(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    candidates = find_sfll_hd0_candidates(circuit)
    print(f"SFLL-HD0 structural candidates: {len(candidates)}")
    if not candidates:
        print("No matching explicit SFLL-HD0 structure found")
        return

    for index, candidate in enumerate(candidates, start=1):
        print(f"Candidate {index}:")
        print(f"  Protected output: {candidate.protected_output}")
        print(f"  Protected source: {candidate.protected_source}")
        print(f"  Stripped output: {candidate.stripped_output}")
        print(f"  Hardcoded strip matcher: {candidate.strip_match_signal}")
        print(f"  Runtime equality comparator: {candidate.restore_match_signal}")
        print(f"  Suspected key size: {candidate.key_size}")
        print(f"  Protected inputs: {', '.join(candidate.protected_inputs)}")
        print(f"  Inferred protected cube: {candidate.inferred_cube}")
        print(f"  Suspected key inputs: {', '.join(candidate.key_inputs)}")
        print("  Key-to-input mapping:")
        for mapping in candidate.mappings:
            print(
                f"    {mapping.key_input} -> {mapping.protected_input} "
                f"(cube bit {mapping.protected_bit})"
            )


def _run_sfll_functional_attack(
    path: Path,
    *,
    top: str | None,
    max_key_size: int,
) -> None:
    circuit = load_circuit(path, top=top)
    assessments = assess_sfll_hd0(circuit, max_key_size=max_key_size)
    exact_count = sum(
        assessment.match_type == "exact topology"
        for assessment in assessments
    )
    functional_count = len(assessments) - exact_count
    print(f"SFLL-HD0 assessment candidates: {len(assessments)}")
    print(f"Exact topology matches: {exact_count}")
    print(f"Functional candidates: {functional_count}")
    if not assessments:
        print("No exact or formally supported functional SFLL-HD0 candidate found")
        return

    for index, assessment in enumerate(assessments, start=1):
        print(f"Candidate {index}:")
        print(f"  Match type: {assessment.match_type}")
        print(f"  Protected output: {assessment.protected_output}")
        print(f"  Strip matcher: {assessment.strip_match_signal}")
        print(f"  Strip active value: {assessment.strip_active_value}")
        print(f"  Runtime comparator: {assessment.restore_match_signal}")
        print(f"  Restore active value: {assessment.restore_active_value}")
        print(f"  Suspected key size: {assessment.key_size}")
        print(f"  Protected inputs: {', '.join(assessment.protected_inputs)}")
        print(f"  Inferred protected cube: {assessment.inferred_cube}")
        print(f"  Suspected key inputs: {', '.join(assessment.key_inputs)}")
        print("  Key-to-input mapping:")
        for mapping, unateness in zip(
            assessment.mappings,
            assessment.strip_unateness,
        ):
            print(
                f"    {mapping.key_input} -> {mapping.protected_input} "
                f"(cube bit {mapping.protected_bit}, {unateness} unate)"
            )


def _run_sfll_fall_attack(
    path: Path,
    *,
    hamming_distance: int,
    top: str | None,
    oracle_path: Path | None,
    oracle_top: str | None,
    max_key_size: int,
    solver_timeout_seconds: float,
) -> bool:
    if oracle_path is None and oracle_top is not None:
        raise CircuitError("--oracle-top requires --oracle")
    circuit = load_circuit(path, top=top)
    candidates = find_sfll_hd_candidates(
        circuit,
        hamming_distance=hamming_distance,
        max_key_size=max_key_size,
        solver_timeout_seconds=solver_timeout_seconds,
    )
    print(f"FALL SFLL-HDh candidates: {len(candidates)}")
    print(f"Known Hamming distance: {hamming_distance}")
    if not candidates:
        print(
            "No formally verified FALL candidate found; this may be outside "
            "Distance2H/SlidingWindow applicability, or synthesis may have "
            "absorbed the comparison cones."
        )
        return False

    confirmations = (
        confirm_sfll_hd_candidates(
            load_circuit(oracle_path, top=oracle_top),
            circuit,
            candidates,
            solver_timeout_seconds=solver_timeout_seconds,
        )
        if oracle_path is not None
        else ()
    )

    for index, candidate in enumerate(candidates, start=1):
        print(f"Candidate {index}:")
        print(f"  Match type: {candidate.match_type}")
        print(f"  Recovery method: {candidate.recovery_method}")
        print(f"  Protected output: {candidate.protected_output}")
        print(
            "  Protected source: "
            f"{candidate.protected_source or 'unavailable after mapping'}"
        )
        print(
            "  Stripped output: "
            f"{candidate.stripped_output or 'unavailable after mapping'}"
        )
        print(f"  Strip function: {candidate.strip_match_signal}")
        print(f"  Restore function: {candidate.restore_match_signal}")
        print(f"  Key size: {candidate.key_size}")
        print(f"  Protected inputs: {', '.join(candidate.protected_inputs)}")
        print(f"  Recovered key: {candidate.inferred_key_string}")
        print(f"  Protected cubes: {candidate.protected_cube_count}")
        print(f"  FALL SAT solver calls: {candidate.solver_calls}")
        print("  Key-to-input mapping:")
        for mapping, bit in zip(
            candidate.mappings,
            candidate.inferred_key,
        ):
            print(
                f"    {mapping.key_input} -> {mapping.protected_input} "
                f"(key bit {bit})"
            )
        if confirmations:
            validation = confirmations[index - 1].validation
            if validation.passed:
                print("  Oracle confirmation: PASS (formal SAT miter UNSAT)")
            else:
                mismatch = validation.mismatches[0]
                print("  Oracle confirmation: FAIL")
                print(f"  Distinguishing input: {mismatch.inputs}")
                print(f"  Oracle output: {mismatch.reference_output}")
                print(f"  Candidate output: {mismatch.candidate_output}")

    return not confirmations or any(
        confirmation.validation.passed for confirmation in confirmations
    )


def _run_antisat_removal_attack(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    result = remove_antisat(circuit)
    output = _default_antisat_removal_output(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_circuit(result.circuit, output)

    written_circuit = load_circuit(output)
    if find_antisat_candidates(written_circuit):
        raise CircuitError("recovered circuit still contains an Anti-SAT candidate")

    print(f"Recovered circuit: {output}")
    print(f"Removed Anti-SAT blocks: {len(result.candidates)}")
    print(f"Removed gates: {result.removed_gate_count}")
    print(f"Removed suspected key inputs: {len(result.removed_inputs)}")
    print(f"Remaining inputs: {len(result.circuit.inputs)}")


def _default_antisat_removal_output(source: Path) -> Path:
    source = source.expanduser()
    base_name = source.stem.removesuffix("_locked")
    filename = f"{base_name}_antisat_removed{source.suffix.lower()}"
    return (Path.cwd() / "outputs" / filename).resolve()


def _run_sarlock_removal_attack(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    result = remove_sarlock(circuit)
    output = _default_sarlock_removal_output(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_circuit(result.circuit, output)

    written_circuit = load_circuit(output)
    if find_sarlock_candidates(written_circuit):
        raise CircuitError("recovered circuit still contains a SARLock candidate")

    print(f"Recovered circuit: {output}")
    print(f"Removed SARLock blocks: {len(result.candidates)}")
    print(f"Removed gates: {result.removed_gate_count}")
    print(f"Removed suspected key inputs: {len(result.removed_inputs)}")
    print(f"Remaining inputs: {len(result.circuit.inputs)}")


def _default_sarlock_removal_output(source: Path) -> Path:
    source = source.expanduser()
    base_name = source.stem.removesuffix("_locked")
    filename = f"{base_name}_sarlock_removed{source.suffix.lower()}"
    return (Path.cwd() / "outputs" / filename).resolve()


def _run_antisat_sps_attack(path: Path, *, top: str | None) -> None:
    circuit = load_circuit(path, top=top)
    scores = signal_probability_scores(circuit)
    if not scores:
        print("SPS candidates: 0")
        return

    maximum_ads = scores[0].ads
    candidate_count = sum(
        abs(score.ads - maximum_ads) <= 1e-12 for score in scores
    )
    shown_scores = scores[:5]
    print("Probability model: independent primary/key inputs with P(1)=0.5")
    print(f"Highest ADS: {maximum_ads:.6f}")
    print(f"Candidates at highest ADS: {candidate_count}")
    print(f"SPS ranking: top {len(shown_scores)} of {len(scores)} gates")
    for rank, score in enumerate(shown_scores, start=1):
        input_skews = ", ".join(
            f"{input_skew:+.6f}" for input_skew in score.input_skews
        )
        print(
            f"  {rank}. {score.signal} [{score.gate_kind}] "
            f"ADS={score.ads:.6f} P(1)={score.probability_one:.6f} "
            f"skew={score.skew:+.6f} inputs=({input_skews})"
        )


def _run_validate(args: argparse.Namespace) -> bool:
    reference = load_circuit(args.reference, top=args.reference_top)
    candidate = load_circuit(args.candidate, top=args.candidate_top)
    key = _parse_key(args.key)
    key_inputs = tuple(name for name in candidate.inputs if name not in reference.inputs)
    result = prove_key_equivalence(
        reference,
        candidate,
        key_inputs=key_inputs,
        key=key,
    )
    if result.passed:
        planted_key = _read_planted_key(args.candidate)
        if planted_key is not None and len(planted_key) != len(key):
            raise CircuitError("lock metadata key length does not match candidate key")
        if planted_key is None:
            print("PASS: key is formally equivalent to the reference circuit")
        elif key == planted_key:
            print("PASS: exact planted key is formally equivalent")
        else:
            hamming_distance = sum(
                candidate_bit != planted_bit
                for candidate_bit, planted_bit in zip(key, planted_key)
            )
            print("PASS: alternative key is formally equivalent")
            print(f"Difference from planted key: {hamming_distance} bit(s)")
        print("Proof: SAT miter is UNSAT")
        return True

    mismatch = result.mismatches[0]
    print("FAIL: key is not functionally equivalent")
    print(
        f"Counterexample: input={mismatch.inputs} "
        f"reference={mismatch.reference_output} "
        f"candidate={mismatch.candidate_output}"
    )
    print("Proof: SAT miter is SAT")
    return False


def _parse_key(text: str) -> tuple[int, ...]:
    if not text or any(character not in "01" for character in text):
        raise CircuitError("key must be a non-empty binary string")
    return tuple(int(character) for character in text)


def _read_planted_key(candidate: Path) -> tuple[int, ...] | None:
    metadata = _read_lock_metadata(candidate)
    if metadata is None:
        return None
    return _parse_key(metadata["key"])


def _read_lock_metadata(candidate: Path) -> dict[str, object] | None:
    metadata_path = candidate.with_name(candidate.name + ".lock.json")
    if not metadata_path.is_file():
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CircuitError(f"cannot read lock metadata {metadata_path}: {error}") from error
    if not isinstance(metadata, dict) or not isinstance(metadata.get("key"), str):
        raise CircuitError(f"lock metadata has no valid key: {metadata_path}")
    return metadata


def _attack_key_classification(
    locked_path: Path,
    recovered_key: tuple[int, ...],
) -> tuple[str, ...]:
    metadata = _read_lock_metadata(locked_path)
    if metadata is None:
        return ("Classification: unavailable (no lock metadata)",)

    planted_key = _parse_key(metadata["key"])
    if len(planted_key) != len(recovered_key):
        raise CircuitError("lock metadata key length does not match recovered key")
    if planted_key == recovered_key:
        return ("Classification: exact planted key",)

    changed_indices = tuple(
        index
        for index, (planted_bit, recovered_bit) in enumerate(
            zip(planted_key, recovered_key)
        )
        if planted_bit != recovered_bit
    )
    lines = [
        "Classification: functionally equivalent alternative key",
        f"Hamming distance: {len(changed_indices)}",
    ]
    component_line = _component_hamming_line(
        metadata,
        planted_key,
        recovered_key,
    )
    if component_line is not None:
        lines.append(component_line)
    lines.append(
        "Changed key bits (zero-based): "
        + ", ".join(map(str, changed_indices))
    )

    insertion_records = metadata.get("insertions")
    if not isinstance(insertion_records, list):
        return tuple(lines)
    insertions = {
        record.get("key_index"): record
        for record in insertion_records
        if isinstance(record, dict) and isinstance(record.get("key_index"), int)
    }
    details: list[str] = []
    for index in changed_indices:
        insertion = insertions.get(index)
        if insertion is None:
            continue
        key_input = insertion.get("key_input")
        protected_signal = insertion.get("protected_signal")
        if not isinstance(key_input, str) or not isinstance(protected_signal, str):
            continue
        detail = f"  bit {index}: {key_input} protects {protected_signal}"
        decoy_signal = insertion.get("decoy_signal")
        if isinstance(decoy_signal, str):
            detail += f", decoy {decoy_signal}"
        details.append(detail)
    if details:
        lines.append("Changed insertions:")
        lines.extend(details)
    return tuple(lines)


def _component_hamming_line(
    metadata: dict[str, object],
    planted_key: tuple[int, ...],
    recovered_key: tuple[int, ...],
) -> str | None:
    components = metadata.get("components")
    if not isinstance(components, dict):
        return None
    rll_size = components.get("rll_key_size")
    antisat_size = components.get("antisat_key_size")
    if (
        not isinstance(rll_size, int)
        or not isinstance(antisat_size, int)
        or rll_size + antisat_size != len(planted_key)
    ):
        return None
    rll_distance = sum(
        planted_bit != recovered_bit
        for planted_bit, recovered_bit in zip(
            planted_key[:rll_size],
            recovered_key[:rll_size],
        )
    )
    antisat_distance = sum(
        planted_bit != recovered_bit
        for planted_bit, recovered_bit in zip(
            planted_key[rll_size:],
            recovered_key[rll_size:],
        )
    )
    return (
        "Component Hamming distance: "
        f"RLL {rll_distance}, Anti-SAT {antisat_distance}"
    )


def _write_lock_metadata(
    path: Path,
    scheme: str,
    lock_result: LockResult,
    validation: ValidationResult,
) -> None:
    payload = {
        "scheme": scheme,
        "key": lock_result.key_string,
        "seed": lock_result.seed,
        "key_inputs": [
            insertion.key_input for insertion in lock_result.insertions
        ],
        "insertions": [
            {
                "key_index": insertion.key_index,
                "key_input": insertion.key_input,
                "correct_bit": insertion.correct_bit,
                "gate": insertion.gate_kind,
                "protected_signal": insertion.protected_signal,
                "source_signal": insertion.source_signal,
                **(
                    {"decoy_signal": insertion.decoy_signal}
                    if insertion.decoy_signal is not None
                    else {}
                ),
            }
            for insertion in lock_result.insertions
        ],
        "validation": {
            "passed": validation.passed,
            "method": validation.method,
            "vectors_checked": validation.vectors_checked,
        },
    }
    if scheme == "rll-antisat":
        component_size = len(lock_result.key) // 2
        payload["components"] = {
            "rll_key_size": component_size,
            "antisat_key_size": component_size,
        }
        for insertion in payload["insertions"]:
            insertion["component"] = (
                "rll" if insertion["key_index"] < component_size else "antisat"
            )
    if lock_result.hamming_distance is not None:
        payload["sfll"] = {
            "key_size": len(lock_result.key),
            "hamming_distance": lock_result.hamming_distance,
            "protected_cube_count": lock_result.protected_cube_count,
            "selected_inputs": [
                insertion.source_signal
                for insertion in lock_result.insertions
            ],
        }
    if lock_result.sarlock_flip_signal is not None:
        payload["sarlock"] = {
            "key_size": len(lock_result.key),
            "selected_inputs": [
                insertion.source_signal
                for insertion in lock_result.insertions
            ],
            "protected_output": lock_result.insertions[0].protected_signal,
            "input_match_signal": lock_result.sarlock_input_match_signal,
            "key_mask_signal": lock_result.sarlock_key_mask_signal,
            "flip_signal": lock_result.sarlock_flip_signal,
            "wrong_key_error_cubes": 1,
            "wrong_key_error_vectors": lock_result.wrong_key_error_vectors,
        }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
