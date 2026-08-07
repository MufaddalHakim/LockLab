from __future__ import annotations

import argparse
import json
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from locklab.circuit import CircuitError
from locklab.doctor import run_doctor
from locklab.formats import load_circuit, write_circuit
from locklab.locking import LockResult, lock_rll
from locklab.sat_attack import sat_attack
from locklab.validation import ValidationResult, validate_key


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
        choices=("rll",),
        default="rll",
        help="Logic-locking scheme (default: rll)",
    )
    lock_parser.add_argument("--key-size", type=int, required=True)
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

    validate_parser = subparsers.add_parser(
        "validate",
        help="Check a key against an unlocked reference circuit",
    )
    validate_parser.add_argument("reference", type=Path)
    validate_parser.add_argument("candidate", type=Path)
    validate_parser.add_argument("--key", required=True)
    validate_parser.add_argument("--reference-top")
    validate_parser.add_argument("--candidate-top")
    validate_parser.add_argument("--random-vectors", type=int, default=1000)
    validate_parser.add_argument("--seed", type=int, default=0)

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
        if args.command == "validate":
            passed = _run_validate(args)
            raise SystemExit(0 if passed else 1)
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


def _run_lock(args: argparse.Namespace) -> None:
    output = _default_lock_output(args.circuit)
    metadata = output.with_suffix(".lock.json")

    source = load_circuit(args.circuit, top=args.top)
    if args.scheme != "rll":
        raise CircuitError(f"unsupported locking scheme: {args.scheme}")
    lock_result = lock_rll(source, key_size=args.key_size, seed=args.seed)

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
    print(f"Distinguishing inputs: {len(result.observations)}")
    print(f"SAT solver calls: {result.solver_calls}")
    print(
        f"Validation: PASS ({result.validation.method}, "
        f"{result.validation.vectors_checked} vectors)"
    )


def _run_validate(args: argparse.Namespace) -> bool:
    reference = load_circuit(args.reference, top=args.reference_top)
    candidate = load_circuit(args.candidate, top=args.candidate_top)
    key = _parse_key(args.key)
    key_inputs = tuple(name for name in candidate.inputs if name not in reference.inputs)
    result = validate_key(
        reference,
        candidate,
        key_inputs=key_inputs,
        key=key,
        random_vectors=args.random_vectors,
        seed=args.seed,
    )
    if result.passed:
        print(f"PASS: circuits matched for {result.vectors_checked} vectors")
        print(f"Method: {result.method}")
        return True

    print(f"FAIL: found mismatches using {result.method} validation")
    for mismatch in result.mismatches[:5]:
        print(
            f"  input={mismatch.inputs} reference={mismatch.reference_output} "
            f"candidate={mismatch.candidate_output}"
        )
    return False


def _parse_key(text: str) -> tuple[int, ...]:
    if not text or any(character not in "01" for character in text):
        raise CircuitError("key must be a non-empty binary string")
    return tuple(int(character) for character in text)


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
            }
            for insertion in lock_result.insertions
        ],
        "validation": {
            "passed": validation.passed,
            "method": validation.method,
            "vectors_checked": validation.vectors_checked,
        },
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
