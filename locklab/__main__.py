from __future__ import annotations

import argparse
import json
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from locklab.circuit import CircuitError
from locklab.doctor import run_doctor
from locklab.formats import load_circuit, write_circuit
from locklab.locking import LockResult, lock_mux, lock_rll
from locklab.sat_attack import sat_attack
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
        choices=("rll", "mux"),
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
    if args.scheme == "rll":
        lock_result = lock_rll(source, key_size=args.key_size, seed=args.seed)
    elif args.scheme == "mux":
        lock_result = lock_mux(source, key_size=args.key_size, seed=args.seed)
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
    print("Validation: PASS (formal SAT miter UNSAT)")


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
    metadata_path = candidate.with_suffix(".lock.json")
    if not metadata_path.is_file():
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CircuitError(f"cannot read lock metadata {metadata_path}: {error}") from error
    if not isinstance(metadata, dict) or not isinstance(metadata.get("key"), str):
        raise CircuitError(f"lock metadata has no valid key: {metadata_path}")
    return _parse_key(metadata["key"])


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
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
