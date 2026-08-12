from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from locklab.analysis import (
    find_antisat_candidates,
    find_sfll_hd0_candidates,
    signal_probability_scores,
)
from locklab.circuit import Circuit, CircuitError
from locklab.doctor import TOOLS, get_version
from locklab.formats import load_circuit
from locklab.locking import (
    LockResult,
    lock_antisat,
    lock_mux,
    lock_rll,
    lock_rll_antisat,
    lock_sfll_hd,
    lock_sfll_hd0,
)
from locklab.sat_attack import appsat_attack, sat_attack
from locklab.sat_solver import SatSolverError
from locklab.sfll_analysis import assess_sfll_hd0
from locklab.validation import prove_key_equivalence


STUDY_SCHEMA_VERSION = 1
SUPPORTED_SCHEMES = {
    "rll",
    "mux",
    "antisat",
    "rll-antisat",
    "sfll-hd0",
    "sfll-hd",
}


@dataclass(frozen=True)
class SchemeMatrix:
    name: str
    key_sizes: tuple[int, ...]
    hamming_distances: tuple[int, ...] = ()


@dataclass(frozen=True)
class AppSatMatrix:
    enabled: bool
    samples: int
    thresholds: tuple[float, ...]


@dataclass(frozen=True)
class StudyConfiguration:
    name: str
    benchmark_root: Path
    benchmarks: tuple[str, ...]
    seeds: tuple[int, ...]
    schemes: tuple[SchemeMatrix, ...]
    exact_sat: bool
    appsat: AppSatMatrix
    solver_timeout_seconds: float


@dataclass(frozen=True)
class StudyCase:
    benchmark: str
    scheme: str
    key_size: int
    seed: int
    hamming_distance: int | None
    appsat_threshold: float | None
    appsat_samples: int | None
    exact_sat: bool
    solver_timeout_seconds: float

    @property
    def identifier(self) -> str:
        payload = {
            "schema_version": STUDY_SCHEMA_VERSION,
            **asdict(self),
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:16]


@dataclass(frozen=True)
class StudyRunResult:
    raw_path: Path
    summary_path: Path
    planned_cases: int
    executed_cases: int
    skipped_existing: int
    status_counts: dict[str, int]


SUMMARY_FIELDS = (
    "case_id",
    "study",
    "status",
    "benchmark",
    "benchmark_sha256",
    "scheme",
    "key_size",
    "hamming_distance",
    "seed",
    "appsat_threshold",
    "appsat_samples",
    "original_gates",
    "locked_gates",
    "added_gates",
    "added_primary_inputs",
    "protected_cube_count",
    "locking_seconds",
    "formal_equivalent",
    "formal_seconds",
    "exact_status",
    "exact_key",
    "exact_key_hamming_distance",
    "exact_functionally_equivalent",
    "exact_distinguishing_inputs",
    "exact_solver_calls",
    "exact_seconds",
    "appsat_status",
    "appsat_key",
    "appsat_key_hamming_distance",
    "appsat_sampled_error",
    "appsat_formal_equivalent",
    "appsat_distinguishing_inputs",
    "appsat_solver_calls",
    "appsat_seconds",
    "sps_top_signal",
    "sps_max_ads",
    "sps_target_signal",
    "sps_target_rank",
    "antisat_structural_candidates",
    "sfll_exact_candidates",
    "sfll_functional_candidates",
    "total_seconds",
    "configuration_sha256",
    "git_commit",
    "git_dirty",
    "anomalies",
)


def load_study_configuration(path: Path) -> StudyConfiguration:
    """Read and strictly validate a comparative-study JSON configuration."""

    source = path.expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CircuitError(f"cannot read study configuration {path}: {error}") from error
    if not isinstance(payload, dict):
        raise CircuitError("study configuration must be a JSON object")

    name = _required_string(payload, "name")
    if not all(character.isalnum() or character in {"-", "_"} for character in name):
        raise CircuitError(
            "study name may contain only letters, numbers, hyphens, and underscores"
        )

    benchmark_root_value = payload.get(
        "benchmark_root",
        "benchmarks/sources/iscas85",
    )
    if not isinstance(benchmark_root_value, str) or not benchmark_root_value:
        raise CircuitError("benchmark_root must be a non-empty string")
    benchmark_root = Path(benchmark_root_value)
    if not benchmark_root.is_absolute():
        benchmark_root = (source.parent / benchmark_root).resolve()

    benchmarks = _string_tuple(payload, "benchmarks")
    seeds = _integer_tuple(payload, "seeds")
    schemes_payload = payload.get("schemes")
    if not isinstance(schemes_payload, list) or not schemes_payload:
        raise CircuitError("schemes must be a non-empty list")
    schemes = tuple(_parse_scheme(item) for item in schemes_payload)

    exact_sat = payload.get("exact_sat", True)
    if not isinstance(exact_sat, bool):
        raise CircuitError("exact_sat must be true or false")

    appsat_payload = payload.get("appsat", {"enabled": False})
    if not isinstance(appsat_payload, dict):
        raise CircuitError("appsat must be a JSON object")
    appsat_enabled = appsat_payload.get("enabled", False)
    if not isinstance(appsat_enabled, bool):
        raise CircuitError("appsat.enabled must be true or false")
    appsat_samples = appsat_payload.get("samples", 256)
    if not isinstance(appsat_samples, int) or appsat_samples <= 0:
        raise CircuitError("appsat.samples must be a positive integer")
    thresholds_value = appsat_payload.get("thresholds", [0.01])
    if not isinstance(thresholds_value, list) or not thresholds_value:
        raise CircuitError("appsat.thresholds must be a non-empty list")
    thresholds: list[float] = []
    for threshold in thresholds_value:
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            raise CircuitError("AppSAT thresholds must be numbers")
        numeric_threshold = float(threshold)
        if not 0.0 <= numeric_threshold <= 1.0:
            raise CircuitError("AppSAT thresholds must be between zero and one")
        thresholds.append(numeric_threshold)

    timeout = payload.get("solver_timeout_seconds", 30.0)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise CircuitError("solver_timeout_seconds must be greater than zero")

    return StudyConfiguration(
        name=name,
        benchmark_root=benchmark_root,
        benchmarks=benchmarks,
        seeds=seeds,
        schemes=schemes,
        exact_sat=exact_sat,
        appsat=AppSatMatrix(
            enabled=appsat_enabled,
            samples=appsat_samples,
            thresholds=tuple(thresholds),
        ),
        solver_timeout_seconds=float(timeout),
    )


def expand_study_cases(configuration: StudyConfiguration) -> tuple[StudyCase, ...]:
    """Expand the declared matrix in deterministic order."""

    cases: list[StudyCase] = []
    app_dimensions: tuple[tuple[float | None, int | None], ...]
    if configuration.appsat.enabled:
        app_dimensions = tuple(
            (threshold, configuration.appsat.samples)
            for threshold in configuration.appsat.thresholds
        )
    else:
        app_dimensions = ((None, None),)

    for benchmark in configuration.benchmarks:
        for scheme in configuration.schemes:
            distances = (
                scheme.hamming_distances
                if scheme.name == "sfll-hd"
                else (None,)
            )
            for key_size in scheme.key_sizes:
                for distance in distances:
                    for seed in configuration.seeds:
                        for threshold, samples in app_dimensions:
                            cases.append(
                                StudyCase(
                                    benchmark=benchmark,
                                    scheme=scheme.name,
                                    key_size=key_size,
                                    seed=seed,
                                    hamming_distance=distance,
                                    appsat_threshold=threshold,
                                    appsat_samples=samples,
                                    exact_sat=configuration.exact_sat,
                                    solver_timeout_seconds=(
                                        configuration.solver_timeout_seconds
                                    ),
                                )
                            )
    return tuple(cases)


def run_comparative_study(
    configuration_path: Path,
    *,
    output_directory: Path | None = None,
    retry_failures: bool = False,
    limit: int | None = None,
) -> StudyRunResult:
    """Run or resume a study, append raw records, and rebuild its CSV summary."""

    configuration = load_study_configuration(configuration_path)
    cases = expand_study_cases(configuration)
    if limit is not None:
        if limit <= 0:
            raise CircuitError("study case limit must be greater than zero")
        cases = cases[:limit]

    destination = (
        output_directory.expanduser().resolve()
        if output_directory is not None
        else (Path.cwd() / "runs").resolve()
    )
    destination.mkdir(parents=True, exist_ok=True)
    raw_path = destination / f"{configuration.name}.jsonl"
    summary_path = destination / f"{configuration.name}.csv"
    existing = _read_raw_records(raw_path)
    environment = _environment_record()
    config_digest = hashlib.sha256(
        configuration_path.expanduser().resolve().read_bytes()
    ).hexdigest()
    existing_digests = {
        record.get("configuration_sha256") for record in existing.values()
    }
    if existing_digests and existing_digests != {config_digest}:
        raise CircuitError(
            "existing study records use a different configuration; "
            "choose a new study name or remove the old generated run files"
        )

    executed_cases = 0
    skipped_existing = 0
    with raw_path.open("a", encoding="utf-8") as raw_file:
        for case in cases:
            previous = existing.get(case.identifier)
            if previous is not None and (
                not retry_failures or previous.get("status") == "completed"
            ):
                skipped_existing += 1
                continue
            record = _run_case(
                configuration,
                case,
                environment=environment,
                config_digest=config_digest,
            )
            raw_file.write(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            )
            raw_file.flush()
            existing[case.identifier] = record
            executed_cases += 1

    _write_summary(summary_path, existing)
    status_counts: dict[str, int] = {}
    selected_ids = {case.identifier for case in cases}
    for case_id, record in existing.items():
        if case_id not in selected_ids:
            continue
        status = str(record.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
    return StudyRunResult(
        raw_path=raw_path,
        summary_path=summary_path,
        planned_cases=len(cases),
        executed_cases=executed_cases,
        skipped_existing=skipped_existing,
        status_counts=status_counts,
    )


def _run_case(
    configuration: StudyConfiguration,
    case: StudyCase,
    *,
    environment: dict[str, object],
    config_digest: str,
) -> dict[str, object]:
    started_wall = datetime.now(timezone.utc)
    started = time.perf_counter()
    metrics: dict[str, object] = {}
    anomalies: list[dict[str, str]] = []
    phase = "load"

    try:
        benchmark_path = configuration.benchmark_root / f"{case.benchmark}.bench"
        benchmark_sha256 = hashlib.sha256(benchmark_path.read_bytes()).hexdigest()
        oracle = load_circuit(benchmark_path)
        metrics.update(
            {
                "benchmark_sha256": benchmark_sha256,
                "original_inputs": len(oracle.inputs),
                "original_outputs": len(oracle.outputs),
                "original_gates": len(oracle.gates),
            }
        )

        phase = "locking"
        phase_started = time.perf_counter()
        try:
            lock_result = _lock_case(oracle, case)
        except CircuitError as error:
            return _record(
                case,
                study_name=configuration.name,
                status="unsupported",
                phase=phase,
                started_wall=started_wall,
                total_seconds=time.perf_counter() - started,
                metrics=metrics,
                anomalies=(
                    {
                        "phase": phase,
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                ),
                environment=environment,
                config_digest=config_digest,
            )
        metrics["locking_seconds"] = time.perf_counter() - phase_started
        locked = lock_result.circuit
        key_inputs = tuple(
            insertion.key_input for insertion in lock_result.insertions
        )
        metrics.update(
            {
                "locked_gates": len(locked.gates),
                "added_gates": len(locked.gates) - len(oracle.gates),
                "added_primary_inputs": len(locked.inputs) - len(oracle.inputs),
                "planted_key": lock_result.key_string,
                "protected_cube_count": lock_result.protected_cube_count,
            }
        )

        phase = "formal-validation"
        phase_started = time.perf_counter()
        formal = prove_key_equivalence(
            oracle,
            locked,
            key_inputs=key_inputs,
            key=lock_result.key,
            solver_timeout_seconds=configuration.solver_timeout_seconds,
        )
        metrics["formal_seconds"] = time.perf_counter() - phase_started
        metrics["formal_equivalent"] = formal.passed
        if not formal.passed:
            raise CircuitError("planted key failed formal equivalence")

        phase = "structural-analysis"
        analysis_started = time.perf_counter()
        antisat_candidates = find_antisat_candidates(locked)
        sfll_exact_candidates = find_sfll_hd0_candidates(locked)
        metrics["antisat_structural_candidates"] = len(antisat_candidates)
        metrics["sfll_exact_candidates"] = len(sfll_exact_candidates)
        if case.scheme == "sfll-hd0":
            metrics["sfll_functional_candidates"] = len(
                assess_sfll_hd0(
                    locked,
                    max_key_size=max(32, case.key_size),
                    solver_timeout_seconds=configuration.solver_timeout_seconds,
                )
            )
        else:
            metrics["sfll_functional_candidates"] = None
        metrics["structural_analysis_seconds"] = (
            time.perf_counter() - analysis_started
        )

        phase = "sps-analysis"
        sps_started = time.perf_counter()
        scores = signal_probability_scores(locked)
        target_signal = _analysis_target(
            lock_result,
            antisat_candidates=antisat_candidates,
            sfll_exact_candidates=sfll_exact_candidates,
        )
        metrics["sps_top_signal"] = scores[0].signal if scores else None
        metrics["sps_max_ads"] = scores[0].ads if scores else None
        metrics["sps_target_signal"] = target_signal
        target_entry = next(
            (
                (rank, score.ads)
                for rank, score in enumerate(scores, start=1)
                if score.signal == target_signal
            ),
            None,
        )
        metrics["sps_target_rank"] = target_entry[0] if target_entry else None
        metrics["sps_target_ads"] = target_entry[1] if target_entry else None
        metrics["sps_seconds"] = time.perf_counter() - sps_started

        if case.exact_sat:
            phase = "exact-sat"
            exact_started = time.perf_counter()
            try:
                exact = sat_attack(
                    locked,
                    oracle,
                    solver_timeout_seconds=configuration.solver_timeout_seconds,
                )
                metrics.update(
                    {
                        "exact_status": "completed",
                        "exact_key": exact.key_string,
                        "exact_key_hamming_distance": _hamming_distance(
                            exact.key,
                            lock_result.key,
                        ),
                        "exact_functionally_equivalent": exact.validation.passed,
                        "exact_distinguishing_inputs": len(exact.observations),
                        "exact_solver_calls": exact.solver_calls,
                    }
                )
            except (CircuitError, SatSolverError) as error:
                metrics["exact_status"] = _measurement_failure_status(error)
                anomalies.append(_anomaly(phase, error))
            metrics["exact_seconds"] = time.perf_counter() - exact_started
        else:
            metrics["exact_status"] = "not-requested"

        if configuration.appsat.enabled:
            phase = "appsat"
            appsat_started = time.perf_counter()
            try:
                approximate = appsat_attack(
                    locked,
                    oracle,
                    samples=case.appsat_samples or configuration.appsat.samples,
                    error_threshold=(
                        case.appsat_threshold
                        if case.appsat_threshold is not None
                        else configuration.appsat.thresholds[0]
                    ),
                    seed=case.seed,
                    solver_timeout_seconds=configuration.solver_timeout_seconds,
                )
                metrics.update(
                    {
                        "appsat_status": "completed",
                        "appsat_key": approximate.key_string,
                        "appsat_key_hamming_distance": _hamming_distance(
                            approximate.key,
                            lock_result.key,
                        ),
                        "appsat_sampled_error": approximate.estimated_error,
                        "appsat_formal_equivalent": approximate.validation.passed,
                        "appsat_distinguishing_inputs": (
                            approximate.distinguishing_inputs
                        ),
                        "appsat_solver_calls": approximate.solver_calls,
                        "appsat_termination": approximate.termination,
                    }
                )
            except (CircuitError, SatSolverError) as error:
                metrics["appsat_status"] = _measurement_failure_status(error)
                anomalies.append(_anomaly(phase, error))
            metrics["appsat_seconds"] = time.perf_counter() - appsat_started
        else:
            metrics["appsat_status"] = "not-requested"

        status = "completed" if not anomalies else "partial"
        return _record(
            case,
            study_name=configuration.name,
            status=status,
            phase="complete",
            started_wall=started_wall,
            total_seconds=time.perf_counter() - started,
            metrics=metrics,
            anomalies=tuple(anomalies),
            environment=environment,
            config_digest=config_digest,
        )
    except (CircuitError, OSError, ValueError, SatSolverError) as error:
        anomalies.append(_anomaly(phase, error))
        return _record(
            case,
            study_name=configuration.name,
            status="failed",
            phase=phase,
            started_wall=started_wall,
            total_seconds=time.perf_counter() - started,
            metrics=metrics,
            anomalies=tuple(anomalies),
            environment=environment,
            config_digest=config_digest,
        )


def _lock_case(oracle: Circuit, case: StudyCase) -> LockResult:
    if case.scheme == "rll":
        return lock_rll(oracle, key_size=case.key_size, seed=case.seed)
    if case.scheme == "mux":
        return lock_mux(oracle, key_size=case.key_size, seed=case.seed)
    if case.scheme == "antisat":
        return lock_antisat(oracle, key_size=case.key_size, seed=case.seed)
    if case.scheme == "rll-antisat":
        return lock_rll_antisat(oracle, key_size=case.key_size, seed=case.seed)
    if case.scheme == "sfll-hd0":
        return lock_sfll_hd0(oracle, key_size=case.key_size, seed=case.seed)
    if case.scheme == "sfll-hd":
        if case.hamming_distance is None:
            raise CircuitError("SFLL-HD study case is missing a Hamming distance")
        return lock_sfll_hd(
            oracle,
            key_size=case.key_size,
            hamming_distance=case.hamming_distance,
            seed=case.seed,
        )
    raise CircuitError(f"unsupported study scheme: {case.scheme}")


def _analysis_target(
    lock_result: LockResult,
    *,
    antisat_candidates: tuple[Any, ...],
    sfll_exact_candidates: tuple[Any, ...],
) -> str | None:
    if antisat_candidates:
        return str(antisat_candidates[0].block_signal)
    if sfll_exact_candidates:
        return str(sfll_exact_candidates[0].strip_match_signal)
    return lock_result.restore_match_signal


def _record(
    case: StudyCase,
    *,
    study_name: str,
    status: str,
    phase: str,
    started_wall: datetime,
    total_seconds: float,
    metrics: dict[str, object],
    anomalies: tuple[dict[str, str], ...],
    environment: dict[str, object],
    config_digest: str,
) -> dict[str, object]:
    return {
        "material_passport": {
            "origin_skill": "experiment-agent",
            "origin_mode": "run",
            "verification_status": (
                "VERIFIED" if status == "completed" else "ANALYZED"
            ),
            "schema": "locklab-study-v1",
        },
        "schema_version": STUDY_SCHEMA_VERSION,
        "study": study_name,
        "case_id": case.identifier,
        "status": status,
        "phase": phase,
        "case": asdict(case),
        "metrics": metrics,
        "anomalies": list(anomalies),
        "started_at": started_wall.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "total_seconds": total_seconds,
        "configuration_sha256": config_digest,
        "environment": environment,
    }


def _read_raw_records(path: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    if not path.exists():
        return records
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CircuitError(f"cannot read existing study records {path}: {error}") from error
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CircuitError(
                f"invalid JSON in {path} at line {line_number}: {error}"
            ) from error
        if not isinstance(record, dict) or not isinstance(record.get("case_id"), str):
            raise CircuitError(
                f"invalid study record in {path} at line {line_number}"
            )
        records[record["case_id"]] = record
    return records


def _write_summary(
    path: Path,
    records: dict[str, dict[str, object]],
) -> None:
    temporary = path.with_suffix(".csv.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        for case_id, record in sorted(records.items()):
            writer.writerow(_summary_row(case_id, record))
    temporary.replace(path)


def _summary_row(
    case_id: str,
    record: dict[str, object],
) -> dict[str, object]:
    case = record.get("case")
    metrics = record.get("metrics")
    if not isinstance(case, dict):
        case = {}
    if not isinstance(metrics, dict):
        metrics = {}
    row: dict[str, object] = {
        "case_id": case_id,
        "study": record.get("study"),
        "status": record.get("status"),
        "total_seconds": record.get("total_seconds"),
        "configuration_sha256": record.get("configuration_sha256"),
        "anomalies": json.dumps(record.get("anomalies", []), sort_keys=True),
    }
    environment = record.get("environment")
    if not isinstance(environment, dict):
        environment = {}
    row["git_commit"] = environment.get("git_commit")
    row["git_dirty"] = environment.get("git_dirty")
    for field in (
        "benchmark",
        "scheme",
        "key_size",
        "hamming_distance",
        "seed",
        "appsat_threshold",
        "appsat_samples",
    ):
        row[field] = case.get(field)
    for field in SUMMARY_FIELDS:
        if field not in row:
            row[field] = metrics.get(field)
    return row


def _environment_record() -> dict[str, object]:
    repository = Path(__file__).resolve().parents[1]
    git_commit = _git_output(repository, "rev-parse", "HEAD")
    git_status = _git_output(repository, "status", "--porcelain")
    tool_versions = {
        tool.command: get_version(tool)
        for tool in TOOLS
        if tool.command in {"git", "yosys", "yices-sat"}
    }
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "git_commit": git_commit,
        "git_dirty": bool(git_status),
        "tools": tool_versions,
    }


def _git_output(repository: Path, *arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ("git", *arguments),
            cwd=repository,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _parse_scheme(payload: object) -> SchemeMatrix:
    if not isinstance(payload, dict):
        raise CircuitError("each scheme must be a JSON object")
    name = _required_string(payload, "name")
    if name not in SUPPORTED_SCHEMES:
        raise CircuitError(f"unsupported study scheme: {name}")
    key_sizes = _integer_tuple(payload, "key_sizes")
    if any(key_size <= 0 for key_size in key_sizes):
        raise CircuitError("study key sizes must be greater than zero")
    distances_value = payload.get("hamming_distances", [])
    if not isinstance(distances_value, list) or any(
        not isinstance(distance, int) or isinstance(distance, bool)
        for distance in distances_value
    ):
        raise CircuitError("hamming_distances must be a list of integers")
    distances = tuple(distances_value)
    if name == "sfll-hd" and not distances:
        raise CircuitError("sfll-hd study scheme requires hamming_distances")
    if name != "sfll-hd" and distances:
        raise CircuitError(
            "hamming_distances may be used only with the sfll-hd scheme"
        )
    if any(distance < 0 for distance in distances):
        raise CircuitError("study Hamming distances cannot be negative")
    return SchemeMatrix(
        name=name,
        key_sizes=key_sizes,
        hamming_distances=distances,
    )


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CircuitError(f"{key} must be a non-empty string")
    return value


def _string_tuple(payload: dict[str, object], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise CircuitError(f"{key} must be a non-empty list of strings")
    if len(value) != len(set(value)):
        raise CircuitError(f"{key} must not contain duplicates")
    return tuple(value)


def _integer_tuple(payload: dict[str, object], key: str) -> tuple[int, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value or any(
        not isinstance(item, int) or isinstance(item, bool) for item in value
    ):
        raise CircuitError(f"{key} must be a non-empty list of integers")
    if len(value) != len(set(value)):
        raise CircuitError(f"{key} must not contain duplicates")
    return tuple(value)


def _hamming_distance(
    first: tuple[int, ...],
    second: tuple[int, ...],
) -> int:
    return sum(left != right for left, right in zip(first, second))


def _anomaly(phase: str, error: Exception) -> dict[str, str]:
    return {
        "phase": phase,
        "type": type(error).__name__,
        "message": str(error),
    }


def _measurement_failure_status(error: Exception) -> str:
    return "timeout" if "timed out" in str(error).lower() else "failed"
