from __future__ import annotations

import argparse

from locklab.doctor import run_doctor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="locklab",
        description="Logic-locking experiment framework",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "doctor",
        help="Check the LockLab development environment",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "doctor":
        raise SystemExit(run_doctor())

    parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()