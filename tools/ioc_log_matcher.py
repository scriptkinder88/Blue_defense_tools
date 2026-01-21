#!/usr/bin/env python3
"""Scan log files for indicators of compromise (IOCs)."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, TextIO


def load_iocs(ioc_file: Path) -> list[str]:
    raw_lines = ioc_file.read_text(encoding="utf-8").splitlines()
    iocs = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        iocs.append(stripped)
    return iocs


def compile_ioc_regex(iocs: Iterable[str], ignore_case: bool) -> re.Pattern[str]:
    escaped = [re.escape(ioc) for ioc in iocs]
    pattern = "|".join(escaped)
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(pattern, flags=flags)


def scan_log(
    log_path: Path,
    regex: re.Pattern[str],
    output: TextIO,
) -> int:
    match_count = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if regex.search(line):
                match_count += 1
                output.write(f"{log_path}:{line_number}:{line}")
    return match_count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan log files for IOCs listed in a file.",
    )
    parser.add_argument(
        "--ioc-file",
        required=True,
        type=Path,
        help="Path to file containing one IOC per line.",
    )
    parser.add_argument(
        "--log-files",
        required=True,
        nargs="+",
        type=Path,
        help="One or more log files to scan.",
    )
    parser.add_argument(
        "--ignore-case",
        action="store_true",
        help="Match IOCs case-insensitively.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write matches to a file instead of stdout.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.ioc_file.exists():
        raise SystemExit(f"IOC file not found: {args.ioc_file}")

    iocs = load_iocs(args.ioc_file)
    if not iocs:
        raise SystemExit("No IOCs found in the IOC file.")

    regex = compile_ioc_regex(iocs, args.ignore_case)

    output_handle: TextIO
    if args.output:
        output_handle = args.output.open("w", encoding="utf-8")
    else:
        output_handle = sys.stdout

    total_matches = 0
    try:
        for log_path in args.log_files:
            if not log_path.exists():
                raise SystemExit(f"Log file not found: {log_path}")
            total_matches += scan_log(log_path, regex, output_handle)
    finally:
        if args.output:
            output_handle.close()

    if args.output:
        print(f"Wrote {total_matches} matches to {args.output}")
    else:
        print(f"Total matches: {total_matches}")


if __name__ == "__main__":
    main()
