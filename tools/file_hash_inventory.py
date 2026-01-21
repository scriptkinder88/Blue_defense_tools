#!/usr/bin/env python3
"""Generate a hash inventory for files on disk."""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import sys
from pathlib import Path
from typing import Iterable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a CSV inventory of file hashes.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Root path to scan for files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write CSV output to a file instead of stdout.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern to exclude (repeatable).",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not recurse into subdirectories.",
    )
    return parser


def is_excluded(path: Path, patterns: Iterable[str]) -> bool:
    as_posix = str(path)
    return any(fnmatch.fnmatch(as_posix, pattern) for pattern in patterns)


def hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def iter_files(root: Path, recursive: bool) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    if recursive:
        yield from (p for p in root.rglob("*") if p.is_file())
    else:
        yield from (p for p in root.glob("*") if p.is_file())


def main() -> None:
    args = build_parser().parse_args()
    if not args.path.exists():
        raise SystemExit(f"Path not found: {args.path}")

    output_handle = args.output.open("w", newline="", encoding="utf-8") if args.output else None

    try:
        writer = csv.writer(output_handle or sys.stdout)
        writer.writerow(["path", "size", "sha256", "mtime"])
        for file_path in iter_files(args.path, not args.no_recursive):
            if is_excluded(file_path, args.exclude):
                continue
            stat = file_path.stat()
            writer.writerow([
                str(file_path),
                stat.st_size,
                hash_file(file_path),
                int(stat.st_mtime),
            ])
    finally:
        if output_handle:
            output_handle.close()


if __name__ == "__main__":
    main()
