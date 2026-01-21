#!/usr/bin/env python3
"""Summarize authentication activity from auth logs."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
SUDO_RE = re.compile(r"sudo: +(?P<user>\S+) : .*COMMAND=")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize authentication events from auth.log/secure files.",
    )
    parser.add_argument(
        "log_files",
        nargs="+",
        type=Path,
        help="One or more auth log files to parse.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Show the top N entries for each category (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON.",
    )
    return parser


def read_lines(paths: Iterable[Path]) -> Iterable[str]:
    for path in paths:
        if not path.exists():
            raise SystemExit(f"Log file not found: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            yield from handle


def summarize(lines: Iterable[str]) -> dict[str, Counter[str]]:
    failed_users = Counter()
    failed_ips = Counter()
    accepted_users = Counter()
    accepted_ips = Counter()
    sudo_users = Counter()

    for line in lines:
        failed = FAILED_RE.search(line)
        if failed:
            failed_users[failed.group("user")] += 1
            failed_ips[failed.group("ip")] += 1
            continue

        accepted = ACCEPTED_RE.search(line)
        if accepted:
            accepted_users[accepted.group("user")] += 1
            accepted_ips[accepted.group("ip")] += 1
            continue

        sudo = SUDO_RE.search(line)
        if sudo:
            sudo_users[sudo.group("user")] += 1

    return {
        "failed_users": failed_users,
        "failed_ips": failed_ips,
        "accepted_users": accepted_users,
        "accepted_ips": accepted_ips,
        "sudo_users": sudo_users,
    }


def render_text(summary: dict[str, Counter[str]], top: int) -> str:
    sections = []
    for title, counter in summary.items():
        lines = [title.replace("_", " ") + ":"]
        for value, count in counter.most_common(top):
            lines.append(f"  {value}: {count}")
        if len(lines) == 1:
            lines.append("  (no entries)")
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def main() -> None:
    args = build_parser().parse_args()
    summary = summarize(read_lines(args.log_files))

    if args.json:
        serializable = {k: dict(v) for k, v in summary.items()}
        print(json.dumps(serializable, indent=2, sort_keys=True))
    else:
        print(render_text(summary, args.top))


if __name__ == "__main__":
    main()
