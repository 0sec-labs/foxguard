#!/usr/bin/env python3
"""Extract the finding total from foxguard's terminal report."""

import re
import sys


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SUMMARY = re.compile(r"^\s*(\d+)\s+issues\s+\d+\s+files\b", re.MULTILINE)


def count_findings(output: str) -> int:
    clean_output = ANSI_ESCAPE.sub("", output)
    match = SUMMARY.search(clean_output)
    return int(match.group(1)) if match else 0


if __name__ == "__main__":
    print(count_findings(sys.stdin.read()))
