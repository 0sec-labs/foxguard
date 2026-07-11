#!/usr/bin/env python3

import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("count-terminal-findings.py")
SPEC = importlib.util.spec_from_file_location("count_terminal_findings", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CountTerminalFindingsTest(unittest.TestCase):
    def test_counts_multiple_findings_in_colored_summary(self) -> None:
        output = "\n  \x1b[2m--------------------------------------------------\x1b[0m\n\n  \x1b[1m12\x1b[0m \x1b[2missues\x1b[0m  \x1b[2m4 files · 0.01s\x1b[0m\n"
        self.assertEqual(MODULE.count_findings(output), 12)

    def test_clean_scan_has_zero_findings(self) -> None:
        output = "\n  ✓ Scanned 4 files in 0.01s.\n"
        self.assertEqual(MODULE.count_findings(output), 0)

    def test_error_text_is_not_a_finding_count(self) -> None:
        self.assertEqual(MODULE.count_findings("Error: invalid configuration\n"), 0)


if __name__ == "__main__":
    unittest.main()
