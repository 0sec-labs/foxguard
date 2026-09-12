#!/usr/bin/env python3
"""Exercise the installed wheel, not a binary from Cargo's target directory."""

import json
import subprocess
import sysconfig
import tempfile
from importlib.metadata import distribution
from pathlib import Path

package = distribution("foxguard")
executables = [
    Path(sysconfig.get_path("scripts")) / name
    for name in ("foxguard", "foxguard.exe")
]
binary = next(path for path in executables if path.is_file())
version = subprocess.check_output([str(binary), "--version"], text=True).strip()
assert version == f"foxguard {package.version}", version

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source = root / "example.py"
    source.write_text("eval(input())\n", encoding="utf-8")
    result = subprocess.run(
        [str(binary), str(source), "--format", "json"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    findings = json.loads(result.stdout)["findings"]
    assert any(
        finding["rule_id"] == "py/no-eval" and finding["line"] == 1
        for finding in findings
    ), findings
    source.write_text("print('hello')\n", encoding="utf-8")
    clean = subprocess.run(
        [str(binary), str(source), "--format", "json"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(clean.stdout)["findings"] == [], clean.stdout

print(f"Installed wheel {version}: vulnerable and clean scans passed")
