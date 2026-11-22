import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "owasp_java", Path(__file__).parent / "precision" / "owasp_java.py"
)
owasp_java = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(owasp_java)


def _sarif(rules, results):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": rules}}, "results": results}]}


def _result(rule, uri):
    return {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}


class SarifReportTest(unittest.TestCase):
    def convert(self, doc):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.sarif"
            path.write_text(json.dumps(doc))
            return owasp_java.sarif_report(path)["findings"]

    def test_cwe_from_tags(self):
        doc = _sarif([{"id": "r1", "properties": {"tags": ["security", "CWE-89: SQL Injection"]}}],
                     [_result("r1", "src/main/java/BenchmarkTest00001.java")])
        self.assertEqual(self.convert(doc), [{"rule_id": "r1", "file": "src/main/java/BenchmarkTest00001.java", "cwe": "CWE-89"}])

    def test_multiple_cwes_count_once_each(self):
        doc = _sarif([{"id": "r1", "properties": {"tags": ["CWE-79", "cwe_80"]}}], [_result("r1", "BenchmarkTest00002.java")])
        self.assertEqual(sorted(f["cwe"] for f in self.convert(doc)), ["CWE-79", "CWE-80"])

    def test_untagged_rule_never_matches_a_category(self):
        doc = _sarif([{"id": "r1"}], [_result("r1", "BenchmarkTest00003.java")])
        self.assertEqual(self.convert(doc)[0]["cwe"], None)

    def test_scores_like_foxguard_output(self):
        truth = {"BenchmarkTest00001": ("sqli", True, "CWE-89"), "BenchmarkTest00002": ("sqli", False, "CWE-89")}
        doc = _sarif([{"id": "r1", "properties": {"tags": ["CWE-89"]}}], [_result("r1", "BenchmarkTest00001.java")])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.sarif"
            path.write_text(json.dumps(doc))
            agg = owasp_java.score(truth, owasp_java.sarif_report(path))["aggregate"]
        self.assertEqual((agg["tp"], agg["fp"], agg["fn"], agg["tn"]), (1, 0, 0, 1))


if __name__ == "__main__":
    unittest.main()
