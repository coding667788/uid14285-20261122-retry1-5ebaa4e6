"""End-to-end CLI tests: ``python -m solution <command> CASE.json [--db DB]``."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def run_cli(args, cwd=ROOT):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, "-m", "solution", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )
    return completed


def write_case(tmp, name, document):
    path = Path(tmp) / name
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return str(path)


SIMPLE = {
    "manifest_id": "cli-simple",
    "switches": [{"id": "a"}],
    "nodes": [
        {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
        {"id": "rel", "kind": "merge"},
    ],
    "edges": [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
    "targets": [{"id": "t", "node": "rel", "allowed_categories": []}],
}


class CliTests(unittest.TestCase):
    def test_find_example(self):
        completed = run_cli(["find", str(EXAMPLES / "find_case.json")])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "find")
        self.assertEqual(
            [row["target"] for row in payload["unsafe_targets"]],
            sorted(row["target"] for row in payload["unsafe_targets"]),
        )

    def test_output_is_single_line_utf8_json(self):
        completed = run_cli(["find", str(EXAMPLES / "find_case.json")])
        self.assertTrue(completed.stdout.endswith("\n"))
        self.assertEqual(completed.stdout.count("\n"), 1)
        json.loads(completed.stdout)

    def test_deterministic_output(self):
        first = run_cli(["find", str(EXAMPLES / "find_case.json")]).stdout
        second = run_cli(["find", str(EXAMPLES / "find_case.json")]).stdout
        self.assertEqual(first, second)

    def test_input_errors_are_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_case(tmp, "bad.json", {"manifest_id": "x"})
            completed = run_cli(["find", path])
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "MISSING_FIELD")
        self.assertEqual(payload["error"]["path"], "$.switches")

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{not json", encoding="utf-8")
            completed = run_cli(["find", str(path)])
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["error"]["code"], "INPUT_INVALID_JSON")

    def test_missing_file(self):
        completed = run_cli(["find", "definitely-missing.json"])
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            json.loads(completed.stdout)["error"]["code"], "INPUT_UNREADABLE"
        )

    def test_bad_expression_reports_field_path(self):
        document = json.loads(json.dumps(SIMPLE))
        document["edges"][0]["condition"] = "a AND nope"
        with tempfile.TemporaryDirectory() as tmp:
            path = write_case(tmp, "bad_expr.json", document)
            completed = run_cli(["find", path])
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["error"]["code"], "EXPR_UNKNOWN_SWITCH")
        self.assertEqual(payload["error"]["path"], "$.edges[0].condition")

    def test_db_history_is_recorded_and_repeatable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_case(tmp, "simple.json", SIMPLE)
            database = str(Path(tmp) / "audit.sqlite")
            first = json.loads(
                run_cli(["find", path, "--db", database]).stdout
            )
            second = json.loads(
                run_cli(["find", path, "--db", database]).stdout
            )
            self.assertEqual(first["persistence"]["identical_prior_runs"], 0)
            self.assertEqual(second["persistence"]["identical_prior_runs"], 1)
            self.assertEqual(second["persistence"]["total_runs"], 2)
            # Volatile persistence block must not leak into the audit result.
            first.pop("persistence")
            second.pop("persistence")
            self.assertEqual(first, second)

    def test_remediate_cli(self):
        document = json.loads(json.dumps(SIMPLE))
        document["candidates"] = [
            {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1}
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_case(tmp, "rem.json", document)
            completed = run_cli(["remediate", path])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["solvable"])
        self.assertEqual(payload["policy"]["ids"], ["c1"])

    def test_compare_cli(self):
        old = json.loads(json.dumps(SIMPLE))
        old["manifest_id"] = "old"
        new = json.loads(json.dumps(SIMPLE))
        new["manifest_id"] = "new"
        new["edges"][0]["condition"] = "FALSE"
        with tempfile.TemporaryDirectory() as tmp:
            path = write_case(
                tmp, "cmp.json", {"case_id": "c", "old": old, "new": new}
            )
            completed = run_cli(["compare", path])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["command"], "compare")
        self.assertEqual(
            [row["category"] for row in payload["targets"][0]["disappeared"]],
            ["secret"],
        )

    def test_usage_error_when_command_missing(self):
        completed = run_cli([])
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
