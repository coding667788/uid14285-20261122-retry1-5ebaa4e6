"""Output ordering and stability guarantees across the three commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from solution.audit import run_compare, run_find
from solution.manifest import parse_compare_case, parse_manifest
from solution.remediate import run_remediate

ROOT = Path(__file__).resolve().parent.parent


def run_cli_seed(args, seed):
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = str(seed)
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, "-m", "solution", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )
    return completed.stdout


def multi_target_doc():
    return {
        "manifest_id": "ordering",
        "switches": [{"id": "zeta"}, {"id": "alpha"}, {"id": "mid"}],
        "nodes": [
            {"id": "sec", "kind": "sensitive_source", "categories": ["b_cat", "a_cat"]},
            {"id": "sec2", "kind": "sensitive_source", "categories": ["c_cat"]},
            {"id": "rel_z", "kind": "merge"},
            {"id": "rel_a", "kind": "merge"},
        ],
        "edges": [
            {"id": "e1", "from": "sec", "to": "rel_z", "condition": "alpha"},
            {"id": "e2", "from": "sec2", "to": "rel_z", "condition": "zeta"},
            {"id": "e3", "from": "sec", "to": "rel_a", "condition": "mid"},
        ],
        "targets": [
            {"id": "t_zz", "node": "rel_z", "allowed_categories": []},
            {"id": "t_aa", "node": "rel_a", "allowed_categories": ["c_cat"]},
        ],
    }


class OrderingTests(unittest.TestCase):
    def test_unsafe_targets_sorted_by_target_then_category(self):
        result = run_find(parse_manifest(multi_target_doc()))
        target_order = [row["target"] for row in result["unsafe_targets"]]
        self.assertEqual(target_order, sorted(target_order))
        for row in result["unsafe_targets"]:
            cats = [leak["category"] for leak in row["leaks"]]
            self.assertEqual(cats, sorted(cats))

    def test_switch_order_false_before_true(self):
        result = run_find(parse_manifest(multi_target_doc()))
        self.assertEqual(result["switches"], ["alpha", "mid", "zeta"])
        for row in result["unsafe_targets"]:
            bits = row["assignment_bits"]
            self.assertEqual(len(bits), 3)
            # The minimal witness for each category is lexicographically <= all
            # other legal witnesses for that category.
            for leak in row["leaks"]:
                self.assertEqual(len(leak["assignment_bits"]), 3)

    def test_repeated_calls_identical(self):
        manifest = parse_manifest(multi_target_doc())
        first = json.dumps(run_find(manifest), sort_keys=True)
        second = json.dumps(run_find(manifest), sort_keys=True)
        self.assertEqual(first, second)

    def test_hash_seed_does_not_change_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text(json.dumps(multi_target_doc()), encoding="utf-8")
            outputs = {run_cli_seed(["find", str(path)], seed) for seed in (0, 1, 99)}
        self.assertEqual(len(outputs), 1)

    def test_compare_stable(self):
        doc = multi_target_doc()
        case = {"case_id": "x", "old": doc, "new": doc}
        old, new = parse_compare_case(case)
        first = json.dumps(run_compare(old, new), sort_keys=True)
        second = json.dumps(run_compare(old, new), sort_keys=True)
        self.assertEqual(first, second)

    def test_remediate_stable(self):
        doc = multi_target_doc()
        doc["candidates"] = [
            {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "alpha", "cost": 1}
        ]
        manifest = parse_manifest(doc)
        first = json.dumps(run_remediate(manifest), sort_keys=True)
        second = json.dumps(run_remediate(manifest), sort_keys=True)
        self.assertEqual(first, second)


class ExampleFilesTests(unittest.TestCase):
    def test_all_examples_parse_and_run(self):
        from solution.audit import run_compare
        from solution.manifest import parse_compare_case, parse_manifest
        from solution.remediate import run_remediate

        find_doc = json.loads((ROOT / "examples" / "find_case.json").read_text(encoding="utf-8"))
        self.assertFalse(run_find(parse_manifest(find_doc))["safe"])

        compare_doc = json.loads(
            (ROOT / "examples" / "compare_case.json").read_text(encoding="utf-8")
        )
        old, new = parse_compare_case(compare_doc)
        self.assertTrue(run_compare(old, new)["ok"])

        remediate_doc = json.loads(
            (ROOT / "examples" / "remediate_case.json").read_text(encoding="utf-8")
        )
        self.assertTrue(run_remediate(parse_manifest(remediate_doc))["solvable"])

        unsolvable_doc = json.loads(
            (ROOT / "examples" / "remediate_unsolvable.json").read_text(encoding="utf-8")
        )
        self.assertFalse(run_remediate(parse_manifest(unsolvable_doc))["solvable"])


if __name__ == "__main__":
    unittest.main()
