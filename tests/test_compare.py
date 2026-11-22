"""Tests for ``compare`` across two manifests over the same switch set."""

from __future__ import annotations

import unittest

from solution.audit import run_compare
from solution.errors import InputError
from solution.manifest import parse_compare_case


def doc(mid, switches, constraints, nodes, edges, targets):
    return {
        "manifest_id": mid,
        "switches": [{"id": s} for s in switches],
        "switch_constraints": constraints,
        "nodes": nodes,
        "edges": edges,
        "targets": targets,
    }


def base_pair():
    switches = ["a", "b"]
    old_nodes = [
        {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
        {"id": "m", "kind": "merge"},
        {"id": "rel", "kind": "merge"},
    ]
    old_edges = [
        {"id": "e1", "from": "sec", "to": "m", "condition": "a"},
        {"id": "e2", "from": "m", "to": "rel", "condition": "TRUE"},
    ]
    old_targets = [{"id": "t", "node": "rel", "allowed_categories": ["public"]}]
    new_nodes = [
        {"id": "sec", "kind": "sensitive_source", "categories": ["secret", "token"]},
        {"id": "m", "kind": "merge"},
        {"id": "rel", "kind": "merge"},
    ]
    new_edges = [
        {"id": "e1", "from": "sec", "to": "m", "condition": "b"},
        {"id": "e2", "from": "m", "to": "rel", "condition": "TRUE"},
    ]
    new_targets = [{"id": "t", "node": "rel", "allowed_categories": ["public"]}]
    case = {
        "case_id": "c",
        "old": doc("old", switches, [], old_nodes, old_edges, old_targets),
        "new": doc("new", switches, [], new_nodes, new_edges, new_targets),
    }
    return parse_compare_case(case)


class CompareTests(unittest.TestCase):
    def test_added_and_disappeared(self):
        old, new = base_pair()
        result = run_compare(old, new)
        targets = {row["target"]: row for row in result["targets"]}
        row = targets["t"]
        added = {item["category"]: item for item in row["added"]}
        gone = {item["category"]: item for item in row["disappeared"]}
        self.assertEqual(set(added), {"secret", "token"})
        self.assertEqual(set(gone), {"secret"})
        # Minimal change from the all-false baseline: flip b (index 1).
        self.assertEqual(row["minimal_change"]["assignment_bits"], [False, True])
        self.assertEqual(row["minimal_change"]["switch_changes"], 1)

    def test_no_change(self):
        old, new = base_pair()
        # Make both manifests identical by reusing the old one.
        result = run_compare(old, old)
        self.assertEqual(result["targets"], [])
        self.assertEqual(len(result["unchanged_targets"]), 1)

    def test_target_missing_in_new(self):
        case = {
            "case_id": "c",
            "old": doc(
                "old",
                ["a"],
                [],
                [
                    {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                    {"id": "rel", "kind": "merge"},
                ],
                [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
                [{"id": "gone", "node": "rel", "allowed_categories": []}],
            ),
            "new": doc(
                "new",
                ["a"],
                [],
                [
                    {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                    {"id": "rel", "kind": "merge"},
                ],
                [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
                [{"id": "kept", "node": "rel", "allowed_categories": []}],
            ),
        }
        old, new = parse_compare_case(case)
        result = run_compare(old, new)
        rows = {row["target"]: row for row in result["targets"]}
        self.assertIn("gone", rows)
        self.assertEqual(rows["gone"]["present_in"], {"old": True, "new": False})
        # With the target removed, its leak "disappears".
        self.assertEqual(
            [item["category"] for item in rows["gone"]["disappeared"]], ["secret"]
        )

    def test_new_target_only(self):
        old, new = base_pair()
        # Reuse structure but rename target only in new.
        old2 = doc(
            "old",
            ["a", "b"],
            [],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
            [{"id": "old_t", "node": "rel", "allowed_categories": ["secret"]}],
        )
        new2 = doc(
            "new",
            ["a", "b"],
            [],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
            [{"id": "new_t", "node": "rel", "allowed_categories": []}],
        )
        o, n = parse_compare_case({"case_id": "x", "old": old2, "new": new2})
        result = run_compare(o, n)
        rows = {row["target"]: row for row in result["targets"]}
        self.assertEqual(rows["new_t"]["present_in"], {"old": False, "new": True})
        self.assertEqual(
            [item["category"] for item in rows["new_t"]["added"]], ["secret"]
        )

    def test_different_legal_domains(self):
        # old legal only when a is true; new legal only when a AND b.
        old_manifest = doc(
            "old",
            ["a", "b"],
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        new_manifest = doc(
            "new",
            ["a", "b"],
            ["a AND b"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        o, n = parse_compare_case(
            {"case_id": "x", "old": old_manifest, "new": new_manifest}
        )
        result = run_compare(o, n)
        # Common legal domain is exactly {a=true, b=true}: 1 assignment.
        self.assertEqual(result["common_legal"]["assignment_count"], 1)
        self.assertFalse(result["no_common_legal_assignments"])
        # secret leaks in both on the common domain -> persisting, no change.
        self.assertEqual(result["targets"], [])
        persisting = result["unchanged_targets"][0]["persisting"]
        self.assertEqual([item["category"] for item in persisting], ["secret"])

    def test_disjoint_legal_domains_reported_explicitly(self):
        old_manifest = doc(
            "old",
            ["a"],
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        new_manifest = doc(
            "new",
            ["a"],
            ["NOT a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        o, n = parse_compare_case(
            {"case_id": "x", "old": old_manifest, "new": new_manifest}
        )
        result = run_compare(o, n)
        self.assertTrue(result["no_common_legal_assignments"])
        self.assertFalse(result["common_legal"]["satisfiable"])
        self.assertEqual(result["common_legal"]["assignment_count"], 0)
        self.assertIn("message", result)

    def test_switch_set_mismatch_is_rejected(self):
        old_manifest = doc(
            "old",
            ["a"],
            [],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        new_manifest = doc(
            "new",
            ["a", "b"],
            [],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        with self.assertRaises(InputError) as ctx:
            parse_compare_case(
                {"case_id": "x", "old": old_manifest, "new": new_manifest}
            )
        self.assertEqual(ctx.exception.code, "COMPARE_SWITCH_MISMATCH")
        self.assertEqual(ctx.exception.path, "$.new.switches")

    def test_minimal_change_respects_legal_domain(self):
        # default a=false; new leaks only when b, but a must be true in new.
        old_manifest = doc(
            "old",
            ["a", "b"],
            [],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "FALSE"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        new_manifest = doc(
            "new",
            ["a", "b"],
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "b"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        o, n = parse_compare_case(
            {"case_id": "x", "old": old_manifest, "new": new_manifest}
        )
        result = run_compare(o, n)
        row = result["targets"][0]
        # Common legal domain requires a=true.  Witness must have a=true, b=true,
        # i.e. both changes from the all-false baseline.
        self.assertEqual(row["added"][0]["witness"]["assignment_bits"], [True, True])
        self.assertEqual(row["added"][0]["witness"]["switch_changes"], 2)


if __name__ == "__main__":
    unittest.main()
