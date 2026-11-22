"""Tests for manifest validation: every structural error gets a code and path."""

from __future__ import annotations

import copy
import unittest

from solution.errors import InputError
from solution.manifest import parse_manifest

BASE = {
    "manifest_id": "m",
    "switches": [{"id": "a"}, {"id": "b"}],
    "nodes": [
        {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
        {"id": "m", "kind": "merge"},
    ],
    "edges": [{"id": "e1", "from": "sec", "to": "m", "condition": "a"}],
    "targets": [{"id": "t", "node": "m", "allowed_categories": []}],
}


def case(**overrides):
    doc = copy.deepcopy(BASE)
    doc.update(overrides)
    return doc


class ManifestValidationTests(unittest.TestCase):
    def assert_error(self, doc, code, path_prefix=None):
        with self.assertRaises(InputError) as ctx:
            parse_manifest(doc)
        self.assertEqual(ctx.exception.code, code)
        if path_prefix is not None:
            self.assertTrue(
                ctx.exception.path.startswith(path_prefix),
                f"{ctx.exception.path} does not start with {path_prefix}",
            )
        return ctx.exception

    def test_minimal_valid(self):
        m = parse_manifest(case())
        self.assertEqual(m.manifest_id, "m")
        self.assertEqual(m.switch_ids, ("a", "b"))

    def test_root_not_object(self):
        self.assert_error([], "ROOT_TYPE", "$")

    def test_unknown_top_level_field(self):
        self.assert_error(case(extra=1), "UNKNOWN_FIELD", "$.extra")

    def test_missing_switches(self):
        doc = case()
        del doc["switches"]
        self.assert_error(doc, "MISSING_FIELD", "$.switches")

    def test_too_many_switches(self):
        doc = case(switches=[{"id": f"s{i}"} for i in range(25)])
        self.assert_error(doc, "TOO_MANY_SWITCHES", "$.switches")

    def test_duplicate_switch(self):
        doc = case(switches=[{"id": "a"}, {"id": "a"}])
        self.assert_error(doc, "DUPLICATE_ID", "$.switches[1].id")

    def test_invalid_switch_id(self):
        doc = case(switches=[{"id": "1bad"}])
        self.assert_error(doc, "INVALID_SWITCH_ID", "$.switches[0].id")

    def test_reserved_switch_id(self):
        doc = case(switches=[{"id": "NOT"}])
        self.assert_error(doc, "RESERVED_SWITCH_ID", "$.switches[0].id")

    def test_unknown_node_kind(self):
        doc = case(
            nodes=[
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "m", "kind": "mystery"},
            ]
        )
        self.assert_error(doc, "UNKNOWN_NODE_KIND", "$.nodes[1].kind")

    def test_source_requires_categories(self):
        doc = case(nodes=[{"id": "sec", "kind": "sensitive_source"}, {"id": "m", "kind": "merge"}])
        self.assert_error(doc, "MISSING_FIELD", "$.nodes[0].categories")

    def test_duplicate_node(self):
        doc = case(
            nodes=[
                {"id": "x", "kind": "merge"},
                {"id": "x", "kind": "merge"},
            ]
        )
        self.assert_error(doc, "DUPLICATE_ID", "$.nodes[1].id")

    def test_unknown_edge_endpoint(self):
        doc = case(
            edges=[{"id": "e1", "from": "sec", "to": "nope", "condition": "a"}]
        )
        self.assert_error(doc, "UNKNOWN_NODE", "$.edges[0].to")

    def test_missing_edge_condition(self):
        doc = case(edges=[{"id": "e1", "from": "sec", "to": "m"}])
        self.assert_error(doc, "MISSING_FIELD", "$.edges[0].condition")

    def test_bad_edge_condition(self):
        doc = case(
            edges=[{"id": "e1", "from": "sec", "to": "m", "condition": "a AND zz"}]
        )
        self.assert_error(doc, "EXPR_UNKNOWN_SWITCH", "$.edges[0].condition")

    def test_unknown_target_node(self):
        doc = case(targets=[{"id": "t", "node": "ghost", "allowed_categories": []}])
        self.assert_error(doc, "UNKNOWN_NODE", "$.targets[0].node")

    def test_empty_targets(self):
        self.assert_error(case(targets=[]), "EMPTY_LIST", "$.targets")

    def test_cycle_detected(self):
        doc = case(
            nodes=[
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "x", "kind": "merge"},
                {"id": "y", "kind": "merge"},
            ],
            edges=[
                {"id": "e1", "from": "x", "to": "y", "condition": "TRUE"},
                {"id": "e2", "from": "y", "to": "x", "condition": "TRUE"},
            ],
            targets=[{"id": "t", "node": "x", "allowed_categories": []}],
        )
        self.assert_error(doc, "DAG_CYCLE", "$.edges")

    def test_bad_clean_condition(self):
        doc = case(
            nodes=[
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [{"condition": "a OR", "categories": ["s"]}],
                },
            ],
            edges=[
                {"id": "e1", "from": "sec", "to": "cl", "condition": "a"},
            ],
            targets=[{"id": "t", "node": "cl", "allowed_categories": []}],
        )
        self.assert_error(doc, "EXPR_UNEXPECTED_END", "$.nodes[1].cleans[0].condition")

    def test_duplicate_category(self):
        doc = case(
            nodes=[
                {"id": "sec", "kind": "sensitive_source", "categories": ["s", "s"]},
                {"id": "m", "kind": "merge"},
            ]
        )
        self.assert_error(doc, "DUPLICATE_CATEGORY", "$.nodes[0].categories[1]")

    def test_requirement_unknown_target(self):
        doc = case(
            nodes=[
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "pub", "kind": "public_source", "categories": ["p"]},
                {"id": "m", "kind": "merge"},
            ],
            edges=[
                {"id": "e1", "from": "sec", "to": "m", "condition": "a"},
                {"id": "e2", "from": "pub", "to": "m", "condition": "TRUE"},
            ],
            required_reachability=[
                {"id": "r1", "source": "pub", "target": "nope", "requirement": "a"}
            ],
        )
        self.assert_error(doc, "UNKNOWN_TARGET", "$.required_reachability[0].target")

    def test_requirement_source_must_be_public(self):
        doc = case(
            required_reachability=[
                {"id": "r1", "source": "sec", "target": "t", "requirement": "a"}
            ]
        )
        self.assert_error(
            doc, "REQUIREMENT_SOURCE_KIND", "$.required_reachability[0].source"
        )

    def test_candidate_unknown_kind(self):
        doc = case(candidates=[{"id": "c1", "kind": "magic"}])
        self.assert_error(doc, "UNKNOWN_CANDIDATE_KIND", "$.candidates[0].kind")

    def test_candidate_unknown_edge(self):
        doc = case(
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "ghost", "condition": "a"}
            ]
        )
        self.assert_error(doc, "UNKNOWN_EDGE", "$.candidates[0].edge")

    def test_candidate_negative_cost(self):
        doc = case(
            candidates=[
                {
                    "id": "c1",
                    "kind": "disable_edge",
                    "edge": "e1",
                    "condition": "a",
                    "cost": -2,
                }
            ]
        )
        self.assert_error(doc, "NEGATIVE_COST", "$.candidates[0].cost")

    def test_switch_order_is_sorted_by_id(self):
        doc = case(
            switches=[{"id": "zeta"}, {"id": "alpha"}, {"id": "mid"}],
            edges=[{"id": "e1", "from": "sec", "to": "m", "condition": "alpha"}],
        )
        m = parse_manifest(doc)
        self.assertEqual(m.switch_ids, ("alpha", "mid", "zeta"))
        self.assertEqual([s.index for s in m.switches], [0, 1, 2])

    def test_default_flag_parsed(self):
        doc = case(switches=[{"id": "a", "default": True}, {"id": "b"}])
        m = parse_manifest(doc)
        self.assertEqual([s.default for s in m.switches], [True, False])


if __name__ == "__main__":
    unittest.main()
