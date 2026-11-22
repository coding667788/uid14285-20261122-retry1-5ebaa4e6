"""Cross-check the symbolic engine against a brute-force enumerator."""

from __future__ import annotations

import random
import unittest

from solution.audit import run_find
from solution.engine import Engine, Policy
from solution.manifest import parse_manifest

from tests import oracle


def manifest(switches, nodes, edges, targets, constraints=None, **extra):
    doc = {
        "manifest_id": "m",
        "switches": [{"id": s} for s in switches],
        "switch_constraints": constraints or [],
        "nodes": nodes,
        "edges": edges,
        "targets": targets,
    }
    doc.update(extra)
    return parse_manifest(doc)


PUB = {"id": "pub", "kind": "public_source", "categories": ["public"]}
SEC = {"id": "sec", "kind": "sensitive_source", "categories": ["secret"]}
TOK = {"id": "tok", "kind": "sensitive_source", "categories": ["token"]}
MERGE = {"id": "m", "kind": "merge"}
MERGE2 = {"id": "rel", "kind": "merge"}


class FindCrossCheckTests(unittest.TestCase):
    def assert_find_matches_oracle(self, m):
        expected = oracle.find_unsafe(m)
        result = run_find(m)
        actual: dict[str, dict[str, tuple]] = {}
        for row in result["unsafe_targets"]:
            for leak in row["leaks"]:
                bits = tuple(leak["assignment_bits"])
                actual.setdefault(row["target"], {})[leak["category"]] = bits
        self.assertEqual(set(actual), set(expected))
        for tid in expected:
            self.assertEqual(set(actual[tid]), set(expected[tid]), tid)
            for cat in expected[tid]:
                self.assertEqual(
                    actual[tid][cat], expected[tid][cat], f"{tid}/{cat}"
                )
        # Legal counts must agree too.
        self.assertEqual(result["legal"]["assignment_count"], len(oracle.legal_assignments(m)))

    def test_simple_leak(self):
        m = manifest(
            ["a"],
            [SEC, MERGE],
            [{"id": "e1", "from": "sec", "to": "m", "condition": "a"}],
            [{"id": "t", "node": "m", "allowed_categories": []}],
        )
        result = run_find(m)
        self.assertFalse(result["safe"])
        row = result["unsafe_targets"][0]
        self.assertEqual(row["assignment_bits"], [True])
        self.assertEqual(row["leaks"][0]["category"], "secret")
        self.assertEqual(row["leaks"][0]["chain"]["edges"], ["e1"])
        self.assert_find_matches_oracle(m)

    def test_clean_bypass(self):
        # Sanitizer removes secret when a is true, but a second path bypasses it.
        m = manifest(
            ["a", "b"],
            [
                SEC,
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [{"condition": "a", "categories": ["secret"]}],
                },
                MERGE2,
            ],
            [
                {"id": "e1", "from": "sec", "to": "cl", "condition": "TRUE"},
                {"id": "e2", "from": "cl", "to": "rel", "condition": "TRUE"},
                {"id": "e3", "from": "sec", "to": "rel", "condition": "b"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        result = run_find(m)
        row = result["unsafe_targets"][0]
        # a=true, b=false: the direct bypass is off but the cleaning node is
        # also relevant; with a false and b false the cleaned path still leaks.
        self.assertEqual(row["assignment_bits"], [False, False])
        self.assertEqual(row["leaks"][0]["chain"]["edges"], ["e1", "e2"])
        self.assert_find_matches_oracle(m)

    def test_cleaning_only_affects_its_own_node(self):
        m = manifest(
            ["a"],
            [
                SEC,
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [{"condition": "TRUE", "categories": ["secret"]}],
                },
                MERGE,
                MERGE2,
            ],
            [
                {"id": "e1", "from": "sec", "to": "m", "condition": "TRUE"},
                {"id": "e2", "from": "m", "to": "cl", "condition": "TRUE"},
                {"id": "e3", "from": "cl", "to": "rel", "condition": "TRUE"},
                # A second, un-cleaned path skips the sanitizer entirely.
                {"id": "e4", "from": "m", "to": "rel", "condition": "a"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
        )
        # e2/e3 path is cleaned at cl, but e4 bypasses cl entirely.
        result = run_find(m)
        self.assertEqual(result["unsafe_targets"][0]["assignment_bits"], [True])
        self.assert_find_matches_oracle(m)

    def test_different_assignments_create_different_dangerous_paths(self):
        m = manifest(
            ["a", "b"],
            [
                SEC,
                TOK,
                MERGE,
                MERGE2,
            ],
            [
                {"id": "e1", "from": "sec", "to": "m", "condition": "a"},
                {"id": "e2", "from": "tok", "to": "m", "condition": "b"},
                {"id": "e3", "from": "m", "to": "rel", "condition": "TRUE"},
            ],
            [
                {
                    "id": "t",
                    "node": "rel",
                    "allowed_categories": ["public"],
                }
            ],
        )
        result = run_find(m)
        row = result["unsafe_targets"][0]
        by_cat = {leak["category"]: leak for leak in row["leaks"]}
        self.assertEqual(by_cat["secret"]["assignment_bits"], [True, False])
        self.assertEqual(by_cat["token"]["assignment_bits"], [False, True])
        self.assertEqual(by_cat["secret"]["chain"]["edges"], ["e1", "e3"])
        self.assertEqual(by_cat["token"]["chain"]["edges"], ["e2", "e3"])
        self.assert_find_matches_oracle(m)

    def test_constraints_restrict_legal_domain(self):
        m = manifest(
            ["a", "b"],
            [SEC, MERGE],
            [{"id": "e1", "from": "sec", "to": "m", "condition": "a"}],
            [{"id": "t", "node": "m", "allowed_categories": []}],
            constraints=["a OR b"],
        )
        result = run_find(m)
        self.assertEqual(result["legal"]["assignment_count"], 3)
        self.assertEqual(result["unsafe_targets"][0]["assignment_bits"], [True, False])
        self.assert_find_matches_oracle(m)

    def test_unsafe_independent_of_switches(self):
        m = manifest(
            ["a"],
            [SEC, MERGE],
            [{"id": "e1", "from": "sec", "to": "m", "condition": "TRUE"}],
            [{"id": "t", "node": "m", "allowed_categories": []}],
        )
        result = run_find(m)
        self.assertEqual(result["unsafe_targets"][0]["assignment_bits"], [False])
        self.assert_find_matches_oracle(m)

    def test_safe_manifest(self):
        m = manifest(
            ["a"],
            [SEC, {"id": "cl", "kind": "sanitizer", "cleans": [{"condition": "TRUE", "categories": ["secret"]}]}, MERGE],
            [
                {"id": "e1", "from": "sec", "to": "cl", "condition": "TRUE"},
                {"id": "e2", "from": "cl", "to": "m", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "m", "allowed_categories": []}],
        )
        result = run_find(m)
        self.assertTrue(result["safe"])
        self.assertEqual(result["unsafe_targets"], [])
        self.assert_find_matches_oracle(m)

    def test_allowed_category_not_reported(self):
        m = manifest(
            ["a"],
            [SEC, MERGE],
            [{"id": "e1", "from": "sec", "to": "m", "condition": "TRUE"}],
            [{"id": "t", "node": "m", "allowed_categories": ["secret"]}],
        )
        self.assertTrue(run_find(m)["safe"])

    def test_random_small_manifests_match_oracle(self):
        rng = random.Random(4242)
        for trial in range(30):
            n = rng.randint(1, 4)
            switches = [f"s{i}" for i in range(n)]
            conds = ["TRUE", "FALSE"] + switches + [
                f"{rng.choice(switches)} AND {rng.choice(switches)}",
                f"{rng.choice(switches)} OR NOT {rng.choice(switches)}",
            ]
            m = self._random_manifest(rng, switches, conds)
            with self.subTest(trial=trial):
                self.assert_find_matches_oracle(m)

    def _random_manifest(self, rng, switches, conds):
        nodes = [
            {"id": "sec1", "kind": "sensitive_source", "categories": ["x"]},
            {"id": "sec2", "kind": "sensitive_source", "categories": ["y"]},
            {
                "id": "cl",
                "kind": "sanitizer",
                "cleans": [
                    {"condition": rng.choice(conds), "categories": ["x"]},
                ],
            },
            {"id": "mid", "kind": "merge"},
            {"id": "rel", "kind": "merge"},
        ]
        edges = []
        pairs = [
            ("sec1", "mid"),
            ("sec2", "mid"),
            ("sec1", "cl"),
            ("cl", "mid"),
            ("sec2", "rel"),
            ("mid", "rel"),
            ("cl", "rel"),
        ]
        edge_id = 0
        for src, dst in pairs:
            if rng.random() < 0.75:
                edges.append(
                    {
                        "id": f"e{edge_id:02d}",
                        "from": src,
                        "to": dst,
                        "condition": rng.choice(conds),
                    }
                )
                edge_id += 1
        targets = [
            {"id": "t1", "node": "rel", "allowed_categories": []},
        ]
        if rng.random() < 0.5:
            targets.append({"id": "t2", "node": "mid", "allowed_categories": ["y"]})
        constraints = []
        if rng.random() < 0.5:
            constraints = [rng.choice(conds)]
        return manifest(switches, nodes, edges, targets, constraints=constraints)


class ChainTieBreakTests(unittest.TestCase):
    def test_shortest_chain_and_edge_id_tie_break(self):
        # Two chains of equal length reach the target; the smaller edge-ID
        # sequence wins: a-b-d vs c-d -> ["e2", "e3"] < ["e1", "e2"]? No:
        # compare IDs lexicographically as sequences.
        m = manifest(
            ["a"],
            [
                {"id": "s", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "x", "kind": "merge"},
                {"id": "y", "kind": "merge"},
                {"id": "t", "kind": "merge"},
            ],
            [
                {"id": "e01", "from": "s", "to": "x", "condition": "TRUE"},
                {"id": "e02", "from": "x", "to": "t", "condition": "TRUE"},
                {"id": "e03", "from": "s", "to": "y", "condition": "TRUE"},
                {"id": "e04", "from": "y", "to": "t", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "t", "allowed_categories": []}],
        )
        row = run_find(m)["unsafe_targets"][0]
        self.assertEqual(row["leaks"][0]["chain"]["edges"], ["e01", "e02"])

    def test_length_beats_edge_id(self):
        # Long chain with small IDs vs short chain with larger IDs: shortest wins.
        m = manifest(
            ["a"],
            [
                {"id": "s", "kind": "sensitive_source", "categories": ["secret"]},
                {"id": "u", "kind": "merge"},
                {"id": "v", "kind": "merge"},
                {"id": "t", "kind": "merge"},
            ],
            [
                {"id": "e01", "from": "s", "to": "u", "condition": "TRUE"},
                {"id": "e02", "from": "u", "to": "v", "condition": "TRUE"},
                {"id": "e03", "from": "v", "to": "t", "condition": "TRUE"},
                {"id": "e09", "from": "s", "to": "t", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "t", "allowed_categories": []}],
        )
        row = run_find(m)["unsafe_targets"][0]
        self.assertEqual(row["leaks"][0]["chain"]["edges"], ["e09"])


class SafeCheckTests(unittest.TestCase):
    def test_engine_is_safe_matches_oracle(self):
        m = manifest(
            ["a", "b"],
            [SEC, MERGE],
            [{"id": "e1", "from": "sec", "to": "m", "condition": "a AND b"}],
            [{"id": "t", "node": "m", "allowed_categories": []}],
        )
        engine = Engine(m)
        self.assertFalse(engine.is_safe(Policy()))
        self.assertEqual(engine.is_safe(Policy()), oracle.is_safe(m))


if __name__ == "__main__":
    unittest.main()
