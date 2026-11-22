"""Tests for ``remediate``: one global fixed policy over every legal assignment."""

from __future__ import annotations

import random
import unittest

from solution.engine import Policy
from solution.manifest import parse_manifest
from solution.remediate import run_remediate

from tests import oracle


def build(switches, nodes, edges, targets, constraints=None, candidates=None, reqs=None):
    doc = {
        "manifest_id": "m",
        "switches": [{"id": s} for s in switches],
        "switch_constraints": constraints or [],
        "nodes": nodes,
        "edges": edges,
        "targets": targets,
        "candidates": candidates or [],
    }
    if reqs is not None:
        doc["required_reachability"] = reqs
    return parse_manifest(doc)


def selected_ids(result):
    return result["policy"]["ids"]


class RemediateBasics(unittest.TestCase):
    def test_already_safe_selects_nothing(self):
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [{"condition": "TRUE", "categories": ["s"]}],
                },
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "cl", "condition": "TRUE"},
                {"id": "e2", "from": "cl", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "TRUE", "cost": 1}
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), [])
        self.assertEqual(result["policy"]["total_cost"], 0)
        self.assertTrue(result["final_audit"]["safe"])

    def test_disable_leaking_edge(self):
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 3}
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), ["c1"])
        self.assertTrue(result["final_audit"]["safe"])

    def test_clean_extension(self):
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "cl", "kind": "sanitizer", "cleans": []},
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "cl", "condition": "TRUE"},
                {"id": "e2", "from": "cl", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {
                    "id": "c2",
                    "kind": "extend_cleaning",
                    "node": "cl",
                    "condition": "TRUE",
                    "categories": ["s"],
                    "cost": 2,
                }
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), ["c2"])

    def test_cheapest_wins(self):
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "cl", "kind": "sanitizer", "cleans": []},
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "cl", "condition": "TRUE"},
                {"id": "e2", "from": "cl", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "TRUE", "cost": 5},
                {
                    "id": "c2",
                    "kind": "extend_cleaning",
                    "node": "cl",
                    "condition": "TRUE",
                    "categories": ["s"],
                    "cost": 1,
                },
            ],
        )
        result = run_remediate(m)
        self.assertEqual(selected_ids(result), ["c2"])
        self.assertEqual(result["policy"]["total_cost"], 1)


class RemediateHardCases(unittest.TestCase):
    def test_disabling_leak_edge_blocks_required_public_source(self):
        # Only candidate disables the shared edge that also carries the public
        # source, so it must be rejected; the correct answer keeps reachability.
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "pub", "kind": "public_source", "categories": ["p"]},
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "rel", "condition": "a"},
                {"id": "e2", "from": "pub", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": ["p"]}],
            reqs=[{"id": "r1", "source": "pub", "target": "t", "requirement": "TRUE"}],
            candidates=[
                # Disabling e1 would fix the leak, but e2 is fine; nothing else
                # is needed.  Sanity: reachability of pub is unaffected.
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), ["c1"])
        self.assertTrue(result["final_audit"]["safe"])
        self.assertTrue(result["reachability"][0]["satisfied"])

    def test_required_reachability_forbids_disabling_edge(self):
        # The only leak edge is also the only route for the public source: no
        # fixed policy can both remove the leak and keep the source reachable.
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "pub", "kind": "public_source", "categories": ["p"]},
                {"id": "mid", "kind": "merge"},
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "mid", "condition": "a"},
                {"id": "e2", "from": "pub", "to": "mid", "condition": "TRUE"},
                {"id": "e3", "from": "mid", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": ["p"]}],
            reqs=[{"id": "r1", "source": "pub", "target": "t", "requirement": "TRUE"}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e3", "condition": "TRUE", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertFalse(result["solvable"])
        self.assertEqual(result["reason"], "unreachable_required_source")
        self.assertIsNotNone(result["minimal_unsatisfied_demand"])

    def test_combined_low_cost_actions_needed(self):
        # Two leaks through different edges; each individually cheap, together
        # still cheaper than the single expensive "clean everything" action.
        m = build(
            ["a", "b"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
                {"id": "rel2", "kind": "merge"},
                {"id": "final", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "rel", "condition": "a"},
                {"id": "e2", "from": "sec", "to": "rel2", "condition": "b"},
                {"id": "e3", "from": "rel", "to": "final", "condition": "TRUE"},
                {"id": "e4", "from": "rel2", "to": "final", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "final", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1},
                {"id": "c2", "kind": "disable_edge", "edge": "e2", "condition": "b", "cost": 1},
                {"id": "c3", "kind": "disable_edge", "edge": "e3", "condition": "TRUE", "cost": 10},
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), ["c1", "c2"])
        self.assertEqual(result["policy"]["total_cost"], 2)

    def test_global_policy_not_per_assignment(self):
        # A single-assignment-specific fix exists but is not global; the global
        # fix must cover every legal assignment, which needs both disables.
        m = build(
            ["a", "b"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "rel", "condition": "a"},
                {"id": "e2", "from": "sec", "to": "rel", "condition": "b"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1},
                {"id": "c2", "kind": "disable_edge", "edge": "e2", "condition": "b", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        # c1 alone only fixes a=true; c2 alone only fixes b=true.
        self.assertEqual(selected_ids(result), ["c1", "c2"])
        self.assertTrue(result["final_audit"]["safe"])
        # Verify against the oracle directly.
        self.assertTrue(oracle.is_safe(m, Policy(frozenset({"c1", "c2"}))))
        self.assertFalse(oracle.is_safe(m, Policy(frozenset({"c1"}))))
        self.assertFalse(oracle.is_safe(m, Policy(frozenset({"c2"}))))

    def test_mutually_exclusive_candidates(self):
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "a"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1},
                {"id": "c2", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        # Only one of the two may be chosen; ascending ID breaks the tie.
        self.assertEqual(selected_ids(result), ["c1"])

    def test_multiple_targets_pull_together(self):
        m = build(
            ["a", "b"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s", "t"]},
                {"id": "rel1", "kind": "merge"},
                {"id": "rel2", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "rel1", "condition": "a"},
                {"id": "e2", "from": "sec", "to": "rel2", "condition": "b"},
            ],
            [
                {"id": "t1", "node": "rel1", "allowed_categories": ["t"]},
                {"id": "t2", "node": "rel2", "allowed_categories": ["s"]},
            ],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "a", "cost": 1},
                {"id": "c2", "kind": "disable_edge", "edge": "e2", "condition": "b", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), ["c1", "c2"])

    def test_tie_break_by_count_then_id(self):
        # Two single-action solutions with equal cost: choose fewest actions,
        # then ascending action ID.
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [],
                },
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "cl", "condition": "TRUE"},
                {"id": "e2", "from": "cl", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "a1", "kind": "disable_edge", "edge": "e1", "condition": "TRUE", "cost": 2},
                {"id": "a2", "kind": "disable_edge", "edge": "e2", "condition": "TRUE", "cost": 2},
                {
                    "id": "b1",
                    "kind": "extend_cleaning",
                    "node": "cl",
                    "condition": "TRUE",
                    "categories": ["s"],
                    "cost": 2,
                },
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(selected_ids(result), ["a1"])
        self.assertEqual(result["policy"]["action_count"], 1)

    def test_no_solution_leak_reports_witness(self):
        # Candidate set cannot fix the leak at all (all irrelevant/no-op).
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
                {"id": "other", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"},
                {"id": "e2", "from": "sec", "to": "other", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e2", "condition": "TRUE", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertFalse(result["solvable"])
        self.assertEqual(result["reason"], "unfixable_leak")
        demand = result["minimal_unsatisfied_demand"]
        self.assertEqual(demand["kind"], "leak")
        self.assertEqual(demand["target"], "t")
        self.assertEqual(demand["category"], "s")
        self.assertIsNotNone(demand["assignment"])

    def test_vacuous_legal_domain(self):
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"}],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            constraints=["a AND NOT a"],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(result["policy"]["ids"], [])
        self.assertTrue(result["vacuous"])

    def test_irrelevant_candidates_are_pruned(self):
        # A candidate on a node with no sensitive path or no target downstream
        # is reported as ignored and never selected.
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "rel", "kind": "merge"},
                {"id": "island", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "TRUE", "cost": 1},
                {
                    "id": "c2",
                    "kind": "extend_cleaning",
                    "node": "island",
                    "condition": "TRUE",
                    "categories": ["s"],
                    "cost": 1,
                },
            ],
        )
        result = run_remediate(m)
        self.assertEqual(selected_ids(result), ["c1"])
        self.assertEqual(result["search"]["candidates_ignored"], ["c2"])

    def test_sanitizer_cannot_substitute_for_reachability(self):
        # A cleaning extension at a node is never treated as making an
        # unreachable required source reachable.
        m = build(
            ["a"],
            [
                {"id": "pub", "kind": "public_source", "categories": ["p"]},
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [],
                },
                {"id": "rel", "kind": "merge"},
            ],
            [{"id": "e1", "from": "pub", "to": "cl", "condition": "a"}],
            [{"id": "t", "node": "rel", "allowed_categories": ["p"]}],
            reqs=[{"id": "r1", "source": "pub", "target": "t", "requirement": "a"}],
            candidates=[
                {
                    "id": "c1",
                    "kind": "extend_cleaning",
                    "node": "cl",
                    "condition": "TRUE",
                    "categories": ["p"],
                    "cost": 1,
                }
            ],
        )
        result = run_remediate(m)
        self.assertFalse(result["solvable"])
        self.assertEqual(result["reason"], "unreachable_required_source")

    def test_requirement_conditional_on_switch(self):
        # Requirement only applies when a is true; a policy that disables the
        # edge only when a is false keeps the requirement satisfiable.
        m = build(
            ["a"],
            [
                {"id": "sec", "kind": "sensitive_source", "categories": ["s"]},
                {"id": "pub", "kind": "public_source", "categories": ["p"]},
                {"id": "mid", "kind": "merge"},
                {"id": "rel", "kind": "merge"},
            ],
            [
                {"id": "e1", "from": "sec", "to": "mid", "condition": "NOT a"},
                {"id": "e2", "from": "pub", "to": "mid", "condition": "TRUE"},
                {"id": "e3", "from": "mid", "to": "rel", "condition": "TRUE"},
            ],
            [{"id": "t", "node": "rel", "allowed_categories": ["p"]}],
            reqs=[{"id": "r1", "source": "pub", "target": "t", "requirement": "TRUE"}],
            candidates=[
                {"id": "c1", "kind": "disable_edge", "edge": "e1", "condition": "NOT a", "cost": 1},
                {"id": "c2", "kind": "disable_edge", "edge": "e3", "condition": "TRUE", "cost": 1},
            ],
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        # c2 would sever the required path; c1 is the only safe choice.
        self.assertEqual(selected_ids(result), ["c1"])
        self.assertTrue(result["reachability"][0]["satisfied"])
        self.assertIn("witness", result["reachability"][0])


class OracleCrossCheck(unittest.TestCase):
    def test_random_manifests_match_exhaustive_search(self):
        rng = random.Random(987654)
        checked = 0
        for trial in range(24):
            n = rng.randint(1, 3)
            switches = [f"s{i}" for i in range(n)]
            conds = ["TRUE", "FALSE"] + switches + [
                f"{rng.choice(switches)} AND {rng.choice(switches)}"
            ]
            nodes = [
                {"id": "sec", "kind": "sensitive_source", "categories": ["x"]},
                {"id": "pub", "kind": "public_source", "categories": ["p"]},
                {
                    "id": "cl",
                    "kind": "sanitizer",
                    "cleans": [
                        {"condition": rng.choice(conds), "categories": ["x"]}
                    ],
                },
                {"id": "mid", "kind": "merge"},
                {"id": "rel", "kind": "merge"},
            ]
            edges = []
            for i, (src, dst) in enumerate(
                [
                    ("sec", "mid"),
                    ("sec", "cl"),
                    ("cl", "rel"),
                    ("mid", "rel"),
                    ("pub", "mid"),
                ]
            ):
                if rng.random() < 0.8:
                    edges.append(
                        {
                            "id": f"e{i}",
                            "from": src,
                            "to": dst,
                            "condition": rng.choice(conds),
                        }
                    )
            targets = [{"id": "t", "node": "rel", "allowed_categories": ["p"]}]
            candidates = []
            for i in range(rng.randint(1, 4)):
                if rng.random() < 0.5 and edges:
                    edge = rng.choice(edges)
                    candidates.append(
                        {
                            "id": f"c{i}",
                            "kind": "disable_edge",
                            "edge": edge["id"],
                            "condition": rng.choice(conds),
                            "cost": rng.randint(1, 3),
                        }
                    )
                else:
                    candidates.append(
                        {
                            "id": f"c{i}",
                            "kind": "extend_cleaning",
                            "node": "cl",
                            "condition": rng.choice(conds),
                            "categories": ["x"],
                            "cost": rng.randint(1, 3),
                        }
                    )
            reqs = None
            if rng.random() < 0.5:
                reqs = [
                    {
                        "id": "r1",
                        "source": "pub",
                        "target": "t",
                        "requirement": rng.choice(["TRUE"] + switches),
                    }
                ]
            try:
                m = build(switches, nodes, edges, targets, candidates=candidates, reqs=reqs)
            except Exception:
                continue
            expected_best, expected_ids = oracle.solve_remediate(m)
            result = run_remediate(m)
            checked += 1
            with self.subTest(trial=trial):
                if expected_best is None:
                    self.assertFalse(result["solvable"])
                else:
                    self.assertTrue(result["solvable"])
                    self.assertEqual(result["policy"]["ids"], expected_ids)
                    self.assertEqual(result["policy"]["total_cost"], expected_best[0])
                    self.assertEqual(result["policy"]["action_count"], expected_best[1])
        self.assertGreaterEqual(checked, 15)


class SearchBudgetTests(unittest.TestCase):
    def test_eighteen_candidates_solve(self):
        # 18 independent leak edges -> {{c_i}} choices; a naive 2**18 sweep is
        # fine but we also assert the pruning counters appear.
        n = 18
        nodes = [{"id": "sec", "kind": "sensitive_source", "categories": ["s"]}]
        nodes.append({"id": "rel", "kind": "merge"})
        edges = []
        candidates = []
        for i in range(n):
            mid = f"mid{i}"
            nodes.append({"id": mid, "kind": "merge"})
            edges.append(
                {"id": f"e{i:02d}a", "from": "sec", "to": mid, "condition": "TRUE"}
            )
            edges.append({"id": f"e{i:02d}b", "from": mid, "to": "rel", "condition": "TRUE"})
            candidates.append(
                {
                    "id": f"c{i:02d}",
                    "kind": "disable_edge",
                    "edge": f"e{i:02d}a",
                    "condition": "TRUE",
                    "cost": 1,
                }
            )
        m = build(
            ["a"],
            nodes,
            edges,
            [{"id": "t", "node": "rel", "allowed_categories": []}],
            candidates=candidates,
        )
        result = run_remediate(m)
        self.assertTrue(result["solvable"])
        self.assertEqual(len(selected_ids(result)), n)
        self.assertEqual(result["search"]["candidates_total"], n)
        self.assertIn("pruned_feasible_superset", result["search"])

    def test_large_manifest_scales(self):
        # 200 nodes, 500 edges with several switches.
        switches = [f"s{i:02d}" for i in range(6)]
        nodes = [
            {"id": "sec", "kind": "sensitive_source", "categories": ["x"]},
            {"id": "pub", "kind": "public_source", "categories": ["p"]},
        ]
        edges = []
        for i in range(198):
            nodes.append({"id": f"n{i:03d}", "kind": "merge"})
        # A backbone chain.
        prev = "sec"
        for i in range(198):
            edges.append(
                {
                    "id": f"e{i:04d}",
                    "from": prev,
                    "to": f"n{i:03d}",
                    "condition": switches[i % len(switches)],
                }
            )
            prev = f"n{i:03d}"
        targets = [{"id": "t", "node": prev, "allowed_categories": []}]
        # 300 extra cross-links to reach 500 edges.
        k = 0
        for i in range(300):
            src = f"n{(i * 7) % 198:03d}"
            dst = f"n{(i * 13 + 5) % 198:03d}"
            if src == dst:
                continue
            edges.append(
                {
                    "id": f"x{k:04d}",
                    "from": src,
                    "to": dst,
                    "condition": switches[k % len(switches)],
                }
            )
            k += 1
        # Ensure DAG by only allowing edges from lower index to higher.
        fixed = []
        idx = {n["id"]: i for i, n in enumerate(nodes)}
        for edge in edges:
            if idx[edge["from"]] < idx[edge["to"]]:
                fixed.append(edge)
            else:
                fixed.append(
                    {**edge, "from": edge["to"], "to": edge["from"]}
                )
        m = build(switches, nodes, fixed, targets)
        from solution.audit import run_find

        result = run_find(m)
        self.assertEqual(result["ok"], True)
        self.assertLessEqual(len(m.edges), 500)
        self.assertEqual(len(m.nodes), 200)


if __name__ == "__main__":
    unittest.main()
