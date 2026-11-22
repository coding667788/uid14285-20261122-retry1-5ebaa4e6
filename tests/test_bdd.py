"""Tests for the reduced ordered BDD package, cross-checked by enumeration."""

from __future__ import annotations

import itertools
import random
import unittest

from solution.bdd import BDD, FALSE, TRUE


def all_bits(n):
    return list(itertools.product((False, True), repeat=n))


class BDDTests(unittest.TestCase):
    def test_constants(self):
        b = BDD(3)
        self.assertEqual(b.count(TRUE), 8)
        self.assertEqual(b.count(FALSE), 0)
        self.assertFalse(b.satisfiable(FALSE))
        self.assertTrue(b.satisfiable(TRUE))

    def test_single_variable(self):
        b = BDD(2)
        a = b.var(0)
        self.assertEqual(b.count(a), 2)
        self.assertEqual(b.minimal_assignment(a), {0: True})
        self.assertEqual(b.count(b.neg(a)), 2)
        self.assertEqual(b.minimal_assignment(b.neg(a)), {0: False})

    def test_apply_matches_enumeration(self):
        b = BDD(3)
        a, bb, c = b.var(0), b.var(1), b.var(2)
        formulas = {
            "and": (b.and_(a, bb), lambda x, y, z: x and y),
            "or": (b.or_(a, c), lambda x, y, z: x or z),
            "xorish": (b.and_(b.or_(a, bb), b.neg(c)), lambda x, y, z: (x or y) and not z),
        }
        for name, (node, ref) in formulas.items():
            with self.subTest(name):
                for bits in all_bits(3):
                    self.assertEqual(b.evaluate(node, bits), ref(*bits))

    def test_minimal_assignment_is_lexicographic(self):
        b = BDD(3)
        a, bb, c = b.var(0), b.var(1), b.var(2)
        # (a OR b) AND c
        node = b.and_(b.or_(a, bb), c)
        partial = b.minimal_assignment(node)
        bits = tuple(partial.get(i, False) for i in range(3))
        satisfying = [x for x in all_bits(3) if b.evaluate(node, x)]
        self.assertEqual(bits, min(satisfying))

    def test_min_cost_prefers_defaults(self):
        b = BDD(2)
        a, bb = b.var(0), b.var(1)
        node = b.and_(a, bb)
        cost, bits = b.min_cost_assignment(node, (False, False))
        self.assertEqual(cost, 2)
        self.assertEqual(bits, (True, True))
        cost, bits = b.min_cost_assignment(node, (True, True))
        self.assertEqual(cost, 0)

    def test_min_cost_tie_break_lexicographic(self):
        b = BDD(2)
        a, bb = b.var(0), b.var(1)
        node = b.and_(a, bb)  # only one satisfying assignment
        self.assertEqual(b.min_cost_assignment(node, (False, True)), (1, (True, True)))

    def test_min_cost_unsatisfiable(self):
        b = BDD(2)
        self.assertIsNone(b.min_cost_assignment(FALSE, (False, False)))

    def test_implies(self):
        b = BDD(2)
        a, bb = b.var(0), b.var(1)
        self.assertTrue(b.implies(b.and_(a, bb), a))
        self.assertFalse(b.implies(a, bb))

    def test_restrict_and_exists(self):
        b = BDD(2)
        a, bb = b.var(0), b.var(1)
        node = b.and_(a, bb)
        self.assertEqual(b.restrict(node, 0, False), FALSE)
        self.assertEqual(b.restrict(node, 0, True), bb)
        self.assertEqual(b.exists(node, 0), bb)

    def test_random_cross_check(self):
        rng = random.Random(20261122)
        for trial in range(40):
            n = rng.randint(1, 4)
            b = BDD(n)
            nodes = [b.var(i) for i in range(n)]
            for _ in range(rng.randint(1, 6)):
                op = rng.choice(("and", "or"))
                left = rng.choice(nodes)
                right = rng.choice(nodes + [b.neg(x) for x in nodes])
                nodes.append(b.and_(left, right) if op == "and" else b.or_(left, right))
            node = nodes[-1]
            expected = sum(
                1 for bits in all_bits(n) if b.evaluate(node, bits)
            )
            self.assertEqual(b.count(node), expected)
            satisfying = [bits for bits in all_bits(n) if b.evaluate(node, bits)]
            if satisfying:
                partial = b.minimal_assignment(node)
                bits = tuple(partial.get(i, False) for i in range(n))
                self.assertEqual(bits, min(satisfying))

    def test_cache_reuses_identical_formulas(self):
        b = BDD(3)
        a = b.var(0)
        first = b.and_(a, b.var(1))
        second = b.and_(b.var(1), a)  # commutative, same node
        self.assertEqual(first, second)
        self.assertLess(b.node_count(), 12)


if __name__ == "__main__":
    unittest.main()
