"""Tests for the boolean expression parser and evaluator."""

from __future__ import annotations

import unittest

from solution.errors import InputError
from solution.expr import evaluate, parse_expr, refs, render

SWITCHES = {"a": 0, "b": 1, "c": 2}


def parse(text):
    return parse_expr(text, SWITCHES, "$.test")


class ParserTests(unittest.TestCase):
    def test_literals(self):
        self.assertTrue(evaluate(parse("TRUE"), (False, False, False)))
        self.assertFalse(evaluate(parse("FALSE"), (True, True, True)))

    def test_variables_and_prefix(self):
        expr = parse("$a")
        self.assertTrue(evaluate(expr, (True, False, False)))
        self.assertFalse(evaluate(expr, (False, False, False)))

    def test_precedence_not_over_and_over_or(self):
        expr = parse("a OR b AND NOT c")
        self.assertTrue(evaluate(expr, (False, True, False)))
        self.assertFalse(evaluate(expr, (False, True, True)))
        self.assertTrue(evaluate(expr, (True, True, True)))

    def test_parentheses_override(self):
        expr = parse("(a OR b) AND NOT c")
        self.assertFalse(evaluate(expr, (True, False, True)))
        self.assertTrue(evaluate(expr, (True, False, False)))

    def test_keywords_case_insensitive(self):
        expr = parse("a and not b or c")
        self.assertTrue(evaluate(expr, (True, False, False)))
        self.assertTrue(evaluate(expr, (False, True, True)))
        self.assertFalse(evaluate(expr, (False, True, False)))

    def test_double_negation(self):
        expr = parse("NOT NOT a")
        self.assertTrue(evaluate(expr, (True, False, False)))
        self.assertFalse(evaluate(expr, (False, False, False)))

    def test_refs(self):
        self.assertEqual(refs(parse("a AND (b OR NOT c)")), {0, 1, 2})
        self.assertEqual(refs(parse("TRUE")), set())

    def test_render_round_trip(self):
        text = render(parse("a AND (b OR NOT c)"), ("a", "b", "c"))
        self.assertEqual(text, "(a AND (b OR NOT c))")


class ParserErrorTests(unittest.TestCase):
    def assert_code(self, text, code):
        with self.assertRaises(InputError) as ctx:
            parse(text)
        self.assertEqual(ctx.exception.code, code)
        self.assertTrue(ctx.exception.path)

    def test_unknown_switch(self):
        self.assert_code("a AND zz", "EXPR_UNKNOWN_SWITCH")

    def test_missing_rparen(self):
        self.assert_code("(a OR b", "EXPR_MISSING_RPAREN")

    def test_trailing_token(self):
        self.assert_code("a b", "EXPR_TRAILING_TOKEN")

    def test_empty(self):
        self.assert_code("   ", "EXPR_EMPTY")

    def test_bad_character(self):
        self.assert_code("a & b", "EXPR_BAD_CHAR")

    def test_not_a_string(self):
        with self.assertRaises(InputError) as ctx:
            parse_expr(17, SWITCHES, "$.x")
        self.assertEqual(ctx.exception.code, "EXPR_NOT_STRING")

    def test_dangling_operator(self):
        self.assert_code("a AND", "EXPR_UNEXPECTED_END")

    def test_stray_rparen(self):
        self.assert_code("a)", "EXPR_TRAILING_TOKEN")

    def test_error_carries_offset_in_message(self):
        with self.assertRaises(InputError) as ctx:
            parse("a AND zz")
        self.assertIn("offset", ctx.exception.message)


if __name__ == "__main__":
    unittest.main()
