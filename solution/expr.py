"""Boolean expressions over switches: strict parsing and evaluation.

Grammar (whitespace insignificant, keywords are case insensitive)::

    expr := or
    or   := and ( 'OR' and )*
    and  := not ( 'AND' not )*
    not  := 'NOT' not | atom
    atom := 'TRUE' | 'FALSE' | switch-ref | '(' expr ')'

A *switch reference* is a switch ID, optionally written ``$ID``.  IDs are
matched exactly (case sensitive) because they are data, not keywords.

Expressions are parsed once into a small immutable AST of tuples so that
evaluation is a cheap recursive walk over a tuple assignment, and so identical
sub-expressions can be memoised for symbolic evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InputError

# Token kinds -------------------------------------------------------------
EOF = "EOF"
IDENT = "IDENT"
LPAREN = "LPAREN"
RPAREN = "RPAREN"
AND = "AND"
OR = "OR"
NOT = "NOT"
TRUE = "TRUE"
FALSE = "FALSE"

KEYWORDS = {
    "AND": AND,
    "OR": OR,
    "NOT": NOT,
    "TRUE": TRUE,
    "FALSE": FALSE,
}

# AST node layout (tuples keep nodes hashable for memo tables):
#   ("const", bool)
#   ("var",   switch_index)
#   ("not",   child)
#   ("and",   left, right)
#   ("or",    left, right)
Expr = tuple


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    offset: int


def tokenize(source: str, path: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append(Token(LPAREN, ch, i))
            i += 1
            continue
        if ch == ")":
            tokens.append(Token(RPAREN, ch, i))
            i += 1
            continue
        if ch.isalpha() or ch == "_" or ch == "$":
            start = i
            i += 1
            while i < n and (source[i].isalnum() or source[i] in "_.-$"):
                i += 1
            word = source[start:i]
            kind = KEYWORDS.get(word.upper())
            tokens.append(Token(kind or IDENT, word, start))
            continue
        raise InputError(
            "EXPR_BAD_CHAR",
            path,
            f"unexpected character {ch!r} at offset {i}",
        )
    tokens.append(Token(EOF, "", n))
    return tokens


class _Parser:
    def __init__(self, source: str, switch_index: dict[str, int], path: str):
        self.path = path
        self.switch_index = switch_index
        self.tokens = tokenize(source, path)
        self.pos = 0

    # -- token helpers ----------------------------------------------------
    def peek(self) -> Token:
        return self.tokens[self.pos]

    def take(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def at(self, kind: str) -> bool:
        return self.tokens[self.pos].kind == kind

    # -- grammar ----------------------------------------------------------
    def parse(self) -> Expr:
        node = self.parse_or()
        if not self.at(EOF):
            tok = self.peek()
            raise InputError(
                "EXPR_TRAILING_TOKEN",
                self.path,
                f"unexpected token {tok.text!r} at offset {tok.offset}",
            )
        return node

    def parse_or(self) -> Expr:
        node = self.parse_and()
        while self.at(OR):
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self) -> Expr:
        node = self.parse_not()
        while self.at(AND):
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self) -> Expr:
        if self.at(NOT):
            self.take()
            return ("not", self.parse_not())
        return self.parse_atom()

    def parse_atom(self) -> Expr:
        tok = self.peek()
        if tok.kind == LPAREN:
            self.take()
            node = self.parse_or()
            if not self.at(RPAREN):
                here = self.peek()
                raise InputError(
                    "EXPR_MISSING_RPAREN",
                    self.path,
                    f"expected ')' at offset {here.offset}",
                )
            self.take()
            return node
        if tok.kind == TRUE:
            self.take()
            return ("const", True)
        if tok.kind == FALSE:
            self.take()
            return ("const", False)
        if tok.kind == IDENT:
            self.take()
            name = tok.text[1:] if tok.text.startswith("$") else tok.text
            index = self.switch_index.get(name)
            if index is None:
                raise InputError(
                    "EXPR_UNKNOWN_SWITCH",
                    self.path,
                    f"unknown switch {tok.text!r} at offset {tok.offset}",
                )
            return ("var", index)
        if tok.kind == EOF:
            raise InputError(
                "EXPR_UNEXPECTED_END",
                self.path,
                f"expression ended unexpectedly at offset {tok.offset}",
            )
        raise InputError(
            "EXPR_UNEXPECTED_TOKEN",
            self.path,
            f"unexpected token {tok.text!r} at offset {tok.offset}",
        )


def parse_expr(
    source: object, switch_index: dict[str, int], path: str
) -> Expr:
    """Parse ``source`` into an AST, validating every switch reference."""
    if not isinstance(source, str):
        raise InputError("EXPR_NOT_STRING", path, "expression must be a string")
    if not source.strip():
        raise InputError("EXPR_EMPTY", path, "expression must not be empty")
    return _Parser(source, switch_index, path).parse()


def evaluate(expr: Expr, assignment: tuple[bool, ...]) -> bool:
    """Evaluate an AST against a complete assignment tuple."""
    op = expr[0]
    if op == "const":
        return expr[1]
    if op == "var":
        return assignment[expr[1]]
    if op == "not":
        return not evaluate(expr[1], assignment)
    if op == "and":
        return evaluate(expr[1], assignment) and evaluate(expr[2], assignment)
    if op == "or":
        return evaluate(expr[1], assignment) or evaluate(expr[2], assignment)
    raise AssertionError(f"unknown AST node {op!r}")


def refs(expr: Expr) -> frozenset[int]:
    """Switch indices referenced anywhere in ``expr``."""
    op = expr[0]
    if op == "const":
        return frozenset()
    if op == "var":
        return frozenset((expr[1],))
    if op == "not":
        return refs(expr[1])
    return refs(expr[1]) | refs(expr[2])


def render(expr: Expr, names: tuple[str, ...]) -> str:
    """Render an AST back to canonical text (used for witnesses)."""
    op = expr[0]
    if op == "const":
        return "TRUE" if expr[1] else "FALSE"
    if op == "var":
        return names[expr[1]]
    if op == "not":
        inner = render(expr[1], names)
        if expr[1][0] in ("and", "or"):
            return f"NOT ({inner})"
        return f"NOT {inner}"
    if op == "and":
        return f"({render(expr[1], names)} AND {render(expr[2], names)})"
    if op == "or":
        return f"({render(expr[1], names)} OR {render(expr[2], names)})"
    raise AssertionError(f"unknown AST node {op!r}")
