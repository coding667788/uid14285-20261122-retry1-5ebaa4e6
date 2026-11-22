"""A small ordered binary decision diagram (BDD) package.

The audit reasons symbolically over switch assignments instead of enumerating
up to ``2**24`` concrete assignments.  Every boolean formula becomes a reduced,
ordered BDD over the switch variables; conjunction/disjunction/negation and
satisfiability counting are then cheap graph operations.

Ordering is the lexicographic switch order (switch IDs ascending, ``false``
before ``true``), which also makes :meth:`BDD.minimal_assignment` return the
lexicographically smallest satisfying assignment in one descent.
"""

from __future__ import annotations

from .errors import AnalysisError

FALSE = 0
TRUE = 1

DEFAULT_NODE_LIMIT = 1_000_000


class BDD:
    """Hash-consed, reduced, ordered BDD manager for ``num_vars`` variables."""

    def __init__(self, num_vars: int, node_limit: int = DEFAULT_NODE_LIMIT):
        self.num_vars = num_vars
        self.node_limit = node_limit
        # nodes[i] = (var, low, high) for i >= 2
        self._nodes: list[tuple[int, int, int] | None] = [None, None]
        self._unique: dict[tuple[int, int, int], int] = {}
        self._apply_cache: dict[tuple[str, int, int], int] = {}
        self._neg_cache: dict[int, int] = {}
        self._count_cache: dict[tuple[int, int], int] = {}
        self._var_cache: dict[int, int] = {}

    # -- construction -----------------------------------------------------
    def mk(self, var: int, low: int, high: int) -> int:
        if low == high:
            return low
        key = (var, low, high)
        existing = self._unique.get(key)
        if existing is not None:
            return existing
        node_id = len(self._nodes)
        if node_id >= self.node_limit:
            raise AnalysisError(
                "BDD_NODE_LIMIT",
                "$",
                "symbolic representation exceeded the node limit; "
                "the switch constraints are too complex for this build",
            )
        self._nodes.append(key)
        self._unique[key] = node_id
        return node_id

    def var(self, index: int) -> int:
        cached = self._var_cache.get(index)
        if cached is None:
            cached = self.mk(index, FALSE, TRUE)
            self._var_cache[index] = cached
        return cached

    # -- accessors --------------------------------------------------------
    def is_terminal(self, node: int) -> bool:
        return node < 2

    def top(self, node: int) -> int:
        if node < 2:
            return self.num_vars
        return self._nodes[node][0]

    def low(self, node: int) -> int:
        return self._nodes[node][1]

    def high(self, node: int) -> int:
        return self._nodes[node][2]

    def node_count(self) -> int:
        return len(self._nodes)

    # -- operations -------------------------------------------------------
    def neg(self, a: int) -> int:
        if a == FALSE:
            return TRUE
        if a == TRUE:
            return FALSE
        cached = self._neg_cache.get(a)
        if cached is not None:
            return cached
        var, lo, hi = self._nodes[a]
        result = self.mk(var, self.neg(lo), self.neg(hi))
        self._neg_cache[a] = result
        self._neg_cache.setdefault(result, a)
        return result

    def apply(self, op: str, a: int, b: int) -> int:
        if op in ("and", "or") and a > b:
            a, b = b, a
        if op == "and":
            if a == FALSE or b == FALSE:
                return FALSE
            if a == TRUE:
                return b
            if b == TRUE:
                return a
        else:  # or
            if a == TRUE or b == TRUE:
                return TRUE
            if a == FALSE:
                return b
            if b == FALSE:
                return a
        if a == b:
            return a
        key = (op, a, b)
        cached = self._apply_cache.get(key)
        if cached is not None:
            return cached
        va = self.top(a)
        vb = self.top(b)
        var = va if va < vb else vb
        a_lo = self.low(a) if va == var else a
        a_hi = self.high(a) if va == var else a
        b_lo = self.low(b) if vb == var else b
        b_hi = self.high(b) if vb == var else b
        lo = self.apply(op, a_lo, b_lo)
        hi = self.apply(op, a_hi, b_hi)
        result = self.mk(var, lo, hi)
        self._apply_cache[key] = result
        return result

    def and_(self, a: int, b: int) -> int:
        return self.apply("and", a, b)

    def or_(self, a: int, b: int) -> int:
        return self.apply("or", a, b)

    def and_all(self, nodes) -> int:
        result = TRUE
        for node in nodes:
            result = self.and_(result, node)
            if result == FALSE:
                break
        return result

    def or_all(self, nodes) -> int:
        result = FALSE
        for node in nodes:
            result = self.or_(result, node)
            if result == TRUE:
                break
        return result

    def implies(self, a: int, b: int) -> bool:
        """True when every assignment satisfying ``a`` also satisfies ``b``."""
        return self.and_(a, self.neg(b)) == FALSE

    # -- analysis ---------------------------------------------------------
    def satisfiable(self, a: int) -> bool:
        return a != FALSE

    def count(self, node: int, level: int = 0) -> int:
        """Number of complete assignments (over all vars) satisfying ``node``."""
        key = (node, level)
        cached = self._count_cache.get(key)
        if cached is not None:
            return cached
        if node == FALSE:
            result = 0
        elif node == TRUE:
            result = 1 << (self.num_vars - level)
        else:
            var, lo, hi = self._nodes[node]
            if var < level:
                raise AssertionError("BDD is not ordered")
            skipped = 1 << (var - level)
            result = skipped * (
                self.count(lo, var + 1) + self.count(hi, var + 1)
            )
        self._count_cache[key] = result
        return result

    def minimal_assignment(self, node: int) -> dict[int, bool] | None:
        """Lexicographically smallest satisfying assignment, or ``None``.

        Variables absent from the result are implicitly ``false``; the caller
        expands them to a full assignment.  Descending through ``low`` first
        follows the ``false``-before-``true`` order at every variable, so the
        first satisfiable leaf reached is the lexicographic minimum.
        """
        if node == FALSE:
            return None
        result: dict[int, bool] = {}
        current = node
        while current != TRUE:
            var, lo, hi = self._nodes[current]
            if lo != FALSE:
                result[var] = False
                current = lo
            else:
                result[var] = True
                current = hi
        return result

    def evaluate(self, node: int, assignment: tuple[bool, ...]) -> bool:
        """Evaluate a BDD node under one complete assignment."""
        while node >= 2:
            var, lo, hi = self._nodes[node]
            node = hi if assignment[var] else lo
        return node == TRUE

    def min_cost_assignment(
        self, node: int, defaults: tuple[bool, ...]
    ) -> tuple[int, tuple[bool, ...]] | None:
        """Minimise Hamming distance from ``defaults``, tie-break lexicographic.

        Returns ``(cost, bits)`` where ``bits`` is a complete assignment over all
        variables, or ``None`` when ``node`` is unsatisfiable.  Variables that
        are skipped by the BDD take their default value (cost 0).
        """
        if node == FALSE:
            return None
        memo: dict[tuple[int, int], tuple[int, tuple[bool, ...]] | None] = {}

        def go(current: int, level: int):
            if current == FALSE:
                return None
            if current == TRUE:
                return (0, tuple(defaults[level:]))
            key = (current, level)
            if key in memo:
                return memo[key]
            var, lo, hi = self._nodes[current]
            assert var >= level, "BDD is not ordered"
            skipped = tuple(defaults[level:var])
            best = None
            for bit, child in ((False, lo), (True, hi)):
                sub = go(child, var + 1)
                if sub is None:
                    continue
                cost = sub[0] + (0 if bit == defaults[var] else 1)
                bits = skipped + (bit,) + sub[1]
                candidate = (cost, bits)
                if best is None or candidate < best:
                    best = candidate
            memo[key] = best
            return best

        found = go(node, 0)
        if found is None:
            return None
        return found

    def restrict(self, node: int, var: int, value: bool) -> int:
        """Cofactor: ``node`` with ``var`` fixed to ``value``."""
        if node < 2 or self.top(node) > var:
            return node
        memo: dict[int, int] = {}

        def go(current: int) -> int:
            if current < 2:
                return current
            cached = memo.get(current)
            if cached is not None:
                return cached
            v, lo, hi = self._nodes[current]
            if v == var:
                result = lo if not value else hi
            elif v > var:
                result = current
            else:
                result = self.mk(v, go(lo), go(hi))
            memo[current] = result
            return result

        return go(node)

    def exists(self, node: int, var: int) -> int:
        """Existentially quantify ``var`` out of ``node``."""
        lo = self.restrict(node, var, False)
        hi = self.restrict(node, var, True)
        return self.or_(lo, hi)

    def support(self, node: int) -> set[int]:
        seen: set[int] = set()
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur < 2:
                continue
            var, lo, hi = self._nodes[cur]
            if var in seen:
                continue
            seen.add(var)
            stack.append(lo)
            stack.append(hi)
        return seen
