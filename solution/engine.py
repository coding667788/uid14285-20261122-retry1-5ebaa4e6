"""Symbolic risk propagation over the build DAG.

Semantics for one concrete switch assignment
-------------------------------------------
* An assignment is *legal* when every ``switch_constraints`` formula is true.
* An edge is *active* when its condition is true and no approved action
  disables it for this assignment.
* Each node's risk is the union of the categories it originates (source nodes)
  and of the risk arriving over active incoming edges.
* A sanitizer removes a category from the risk that actually arrives whenever
  one of its clean rules for that category holds.  Cleaning therefore only
  affects categories flowing *through that node*: an alternative, un-cleaned
  path still contributes the same category.  This is why risk is propagated as
  one boolean formula per (node, category) and never as a per-path set.

Symbolic representation (why no 2**24 enumeration)
--------------------------------------------------
Every formula -- switch constraints, edge conditions, clean conditions, and
"category ``c`` is present at node ``n``" -- is a reduced ordered BDD over the
switch variables (see :mod:`solution.bdd`).  Consequently:

* the legal domain is one BDD, counted exactly in a single descent;
* "is this target unsafe for *some* legal assignment?" is a satisfiability test;
* the lexicographically smallest leaking assignment is a descent that prefers
  the ``false`` branch at every variable;
* compare is a BDD difference restricted to the common legal domain.

Category presence is a least fixpoint over the topologically sorted DAG, so
each (node, category) pair is computed once per policy.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from .bdd import BDD, FALSE, TRUE
from .expr import Expr, render
from .manifest import Candidate, Manifest, Target, topological_order

# Node kinds ---------------------------------------------------------------
PUBLIC = "public_source"
SENSITIVE = "sensitive_source"
MERGE = "merge"
SANITIZER = "sanitizer"


@dataclass(frozen=True)
class Policy:
    """A set of approved remediation actions, applied to every assignment."""

    selected: frozenset[str] = frozenset()

    def with_action(self, action_id: str) -> "Policy":
        return Policy(self.selected | {action_id})


@dataclass
class Propagated:
    """Risk formulas for one policy.

    ``reach[node][category]`` is the BDD of assignments under which the
    category is present at the node (after any cleaning at that node).
    """

    live: dict[int, int]
    cleans: dict[tuple[int, str], int]
    reach: dict[tuple[int, str], int] = field(default_factory=dict)


class Engine:
    """Symbolic evaluator for one parsed manifest.

    Engines that reason about two manifests with the same switch set (compare)
    can share one :class:`~solution.bdd.BDD` manager so their formulas live in
    the same decision diagram.
    """

    def __init__(self, manifest: Manifest, bdd: BDD | None = None):
        self.m = manifest
        self.num_vars = len(manifest.switches)
        self.names = manifest.switch_ids
        self.bdd = bdd if bdd is not None else BDD(self.num_vars)
        self._expr_cache: dict[Expr, int] = {}
        self._policy_cache: dict[tuple, Propagated] = {}
        self._safe_cache: dict[tuple, bool] = {}
        self._req_cache: dict[tuple, list[dict]] = {}
        self._policy_stats: dict[str, int] = {
            "evaluations": 0,
            "cache_hits": 0,
        }

        self.legal = self.bdd.and_all(
            [self.compile(expr) for expr in manifest.constraints]
        ) if manifest.constraints else TRUE

        self.node_ids = [n.id for n in manifest.nodes]
        self.node_index = manifest.node_index
        self.topo = [self.node_index[nid] for nid in topological_order(manifest)]

        self.in_edges: list[list[tuple[int, int]]] = [
            [] for _ in manifest.nodes
        ]
        self.out_edges: list[list[tuple[int, int]]] = [
            [] for _ in manifest.nodes
        ]
        self.edge_condition: list[int] = []
        for idx, edge in enumerate(manifest.edges):
            cond = self.compile(edge.condition)
            self.edge_condition.append(cond)
            src = self.node_index[edge.source]
            dst = self.node_index[edge.target]
            self.in_edges[dst].append((idx, src))
            self.out_edges[src].append((idx, dst))

        # Categories that can ever be sensitive: emitted by a sensitive source.
        sensitive: set[str] = set()
        for node in manifest.nodes:
            if node.kind == SENSITIVE:
                sensitive.update(node.categories)
        self.sensitive_cats = tuple(sorted(sensitive))

        # Categories that at least one target forbids (and that can be sensitive).
        relevant: set[str] = set()
        for target in manifest.targets:
            relevant.update(c for c in self.sensitive_cats if c not in target.allowed)
        self.relevant_cats = tuple(sorted(relevant))

        self.emits: dict[int, frozenset[str]] = {}
        for idx, node in enumerate(manifest.nodes):
            if node.kind in (PUBLIC, SENSITIVE):
                self.emits[idx] = frozenset(
                    c for c in node.categories if c in sensitive
                )

        self.target_index = manifest.targets
        self.requirements = manifest.requirements
        self.candidate_index = {c.id: c for c in manifest.candidates}

    # -- expression compilation ------------------------------------------
    def compile(self, expr: Expr) -> int:
        cached = self._expr_cache.get(expr)
        if cached is not None:
            return cached
        op = expr[0]
        if op == "const":
            node = TRUE if expr[1] else FALSE
        elif op == "var":
            node = self.bdd.var(expr[1])
        elif op == "not":
            node = self.bdd.neg(self.compile(expr[1]))
        elif op == "and":
            node = self.bdd.and_(self.compile(expr[1]), self.compile(expr[2]))
        elif op == "or":
            node = self.bdd.or_(self.compile(expr[1]), self.compile(expr[2]))
        else:  # pragma: no cover - guarded by the parser
            raise AssertionError(op)
        self._expr_cache[expr] = node
        return node

    # -- policies ---------------------------------------------------------
    def _selected_candidates(self, policy: Policy) -> list[Candidate]:
        return [
            c for c in self.m.candidates if c.id in policy.selected
        ]

    def derive(self, policy: Policy) -> tuple[dict[int, int], dict[tuple[int, str], int]]:
        """Effective live-edge and cleaning formulas for ``policy``."""
        selected = self._selected_candidates(policy)
        disables: dict[int, list[int]] = {}
        clean_extra: dict[tuple[int, str], list[int]] = {}
        for candidate in selected:
            if candidate.kind == "disable_edge":
                edge_idx = self.m.edge_index[candidate.edge]
                disables.setdefault(edge_idx, []).append(
                    self.compile(candidate.disable)
                )
            else:
                node_idx = self.node_index[candidate.node]
                cond = self.compile(candidate.condition)
                for cat in candidate.categories:
                    clean_extra.setdefault((node_idx, cat), []).append(cond)

        live: dict[int, int] = {}
        for idx, base in enumerate(self.edge_condition):
            if idx in disables:
                # Several disable candidates on one edge compose: the edge is
                # off when *any* of them applies.
                blocked = self.bdd.or_all(disables[idx])
                live[idx] = self.bdd.and_(base, self.bdd.neg(blocked))
            else:
                live[idx] = base

        cleans: dict[tuple[int, str], int] = {}
        for idx, node in enumerate(self.m.nodes):
            if node.kind != SANITIZER:
                continue
            for rule in node.cleans:
                rule_bdd = self.compile(rule.condition)
                for cat in rule.categories:
                    key = (idx, cat)
                    cleans[key] = self.bdd.or_(cleans.get(key, FALSE), rule_bdd)
        for (node_idx, cat), conditions in clean_extra.items():
            key = (node_idx, cat)
            extra = self.bdd.or_all(conditions)
            cleans[key] = self.bdd.or_(cleans.get(key, FALSE), extra)
        return live, cleans

    @staticmethod
    def signature(policy: Policy) -> tuple:
        return (tuple(sorted(policy.selected)),)

    def propagate(self, policy: Policy) -> Propagated:
        key = self.signature(policy)
        cached = self._policy_cache.get(key)
        if cached is not None:
            self._policy_stats["cache_hits"] += 1
            return cached
        self._policy_stats["evaluations"] += 1
        live, cleans = self.derive(policy)
        reach: dict[tuple[int, str], int] = {}
        cats = self.sensitive_cats
        if not cats:
            result = Propagated(live=live, cleans=cleans, reach=reach)
            self._policy_cache[key] = result
            return result
        for node_idx in self.topo:
            emitted = self.emits.get(node_idx, frozenset())
            incoming = self.in_edges[node_idx]
            is_sanitizer = self.m.nodes[node_idx].kind == SANITIZER
            for cat in cats:
                acc = FALSE
                for edge_idx, src_idx in incoming:
                    sub = reach.get((src_idx, cat), FALSE)
                    if sub == FALSE:
                        continue
                    acc = self.bdd.or_(acc, self.bdd.and_(live[edge_idx], sub))
                if is_sanitizer:
                    clean = cleans.get((node_idx, cat), FALSE)
                    if clean != FALSE:
                        acc = self.bdd.and_(acc, self.bdd.neg(clean))
                if cat in emitted:
                    acc = TRUE
                reach[(node_idx, cat)] = acc
        result = Propagated(live=live, cleans=cleans, reach=reach)
        self._policy_cache[key] = result
        return result

    # -- assignment helpers ----------------------------------------------
    def bits(self, partial: dict[int, bool]) -> tuple[bool, ...]:
        return tuple(partial.get(i, False) for i in range(self.num_vars))

    def assignment_dict(self, bits: tuple[bool, ...]) -> dict[str, bool]:
        return {name: bool(bits[i]) for i, name in enumerate(self.names)}

    def legal_count(self) -> int:
        return self.bdd.count(self.legal)

    def leaked(self, policy: Policy, target: Target, cat: str) -> int:
        """BDD of legal assignments where ``cat`` leaks into ``target``."""
        prop = self.propagate(policy)
        node_idx = self.node_index[target.node]
        risk = prop.reach.get((node_idx, cat), FALSE)
        return self.bdd.and_(self.legal, risk)

    # -- audits -----------------------------------------------------------
    def audit_targets(self, policy: Policy, with_chains: bool = True) -> list[dict]:
        prop = self.propagate(policy)
        out: list[dict] = []
        for target in sorted(self.m.targets, key=lambda t: t.id):
            node_idx = self.node_index[target.node]
            forbidden = [
                c for c in self.sensitive_cats if c not in target.allowed
            ]
            leaks: list[dict] = []
            for cat in forbidden:
                leak_bdd = self.bdd.and_(
                    self.legal, prop.reach.get((node_idx, cat), FALSE)
                )
                if leak_bdd == FALSE:
                    continue
                minimal = self.bdd.minimal_assignment(leak_bdd)
                assert minimal is not None
                bits = self.bits(minimal)
                entry = {
                    "category": cat,
                    "assignment": self.assignment_dict(bits),
                    "assignment_bits": list(bits),
                }
                if with_chains:
                    chain = self.shortest_chain(bits, node_idx, cat, prop)
                    entry["chain"] = chain
                leaks.append(entry)
            out.append(
                {
                    "target": target.id,
                    "node": target.node,
                    "allowed_categories": sorted(target.allowed),
                    "safe": not leaks,
                    "leaks": leaks,
                }
            )
        return out

    def shortest_chain(
        self,
        bits: tuple[bool, ...],
        target_idx: int,
        cat: str,
        prop: Propagated,
    ) -> dict | None:
        """Shortest un-cleaned source chain for ``cat`` under ``bits``.

        Tie-break: fewest edges, then lexicographically smallest edge-ID tuple.
        Nodes whose cleaning is active for ``cat`` cannot carry the category
        onwards, so the search never expands from them.
        """
        blocked: set[int] = set()
        for idx, node in enumerate(self.m.nodes):
            if node.kind != SANITIZER:
                continue
            clean = prop.cleans.get((idx, cat), FALSE)
            if clean != FALSE and self.bdd.evaluate(clean, bits):
                blocked.add(idx)
        if target_idx in blocked:
            return None

        starts = [
            idx
            for idx, node in enumerate(self.m.nodes)
            if node.kind == SENSITIVE and cat in node.categories and idx not in blocked
        ]
        if not starts:
            return None

        heap: list[tuple[int, tuple[str, ...], tuple[str, ...], int]] = []
        best: dict[int, tuple[int, tuple[str, ...]]] = {}
        for start in starts:
            key = (0, ())
            if start not in best or key < best[start]:
                best[start] = key
                heapq.heappush(
                    heap,
                    (0, (), (self.node_ids[start],), start),
                )
        edge_ids = [e.id for e in self.m.edges]
        while heap:
            length, seq, nodes, node_idx = heapq.heappop(heap)
            if best.get(node_idx) != (length, seq):
                continue
            if node_idx == target_idx:
                return {
                    "source": nodes[0],
                    "nodes": list(nodes),
                    "edges": list(seq),
                    "length": length,
                }
            for edge_idx, dst in self.out_edges[node_idx]:
                if dst in blocked:
                    continue
                if not self.bdd.evaluate(prop.live[edge_idx], bits):
                    continue
                candidate = (length + 1, seq + (edge_ids[edge_idx],))
                if dst in best and best[dst] <= candidate:
                    continue
                best[dst] = candidate
                heapq.heappush(
                    heap,
                    (
                        candidate[0],
                        candidate[1],
                        nodes + (self.node_ids[dst],),
                        dst,
                    ),
                )
        return None

    # -- required reachability -------------------------------------------
    def reachable_bdd(
        self, source_idx: int, target_idx: int, live: dict[int, int]
    ) -> int:
        """BDD of assignments under which ``source`` reaches ``target``."""
        can: dict[int, int] = {}
        for node_idx in self.topo:
            if node_idx == source_idx:
                can[node_idx] = TRUE
                continue
            acc = FALSE
            for edge_idx, src_idx in self.in_edges[node_idx]:
                sub = can.get(src_idx, FALSE)
                if sub == FALSE:
                    continue
                acc = self.bdd.or_(acc, self.bdd.and_(live[edge_idx], sub))
            can[node_idx] = acc
        return can.get(target_idx, FALSE)

    def requirement_status(self, policy: Policy) -> list[dict]:
        live, _cleans = self.derive(policy)
        targets = {t.id: t for t in self.m.targets}
        out: list[dict] = []
        for req in sorted(self.requirements, key=lambda r: r.id):
            source_idx = self.node_index[req.source]
            target = targets[req.target]
            target_idx = self.node_index[target.node]
            reach = self.reachable_bdd(source_idx, target_idx, live)
            formula = self.compile(req.requirement)
            gated = self.bdd.and_(self.legal, formula)
            violation = self.bdd.and_(gated, self.bdd.neg(reach))
            holds = violation == FALSE
            count = self.bdd.count(gated)
            minimal = self.bdd.minimal_assignment(gated)
            entry = {
                "id": req.id,
                "source": req.source,
                "target": req.target,
                "requirement": render(req.requirement, self.names),
                "satisfied": holds,
                "assignment_count": count,
                "vacuous": count == 0,
            }
            if minimal is not None:
                bits = self.bits(minimal)
                entry["satisfying_assignment"] = self.assignment_dict(bits)
                entry["satisfying_assignment_bits"] = list(bits)
                if holds:
                    entry["path"] = self.shortest_path(
                        bits, source_idx, target_idx, live
                    )
                else:
                    witness = self.bdd.minimal_assignment(violation)
                    assert witness is not None
                    wbits = self.bits(witness)
                    entry["violation_assignment"] = self.assignment_dict(wbits)
                    entry["violation_assignment_bits"] = list(wbits)
            out.append(entry)
        return out

    def shortest_path(
        self,
        bits: tuple[bool, ...],
        source_idx: int,
        target_idx: int,
        live: dict[int, int],
    ) -> dict | None:
        """Shortest edge-count path, tie-broken by edge-ID sequence."""
        edge_ids = [e.id for e in self.m.edges]
        heap: list[tuple[int, tuple[str, ...], tuple[str, ...], int]] = [
            (0, (), (self.node_ids[source_idx],), source_idx)
        ]
        best: dict[int, tuple[int, tuple[str, ...]]] = {source_idx: (0, ())}
        while heap:
            length, seq, nodes, node_idx = heapq.heappop(heap)
            if best.get(node_idx) != (length, seq):
                continue
            if node_idx == target_idx:
                return {
                    "nodes": list(nodes),
                    "edges": list(seq),
                    "length": length,
                }
            for edge_idx, dst in self.out_edges[node_idx]:
                if not self.bdd.evaluate(live[edge_idx], bits):
                    continue
                candidate = (length + 1, seq + (edge_ids[edge_idx],))
                if dst in best and best[dst] <= candidate:
                    continue
                best[dst] = candidate
                heapq.heappush(
                    heap,
                    (
                        candidate[0],
                        candidate[1],
                        nodes + (self.node_ids[dst],),
                        dst,
                    ),
                )
        return None

    # -- global safety ----------------------------------------------------
    def is_safe(self, policy: Policy) -> bool:
        key = self.signature(policy)
        cached = self._safe_cache.get(key)
        if cached is not None:
            return cached
        prop = self.propagate(policy)
        result = True
        for target in self.m.targets:
            node_idx = self.node_index[target.node]
            for cat in self.sensitive_cats:
                if cat in target.allowed:
                    continue
                risk = prop.reach.get((node_idx, cat), FALSE)
                if risk == FALSE:
                    continue
                if self.bdd.and_(self.legal, risk) != FALSE:
                    result = False
                    break
            if not result:
                break
        self._safe_cache[key] = result
        return result

    def requirements_hold(self, policy: Policy) -> bool:
        key = self.signature(policy)
        cached = self._req_cache.get(key)
        if cached is None:
            cached = self.requirement_status(policy)
            self._req_cache[key] = cached
        return all(entry["satisfied"] for entry in cached)

    def residual_leaks(self, policy: Policy) -> list[dict]:
        """First residual leak per (target, category), with witness chain."""
        prop = self.propagate(policy)
        out: list[dict] = []
        for target in sorted(self.m.targets, key=lambda t: t.id):
            node_idx = self.node_index[target.node]
            for cat in sorted(
                c for c in self.sensitive_cats if c not in target.allowed
            ):
                risk = self.bdd.and_(
                    self.legal, prop.reach.get((node_idx, cat), FALSE)
                )
                if risk == FALSE:
                    continue
                minimal = self.bdd.minimal_assignment(risk)
                assert minimal is not None
                bits = self.bits(minimal)
                out.append(
                    {
                        "target": target.id,
                        "target_node": target.node,
                        "target_index": node_idx,
                        "category": cat,
                        "assignment": self.assignment_dict(bits),
                        "assignment_bits": list(bits),
                        "chain": self.shortest_chain(bits, node_idx, cat, prop),
                    }
                )
        return out

    def requirement_violations(self, policy: Policy) -> list[dict]:
        status = self.requirement_status(policy)
        return [s for s in status if not s["satisfied"]]

    # -- diagnostics ------------------------------------------------------
    def stats(self) -> dict:
        return {
            "bdd_nodes": self.bdd.node_count(),
            "propagation_evaluations": self._policy_stats["evaluations"],
            "propagation_cache_hits": self._policy_stats["cache_hits"],
        }
