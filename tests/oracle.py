"""Brute-force reference oracle for tiny manifests (test-only).

The production engine is symbolic (BDDs).  These helpers enumerate concrete
assignments directly from the documented semantics, with no BDD involvement, so
the test suite can cross-check the symbolic result against an independent
implementation.  They are deliberately slow and only suitable for a handful of
switches.
"""

from __future__ import annotations

import itertools

from solution.expr import evaluate


def all_assignments(n: int):
    for bits in itertools.product((False, True), repeat=n):
        yield tuple(bits)


def legal_assignments(manifest, policy=None):
    selected = set() if policy is None else policy.selected
    disabled_by = {}
    extra_clean = {}
    if selected:
        for candidate in manifest.candidates:
            if candidate.id not in selected:
                continue
            if candidate.kind == "disable_edge":
                disabled_by[manifest.edge_index[candidate.edge]] = candidate.disable
            else:
                node_idx = manifest.node_index[candidate.node]
                for cat in candidate.categories:
                    extra_clean.setdefault((node_idx, cat), []).append(
                        candidate.condition
                    )
    live = {}
    for idx, edge in enumerate(manifest.edges):
        def ok(bits, edge=edge, idx=idx):
            if not evaluate(edge.condition, bits):
                return False
            formula = disabled_by.get(idx)
            return formula is None or not evaluate(formula, bits)

        live[idx] = ok

    clean = {}
    for idx, node in enumerate(manifest.nodes):
        if node.kind != "sanitizer":
            continue
        for rule in node.cleans:
            for cat in rule.categories:
                clean.setdefault((idx, cat), []).append(rule.condition)
    for key, formulas in extra_clean.items():
        clean.setdefault(key, []).extend(formulas)

    states = []
    for bits in all_assignments(len(manifest.switches)):
        if not all(evaluate(c, bits) for c in manifest.constraints):
            continue
        states.append((bits, live, clean))
    return states


def risk_at(manifest, bits, live, clean, node_idx, cat):
    """Concrete category presence at ``node_idx`` (least fixpoint)."""
    incoming = {i: [] for i in range(len(manifest.nodes))}
    for idx, edge in enumerate(manifest.edges):
        incoming[manifest.node_index[edge.target]].append(
            (idx, manifest.node_index[edge.source])
        )
    # Topological order by repeated relaxation (graph is small and acyclic).
    presence: dict[tuple[int, str], bool] = {}
    changed = True

    def base(idx):
        node = manifest.nodes[idx]
        if node.kind in ("public_source", "sensitive_source"):
            return cat in node.categories
        return False

    while changed:
        changed = False
        for idx in range(len(manifest.nodes)):
            value = base(idx)
            if not value:
                for edge_idx, src in incoming[idx]:
                    if live[edge_idx](bits) and presence.get((src, cat), False):
                        value = True
                        break
            if value and manifest.nodes[idx].kind == "sanitizer":
                for formula in clean.get((idx, cat), ()):
                    if evaluate(formula, bits):
                        value = False
                        break
            if presence.get((idx, cat), False) != value:
                presence[(idx, cat)] = value
                changed = True
            else:
                presence[(idx, cat)] = value
    return presence.get((node_idx, cat), False)


def leaking_categories(manifest, bits, state, target):
    _b, live, clean = state
    node_idx = manifest.node_index[target.node]
    cats = set()
    for node in manifest.nodes:
        if node.kind == "sensitive_source":
            cats.update(node.categories)
    out = set()
    for cat in sorted(cats):
        if cat in target.allowed:
            continue
        if risk_at(manifest, bits, live, clean, node_idx, cat):
            out.add(cat)
    return out


def find_unsafe(manifest, policy=None):
    """Map target id -> category -> lexicographically smallest assignment."""
    states = legal_assignments(manifest, policy)
    out: dict[str, dict[str, tuple]] = {}
    for target in sorted(manifest.targets, key=lambda t: t.id):
        for cat in sorted(
            {c for n in manifest.nodes if n.kind == "sensitive_source" for c in n.categories}
            - target.allowed
        ):
            witness = None
            for bits, live, clean in states:
                node_idx = manifest.node_index[target.node]
                if risk_at(manifest, bits, live, clean, node_idx, cat):
                    witness = bits
                    break
            if witness is not None:
                out.setdefault(target.id, {})[cat] = witness
    return out


def reachable(manifest, bits, live, source_idx, target_idx):
    seen = {source_idx}
    frontier = [source_idx]
    outgoing = {i: [] for i in range(len(manifest.nodes))}
    for idx, edge in enumerate(manifest.edges):
        outgoing[manifest.node_index[edge.source]].append(
            (idx, manifest.node_index[edge.target])
        )
    while frontier:
        current = frontier.pop()
        for edge_idx, dst in outgoing[current]:
            if dst in seen:
                continue
            if live[edge_idx](bits):
                seen.add(dst)
                frontier.append(dst)
    return target_idx in seen


def is_safe(manifest, policy=None):
    states = legal_assignments(manifest, policy)
    for bits, live, clean in states:
        for target in manifest.targets:
            if leaking_categories(manifest, bits, (bits, live, clean), target):
                return False
    return True


def requirements_hold(manifest, policy=None):
    states = legal_assignments(manifest, policy)
    target_nodes = {t.id: t for t in manifest.targets}
    for bits, live, clean in states:
        for req in manifest.requirements:
            if not evaluate(req.requirement, bits):
                continue
            source_idx = manifest.node_index[req.source]
            target_idx = manifest.node_index[target_nodes[req.target].node]
            if not reachable(manifest, bits, live, source_idx, target_idx):
                return False
    return True


def solve_remediate(manifest, limit_states=None):
    """Exhaustive subset search; returns (best, selected_ids) or (None, None)."""
    candidate_ids = sorted(c.id for c in manifest.candidates)
    best = None
    for size in range(len(candidate_ids) + 1):
        for combo in itertools.combinations(candidate_ids, size):
            used = set()
            conflict = False
            by_id = {c.id: c for c in manifest.candidates}
            for cid in combo:
                key = by_id[cid].key
                if key in used:
                    conflict = True
                    break
                used.add(key)
            if conflict:
                continue
            from solution.engine import Policy

            policy = Policy(frozenset(combo))
            if is_safe(manifest, policy) and requirements_hold(manifest, policy):
                cost = sum(by_id[cid].cost for cid in combo)
                key = (cost, len(combo), combo)
                if best is None or key < best:
                    best = key
    if best is None:
        return None, None
    return best, list(best[2])
