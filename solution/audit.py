"""``find`` and ``compare``: read-only audits over the symbolic engine.

``find``
    For every target and every disallowed sensitive category, report the
    lexicographically smallest legal switch assignment (switch IDs ascending,
    ``false`` before ``true``) under which that category reaches the target,
    together with the shortest un-cleaned source chain (fewest edges; ties
    broken by the smallest edge-ID sequence).  Rows are sorted by target ID and
    then category ID.

``compare``
    Between two manifests over the same switch set, report per target the
    leak categories that appeared and disappeared, each with the minimal-change
    witness assignment.  Only assignments legal in *both* manifests are
    considered; when the common legal domain is empty this is stated
    explicitly.
"""

from __future__ import annotations

from .bdd import BDD, FALSE
from .engine import Engine, Policy
from .manifest import Manifest

# The neutral policy: no approved remediation actions selected.
EMPTY_POLICY = Policy(frozenset())


# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------


def run_find(manifest: Manifest) -> dict:
    engine = Engine(manifest)
    legal_count = engine.legal_count()
    audit = engine.audit_targets(EMPTY_POLICY, with_chains=True)
    prop = engine.propagate(EMPTY_POLICY)

    unsafe = [row for row in audit if not row["safe"]]
    for row in unsafe:
        node_idx = engine.node_index[row["node"]]
        allowed = set(row["allowed_categories"])
        # Target-level witness: the lexicographically smallest assignment that
        # leaks *any* disallowed category at this target, plus the chains that
        # actually occur under exactly that assignment.
        combined = FALSE
        for cat in engine.sensitive_cats:
            if cat in allowed:
                continue
            combined = engine.bdd.or_(
                combined,
                engine.bdd.and_(engine.legal, prop.reach.get((node_idx, cat), FALSE)),
            )
        minimal = engine.bdd.minimal_assignment(combined)
        assert minimal is not None
        bits = engine.bits(minimal)
        leaking_here = []
        for cat in engine.sensitive_cats:
            if cat in allowed:
                continue
            risk = prop.reach.get((node_idx, cat), FALSE)
            if risk == FALSE or not engine.bdd.evaluate(risk, bits):
                continue
            leaking_here.append(
                {"category": cat, "chain": engine.shortest_chain(bits, node_idx, cat, prop)}
            )
        row["assignment"] = engine.assignment_dict(bits)
        row["assignment_bits"] = list(bits)
        row["leaking_categories_at_assignment"] = leaking_here

    result = {
        "ok": True,
        "command": "find",
        "manifest_id": manifest.manifest_id,
        "switches": list(engine.names),
        "legal": {
            "satisfiable": engine.legal != FALSE,
            "assignment_count": legal_count,
        },
        "safe": not unsafe,
        "unsafe_targets": [
            {
                "target": row["target"],
                "node": row["node"],
                "allowed_categories": row["allowed_categories"],
                "assignment": row["assignment"],
                "assignment_bits": row["assignment_bits"],
                "leaking_categories": [
                    item["category"]
                    for item in row["leaking_categories_at_assignment"]
                ],
                "chains": row["leaking_categories_at_assignment"],
                # Per-category lexicographic-minimum witnesses (the required
                # ordering is target, then category ID).
                "leaks": [
                    {
                        "category": leak["category"],
                        "assignment": leak["assignment"],
                        "assignment_bits": leak["assignment_bits"],
                        "chain": leak["chain"],
                    }
                    for leak in row["leaks"]
                ],
            }
            for row in unsafe
        ],
        "targets": [
            {
                "target": row["target"],
                "node": row["node"],
                "allowed_categories": row["allowed_categories"],
                "safe": row["safe"],
                "leaking_categories": [leak["category"] for leak in row["leaks"]],
            }
            for row in audit
        ],
        "symbolic": {
            **engine.stats(),
            "method": "reduced ordered BDD over switches; fixpoint over topological DAG",
        },
    }
    return result


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------


def _leak_bdd(engine: Engine, target, cat: str, legal: int) -> int:
    """Leak formula for one target/category, intersected with ``legal``."""
    node_idx = engine.node_index[target.node]
    risk = engine.propagate(EMPTY_POLICY).reach.get((node_idx, cat), FALSE)
    return engine.bdd.and_(legal, risk)


def _witness(engine: Engine, bdd_node: int, defaults: tuple[bool, ...]):
    found = engine.bdd.min_cost_assignment(bdd_node, defaults)
    if found is None:
        return None
    cost, bits = found
    return {
        "assignment": engine.assignment_dict(bits),
        "assignment_bits": list(bits),
        "switch_changes": cost,
    }


def _best_of(entries: list[dict]) -> dict | None:
    """Smallest-change witness; ties broken lexicographically by bits."""
    best = None
    for entry in entries:
        key = (entry["switch_changes"], tuple(entry["assignment_bits"]))
        if best is None or key < best[0]:
            best = (key, entry)
    return None if best is None else best[1]


def run_compare(old: Manifest, new: Manifest) -> dict:
    # One shared BDD manager so formulas from both manifests are comparable.
    shared = BDD(len(old.switches))
    old_engine = Engine(old, bdd=shared)
    new_engine = Engine(new, bdd=shared)

    old_defaults = tuple(s.default for s in old.switches)
    new_defaults = tuple(s.default for s in new.switches)
    names = old_engine.names
    defaults_equal = old_defaults == new_defaults

    common_legal = shared.and_(old_engine.legal, new_engine.legal)
    common_count = shared.count(common_legal)

    base = {
        "ok": True,
        "command": "compare",
        "case_switches": list(names),
        "baseline_defaults": dict(zip(names, old_defaults)),
        "defaults_identical": defaults_equal,
    }

    if common_legal == FALSE:
        base.update(
            {
                "common_legal": {"satisfiable": False, "assignment_count": 0},
                "no_common_legal_assignments": True,
                "message": (
                    "the old and new manifests share no assignment that is legal "
                    "in both; added/disappeared leak categories are undefined"
                ),
                "targets": [],
            }
        )
        return base

    old_targets = {t.id: t for t in old.targets}
    new_targets = {t.id: t for t in new.targets}
    all_cats = sorted(set(old_engine.sensitive_cats) | set(new_engine.sensitive_cats))

    changed: list[dict] = []
    unchanged: list[dict] = []

    for tid in sorted(set(old_targets) | set(new_targets)):
        ot = old_targets.get(tid)
        nt = new_targets.get(tid)
        added_rows: list[dict] = []
        gone_rows: list[dict] = []
        same_rows: list[dict] = []
        target_witness: list[dict] = []

        for cat in all_cats:
            old_forbidden = ot is not None and cat not in ot.allowed
            new_forbidden = nt is not None and cat not in nt.allowed
            old_leak = (
                _leak_bdd(old_engine, ot, cat, common_legal)
                if old_forbidden
                else FALSE
            )
            new_leak = (
                _leak_bdd(new_engine, nt, cat, common_legal)
                if new_forbidden
                else FALSE
            )
            if old_forbidden and new_forbidden:
                appeared = shared.and_(new_leak, shared.neg(old_leak))
                vanished = shared.and_(old_leak, shared.neg(new_leak))
                both = shared.and_(old_leak, new_leak)
                if both != FALSE:
                    witness = _witness(old_engine, both, old_defaults)
                    same_rows.append(
                        {"category": cat, "witness": witness}
                    )
            elif new_forbidden:
                appeared = new_leak
                vanished = FALSE
            elif old_forbidden:
                appeared = FALSE
                vanished = old_leak
            else:  # pragma: no cover - cat is sensitive somewhere
                appeared = FALSE
                vanished = FALSE

            if appeared != FALSE:
                witness = _witness(old_engine, appeared, old_defaults)
                added_rows.append({"category": cat, "witness": witness})
            if vanished != FALSE:
                witness = _witness(old_engine, vanished, old_defaults)
                gone_rows.append({"category": cat, "witness": witness})

        for entry in added_rows + gone_rows:
            if entry["witness"] is not None:
                target_witness.append(entry["witness"])

        target_min = _best_of(target_witness)
        row = {
            "target": tid,
            "present_in": {"old": ot is not None, "new": nt is not None},
            "old_node": None if ot is None else ot.node,
            "new_node": None if nt is None else nt.node,
            "added": added_rows,
            "disappeared": gone_rows,
            "persisting": same_rows,
            "minimal_change": target_min,
        }
        if added_rows or gone_rows:
            changed.append(row)
        else:
            unchanged.append(row)

    base.update(
        {
            "common_legal": {
                "satisfiable": True,
                "assignment_count": common_count,
            },
            "no_common_legal_assignments": False,
            "targets": changed,
            "unchanged_targets": unchanged,
            "symbolic": {
                "method": "shared reduced ordered BDD; difference restricted to common legal domain",
                "bdd_nodes": shared.node_count(),
            },
        }
    )
    return base
