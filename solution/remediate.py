"""``remediate``: choose one global set of approved changes.

The chosen set is a *single fixed policy* applied to every switch assignment --
never a different set per assignment.  Under that policy:

1. no disallowed sensitive category reaches any release target for any legal
   assignment, and
2. every required public source still reaches its target whenever that
   requirement's own formula is true.

Actions
    ``disable_edge``     removes an edge for a specified condition subset:
                         ``effective = edge_condition AND NOT disable_condition``
    ``extend_cleaning``  adds a clean rule at a node under a condition

Two actions on the same edge, or on the same node, are mutually exclusive.

Search
    Candidates are restricted to those that can structurally matter (on a path
    from a sensitive source to a target).  A depth-first branch-and-bound then
    walks candidates in ascending ID order and reuses one shared BDD decision
    state across the whole search:

    * **requirement monotonicity** -- reachability only shrinks as actions are
      added, so a violated required-reachability check is permanent and the
      branch is cut;
    * **feasible-superset pruning** -- once a selection is already safe and its
      requirements hold, adding more actions can only raise cost and count, so
      the whole subtree is cut;
    * **maximal-closure infeasibility** -- category presence also only shrinks
      as actions are added, so if even the maximal conflict-free superset of the
      current prefix is unsafe, nothing in the subtree can be safe;
    * **cost bound** -- a selection whose cost exceeds the best known solution
      cannot win; ties are broken by count and then by ascending ID tuple;
    * **dominance memoisation** -- two different selections that yield the same
      effective (live-edge, cleaning) formulas at the same search position are
      interchangeable for every remaining decision; only a strictly cheaper
      prefix is kept;
    * **no-op pruning** -- adding a candidate that leaves those formulas
      unchanged can never help;
    * **conflict pruning** -- candidates sharing an edge or node are skipped
      once one of them is selected.

Requirements are checked over *live edges only*: cleaning removes categories,
never reachability, so a sanitizer can never stand in for the check that a
required input still arrives.
"""

from __future__ import annotations

from .bdd import FALSE
from .engine import Engine, Policy
from .errors import AnalysisError
from .expr import render
from .manifest import Candidate, Manifest

# Bound on visited search states.  18 candidates is ~262k subsets in the worst
# case; pruning normally keeps this far lower, but the bound guarantees the
# command fails loudly instead of stalling.
SEARCH_STATE_BUDGET = 400_000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _forward_reachable(manifest: Manifest, starts: set[int]) -> set[int]:
    """Nodes reachable from ``starts`` ignoring edge conditions."""
    out: dict[int, list[int]] = {i: [] for i in range(len(manifest.nodes))}
    for edge in manifest.edges:
        out[manifest.node_index[edge.source]].append(
            manifest.node_index[edge.target]
        )
    seen = set(starts)
    stack = list(starts)
    while stack:
        cur = stack.pop()
        for nxt in out[cur]:
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _backward_reachable(manifest: Manifest, goals: set[int]) -> set[int]:
    """Nodes that can reach ``goals`` ignoring edge conditions."""
    incoming: dict[int, list[int]] = {i: [] for i in range(len(manifest.nodes))}
    for edge in manifest.edges:
        incoming[manifest.node_index[edge.target]].append(
            manifest.node_index[edge.source]
        )
    seen = set(goals)
    stack = list(goals)
    while stack:
        cur = stack.pop()
        for prv in incoming[cur]:
            if prv not in seen:
                seen.add(prv)
                stack.append(prv)
    return seen


def _candidate_relevance(manifest: Manifest) -> dict[str, bool]:
    sensitive_starts = {
        i for i, node in enumerate(manifest.nodes) if node.kind == "sensitive_source"
    }
    target_nodes = {manifest.node_index[t.node] for t in manifest.targets}
    forward = _forward_reachable(manifest, sensitive_starts)
    backward = _backward_reachable(manifest, target_nodes)
    relevant: dict[str, bool] = {}
    for candidate in manifest.candidates:
        if candidate.kind == "disable_edge":
            edge = manifest.edges[manifest.edge_index[candidate.edge]]
            src = manifest.node_index[edge.source]
            dst = manifest.node_index[edge.target]
            relevant[candidate.id] = src in forward and dst in backward
        else:
            node_idx = manifest.node_index[candidate.node]
            relevant[candidate.id] = node_idx in forward and node_idx in backward
    return relevant


def _signature(engine: Engine, policy: Policy):
    prop = engine.propagate(policy)
    return (
        tuple(sorted(prop.live.items())),
        tuple(sorted(prop.cleans.items())),
    )


class _Search:
    def __init__(self, engine: Engine, candidates: list[Candidate]):
        self.engine = engine
        self.candidates = candidates  # ascending ID order
        self.best: tuple[int, int, tuple[str, ...]] | None = None
        self.best_policy: Policy | None = None
        self.states = 0
        self.stats = {
            "states_visited": 0,
            "pruned_feasible_superset": 0,
            "pruned_cost_bound": 0,
            "pruned_dominance": 0,
            "pruned_noop": 0,
            "pruned_conflict": 0,
            "pruned_requirement_bound": 0,
            "pruned_infeasible_closure": 0,
        }
        self.memo: dict[tuple, tuple[int, int, tuple[str, ...]]] = {}

    # -- solution bookkeeping --------------------------------------------
    def _is_feasible(self, policy: Policy) -> bool:
        return self.engine.is_safe(policy) and self.engine.requirements_hold(policy)

    def _record(self, policy: Policy, cost: int, count: int, ids: tuple[str, ...]):
        key = (cost, count, ids)
        if self.best is None or key < self.best:
            self.best = key
            self.best_policy = policy

    def seed(self, policy: Policy, cost: int, count: int, ids: tuple[str, ...]):
        if self._is_feasible(policy):
            self._record(policy, cost, count, ids)
            return True
        return False

    # -- DFS ---------------------------------------------------------------
    def run(self):
        self._dfs(0, frozenset(), 0, 0, _signature(self.engine, Policy()), set())
        return self.best, self.best_policy

    def _maximal_closure(self, i: int, selected: frozenset[str], used_keys) -> frozenset[str] | None:
        """Everything still selectable from ``i`` onwards, conflict-free.

        Returns ``None`` when a conflict among the remaining candidates makes
        the greedy closure unsound as an upper bound (picking the lowest-ID
        candidate blocks a different, possibly more effective one).
        """
        remaining_keys: dict[tuple[str, str], list[str]] = {}
        for candidate in self.candidates[i:]:
            if candidate.key in used_keys:
                continue
            remaining_keys.setdefault(candidate.key, []).append(candidate.id)
        if any(len(ids) > 1 for ids in remaining_keys.values()):
            return None
        closure = set(selected)
        for ids in remaining_keys.values():
            closure.update(ids)
        return frozenset(closure)

    def _dfs(self, i, selected: frozenset[str], cost, count, sig, used_keys):
        self.states += 1
        self.stats["states_visited"] = self.states
        if self.states > SEARCH_STATE_BUDGET:
            raise AnalysisError(
                "REMEDIATE_SEARCH_LIMIT",
                "$.candidates",
                f"remediation search exceeded {SEARCH_STATE_BUDGET} states; "
                "the candidate set is too entangled to solve exhaustively",
            )

        memo_key = (sig, i, tuple(sorted(used_keys)))
        seen = self.memo.get(memo_key)
        if seen is not None and (seen[0], seen[1]) < (cost, count):
            self.stats["pruned_dominance"] += 1
            return
        if seen is None or (cost, count, tuple(sorted(selected))) < seen:
            self.memo[memo_key] = (cost, count, tuple(sorted(selected)))

        # Monotonicity facts behind the two bounds below:
        #   * selecting more actions can only shrink a category's presence, so
        #     a leak that persists even under the *maximal* conflict-free
        #     closure of this subtree can never be repaired inside it;
        #   * selecting more actions can only shrink reachability, so a
        #     required-reachability violation under the current prefix is
        #     permanent and adding actions can never restore it.
        if not self.engine.requirements_hold(Policy(selected)):
            self.stats["pruned_requirement_bound"] += 1
            return
        # A feasible prefix plus any further action is strictly worse in
        # (cost, count): record and cut the whole subtree.
        if self.engine.is_safe(Policy(selected)):
            self.stats["pruned_feasible_superset"] += 1
            self._record(Policy(selected), cost, count, tuple(sorted(selected)))
            return
        closure = self._maximal_closure(i, selected, used_keys)
        if closure is not None and closure != selected:
            if not self.engine.is_safe(Policy(closure)):
                self.stats["pruned_infeasible_closure"] += 1
                return

        if i == len(self.candidates):
            return

        candidate = self.candidates[i]
        # --- include branch first: it discovers incumbents earlier ----------
        if candidate.key not in used_keys:
            new_cost = cost + candidate.cost
            allowed = True
            if self.best is not None:
                best_cost, best_count, _ = self.best
                if new_cost > best_cost:
                    self.stats["pruned_cost_bound"] += 1
                    allowed = False
                elif new_cost == best_cost and count + 1 > best_count:
                    self.stats["pruned_cost_bound"] += 1
                    allowed = False
            if allowed:
                new_selected = selected | {candidate.id}
                new_policy = Policy(new_selected)
                new_sig = _signature(self.engine, new_policy)
                if new_sig == sig:
                    self.stats["pruned_noop"] += 1
                else:
                    self._dfs(
                        i + 1,
                        new_selected,
                        new_cost,
                        count + 1,
                        new_sig,
                        used_keys | {candidate.key},
                    )
        else:
            self.stats["pruned_conflict"] += 1

        # --- exclude branch -------------------------------------------------
        self._dfs(i + 1, selected, cost, count, sig, used_keys)


# ---------------------------------------------------------------------------
# Output shaping
# ---------------------------------------------------------------------------


def _policy_action_rows(manifest: Manifest, policy: Policy) -> list[dict]:
    rows = []
    for candidate in sorted(manifest.candidates, key=lambda c: c.id):
        if candidate.id not in policy.selected:
            continue
        row = {
            "id": candidate.id,
            "kind": candidate.kind,
            "cost": candidate.cost,
        }
        if candidate.kind == "disable_edge":
            row["edge"] = candidate.edge
            row["condition"] = render(candidate.disable, manifest.switch_ids)
        else:
            row["node"] = candidate.node
            row["condition"] = render(candidate.condition, manifest.switch_ids)
            row["categories"] = list(candidate.categories)
        rows.append(row)
    return rows


def _full_audit(engine: Engine, policy: Policy) -> dict:
    audit = engine.audit_targets(policy, with_chains=True)
    unsafe = []
    for row in audit:
        if row["safe"]:
            continue
        node_idx = engine.node_index[row["node"]]
        combined = FALSE
        prop = engine.propagate(policy)
        for cat in engine.sensitive_cats:
            if cat in row["allowed_categories"]:
                continue
            combined = engine.bdd.or_(
                combined,
                engine.bdd.and_(
                    engine.legal, prop.reach.get((node_idx, cat), FALSE)
                ),
            )
        minimal = engine.bdd.minimal_assignment(combined)
        assert minimal is not None
        bits = engine.bits(minimal)
        unsafe.append(
            {
                "target": row["target"],
                "node": row["node"],
                "assignment": engine.assignment_dict(bits),
                "assignment_bits": list(bits),
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
        )
    return {
        "safe": not unsafe,
        "unsafe_targets": unsafe,
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
    }


def _requirement_summary(engine: Engine, policy: Policy) -> list[dict]:
    """Required-reachability verdicts with a concrete witness per requirement.

    The witness is the lexicographically first legal assignment satisfying the
    requirement formula; ``path`` is the shortest edge path for the source at
    that assignment, and ``violation`` is the lexicographically first legal
    assignment where the formula holds but the source cannot reach the target.
    A cleaning action never appears here: reachability is computed over live
    edges alone, so a sanitizer cannot stand in for a lost input.
    """
    out = []
    for entry in engine.requirement_status(policy):
        summary = {
            "id": entry["id"],
            "source": entry["source"],
            "target": entry["target"],
            "requirement": entry["requirement"],
            "satisfied": entry["satisfied"],
            "vacuous": entry["vacuous"],
            "assignment_count": entry["assignment_count"],
        }
        if "satisfying_assignment" in entry:
            summary["witness"] = {
                "assignment": entry["satisfying_assignment"],
                "assignment_bits": entry["satisfying_assignment_bits"],
            }
            if entry["satisfied"] and "path" in entry:
                summary["witness"]["path"] = entry["path"]
        if not entry["satisfied"]:
            summary["violation"] = {
                "assignment": entry.get("violation_assignment"),
                "assignment_bits": entry.get("violation_assignment_bits"),
            }
        out.append(summary)
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_remediate(manifest: Manifest) -> dict:
    engine = Engine(manifest)
    legal_count = engine.legal_count()

    base = {
        "ok": True,
        "command": "remediate",
        "manifest_id": manifest.manifest_id,
        "switches": list(engine.names),
        "legal": {
            "satisfiable": engine.legal != FALSE,
            "assignment_count": legal_count,
        },
    }

    empty = Policy(frozenset())

    if legal_count == 0:
        # Vacuously safe: no legal assignment can carry anything anywhere.
        base.update(
            {
                "solvable": True,
                "vacuous": True,
                "message": "no legal switch assignment exists; the audit is vacuous",
                "policy": {
                    "selected_actions": [],
                    "total_cost": 0,
                    "action_count": 0,
                    "ids": [],
                },
                "final_audit": _full_audit(engine, empty),
                "reachability": _requirement_summary(engine, empty),
                "search": {
                    "candidates_total": len(manifest.candidates),
                    "candidates_relevant": 0,
                    "states_visited": 0,
                },
            }
        )
        return base

    relevance = _candidate_relevance(manifest)
    relevant = sorted(
        (c for c in manifest.candidates if relevance[c.id]), key=lambda c: c.id
    )
    ignored = [c.id for c in manifest.candidates if not relevance[c.id]]

    search = _Search(engine, relevant)

    # Seed an incumbent so the cost bound bites early: greedily take every
    # relevant action, first-come-first-served on conflicting keys.
    greedy_ids: list[str] = []
    greedy_keys: set[tuple[str, str]] = set()
    greedy_cost = 0
    for candidate in relevant:
        if candidate.key in greedy_keys:
            continue
        greedy_keys.add(candidate.key)
        greedy_ids.append(candidate.id)
        greedy_cost += candidate.cost
    search.seed(
        Policy(frozenset(greedy_ids)),
        greedy_cost,
        len(greedy_ids),
        tuple(sorted(greedy_ids)),
    )

    best, best_policy = search.run()
    engine_stats = engine.stats()
    search_stats = {
        "candidates_total": len(manifest.candidates),
        "candidates_relevant": len(relevant),
        "candidates_ignored": ignored,
        "states_visited": search.stats["states_visited"],
        "pruned_feasible_superset": search.stats["pruned_feasible_superset"],
        "pruned_cost_bound": search.stats["pruned_cost_bound"],
        "pruned_dominance": search.stats["pruned_dominance"],
        "pruned_noop": search.stats["pruned_noop"],
        "pruned_conflict": search.stats["pruned_conflict"],
        "pruned_requirement_bound": search.stats["pruned_requirement_bound"],
        "pruned_infeasible_closure": search.stats["pruned_infeasible_closure"],
        "propagation_evaluations": engine_stats["propagation_evaluations"],
        "propagation_cache_hits": engine_stats["propagation_cache_hits"],
        "bdd_nodes": engine_stats["bdd_nodes"],
        "method": (
            "single global fixed policy over a shared BDD decision state; "
            "branch-and-bound pruned by feasible-superset monotonicity, cost "
            "bound, requirement monotonicity, maximal-closure infeasibility, "
            "state dominance, no-op and mutual-exclusion cuts"
        ),
    }

    if best is None:
        # No fixed policy works.  Compare the neutral policy with the maximal
        # conflict-free one and report whichever leaves the *least* residual
        # demand, so the reported witness is as close to feasible as possible.
        empty_leaks = engine.residual_leaks(empty)
        empty_req = engine.requirement_violations(empty)
        max_policy = Policy(frozenset(greedy_ids))
        max_leaks = engine.residual_leaks(max_policy)
        max_req = engine.requirement_violations(max_policy)

        def score(leaks, reqs):
            return (len(leaks) + len(reqs), len(leaks))

        if score(max_leaks, max_req) <= score(empty_leaks, empty_req):
            leaks, reqs, ref_policy = max_leaks, max_req, max_policy
        else:
            leaks, reqs, ref_policy = empty_leaks, empty_req, empty

        demand = None
        if leaks:
            first = leaks[0]
            demand = {
                "kind": "leak",
                "target": first["target"],
                "category": first["category"],
                "assignment": first["assignment"],
                "assignment_bits": first["assignment_bits"],
                "chain": first["chain"],
            }
        elif reqs:
            first = reqs[0]
            demand = {
                "kind": "requirement",
                "requirement": first["id"],
                "source": first["source"],
                "target": first["target"],
                "requirement_formula": first["requirement"],
                "violating_assignment": {
                    "assignment": first.get("violation_assignment"),
                    "assignment_bits": first.get("violation_assignment_bits"),
                },
            }
        base.update(
            {
                "solvable": False,
                "reason": "unfixable_leak" if leaks else "unreachable_required_source",
                "message": (
                    "no single fixed approved-action set makes every legal "
                    "assignment safe while keeping all required public sources reachable"
                ),
                "minimal_unsatisfied_demand": demand,
                "residual_leaks": leaks,
                "requirement_violations": reqs,
                "reference_policy": {
                    "selected_actions": sorted(ref_policy.selected),
                    "total_cost": sum(
                        c.cost for c in manifest.candidates if c.id in ref_policy.selected
                    ),
                },
                "final_audit": _full_audit(engine, ref_policy),
                "reachability": _requirement_summary(engine, ref_policy),
                "search": search_stats,
            }
        )
        return base

    cost, count, ids = best
    policy = best_policy
    base.update(
        {
            "solvable": True,
            "vacuous": False,
            "policy": {
                "selected_actions": _policy_action_rows(manifest, policy),
                "ids": list(ids),
                "total_cost": cost,
                "action_count": count,
            },
            "final_audit": _full_audit(engine, policy),
            "reachability": _requirement_summary(engine, policy),
            "search": search_stats,
        }
    )
    return base
