"""Strict parsing and validation of build manifests.

Schema (all sections except ``switches``/``nodes``/``edges``/``targets`` are
optional)::

    {
      "manifest_id": "m1",
      "switches": [{"id": "s1", "default": false}],
      "switch_constraints": ["s1 OR NOT s2"],
      "nodes": [
        {"id": "pub_a", "kind": "public_source"},
        {"id": "in_a",  "kind": "public_source", "categories": ["pub"]},
        {"id": "sec_a", "kind": "sensitive_source", "categories": ["secret"]},
        {"id": "mix",   "kind": "merge"},
        {"id": "clean", "kind": "sanitizer",
         "cleans": [{"condition": "s1", "categories": ["secret"]}]}
      ],
      "edges": [
        {"id": "e1", "from": "sec_a", "to": "mix", "condition": "s1"}
      ],
      "targets": [
        {"id": "t1", "node": "mix", "allowed_categories": ["public"]}
      ],
      "required_reachability": [
        {"id": "r1", "source": "in_a", "target": "t1", "requirement": "s2"}
      ],
      "candidates": [
        {"id": "a1", "kind": "disable_edge", "edge": "e1",
         "condition": "s1", "cost": 1},
        {"id": "a2", "kind": "extend_cleaning", "node": "clean",
         "condition": "s2", "categories": ["secret"], "cost": 2}
      ]
    }

Node kinds
    ``public_source``     carries exactly its ``categories`` (may be empty)
    ``sensitive_source``  carries its sensitive ``categories``
    ``merge``             passive junction, carries nothing itself
    ``sanitizer``         removes categories arriving from upstream whenever a
                          clean rule condition holds; requires ``cleans``

Semantics of a concrete switch assignment: an edge is *active* when its
condition is true; every active incoming edge contributes the risk categories
of its source node; risk is the union of categories; a sanitizer removes a
category only from the risk that actually reaches it.  A target rejects every
reached category outside its ``allowed_categories``.

Switches are re-ordered by ID (ascending, Unicode order) at parse time so that
the canonical assignment order is "switch ID ascending, ``false`` before
``true``" everywhere in the tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .errors import InputError
from .expr import Expr, parse_expr

MAX_SWITCHES = 24

NODE_KINDS = ("public_source", "sensitive_source", "merge", "sanitizer")
CANDIDATE_KINDS = ("disable_edge", "extend_cleaning")

_SWITCH_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_RESERVED = {"AND", "OR", "NOT", "TRUE", "FALSE"}

_ALLOWED_TOP = {
    "manifest_id",
    "switches",
    "switch_constraints",
    "nodes",
    "edges",
    "targets",
    "required_reachability",
    "candidates",
}

_ALLOWED_NODE_KEYS = {
    "public_source": {"id", "kind", "categories", "label"},
    "sensitive_source": {"id", "kind", "categories", "label"},
    "merge": {"id", "kind", "label"},
    "sanitizer": {"id", "kind", "cleans", "label"},
}

_ALLOWED_CANDIDATE_KEYS = {
    "disable_edge": {"id", "kind", "edge", "condition", "cost", "label"},
    "extend_cleaning": {
        "id",
        "kind",
        "node",
        "condition",
        "categories",
        "cost",
        "label",
    },
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Switch:
    id: str
    index: int
    default: bool = False


@dataclass(frozen=True)
class CleanRule:
    condition: Expr
    categories: tuple[str, ...]


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    categories: tuple[str, ...] = ()
    cleans: tuple[CleanRule, ...] = ()


@dataclass(frozen=True)
class Edge:
    id: str
    source: str
    target: str
    condition: Expr


@dataclass(frozen=True)
class Target:
    id: str
    node: str
    allowed: frozenset[str]


@dataclass(frozen=True)
class Requirement:
    id: str
    source: str
    target: str
    requirement: Expr


@dataclass(frozen=True)
class Candidate:
    id: str
    kind: str
    cost: int
    # disable_edge
    edge: str | None = None
    disable: Expr | None = None
    # extend_cleaning
    node: str | None = None
    condition: Expr | None = None
    categories: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        """Mutual-exclusion key: at most one candidate per edge or node."""
        if self.kind == "disable_edge":
            return ("edge", self.edge)
        return ("node", self.node)


@dataclass(frozen=True)
class Manifest:
    manifest_id: str
    switches: tuple[Switch, ...]
    switch_index: dict[str, int]
    constraints: tuple[Expr, ...]
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    targets: tuple[Target, ...]
    requirements: tuple[Requirement, ...]
    candidates: tuple[Candidate, ...]
    category_ids: tuple[str, ...]
    node_index: dict[str, int] = field(default_factory=dict)
    edge_index: dict[str, int] = field(default_factory=dict)

    @property
    def switch_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self.switches)


# ---------------------------------------------------------------------------
# Primitive validators
# ---------------------------------------------------------------------------


def _fail(code: str, path: str, message: str):
    raise InputError(code, path, message)


def _expect_object(value, path: str, what: str) -> dict:
    if not isinstance(value, dict):
        _fail("FIELD_TYPE", path, f"{what} must be an object")
    return value


def _expect_string(obj: dict, key: str, path: str, what: str) -> str:
    if key not in obj:
        _fail("MISSING_FIELD", f"{path}.{key}", f"missing {what}")
    value = obj[key]
    if not isinstance(value, str):
        _fail("FIELD_TYPE", f"{path}.{key}", f"{what} must be a string")
    return value


def _expect_list(obj: dict, key: str, path: str, what: str) -> list:
    if key not in obj:
        _fail("MISSING_FIELD", f"{path}.{key}", f"missing {what}")
    value = obj[key]
    if not isinstance(value, list):
        _fail("FIELD_TYPE", f"{path}.{key}", f"{what} must be a list")
    return value


def _check_keys(obj: dict, allowed: set[str], path: str) -> None:
    for key in obj:
        if key not in allowed:
            _fail("UNKNOWN_FIELD", f"{path}.{key}", f"unknown field {key!r}")


def _read_id(obj: dict, path: str, what: str = "id") -> str:
    value = _expect_string(obj, "id", path, what)
    if not value.strip():
        _fail("EMPTY_ID", f"{path}.id", f"{what} must not be empty")
    return value


def _read_categories(value, path: str, what: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail("FIELD_TYPE", path, f"{what} must be a list")
    seen: set[str] = set()
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            _fail(
                "FIELD_TYPE",
                f"{path}[{i}]",
                f"{what} entries must be non-empty strings",
            )
        if item in seen:
            _fail("DUPLICATE_CATEGORY", f"{path}[{i}]", f"duplicate category {item!r}")
        seen.add(item)
        out.append(item)
    return tuple(out)


def _check_unique(ids: list[str], path: str, what: str) -> None:
    seen: set[str] = set()
    for i, item in enumerate(ids):
        if item in seen:
            _fail("DUPLICATE_ID", f"{path}[{i}].id", f"duplicate {what} id {item!r}")
        seen.add(item)


def _read_cost(entry: dict, path: str) -> int:
    value = entry.get("cost", 1)
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("FIELD_TYPE", f"{path}.cost", "cost must be an integer")
    if value < 0:
        _fail("NEGATIVE_COST", f"{path}.cost", "cost must be non-negative")
    return value


def _read_label(entry: dict, path: str) -> None:
    if "label" in entry and not isinstance(entry["label"], str):
        _fail("FIELD_TYPE", f"{path}.label", "label must be a string")


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------


def _parse_switches(raw) -> tuple[tuple[Switch, ...], dict[str, int]]:
    if not isinstance(raw, list):
        _fail("FIELD_TYPE", "$.switches", "switches must be a list")
    if len(raw) > MAX_SWITCHES:
        _fail(
            "TOO_MANY_SWITCHES",
            "$.switches",
            f"at most {MAX_SWITCHES} switches are supported, got {len(raw)}",
        )
    parsed: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw):
        path = f"$.switches[{i}]"
        _expect_object(entry, path, "switch")
        _check_keys(entry, {"id", "default", "label"}, path)
        sid = _read_id(entry, path, "switch")
        if not _SWITCH_ID.match(sid):
            _fail(
                "INVALID_SWITCH_ID",
                f"{path}.id",
                "switch ids must start with a letter or '_' and contain only "
                "letters, digits, '_', '.', '-'",
            )
        if sid.upper() in _RESERVED:
            _fail(
                "RESERVED_SWITCH_ID",
                f"{path}.id",
                f"switch id {sid!r} collides with an expression keyword",
            )
        if sid in seen:
            _fail("DUPLICATE_ID", f"{path}.id", f"duplicate switch id {sid!r}")
        seen.add(sid)
        default = entry.get("default", False)
        if not isinstance(default, bool):
            _fail("FIELD_TYPE", f"{path}.default", "default must be a boolean")
        _read_label(entry, path)
        parsed.append((sid, default))

    parsed.sort(key=lambda item: item[0])
    switches: list[Switch] = []
    index: dict[str, int] = {}
    for position, (sid, default) in enumerate(parsed):
        index[sid] = position
        switches.append(Switch(id=sid, index=position, default=default))
    return tuple(switches), index


def _parse_constraints(raw, switch_index) -> tuple[Expr, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        _fail(
            "FIELD_TYPE",
            "$.switch_constraints",
            "switch_constraints must be a list",
        )
    return tuple(
        parse_expr(item, switch_index, f"$.switch_constraints[{i}]")
        for i, item in enumerate(raw)
    )


def _parse_clean_rules(raw, switch_index, path: str) -> tuple[CleanRule, ...]:
    if not isinstance(raw, list):
        _fail("FIELD_TYPE", path, "cleans must be a list")
    rules: list[CleanRule] = []
    for i, entry in enumerate(raw):
        epath = f"{path}[{i}]"
        _expect_object(entry, epath, "clean rule")
        _check_keys(entry, {"condition", "categories"}, epath)
        if "condition" not in entry:
            _fail("MISSING_FIELD", f"{epath}.condition", "missing condition")
        if "categories" not in entry:
            _fail("MISSING_FIELD", f"{epath}.categories", "missing categories")
        cond = parse_expr(entry["condition"], switch_index, f"{epath}.condition")
        cats = _read_categories(entry["categories"], f"{epath}.categories", "categories")
        if not cats:
            _fail(
                "EMPTY_CATEGORIES",
                f"{epath}.categories",
                "a clean rule must name at least one category",
            )
        rules.append(CleanRule(condition=cond, categories=cats))
    return tuple(rules)


def _parse_nodes(raw, switch_index) -> tuple[Node, ...]:
    if not isinstance(raw, list):
        _fail("FIELD_TYPE", "$.nodes", "nodes must be a list")
    if not raw:
        _fail("EMPTY_LIST", "$.nodes", "at least one node is required")
    nodes: list[Node] = []
    for i, entry in enumerate(raw):
        path = f"$.nodes[{i}]"
        _expect_object(entry, path, "node")
        if "kind" not in entry:
            _fail("MISSING_FIELD", f"{path}.kind", "missing node kind")
        kind = entry["kind"]
        if not isinstance(kind, str) or kind not in NODE_KINDS:
            _fail(
                "UNKNOWN_NODE_KIND",
                f"{path}.kind",
                f"node kind must be one of: {', '.join(NODE_KINDS)}",
            )
        _check_keys(entry, _ALLOWED_NODE_KEYS[kind], path)
        nid = _read_id(entry, path, "node")
        _read_label(entry, path)
        if kind in ("public_source", "sensitive_source"):
            if "categories" not in entry:
                _fail("MISSING_FIELD", f"{path}.categories", "missing categories")
            cats = _read_categories(entry["categories"], f"{path}.categories", "categories")
            nodes.append(Node(id=nid, kind=kind, categories=cats))
        elif kind == "sanitizer":
            if "cleans" not in entry:
                _fail("MISSING_FIELD", f"{path}.cleans", "missing cleans list")
            rules = _parse_clean_rules(entry["cleans"], switch_index, f"{path}.cleans")
            nodes.append(Node(id=nid, kind=kind, cleans=rules))
        else:
            nodes.append(Node(id=nid, kind=kind))
    _check_unique([n.id for n in nodes], "$.nodes", "node")
    return tuple(nodes)


def _parse_edges(raw, switch_index, node_ids) -> tuple[Edge, ...]:
    if not isinstance(raw, list):
        _fail("FIELD_TYPE", "$.edges", "edges must be a list")
    edges: list[Edge] = []
    for i, entry in enumerate(raw):
        path = f"$.edges[{i}]"
        _expect_object(entry, path, "edge")
        _check_keys(entry, {"id", "from", "to", "condition", "label"}, path)
        eid = _read_id(entry, path, "edge")
        if "from" not in entry:
            _fail("MISSING_FIELD", f"{path}.from", "missing edge source")
        if "to" not in entry:
            _fail("MISSING_FIELD", f"{path}.to", "missing edge target")
        if "condition" not in entry:
            _fail("MISSING_FIELD", f"{path}.condition", "missing edge condition")
        src = _expect_string(entry, "from", path, "edge source")
        dst = _expect_string(entry, "to", path, "edge target")
        if src not in node_ids:
            _fail("UNKNOWN_NODE", f"{path}.from", f"unknown node {src!r}")
        if dst not in node_ids:
            _fail("UNKNOWN_NODE", f"{path}.to", f"unknown node {dst!r}")
        condition = parse_expr(entry["condition"], switch_index, f"{path}.condition")
        _read_label(entry, path)
        edges.append(Edge(id=eid, source=src, target=dst, condition=condition))
    _check_unique([e.id for e in edges], "$.edges", "edge")
    return tuple(edges)


def _parse_targets(raw, node_ids) -> tuple[Target, ...]:
    if not isinstance(raw, list):
        _fail("FIELD_TYPE", "$.targets", "targets must be a list")
    if not raw:
        _fail("EMPTY_LIST", "$.targets", "at least one target is required")
    targets: list[Target] = []
    for i, entry in enumerate(raw):
        path = f"$.targets[{i}]"
        _expect_object(entry, path, "target")
        _check_keys(entry, {"id", "node", "allowed_categories", "label"}, path)
        tid = _read_id(entry, path, "target")
        node = _expect_string(entry, "node", path, "target node")
        if node not in node_ids:
            _fail("UNKNOWN_NODE", f"{path}.node", f"unknown node {node!r}")
        allowed = frozenset()
        if "allowed_categories" in entry:
            allowed = frozenset(
                _read_categories(
                    entry["allowed_categories"],
                    f"{path}.allowed_categories",
                    "allowed_categories",
                )
            )
        _read_label(entry, path)
        targets.append(Target(id=tid, node=node, allowed=allowed))
    _check_unique([t.id for t in targets], "$.targets", "target")
    return tuple(targets)


def _parse_requirements(
    raw, switch_index, node_ids, targets, node_kinds
) -> tuple[Requirement, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        _fail(
            "FIELD_TYPE",
            "$.required_reachability",
            "required_reachability must be a list",
        )
    target_ids = {t.id for t in targets}
    requirements: list[Requirement] = []
    for i, entry in enumerate(raw):
        path = f"$.required_reachability[{i}]"
        _expect_object(entry, path, "requirement")
        _check_keys(
            entry, {"id", "source", "target", "requirement", "label"}, path
        )
        rid = _read_id(entry, path, "requirement")
        source = _expect_string(entry, "source", path, "source node")
        if source not in node_ids:
            _fail("UNKNOWN_NODE", f"{path}.source", f"unknown node {source!r}")
        if node_kinds.get(source) != "public_source":
            _fail(
                "REQUIREMENT_SOURCE_KIND",
                f"{path}.source",
                "required reachability sources must be public_source nodes",
            )
        target = _expect_string(entry, "target", path, "target id")
        if target not in target_ids:
            _fail("UNKNOWN_TARGET", f"{path}.target", f"unknown target {target!r}")
        if "requirement" not in entry:
            _fail("MISSING_FIELD", f"{path}.requirement", "missing requirement formula")
        formula = parse_expr(
            entry["requirement"], switch_index, f"{path}.requirement"
        )
        _read_label(entry, path)
        requirements.append(
            Requirement(
                id=rid, source=source, target=target, requirement=formula
            )
        )
    _check_unique(
        [r.id for r in requirements], "$.required_reachability", "requirement"
    )
    return tuple(requirements)


def _parse_candidates(raw, switch_index, node_ids, edge_ids) -> tuple[Candidate, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        _fail("FIELD_TYPE", "$.candidates", "candidates must be a list")
    candidates: list[Candidate] = []
    for i, entry in enumerate(raw):
        path = f"$.candidates[{i}]"
        _expect_object(entry, path, "candidate")
        if "kind" not in entry:
            _fail("MISSING_FIELD", f"{path}.kind", "missing candidate kind")
        kind = entry["kind"]
        if not isinstance(kind, str) or kind not in CANDIDATE_KINDS:
            _fail(
                "UNKNOWN_CANDIDATE_KIND",
                f"{path}.kind",
                f"candidate kind must be one of: {', '.join(CANDIDATE_KINDS)}",
            )
        _check_keys(entry, _ALLOWED_CANDIDATE_KEYS[kind], path)
        cid = _read_id(entry, path, "candidate")
        cost = _read_cost(entry, path)
        _read_label(entry, path)
        if kind == "disable_edge":
            if "edge" not in entry:
                _fail("MISSING_FIELD", f"{path}.edge", "missing edge id")
            eid = _expect_string(entry, "edge", path, "edge id")
            if eid not in edge_ids:
                _fail("UNKNOWN_EDGE", f"{path}.edge", f"unknown edge {eid!r}")
            if "condition" not in entry:
                _fail(
                    "MISSING_FIELD",
                    f"{path}.condition",
                    "missing disable condition",
                )
            disable = parse_expr(
                entry["condition"], switch_index, f"{path}.condition"
            )
            candidates.append(
                Candidate(
                    id=cid,
                    kind=kind,
                    cost=cost,
                    edge=eid,
                    disable=disable,
                )
            )
        else:
            if "node" not in entry:
                _fail("MISSING_FIELD", f"{path}.node", "missing node id")
            nid = _expect_string(entry, "node", path, "node id")
            if nid not in node_ids:
                _fail("UNKNOWN_NODE", f"{path}.node", f"unknown node {nid!r}")
            if "condition" not in entry:
                _fail(
                    "MISSING_FIELD",
                    f"{path}.condition",
                    "missing cleaning condition",
                )
            if "categories" not in entry:
                _fail(
                    "MISSING_FIELD",
                    f"{path}.categories",
                    "missing cleaning categories",
                )
            condition = parse_expr(
                entry["condition"], switch_index, f"{path}.condition"
            )
            cats = _read_categories(
                entry["categories"], f"{path}.categories", "categories"
            )
            if not cats:
                _fail(
                    "EMPTY_CATEGORIES",
                    f"{path}.categories",
                    "a cleaning candidate must name at least one category",
                )
            candidates.append(
                Candidate(
                    id=cid,
                    kind=kind,
                    cost=cost,
                    node=nid,
                    condition=condition,
                    categories=cats,
                )
            )
    _check_unique([c.id for c in candidates], "$.candidates", "candidate")
    return tuple(candidates)


# ---------------------------------------------------------------------------
# Graph validation
# ---------------------------------------------------------------------------


def topological_order(manifest: Manifest) -> tuple[str, ...]:
    """Kahn's algorithm over node IDs; rejects cycles with a field path."""
    node_ids = [n.id for n in manifest.nodes]
    indegree = {nid: 0 for nid in node_ids}
    outgoing: dict[str, list[str]] = {nid: [] for nid in node_ids}
    seen_edges: set[tuple[str, str]] = set()
    for edge in manifest.edges:
        pair = (edge.source, edge.target)
        if pair in seen_edges:
            continue
        seen_edges.add(pair)
        outgoing[edge.source].append(edge.target)
        indegree[edge.target] += 1
    # Deterministic ready set: always process the smallest ID available.
    ready = sorted(nid for nid in node_ids if indegree[nid] == 0)
    order: list[str] = []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for nxt in sorted(outgoing[current]):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                ready.append(nxt)
                ready.sort()
    if len(order) != len(node_ids):
        cyclic = sorted(nid for nid in node_ids if nid not in set(order))
        raise InputError(
            "DAG_CYCLE",
            "$.edges",
            "node graph contains a cycle involving: " + ", ".join(cyclic),
        )
    return tuple(order)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_manifest(doc: object) -> Manifest:
    if not isinstance(doc, dict):
        _fail("ROOT_TYPE", "$", "manifest root must be a JSON object")
    _check_keys(doc, _ALLOWED_TOP, "$")

    manifest_id = _expect_string(doc, "manifest_id", "$", "manifest_id")
    if not manifest_id.strip():
        _fail("EMPTY_ID", "$.manifest_id", "manifest_id must not be empty")

    switches, switch_index = _parse_switches(_expect_list(doc, "switches", "$", "switches"))
    constraints = _parse_constraints(doc.get("switch_constraints"), switch_index)
    nodes = _parse_nodes(_expect_list(doc, "nodes", "$", "nodes"), switch_index)
    node_ids = {n.id for n in nodes}
    edges = _parse_edges(
        _expect_list(doc, "edges", "$", "edges"), switch_index, node_ids
    )
    edge_ids = {e.id for e in edges}
    targets = _parse_targets(
        _expect_list(doc, "targets", "$", "targets"), node_ids
    )
    requirements = _parse_requirements(
        doc.get("required_reachability"),
        switch_index,
        node_ids,
        targets,
        {n.id: n.kind for n in nodes},
    )

    categories: set[str] = set()
    for node in nodes:
        categories.update(node.categories)
        for rule in node.cleans:
            categories.update(rule.categories)

    candidates = _parse_candidates(
        doc.get("candidates"), switch_index, node_ids, edge_ids
    )

    manifest = Manifest(
        manifest_id=manifest_id,
        switches=switches,
        switch_index=switch_index,
        constraints=constraints,
        nodes=nodes,
        edges=edges,
        targets=targets,
        requirements=requirements,
        candidates=candidates,
        category_ids=tuple(sorted(categories)),
        node_index={n.id: i for i, n in enumerate(nodes)},
        edge_index={e.id: i for i, e in enumerate(edges)},
    )
    topological_order(manifest)  # validate acyclicity up front
    return manifest


def parse_compare_case(doc: object) -> tuple[Manifest, Manifest]:
    if not isinstance(doc, dict):
        _fail("ROOT_TYPE", "$", "compare case must be a JSON object")
    _check_keys(doc, {"case_id", "old", "new"}, "$")
    if "old" not in doc:
        _fail("MISSING_FIELD", "$.old", "missing old manifest")
    if "new" not in doc:
        _fail("MISSING_FIELD", "$.new", "missing new manifest")
    if "case_id" in doc and not isinstance(doc["case_id"], str):
        _fail("FIELD_TYPE", "$.case_id", "case_id must be a string")
    old = parse_manifest(doc["old"])
    new = parse_manifest(doc["new"])
    if set(old.switch_index) != set(new.switch_index):
        old_only = sorted(set(old.switch_index) - set(new.switch_index))
        new_only = sorted(set(new.switch_index) - set(old.switch_index))
        detail = []
        if old_only:
            detail.append("only in old: " + ", ".join(old_only))
        if new_only:
            detail.append("only in new: " + ", ".join(new_only))
        raise InputError(
            "COMPARE_SWITCH_MISMATCH",
            "$.new.switches",
            "both manifests must use the same switch set (" + "; ".join(detail) + ")",
        )
    return old, new
