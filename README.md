# Build Manifest Security Audit

A read-only security audit for synthetic build manifests.  It answers three
questions over a directed acyclic graph of build steps and a set of boolean
switches:

| command | question |
| --- | --- |
| `find` | Which release targets can receive disallowed sensitive categories, under which switch assignments, and over which source chain? |
| `compare` | Between two manifests over the same switch set, which leak categories appeared or disappeared, and what is the smallest switch change that shows it? |
| `remediate` | Which single fixed set of *approved* changes makes every legal switch assignment safe while keeping required public inputs reachable? |

Everything is local, synthetic and offline.  No real build is executed, no
network is used.  The only dependencies are the Python standard library and
the CPU.

---

## Requirements

* Windows native Python **3.12** (also runs on any POSIX Python 3.12)
* Standard library only (`json`, `sqlite3`, `argparse`, `hashlib`, `unittest`)
* No third-party packages, no network access

---

## Quick start

```bash
python -m solution find      examples/find_case.json
python -m solution compare   examples/compare_case.json
python -m solution remediate examples/remediate_case.json
python -m solution remediate examples/remediate_unsolvable.json
```

Add run history with a SQLite file:

```bash
python -m solution find examples/find_case.json --db audit.sqlite
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

---

## Model

### Manifest schema

```jsonc
{
  "manifest_id": "example",                       // required, non-empty
  "switches": [                                   // required, at most 24
    {"id": "analytics", "default": false}
  ],
  "switch_constraints": ["NOT (debug AND analytics)"],   // optional boolean formulas
  "nodes": [                                      // required, >= 1
    {"id": "app_public", "kind": "public_source",    "categories": ["build_meta"]},
    {"id": "vendor_sdk", "kind": "sensitive_source", "categories": ["device_id"]},
    {"id": "redactor",   "kind": "sanitizer",
     "cleans": [{"condition": "telemetry", "categories": ["email"]}]},
    {"id": "bundle",     "kind": "merge"}
  ],
  "edges": [                                      // required
    {"id": "e01", "from": "vendor_sdk", "to": "bundle", "condition": "analytics"}
  ],
  "targets": [                                    // required, >= 1
    {"id": "t_pkg", "node": "bundle", "allowed_categories": ["build_meta"]}
  ],
  "required_reachability": [                      // optional, used by remediate
    {"id": "r1", "source": "app_public", "target": "t_pkg", "requirement": "TRUE"}
  ],
  "candidates": [                                 // optional, used by remediate
    {"id": "a01", "kind": "disable_edge", "edge": "e01",
     "condition": "analytics", "cost": 2},
    {"id": "a02", "kind": "extend_cleaning", "node": "redactor",
     "condition": "TRUE", "categories": ["email"], "cost": 3}
  ]
}
```

### Nodes

| kind | payload | meaning |
| --- | --- | --- |
| `public_source` | `categories` | originates the listed (normally non-sensitive) categories |
| `sensitive_source` | `categories` | originates sensitive categories; these are the categories the audit tracks |
| `merge` | none | passive junction |
| `sanitizer` | `cleans[]` | removes a category from the risk that **arrives** while a rule condition holds |

`sanitizer.cleans` entries are `{"condition": <formula>, "categories": [...]}`.
Cleaning is applied *at the sanitizer*: it only removes categories that flow
through that node.  Any alternative path around the sanitizer still carries the
category.  This is the "cleaning chain is bypassed" case the tests exercise.

### Boolean formula language

`switch_constraints`, `edges[].condition`, `cleans[].condition`,
`required_reachability[].requirement`, and both candidate `condition` fields all
share one strict language:

```
expr := or
or   := and ( 'OR' and )*
and  := not ( 'AND' not )*
not  := 'NOT' not | atom
atom := 'TRUE' | 'FALSE' | switch-id | '(' expr ')'
```

* Keywords (`AND`, `OR`, `NOT`, `TRUE`, `FALSE`) are case insensitive.
* A switch reference is the switch ID, optionally written `$id`.
* Switch IDs must start with a letter or `_` and may contain letters, digits,
  `_`, `.`, `-`; they may not collide with a keyword.
* Parsing is strict: an unknown switch, a missing `)`, a bad character or a
  dangling operator is a structural error with a code and a field path.

### Semantics for one switch assignment

1. The assignment is **legal** when every `switch_constraints` formula is true.
2. An edge is **active** when its `condition` is true and no selected
   `disable_edge` action cuts it for this assignment.
3. A node's risk is the union of the categories it originates (source nodes)
   plus the risk arriving over active incoming edges.
4. A sanitizer removes a category from that arriving risk while one of its
   clean rules for the category holds.
5. A target **rejects** every sensitive category that is not in its
   `allowed_categories`.

Risk is propagated as one boolean formula per (node, category), never as a
per-path category set.  Consequently a cleaned chain cannot "explain away" a
second, uncleaned route to the same category — the union keeps both.

### Symbolic evaluation (why 24 switches is not 2^24 work)

Every formula becomes a **reduced ordered BDD** over the switches
(`solution/bdd.py`).  Switch order is the lexicographic switch-ID order
(ascending), which is also the canonical assignment order used in output
(`false` before `true`).  Category presence is a least fixpoint over the
topologically sorted DAG, so each (node, category) pair is computed once per
policy.

This gives:

* the legal domain as one BDD, counted exactly in a single descent;
* "does any legal assignment leak here?" as a satisfiability test;
* the lexicographically smallest witness as a descent that prefers the `false`
  branch;
* `compare` as a BDD difference restricted to the common legal domain.

The engine handles 200 nodes / 500 edges / 24 switches in milliseconds (see
`tests/test_remediate.py::SearchBudgetTests::test_large_manifest_scales`).

---

## Output contract

All commands print **exactly one line of UTF-8 JSON** to stdout and nothing
else.  Keys are sorted, so identical logical input produces byte-identical
output (verified across `PYTHONHASHSEED` values in the tests).  Exit status is
`0` for a valid audit — including an "unsafe" or "unsolvable" verdict — and `2`
for a structural input error.

Every result carries `{"ok": true, "command": "<name>"}`.  Failures carry:

```json
{"ok": false, "error": {"code": "EXPR_UNKNOWN_SWITCH", "path": "$.edges[0].condition", "message": "..."}}
```

`path` is JSONPath-like, rooted at `$`.

### `find`

```jsonc
{
  "ok": true, "command": "find",
  "manifest_id": "…",
  "switches": ["alpha", "mid", "zeta"],                  // canonical ID order
  "legal": {"satisfiable": true, "assignment_count": 6},
  "safe": false,
  "unsafe_targets": [                                    // sorted by target ID
    {
      "target": "t_pkg", "node": "release",
      "allowed_categories": ["build_meta"],
      "assignment": {"analytics": false, "debug": false, "telemetry": false},
      "assignment_bits": [false, false, false],
      "leaking_categories": ["email"],                   // categories leaking at THIS assignment
      "chains": [{"category": "email", "chain": {…}}],
      "leaks": [                                         // sorted by category ID
        {
          "category": "device_id",
          "assignment": {…}, "assignment_bits": [true, false, false],
          "chain": {"source": "vendor_sdk",
                    "nodes": ["vendor_sdk", "bundle", "release"],
                    "edges": ["e01", "e07"], "length": 2}
        }
      ]
    }
  ],
  "targets": [ … per-target summary … ],
  "symbolic": {"method": "…", "bdd_nodes": 17, …}
}
```

* Each `leaks[i].assignment` is the **lexicographically smallest legal
  assignment** under which that target receives that disallowed category.
* Each `leaks[i].chain` is the **shortest un-cleaned source chain** under that
  assignment: fewest edges first, then the smallest edge-ID sequence.  A chain
  passing through a node whose cleaning is active under that assignment is not
  eligible (the category is not present there).
* The target-level `assignment` is the smallest witness that leaks *any*
  disallowed category at that target.

### `compare`

Input is a wrapper: `{"case_id": …, "old": <manifest>, "new": <manifest>}`.
Both manifests must use the **same switch set**, else
`COMPARE_SWITCH_MISMATCH` at `$.new.switches`.

```jsonc
{
  "ok": true, "command": "compare",
  "case_switches": ["analytics", "debug", "telemetry"],
  "baseline_defaults": {"analytics": false, …},
  "defaults_identical": true,
  "common_legal": {"satisfiable": true, "assignment_count": 6},
  "no_common_legal_assignments": false,
  "targets": [                                    // only targets with changes
    {
      "target": "t_pkg",
      "present_in": {"old": true, "new": true},
      "old_node": "release", "new_node": "release",
      "added":       [{"category": "token", "witness": {…}}],
      "disappeared": [{"category": "device_id", "witness": {…}}],
      "persisting":  [{"category": "email", "witness": {…}}],
      "minimal_change": {"assignment": {…}, "assignment_bits": […], "switch_changes": 0}
    }
  ],
  "unchanged_targets": [ … ],
  "symbolic": {…}
}
```

* Comparison is restricted to assignments legal in **both** manifests.
* `switch_changes` is the Hamming distance from the `old` switch defaults; ties
  are broken by the lexicographically smaller assignment.
* If the common legal domain is empty, the command sets
  `"no_common_legal_assignments": true`, `common_legal.satisfiable: false`,
  `assignment_count: 0`, an explanatory `message`, and an empty `targets`
  list.  This is not an error — it is an explicit answer.
* A target present in only one manifest is kept, with `present_in` recording
  which side it belongs to; its categories are reported as added or
  disappeared accordingly.

### `remediate`

```jsonc
{
  "ok": true, "command": "remediate",
  "switches": […],
  "legal": {"satisfiable": true, "assignment_count": 6},
  "solvable": true,
  "vacuous": false,                              // true when no legal assignment exists
  "policy": {
    "selected_actions": [
      {"id": "a01", "kind": "disable_edge", "edge": "e01",
       "condition": "analytics", "cost": 2},
      {"id": "a03", "kind": "extend_cleaning", "node": "redactor",
       "condition": "TRUE", "categories": ["email"], "cost": 3}
    ],
    "ids": ["a01", "a03"],
    "total_cost": 5,
    "action_count": 2
  },
  "final_audit": {"safe": true, "unsafe_targets": [], "targets": […]},
  "reachability": [
    {"id": "r_app_meta", "source": "app_public", "target": "t_pkg",
     "requirement": "TRUE", "satisfied": true, "vacuous": false,
     "assignment_count": 6,
     "witness": {"assignment": {…}, "assignment_bits": […],
                 "path": {"nodes": […], "edges": […], "length": …}}}
  ],
  "search": {
    "candidates_total": 5, "candidates_relevant": 5, "candidates_ignored": [],
    "states_visited": 22,
    "pruned_feasible_superset": 3, "pruned_cost_bound": 0,
    "pruned_dominance": 0, "pruned_noop": 0, "pruned_conflict": 0,
    "pruned_requirement_bound": 0, "pruned_infeasible_closure": 0,
    "propagation_evaluations": 16, "propagation_cache_hits": 6,
    "bdd_nodes": 17, "method": "…"
  }
}
```

The selected set is **one global fixed policy** applied to every legal switch
assignment.  It is *not* a per-assignment choice.  Ordering of the objective:
minimise total action `cost`, then the number of actions, then the ascending
action-ID tuple.

Candidate actions:

* `disable_edge` — the edge becomes inactive when
  `edge_condition AND disable_condition` holds.
* `extend_cleaning` — the node also cleans the listed categories while
  `condition` holds.

Two candidates that name the same edge (for `disable_edge`) or the same node
(for `extend_cleaning`) are **mutually exclusive**; a feasible policy contains
at most one per edge/node.

Requirements: each entry requires its `public_source` to reach its target
whenever the requirement formula holds.  Reachability uses live edges only;
cleaning removes categories, never paths, so a sanitizer can never substitute
for a required input that has genuinely disappeared.  A requirement whose
formula is unsatisfiable in the legal domain is reported as `"vacuous": true`.

If no fixed policy exists, `solvable` is `false` and the result carries
`reason`, a `minimal_unsatisfied_demand` (kind `leak` or `requirement`) with the
concrete violating assignment, plus the residual leak / requirement lists under
the closest reference policy and a full audit of that policy.

**Search and pruning.** Only candidates that sit on some source→target path are
considered; the rest are listed in `candidates_ignored`.  A depth-first
branch-and-bound in ascending ID order shares one BDD decision state across the
whole search:

* *feasible-superset* — a feasible prefix plus any further action is strictly
  worse in cost and count, so the subtree is cut;
* *cost bound* — a prefix already exceeding the best known cost cannot win;
* *requirement monotonicity* — reachability only shrinks as actions are added,
  so a violated requirement is permanent and the branch is cut;
* *maximal-closure infeasibility* — if even the maximal conflict-free superset
  of the current prefix is unsafe, no selection in the subtree can be;
* *state dominance* — identical effective (live-edge, cleaning) formulas at the
  same position with a strictly better prefix dominates;
* *no-op* and *conflict* cuts.

With 18 candidates the 2^18 subsets collapse to a few dozen visited states on
realistic inputs, and a hard budget raises `REMEDIATE_SEARCH_LIMIT` if a case
ever exceeds it.

---

## Persistence (`--db`)

`--db DB.sqlite` appends every run to a `runs` table (command, manifest ID,
input fingerprint, payload).  The result then gains a `persistence` block:

```jsonc
{"database": "audit.sqlite", "run_id": 2, "identical_prior_runs": 1,
 "total_runs": 2, "input_changed_since_prior_run": false}
```

The block is volatile metadata and is the only part of the output that changes
between runs; the audit body is byte-identical for identical logical input.
Without `--db` no database is touched.

---

## Error codes

| code | meaning |
| --- | --- |
| `INPUT_UNREADABLE`, `INPUT_INVALID_JSON` | the file cannot be read / parsed |
| `ROOT_TYPE`, `FIELD_TYPE`, `MISSING_FIELD`, `UNKNOWN_FIELD` | schema shape |
| `EMPTY_ID`, `DUPLICATE_ID`, `INVALID_SWITCH_ID`, `RESERVED_SWITCH_ID` | identifiers |
| `TOO_MANY_SWITCHES` | more than 24 switches |
| `UNKNOWN_NODE`, `UNKNOWN_EDGE`, `UNKNOWN_TARGET`, `UNKNOWN_NODE_KIND`, `UNKNOWN_CANDIDATE_KIND` | dangling references |
| `DAG_CYCLE` | the node graph is not acyclic |
| `DUPLICATE_CATEGORY`, `EMPTY_CATEGORIES` | category lists |
| `EXPR_*` | expression tokenizer/parser problems |
| `COMPARE_SWITCH_MISMATCH` | `compare` operands use different switch sets |
| `REQUIREMENT_SOURCE_KIND` | a required source is not a `public_source` |
| `REMEDIATE_SEARCH_LIMIT` | remediation search exceeded its state budget |
| `BDD_NODE_LIMIT` | symbolic representation exceeded its node budget |
| `INTERNAL_ERROR` | unexpected internal failure (details on stderr) |

Every error path is a JSONPath-like field location such as
`$.nodes[1].cleans[0].condition`.

---

## Project layout

```
solution/
  __main__.py     CLI: argument parsing, JSON output, exit codes
  errors.py       SolutionError / InputError / AnalysisError
  expr.py         strict boolean parser + AST evaluator
  bdd.py          reduced ordered BDD with apply/negate/count/cofactors
  manifest.py     schema validation, switch canonicalisation, DAG check
  engine.py       symbolic risk propagation, target audit, reachability
  audit.py        find and compare
  remediate.py    global fixed-policy search + output shaping
  db.py           optional SQLite run history
  jsonio.py       deterministic UTF-8 JSON helpers
examples/         runnable fixture configs for all three commands
tests/            unittest suite (including tests/oracle.py brute-force oracle)
```

---

## Reproduction commands

```bash
# audit
python -m solution find      examples/find_case.json
python -m solution compare   examples/compare_case.json
python -m solution remediate examples/remediate_case.json
python -m solution remediate examples/remediate_unsolvable.json

# with history
python -m solution find examples/find_case.json --db audit.sqlite

# tests
python -m unittest discover -s tests -v
```

`tests/oracle.py` is an independent brute-force implementation of the same
semantics used only by the test suite.  The randomized tests compare the
symbolic engine against it, including the remediation chosen-set, on hundreds
of small manifests.
