"""Deterministic JSON output helpers.

Output must be UTF-8, stable for logically identical input, and independent of
dict insertion order.  ``dumps`` therefore sorts keys and disables ``ensure_ascii``
so that non-ASCII IDs survive round-tripping.  ``write_json`` always appends a
single trailing newline.
"""

from __future__ import annotations

import json
import sys


def dumps(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def pretty(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )


def write_json(value: object, stream=None) -> None:
    """Write ``value`` as compact JSON plus a newline to ``stream`` (stdout)."""
    out = stream if stream is not None else sys.stdout
    out.write(dumps(value))
    out.write("\n")
    out.flush()
