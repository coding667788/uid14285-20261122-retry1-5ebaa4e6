"""Command line entry point: ``python -m solution <command> CASE.json [--db DB]``.

Commands
    ``find``       read-only unsafe-target audit
    ``compare``    old-vs-new leak category diff over a shared switch set
    ``remediate``  fixed approved-action policy search

Output is UTF-8 JSON on stdout and nothing else.  Structural errors are printed
as ``{"ok": false, "error": {"code", "path", "message"}}`` with exit status 2.
An *infeasible but well-formed* result (for example no common legal assignment
in ``compare``) is still ``ok: true`` and exit status 0, because it is a valid
audit answer rather than a tool failure.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback

from . import db as dbmod
from .audit import run_compare, run_find
from .errors import InputError, SolutionError
from .jsonio import write_json
from .manifest import parse_compare_case, parse_manifest
from .remediate import run_remediate

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_INPUT = 2
EXIT_INTERNAL = 3

PERSISTENT = {"find", "compare", "remediate"}


def _load_json(path: str) -> object:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise InputError("INPUT_UNREADABLE", "$", f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(
            "INPUT_INVALID_JSON",
            "$",
            f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}",
        ) from exc


def _emit_failure(code: str, path: str, message: str, exit_code: int) -> int:
    write_json({"ok": False, "error": {"code": code, "path": path, "message": message}})
    return exit_code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Read-only symbolic security audit for synthetic build manifests.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("find", "list unsafe targets with lexicographically minimal assignments"),
        ("compare", "diff leak categories between two manifests"),
        ("remediate", "search one global approved-action policy"),
    ):
        child = sub.add_parser(name, help=help_text)
        child.add_argument("case", help="path to CASE.json")
        child.add_argument(
            "--db",
            default=None,
            help="optional SQLite file for persistent run history",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    # Output must be UTF-8 regardless of the console code page.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", newline="\n")

    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed usage to stderr
        return EXIT_USAGE if exc.code else EXIT_OK

    try:
        document = _load_json(args.case)
        if args.command == "find":
            manifest = parse_manifest(document)
            result = run_find(manifest)
            manifest_id = manifest.manifest_id
        elif args.command == "compare":
            old, new = parse_compare_case(document)
            result = run_compare(old, new)
            manifest_id = f"{old.manifest_id}->{new.manifest_id}"
        elif args.command == "remediate":
            manifest = parse_manifest(document)
            result = run_remediate(manifest)
            manifest_id = manifest.manifest_id
        else:  # pragma: no cover - argparse guards this
            return _emit_failure("UNKNOWN_COMMAND", "$", args.command, EXIT_USAGE)

        if args.command in PERSISTENT:
            store = dbmod.Store(args.db) if args.db else None
            if store is not None:
                fp = dbmod.fingerprint(document)
                result["persistence"] = store.record(
                    args.command, manifest_id, fp, result
                )
                store.close()

        write_json(result)
        return EXIT_OK

    except SolutionError as exc:
        return _emit_failure(exc.code, exc.path, exc.message, EXIT_INPUT)
    except BrokenPipeError:  # pragma: no cover - pipe closed by consumer
        return EXIT_OK
    except Exception as exc:  # pragma: no cover - defensive
        traceback.print_exc(file=sys.stderr)
        return _emit_failure(
            "INTERNAL_ERROR", "$", f"{type(exc).__name__}: {exc}", EXIT_INTERNAL
        )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
