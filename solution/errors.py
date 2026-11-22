"""Typed structural errors with stable error codes and field locations.

All user-visible failures are :class:`SolutionError` instances.  ``path`` uses a
JSONPath-like dotted notation rooted at ``$`` (for example
``$.edges[2].condition``) so operators can locate the offending field directly.
"""

from __future__ import annotations


class SolutionError(Exception):
    """Base class for errors rendered as ``{"ok": false, "error": {...}}``."""

    def __init__(self, code: str, path: str, message: str):
        super().__init__(f"{code} at {path}: {message}")
        self.code = code
        self.path = path
        self.message = message

    def to_dict(self) -> dict:
        return {"code": self.code, "path": self.path, "message": self.message}


class InputError(SolutionError):
    """A structural problem in the input document."""


class AnalysisError(SolutionError):
    """A limit or precondition violated while auditing a well-formed input."""
