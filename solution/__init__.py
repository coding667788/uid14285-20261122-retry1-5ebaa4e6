"""Read-only symbolic security audit for synthetic build manifests.

Public surface:

* :func:`solution.manifest.parse_manifest` -- strict schema validation
* :func:`solution.audit.run_find` -- unsafe targets + minimal assignments
* :func:`solution.audit.run_compare` -- leak category diff across two manifests
* :func:`solution.remediate.run_remediate` -- one global approved-action policy

Run it as ``python -m solution <find|compare|remediate> CASE.json [--db DB.sqlite]``.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
