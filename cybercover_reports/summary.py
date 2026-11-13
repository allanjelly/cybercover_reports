"""Ordering of findings for the portal."""

from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most important first: by severity, then area, title and asset (stable for the portal)."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity") or "", 3), f["area"], f["title"], str(f["asset"])),
    )
