"""A short business summary of findings, for owners of small businesses."""

from collections import Counter
from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_TOP_ACTIONS = 3


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most important first: by severity, then area, title and asset (stable for the portal)."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity") or "", 3), f["area"], f["title"], str(f["asset"])),
    )


def build_summary(findings: list[dict[str, Any]], catalog: dict[str, Any]) -> dict[str, Any]:
    by_severity = Counter(f.get("severity") or "unknown" for f in findings)
    risk_level = next((level for level in ("high", "medium", "low") if by_severity.get(level)), "none")
    if risk_level == "none" and findings:
        risk_level = "low"  # findings without a severity still deserve a look

    # The most important distinct recommendations, each with the problems it addresses.
    actions: dict[str, dict[str, Any]] = {}
    for finding in sort_findings(findings):
        action = actions.setdefault(
            finding["recommendation"],
            {"recommendation": finding["recommendation"], "severity": finding.get("severity"), "titles": [], "count": 0},
        )
        action["count"] += 1
        if finding["title"] not in action["titles"]:
            action["titles"].append(finding["title"])

    return {
        "risk_level": risk_level,
        "headline": catalog["summary"][risk_level].format(count=len(findings)),
        "total": len(findings),
        "by_severity": {level: by_severity.get(level, 0) for level in ("high", "medium", "low")},
        "by_area": dict(sorted(Counter(f["area"] for f in findings).items())),
        "top_actions": list(actions.values())[:MAX_TOP_ACTIONS],
        # Findings whose text is not reviewed for this exact problem; operators should check them.
        "needs_review": sum(1 for f in findings if f["catalog"] != "curated"),
    }
