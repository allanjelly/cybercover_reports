import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from artemis.reporting.base.report import Report

CATALOG_DIR = Path(__file__).parent / "catalog"
FIELDS = ("area", "title", "description", "business_risk", "recommendation")


def load_catalog() -> dict[str, Any]:
    with (CATALOG_DIR / "pl.yaml").open(encoding="utf-8") as file:
        catalog = yaml.safe_load(file)
    if not isinstance(catalog, dict) or not all(
        isinstance(catalog.get(section), dict) for section in ("report_types", "nuclei")
    ):
        raise ValueError("Invalid report catalog")
    for section in ("report_types", "nuclei"):
        for key, entry in catalog[section].items():
            if not isinstance(entry, dict) or any(
                not isinstance(entry.get(field), str) or not entry[field].strip() for field in FIELDS
            ):
                raise ValueError(f"Incomplete catalog entry {section}:{key}")
    return catalog


def enrich(report: Report, catalog: dict[str, Any]) -> dict[str, Any]:
    report_type = str(report.report_type)
    template_id = report.additional_data.get("template_id")
    key = f"nuclei:{template_id}" if template_id else report_type
    entry = (
        catalog["nuclei"].get(template_id)
        if template_id
        else catalog["report_types"].get(report_type)
    )
    identity = json.dumps(
        [report.top_level_target, report.normal_form], ensure_ascii=False, separators=(",", ":")
    )
    result = {
        "id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "severity": report.severity.value if report.severity else None,
        "asset": report.target,
        "catalog_key": key,
        "catalog": "curated" if entry else "fallback",
        "technical": {
            "report_type": report_type,
            "additional_data": report.additional_data,
            "original_task_result_id": report.original_task_result_id,
            "original_karton_name": report.original_karton_name,
            "normal_form": report.normal_form,
            "is_suspicious": report.is_suspicious,
        },
    }
    if entry:
        result.update({field: entry[field] for field in FIELDS})
    else:
        result.update({
            "area": "unknown",
            "title": "Wykryto problem wymagający oceny",
            "description": "Skan wykrył problem, dla którego nie ma jeszcze zatwierdzonego opisu.",
            "business_risk": "Wpływ na firmę wymaga oceny specjalisty.",
            "recommendation": "Przekaż wynik administratorowi do analizy.",
        })
    return result
