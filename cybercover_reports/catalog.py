"""Business texts for findings, looked up in layers from the most to the least specific."""

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from artemis.reporting.base.report import Report

CATALOG_DIR = Path(__file__).parent / "catalog"
FIELDS = ("area", "title", "description", "business_risk", "recommendation")
SEVERITIES = ("high", "medium", "low")

# The areas of the portal's cyber shield, in display order. Every catalog entry has one of them.
AREAS = ("domain", "network", "passwords", "applications", "files")
DEFAULT_AREA = "applications"
# For Nuclei findings without a template text, these kinds of problem keep their class area; for the
# others (e.g. a known vulnerability) the area follows the protocol of the template.
KIND_AREAS = frozenset({"domain", "passwords", "files"})
NETWORK_TEMPLATE_DIRS = frozenset({"network", "javascript"})
DOMAIN_TEMPLATE_DIRS = frozenset({"dns", "ssl"})

# Where the business text of a finding comes from (text_level), from the most to the least specific:
#   template    - text for this exact Nuclei template (catalog section `nuclei`),
#   report_type - text for this exact Artemis report type, for findings of other modules,
#   class       - text for the kind of problem of a Nuclei template (e.g. default login, exposed panel),
#   severity    - text chosen only by the finding's severity,
#   generic     - generic text; the finding needs a specialist's assessment.
# Nuclei: template -> class -> severity -> generic. Other modules: report_type -> severity -> generic.
LEVELS = ("template", "report_type", "class", "severity", "generic")
SPECIFIC_LEVELS = frozenset({"template", "report_type"})


def _check_entry(entry: Any, name: str) -> None:
    if not isinstance(entry, dict) or any(
        not isinstance(entry.get(field), str) or not entry[field].strip() for field in FIELDS
    ):
        raise ValueError(f"Incomplete catalog entry {name}")
    if entry["area"] not in AREAS:
        raise ValueError(f"Catalog entry {name} has area {entry['area']!r}, expected one of {', '.join(AREAS)}")


def _check_strings(values: Any, name: str) -> None:
    if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"Invalid catalog list {name}")


def validate_catalog(catalog: Any) -> dict[str, Any]:
    if not isinstance(catalog, dict) or not all(
        isinstance(catalog.get(section), dict) for section in ("report_types", "nuclei", "by_severity")
    ):
        raise ValueError("Invalid report catalog")
    for section in ("report_types", "nuclei"):
        for key, entry in catalog[section].items():
            _check_entry(entry, f"{section}:{key}")
    classes = catalog.get("nuclei_classes")
    if not isinstance(classes, list):
        raise ValueError("Invalid report catalog: nuclei_classes must be a list")
    seen = set()
    for entry in classes:
        key = entry.get("key") if isinstance(entry, dict) else None
        if not isinstance(key, str) or key in seen:
            raise ValueError(f"Missing or duplicate nuclei_classes key {key!r}")
        seen.add(key)
        _check_entry(entry, f"nuclei_classes:{key}")
        match = entry.get("match")
        if not isinstance(match, dict) or not (match.get("paths") or match.get("tags")):
            raise ValueError(f"nuclei_classes:{key} needs match.paths or match.tags")
        for field in ("paths", "tags"):
            if field in match:
                _check_strings(match[field], f"nuclei_classes:{key}.match.{field}")
    for severity in SEVERITIES:
        _check_entry(catalog["by_severity"].get(severity), f"by_severity:{severity}")
    _check_entry(catalog.get("generic"), "generic")
    return catalog


@lru_cache(maxsize=1)
def _load_catalog_cached() -> str:
    with (CATALOG_DIR / "pl.yaml").open(encoding="utf-8") as file:
        catalog = validate_catalog(yaml.safe_load(file))
    return json.dumps(catalog)


def load_catalog() -> dict[str, Any]:
    # Parsed once per process; a fresh copy each time so callers cannot modify the cache.
    return json.loads(_load_catalog_cached())


def _tags(report: Report) -> set[str]:
    tags = report.additional_data.get("template_tags") or []
    if isinstance(tags, str):
        tags = tags.split(",")
    return {str(tag).strip().lower() for tag in tags if str(tag).strip()}


def nuclei_class(template_path: Optional[str], tags: Iterable[str], catalog: dict[str, Any]) -> Optional[dict[str, Any]]:
    """The first class whose path fragment occurs in the template path, or whose tag the template
    has. Classes are ordered from the most specific (e.g. remote code execution) to the broadest."""
    path = f"/{template_path.lower()}" if template_path and not template_path.startswith("custom:") else ""
    tag_set = set(tags)
    for entry in catalog["nuclei_classes"]:
        match = entry["match"]
        if path and any(f"/{fragment.strip('/')}/" in path for fragment in match.get("paths", [])):
            return entry
        if tag_set.intersection(match.get("tags", [])):
            return entry
    return None


def nuclei_area(template_path: Optional[str], tags: Iterable[str], class_area: Optional[str]) -> str:
    """The area of a Nuclei finding without a curated text.

    The kind of problem decides for passwords, files and domain classes (e.g. a default login is
    "passwords" whatever the protocol). Otherwise the template's protocol does: templates under
    network/ or javascript/ (or tagged "network") are "network", dns/ and ssl/ are "domain"; the rest
    keeps the class area, or "applications".
    """
    if class_area in KIND_AREAS:
        return class_area
    top = template_path.split("/", 1)[0].lower() if template_path and not template_path.startswith("custom:") else ""
    tag_set = set(tags)
    if top in NETWORK_TEMPLATE_DIRS or "network" in tag_set:
        return "network"
    if top in DOMAIN_TEMPLATE_DIRS or tag_set & {"dns", "ssl", "tls"}:
        return "domain"
    return class_area or DEFAULT_AREA


def enrich(report: Report, catalog: dict[str, Any]) -> dict[str, Any]:
    report_type = str(report.report_type)
    template_id = report.additional_data.get("template_id")
    severity = report.severity.value if report.severity else None

    entry: Optional[dict[str, Any]] = None
    level = entry_used = None
    if template_id:
        # Nuclei findings: the template, then the kind of problem. Artemis' Nuclei report types are too
        # coarse for a text (nearly every template is "nuclei_vulnerability").
        curation_key = f"nuclei.{template_id}"
        entry = catalog["nuclei"].get(template_id)
        if entry:
            level, entry_used = "template", curation_key
        else:
            matched = nuclei_class(report.additional_data.get("original_template_name"), _tags(report), catalog)
            if matched:
                entry, level, entry_used = matched, "class", f"nuclei_classes.{matched['key']}"
    else:
        curation_key = f"report_types.{report_type}"
        entry = catalog["report_types"].get(report_type)
        if entry:
            level, entry_used = "report_type", curation_key
    if entry is None and severity in catalog["by_severity"]:
        entry, level, entry_used = catalog["by_severity"][severity], "severity", f"by_severity.{severity}"
    if entry is None:
        entry, level, entry_used = catalog["generic"], "generic", "generic"

    identity = json.dumps([report.top_level_target, report.normal_form], ensure_ascii=False, separators=(",", ":"))
    result = {
        "id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "severity": severity,
        "asset": report.target,
        # text_level: where the texts come from (see LEVELS); text_entry_used: the catalog entry used;
        # curation_key: where a text specific to this finding would go in the catalog.
        "text_level": level,
        "text_entry_used": entry_used,
        "curation_key": curation_key,
        "technical": {
            "report_type": report_type,
            "additional_data": report.additional_data,
            "is_suspicious": report.is_suspicious,
            # Links the finding to its raw result in Artemis (request, response, matched data) for support.
            "original_task_result_id": report.original_task_result_id,
        },
    }
    result.update({field: entry[field] for field in FIELDS})
    if template_id and level != "template":
        class_area = entry["area"] if level == "class" else None
        result["area"] = nuclei_area(report.additional_data.get("original_template_name"), _tags(report), class_area)
    return result
