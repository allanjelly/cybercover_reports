import datetime
import json
import os
from functools import lru_cache
from typing import Annotated, Any, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.openapi.docs import get_swagger_ui_html
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig

from artemis.api import verify_api_token
from artemis.blocklist import load_blocklist
from artemis.config import Config
from artemis.db import DB
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.karton_utils import get_num_pending_tasks

from .catalog import SPECIFIC_LEVELS, enrich, load_catalog
from .loader import load_analyses, load_results
from .reporting import ProcessedResults, process_results
from .summary import sort_findings

# The API docs are served only with the token (below), not publicly.
app = FastAPI(title="Cybercover fast reporter", docs_url=None, redoc_url=None, openapi_url=None)

MAX_POSTURE_TARGETS = 50

# Errors of these modules make a report partial: they produce (or feed) most findings. Errors of
# other modules are listed in module_errors without marking the whole report as partial.
ESSENTIAL_MODULES = frozenset(
    module.strip()
    for module in os.environ.get(
        "CYBERCOVER_REPORTS_ESSENTIAL_MODULES",
        "port_scanner,cybercover_port_scanner,nuclei-router,nuclei-module,cybercover_nuclei",
    ).split(",")
    if module.strip()
)

INCREMENTAL_MODULE = "cybercover_nuclei"
FULL_SCAN_MODULE = "nuclei-module"
# A full scan runs at least these modules. A narrower analysis (e.g. a quick Nuclei-only re-test
# from the UI) is "custom" and never becomes the posture baseline.
FULL_SCAN_CORE_MODULES = frozenset({"nuclei-module", "port_scanner", "subdomain_enumeration"})


@lru_cache(maxsize=1)
def get_db() -> DB:
    return DB()


def scan_type(analysis: dict[str, Any]) -> str:
    """"full", "incremental" or "custom", derived from the modules Artemis stores as disabled for
    the analysis.

    A full scan is requested with targets only (Cybercover modules are disabled by default), so the
    stock Nuclei, port scanner and subdomain enumeration all run. An incremental scan is requested
    with enabled_modules = [nuclei-router, cybercover_port_scanner, cybercover_nuclei]. Anything else
    is custom.
    """
    disabled = {module.strip() for module in (analysis.get("disabled_modules") or "").split(",") if module.strip()}
    if not disabled & FULL_SCAN_CORE_MODULES:
        return "full"
    if INCREMENTAL_MODULE not in disabled and FULL_SCAN_MODULE in disabled:
        return "incremental"
    return "custom"


def _possibly_archived(analysis: dict[str, Any]) -> bool:
    """Whether Artemis' autoarchiver may already have removed non-INTERESTING task results (including
    module errors) of the analysis, so its completeness can no longer be judged from the database."""
    created_at = analysis.get("created_at")
    if not isinstance(created_at, datetime.datetime):
        return False
    if created_at.tzinfo is not None:
        created_at = created_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    age = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - created_at
    limit = Config.Data.Autoarchiver.AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING
    return age.total_seconds() > limit


def _pending_tasks() -> dict[str, int]:
    return get_num_pending_tasks(KartonBackend(config=KartonConfig()))


def _partial_reasons(
    processed: ProcessedResults,
    pending: int,
    stopped: bool,
    *,
    no_baseline: bool = False,
    count_module_errors: bool = True,
) -> list[str]:
    reasons = []
    if pending:
        reasons.append("pending_tasks")
    if stopped:
        reasons.append("stopped")
    if no_baseline:
        reasons.append("no_completed_full_scan")
    if processed.processing_errors:
        reasons.append("processing_errors")
    if count_module_errors and any(error["module"] in ESSENTIAL_MODULES for error in processed.module_errors):
        reasons.append("essential_module_errors")
    return reasons


def _analysis_summary(analysis: dict[str, Any], pending: dict[str, int]) -> dict[str, Any]:
    return {
        "analysis_id": analysis["id"],
        "target": analysis["target"],
        "created_at": analysis.get("created_at"),
        "tag": analysis.get("tag"),
        "scan_type": scan_type(analysis),
        "stopped": bool(analysis.get("stopped")),
        "pending_tasks": pending.get(analysis["id"], 0),
    }


def _respond(response: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(response, cls=JSONEncoderAdditionalTypes))


@app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(verify_api_token)])
def openapi_schema() -> dict:
    return app.openapi()


@app.get("/docs", include_in_schema=False, dependencies=[Depends(verify_api_token)])
def api_docs() -> Any:
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - docs")


@app.get("/cybercover/findings", dependencies=[Depends(verify_api_token)])
def findings(analysis_id: UUID) -> dict:
    analysis_id_str = str(analysis_id)
    db = get_db()
    analysis = db.get_analysis_by_id(analysis_id_str)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    pending_before = _pending_tasks().get(analysis_id_str, 0)
    processed = process_results(load_results(db, analysis_id_str), load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE))
    pending_after = _pending_tasks().get(analysis_id_str, 0)
    catalog = load_catalog()
    entries = sort_findings([enrich(report, catalog) for report in processed.reports])
    reasons = _partial_reasons(processed, pending_before or pending_after, bool(analysis.get("stopped")))
    if _possibly_archived(analysis):
        reasons.append("results_possibly_archived")
    return _respond(
        {
            "analysis_id": analysis_id_str,
            "target": analysis["target"],
            "tag": analysis.get("tag"),
            "created_at": analysis.get("created_at"),
            "scan_type": scan_type(analysis),
            "stopped": analysis.get("stopped", False),
            "pending_tasks": pending_after,
            "results_may_be_partial": bool(reasons),
            "partial_reasons": reasons,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "findings": entries,
            "without_specific_text": sorted(
                {item["curation_key"] for item in entries if item["text_level"] not in SPECIFIC_LEVELS}
            ),
            "scanned_targets": processed.scanned_targets,
            "alerts": processed.alerts,
            "task_status_counts": processed.status_counts,
            "module_errors": processed.module_errors,
            "processing_errors": processed.processing_errors,
        }
    )


def _select_analyses(
    analyses: list[dict[str, Any]], pending: dict[str, int]
) -> tuple[Optional[dict[str, Any]], list[dict[str, Any]]]:
    """The baseline (latest completed full scan) and the analyses that make up the current posture:
    the baseline and every later analysis. Without a completed full scan: all analyses."""
    completed_full = [
        a for a in analyses if scan_type(a) == "full" and not a.get("stopped") and not pending.get(a["id"], 0)
    ]
    if not completed_full:
        return None, list(analyses)
    baseline = completed_full[-1]
    position = analyses.index(baseline)
    return baseline, analyses[position:]


@app.get("/cybercover/posture", dependencies=[Depends(verify_api_token)])
def posture(target: Annotated[list[str], Query()], tag: Optional[str] = None) -> dict:
    """Current findings of a customer's targets: the latest completed full scan of each target
    merged with all later (incremental or full) scans, deduplicated across scans."""
    # Artemis stores targets in lower case.
    targets = sorted({item.strip().lower() for item in target if item.strip()})
    if not targets or len(targets) > MAX_POSTURE_TARGETS:
        raise HTTPException(status_code=422, detail=f"Pass 1 to {MAX_POSTURE_TARGETS} target parameters")
    db = get_db()
    analyses = load_analyses(db, targets, tag)
    if not analyses:
        raise HTTPException(status_code=404, detail="No analyses found for the given targets")

    pending_before = _pending_tasks()
    blocklist = load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE)
    catalog = load_catalog()

    per_target = []
    merged: dict[str, dict[str, Any]] = {}
    alerts: list[str] = []
    module_errors: list[dict[str, Any]] = []
    processing_errors: list[dict[str, Any]] = []
    reasons: set[str] = set()
    status_counts: dict[str, int] = {}

    for name in targets:
        target_analyses = [a for a in analyses if a["target"] == name]
        if not target_analyses:
            per_target.append({"target": name, "baseline": None, "analyses": [], "found": False})
            continue
        baseline, selected = _select_analyses(target_analyses, pending_before)
        per_target.append(
            {
                "target": name,
                "found": True,
                "baseline": _analysis_summary(baseline, pending_before) if baseline else None,
                "analyses": [_analysis_summary(a, pending_before) for a in selected],
            }
        )
        if baseline is None:
            reasons.add("no_completed_full_scan")

        # A failed incremental scan does not advance Cybercover's scan state, so the next successful
        # incremental scan covers the same templates: only errors of the latest one leave a gap.
        incrementals = [a["id"] for a in selected if scan_type(a) == "incremental"]
        latest_incremental = incrementals[-1] if incrementals else None

        for analysis in selected:  # oldest first
            seen = _analysis_summary(analysis, pending_before)
            processed = process_results(load_results(db, analysis["id"]), blocklist)
            superseded = scan_type(analysis) == "incremental" and analysis["id"] != latest_incremental
            if not superseded and _possibly_archived(analysis):
                reasons.add("results_possibly_archived")
            reasons.update(
                _partial_reasons(
                    processed,
                    pending_before.get(analysis["id"], 0),
                    bool(analysis.get("stopped")),
                    count_module_errors=not superseded,
                )
            )
            for status, count in processed.status_counts.items():
                status_counts[status] = status_counts.get(status, 0) + count
            for entry in (enrich(report, catalog) for report in processed.reports):
                first_seen = merged[entry["id"]]["first_seen"] if entry["id"] in merged else seen
                merged[entry["id"]] = {**entry, "first_seen": first_seen, "last_seen": seen}
            alerts.extend(alert for alert in processed.alerts if alert not in alerts)
            module_errors.extend(
                {**error, "analysis_id": analysis["id"], "superseded": superseded} for error in processed.module_errors
            )
            processing_errors.extend({**error, "analysis_id": analysis["id"]} for error in processed.processing_errors)

    pending_after = _pending_tasks()
    if any(pending_after.get(a["analysis_id"], 0) for t in per_target for a in t["analyses"]):
        reasons.add("pending_tasks")
    entries = sort_findings(list(merged.values()))
    return _respond(
        {
            "targets": targets,
            "tag": tag,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "per_target": per_target,
            "results_may_be_partial": bool(reasons),
            "partial_reasons": sorted(reasons),
            "findings": entries,
            "without_specific_text": sorted(
                {item["curation_key"] for item in entries if item["text_level"] not in SPECIFIC_LEVELS}
            ),
            "alerts": alerts,
            "task_status_counts": status_counts,
            "module_errors": module_errors,
            "processing_errors": processing_errors,
        }
    )
