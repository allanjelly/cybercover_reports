import copy
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from karton.core import Task

from artemis.blocklist import blocklist_reports
from artemis.ip_utils import is_ip_address
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.reporters import get_all_reporters
from artemis.reporting.export.db import _fill_missing_data
from artemis.reporting.export.deduplication import deduplicate_reports
from artemis.reporting.modules.nuclei.reporter import NucleiReporter
from artemis.reporting.modules.port_scanner.reporter import PortScannerReporter
from artemis.reporting.severity import get_severity
from artemis.reporting.utils import get_top_level_target
from artemis.task_utils import get_target_host

log = logging.getLogger(__name__)

NUCLEI_RECEIVERS = ("nuclei", "nuclei-module", "cybercover_nuclei")
DEFAULT_REPLAY_SOURCE = "replayed"


class RowError(Exception):
    """A task result that cannot be processed; recorded in processing_errors, other rows continue."""


@dataclass
class ProcessedResults:
    reports: list[Report]
    assets: list[Asset]
    cached_endpoints: list[dict[str, Any]]
    scanned_targets: list[str]
    alerts: list[str]
    status_counts: dict[str, int]
    module_errors: list[dict[str, Any]] = field(default_factory=list)
    processing_errors: list[dict[str, Any]] = field(default_factory=list)


def _template_tags(finding: dict[str, Any]) -> list[str]:
    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = tags.split(",")
    if not isinstance(tags, list):
        return []
    return sorted({str(tag).strip().lower() for tag in tags if str(tag).strip()})


def _nuclei_reports(data: dict[str, Any]) -> tuple[list[Report], list[Asset]]:
    # English avoids Artemis' exception for new templates missing a Polish translation.
    # Business descriptions come from our catalog, not this technical description.
    normalized = copy.deepcopy(data)
    normalized["headers"]["receiver"] = "nuclei"
    findings = normalized["result"]
    if not isinstance(findings, list):
        return [], []
    for finding in findings:
        # cybercover_nuclei records "template" itself; older results only had the temporary path.
        if isinstance(finding, dict) and "template" not in finding:
            path = finding.get("template-path", "")
            match = re.fullmatch(r".*/cybercover-nuclei-[^/]+/(.+\.ya?ml)", path)
            if match:
                finding["template"] = match.group(1)
    reports: list[Report] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        single = dict(normalized, result=[finding])
        for report in NucleiReporter.create_reports(single, Language.en_US):
            template_id = finding.get("template-id")
            if template_id:
                report.additional_data["template_id"] = template_id
            report.additional_data["template_tags"] = _template_tags(finding)
            reports.append(report)
    return reports, NucleiReporter.get_assets(normalized)


def _port_data(data: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(data)
    normalized["headers"]["receiver"] = "port_scanner"
    return normalized


def _port_entries(result: dict[str, Any]) -> list[Any]:
    return [details for ports in result.values() if isinstance(ports, dict) for details in ports.values()]


def _cybercover_port_rows(row: dict[str, Any], data: dict[str, Any], cached: list[dict[str, Any]]):
    """Endpoints of a cybercover_port_scanner result.

    Replayed or adopted endpoints (not scanned in this task) go to ``cached`` and are never reported
    as new findings: current results mark every port entry with "source"; earlier versions marked
    replays only with status OK. A fresh discovery has the stock port_scanner format and is reported
    like the stock module.
    """
    result = row["result"]
    if row["status"] == "ERROR":
        return [], []
    if not isinstance(result, dict) or not all(isinstance(ports, dict) for ports in result.values()):
        raise RowError("unexpected cybercover_port_scanner result")
    entries = _port_entries(result)
    if not all(isinstance(details, dict) for details in entries):
        raise RowError("unexpected cybercover_port_scanner result")
    if any("source" in details for details in entries) or row["status"] == "OK":
        for host, ports in result.items():
            for port, details in ports.items():
                cached.append(
                    {
                        "host": host,
                        "port": int(port),
                        "service": details["service"],
                        "ssl": details["ssl"],
                        "source": details.get("source", DEFAULT_REPLAY_SOURCE),
                    }
                )
        return [], []
    if all(is_ip_address(host) for host in result):
        normalized = _port_data(data)
        return (
            PortScannerReporter.create_reports(normalized, Language.pl_PL),
            PortScannerReporter.get_assets(normalized),
        )
    raise RowError("unexpected cybercover_port_scanner result")


def _process_row(row: dict[str, Any], reporters: list[Any], cached: list[dict[str, Any]]):
    task = row["task"]
    data = {**task, **row}
    receiver = task["headers"]["receiver"]
    if receiver in NUCLEI_RECEIVERS:
        found_reports, found_assets = _nuclei_reports(data)
    elif receiver == "cybercover_port_scanner":
        found_reports, found_assets = _cybercover_port_rows(row, data, cached)
    else:
        found_reports, found_assets = [], []
        for reporter in reporters:
            if reporter is NucleiReporter:
                continue
            found_reports.extend(reporter.create_reports(data, Language.pl_PL))
            found_assets.extend(reporter.get_assets(data))
    if found_reports and row["status"] != "INTERESTING":
        raise RowError(f"reports produced for a result with status {row['status']}")
    return found_reports, found_assets


def _asset_key(asset: Asset) -> tuple[Any, ...]:
    # One entry per asset: the same IP or open port found with and without a domain is one asset.
    return (asset.asset_type, asset.additional_type, asset.name)


def process_results(rows: Iterable[dict[str, Any]], blocklist: list[Any]) -> ProcessedResults:
    reports: list[Report] = []
    assets: list[Asset] = []
    cached_endpoints: list[dict[str, Any]] = []
    seen_assets: dict[tuple[Any, ...], Asset] = {}
    scanned_targets: set[str] = set()
    status_counts: Counter[str] = Counter()
    module_errors: list[dict[str, Any]] = []
    processing_errors: list[dict[str, Any]] = []
    reporters = get_all_reporters()

    for row in rows:
        receiver = (row.get("task") or {}).get("headers", {}).get("receiver", row.get("receiver"))
        status_counts[row["status"]] += 1
        if row["status"] == "ERROR":
            module_errors.append(
                {
                    "module": receiver,
                    "target": row.get("target_string"),
                    "reason": row.get("status_reason"),
                    "task_result_id": row["id"],
                }
            )
        try:
            task = row["task"]
            scanned_targets.add(get_target_host(Task(headers=task["headers"], payload=task["payload"])))
            try:
                top_target = get_top_level_target(task)
            except ValueError:
                top_target = None
            # Stock and extra reporters raise on unexpected data; one such row must not hide the rest.
            found_cached: list[dict[str, Any]] = []
            found_reports, found_assets = _process_row(row, reporters, found_cached)

            for asset in found_assets:
                asset.original_karton_name = receiver
                asset.original_task_result_id = row["id"]
                domain = asset.name if asset.asset_type == AssetType.DOMAIN else None
                asset.last_domain = domain or task["payload"].get("last_domain")
                asset.top_level_target = top_target
                if not asset.top_level_target and receiver == "classifier":
                    asset.top_level_target = asset.name
                if not asset.top_level_target:
                    raise RowError("asset without a top-level target")
        except Exception as exc:  # noqa: BLE001 - isolate any reporter failure to its row
            log.exception("Unable to process task result %s", row.get("id"))
            processing_errors.append(
                {"task_result_id": row.get("id"), "module": receiver, "error": f"{type(exc).__name__}: {exc}"}
            )
            continue

        cached_endpoints.extend(found_cached)
        for report in found_reports:
            report.tag = row.get("tag")
            report.target_is_ip_address__as_property = report.target_is_ip_address()
            persistent = task.get("payload_persistent", {})
            if "original_ip" in persistent:
                report.target_ip = persistent["original_ip"]
                report.target_ip_checked = True
            report.original_karton_name = receiver
            report.original_task_result_id = row["id"]
            report.original_task_result_root_uid = row["analysis_id"]
            report.original_task_target_string = row["target_string"]
            report.severity = get_severity(report)
            report.last_domain = task["payload"].get("last_domain")
        accepted = blocklist_reports(found_reports, blocklist)
        for report in accepted:
            template_id = report.additional_data.get("template_id")
            if template_id and not report.additional_data["template_name"].startswith("group:"):
                report.additional_data["artemis_template_name"] = report.additional_data["template_name"]
                report.additional_data["template_name"] = f"custom:{template_id}"
            report.normal_form = report.get_normal_form()
        reports.extend(accepted)

        for asset in found_assets:
            key = _asset_key(asset)
            if key in seen_assets:
                _fill_missing_data(seen_assets[key], asset)
            else:
                seen_assets[key] = asset
                assets.append(asset)

    deduplicated = deduplicate_reports([], reports)
    alerts = [alert for reporter in reporters for alert in reporter.get_alerts(deduplicated)]
    unique_endpoints = {(e["host"], e["port"]): e for e in cached_endpoints}
    return ProcessedResults(
        reports=deduplicated,
        assets=assets,
        cached_endpoints=sorted(unique_endpoints.values(), key=lambda e: (e["host"], e["port"])),
        scanned_targets=sorted(scanned_targets),
        alerts=alerts,
        status_counts=dict(status_counts),
        module_errors=module_errors,
        processing_errors=processing_errors,
    )
