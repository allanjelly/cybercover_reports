import copy
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

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


@dataclass
class ProcessedResults:
    reports: list[Report]
    assets: list[Asset]
    cached_endpoints: list[dict[str, Any]]
    scanned_targets: list[str]
    alerts: list[str]
    status_counts: dict[str, int]


def _nuclei_reports(data: dict[str, Any]) -> tuple[list[Report], list[Asset]]:
    # English avoids Artemis' exception for new templates missing a Polish translation.
    # Business descriptions come from our catalog, not this technical description.
    normalized = copy.deepcopy(data)
    normalized["headers"]["receiver"] = "nuclei"
    findings = normalized["result"]
    if not isinstance(findings, list):
        return [], []
    for finding in findings:
        if isinstance(finding, dict) and "template" not in finding:
            path = finding.get("template-path", "")
            match = re.fullmatch(r"/tmp/cybercover-nuclei-[^/]+/(.+\.ya?ml)", path)
            if match:
                finding["template"] = match.group(1)
    reports: list[Report] = []
    for finding in findings:
        single = dict(normalized, result=[finding])
        for report in NucleiReporter.create_reports(single, Language.en_US):
            template_id = finding.get("template-id")
            if template_id:
                report.additional_data["template_id"] = template_id
            reports.append(report)
    return reports, NucleiReporter.get_assets(normalized)


def _port_data(data: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(data)
    normalized["headers"]["receiver"] = "port_scanner"
    return normalized


def process_results(rows: Any, blocklist: list[Any]) -> ProcessedResults:
    reports: list[Report] = []
    assets: list[Asset] = []
    cached_endpoints: list[dict[str, Any]] = []
    seen_assets: dict[tuple[Any, ...], Asset] = {}
    scanned_targets: set[str] = set()
    status_counts: Counter[str] = Counter()
    reporters = get_all_reporters()

    for row in rows:
        task = row["task"]
        data = {**task, **row}
        receiver = task["headers"]["receiver"]
        status_counts[row["status"]] += 1
        scanned_targets.add(get_target_host(Task(headers=task["headers"], payload=task["payload"])))
        try:
            top_target = get_top_level_target(task)
        except ValueError:
            top_target = None

        if receiver in ("nuclei", "nuclei-module", "cybercover_nuclei"):
            found_reports, found_assets = _nuclei_reports(data)
        elif receiver == "cybercover_port_scanner":
            result = row["result"]
            if row["status"] == "ERROR":
                found_reports, found_assets = [], []
            elif row["status"] == "OK" and isinstance(result, dict):
                for host, ports in result.items():
                    for port, details in ports.items():
                        cached_endpoints.append(
                            {"host": host, "port": int(port), "service": details["service"],
                             "ssl": details["ssl"], "source": "replayed"}
                        )
                found_reports, found_assets = [], []
            elif isinstance(result, dict) and all(is_ip_address(host) for host in result):
                normalized = _port_data(data)
                found_reports = PortScannerReporter.create_reports(normalized, Language.pl_PL)
                found_assets = PortScannerReporter.get_assets(normalized)
            else:
                raise ValueError(f"Unexpected cybercover port scanner result for {row['id']}")
        else:
            found_reports = []
            found_assets = []
            for reporter in reporters:
                if reporter is NucleiReporter:
                    continue
                found_reports.extend(reporter.create_reports(data, Language.pl_PL))
                found_assets.extend(reporter.get_assets(data))

        if found_reports and row["status"] != "INTERESTING":
            raise ValueError(f"Reports produced for non-interesting result {row['id']}")
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
            asset.original_karton_name = receiver
            asset.original_task_result_id = row["id"]
            domain = asset.name if asset.asset_type == AssetType.DOMAIN else None
            asset.last_domain = domain or task["payload"].get("last_domain")
            asset.top_level_target = top_target
            if not asset.top_level_target and receiver == "classifier":
                asset.top_level_target = asset.name
            if not asset.top_level_target:
                raise ValueError(f"Asset without top-level target in result {row['id']}")
            key = (asset.asset_type, asset.additional_type, asset.name, asset.last_domain)
            if key in seen_assets:
                _fill_missing_data(seen_assets[key], asset)
            else:
                seen_assets[key] = asset
                assets.append(asset)

    deduplicated = deduplicate_reports([], reports)
    alerts = [alert for reporter in reporters for alert in reporter.get_alerts(deduplicated)]
    return ProcessedResults(
        reports=deduplicated,
        assets=assets,
        cached_endpoints=cached_endpoints,
        scanned_targets=sorted(scanned_targets),
        alerts=alerts,
        status_counts=dict(status_counts),
    )
