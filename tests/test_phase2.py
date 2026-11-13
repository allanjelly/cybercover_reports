"""Tests for the Phase 2 changes (R1-R6); see README."""

import copy
import datetime
import os

import pytest
from fastapi.testclient import TestClient

from cybercover_reports.catalog import enrich, load_catalog, nuclei_class, validate_catalog
from cybercover_reports.reporting import process_results
from cybercover_reports.summary import sort_findings

ANALYSIS_ID = "1497e976-6e7c-459d-80b2-681e1ea8c000"


def nuclei_finding(template_id="example", template="http/miscellaneous/example.yaml", severity="high", tags=None):
    finding = {
        "template-id": template_id,
        "info": {"name": "Example", "severity": severity, "description": "Example."},
        "matched-at": "http://192.0.2.1:5000/",
    }
    if template:
        finding["template"] = template
    if tags is not None:
        finding["info"]["tags"] = tags
    return finding


def nuclei_rows(make_row, *findings, receiver="cybercover_nuclei", row_id="nuclei"):
    return [
        make_row(receiver, list(findings), row_id=row_id, task_type="nuclei_target",
                 payload={"host": "192.0.2.1", "port": 5000, "ssl": False})
    ]


def entry_for(make_row, finding, **kwargs):
    result = process_results(nuclei_rows(make_row, finding, **kwargs), [])
    assert len(result.reports) == 1, result
    return enrich(result.reports[0], load_catalog())


# --- R2: layered business texts --------------------------------------------------------------------


def test_curated_template_entry_wins(make_row, monkeypatch):
    catalog = load_catalog()
    catalog["nuclei"]["grafana-default-login"] = dict(catalog["generic"], title="Reviewed Grafana text")
    monkeypatch.setattr("cybercover_reports.catalog.load_catalog", lambda: catalog)
    result = process_results(nuclei_rows(make_row, nuclei_finding(
        "grafana-default-login", "http/default-logins/grafana/grafana-default-login.yaml")), [])
    entry = enrich(result.reports[0], catalog)
    assert (entry["text_level"], entry["title"]) == ("template", "Reviewed Grafana text")
    assert entry["text_entry_used"] == entry["curation_key"] == "nuclei.grafana-default-login"


def test_exposed_panel_uses_the_panel_class(make_row):
    result = process_results(nuclei_rows(make_row, nuclei_finding(
        "grafana-detect", "http/exposed-panels/grafana-detect.yaml", severity="info", tags=["panel", "grafana"])), [])
    entry = enrich(result.reports[0], load_catalog())
    assert entry["technical"]["report_type"] == "nuclei_exposed_panel"
    assert (entry["text_level"], entry["text_entry_used"]) == ("class", "nuclei_classes.exposed_panel")
    assert entry["curation_key"] == "nuclei.grafana-detect"
    assert entry["title"] == "Panel administracyjny widoczny w internecie"


def test_panel_tag_alone_does_not_make_a_panel(make_row):
    """A default login tagged "panel" keeps the default-login text (exposed_panel matches folders only)."""
    entry = entry_for(make_row, nuclei_finding(
        "x-default-login", "http/default-logins/x/x-default-login.yaml", tags=["panel", "default-login"]))
    assert entry["text_entry_used"] == "nuclei_classes.default_login"


@pytest.mark.parametrize(
    "template, tags, expected",
    [
        ("http/default-logins/grafana/grafana-default-login.yaml", None, "default_login"),
        ("http/cves/2024/CVE-2024-0001.yaml", ["cve", "rce"], "remote_code_execution"),  # most specific first
        ("http/cves/2024/CVE-2024-0002.yaml", ["cve"], "known_vulnerability"),
        ("http/exposures/backups/zip-backup.yaml", None, "exposed_backup"),
        ("http/exposures/configs/env.yaml", None, "exposed_configuration"),
        ("http/exposures/files/other.yaml", None, "exposure"),
        ("http/takeovers/github-takeover.yaml", None, "takeover"),
        ("dast/vulnerabilities/sqli/sqli-error-based.yaml", None, "sql_injection"),
        (None, ["default-login", "grafana"], "default_login"),  # downloaded template without a path: tags
    ],
)
def test_nuclei_class_by_path_or_tags(make_row, template, tags, expected):
    entry = entry_for(make_row, nuclei_finding("t", template, tags=tags))
    assert (entry["text_level"], entry["text_entry_used"]) == ("class", f"nuclei_classes.{expected}")
    assert entry["area"] and entry["recommendation"]


def test_unclassified_template_uses_severity_text(make_row):
    entry = entry_for(make_row, nuclei_finding("t", "http/miscellaneous/something.yaml", severity="critical"))
    assert (entry["text_level"], entry["text_entry_used"]) == ("severity", "by_severity.high")
    assert entry["severity"] == "high"
    assert entry["title"] == load_catalog()["by_severity"]["high"]["title"]


def test_class_matching_needs_whole_path_segments():
    catalog = load_catalog()
    assert nuclei_class("http/vulnerabilities-like/x.yaml", [], catalog) is None
    assert nuclei_class("custom:sqli-looking-id", [], catalog) is None


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c["nuclei_classes"].append(copy.deepcopy(c["nuclei_classes"][0])),  # duplicate key
        lambda c: c["nuclei_classes"][0].pop("title"),
        lambda c: c["nuclei_classes"][0].update(match={}),
        lambda c: c["by_severity"].pop("low"),
        lambda c: c.pop("generic"),
    ],
)
def test_invalid_catalog_is_rejected(change):
    catalog = load_catalog()
    change(catalog)
    with pytest.raises(ValueError):
        validate_catalog(catalog)


# --- R3: one bad row does not break the report ------------------------------------------------------


def test_failing_reporter_is_isolated_to_its_row(make_row, monkeypatch):
    from artemis.reporting.base.reporters import get_all_reporters

    class Broken:
        @staticmethod
        def create_reports(task_result, language):
            if task_result["id"] == "bad":
                raise KeyError("unexpected format")
            return []

        @staticmethod
        def get_assets(task_result):
            return []

        @staticmethod
        def get_alerts(reports):
            return []

    monkeypatch.setattr("cybercover_reports.reporting.get_all_reporters", lambda: get_all_reporters() + [Broken])
    rows = [make_row("mail_dns_scanner", {}, row_id="bad")] + nuclei_rows(make_row, nuclei_finding(), row_id="good")
    result = process_results(rows, [])
    assert [r.original_task_result_id for r in result.reports] == ["good"]
    assert result.processing_errors == [
        {"task_result_id": "bad", "module": "mail_dns_scanner", "error": "KeyError"}
    ]


def test_malformed_port_result_is_recorded(make_row):
    result = process_results([make_row("cybercover_port_scanner", ["not", "a", "dict"], status="INTERESTING")], [])
    assert result.processing_errors and "cybercover_port_scanner" in result.processing_errors[0]["error"]


def test_module_errors_are_listed(make_row):
    error = make_row("dns_scanner", None, status="ERROR", row_id="dns")
    error["status_reason"] = "lookup failed"
    result = process_results([error], [])
    assert result.module_errors == [
        {"module": "dns_scanner", "target": "example.test", "reason": "lookup failed", "task_result_id": "dns"}
    ]


# --- duplicate assets -------------------------------------------------------------------------------


def test_same_asset_found_with_and_without_domain_is_listed_once(make_row):
    ports = {"192.0.2.1": {"80": {"service": "http", "ssl": False, "version": "nginx"}}}
    by_ip = make_row("port_scanner", ports, task_type="ip", row_id="ip", payload={"ip": "192.0.2.1"})
    by_domain = make_row("port_scanner", ports, task_type="domain", row_id="domain",
                         payload={"domain": "www.example.test", "last_domain": "www.example.test"})
    result = process_results([by_ip, by_domain], [])
    names = [(a.asset_type.value, a.name) for a in result.assets]
    assert len(names) == len(set(names))
    assert names.count(("open_port", "192.0.2.1:80")) == 1


# --- P2 consumer: replay marker -----------------------------------------------------------------


@pytest.mark.parametrize("source", ["replayed", "full_scan"])
def test_marked_replay_is_cached_endpoint_with_its_source(make_row, source):
    row = make_row("cybercover_port_scanner",
                   {"192.0.2.1": {"3389": {"service": "rdp", "ssl": False, "source": source}}},
                   status="OK", task_type="ip", payload={"ip": "192.0.2.1"})
    result = process_results([row], [])
    assert result.reports == []
    assert result.cached_endpoints == [
        {"host": "192.0.2.1", "port": 3389, "service": "rdp", "ssl": False, "source": source}
    ]


# --- R4: summary ------------------------------------------------------------------------------------


def _entry(severity, title, recommendation, area="applications", text_level="class"):
    return {"severity": severity, "title": title, "recommendation": recommendation, "area": area,
            "asset": "x", "text_level": text_level}


def test_findings_are_sorted_by_severity():
    entries = [
        _entry("low", "Low", "Fix later"),
        _entry("high", "Default login", "Change password", text_level="template"),
        _entry("medium", "Medium", "Fix soon", area="domain"),
        _entry("high", "RCE", "Update now"),
    ]
    assert [e["severity"] for e in sort_findings(entries)] == ["high", "high", "medium", "low"]


# --- scan type --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "disabled, expected",
    [
        ("admin_panel_login_bruter,example,cybercover_nuclei,cybercover_port_scanner", "full"),
        ("port_scanner,nuclei-module,bruter,vcs", "incremental"),
        ("nuclei-module,cybercover_nuclei", "custom"),
        (None, "full"),
    ],
)
def test_scan_type(disabled, expected):
    from cybercover_reports.api import scan_type

    assert scan_type({"disabled_modules": disabled}) == expected


# --- R6: catalog keys and coverage --------------------------------------------------------------


def test_extra_module_reporters_are_installed():
    from cybercover_reports.coverage import artemis_report_types

    # Mounted as in docker-compose.yml; without them findings of these modules are silently lost.
    assert {"no_https_redirect", "sql_injection", "bad_certificate_names"} <= artemis_report_types()


def test_every_catalog_key_is_an_artemis_report_type():
    from cybercover_reports.coverage import coverage

    result = coverage()
    assert result["unknown"] == [], f"catalog keys that are not Artemis report types: {result['unknown']}"
    assert "nuclei_vulnerability" not in result["missing"]


# --- R1: findings of extra modules are reported -----------------------------------------------------


def test_extra_module_finding_is_reported_with_curated_text(make_row):
    page = "<html><head><title>Shop</title></head><body>" + "Welcome to our shop. " * 20 + "</body></html>"
    row = make_row("ssl_checks", {"response_status_code": 200, "response_content_prefix": page, "bad_redirect": True},
                   payload={"domain": "shop.example.com", "last_domain": "shop.example.com"})
    row["task"]["payload_persistent"]["original_target"] = "shop.example.com"
    result = process_results([row], [])
    assert [str(r.report_type) for r in result.reports] == ["no_https_redirect"]
    entry = enrich(result.reports[0], load_catalog())
    assert entry["text_level"] == "report_type"
    assert entry["title"] == "Strona nie zawsze wymusza bezpieczne połączenie"


# --- R5: posture endpoint against Artemis' real tables ----------------------------------------------


@pytest.fixture
def artemis_db(monkeypatch):
    if not os.environ.get("POSTGRES_CONN_STR", "").startswith("postgresql"):
        pytest.skip("PostgreSQL not configured (run tests/run_in_docker.sh)")
    from artemis.config import Config
    from artemis.db import DB, Base

    db = DB()
    Base.metadata.drop_all(db._engine)
    Base.metadata.create_all(db._engine)
    monkeypatch.setattr(Config.Miscellaneous, "API_TOKEN", "test-token")
    # The posture tests use fixed dates; keep them younger than the archiver age whatever today is.
    monkeypatch.setattr(Config.Data.Autoarchiver, "AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING", 100 * 365 * 86400)
    from cybercover_reports import api

    monkeypatch.setattr(api, "get_db", lambda: db)
    yield db
    Base.metadata.drop_all(db._engine)


FULL = "admin_panel_login_bruter,example,cybercover_nuclei,cybercover_port_scanner"
INCREMENTAL = "port_scanner,nuclei-module,bruter,vcs"


def _insert(db, make_row, analyses, results):
    from sqlalchemy import insert

    from artemis.db import Analysis, TaskResult

    with db._engine.begin() as connection:
        connection.execute(insert(Analysis), [
            {"id": a, "created_at": created, "target": target, "tag": None, "stopped": False,
             "disabled_modules": disabled, "priority": "normal"}
            for a, created, target, disabled in analyses
        ])
        for analysis_id, row_id, finding, created in results:
            row = nuclei_rows(make_row, finding, receiver="cybercover_nuclei" if "inc" in analysis_id else "nuclei-module",
                              row_id=row_id)[0]
            row["task"]["payload_persistent"]["original_target"] = "192.0.2.1"
            connection.execute(insert(TaskResult), [{
                "id": row_id, "analysis_id": analysis_id, "created_at": created, "status": "INTERESTING",
                "receiver": row["receiver"], "target_string": "192.0.2.1:5000", "task": row["task"],
                "result": row["result"],
            }])


def test_posture_merges_latest_completed_full_scan_with_later_scans(artemis_db, make_row, monkeypatch):
    from cybercover_reports import api

    t = datetime.datetime(2026, 11, 1, 12, 0)
    day = datetime.timedelta(days=1)
    login = nuclei_finding("grafana-default-login", "http/default-logins/grafana/grafana-default-login.yaml")
    _insert(artemis_db, make_row, [
        ("full-old", t, "192.0.2.1", FULL),
        ("inc-before", t + day, "192.0.2.1", INCREMENTAL),
        ("full-baseline", t + 2 * day, "192.0.2.1", FULL),
        ("inc-after", t + 3 * day, "192.0.2.1", INCREMENTAL),
        ("full-running", t + 4 * day, "192.0.2.1", FULL),
        ("other-target", t + 3 * day, "192.0.2.99", FULL),
    ], [
        ("inc-before", "r1", nuclei_finding("only-before", "http/cves/2026/CVE-2026-1.yaml"), t + day),
        ("full-baseline", "r2", login, t + 2 * day),
        ("inc-after", "r3", login, t + 3 * day),
        ("inc-after", "r4", nuclei_finding("new-cve", "http/cves/2026/CVE-2026-2.yaml"), t + 3 * day),
    ])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {"full-running": 3})
    client = TestClient(api.app)
    headers = {"X-API-Token": "test-token"}

    data = client.get("/cybercover/posture", params={"target": "192.0.2.1"}, headers=headers).json()
    (target,) = data["per_target"]
    assert target["baseline"]["analysis_id"] == "full-baseline"
    assert [a["analysis_id"] for a in target["analyses"]] == ["full-baseline", "inc-after", "full-running"]
    assert [a["scan_type"] for a in target["analyses"]] == ["full", "incremental", "full"]
    by_key = {f["curation_key"]: f for f in data["findings"]}
    assert set(by_key) == {"nuclei.grafana-default-login", "nuclei.new-cve"}  # not "only-before"
    assert by_key["nuclei.grafana-default-login"]["first_seen"]["analysis_id"] == "full-baseline"
    assert by_key["nuclei.grafana-default-login"]["last_seen"]["analysis_id"] == "inc-after"
    assert by_key["nuclei.new-cve"]["first_seen"]["scan_type"] == "incremental"
    assert data["without_specific_text"] == ["nuclei.new-cve"]  # grafana-default-login has its own text
    assert data["results_may_be_partial"] and data["partial_reasons"] == ["pending_tasks"]
    assert sorted(f["severity"] for f in data["findings"]) == ["high", "high"]
    assert not {"summary", "assets", "cached_endpoints"} & set(data)

    assert client.get("/cybercover/posture", params={"target": "203.0.113.1"}, headers=headers).status_code == 404
    assert client.get("/cybercover/posture", headers=headers).status_code == 422
    assert client.get("/cybercover/posture", params={"target": "192.0.2.1"}).status_code in (401, 422)


def test_posture_without_completed_full_scan_uses_all_scans(artemis_db, make_row, monkeypatch):
    from cybercover_reports import api

    t = datetime.datetime(2026, 11, 1, 12, 0)
    _insert(artemis_db, make_row, [("inc-1", t, "192.0.2.1", INCREMENTAL)],
            [("inc-1", "r1", nuclei_finding("new-cve", "http/cves/2026/CVE-2026-2.yaml"), t)])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {})
    data = TestClient(api.app).get("/cybercover/posture", params={"target": "192.0.2.1"},
                                   headers={"X-API-Token": "test-token"}).json()
    assert data["per_target"][0]["baseline"] is None
    assert data["partial_reasons"] == ["no_completed_full_scan"]
    assert [f["curation_key"] for f in data["findings"]] == ["nuclei.new-cve"]


def test_posture_ignores_errors_of_superseded_incremental_scans(artemis_db, make_row, monkeypatch):
    from sqlalchemy import insert

    from artemis.db import TaskResult
    from cybercover_reports import api

    t = datetime.datetime(2026, 11, 1, 12, 0)
    day = datetime.timedelta(days=1)
    _insert(artemis_db, make_row, [
        ("full-1", t, "192.0.2.1", FULL),
        ("inc-failed", t + day, "192.0.2.1", INCREMENTAL),
        ("inc-ok", t + 2 * day, "192.0.2.1", INCREMENTAL),
    ], [])

    def error_row(analysis_id, row_id):
        row = make_row("cybercover_nuclei", [], status="ERROR", row_id=row_id, task_type="nuclei_target",
                       payload={"host": "192.0.2.1", "port": 5000})
        return {"id": row_id, "analysis_id": analysis_id, "created_at": t, "status": "ERROR",
                "receiver": "cybercover_nuclei", "target_string": "192.0.2.1:5000", "task": row["task"],
                "status_reason": "GitHub unavailable", "result": []}

    with artemis_db._engine.begin() as connection:
        connection.execute(insert(TaskResult), [error_row("inc-failed", "e1")])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {})
    client = TestClient(api.app)
    headers = {"X-API-Token": "test-token"}
    data = client.get("/cybercover/posture", params={"target": "192.0.2.1"}, headers=headers).json()
    assert data["results_may_be_partial"] is False
    assert [(e["analysis_id"], e["superseded"]) for e in data["module_errors"]] == [("inc-failed", True)]

    # The same error in the latest incremental scan leaves a gap.
    with artemis_db._engine.begin() as connection:
        connection.execute(insert(TaskResult), [error_row("inc-ok", "e2")])
    data = client.get("/cybercover/posture", params={"target": "192.0.2.1"}, headers=headers).json()
    assert data["partial_reasons"] == ["essential_module_errors"]
