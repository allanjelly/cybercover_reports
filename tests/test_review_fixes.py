"""Regression tests for the findings of the independent review of 2026-11-12 (R1-R6)."""

import datetime

import pytest
from fastapi.testclient import TestClient

from cybercover_reports.reporting import process_results
from test_phase2 import FULL, INCREMENTAL, _insert, artemis_db, nuclei_finding, nuclei_rows  # noqa: F401

T = datetime.datetime(2026, 11, 1, 12, 0)
DAY = datetime.timedelta(days=1)
HEADERS = {"X-API-Token": "test-token"}


def _posture(params):
    from cybercover_reports import api

    return TestClient(api.app).get("/cybercover/posture", params=params, headers=HEADERS)


def _error_row(make_row, analysis_id, row_id, receiver, created_at=T):
    row = make_row(receiver, [], status="ERROR", row_id=row_id, task_type="nuclei_target",
                   payload={"host": "192.0.2.1", "port": 5000})
    return {"id": row_id, "analysis_id": analysis_id, "created_at": created_at, "status": "ERROR",
            "receiver": receiver, "target_string": "192.0.2.1:5000", "task": row["task"],
            "status_reason": "Nuclei failed", "result": []}


# R1: results that the autoarchiver may have removed are flagged -----------------------------------


def test_analysis_older_than_the_archiver_age_is_flagged(artemis_db, make_row, monkeypatch):  # noqa: F811
    from artemis.config import Config
    from cybercover_reports import api

    old = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - 20 * DAY
    recent = old + 18 * DAY
    full_id, inc_id = "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"
    _insert(artemis_db, make_row, [(full_id, old, "192.0.2.1", FULL), (inc_id, recent, "192.0.2.1", INCREMENTAL)], [])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {})
    monkeypatch.setattr(Config.Data.Autoarchiver, "AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING", 15 * 86400)
    data = _posture({"target": "192.0.2.1"}).json()
    assert data["partial_reasons"] == ["results_possibly_archived"]
    findings = TestClient(api.app).get(
        "/cybercover/findings", params={"analysis_id": inc_id}, headers=HEADERS
    ).json()
    assert "results_possibly_archived" not in findings["partial_reasons"]
    old_findings = TestClient(api.app).get(
        "/cybercover/findings", params={"analysis_id": full_id}, headers=HEADERS
    ).json()
    assert "results_possibly_archived" in old_findings["partial_reasons"]

    # With the archiver age raised above the full-scan interval (the documented deployment step).
    monkeypatch.setattr(Config.Data.Autoarchiver, "AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING", 40 * 86400)
    assert _posture({"target": "192.0.2.1"}).json()["partial_reasons"] == []


# R2: only a scan that ran the core modules is "full" ----------------------------------------------


@pytest.mark.parametrize(
    "disabled, expected",
    [
        ("port_scanner,bruter,vcs,cybercover_nuclei,cybercover_port_scanner", "custom"),  # Nuclei-only re-test
        ("subdomain_enumeration,cybercover_nuclei", "custom"),
        ("admin_panel_login_bruter,example,cybercover_nuclei,cybercover_port_scanner,bruter", "full"),
        ("port_scanner,nuclei-module,subdomain_enumeration,bruter", "incremental"),
    ],
)
def test_scan_type_requires_the_core_modules_for_a_full_scan(disabled, expected):
    from cybercover_reports.api import scan_type

    assert scan_type({"disabled_modules": disabled}) == expected


def test_narrow_scan_with_stock_nuclei_does_not_become_the_baseline(artemis_db, make_row, monkeypatch):  # noqa: F811
    """Inverted proof R2."""
    from cybercover_reports import api

    only_nuclei = "port_scanner,bruter,vcs,mail_dns_scanner,ssl_checks,cybercover_nuclei,cybercover_port_scanner"
    _insert(artemis_db, make_row, [
        ("full-real", T, "192.0.2.1", FULL),
        ("full-narrow", T + DAY, "192.0.2.1", only_nuclei),
    ], [("full-real", "r1", nuclei_finding("old-cve", "http/cves/2025/CVE-2025-1.yaml"), T)])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {})
    data = _posture({"target": "192.0.2.1"}).json()
    assert data["per_target"][0]["baseline"]["analysis_id"] == "full-real"
    assert [a["scan_type"] for a in data["per_target"][0]["analyses"]] == ["full", "custom"]
    assert [f["curation_key"] for f in data["findings"]] == ["nuclei.old-cve"]


# R3: findings of a partially failed incremental run are kept --------------------------------------


def test_findings_of_a_partially_failed_incremental_run_are_kept(make_row):
    """Inverted proof R3."""
    row = nuclei_rows(make_row, nuclei_finding("confirmed-cve", "http/cves/2026/CVE-2026-9.yaml"),
                      receiver="cybercover_nuclei")[0]
    row["status"] = "ERROR"
    row["status_reason"] = "1 Nuclei runs failed; results may be incomplete"
    result = process_results([row], [])
    assert [r.additional_data["template_id"] for r in result.reports] == ["confirmed-cve"]
    assert result.processing_errors == []
    assert [e["module"] for e in result.module_errors] == ["cybercover_nuclei"]


def test_stock_nuclei_error_row_with_reports_is_still_rejected(make_row):
    row = nuclei_rows(make_row, nuclei_finding("x"), receiver="nuclei-module")[0]
    row["status"] = "ERROR"
    result = process_results([row], [])
    assert result.reports == []
    assert "status ERROR" in result.processing_errors[0]["error"]


# R4: every step of a row is isolated --------------------------------------------------------------


def test_error_after_row_processing_is_isolated(make_row):
    """Inverted proof R4: an artificial severity breaks get_severity for one row only."""
    good = nuclei_rows(make_row, nuclei_finding("good"), row_id="good")
    bad = nuclei_rows(make_row, nuclei_finding("odd", severity="none"), row_id="bad")
    result = process_results(good + bad, [])
    assert [r.original_task_result_id for r in result.reports] == ["good"]
    assert [(e["task_result_id"], e["error"]) for e in result.processing_errors] == [("bad", "KeyError")]


# R5: API surface ----------------------------------------------------------------------------------


def test_docs_require_the_token(artemis_db):  # noqa: F811
    """Inverted proof R5/R6 (proof file: R6)."""
    from cybercover_reports import api

    client = TestClient(api.app)
    for path in ("/openapi.json", "/docs", "/redoc"):
        assert client.get(path).status_code in (401, 404, 422), path
    assert client.get("/openapi.json", headers=HEADERS).json()["info"]["title"] == "Cybercover fast reporter"
    assert client.get("/docs", headers=HEADERS).status_code == 200


def test_posture_target_is_case_insensitive(artemis_db, make_row, monkeypatch):  # noqa: F811
    """Inverted proof R5."""
    from cybercover_reports import api

    _insert(artemis_db, make_row, [("full-1", T, "example.com", FULL)], [])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {})
    response = _posture({"target": " Example.COM "})
    assert response.status_code == 200
    assert response.json()["targets"] == ["example.com"]


def test_raw_exception_text_is_not_returned(make_row, monkeypatch):
    from artemis.reporting.base.reporters import get_all_reporters

    class Leaky:
        @staticmethod
        def create_reports(data, language):
            raise ValueError("secret=hunter2 from the task result")

        @staticmethod
        def get_assets(data):
            return []

        @staticmethod
        def get_alerts(reports):
            return []

    monkeypatch.setattr("cybercover_reports.reporting.get_all_reporters", lambda: get_all_reporters() + [Leaky])
    result = process_results([make_row("mail_dns_scanner", {}, row_id="bad")], [])
    assert result.processing_errors == [{"task_result_id": "bad", "module": "mail_dns_scanner", "error": "ValueError"}]


# R6: the receiver name passed to NucleiReporter --------------------------------------------------


def test_nuclei_reports_use_the_current_receiver_name(make_row, monkeypatch):
    from artemis.reporting.modules.nuclei.reporter import NucleiReporter

    seen = []
    original = NucleiReporter.create_reports

    def spy(data, language):
        seen.append(data["headers"]["receiver"])
        return original(data, language)

    monkeypatch.setattr(NucleiReporter, "create_reports", staticmethod(spy))
    result = process_results(nuclei_rows(make_row, nuclei_finding("x"), receiver="cybercover_nuclei"), [])
    assert result.reports and set(seen) == {"nuclei-module"}


def test_archived_flag_ignores_superseded_incrementals(artemis_db, make_row, monkeypatch):  # noqa: F811
    """Second review, test gap 5: an old incremental scan followed by a newer one does not flag the
    posture as possibly archived; the latest incremental does."""
    from artemis.config import Config
    from cybercover_reports import api

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    # No full scan, so both incrementals are in the posture window.
    _insert(artemis_db, make_row, [
        ("inc-old", now - 11 * DAY, "192.0.2.1", INCREMENTAL),
        ("inc-new", now - DAY, "192.0.2.1", INCREMENTAL),
    ], [])
    monkeypatch.setattr(api, "_pending_tasks", lambda: {})
    monkeypatch.setattr(Config.Data.Autoarchiver, "AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING", 10 * 86400)
    assert _posture({"target": "192.0.2.1"}).json()["partial_reasons"] == ["no_completed_full_scan"]
    # The latest incremental older than the archiver age is flagged.
    monkeypatch.setattr(Config.Data.Autoarchiver, "AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING", 12 * 3600)
    assert _posture({"target": "192.0.2.1"}).json()["partial_reasons"] == [
        "no_completed_full_scan", "results_possibly_archived"
    ]
