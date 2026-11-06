import copy

import pytest

from artemis.blocklist import BlocklistItem, BlocklistMode

from cybercover_reports.catalog import enrich, load_catalog
from cybercover_reports.reporting import process_results


def finding(template="http/cves/2023/CVE-2023-0001.yaml"):
    return {
        "template-id": "CVE-2023-0001",
        "template": template,
        "info": {
            "name": "Example vulnerability",
            "severity": "critical",
            "description": "A description not present in the Polish Artemis catalog.",
        },
        "matched-at": "http://192.0.2.1:5000/",
    }


def nuclei_row(make_row, receiver, vulnerability, row_id="nuclei"):
    return make_row(
        receiver, [vulnerability], row_id=row_id, task_type="nuclei_target",
        payload={"host": "192.0.2.1", "port": 5000, "ssl": False},
    )


def test_standard_and_incremental_nuclei_are_deduplicated(make_row):
    normal = finding()
    custom = copy.deepcopy(normal)
    del custom["template"]
    custom["template-path"] = "/tmp/cybercover-nuclei-abcdef/http/cves/2023/CVE-2023-0001.yaml"
    rows = [nuclei_row(make_row, "nuclei-module", normal),
            nuclei_row(make_row, "cybercover_nuclei", custom, "incremental")]
    result = process_results(rows, [])
    assert len(result.reports) == 1
    report = result.reports[0]
    assert report.additional_data["template_id"] == "CVE-2023-0001"
    assert report.severity.value == "high"
    entry = enrich(report, load_catalog())
    assert entry["catalog"] == "fallback"
    assert entry["catalog_key"] == "nuclei:CVE-2023-0001"
    assert entry["business_risk"]
    assert entry["id"] == enrich(report, load_catalog())["id"]


def test_nuclei_applies_blocklist_before_identity_normalization(make_row):
    row = nuclei_row(make_row, "cybercover_nuclei", finding())
    blocklist = [BlocklistItem(mode=BlocklistMode.BLOCK_REPORTING_ONLY,
                               nuclei_template_names=["http/cves/2023/CVE-2023-0001.yaml"])]
    assert process_results([row], blocklist).reports == []


def test_nuclei_custom_path_preserves_technology_filter(make_row):
    template = finding()
    del template["template"]
    template["template-path"] = "/tmp/cybercover-nuclei-abcdef/http/technologies/example.yaml"
    result = process_results([nuclei_row(make_row, "cybercover_nuclei", template)], [])
    assert result.reports == []
    assert len(result.assets) == 1


def test_nuclei_stock_template_skip_rules_apply_to_custom_files(make_row, monkeypatch):
    from artemis.config import Config

    template = finding()
    del template["template"]
    template["template-path"] = "/tmp/cybercover-nuclei-abcdef/http/cves/2023/CVE-2023-0001.yaml"
    monkeypatch.setattr(Config.Modules.Nuclei, "NUCLEI_TEMPLATES_TO_SKIP",
                        ["http/cves/2023/CVE-2023-0001.yaml"])
    result = process_results([nuclei_row(make_row, "cybercover_nuclei", template)], [])
    assert not result.reports and not result.assets


@pytest.mark.parametrize("receiver", ["port_scanner", "cybercover_port_scanner"])
def test_discovery_uses_artemis_port_reporter(make_row, receiver):
    ports = {"192.0.2.1": {
        "3389": {"service": "rdp", "ssl": False, "version": "N/A"},
        "5000": {"service": "http", "ssl": False, "version": "uvicorn"},
    }}
    row = make_row(receiver, ports, task_type="ip",
                   payload={"ip": "192.0.2.1", "last_domain": "example.test"})
    result = process_results([row], [])
    assert [str(report.report_type) for report in result.reports] == ["open_port_remote_desktop"]
    assert len([a for a in result.assets if a.asset_type.value == "open_port"]) == 2
    entry = enrich(result.reports[0], load_catalog())
    assert entry["catalog"] == "curated"
    assert entry["area"] == "network"


def test_replay_is_not_a_new_finding(make_row):
    row = make_row("cybercover_port_scanner",
                   {"example.test": {"3389": {"service": "rdp", "ssl": False}}},
                   status="OK")
    result = process_results([row], [])
    assert result.reports == []
    assert result.cached_endpoints == [
        {"host": "example.test", "port": 3389, "service": "rdp", "ssl": False, "source": "replayed"}
    ]


def test_failed_port_scan_is_counted(make_row):
    result = process_results([make_row("cybercover_port_scanner", None, status="ERROR")], [])
    assert result.status_counts == {"ERROR": 1}
    assert not result.reports and not result.cached_endpoints


def test_mail_reporter_and_catalog(make_row):
    error = ("Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
             "to decrease the possibility of successful e-mail message spoofing.")
    mail = {"spf_dmarc_scan_result": {
        "spf": {"valid": True, "record_not_found": True, "errors": ["missing"]},
        "dmarc": {"valid": False, "record_not_found": True, "errors": [error]},
        "base_domain": "example.test",
    }}
    row = make_row("mail_dns_scanner", mail)
    www = make_row("mail_dns_scanner", mail, row_id="www",
                   payload={"domain": "www.example.test", "last_domain": "www.example.test"})
    reports = process_results([row, www], []).reports
    assert len(reports) == 1
    assert reports[0].additional_data["type"] == "DMARC"
    assert enrich(reports[0], load_catalog())["catalog"] == "curated"


def test_noninteresting_result_cannot_create_report(make_row):
    row = nuclei_row(make_row, "nuclei", finding())
    row["status"] = "OK"
    with pytest.raises(ValueError, match="non-interesting"):
        process_results([row], [])
