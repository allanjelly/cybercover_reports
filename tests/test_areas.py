"""The five areas of the portal's cyber shield: domain, network, passwords, applications, files."""

import copy

import pytest

from cybercover_reports.catalog import AREAS, enrich, load_catalog, nuclei_area, validate_catalog
from cybercover_reports.reporting import process_results
from test_phase2 import nuclei_finding, nuclei_rows


def _areas(catalog):
    found = {f"report_types:{k}": v["area"] for k, v in catalog["report_types"].items()}
    found.update({f"nuclei_classes:{v['key']}": v["area"] for v in catalog["nuclei_classes"]})
    found.update({f"by_severity:{k}": v["area"] for k, v in catalog["by_severity"].items()})
    found["generic"] = catalog["generic"]["area"]
    return found


def test_every_catalog_entry_uses_one_of_the_five_areas():
    areas = _areas(load_catalog())
    assert set(areas.values()) == set(AREAS)
    assert AREAS == ("domain", "network", "passwords", "applications", "files")


@pytest.mark.parametrize(
    "key, area",
    [
        ("report_types:misconfigured_email", "domain"),
        ("report_types:expired_ssl_certificate", "domain"),
        ("report_types:heartbleed", "domain"),
        ("report_types:subdomain_takeover_possible", "domain"),
        ("report_types:open_port_remote_desktop", "network"),
        ("report_types:forti_vuln", "network"),
        ("report_types:exposed_ssh_with_easy_password", "passwords"),
        ("report_types:exposed_password_file", "passwords"),
        ("report_types:exposed_keys", "passwords"),
        ("report_types:exposed_version_control_folder_with_credentials", "passwords"),
        ("report_types:exposed_archive", "files"),
        ("report_types:exposed_sql_dump", "files"),
        ("report_types:directory_index", "files"),
        ("report_types:old_wordpress", "applications"),
        ("report_types:nuclei_exposed_panel", "applications"),
        ("nuclei_classes:default_login", "passwords"),
        ("nuclei_classes:exposed_secrets", "passwords"),
        ("nuclei_classes:exposed_backup", "files"),
        ("nuclei_classes:certificate_problem", "domain"),
        ("nuclei_classes:known_vulnerability", "applications"),
        ("generic", "applications"),
    ],
)
def test_catalog_areas(key, area):
    assert _areas(load_catalog())[key] == area


def test_credential_files_have_their_own_text():
    catalog = load_catalog()
    assert catalog["report_types"]["exposed_password_file"]["title"] != catalog["report_types"]["exposed_archive"]["title"]


def test_unknown_area_is_rejected():
    catalog = copy.deepcopy(load_catalog())
    catalog["report_types"]["old_wordpress"]["area"] = "website"
    with pytest.raises(ValueError, match="area"):
        validate_catalog(catalog)


@pytest.mark.parametrize(
    "path, tags, class_area, expected",
    [
        ("network/cves/2026/CVE-2026-1.yaml", [], "applications", "network"),  # e.g. an OpenSSH CVE
        ("javascript/cves/2026/x.yaml", [], None, "network"),
        ("code/cves/2026/sshole.yaml", ["ssh", "network"], "applications", "network"),
        ("dns/x.yaml", [], None, "domain"),
        ("ssl/weak-cipher.yaml", [], None, "domain"),
        ("http/cves/2026/x.yaml", [], "applications", "applications"),
        ("http/cves/2026/x.yaml", [], None, "applications"),
        ("network/default-logins/ftp-anonymous.yaml", [], "passwords", "passwords"),  # kind wins
        ("network/backups/x.yaml", [], "files", "files"),
        ("custom:new-template", [], None, "applications"),
        (None, ["network"], None, "network"),
    ],
)
def test_nuclei_area(path, tags, class_area, expected):
    assert nuclei_area(path, tags, class_area) == expected


def _finding(make_row, template_id, path, severity="high", tags=None):
    row = nuclei_rows(make_row, nuclei_finding(template_id, path, severity=severity, tags=tags))
    reports = process_results(row, []).reports
    assert len(reports) == 1
    return enrich(reports[0], load_catalog())


def test_network_cve_gets_the_network_area(make_row):
    entry = _finding(make_row, "openssh-cve", "network/cves/2026/CVE-2026-123158.yaml", tags=["cve", "ssh"])
    assert entry["catalog"] in ("class", "severity") and entry["area"] == "network"


def test_default_login_is_passwords_on_any_protocol(make_row):
    entry = _finding(make_row, "ftp-default", "network/default-logins/ftp/ftp-default.yaml", tags=["default-login"])
    assert entry["catalog_class"] == "default_login" and entry["area"] == "passwords"


def test_web_finding_without_class_is_applications(make_row):
    entry = _finding(make_row, "odd-web", "http/miscellaneous/odd.yaml", tags=["misc"])
    assert entry["area"] == "applications"
