# Cybercover fast reporter

An independent JSON API for Artemis results, using Artemis reporters, blocklist and
deduplication without running its export job or generating a ZIP. It supports both
standard and Cybercover incremental scans. It does not modify Artemis or its autoreporter.

## Deployment

This version uses Artemis internals and was last verified against Artemis commit
`8a79b34` (`certpl/artemis:latest` of 2026-11-12); see "Upgrading Artemis" below.
The image must provide Artemis, FastAPI, PyYAML and its usual dependencies.

Scans are requested through Artemis' `/api/add`: a monthly full scan with targets only, and daily
incremental scans with `enabled_modules` = `nuclei-router`, `cybercover_port_scanner`,
`cybercover_nuclei` (see the `cybercover_incremental` README). The reporter needs no tags or other
conventions to tell them apart.

Clone this repository as `cybercover_reports` inside the Artemis directory (next
to Artemis' `docker-compose.yaml`) and start Artemis as usual:

```sh
./scripts/start --mode=development   # or --mode=production
```

No Artemis file is modified: Artemis' `scripts/find_docker_compose_files`
automatically includes every `*/docker-compose.yml`, so this repo's
`docker-compose.yml` adds the `cybercover-reports` service (the same mechanism
Artemis-modules-extra uses). Development mode generates `docker-compose.dev.yml`
from it. `CYBERCOVER_REPORTS_DIR` in `.env` can point to a clone elsewhere.

The service mounts the reporters of Artemis-modules-extra (SSL checks, sqlmap,
XSS, ...), which Artemis-modules-extra mounts only into its autoreporter.
Artemis-modules-extra must therefore be cloned in the Artemis directory; keep the
mount list in `docker-compose.yml` in sync with its autoreporter volumes.

The service uses the same `.env`, PostgreSQL, Redis and `API_TOKEN` as Artemis.
Set Artemis' archiver age for non-interesting results above the full-scan interval, e.g. 40 days:
`AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING=3456000`. With Artemis' default (15 days) the module
errors of the baseline full scan are deleted while it is still the baseline, and every posture older
than 15 days is marked `results_possibly_archived`.
In its container it listens on port 5000, separately from Artemis web. On the host
it defaults to `127.0.0.1:5001`, so a remote portal cannot reach it directly.
`CYBERCOVER_REPORTS_BIND` in `.env` controls the host bind address. Set it to
`0.0.0.0` only when explicitly exposing the service, and restrict access at the
network firewall. When a VPN is available, set it to the server's VPN interface
address. Recreate the service to apply changes to the host binding.

The service itself uses HTTP, not HTTPS. Its token and response are unencrypted
unless the connection uses a VPN or HTTPS reverse proxy. For internet access,
prefer an HTTPS reverse proxy forwarding `/cybercover/` (both endpoints) to
`http://127.0.0.1:5001`. Keep Artemis API access protected in the same way.
Docker-published ports can bypass host firewall rules such as ordinary UFW rules;
verify effective restrictions from an external host. The token grants access to
all analyses; the portal must authorize each client against its own analysis IDs and targets.
No database or Redis credentials should be sent to clients.

Check the service after startup using the same mode as `scripts/start`:

```sh
docker compose -f docker-compose.dev.yaml logs --tail=50 cybercover-reports
# Production: docker compose -f docker-compose.yaml logs --tail=50 cybercover-reports
```

```sh
curl -H "X-API-Token: $API_TOKEN" \
  'http://127.0.0.1:5001/cybercover/findings?analysis_id=1497e976-6e7c-459d-80b2-681e1ea8c000'
```

`analysis_id` is the UUID/root UID, not the entire `{root_uid}:task_uid` returned
by `/api/add`. `/api/analyses` maps analysis IDs to targets. The endpoint processes
one analysis at a time; it never mixes results from different analyses. Missing
analyses return 404, malformed IDs 422, and missing or invalid tokens are rejected.

The current posture of a customer's targets (see Endpoints):

```sh
curl -H "X-API-Token: $API_TOKEN" \
  'http://127.0.0.1:5001/cybercover/posture?target=example.com&target=www.example.com'
```

## Endpoints

Both endpoints require the `X-API-Token` header (Artemis' `API_TOKEN`).

- `GET /cybercover/findings?analysis_id=<uuid>` - one analysis (one target of one scan).
- `GET /cybercover/posture?target=<t>[&target=<t2>...][&tag=<tag>]` - the current state of a
  customer's targets (1-50, as entered in `/api/add`): for each target, its latest **completed** full
  scan (the baseline) merged with every later scan (daily incrementals, or a full scan still running),
  deduplicated across scans. Older scans are ignored. Without a completed full scan, all scans of the
  target are used and `partial_reasons` contains `no_completed_full_scan`. Unknown targets: 404.

**Scan type** (`scan_type`) is derived from the modules Artemis stores as disabled for each analysis -
no tagging convention is needed: `full` when the stock `nuclei-module`, `port_scanner` and
`subdomain_enumeration` all ran (the request had targets only), `incremental` when `cybercover_nuclei`
ran instead of `nuclei-module` (`enabled_modules` = `nuclei-router`, `cybercover_port_scanner`,
`cybercover_nuclei`), otherwise `custom`. A narrower analysis, such as a Nuclei-only re-test started
from the Artemis UI, is `custom` and never becomes the posture baseline. Do not put `port_scanner` or
`subdomain_enumeration` into `MODULES_DISABLED_BY_DEFAULT`: no analysis would then count as a full scan,
and every posture would report `no_completed_full_scan`.

Targets are matched case-insensitively (Artemis stores them in lower case). `first_seen` is the first
analysis in the current posture window (the baseline or later) that reported the finding: it restarts
when a new full scan becomes the baseline.

`/docs` and `/openapi.json` also require the `X-API-Token` header, e.g.
`curl -H "X-API-Token: $API_TOKEN" http://127.0.0.1:5001/openapi.json`. In a browser they need an
extension that adds the header.

## Response

`findings` are sorted by severity and contain `id`, `severity` (Artemis high/medium/low), `area`,
`asset`, `title`, `description`, `business_risk`, `recommendation`, `catalog`, `catalog_key`,
`catalog_class` and `technical` (`report_type`, `additional_data` with the reporter's details such as
the template id, tags and matched URL, `is_suspicious`, and `original_task_result_id`: the id of the
raw Artemis task result, for support to look up the request, response and matched data). In the posture response each finding also
has `first_seen` and `last_seen` (analysis id, time, scan type). The technical data and alerts are
intended for the portal and operators, not automatically for customers. Counts by severity or area,
the overall risk and the list of recommendations are left to the portal: they follow directly from
`findings`.

**Business texts** come from `catalog/pl.yaml`, looked up from the most to the least specific; `catalog`
says which level was used:

1. `curated` - a reviewed entry for the Nuclei `template-id` (`nuclei`) or the report type (`report_types`);
2. `class` - for Nuclei findings, the kind of problem (`nuclei_classes`, e.g. `default_login`,
   `exposed_backup`, `known_vulnerability`), matched by template path segments, then tags; the first
   matching class in file order wins, so the most specific classes come first;
3. `severity` - a text chosen by severity only (`by_severity`);
4. `fallback` - the generic text (`generic`).

Keys of all findings below `curated` appear in `untranslated`. Review
catalog texts before presenting them to customers. No LLM is called by the service. To see which Artemis
report types lack a curated text, or catalog keys that are not report types (typos):

```sh
docker compose -f docker-compose.dev.yaml exec cybercover-reports python3 -m cybercover_reports.coverage
# Production: docker compose -f docker-compose.yaml exec cybercover-reports ...
```

Run it after adding catalog entries and after Artemis or Artemis-modules-extra upgrades (new report
types appear under `missing`).

**Areas.** Every finding has one of the five `area` values of the portal's cyber shield (codes; the
portal shows its own labels):

| `area` | What belongs there |
|---|---|
| `domain` | DNS and the domain: zone transfer, domain expiry, dangling records, subdomain takeover, e-mail (SPF/DMARC), certificates and HTTPS/TLS |
| `network` | Network services and open ports: remote desktop, databases, SMB, Telnet, FTP, NTLM, VPN appliances |
| `passwords` | Weak or default passwords, and exposed or leaked credentials (password files, keys, shell history, Git folders with credentials, secrets) |
| `applications` | Websites and web applications: outdated CMS and plugins, known vulnerabilities, injections, admin panels, security headers |
| `files` | Exposed files without credentials: backups, archives, configuration, logs, SQL dumps, directory listings, source code |

Curated entries define their area in `catalog/pl.yaml`; `validate_catalog` accepts only these five.
For Nuclei findings without a curated text, `passwords`, `files` and `domain` classes keep their area
(e.g. a default login is `passwords` on any protocol); otherwise the template decides: `network/` and
`javascript/` templates (or the `network` tag) are `network`, `dns/` and `ssl/` are `domain`, and
everything else is `applications`.

Ports that the incremental scan reused instead of scanning them (`cybercover_port_scanner` replays)
are never reported as findings.

**Completeness.** `results_may_be_partial` is true when `partial_reasons` is not empty:
`pending_tasks`, `stopped`, `processing_errors` (a task result the service could not process - listed in
`processing_errors`, the rest of the report is still produced), `essential_module_errors` (an ERROR of a
module that produces most findings: `CYBERCOVER_REPORTS_ESSENTIAL_MODULES`, default
`port_scanner,cybercover_port_scanner,nuclei-router,nuclei-module,cybercover_nuclei`),
`results_possibly_archived` (an analysis is older than Artemis' archiver age for non-interesting
results, `AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING`, so its errors may already have been deleted)
and, for the posture, `no_completed_full_scan`. Errors of other modules are listed in `module_errors` without making
the report partial. Findings saved by `cybercover_nuclei` together with an ERROR status (some Nuclei
runs failed, others succeeded) are reported; the error is listed in `module_errors`.
`processing_errors[].error` gives only the error type; details are in the service log. In the posture, errors of an incremental scan followed by a later incremental scan are
marked `superseded` and do not count: a failed incremental scan does not advance the scan state, so the
next one covers the same templates. `task_status_counts` includes errors. This is a snapshot, not a transactional
completion guarantee; zero pending tasks is not proof of a successful or complete scan.

Report identities are hashes of the top-level target and Artemis normal form, not
globally unique customer IDs. Scope them by customer in the portal. Artemis'
Nuclei normal form groups by hostname and template and may merge different ports
or paths. We normalize ungrouped Nuclei template identity to `template-id` for
deduplication across standard and incremental scans, after applying Artemis filtering; Artemis
template groups retain their group identity. Scan types and time are not
encoded in the ID. An absent finding, especially in an incremental scan, does not
prove it was fixed. The portal manages finding lifecycle.

Nuclei reports use Artemis' English extraction to avoid failing on new templates
without a Polish Artemis translation; Polish business text comes from the YAML catalog.
Other reporters use `pl_PL`. Stock reporter filtering remains subject to its own
limitations (e.g. SSL findings of placeholder pages such as a default "Welcome to nginx" page are
not reported, and an SPF missing-record error with `valid: true` may not produce a report). A newly
discovered Cybercover port result is processed through the stock port reporter; replayed or adopted
ports are never presented as new vulnerabilities.

## Example responses

Generated by the service from sample data (`example.com`, customer tag `client-42`): a full scan on
2 November found a Grafana default login and the Grafana login panel; the incremental scan on
12 November ran a newly published OpenSSH template (critical, shown as Artemis severity `high`) and
reused the ports of the full scan instead of scanning them. Business texts are
the current drafts of `catalog/pl.yaml`.

<details>
<summary><code>GET /cybercover/findings?analysis_id=b3e9d7a2-5c4f-4e8b-8d21-7a6c5b4e3f02</code> (the incremental scan)</summary>

```json
{
  "analysis_id": "b3e9d7a2-5c4f-4e8b-8d21-7a6c5b4e3f02",
  "target": "example.com",
  "tag": "client-42",
  "created_at": "2026-11-12T06:00:00",
  "scan_type": "incremental",
  "stopped": false,
  "pending_tasks": 0,
  "results_may_be_partial": false,
  "partial_reasons": [],
  "generated_at": "2026-11-13T09:58:16.613144+00:00",
  "findings": [
    {
      "id": "62991ece6b029dab59f2ff142ff6f457c061f691b88cf67baf7c3e06a9962ce9",
      "severity": "high",
      "asset": "ssh://example.com:22",
      "catalog_key": "nuclei:CVE-2026-123158",
      "catalog": "class",
      "catalog_class": "known_vulnerability",
      "technical": {
        "report_type": "nuclei_vulnerability",
        "additional_data": {
          "is_url_without_query_fragment": true,
          "hostname": "example.com",
          "path_query_fragment": "",
          "description_en": "sshd in OpenSSH before 10.6p2 with musl libc and no PAM lacks a workaround for a password authentication bypass.",
          "description_translated": "sshd in OpenSSH before 10.6p2 with musl libc and no PAM lacks a workaround for a password authentication bypass.",
          "reference": [],
          "severity": "critical",
          "matched_at": "ssh://example.com:22",
          "template_name": "custom:CVE-2026-123158",
          "original_template_name": "network/cves/2026/CVE-2026-123158.yaml",
          "curl_command": null,
          "template_id": "CVE-2026-123158",
          "template_tags": [
            "cve",
            "kev",
            "network",
            "ssh"
          ],
          "artemis_template_name": "network/cves/2026/CVE-2026-123158.yaml"
        },
        "is_suspicious": false,
        "original_task_result_id": "inc-nuclei"
      },
      "area": "network",
      "title": "Znana podatność w używanym oprogramowaniu",
      "description": "Wykryto oprogramowanie z opisaną publicznie podatnością bezpieczeństwa.",
      "business_risk": "Dla znanych podatności często istnieją gotowe narzędzia, więc atak może być łatwy do przeprowadzenia.",
      "recommendation": "Poproś administratora o aktualizację oprogramowania do wersji z poprawką bezpieczeństwa."
    }
  ],
  "untranslated": [
    "nuclei:CVE-2026-123158"
  ],
  "scanned_targets": [
    "example.com"
  ],
  "alerts": [],
  "task_status_counts": {
    "INTERESTING": 1,
    "OK": 1
  },
  "module_errors": [],
  "processing_errors": []
}
```

</details>

<details>
<summary><code>GET /cybercover/posture?target=example.com</code> (the full scan as baseline, merged with the incremental scan)</summary>

```json
{
  "targets": [
    "example.com"
  ],
  "tag": null,
  "generated_at": "2026-11-13T09:58:16.646510+00:00",
  "per_target": [
    {
      "target": "example.com",
      "found": true,
      "baseline": {
        "analysis_id": "6f1c2a4e-1d2b-4c1a-9a51-2f0e8b7c1a01",
        "target": "example.com",
        "created_at": "2026-11-02T10:00:00",
        "tag": "client-42",
        "scan_type": "full",
        "stopped": false,
        "pending_tasks": 0
      },
      "analyses": [
        {
          "analysis_id": "6f1c2a4e-1d2b-4c1a-9a51-2f0e8b7c1a01",
          "target": "example.com",
          "created_at": "2026-11-02T10:00:00",
          "tag": "client-42",
          "scan_type": "full",
          "stopped": false,
          "pending_tasks": 0
        },
        {
          "analysis_id": "b3e9d7a2-5c4f-4e8b-8d21-7a6c5b4e3f02",
          "target": "example.com",
          "created_at": "2026-11-12T06:00:00",
          "tag": "client-42",
          "scan_type": "incremental",
          "stopped": false,
          "pending_tasks": 0
        }
      ]
    }
  ],
  "results_may_be_partial": false,
  "partial_reasons": [],
  "findings": [
    {
      "id": "62991ece6b029dab59f2ff142ff6f457c061f691b88cf67baf7c3e06a9962ce9",
      "severity": "high",
      "asset": "ssh://example.com:22",
      "catalog_key": "nuclei:CVE-2026-123158",
      "catalog": "class",
      "catalog_class": "known_vulnerability",
      "technical": {
        "report_type": "nuclei_vulnerability",
        "additional_data": {
          "is_url_without_query_fragment": true,
          "hostname": "example.com",
          "path_query_fragment": "",
          "description_en": "sshd in OpenSSH before 10.6p2 with musl libc and no PAM lacks a workaround for a password authentication bypass.",
          "description_translated": "sshd in OpenSSH before 10.6p2 with musl libc and no PAM lacks a workaround for a password authentication bypass.",
          "reference": [],
          "severity": "critical",
          "matched_at": "ssh://example.com:22",
          "template_name": "custom:CVE-2026-123158",
          "original_template_name": "network/cves/2026/CVE-2026-123158.yaml",
          "curl_command": null,
          "template_id": "CVE-2026-123158",
          "template_tags": [
            "cve",
            "kev",
            "network",
            "ssh"
          ],
          "artemis_template_name": "network/cves/2026/CVE-2026-123158.yaml"
        },
        "is_suspicious": false,
        "original_task_result_id": "inc-nuclei"
      },
      "area": "network",
      "title": "Znana podatność w używanym oprogramowaniu",
      "description": "Wykryto oprogramowanie z opisaną publicznie podatnością bezpieczeństwa.",
      "business_risk": "Dla znanych podatności często istnieją gotowe narzędzia, więc atak może być łatwy do przeprowadzenia.",
      "recommendation": "Poproś administratora o aktualizację oprogramowania do wersji z poprawką bezpieczeństwa.",
      "first_seen": {
        "analysis_id": "b3e9d7a2-5c4f-4e8b-8d21-7a6c5b4e3f02",
        "target": "example.com",
        "created_at": "2026-11-12T06:00:00",
        "tag": "client-42",
        "scan_type": "incremental",
        "stopped": false,
        "pending_tasks": 0
      },
      "last_seen": {
        "analysis_id": "b3e9d7a2-5c4f-4e8b-8d21-7a6c5b4e3f02",
        "target": "example.com",
        "created_at": "2026-11-12T06:00:00",
        "tag": "client-42",
        "scan_type": "incremental",
        "stopped": false,
        "pending_tasks": 0
      }
    },
    {
      "id": "0c82a6c3fe592541b714952af346407b97f786a820dcca3b4ec584d034004034",
      "severity": "high",
      "asset": "http://example.com:3000",
      "catalog_key": "nuclei:grafana-default-login",
      "catalog": "class",
      "catalog_class": "default_login",
      "technical": {
        "report_type": "nuclei_vulnerability",
        "additional_data": {
          "is_url_without_query_fragment": true,
          "hostname": "example.com",
          "path_query_fragment": "/login",
          "description_en": "Grafana default admin credentials were discovered.",
          "description_translated": "Grafana default admin credentials were discovered.",
          "reference": [],
          "severity": "high",
          "matched_at": "http://example.com:3000/login",
          "template_name": "custom:grafana-default-login",
          "original_template_name": "http/default-logins/grafana/grafana-default-login.yaml",
          "curl_command": null,
          "template_id": "grafana-default-login",
          "template_tags": [
            "default-login",
            "grafana"
          ],
          "artemis_template_name": "http/default-logins/grafana/grafana-default-login.yaml"
        },
        "is_suspicious": false,
        "original_task_result_id": "full-nuclei"
      },
      "area": "passwords",
      "title": "Domyślne hasło dostępu do usługi",
      "description": "Do usługi można zalogować się przy użyciu domyślnej nazwy użytkownika i hasła ustawionych przez producenta.",
      "business_risk": "Domyślne hasła są publicznie znane - każdy może zalogować się i przejąć kontrolę nad usługą.",
      "recommendation": "Niezwłocznie zmień hasło na silne i unikalne oraz ogranicz dostęp do usługi z internetu.",
      "first_seen": {
        "analysis_id": "6f1c2a4e-1d2b-4c1a-9a51-2f0e8b7c1a01",
        "target": "example.com",
        "created_at": "2026-11-02T10:00:00",
        "tag": "client-42",
        "scan_type": "full",
        "stopped": false,
        "pending_tasks": 0
      },
      "last_seen": {
        "analysis_id": "6f1c2a4e-1d2b-4c1a-9a51-2f0e8b7c1a01",
        "target": "example.com",
        "created_at": "2026-11-02T10:00:00",
        "tag": "client-42",
        "scan_type": "full",
        "stopped": false,
        "pending_tasks": 0
      }
    },
    {
      "id": "dd64be2dc0f47813003db73ab9c82202657aae1fa0c118791004f5a3e5162cd9",
      "severity": "low",
      "asset": "http://example.com:3000/login",
      "catalog_key": "nuclei:grafana-detect",
      "catalog": "curated",
      "catalog_class": null,
      "technical": {
        "report_type": "nuclei_exposed_panel",
        "additional_data": {
          "description_en": "Grafana login panel was detected.",
          "description_translated": "Grafana login panel was detected.",
          "matched_at": "http://example.com:3000/login",
          "template_name": "custom:grafana-detect",
          "original_template_name": "http/exposed-panels/grafana-detect.yaml",
          "curl_command": null,
          "template_id": "grafana-detect",
          "template_tags": [
            "grafana",
            "panel"
          ],
          "artemis_template_name": "http/exposed-panels/grafana-detect.yaml"
        },
        "is_suspicious": false,
        "original_task_result_id": "full-nuclei"
      },
      "area": "applications",
      "title": "Panel administracyjny widoczny w internecie",
      "description": "Strona logowania do panelu zarządzania usługą jest dostępna dla każdego z internetu.",
      "business_risk": "Atakujący mogą próbować odgadnąć hasło lub wykorzystać błędy panelu, aby przejąć kontrolę nad usługą.",
      "recommendation": "Poproś administratora o ograniczenie dostępu do panelu (np. tylko z sieci firmowej lub przez VPN) i włączenie silnego uwierzytelniania.",
      "first_seen": {
        "analysis_id": "6f1c2a4e-1d2b-4c1a-9a51-2f0e8b7c1a01",
        "target": "example.com",
        "created_at": "2026-11-02T10:00:00",
        "tag": "client-42",
        "scan_type": "full",
        "stopped": false,
        "pending_tasks": 0
      },
      "last_seen": {
        "analysis_id": "6f1c2a4e-1d2b-4c1a-9a51-2f0e8b7c1a01",
        "target": "example.com",
        "created_at": "2026-11-02T10:00:00",
        "tag": "client-42",
        "scan_type": "full",
        "stopped": false,
        "pending_tasks": 0
      }
    }
  ],
  "untranslated": [
    "nuclei:CVE-2026-123158",
    "nuclei:grafana-default-login"
  ],
  "alerts": [],
  "task_status_counts": {
    "INTERESTING": 2,
    "OK": 1
  },
  "module_errors": [],
  "processing_errors": []
}
```

</details>

## Tests

Tests need Artemis and its dependencies, Redis, PostgreSQL, a writable `/data` and
a Karton config. The script below runs them in the Artemis image with throwaway
Redis/PostgreSQL (`tests/test-stack.compose.yaml`, separate from Artemis' compose
files) and removes them afterwards:

```sh
tests/run_in_docker.sh                        # whole suite
tests/run_in_docker.sh tests/test_api.py -x   # any pytest arguments
```

`ARTEMIS_BUILD_IMAGE` selects the image (default `certpl/artemis:latest`). Artemis-modules-extra
must be cloned next to this repository (its reporters are mounted as in `docker-compose.yml`).
The findings tests mock the database and queue at the API boundary but exercise the actual Artemis
reporter classes and deduplication; the posture tests write analyses and task results to Artemis'
real tables in the throwaway PostgreSQL. The catalog tests check that every catalog key is a report
type of an installed reporter. Deployment against a live Artemis instance still requires an
end-to-end verification.

## Upgrading Artemis

The service imports Artemis internals, so an Artemis upgrade can break it without any Artemis file
having been modified. After pulling a new Artemis version or image (or Artemis-modules-extra):

1. Run the tests against the new image (`ARTEMIS_BUILD_IMAGE=<new image> tests/run_in_docker.sh`).
2. Review the diff since the last verified commit
   (`git diff 8a79b34 -- artemis/reporting artemis/db.py artemis/api.py artemis/karton_utils.py`)
   for these internals:
   - `artemis.reporting.export.db._fill_missing_data` and
     `artemis.reporting.export.deduplication.deduplicate_reports` (the export job's processing, reused
     per analysis);
   - `NucleiReporter`, `PortScannerReporter`, `get_all_reporters`, `Report`, `Asset`, `get_severity`,
     `get_top_level_target`, `blocklist_reports`, `load_blocklist`;
   - `artemis.db.DB` (`get_analysis_by_id`), the `Analysis` (`target`, `tag`, `disabled_modules`,
     `stopped`, `created_at`) and `TaskResult` tables;
   - `artemis.api.verify_api_token`, `artemis.karton_utils.get_num_pending_tasks`.
3. Compare the reporter mounts in `docker-compose.yml` with Artemis-modules-extra's autoreporter
   volumes, then run the coverage tool for new report types.
4. If `MODULES_DISABLED_BY_DEFAULT` or module identities changed, check `scan_type` detection
   (`nuclei-module`, `cybercover_nuclei`) and `CYBERCOVER_REPORTS_ESSENTIAL_MODULES`.
5. Request `/cybercover/findings` for one full and one incremental analysis and `/cybercover/posture`
   for their target, and compare with the Artemis UI.
