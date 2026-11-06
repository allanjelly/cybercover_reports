# Cybercover fast reporter

An independent JSON API for Artemis results, using Artemis reporters, blocklist and
deduplication without running its export job or generating a ZIP. It supports both
standard and Cybercover incremental scans. It does not modify Artemis or its autoreporter.

## Deployment

This version uses Artemis internals and has been developed against Artemis commit
`0adbc0c`. Use a matching Artemis image and run the tests when upgrading it.
The image must provide Artemis, FastAPI, PyYAML and its usual dependencies.

Clone this repository as `cybercover_reports` beside Artemis's compose file, or
set `CYBERCOVER_REPORTS_DIR` to the clone path. From the Artemis directory, check
and apply the patch:

```sh
patch --dry-run -p0 < cybercover_reports/artemis-docker-compose.patch
patch -p0 < cybercover_reports/artemis-docker-compose.patch
./scripts/start --mode=development
```

For production, use `./scripts/start --mode=production` instead. The startup
script stops and restarts the Artemis stack; development mode also rebuilds the
image and generates `docker-compose.dev.yaml` from the patched compose file.
If the dry run fails, do not apply the patch blindly: add the `cybercover-reports`
service manually under `services` without replacing existing local changes.

The service uses the same `.env`, PostgreSQL, Redis and `API_TOKEN` as Artemis.
In its container it listens on port 5000, separately from Artemis web. On the host
it defaults to `127.0.0.1:5001`, so a remote portal cannot reach it directly.
`CYBERCOVER_REPORTS_BIND` in `.env` controls the host bind address. Set it to
`0.0.0.0` only when explicitly exposing the service, and restrict access at the
network firewall. When a VPN is available, set it to the server's VPN interface
address. Recreate the service to apply changes to the host binding.

The service itself uses HTTP, not HTTPS. Its token and response are unencrypted
unless the connection uses a VPN or HTTPS reverse proxy. For internet access,
prefer an HTTPS reverse proxy forwarding `/cybercover/findings` to
`http://127.0.0.1:5001`. Keep Artemis API access protected in the same way.
Docker-published ports can bypass host firewall rules such as ordinary UFW rules;
verify effective restrictions from an external host. The token grants access to
all analyses; the portal must authorize each client against its own analysis IDs.
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

## Response

`findings` contain `id`, `severity` (Artemis high/medium/low), `area`, `asset`,
`title`, `description`, `business_risk`, `recommendation`, `catalog`, `catalog_key`
and `technical`. The technical data, assets, and alerts are intended for the portal
and operators, not automatically for customers. Only known catalog entries are
curated; an unknown type or Nuclei template gets a clearly marked generic fallback
and its key appears in `untranslated`. Review catalog texts before presenting them
to customers. The initial Polish catalog covers a subset of report types, not all.
Add reviewed entries under `report_types` or `nuclei` in `catalog/pl.yaml`.
Nuclei entries use the Nuclei `template-id`. No LLM is called by the service.

`assets` are inventory observations. `cached_endpoints` are replayed port-scan
state, not fresh findings or proof that a port is currently open. `task_status_counts`
includes errors. `pending_tasks` follows Artemis' queue count, and
`results_may_be_partial` is true if tasks were pending during processing, the analysis
was stopped, or an ERROR result was seen. This is a snapshot, not a transactional
completion guarantee; zero pending tasks is not proof of a successful or complete scan.

Report identities are hashes of the top-level target and Artemis normal form, not
globally unique customer IDs. Scope them by customer in the portal. Artemis'
Nuclei normal form groups by hostname and template and may merge different ports
or paths. We normalize ungrouped Nuclei template identity to `template-id` for
deduplication within one analysis, after applying Artemis filtering; Artemis template
groups retain their group identity. Scan types and time are not
encoded in the ID. An absent finding, especially in an incremental scan, does not
prove it was fixed. The portal manages finding lifecycle.

Nuclei reports use Artemis' English extraction to avoid failing on new templates
without a Polish Artemis translation; Polish business text comes from the YAML catalog.
Other reporters use `pl_PL`. Stock reporter filtering remains subject to its own
limitations; in particular, an SPF missing-record error with `valid: true` may not
produce a report. A newly discovered Cybercover port result is processed through the
stock port reporter; replayed ports are never presented as new vulnerabilities.

## Tests

Tests require a checkout of the supported Artemis version and its dependencies,
Redis, `/data` writable, and a Karton config, as for Artemis modules. Example:

```sh
KARTON_CONFIG_FILE=/path/to/karton.ini \
PYTHONPATH=.:/path/to/Artemis \
NUCLEI_TEMPLATE_GROUPS_FILE=/path/to/Artemis/artemis/modules/data/nuclei_template_groups.json \
python -m pytest -q
```

Set the normal Artemis database, Redis and API configuration environment variables.
Tests mock the database and queue at the API boundary, but exercise the actual
Artemis reporter classes and deduplication. Deployment against a live Artemis
instance still requires an end-to-end verification.
