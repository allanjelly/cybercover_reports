"""Which Artemis report types have reviewed business texts.

Run in the cybercover-reports container (so the reporters of Artemis-modules-extra are mounted):

    docker compose exec cybercover-reports python3 -m cybercover_reports.coverage
"""

import json
from typing import Any, Optional

from artemis.reporting.base.reporters import get_all_reporters

from .catalog import load_catalog

# Nuclei findings are described per template (catalog `nuclei`) or by class, not by report type.
DESCRIBED_ELSEWHERE = {"nuclei_vulnerability", "nuclei_exposed_panel"}


def artemis_report_types() -> set[str]:
    return {str(report_type) for reporter in get_all_reporters() for report_type in reporter.get_report_types()}


def coverage(catalog: Optional[dict[str, Any]] = None) -> dict[str, list[str]]:
    catalog = catalog or load_catalog()
    known = artemis_report_types()
    curated = set(catalog["report_types"])
    return {
        # Report types that fall back to the severity or generic text.
        "missing": sorted(known - curated - DESCRIBED_ELSEWHERE),
        # Catalog keys that are not report types of any installed reporter (typos or removed types).
        "unknown": sorted(curated - known),
        "covered": sorted(curated & known),
    }


if __name__ == "__main__":
    print(json.dumps(coverage(), indent=2))
