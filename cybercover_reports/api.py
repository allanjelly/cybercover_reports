import dataclasses
import datetime
import json
from functools import lru_cache
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig

from artemis.api import verify_api_token
from artemis.blocklist import load_blocklist
from artemis.config import Config
from artemis.db import DB
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.karton_utils import get_num_pending_tasks

from .catalog import enrich, load_catalog
from .loader import load_results
from .reporting import process_results

app = FastAPI(title="Cybercover fast reporter")


@lru_cache(maxsize=1)
def get_db() -> DB:
    return DB()


@app.get("/cybercover/findings", dependencies=[Depends(verify_api_token)])
def findings(analysis_id: UUID) -> dict:
    analysis_id_str = str(analysis_id)
    db = get_db()
    analysis = db.get_analysis_by_id(analysis_id_str)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    pending_before = get_num_pending_tasks(KartonBackend(config=KartonConfig())).get(analysis_id_str, 0)
    processed = process_results(load_results(db, analysis_id_str), load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE))
    pending_after = get_num_pending_tasks(KartonBackend(config=KartonConfig())).get(analysis_id_str, 0)
    catalog = load_catalog()
    entries = [enrich(report, catalog) for report in processed.reports]
    response = {
        "analysis_id": analysis_id_str,
        "target": analysis["target"],
        "tag": analysis.get("tag"),
        "stopped": analysis.get("stopped", False),
        "pending_tasks": pending_after,
        "results_may_be_partial": bool(
            pending_before or pending_after or analysis.get("stopped") or processed.status_counts.get("ERROR")
        ),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "findings": entries,
        "untranslated": sorted({item["catalog_key"] for item in entries if item["catalog"] == "fallback"}),
        "assets": [dataclasses.asdict(asset) for asset in processed.assets],
        "cached_endpoints": processed.cached_endpoints,
        "scanned_targets": processed.scanned_targets,
        "alerts": processed.alerts,
        "task_status_counts": processed.status_counts,
    }
    return json.loads(json.dumps(response, cls=JSONEncoderAdditionalTypes))
