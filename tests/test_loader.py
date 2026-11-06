import json
from types import SimpleNamespace

from sqlalchemy import create_engine

from cybercover_reports.loader import load_results


def test_query_filters_and_orders_results_per_analysis(make_row):
    engine = create_engine("sqlite://")
    one = make_row("mail_dns_scanner", {}, row_id="a")
    other = make_row("mail_dns_scanner", {}, row_id="b")
    other["analysis_id"] = "other"
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """CREATE TABLE task_result (
              id TEXT, analysis_id TEXT, created_at DATETIME, status TEXT, tag TEXT,
              receiver TEXT, target_string TEXT, status_reason TEXT, headers_string TEXT,
              logs TEXT, task JSON, result JSON, additional_info JSON, fulltext TEXT
            )"""
        )
        for row in (other, one):
            conn.exec_driver_sql(
                """INSERT INTO task_result
                   (id, analysis_id, created_at, status, receiver, target_string, task, result)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["id"], row["analysis_id"], row["created_at"].isoformat(" "),
                 row["status"], row["receiver"], row["target_string"],
                 json.dumps(row["task"]), json.dumps(row["result"])),
            )
    results = list(load_results(SimpleNamespace(_engine=engine), one["analysis_id"]))
    assert [row["id"] for row in results] == ["a"]
    assert results[0]["task"]["headers"]["receiver"] == "mail_dns_scanner"
