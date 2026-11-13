from fastapi.testclient import TestClient

from artemis.config import Config
from cybercover_reports import api

ANALYSIS_ID = "1497e976-6e7c-459d-80b2-681e1ea8c000"


class FakeDB:
    def get_analysis_by_id(self, analysis_id):
        if analysis_id == ANALYSIS_ID:
            return {"id": analysis_id, "target": "example.test", "tag": None, "stopped": False}
        return None


def setup_api(monkeypatch, rows, pending=None):
    monkeypatch.setattr(Config.Miscellaneous, "API_TOKEN", "test-token")
    monkeypatch.setattr(api, "get_db", lambda: FakeDB())
    monkeypatch.setattr(api, "load_results", lambda db, analysis_id: iter(rows))
    monkeypatch.setattr(api, "KartonBackend", lambda **kwargs: object())
    values = iter(pending or [0, 0])
    monkeypatch.setattr(api, "get_num_pending_tasks", lambda backend: {ANALYSIS_ID: next(values)})
    return TestClient(api.app)


def test_api_auth_validation_and_missing_analysis(monkeypatch):
    client = setup_api(monkeypatch, [])
    assert client.get("/cybercover/findings", params={"analysis_id": ANALYSIS_ID}).status_code in (401, 422)
    assert client.get("/cybercover/findings", params={"analysis_id": ANALYSIS_ID},
                      headers={"X-API-Token": "wrong"}).status_code == 401
    headers = {"X-API-Token": "test-token"}
    assert client.get("/cybercover/findings", params={"analysis_id": "invalid"}, headers=headers).status_code == 422
    assert client.get("/cybercover/findings",
                      params={"analysis_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
                      headers=headers).status_code == 404


def test_api_returns_enriched_data_and_partial_status(monkeypatch, make_row):
    row = make_row("cybercover_port_scanner",
                   {"192.0.2.1": {"3389": {"service": "rdp", "ssl": False, "version": "N/A"}}},
                   task_type="ip", payload={"ip": "192.0.2.1", "last_domain": "example.test"})
    client = setup_api(monkeypatch, [row], [1, 0])
    response = client.get("/cybercover/findings", params={"analysis_id": ANALYSIS_ID},
                          headers={"X-API-Token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["analysis_id"] == ANALYSIS_ID
    assert data["results_may_be_partial"] is True
    assert data["pending_tasks"] == 0
    assert data["task_status_counts"] == {"INTERESTING": 1}
    assert data["findings"][0]["title"] == "Dostęp zdalny widoczny w internecie"
    assert set(data["findings"][0]["technical"]) == {
        "report_type", "additional_data", "is_suspicious", "original_task_result_id"
    }
    assert not {"summary", "assets", "cached_endpoints"} & set(data)


def test_api_errors_are_not_successful_completion(monkeypatch, make_row):
    client = setup_api(monkeypatch, [make_row("cybercover_port_scanner", None, status="ERROR")])
    data = client.get("/cybercover/findings", params={"analysis_id": ANALYSIS_ID},
                      headers={"X-API-Token": "test-token"}).json()
    assert data["results_may_be_partial"] is True
    assert data["task_status_counts"]["ERROR"] == 1


def test_real_loader_with_api_isolates_analysis(monkeypatch, make_row):
    import json
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """CREATE TABLE task_result (
              id TEXT, analysis_id TEXT, created_at DATETIME, status TEXT, tag TEXT,
              receiver TEXT, target_string TEXT, status_reason TEXT, headers_string TEXT,
              logs TEXT, task JSON, result JSON, additional_info JSON, fulltext TEXT
            )"""
        )
        for analysis_id, row_id in [(ANALYSIS_ID, "correct"), ("other", "other")]:
            row = make_row("cybercover_port_scanner",
                           {"192.0.2.1": {"3389": {"service": "rdp", "ssl": False, "version": "N/A"}}},
                           task_type="ip", row_id=row_id,
                           payload={"ip": "192.0.2.1", "last_domain": "example.test"})
            conn.exec_driver_sql(
                """INSERT INTO task_result
                   (id, analysis_id, created_at, status, receiver, target_string, task, result)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["id"], analysis_id, row["created_at"].isoformat(" "), row["status"],
                 row["receiver"], row["target_string"], json.dumps(row["task"]), json.dumps(row["result"])),
            )
    db = FakeDB()
    db._engine = engine
    monkeypatch.setattr(Config.Miscellaneous, "API_TOKEN", "test-token")
    monkeypatch.setattr(api, "get_db", lambda: db)
    monkeypatch.setattr(api, "KartonBackend", lambda **kwargs: object())
    monkeypatch.setattr(api, "get_num_pending_tasks", lambda backend: {})
    response = TestClient(api.app).get("/cybercover/findings", params={"analysis_id": ANALYSIS_ID},
                                       headers={"X-API-Token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["task_status_counts"] == {"INTERESTING": 1}
    assert len(data["findings"]) == 1  # the row of the other analysis is not included
    assert data["findings"][0]["technical"]["original_task_result_id"] == "correct"
