import datetime

import pytest


@pytest.fixture
def make_row():
    def make(receiver, result, *, status="INTERESTING", task_type="domain", payload=None, row_id="row-1"):
        payload = payload or {"domain": "example.test", "last_domain": "example.test"}
        task = {
            "headers": {"receiver": receiver, "type": task_type},
            "payload": payload,
            "payload_persistent": {"original_target": "example.test", "original_domain": "example.test"},
        }
        return {
            "id": row_id,
            "analysis_id": "1497e976-6e7c-459d-80b2-681e1ea8c000",
            "task": task,
            "receiver": receiver,
            "status": status,
            "target_string": payload.get("domain", payload.get("host", "example.test")),
            "tag": None,
            "created_at": datetime.datetime(2026, 11, 5, 14, 16, 40),
            "result": result,
        }
    return make
