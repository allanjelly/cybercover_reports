from collections.abc import Iterator
from typing import Any

from sqlalchemy import select

from artemis.db import DB, TaskResult


def load_results(db: DB, analysis_id: str) -> Iterator[dict[str, Any]]:
    statement = (
        select(TaskResult)
        .where(TaskResult.analysis_id == analysis_id)
        .order_by(TaskResult.created_at, TaskResult.id)
    )
    with db._engine.connect() as connection:
        with connection.execution_options(stream_results=True).execute(statement) as result:
            for row in result:
                yield dict(row._mapping)
