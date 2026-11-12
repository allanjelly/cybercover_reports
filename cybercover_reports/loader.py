from collections.abc import Iterator
from typing import Any, Optional

from sqlalchemy import select

from artemis.db import DB, Analysis, TaskResult


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


def load_analyses(db: DB, targets: list[str], tag: Optional[str] = None) -> list[dict[str, Any]]:
    """Analyses of the given targets (as entered in /api/add), oldest first."""
    statement = select(
        Analysis.id, Analysis.created_at, Analysis.target, Analysis.tag, Analysis.stopped, Analysis.disabled_modules
    ).where(Analysis.target.in_(targets))
    if tag is not None:
        statement = statement.where(Analysis.tag == tag)
    statement = statement.order_by(Analysis.created_at, Analysis.id)
    with db._engine.connect() as connection:
        return [dict(row._mapping) for row in connection.execute(statement)]
