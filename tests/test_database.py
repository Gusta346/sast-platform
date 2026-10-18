import pytest

from services.api import database


def test_migration_rejects_invalid_values(monkeypatch):
    invalid_migrations = [
        ("scans; DROP TABLE findings", "coluna", "VARCHAR(255)"),
        ("scans", "coluna-invalida", "VARCHAR(255)"),
        ("scans", "coluna", "INTEGER"),
    ]

    for migration in invalid_migrations:
        monkeypatch.setattr(database, "MIGRATIONS", [migration])
        with pytest.raises(ValueError):
            database.migrate_schema()


def test_migration_is_idempotent(monkeypatch):
    database.create_tables()
    monkeypatch.setattr(
        database,
        "MIGRATIONS",
        [("scans", "celery_task_id", "VARCHAR(255)")],
    )

    database.migrate_schema()
    database.migrate_schema()
