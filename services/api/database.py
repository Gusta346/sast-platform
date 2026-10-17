"""Configuração de conexão e sessões SQLAlchemy."""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Base declarativa dos modelos da API."""


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sast.db")

if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    if DATABASE_URL in {"sqlite://", "sqlite:///:memory:"}:
        engine = create_engine(
            DATABASE_URL,
            connect_args=connect_args,
            poolclass=StaticPool,
        )
    else:
        engine = create_engine(DATABASE_URL, connect_args=connect_args)
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    """Fornece uma sessão e garante seu fechamento."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def create_tables() -> None:
    """Cria as tabelas necessárias caso ainda não existam."""
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    migrate_schema()


def migrate_schema() -> None:
    """Adiciona colunas novas sem exigir migrações manuais."""
    columns = (
        ("scans", "celery_task_id", "VARCHAR(255)"),
        ("scans", "ia_pendente", "BOOLEAN DEFAULT FALSE"),
        ("findings", "ia_origem", "VARCHAR(20) DEFAULT 'fallback'"),
    )
    with engine.begin() as connection:
        inspector = inspect(connection)
        supports_if_not_exists = connection.dialect.name == "postgresql"
        for table, column, column_type in columns:
            if column not in {item["name"] for item in inspector.get_columns(table)}:
                clause = " IF NOT EXISTS" if supports_if_not_exists else ""
                connection.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN{clause} {column} {column_type}")
                )
            if table == "scans" and column == "ia_pendente":
                connection.execute(
                    text("UPDATE scans SET ia_pendente = FALSE WHERE ia_pendente IS NULL")
                )
