"""Configuração de conexão e sessões SQLAlchemy."""

from __future__ import annotations

import os
import re
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Base declarativa dos modelos da API."""


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sast.db")
MIGRATIONS = [
    ("scans", "celery_task_id", "VARCHAR(255)"),
    ("scans", "ia_pendente", "BOOLEAN DEFAULT FALSE"),
    ("findings", "ia_origem", "VARCHAR(20) DEFAULT 'fallback'"),
]
_IDENTIFIER_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*$")
_ALLOWED_COLUMN_TYPES = frozenset(
    {
        "VARCHAR(20) DEFAULT 'fallback'",
        "VARCHAR(255)",
        "BOOLEAN DEFAULT FALSE",
    }
)

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
    for table, column, column_type in MIGRATIONS:
        _validate_migration(table, column, column_type)

    with engine.begin() as connection:
        preparer = engine.dialect.identifier_preparer
        for table, column, column_type in MIGRATIONS:
            inspector = inspect(engine)
            if column not in {item["name"] for item in inspector.get_columns(table)}:
                quoted_table = preparer.quote(table)
                quoted_column = preparer.quote(column)
                connection.execute(
                    # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text -- DDL com identificadores constantes validados por allowlist; não há entrada do usuário
                    text(
                        f"ALTER TABLE {quoted_table} ADD COLUMN "
                        f"{quoted_column} {column_type}"
                    )
                )
            if table == "scans" and column == "ia_pendente":
                connection.execute(
                    text(
                        "UPDATE scans SET ia_pendente = FALSE "
                        "WHERE ia_pendente IS NULL"
                    )
                )


def _validate_migration(table: str, column: str, column_type: str) -> None:
    """Valida os elementos de uma migração definida no próprio módulo."""
    if not _IDENTIFIER_PATTERN.fullmatch(table):
        raise ValueError(f"Tabela de migração inválida: {table}")
    if not _IDENTIFIER_PATTERN.fullmatch(column):
        raise ValueError(f"Coluna de migração inválida: {column}")
    if column_type not in _ALLOWED_COLUMN_TYPES:
        raise ValueError(f"Tipo de coluna de migração inválido: {column_type}")
