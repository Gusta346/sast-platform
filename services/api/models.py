"""Modelos persistidos da plataforma SAST."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Scan(Base):
    """Representa uma análise enviada à plataforma."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    nome: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ia_pendente: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    criado_em: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class Finding(Base):
    """Representa um finding associado a uma análise."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(100))
    titulo: Mapped[str] = mapped_column(String(255))
    severidade: Mapped[str] = mapped_column(String(20))
    arquivo: Mapped[str] = mapped_column(String(1024))
    linha: Mapped[int] = mapped_column(Integer)
    trecho: Mapped[str] = mapped_column(Text)
    cwe: Mapped[str] = mapped_column(String(100), default="")
    owasp: Mapped[str] = mapped_column(String(255), default="")
    descricao: Mapped[str] = mapped_column(Text)
    remediacao: Mapped[str] = mapped_column(Text)
    ferramentas: Mapped[str] = mapped_column(String(255), default="")
    falso_positivo: Mapped[bool] = mapped_column(default=False)
    explicacao_ia: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediacao_ia: Mapped[str | None] = mapped_column(Text, nullable=True)
    severidade_ia: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ia_origem: Mapped[str] = mapped_column(String(20), default="fallback")
    scan: Mapped[Scan] = relationship(back_populates="findings")
