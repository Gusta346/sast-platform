"""Schemas públicos da API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, field_serializer


class ScanResponse(BaseModel):
    """Resposta resumida de uma análise."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    nome: str
    status: str
    celery_task_id: str | None
    ia_pendente: bool
    criado_em: datetime

    @field_serializer("criado_em")
    def serialize_criado_em(self, value: datetime) -> str:
        """Serializa a data em UTC no formato ISO 8601 com sufixo Z."""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class FindingResponse(BaseModel):
    """Resposta de um finding persistido."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: str
    rule_id: str
    titulo: str
    severidade: str
    arquivo: str
    linha: int
    trecho: str
    cwe: str
    owasp: str
    descricao: str
    remediacao: str
    ferramentas: str
    falso_positivo: bool
    remediacao_ia: str | None
    severidade_ia: str | None
    ia_origem: str


def model_dump(value: Any) -> dict[str, Any]:
    """Converte um modelo SQLAlchemy para o schema público."""
    return value.model_dump() if hasattr(value, "model_dump") else dict(value)
