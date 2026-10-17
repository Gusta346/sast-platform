"""Schemas públicos da API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ScanResponse(BaseModel):
    """Resposta resumida de uma análise."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    nome: str
    status: str
    criado_em: datetime


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
