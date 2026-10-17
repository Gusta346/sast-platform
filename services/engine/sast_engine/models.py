"""Modelos de dados do motor SAST."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Níveis de severidade aceitos pelo contrato de findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Finding:
    """Representa um achado de segurança."""

    rule_id: str
    titulo: str
    severidade: Severity
    arquivo: str
    linha: int
    trecho: str
    cwe: str
    owasp: str
    descricao: str
    remediacao: str
    ferramentas: tuple[str, ...] = field(default_factory=lambda: ("ast",))
    ia_origem: str = "fallback"
