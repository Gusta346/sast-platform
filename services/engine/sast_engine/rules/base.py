"""Abstrações compartilhadas pelas regras AST."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod

from ..models import Finding, Severity


class BaseRule(ABC):
    """Contrato para uma regra de análise."""

    rule_id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity

    def finding(
        self,
        node: ast.AST,
        filename: str,
        source_lines: list[str],
        description: str,
        remediation: str,
    ) -> Finding:
        """Cria um finding usando a posição do nó."""
        line = getattr(node, "lineno", 1)
        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
        return Finding(
            rule_id=self.rule_id,
            titulo=self.title,
            severidade=self.severity,
            arquivo=filename,
            linha=line,
            trecho=snippet,
            cwe=self.cwe,
            owasp=self.owasp,
            descricao=description,
            remediacao=remediation,
        )

    @abstractmethod
    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        """Executa a regra sobre uma árvore AST."""
