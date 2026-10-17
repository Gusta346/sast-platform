"""Regra para modo debug em aplicações Flask."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class DebugEnabledRule(BaseRule):
    """Detecta app.run(debug=True)."""

    rule_id = "debug_enabled"
    title = "Debug habilitado"
    cwe = "CWE-489"
    owasp = "A05:2021 - Security Misconfiguration"
    severity = Severity.HIGH

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        return [
            self.finding(
                node,
                filename,
                lines,
                "O servidor da aplicação está sendo iniciado com debug habilitado.",
                "Desabilite debug em ambientes que não sejam desenvolvimento.",
            )
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and _keyword_true(node, "debug")
        ]


def _keyword_true(node: ast.Call, name: str) -> bool:
    return any(keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
