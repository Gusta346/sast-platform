"""Regra para algoritmos criptográficos fracos."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class WeakCryptoRule(BaseRule):
    """Detecta hashlib.md5 e hashlib.sha1."""

    rule_id = "weak_crypto"
    title = "Criptografia fraca"
    cwe = "CWE-327"
    owasp = "A02:2021 - Cryptographic Failures"
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        return [
            self.finding(
                node,
                filename,
                lines,
                "O algoritmo criptográfico não é adequado para proteger senhas ou dados sensíveis.",
                "Use um algoritmo moderno e apropriado ao caso, como Argon2 ou SHA-256 para integridade.",
            )
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _dotted_name(node.func) in {"hashlib.md5", "hashlib.sha1"}
        ]


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
