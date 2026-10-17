"""Regra para segredos literais no código."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class HardcodedSecretRule(BaseRule):
    """Detecta constantes de segredo com valor literal."""

    rule_id = "hardcoded_secret"
    title = "Segredo hardcoded"
    cwe = "CWE-798"
    owasp = "A07:2021 - Identification and Authentication Failures"
    severity = Severity.HIGH
    _keywords = ("password", "passwd", "secret", "token", "api_key", "key")

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or not value.value:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and any(
                    keyword in target.id.lower() for keyword in self._keywords
                ):
                    findings.append(
                        self.finding(
                            node,
                            filename,
                            lines,
                            "Uma constante com nome de segredo contém um valor literal não vazio.",
                            "Use uma variável de ambiente ou um gerenciador de segredos.",
                        )
                    )
        return findings
