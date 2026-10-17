"""Regra para execução de comandos com shell."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class CommandInjectionRule(BaseRule):
    """Detecta os.system e subprocess com shell=True."""

    rule_id = "command_injection"
    title = "Command injection"
    cwe = "CWE-78"
    owasp = "A03:2021 - Injection"
    severity = Severity.CRITICAL

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted_name(node.func)
            if name == "os.system" or (name.startswith("subprocess.") and _shell_true(node)):
                findings.append(
                    self.finding(
                        node,
                        filename,
                        lines,
                        "Um comando do sistema pode interpretar entrada como shell.",
                        "Evite shell=True e use uma lista de argumentos validada.",
                    )
                )
        return findings


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _shell_true(node: ast.Call) -> bool:
    return any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
