"""Regra para funções de execução e desserialização perigosas."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class DangerousFunctionsRule(BaseRule):
    """Detecta eval, exec, pickle.loads e yaml.load inseguro."""

    rule_id = "dangerous_functions"
    title = "Função perigosa"
    cwe = "CWE-95/CWE-502"
    owasp = "A03:2021 - Injection"
    severity = Severity.CRITICAL

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = _dotted_name(node.func)
            unsafe = function in {"eval", "exec", "pickle.loads"}
            if function == "yaml.load":
                loader = next((keyword.value for keyword in node.keywords if keyword.arg == "Loader"), None)
                unsafe = not _is_safe_loader(loader)
            if unsafe:
                findings.append(
                    self.finding(
                        node,
                        filename,
                        lines,
                        f"A chamada {function} pode executar código ou desserializar dados não confiáveis.",
                        "Valide a entrada e use APIs seguras; para YAML, use yaml.safe_load ou SafeLoader.",
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


def _is_safe_loader(node: ast.AST | None) -> bool:
    return _dotted_name(node) in {"SafeLoader", "yaml.SafeLoader"}
