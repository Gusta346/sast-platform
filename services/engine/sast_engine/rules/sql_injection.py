"""Regra para construção insegura de consultas SQL."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class SqlInjectionRule(BaseRule):
    """Detecta argumentos dinâmicos em métodos de execução SQL."""

    rule_id = "sql_injection"
    title = "SQL injection"
    cwe = "CWE-89"
    owasp = "A03:2021 - Injection"
    severity = Severity.HIGH

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        dynamic_names = {
            target.id
            for assignment in ast.walk(tree)
            if isinstance(assignment, ast.Assign)
            and _is_dynamic_sql(assignment.value)
            for target in assignment.targets
            if isinstance(target, ast.Name)
        }
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"execute", "executemany", "executescript"}:
                continue
            if any(_is_dynamic_sql(argument, dynamic_names) for argument in node.args):
                findings.append(
                    self.finding(
                        node,
                        filename,
                        lines,
                        "A consulta SQL é construída com dados ou formatação dinâmica.",
                        "Use queries parametrizadas e nunca concatene entrada do usuário na consulta.",
                    )
                )
        return findings


def _is_dynamic_sql(node: ast.AST, dynamic_names: set[str] | None = None) -> bool:
    dynamic_names = dynamic_names or set()
    if isinstance(node, ast.Name):
        return node.id in dynamic_names or not dynamic_names
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _is_dynamic_sql(node.left, dynamic_names) or _is_dynamic_sql(node.right, dynamic_names)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False
