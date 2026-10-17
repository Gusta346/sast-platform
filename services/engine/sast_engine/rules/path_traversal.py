"""Regra para acesso a caminhos controlados pelo usuário."""

import ast

from ..models import Finding, Severity
from .base import BaseRule


class PathTraversalRule(BaseRule):
    """Detecta APIs de arquivo com caminhos não constantes."""

    rule_id = "path_traversal"
    title = "Path traversal"
    cwe = "CWE-22"
    owasp = "A01:2021 - Broken Access Control"
    severity = Severity.HIGH

    def check(self, tree: ast.AST, filename: str, source: str) -> list[Finding]:
        lines = source.splitlines()
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted_name(node.func)
            vulnerable = (
                name in {"open", "send_file"}
                and bool(node.args)
                and not _constant(node.args[0])
            ) or (
                name in {"read_text", "read_bytes", "open"}
                and isinstance(node.func, ast.Attribute)
                and _path_constructor_is_dynamic(node.func.value)
            ) or (
                name == "os.path.join"
                and any(not _constant(argument) for argument in node.args)
            )
            if vulnerable:
                findings.append(
                    self.finding(
                        node,
                        filename,
                        lines,
                        "Um caminho de arquivo pode ser controlado sem validação suficiente.",
                        "Restrinja o caminho a um diretório permitido e normalize/valide o resultado.",
                    )
                )
        return findings


def _constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _path_constructor_is_dynamic(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and _dotted_name(node.func) == "Path"
        and bool(node.args)
        and not _constant(node.args[0])
    ) or not _constant(node)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
