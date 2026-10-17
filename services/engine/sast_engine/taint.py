"""Análise intraprocedural de fluxo de dados tainted."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .models import Finding, Severity


@dataclass(frozen=True)
class Taint:
    """Valor tainted e suas linhas de origem."""

    source_lines: frozenset[int]


class TaintAnalyzer:
    """Detecta fluxo de entradas não confiáveis até sinks perigosos."""

    _source_attributes = {
        ("request", "args"),
        ("request", "form"),
        ("request", "json"),
        ("request", "values"),
        ("request", "cookies"),
        ("request", "headers"),
        ("sys", "argv"),
        ("os", "environ"),
    }
    _sanitizer_names = {"int", "float", "html.escape", "shlex.quote", "secure_filename"}
    _sink_rules = {
        "sql": ("TAINT-001", "CWE-89", Severity.HIGH, "SQL injection"),
        "command": ("TAINT-002", "CWE-78", Severity.CRITICAL, "Command injection"),
        "code": ("TAINT-003", "CWE-95", Severity.CRITICAL, "Execução de código"),
        "file": ("TAINT-004", "CWE-22", Severity.HIGH, "Acesso a arquivo tainted"),
        "pickle": ("TAINT-005", "CWE-502", Severity.CRITICAL, "Desserialização insegura"),
    }

    def analyze(self, source: str, filename: str = "<string>") -> list[Finding]:
        """Analisa cada função do módulo de forma intraprocedural."""
        tree = ast.parse(source)
        lines = source.splitlines()
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        findings: list[Finding] = []
        for function in functions:
            findings.extend(self._analyze_function(function, filename, lines))
        return _unique_findings(findings)

    def _analyze_function(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        filename: str,
        lines: list[str],
    ) -> list[Finding]:
        state: dict[str, Taint] = {}
        findings: list[Finding] = []
        for statement in function.body:
            self._visit_statement(statement, state, findings, filename, lines)
        return findings

    def _visit_statement(
        self,
        statement: ast.stmt,
        state: dict[str, Taint],
        findings: list[Finding],
        filename: str,
        lines: list[str],
    ) -> None:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            taint = self._expression_taint(value, state) if value else None
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                self._assign(target, taint, state)
            self._check_expression(value, state, findings, filename, lines) if value else None
            return
        if isinstance(statement, ast.AugAssign):
            taint = self._expression_taint(statement.value, state)
            if isinstance(statement.target, ast.Name):
                old = state.get(statement.target.id)
                if old and taint:
                    taint = Taint(old.source_lines | taint.source_lines)
                state[statement.target.id] = taint or old
            self._check_expression(statement.value, state, findings, filename, lines)
            return
        if isinstance(statement, ast.Expr):
            self._check_expression(statement.value, state, findings, filename, lines)
            return
        if isinstance(statement, ast.Return):
            if statement.value:
                self._check_expression(statement.value, state, findings, filename, lines)
            return
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.stmt):
                self._visit_statement(child, state, findings, filename, lines)
            elif isinstance(child, ast.expr):
                self._check_expression(child, state, findings, filename, lines)

    def _assign(self, target: ast.AST, taint: Taint | None, state: dict[str, Taint]) -> None:
        if isinstance(target, ast.Name):
            if taint:
                state[target.id] = taint
            else:
                state.pop(target.id, None)

    def _check_expression(
        self,
        expression: ast.AST,
        state: dict[str, Taint],
        findings: list[Finding],
        filename: str,
        lines: list[str],
    ) -> None:
        for node in ast.walk(expression):
            if isinstance(node, ast.Call):
                self._check_call(node, state, findings, filename, lines)

    def _expression_taint(self, node: ast.AST | None, state: dict[str, Taint]) -> Taint | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, ast.Constant):
            return None
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.BoolOp, ast.Tuple, ast.List, ast.Set, ast.Dict)):
            taints = [self._expression_taint(child, state) for child in ast.iter_child_nodes(node)]
            return _combine(taints)
        if isinstance(node, ast.Attribute):
            if _dotted_name(node) in {"request.json", "request.args", "request.form", "request.values", "request.cookies", "request.headers", "sys.argv", "os.environ"}:
                return Taint(frozenset({node.lineno}))
            return self._expression_taint(node.value, state)
        if isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            if name in self._sanitizer_names or name.endswith(".escape") or name.endswith(".quote"):
                return None
            if name in {"request.get_data", "request.get_json"}:
                return Taint(frozenset({node.lineno}))
            if name == "input":
                return Taint(frozenset({node.lineno}))
            receiver = self._expression_taint(node.func.value, state) if isinstance(node.func, ast.Attribute) else None
            return _combine([receiver, *[self._expression_taint(argument, state) for argument in node.args], *[self._expression_taint(keyword.value, state) for keyword in node.keywords]])
        return _combine([self._expression_taint(child, state) for child in ast.iter_child_nodes(node)])

    def _check_call(
        self,
        node: ast.Call,
        state: dict[str, Taint],
        findings: list[Finding],
        filename: str,
        lines: list[str],
    ) -> None:
        sink = self._sink_kind(node)
        if sink is None:
            return
        if sink == "sql" and len(node.args) > 1:
            return
        taints = [self._expression_taint(argument, state) for argument in node.args]
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"read_text", "read_bytes", "open"}
        ):
            taints.append(self._expression_taint(node.func.value, state))
        taint = _combine(taints)
        if not taint:
            return
        rule_id, cwe, severity, title = self._sink_rules[sink]
        source_line = min(taint.source_lines)
        sink_line = getattr(node, "lineno", 1)
        snippet = lines[sink_line - 1].strip() if sink_line <= len(lines) else ""
        findings.append(
            Finding(
                rule_id=rule_id,
                titulo=title,
                severidade=severity,
                arquivo=filename,
                linha=sink_line,
                trecho=snippet,
                cwe=cwe,
                owasp="A03:2021 - Injection" if sink in {"sql", "command", "code"} else "",
                descricao=f"Fluxo tainted detectado: source linha {source_line} -> sink linha {sink_line}.",
                remediacao="Valide e sanitize a entrada antes de utilizá-la no sink.",
            )
        )

    def _sink_kind(self, node: ast.Call) -> str | None:
        name = _dotted_name(node.func)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}:
            return "sql"
        if name == "os.system" or name in {"subprocess.run", "subprocess.Popen", "subprocess.call"}:
            return "command"
        if name in {"eval", "exec"}:
            return "code"
        if name in {"open", "send_file"}:
            return "file"
        if name == "pickle.loads":
            return "pickle"
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "open"}:
            if isinstance(node.func.value, ast.Call) and _dotted_name(node.func.value.func) == "Path":
                return "file"
        return None


def analyze_taint(source: str, filename: str = "<string>") -> list[Finding]:
    """Executa a análise de taint sobre uma fonte Python."""
    return TaintAnalyzer().analyze(source, filename)


def _combine(taints: list[Taint | None]) -> Taint | None:
    lines = frozenset(line for taint in taints if taint for line in taint.source_lines)
    return Taint(lines) if lines else None


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _unique_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        unique[(finding.arquivo, finding.linha, finding.rule_id)] = finding
    return list(unique.values())
