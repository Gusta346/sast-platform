"""Orquestração das regras internas e ferramentas externas."""

from __future__ import annotations

import json
import fnmatch
import logging
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from collections.abc import Callable, Iterable

from .models import Finding, Severity
from .parser import parse_source
from .rules import ALL_RULES
from .taint import analyze_taint

logger = logging.getLogger(__name__)


class Scanner:
    """Percorre arquivos Python e agrega findings normalizados."""

    def __init__(
        self,
        include_external: bool = True,
        ignore_patterns: Iterable[str] | None = None,
    ) -> None:
        self.include_external = include_external
        self.ignore_patterns = tuple(ignore_patterns or ())
        self.rules = tuple(rule() for rule in ALL_RULES)

    def scan_directory(self, directory: str | Path) -> list[Finding]:
        """Analisa todos os arquivos Python de um diretório."""
        root = Path(directory)
        if not self.ignore_patterns:
            self.ignore_patterns = tuple(_read_ignore_file(root / ".sast-ignore"))
        findings: list[Finding] = []
        python_files = [
            path
            for path in sorted(root.rglob("*.py"))
            if not self._is_ignored(path, root)
        ]
        for path in python_files:
            findings.extend(self.scan_file(path, root))
        if self.include_external:
            findings.extend(self._run_bandit(root))
            findings.extend(self._run_semgrep(root))
        return _deduplicate(findings)

    def scan_file(self, path: str | Path, root: Path | None = None) -> list[Finding]:
        """Analisa um arquivo com as regras internas."""
        file_path = Path(path)
        source = file_path.read_text(encoding="utf-8")
        parsed = parse_source(source)
        filename = str(file_path.relative_to(root)) if root else str(file_path)
        findings = [
            finding
            for rule in self.rules
            for finding in rule.check(parsed.ast_tree, filename, source)
        ]
        findings.extend(analyze_taint(source, filename))
        return findings

    def _run_bandit(self, directory: Path) -> list[Finding]:
        if shutil.which("bandit") is None:
            logger.warning("Bandit não está instalado; análise complementar ignorada.")
            return []
        command = [
            "bandit",
            "-r",
            str(directory),
            "-f",
            "json",
            "-q",
            "--ignore-nosec",
        ]
        if self.ignore_patterns:
            command.extend(["--exclude", ",".join(self.ignore_patterns)])
        return self._run_external(
            command,
            "Bandit",
            lambda payload: _normalize_bandit(payload, directory),
            directory,
        )

    def _run_semgrep(self, directory: Path) -> list[Finding]:
        if shutil.which("semgrep") is None:
            logger.warning("Semgrep não está instalado; análise complementar ignorada.")
            return []
        command = ["semgrep", "--config", "p/python", "--json", "--no-git-ignore"]
        for pattern in self.ignore_patterns:
            command.extend(["--exclude", pattern])
        command.append(str(directory))
        return self._run_external(
            command,
            "Semgrep",
            lambda payload: _normalize_semgrep(payload, directory),
            directory,
            timeout=120,
        )

    def _run_external(
        self,
        command: list[str],
        tool_name: str,
        normalizer: Callable[[dict], list[Finding]],
        directory: Path,
        timeout: int = 60,
    ) -> list[Finding]:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("%s falhou e foi ignorado: %s", tool_name, exc)
            return []
        if not result.stdout.strip():
            if tool_name == "Semgrep":
                logger.warning("Semgrep não retornou resultados: %s", result.stderr.strip())
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Saída JSON inválida do %s: %s", tool_name, exc)
            return []
        return [
            finding
            for finding in normalizer(payload)
            if not self._is_ignored(Path(finding.arquivo), directory)
        ]

    def _is_ignored(self, path: Path, root: Path) -> bool:
        relative = path if not path.is_absolute() else path.relative_to(root)
        normalized = str(relative).replace("\\", "/")
        return any(_matches_ignore(normalized, pattern) for pattern in self.ignore_patterns)


def scan_directory(
    directory: str | Path,
    include_external: bool = True,
    ignore_patterns: Iterable[str] | None = None,
) -> list[Finding]:
    """Analisa um diretório com a configuração padrão."""
    return Scanner(
        include_external=include_external,
        ignore_patterns=ignore_patterns,
    ).scan_directory(directory)


def _normalize_bandit(payload: dict, directory: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        findings.append(
            Finding(
                rule_id=f"bandit_{result.get('test_id', 'unknown')}",
                titulo=result.get("test_name", "Bandit finding"),
                severidade=_severity(result.get("issue_severity")),
                arquivo=_relative_path(result.get("filename", ""), directory),
                linha=int(result.get("line_number", 1)),
                trecho=result.get("code", "").strip(),
                cwe=_normalize_cwe(result.get("issue_cwe")),
                owasp="",
                descricao=result.get("issue_text", ""),
                remediacao="Revise a recomendação da regra Bandit correspondente.",
                ferramentas=("bandit",),
            )
        )
    return findings


def _normalize_semgrep(payload: dict, directory: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(
            Finding(
                rule_id=f"semgrep_{result.get('check_id', 'unknown')}",
                titulo=metadata.get("title", result.get("check_id", "Semgrep finding")),
                severidade=_severity(metadata.get("severity", extra.get("severity"))),
                arquivo=_relative_path(result.get("path", ""), directory),
                linha=int(result.get("start", {}).get("line", 1)),
                trecho=extra.get("lines", "").strip(),
                cwe=_normalize_cwe(metadata.get("cwe")),
                owasp=str(metadata.get("owasp", "")),
                descricao=extra.get("message", ""),
                remediacao=str(metadata.get("fix", "Aplique a correção indicada pela regra Semgrep.")),
                ferramentas=("semgrep",),
            )
        )
    return findings


def _severity(value: str | None) -> Severity:
    normalized = (value or "LOW").upper()
    normalized = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }.get(normalized, normalized)
    return Severity[normalized] if normalized in Severity.__members__ else Severity.LOW


def _cwe_value(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("id", ""))
    if isinstance(value, (list, tuple)):
        return " ".join(_cwe_value(item) for item in value)
    return str(value or "")


def _normalize_cwe(value: object) -> str:
    raw = _cwe_value(value)
    match = re.search(r"(?:CWE-)?(\d+)", raw, re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else ""


def _read_ignore_file(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _relative_path(filename: str, directory: Path) -> str:
    path = Path(filename)
    try:
        relative = path.relative_to(directory)
    except ValueError:
        relative = path
    return str(relative).replace("\\", "/")


def _matches_ignore(filename: str, pattern: str) -> bool:
    normalized = filename.replace("\\", "/").lstrip("./")
    normalized_pattern = pattern.replace("\\", "/").lstrip("./")
    return (
        fnmatch.fnmatch(normalized, normalized_pattern)
        or fnmatch.fnmatch(normalized, normalized_pattern.rstrip("/") + "/**")
    )


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        finding = replace(
            finding,
            cwe=_normalize_cwe(finding.cwe),
            arquivo=finding.arquivo.replace("\\", "/"),
        )
        key = (finding.arquivo, finding.linha, finding.cwe)
        previous = unique.get(key)
        if previous is None:
            unique[key] = finding
            continue
        severity = max(
            (previous.severidade, finding.severidade),
            key=lambda item: _SEVERITY_RANK[item],
        )
        unique[key] = replace(
            previous,
            severidade=severity,
            ferramentas=tuple(
                sorted(set(previous.ferramentas) | set(finding.ferramentas))
            ),
        )
    return list(unique.values())


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}
