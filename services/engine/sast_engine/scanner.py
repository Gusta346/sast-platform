"""Orquestração das regras internas e ferramentas externas."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from collections.abc import Callable, Iterable

from .models import Finding, Severity
from .parser import parse_source
from .rules import ALL_RULES

logger = logging.getLogger(__name__)


class Scanner:
    """Percorre arquivos Python e agrega findings normalizados."""

    def __init__(self, include_external: bool = True) -> None:
        self.include_external = include_external
        self.rules = tuple(rule() for rule in ALL_RULES)

    def scan_directory(self, directory: str | Path) -> list[Finding]:
        """Analisa todos os arquivos Python de um diretório."""
        root = Path(directory)
        findings: list[Finding] = []
        for path in sorted(root.rglob("*.py")):
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
        return [
            finding
            for rule in self.rules
            for finding in rule.check(parsed.ast_tree, filename, source)
        ]

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
        return self._run_external(command, "Bandit", _normalize_bandit)

    def _run_semgrep(self, directory: Path) -> list[Finding]:
        if shutil.which("semgrep") is None:
            logger.warning("Semgrep não está instalado; análise complementar ignorada.")
            return []
        command = ["semgrep", "--config", "p/python", "--json", "--no-git-ignore", str(directory)]
        return self._run_external(command, "Semgrep", _normalize_semgrep, timeout=120)

    def _run_external(
        self,
        command: list[str],
        tool_name: str,
        normalizer: Callable[[dict], list[Finding]],
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
        return normalizer(payload)


def scan_directory(directory: str | Path, include_external: bool = True) -> list[Finding]:
    """Analisa um diretório com a configuração padrão."""
    return Scanner(include_external=include_external).scan_directory(directory)


def _normalize_bandit(payload: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        findings.append(
            Finding(
                rule_id=f"bandit_{result.get('test_id', 'unknown')}",
                titulo=result.get("test_name", "Bandit finding"),
                severidade=_severity(result.get("issue_severity")),
                arquivo=result.get("filename", ""),
                linha=int(result.get("line_number", 1)),
                trecho=result.get("code", "").strip(),
                cwe=_cwe_value(result.get("issue_cwe")),
                owasp="",
                descricao=result.get("issue_text", ""),
                remediacao="Revise a recomendação da regra Bandit correspondente.",
            )
        )
    return findings


def _normalize_semgrep(payload: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(
            Finding(
                rule_id=f"semgrep_{result.get('check_id', 'unknown')}",
                titulo=metadata.get("title", result.get("check_id", "Semgrep finding")),
                severidade=_severity(metadata.get("severity", extra.get("severity"))),
                arquivo=result.get("path", ""),
                linha=int(result.get("start", {}).get("line", 1)),
                trecho=extra.get("lines", "").strip(),
                cwe=_cwe_value(metadata.get("cwe")),
                owasp=str(metadata.get("owasp", "")),
                descricao=extra.get("message", ""),
                remediacao=str(metadata.get("fix", "Aplique a correção indicada pela regra Semgrep.")),
            )
        )
    return findings


def _severity(value: str | None) -> Severity:
    normalized = (value or "LOW").upper()
    return Severity[normalized] if normalized in Severity.__members__ else Severity.LOW


def _cwe_value(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("id", ""))
    return str(value or "")


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        key = (finding.arquivo, finding.linha, finding.cwe)
        unique.setdefault(key, finding)
    return list(unique.values())
