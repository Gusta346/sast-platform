"""Interface de linha de comando do scanner SAST."""

from __future__ import annotations

import argparse
import fnmatch
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from .models import Finding, Severity
from .scanner import scan_directory

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def build_parser() -> argparse.ArgumentParser:
    """Cria o parser de argumentos da CLI."""
    parser = argparse.ArgumentParser(prog="python -m sast_engine.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Analisa uma pasta")
    scan.add_argument("directory", type=Path)
    scan.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        default=Severity.HIGH.value,
        help="Severidade mínima que faz a CLI retornar código 1",
    )
    scan.add_argument(
        "--format",
        required=True,
        help="Formatos separados por vírgula: json,sarif",
    )
    scan.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Prefixo dos arquivos de relatório",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Executa a CLI e retorna o exit code."""
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2

    formats = {item.strip().lower() for item in args.format.split(",") if item.strip()}
    unsupported = formats - {"json", "sarif"}
    if unsupported or not formats:
        logger.error("Formatos inválidos: %s. Use json,sarif.", ", ".join(sorted(unsupported)))
        return 2

    directory = args.directory.resolve()
    ignore_patterns = _load_ignore_patterns(directory)
    python_files = (
        [
            path
            for path in sorted(directory.rglob("*.py"))
            if not any(
                _matches_ignore(str(path.relative_to(directory)), pattern)
                for pattern in ignore_patterns
            )
        ]
        if directory.is_dir()
        else []
    )
    if not directory.exists() or not directory.is_dir() or not python_files:
        print(f"Caminho não encontrado: {args.directory}", file=sys.stderr)
        return 2

    findings = scan_directory(directory, ignore_patterns=ignore_patterns)
    if "json" in formats:
        _write_json(args.output.with_suffix(".json"), findings)
    if "sarif" in formats:
        _write_sarif(args.output.with_suffix(".sarif"), findings)

    threshold = Severity(args.fail_on)
    failed = any(_SEVERITY_RANK[finding.severidade] >= _SEVERITY_RANK[threshold] for finding in findings)
    print(
        f"SAST: {len(findings)} finding(s); "
        f"arquivos analisados: {len(python_files)}; "
        f"fail-on={threshold.value}; failed={failed}"
    )
    return 1 if failed else 0


def _load_ignore_patterns(directory: Path) -> list[str]:
    """Carrega o ignore do diretório analisado ou da raiz atual."""
    local = directory / ".sast-ignore"
    if local.is_file():
        return _read_ignore_file(local)
    return _read_ignore_file(Path.cwd() / ".sast-ignore")


def _read_ignore_file(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _matches_ignore(filename: str, pattern: str) -> bool:
    normalized = filename.replace("\\", "/").lstrip("./")
    normalized_pattern = pattern.replace("\\", "/").lstrip("./")
    return fnmatch.fnmatch(normalized, normalized_pattern) or fnmatch.fnmatch(
        normalized,
        normalized_pattern.rstrip("/") + "/**",
    )


def _write_json(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [{**asdict(finding), "severidade": finding.severidade.value} for finding in findings]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_sarif(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    results = []
    rules: dict[str, dict[str, str]] = {}
    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.titulo,
                "shortDescription": {"text": finding.titulo},
                "helpUri": "https://owasp.org/www-project-top-ten/",
            },
        )
        result = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severidade),
            "message": {"text": finding.descricao},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.arquivo.replace("\\", "/")},
                        "region": {
                            "startLine": finding.linha,
                            "snippet": {"text": finding.trecho},
                        },
                    }
                }
            ],
            "properties": {
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "remediacao": finding.remediacao,
                "ferramentas": list(finding.ferramentas),
            },
        }
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SAST Platform",
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


if __name__ == "__main__":
    sys.exit(main())
