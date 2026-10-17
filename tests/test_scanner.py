"""Testes de normalização e deduplicação do scanner."""

from pathlib import Path

from services.engine.sast_engine.models import Finding, Severity
from services.engine.sast_engine.scanner import (
    Scanner,
    _deduplicate,
    _normalize_bandit,
    _normalize_semgrep,
)


def test_ignore_file_excludes_findings_from_scanned_files(tmp_path: Path) -> None:
    """O ignore deve impedir a análise de arquivos internos ignorados."""
    ignored = tmp_path / "samples"
    ignored.mkdir()
    (tmp_path / ".sast-ignore").write_text("samples/\n", encoding="utf-8")
    (ignored / "vulnerable.py").write_text("eval(input())\n", encoding="utf-8")

    assert Scanner(include_external=False).scan_directory(tmp_path) == []


def test_semgrep_error_maps_to_high() -> None:
    """Severity ERROR do Semgrep deve ser HIGH."""
    findings = _normalize_semgrep(
        {
            "results": [
                {
                    "check_id": "python.test",
                    "path": "/workspace/app.py",
                    "start": {"line": 4},
                    "extra": {
                        "severity": "ERROR",
                        "lines": "eval(value)",
                        "message": "unsafe",
                        "metadata": {"cwe": ["CWE-327: weak crypto"]},
                    },
                }
            ]
        },
        Path("/workspace"),
    )

    assert findings[0].severidade == Severity.HIGH
    assert findings[0].cwe == "CWE-327"


def test_bandit_and_semgrep_same_location_are_merged() -> None:
    """Ferramentas diferentes no mesmo finding devem ser consolidadas."""
    bandit = _normalize_bandit(
        {
            "results": [
                {
                    "test_id": "B307",
                    "test_name": "eval",
                    "issue_severity": "MEDIUM",
                    "filename": "/workspace/app.py",
                    "line_number": 10,
                    "code": "eval(value)",
                    "issue_cwe": {"id": "95"},
                    "issue_text": "unsafe",
                }
            ]
        },
        Path("/workspace"),
    )
    semgrep = _normalize_semgrep(
        {
            "results": [
                {
                    "check_id": "python.eval",
                    "path": "/workspace/app.py",
                    "start": {"line": 10},
                    "extra": {
                        "severity": "ERROR",
                        "lines": "eval(value)",
                        "message": "unsafe",
                        "metadata": {"cwe": ["CWE-95: eval"]},
                    },
                }
            ]
        },
        Path("/workspace"),
    )

    merged = _deduplicate([*bandit, *semgrep])

    assert len(merged) == 1
    assert merged[0].arquivo == "app.py"
    assert merged[0].cwe == "CWE-95"
    assert merged[0].severidade == Severity.HIGH
    assert set(merged[0].ferramentas) == {"bandit", "semgrep"}
