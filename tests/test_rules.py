"""Testes de regressão do motor de regras SAST."""

from pathlib import Path

from services.engine.sast_engine.scanner import scan_directory


SAMPLE_DIR = Path(__file__).parents[1] / "samples" / "vulnerable_app"


def test_vulnerable_sample_has_all_expected_findings() -> None:
    """A amostra deve conter as oito ocorrências vulneráveis esperadas."""
    findings = scan_directory(SAMPLE_DIR, include_external=False)
    findings = [finding for finding in findings if not finding.rule_id.startswith("TAINT-")]
    app_findings = [finding for finding in findings if finding.arquivo.endswith("app.py")]

    assert len(app_findings) == 8
    assert {finding.rule_id for finding in app_findings} == {
        "hardcoded_secret",
        "dangerous_functions",
        "sql_injection",
        "command_injection",
        "weak_crypto",
        "debug_enabled",
        "path_traversal",
    }
    assert sum(finding.rule_id == "dangerous_functions" for finding in app_findings) == 2


def test_clean_file_has_no_findings(tmp_path: Path) -> None:
    """Código sem padrões vulneráveis não deve gerar achados."""
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(
        "import hashlib\n\n"
        "def greet(name: str) -> str:\n"
        "    return f'hello {name}'\n\n"
        "digest = hashlib.sha256(b'data').hexdigest()\n",
        encoding="utf-8",
    )

    assert scan_directory(tmp_path, include_external=False) == []
