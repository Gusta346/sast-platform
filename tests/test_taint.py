"""Testes da análise intraprocedural de taint."""

from pathlib import Path

from services.engine.sast_engine.taint import analyze_taint


SAMPLE = Path(__file__).parents[1] / "samples" / "vulnerable_app" / "app.py"


def test_vulnerable_sample_taint_flows_are_detected() -> None:
    """Os cinco fluxos da amostra devem alcançar seus sinks."""
    findings = analyze_taint(SAMPLE.read_text(encoding="utf-8"), "app.py")

    assert {finding.rule_id for finding in findings} >= {
        "TAINT-001",
        "TAINT-002",
        "TAINT-003",
        "TAINT-004",
        "TAINT-005",
    }
    assert all("source linha" in finding.descricao and "sink linha" in finding.descricao for finding in findings)


def test_sanitized_flow_has_no_taint_finding() -> None:
    """Sanitizadores devem interromper o fluxo até o sink."""
    source = """
import html
import shlex
import sqlite3
import subprocess

def safe(request):
    query = "SELECT * FROM users WHERE id = ?"
    connection.execute(query, (int(request.args["id"]),))
    subprocess.run(shlex.quote(request.args["command"]), shell=True)
    return html.escape(request.args["html"])
"""

    assert analyze_taint(source, "clean.py") == []
