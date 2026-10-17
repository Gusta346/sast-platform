"""Testes do worker inicial."""

from services.engine.sast_engine.models import Finding, Severity
from services.worker.celery_app import health_task
from services.worker.tasks import _ai_budget, _should_use_llm


def test_health_task() -> None:
    """A tarefa de saúde deve retornar o estado esperado."""
    assert health_task.run() == "ok"


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="test",
        titulo="Teste",
        severidade=severity,
        arquivo="app.py",
        linha=1,
        trecho="",
        cwe="CWE-1",
        owasp="",
        descricao="",
        remediacao="",
    )


def test_llm_is_limited_to_high_critical_ten_and_budget() -> None:
    """Somente findings elegíveis dentro dos limites usam o LLM."""
    assert _should_use_llm(_finding(Severity.HIGH), 0, 0, 90)
    assert _should_use_llm(_finding(Severity.CRITICAL), 4, 89.9, 90)
    assert not _should_use_llm(_finding(Severity.MEDIUM), 0, 0, 90)
    assert not _should_use_llm(_finding(Severity.HIGH), 5, 0, 90)
    assert not _should_use_llm(_finding(Severity.HIGH), 0, 90, 90)


def test_ai_budget_uses_environment(monkeypatch) -> None:
    """O orçamento deve ser configurável e ter fallback seguro."""
    monkeypatch.setenv("SAST_AI_BUDGET", "12.5")
    assert _ai_budget() == 12.5
    monkeypatch.setenv("SAST_AI_BUDGET", "invalido")
    assert _ai_budget() == 90.0
