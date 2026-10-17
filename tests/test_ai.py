"""Testes do cliente Ollama e de seus fallbacks."""

import json

import requests

from services.engine.sast_engine.ai import classify_and_remediate
from services.engine.sast_engine.models import Finding, Severity


def _finding() -> Finding:
    return Finding(
        rule_id="sql_injection",
        titulo="SQL injection",
        severidade=Severity.HIGH,
        arquivo="app.py",
        linha=3,
        trecho="connection.execute(query)",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        descricao="Consulta dinâmica.",
        remediacao="Use parâmetros.",
    )


def test_ollama_success(monkeypatch) -> None:
    """Resposta válida do Ollama deve ser retornada."""
    expected = {
        "severidade": "HIGH",
        "falso_positivo": False,
        "justificativa": "Entrada externa alcança a consulta.",
        "codigo_corrigido": "connection.execute(query, params)",
    }

    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, str]:
            return {"response": json.dumps(expected)}

    calls = []

    def post(*args, **kwargs):
        calls.append((args, kwargs))
        return Response()

    monkeypatch.setattr(requests, "post", post)
    result = classify_and_remediate(_finding(), "a = 1\nb = 2\nconnection.execute(query)\nc = 3")

    assert result == expected
    assert len(calls) == 1
    assert calls[0][1]["timeout"] == 30.0
    assert "a = 1" in calls[0][1]["json"]["prompt"]


def test_invalid_json_retries_then_uses_fallback(monkeypatch) -> None:
    """JSON inválido deve gerar uma nova tentativa e depois fallback."""

    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, str]:
            return {"response": "não é json"}

    calls = []
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: calls.append(1) or Response())

    result = classify_and_remediate(_finding(), "connection.execute(query)")

    assert len(calls) == 2
    assert result["severidade"] == "HIGH"
    assert result["falso_positivo"] is False
    assert result["codigo_corrigido"] == "Use consultas parametrizadas e nunca concatene dados externos na instrução SQL."


def test_ollama_unavailable_uses_fallback(monkeypatch) -> None:
    """Falha de rede não deve quebrar a análise."""
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.ConnectionError("offline")),
    )

    result = classify_and_remediate(_finding(), "connection.execute(query)")

    assert result["severidade"] == "HIGH"
    assert result["falso_positivo"] is False
