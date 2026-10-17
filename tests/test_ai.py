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
        "ia_origem": "llm",
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


def test_ollama_model_and_timeout_are_configurable(monkeypatch) -> None:
    """Modelo e timeout devem respeitar as variáveis de ambiente."""
    monkeypatch.setenv("OLLAMA_MODEL", "modelo-de-teste")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "7.5")

    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, str]:
            return {
                "response": json.dumps(
                    {
                        "severidade": "HIGH",
                        "falso_positivo": False,
                        "justificativa": "justificativa",
                        "codigo_corrigido": "correcao",
                    }
                )
            }

    calls = []
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: calls.append((args, kwargs)) or Response(),
    )

    classify_and_remediate(_finding(), "connection.execute(query)")

    assert calls[0][1]["json"]["model"] == "modelo-de-teste"
    assert calls[0][1]["timeout"] == 7.5


def test_invalid_ollama_timeout_uses_default(monkeypatch) -> None:
    """Timeout inválido não deve criar uma requisição sem limite válido."""
    monkeypatch.setenv("OLLAMA_TIMEOUT", "0")

    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, str]:
            return {
                "response": json.dumps(
                    {
                        "severidade": "HIGH",
                        "falso_positivo": False,
                        "justificativa": "justificativa",
                        "codigo_corrigido": "correcao",
                    }
                )
            }

    calls = []
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: calls.append((args, kwargs)) or Response(),
    )

    classify_and_remediate(_finding(), "connection.execute(query)")

    assert calls[0][1]["timeout"] == 30.0


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
    assert result["ia_origem"] == "fallback"
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
    assert result["ia_origem"] == "fallback"


def test_fallback_can_be_forced_without_calling_ollama(monkeypatch) -> None:
    """Findings fora do gate de IA devem usar fallback sem requisição HTTP."""
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("não deveria chamar Ollama")),
    )

    result = classify_and_remediate(_finding(), "connection.execute(query)", use_llm=False)

    assert result["ia_origem"] == "fallback"
    assert result["severidade"] == "HIGH"
