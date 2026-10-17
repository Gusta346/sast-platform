"""Integração opcional com o Ollama para triagem de findings."""

from __future__ import annotations

import json
import os
from typing import Any

import requests

from .models import Finding, Severity

_DEFAULT_TIMEOUT = 30.0
_MAX_ATTEMPTS = 2
_REMEDIATIONS = {
    "hardcoded_secret": "Remova o segredo do código e leia-o de uma variável de ambiente ou gerenciador de segredos.",
    "dangerous_functions": "Valide a entrada e substitua a execução ou desserialização insegura por uma API segura.",
    "sql_injection": "Use consultas parametrizadas e nunca concatene dados externos na instrução SQL.",
    "command_injection": "Evite shell=True, valide os argumentos e execute comandos com uma lista de parâmetros.",
    "weak_crypto": "Use um algoritmo moderno adequado ao objetivo, como Argon2id para senhas.",
    "debug_enabled": "Desabilite o modo debug em ambientes de produção.",
    "path_traversal": "Restrinja o caminho a um diretório permitido e valide o caminho normalizado.",
    "TAINT-001": "Valide a entrada e use consultas SQL parametrizadas.",
    "TAINT-002": "Evite shell=True e passe argumentos validados como uma lista.",
    "TAINT-003": "Não execute entrada controlada pelo usuário; use uma API explícita e segura.",
    "TAINT-004": "Normalize e restrinja o caminho a uma raiz de arquivos permitida.",
    "TAINT-005": "Evite pickle para dados não confiáveis e use um formato seguro.",
}


def classify_and_remediate(
    finding: Finding,
    code_context: str,
) -> dict[str, Any]:
    """Classifica e sugere correção para um finding usando Ollama ou fallback."""
    prompt = _build_prompt(finding, code_context)
    endpoint = f"{os.getenv('OLLAMA_URL', 'http://localhost:11434').rstrip('/')}/api/generate"
    model = os.getenv("OLLAMA_MODEL", "llama3")
    timeout = _timeout_from_environment()

    for attempt in range(_MAX_ATTEMPTS):
        try:
            response = requests.post(
                endpoint,
                json={
                    "model": model,
                    "system": _system_prompt(),
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
                timeout=timeout,
            )
            response.raise_for_status()
            result = _validate_result(_response_text(response))
            if result is not None:
                return result
        except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError):
            if attempt == _MAX_ATTEMPTS - 1:
                break

    return _fallback(finding)


def _system_prompt() -> str:
    return (
        "Você é um analista de segurança de aplicações. "
        "Responda exclusivamente com um objeto JSON válido, sem markdown, "
        "contendo exatamente: severidade, falso_positivo, justificativa e codigo_corrigido. "
        "A severidade deve ser CRITICAL, HIGH, MEDIUM ou LOW; falso_positivo deve ser booleano."
    )


def _build_prompt(finding: Finding, code_context: str) -> str:
    context = _context_window(code_context, finding.linha)
    return (
        "Analise o finding abaixo e proponha uma correção mínima e segura.\n"
        f"Regra: {finding.rule_id}\n"
        f"Título: {finding.titulo}\n"
        f"Severidade padrão: {finding.severidade.value}\n"
        f"CWE: {finding.cwe}\n"
        f"Descrição: {finding.descricao}\n"
        f"Linha do finding: {finding.linha}\n"
        "Código (cinco linhas antes e depois, quando disponíveis):\n"
        f"{context}\n"
        "Retorne somente o JSON solicitado."
    )


def _context_window(source: str, line: int) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    start = max(0, line - 6)
    end = min(len(lines), line + 5)
    return "\n".join(
        f"{index + 1}: {lines[index]}"
        for index in range(start, end)
    )


def _response_text(response: requests.Response) -> str:
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("response"), str):
        raise ValueError("Resposta do Ollama sem campo response textual")
    return payload["response"]


def _validate_result(raw: str) -> dict[str, Any] | None:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return None
    severity = payload.get("severidade")
    false_positive = payload.get("falso_positivo")
    justification = payload.get("justificativa")
    fixed_code = payload.get("codigo_corrigido")
    if (
        severity not in {severity.value for severity in Severity}
        or not isinstance(false_positive, bool)
        or not isinstance(justification, str)
        or not isinstance(fixed_code, str)
    ):
        return None
    return {
        "severidade": severity,
        "falso_positivo": false_positive,
        "justificativa": justification,
        "codigo_corrigido": fixed_code,
    }


def _fallback(finding: Finding) -> dict[str, Any]:
    return {
        "severidade": finding.severidade.value,
        "falso_positivo": False,
        "justificativa": "Ollama indisponível ou respondeu em formato inválido; foi usada a classificação padrão da regra.",
        "codigo_corrigido": _REMEDIATIONS.get(
            finding.rule_id,
            finding.remediacao or "Revise a entrada e aplique validação e sanitização adequadas.",
        ),
    }


def _timeout_from_environment() -> float:
    try:
        return float(os.getenv("OLLAMA_TIMEOUT", str(_DEFAULT_TIMEOUT)))
    except ValueError:
        return _DEFAULT_TIMEOUT
