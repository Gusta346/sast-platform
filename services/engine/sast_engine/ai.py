"""Integração opcional com o Ollama para triagem de findings."""

from __future__ import annotations

import ast
import json
import os
import re
import textwrap
import unicodedata
from typing import Any

import requests

from .models import Finding, Severity

_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MODEL = "llama3.2"
_MAX_ATTEMPTS = 2
_MSG_FALHA = (
    "Ollama indisponível ou resposta inválida; "
    "foi usada a orientação determinística da regra."
)
_MSG_LIMITE = (
    "Orientação determinística da regra "
    "(achado fora dos mais críticos analisados pela IA)."
)
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
    *,
    use_llm: bool = True,
) -> dict[str, Any]:
    """Classifica e sugere correção para um finding usando Ollama ou fallback."""
    if not use_llm:
        return _fallback(finding, motivo=_MSG_LIMITE)

    prompt = _build_prompt(finding, code_context)
    endpoint = f"{os.getenv('OLLAMA_URL', 'http://localhost:11434').rstrip('/')}/api/generate"
    model = os.getenv("OLLAMA_MODEL") or _DEFAULT_MODEL
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
                    "format": _response_schema(),
                    "options": {"temperature": 0.1},
                },
                timeout=timeout,
            )
            response.raise_for_status()
            result = _validate_result(
                _response_text(response),
                finding.severidade,
            )
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
        "contendo exatamente: severidade, explicacao e codigo_corrigido. "
        "A severidade deve ser CRITICAL, HIGH, MEDIUM ou LOW; "
        "explicacao deve ter até 3 frases, em português, e codigo_corrigido "
        "deve conter apenas o código, sem números de linha."
    )


def _response_schema() -> dict[str, Any]:
    """Retorna o schema JSON esperado pelo Ollama."""
    return {
        "type": "object",
        "properties": {
            "severidade": {
                "type": "string",
                "enum": [severity.value for severity in Severity],
            },
            "explicacao": {"type": "string"},
            "codigo_corrigido": {"type": "string"},
        },
        "required": ["severidade", "explicacao", "codigo_corrigido"],
        "additionalProperties": False,
    }


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
        "Explique em até 3 frases e proponha um código corrigido curto, "
        "sem inventar funções ou parâmetros que não existem.\n"
        "Retorne somente o JSON solicitado."
    )


def _context_window(source: str, line: int) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    start = max(0, line - 6)
    end = min(len(lines), line + 5)
    return "\n".join(
        re.sub(r"^\s*\d+:\s?", "", lines[index])
        for index in range(start, end)
    )


def _response_text(response: requests.Response) -> str:
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("response"), str):
        raise ValueError("Resposta do Ollama sem campo response textual")
    return payload["response"]


def _validate_result(
    raw: str,
    original_severity: Severity,
) -> dict[str, Any] | None:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return None
    severity = _safe_severity(payload.get("severidade"), original_severity)
    explanation = payload.get("explicacao")
    fixed_code = payload.get("codigo_corrigido")
    if not isinstance(explanation, str) or not explanation.strip():
        return None
    if _looks_like_echo(explanation):
        return None
    corrected_code = _validated_code(fixed_code)
    return {
        "severidade": severity,
        "explicacao": explanation.strip(),
        "codigo_corrigido": corrected_code,
        "ia_origem": "llm",
    }


def _safe_severity(value: Any, original: Severity) -> str:
    """Normaliza a severidade e limita a alteração a um nível."""
    aliases = {
        "ERRO": Severity.CRITICAL,
        "ERROR": Severity.CRITICAL,
        "CRITICO": Severity.CRITICAL,
        "CRITICAL": Severity.CRITICAL,
        "ALTO": Severity.HIGH,
        "ALTA": Severity.HIGH,
        "HIGH": Severity.HIGH,
        "MEDIO": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "BAIXO": Severity.LOW,
        "BAIXA": Severity.LOW,
        "LOW": Severity.LOW,
    }
    normalized = _remove_accents(value).upper() if isinstance(value, str) else ""
    candidate = aliases.get(normalized)
    if candidate is None:
        return original.value
    levels = list(Severity)
    if abs(levels.index(candidate) - levels.index(original)) > 1:
        return original.value
    return candidate.value


def _remove_accents(value: str) -> str:
    return "".join(
        char
        for char in unicodedata.normalize("NFD", value)
        if unicodedata.category(char) != "Mn"
    )


def _validated_code(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    code = textwrap.dedent(value).strip()
    try:
        ast.parse(code)
    except SyntaxError:
        return ""
    return code


def _looks_like_echo(text: str) -> bool:
    """Detecta resposta que apenas repete o trecho de código numerado."""
    lines = [item for item in text.splitlines() if item.strip()]
    if not lines:
        return True
    numbered = sum(1 for item in lines if re.match(r"^\s*\d+\s*:", item))
    return numbered >= max(2, len(lines) // 2)


def _fallback(finding: Finding, *, motivo: str = _MSG_FALHA) -> dict[str, Any]:
    return {
        "severidade": finding.severidade.value,
        "explicacao": motivo,
        "codigo_corrigido": _REMEDIATIONS.get(
            finding.rule_id,
            finding.remediacao
            or "Revise a entrada e aplique validação e sanitização adequadas.",
        ),
        "ia_origem": "fallback",
    }


def fallback_result(finding: Finding) -> dict[str, Any]:
    """Retorna a remediação determinística sem consultar o Ollama."""
    return _fallback(finding, motivo=_MSG_LIMITE)


def _timeout_from_environment() -> float:
    try:
        timeout = float(os.getenv("OLLAMA_TIMEOUT", str(_DEFAULT_TIMEOUT)))
        return timeout if timeout > 0 else _DEFAULT_TIMEOUT
    except ValueError:
        return _DEFAULT_TIMEOUT