# IA local com Ollama

O motor pode usar o Ollama para apoiar a classificação de severidade e a
remediação de findings. A integração é opcional: se o Ollama estiver fora do
ar, responder em formato inválido ou exceder o timeout, o resultado
determinístico da regra é preservado.

## Configuração

```bash
OLLAMA_URL=http://ollama:11434
OLLAMA_MODEL=llama3
OLLAMA_TIMEOUT=30
SAST_AI_BUDGET=90
SAST_AI_MAX_FINDINGS=5
```

O worker envia ao Ollama apenas findings `HIGH` e `CRITICAL`, no máximo cinco
por scan por padrão. O orçamento total de enriquecimento é controlado por
`SAST_AI_BUDGET`;
quando ele se esgota, os findings restantes usam o fallback determinístico.
`SAST_AI_MAX_FINDINGS` limita quantos achados críticos são enviados ao LLM por
scan; os demais permanecem com `ia_origem="fallback"`.

O modelo pode ser carregado no container com:

```bash
sh scripts/pull_model.sh
```

## Prompt de sistema

O cliente envia este prompt de sistema:

> Você é um analista de segurança de aplicações. Responda exclusivamente com
> um objeto JSON válido, sem markdown, contendo exatamente: severidade,
> falso_positivo, justificativa e codigo_corrigido. A severidade deve ser
> CRITICAL, HIGH, MEDIUM ou LOW; falso_positivo deve ser booleano.

O prompt da análise inclui o `rule_id`, título, severidade padrão, CWE,
descrição, linha do finding e uma janela de até cinco linhas antes e cinco
linhas depois do trecho.

## Formato esperado

```json
{
  "severidade": "HIGH",
  "falso_positivo": false,
  "justificativa": "A entrada externa alcança uma operação perigosa.",
  "codigo_corrigido": "Use uma consulta parametrizada."
}
```

O cliente valida todos os campos, restringe a severidade aos valores do
contrato e faz duas tentativas quando a resposta não é JSON válido ou não
contém os tipos esperados.

## Limitações

- A IA local não substitui as regras determinísticas, o Bandit ou o Semgrep.
- O modelo pode classificar incorretamente um finding ou sugerir uma correção
  incompleta; toda remediação deve passar por revisão e testes.
- O contexto enviado é limitado à janela ao redor da linha do finding e não
  representa necessariamente o fluxo completo do programa.
- O fallback usa a severidade da regra e um texto fixo por `rule_id`, portanto
  o CI continua determinístico sem depender do Ollama.
