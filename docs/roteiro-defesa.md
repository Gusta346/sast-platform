# Roteiro de defesa — 10 minutos

## 0:00–1:00 — Problema

Explique que vulnerabilidades frequentemente entram no código antes da revisão
manual. O objetivo é detectar problemas Python no fluxo de desenvolvimento,
normalizar findings e bloquear o merge quando houver risco `HIGH` ou
`CRITICAL`.

Mostre o contrato do finding: regra, título, severidade, arquivo, linha,
trecho, CWE, OWASP, descrição, remediação e ferramentas.

## 1:00–2:30 — Arquitetura

Abra [docs/arquitetura.md](arquitetura.md) e explique:

- API FastAPI recebe ZIP;
- Redis transporta a tarefa Celery;
- worker executa o engine sem executar o código analisado;
- PostgreSQL guarda scans e findings;
- dashboard consulta a API;
- Ollama é local e opcional;
- GitHub Actions executa o Security Gate.

Mostre que o worker tem concorrência 2 e que o scan mais recente pode cancelar
scans anteriores.

## 2:30–4:00 — Demo ao vivo: subir a plataforma

Execute:

```bash
docker compose up --build
```

Em outro terminal, carregue o modelo:

```bash
docker compose exec ollama ollama pull llama3
```

Abra:

- <http://localhost:8080>
- <http://localhost:8000/docs>

Se o modelo não estiver disponível, explique que o fallback determinístico
mantém o scan funcionando.

## 4:00–6:00 — Demo ao vivo: análise

Use a CLI:

```bash
docker compose run --rm api \
  python -m services.engine.sast_engine.cli scan services \
  --fail-on HIGH --format json,sarif --output relatorio
```

Explique os códigos de saída `0`, `1` e `2`, o `.sast-ignore` e a diferença
entre JSON e SARIF.

No dashboard, envie um ZIP de código próprio de demonstração. Mostre:

1. scan criado;
2. findings aparecendo antes do enriquecimento completo;
3. etiqueta `fallback` mudando para `llm`;
4. métricas e seleção de escopo;
5. CSV exportado.

## 6:00–7:30 — Demo ao vivo: Security Gate

Crie uma branch:

```bash
git checkout -b demo/security-gate
```

Adicione, fora de `samples/` e `tests/`, um código próprio como:

```python
import subprocess

def run_user_command(command: str) -> None:
    subprocess.run(command, shell=True)
```

Faça commit, push e abra um Pull Request. O workflow
[sast.yml](../.github/workflows/sast.yml) executará testes, o scanner, upload
de SARIF e comentário no PR. O job falha porque `command_injection` é
`CRITICAL`.

Corrija usando argumentos separados e faça push novamente:

```python
import shlex
import subprocess

def run_user_command(command: str) -> None:
    subprocess.run(shlex.split(command), check=True)
```

O Security Gate deve passar após a correção.

## 7:30–8:30 — Resultados

Apresente apenas resultados verificáveis:

- suíte automatizada executada com `pytest`;
- amostra vulnerável coberta por testes;
- JSON e SARIF produzidos pela CLI;
- findings normalizados e deduplicados;
- fallback disponível quando a IA falha;
- dashboard atualizado por polling;
- logs com tempo por finding e por scan.

Não apresente tempos de IA, precisão ou recall como números se não tiverem
sido medidos no ambiente da demonstração.

## 8:30–10:00 — Perguntas prováveis

### O sistema executa o código enviado?

Não. O worker extrai o ZIP com proteção contra zip-slip e analisa arquivos
como texto/AST. O código analisado não é importado nem executado.

### Por que usar três fontes de análise?

O motor próprio cobre requisitos específicos e taint; Bandit e Semgrep
complementam com regras maduras. O scanner normaliza e deduplica os
resultados.

### O que significa `fallback`?

É a remediação determinística da regra. Ela evita que uma falha do Ollama
quebre o pipeline ou deixe uma linha sem sugestão.

### Por que limitar a IA a cinco findings?

Para manter a resposta rápida e previsível. São escolhidos os mais críticos,
com preferência por `rule_id` distintos. O limite pode ser alterado por
`SAST_AI_MAX_FINDINGS`.

### O taint é interprocedural?

Não. Atualmente é intraprocedural. Taint interprocedural está listado como
trabalho futuro.

### Como o Security Gate decide bloquear?

A CLI compara a severidade com `--fail-on HIGH`. Um finding `HIGH` ou
`CRITICAL` retorna código 1, e o workflow transforma isso em falha do job.

### Há migrações de banco?

Há uma rotina automática e idempotente para algumas colunas novas, mas não há
Alembic nem histórico de migrações versionadas. Alembic é trabalho futuro.

### O código analisado pode ser de terceiros?

Somente se houver autorização compatível, como licença open source aplicável ou
permissão explícita. A demonstração usa código próprio e fictício.
