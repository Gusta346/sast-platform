# Análise crítica

## Escopo avaliado

O motor atual analisa Python com AST, Tree-sitter, regras próprias e taint
intraprocedural. Bandit e Semgrep são ferramentas complementares invocadas por
subprocesso quando estão instaladas. O scanner normaliza seus JSONs, aplica
`.sast-ignore` e deduplica por arquivo, linha e CWE.

## Limitações conhecidas

### Taint intraprocedural

O taint percorre cada função isoladamente. Ele propaga valores por
atribuições, concatenação, f-strings, `.format`, `%` e chamadas simples, mas
não modela de forma completa:

- chamadas entre funções;
- retorno tainted de outra função;
- objetos complexos, aliases e containers mutáveis;
- fluxo entre módulos;
- análise interprocedural ou sensibilidade a caminhos.

Consequentemente, pode haver falsos negativos quando a source e o sink estão
em funções diferentes e falsos positivos quando o fluxo real é sanitizado por
uma abstração não reconhecida.

### Falsos positivos e negativos observados

A amostra `samples/vulnerable_app/app.py` foi criada para exercitar as regras,
portanto seus findings são intencionais. O próprio teste exige a detecção das
vulnerabilidades presentes. Não há, no repositório, uma suíte anotada de
aplicações reais que permita estimar uma taxa estatística de precisão ou
recall.

Falsos positivos possíveis incluem nomes que parecem segredos mas são apenas
constantes de demonstração, caminhos que são validados por helpers externos e
chamadas dinâmicas que o AST não consegue resolver. Falsos negativos podem
ocorrer com aliases, wrappers, reflexão, SQL construído em módulos diferentes,
sanitizers próprios e padrões de framework não implementados.

## Comparação com ferramentas isoladas

| Configuração | O que é executado | Resultado verificável no repositório |
|---|---|---|
| Motor próprio | Regras AST + taint | Os testes exigem as oito categorias da amostra vulnerável |
| Bandit isolado | Bandit com saída JSON | O scanner sabe normalizar Bandit quando o executável está instalado |
| Semgrep isolado | Semgrep com `p/python` e saída JSON | O scanner sabe normalizar Semgrep; a execução depende da instalação/configuração local |
| Pipeline completo | Motor próprio + Bandit + Semgrep + deduplicação | Consolida fontes e mantém a maior severidade por arquivo/linha/CWE |

O código não contém um benchmark fixo com número de findings e tempos
isolados de Bandit e Semgrep, e esses valores variam por versão e ambiente.
Portanto, não é correto afirmar números de comparação que não foram medidos.
Para reproduzir uma medição local, use:

```bash
python -m bandit -r samples/vulnerable_app -f json
semgrep --config p/python --json samples/vulnerable_app
PYTHONPATH=. python -m services.engine.sast_engine.cli scan samples/vulnerable_app \
  --fail-on LOW --format json --output motor-proprio
```

## Tempos da IA em CPU

O worker registra `tempo_ms` por finding e `tempo_total_ms` por scan no log.
Entretanto, o repositório não contém uma medição reproduzível de CPU com um
modelo Ollama executado localmente; o resultado depende de CPU, memória,
quantização, modelo e carga. Assim, não há número de tempo de IA apresentado
como fato nesta documentação.

Uma medição adequada deve registrar pelo menos:

- modelo e quantização;
- CPU e memória;
- quantidade de findings enviados;
- timeout e orçamento;
- tempo por resposta e tempo total;
- quantidade de respostas válidas e fallbacks.

## Decisão de limitar o LLM

O worker seleciona no máximo cinco findings por padrão (`SAST_AI_MAX_FINDINGS=5`),
priorizando `CRITICAL`, depois `HIGH`, e regras distintas antes de repetições.
Essa decisão reduz latência, custo computacional e impacto de indisponibilidade
do Ollama, mantendo todos os findings imediatamente disponíveis com fallback.
O limite é configurável.

## Banco de dados e migrações

Não há Alembic ou migrações versionadas. A aplicação usa `create_all` e uma
rotina idempotente de `ALTER TABLE` para algumas colunas novas. Isso atende à
demonstração e a upgrades simples, mas não oferece histórico, downgrade,
controle de dependências ou migrações complexas.

## Trabalho futuro

- suporte a JavaScript e Java;
- taint interprocedural e intermodular;
- conjunto de benchmarks reais autorizados;
- métricas de precisão, recall e tempo em ambientes controlados;
- regras específicas de frameworks;
- adoção de Alembic;
- autenticação, autorização e retenção de dados;
- fila dedicada para enriquecimento de IA e observabilidade estruturada.

## Ética

O scanner deve ser usado somente em código próprio ou open source autorizado.
Não se deve enviar código confidencial, segredos ou dados pessoais ao Ollama
ou a ferramentas externas sem autorização e controles apropriados.
