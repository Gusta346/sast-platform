# Instruções do projeto

## Contexto

Este projeto é uma plataforma SAST (Static Application Security Testing) e
DevSecOps. A aplicação é executada com Python 3.11 e analisa código Python.

## Stack

- Parsing: `ast` da biblioteca padrão e Tree-sitter.
- Regras complementares: Bandit e Semgrep.
- API: FastAPI.
- Persistência: PostgreSQL com SQLAlchemy.
- Processamento assíncrono: Redis e Celery.
- IA local: Ollama com Llama 3 para classificação de severidade e sugestões de
  remediação.
- Execução e infraestrutura: Docker Compose.
- Integração contínua: GitHub Actions, incluindo o Security Gate.
- Testes: pytest.

## Estrutura do projeto

- `services/api`: aplicação e endpoints da API.
- `services/worker`: tarefas assíncronas executadas pelo Celery.
- `services/engine`: pacote `sast_engine`, responsável pela análise estática.
- `services/dashboard`: dashboard da plataforma.
- `samples/vulnerable_app`: aplicações vulneráveis usadas como amostras.
- `tests`: testes automatizados.
- `docs`: documentação do projeto.
- `.github/workflows`: workflows do GitHub Actions.

## Diretrizes de implementação

- Mantenha o código modular, com responsabilidades bem definidas entre API,
  worker, engine e dashboard.
- Use type hints de forma consistente.
- Escreva docstrings curtas em português para módulos, classes e funções
  públicas.
- Preserve a compatibilidade com Python 3.11.
- Reutilize helpers, tipos e padrões já existentes antes de criar duplicações.
- Não inclua credenciais reais, tokens ou segredos no código. Use variáveis de
  ambiente e mantenha apenas valores de exemplo em `.env.example`.
- Trate erros explicitamente e preserve logs e notificações conforme os padrões
  do serviço correspondente.

## Contrato de findings

Todo finding produzido pela plataforma deve conter os seguintes campos:

- `rule_id`
- `titulo`
- `severidade`, com um dos valores `CRITICAL`, `HIGH`, `MEDIUM` ou `LOW`
- `arquivo`
- `linha`
- `trecho`
- `CWE`
- `categoria OWASP Top 10`
- `descricao`
- `remediacao`

Ao alterar o modelo, serialização, persistência ou apresentação de findings,
preserve esse contrato em todas as camadas.

## Testes e validação

- Crie testes pytest para cada módulo novo ou alterado, cobrindo comportamento
  normal, entradas inválidas e casos de segurança relevantes.
- Execute os testes direcionados durante o desenvolvimento e a suíte completa
  antes de concluir mudanças que afetem múltiplos serviços.
- Preserve a execução do Security Gate nos workflows do GitHub Actions.
- Prefira testes determinísticos e não dependa de serviços externos ou de
  credenciais reais; use fixtures, mocks e variáveis de ambiente de teste.

## Respostas

Sempre entregue os arquivos completos e prontos para rodar, incluindo o
conteúdo integral de qualquer arquivo criado ou alterado.
