# Arquitetura da plataforma SAST

## Diagrama C4 — Contexto

```mermaid
C4Context
    title Contexto da plataforma SAST
    Person(developer, "Desenvolvedor", "Envia código e consulta resultados")
    System(sast, "Plataforma SAST", "Analisa código Python e aplica o Security Gate")
    System_Ext(ollama, "Ollama + Llama 3", "Classifica severidade e sugere remediações localmente")
    Rel(developer, sast, "Envia código e consulta findings", "HTTPS")
    Rel(sast, ollama, "Solicita classificação e remediação", "HTTP")
```

## Diagrama C4 — Contêiner

```mermaid
C4Container
    title Contêineres da plataforma SAST
    Person(developer, "Desenvolvedor", "Usuário da plataforma")
    Container(api, "API", "FastAPI", "Recebe código, cria análises e expõe findings")
    Container(worker, "Worker", "Celery + Python", "Executa análises de forma assíncrona")
    Container(redis, "Fila", "Redis", "Broker e backend de resultados do Celery")
    ContainerDb(postgres, "Banco", "PostgreSQL", "Armazena análises e findings")
    Container(ollama, "IA local", "Ollama + Llama 3", "Apoia severidade e remediação")
    Container(dashboard, "Dashboard", "Nginx", "Entrega a interface web estática")
    Rel(developer, dashboard, "Acessa", "HTTP")
    Rel(developer, api, "Envia código e consulta", "HTTP/JSON")
    Rel(api, redis, "Enfileira tarefas", "Redis protocol")
    Rel(worker, redis, "Consome tarefas", "Redis protocol")
    Rel(worker, postgres, "Salva análises e findings", "SQL")
    Rel(api, postgres, "Consulta estado e findings", "SQL")
    Rel(worker, ollama, "Solicita inferências locais", "HTTP")
    Rel(dashboard, api, "Consulta dados", "HTTP/JSON")
```

## Serviços e fluxo

- **API**: recebe o código-fonte, valida a requisição, enfileira a análise e
  disponibiliza o estado e os findings.
- **Worker**: consome tarefas do Celery, executa o engine com `ast`, Tree-sitter,
  Bandit e Semgrep, e coordena a classificação opcional pela IA local.
- **Redis**: funciona como broker das tarefas e backend de resultados do Celery.
- **PostgreSQL**: persiste análises, findings e seus metadados.
- **Ollama**: executa o Llama 3 localmente para apoiar severidade e remediação,
  sem enviar código para um serviço externo.
- **Dashboard**: entrega o front-end estático via Nginx e consulta a API.

O fluxo assíncrono começa quando a API recebe o código e publica uma tarefa no
Redis. O worker consome essa tarefa, analisa o código, consulta o Ollama quando
necessário e salva os resultados no PostgreSQL. O dashboard consulta a API para
exibir o estado da análise e os findings.
