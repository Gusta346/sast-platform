# Regras de análise

As regras abaixo são implementadas em
`services/engine/sast_engine/rules`. A severidade indicada é a severidade
padrão do motor; Bandit, Semgrep e taint podem gerar findings adicionais,
normalizados pelo scanner.

## `hardcoded_secret`

- **Descrição:** detecta atribuições a nomes contendo `password`, `passwd`,
  `secret`, `token`, `api_key` ou `key` quando o valor é string literal não
  vazia.
- **CWE:** CWE-798.
- **OWASP:** A07:2021 - Identification and Authentication Failures.
- **Severidade:** HIGH.
- **Vulnerável:**

  ```python
  API_KEY = "valor-ficticio"
  ```

- **Corrigido:**

  ```python
  import os

  API_KEY = os.environ["API_KEY"]
  ```

## `dangerous_functions`

- **Descrição:** detecta `eval`, `exec`, `pickle.loads` e `yaml.load` sem
  `SafeLoader`.
- **CWE:** CWE-95/CWE-502.
- **OWASP:** A03:2021 - Injection.
- **Severidade:** CRITICAL.
- **Vulnerável:**

  ```python
  result = eval(user_expression)
  restored = pickle.loads(payload)
  ```

- **Corrigido:**

  ```python
  import ast

  result = ast.literal_eval(user_expression)
  ```

  Para dados não confiáveis, prefira formatos seguros e valide o schema antes
  de desserializar.

## `sql_injection`

- **Descrição:** detecta chamadas `.execute`, `.executemany` ou
  `.executescript` cujo SQL usa concatenação, f-string, `.format`, `%` ou
  variável dinâmica.
- **CWE:** CWE-89.
- **OWASP:** A03:2021 - Injection.
- **Severidade:** HIGH.
- **Vulnerável:**

  ```python
  query = "SELECT * FROM users WHERE name = '" + name + "'"
  connection.execute(query)
  ```

- **Corrigido:**

  ```python
  connection.execute(
      "SELECT * FROM users WHERE name = ?",
      (name,),
  )
  ```

## `command_injection`

- **Descrição:** detecta `os.system` e chamadas `subprocess.*` com
  `shell=True`.
- **CWE:** CWE-78.
- **OWASP:** A03:2021 - Injection.
- **Severidade:** CRITICAL.
- **Vulnerável:**

  ```python
  subprocess.run(command, shell=True)
  ```

- **Corrigido:**

  ```python
  import shlex

  subprocess.run(shlex.split(command), check=True)
  ```

## `weak_crypto`

- **Descrição:** detecta chamadas a `hashlib.md5` e `hashlib.sha1`.
- **CWE:** CWE-327.
- **OWASP:** A02:2021 - Cryptographic Failures.
- **Severidade:** MEDIUM.
- **Vulnerável:**

  ```python
  digest = hashlib.md5(password.encode()).hexdigest()
  ```

- **Corrigido:**

  ```python
  from argon2 import PasswordHasher

  digest = PasswordHasher().hash(password)
  ```

  O pacote Argon2 não faz parte da dependência atual; o exemplo representa a
  recomendação de arquitetura para senhas.

## `debug_enabled`

- **Descrição:** detecta `app.run(debug=True)`.
- **CWE:** CWE-489.
- **OWASP:** A05:2021 - Security Misconfiguration.
- **Severidade:** HIGH.
- **Vulnerável:**

  ```python
  app.run(debug=True)
  ```

- **Corrigido:**

  ```python
  app.run(debug=False)
  ```

## `path_traversal`

- **Descrição:** detecta `open`, `send_file`, `Path(...).read_text`,
  `read_bytes`, `Path(...).open` e `os.path.join` quando o caminho não é
  constante.
- **CWE:** CWE-22.
- **OWASP:** A01:2021 - Broken Access Control.
- **Severidade:** HIGH.
- **Vulnerável:**

  ```python
  Path(request.args["path"]).read_text()
  ```

- **Corrigido:**

  ```python
  from pathlib import Path

  root = Path("/srv/uploads").resolve()
  candidate = (root / user_name).resolve()
  if root not in candidate.parents:
      raise ValueError("caminho inválido")
  candidate.read_text()
  ```

## Findings de taint

Além das regras AST, o `TaintAnalyzer` produz:

| Rule ID | Sink | CWE | Severidade |
|---|---|---|---|
| `TAINT-001` | SQL `execute`/`executemany` | CWE-89 | HIGH |
| `TAINT-002` | `os.system`, `subprocess.*` | CWE-78 | CRITICAL |
| `TAINT-003` | `eval`, `exec` | CWE-95 | CRITICAL |
| `TAINT-004` | APIs de arquivo | CWE-22 | HIGH |
| `TAINT-005` | `pickle.loads` | CWE-502 | CRITICAL |

As sources incluem objetos `request`, `input()`, `sys.argv`, `os.environ`,
`request.get_data()` e `request.get_json()`. Os sanitizers implementados
incluem `int`, `float`, `html.escape`, `shlex.quote`, `secure_filename` e
consultas SQL parametrizadas.

## Ferramentas complementares

- **Bandit:** resultados JSON são normalizados para `Finding`, preservando
  regra, severidade e CWE.
- **Semgrep:** usa a configuração `p/python`; `ERROR`, `WARNING` e `INFO` são
  convertidos para HIGH, MEDIUM e LOW.
- Findings são deduplicados por arquivo, linha e CWE, mantendo a maior
  severidade e agregando `ferramentas`.

## Ética

As regras devem ser executadas somente sobre código próprio ou open source
autorizado. Não use o scanner para acessar, modificar ou publicar código sem
permissão.
