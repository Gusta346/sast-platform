# DevSecOps e Security Gate

O workflow [sast.yml](../.github/workflows/sast.yml) executa os testes, roda o
scanner completo e publica JSON/SARIF. Em pull requests, o job `sast` falha
quando encontra um finding `HIGH` ou `CRITICAL`, impedindo que o PR seja
aprovado enquanto o problema não for corrigido.

## Demonstrar um PR bloqueado

1. Crie uma branch de demonstração:

   ```bash
   git checkout -b demo/security-gate
   ```

2. Adicione uma vulnerabilidade nova em um arquivo analisado fora de
   `samples/` e `tests/`, por exemplo em `services/api/demo_vulnerability.py`:

   ```python
   import subprocess

   def run_user_command(command: str) -> None:
       subprocess.run(command, shell=True)
   ```

3. Faça commit e publique a branch:

   ```bash
   git add services/api/demo_vulnerability.py
   git commit -m "demo: adicionar vulnerabilidade para o security gate"
   git push -u origin demo/security-gate
   ```

4. Abra um Pull Request da branch `demo/security-gate` para a branch padrão.

5. Aguarde os jobs `test`, `sast` e `docker`. O scanner deve produzir um finding
   `HIGH`/`CRITICAL` para command injection. O workflow publica o SARIF no Code
   Scanning, anexa os relatórios e comenta um resumo no PR, mas o passo final
   do Security Gate retorna código 1.

6. Corrija o código usando uma lista de argumentos sem `shell=True`, faça push
   novamente e confirme que o job `sast` passa:

   ```python
   import shlex
   import subprocess

   def run_user_command(command: str) -> None:
       subprocess.run(shlex.split(command), check=True)
   ```

7. Depois da demonstração, remova a branch:

   ```bash
   git push origin --delete demo/security-gate
   git checkout main
   git branch -D demo/security-gate
   ```

## Execução local

Dentro do contêiner da API, o projeto fica em `/app` e o pacote pode ser
executado a partir da raiz com:

```bash
PYTHONPATH=/app python -m services.engine.sast_engine.cli scan . \
  --fail-on HIGH \
  --format json,sarif \
  --output relatorio
```

Isso gera `relatorio.json` e `relatorio.sarif`. O arquivo `.sast-ignore` exclui
as amostras vulneráveis e os testes intencionais da análise padrão.

Em um contêiner da API, a montagem de `./services` em `/app/services` e
`PYTHONPATH=/app` permitem executar diretamente:

```bash
docker compose run --rm api python -m pytest -v
docker compose run --rm api python -m services.engine.sast_engine.cli scan services \
  --fail-on HIGH --format json --output relatorio
```
