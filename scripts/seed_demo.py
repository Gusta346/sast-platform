"""Popula o banco com dados fictícios para apresentação."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from services.api.database import SessionLocal, create_tables
from services.api.models import Finding, Scan


def seed() -> None:
    """Insere scans e findings demonstrativos sem código real."""
    create_tables()
    session = SessionLocal()
    try:
        if session.query(Scan).filter(Scan.nome == "demo-vulnerable-app.zip").first():
            return
        now = datetime.now(timezone.utc)
        scans = [
            Scan(nome="demo-vulnerable-app.zip", status="DONE", criado_em=now - timedelta(days=1)),
            Scan(nome="demo-api.zip", status="DONE", criado_em=now - timedelta(days=8)),
            Scan(nome="demo-clean.zip", status="DONE", criado_em=now - timedelta(days=15)),
        ]
        session.add_all(scans)
        session.flush()
        findings = [
            Finding(scan_id=scans[0].id, rule_id="TAINT-001", titulo="SQL injection", severidade="CRITICAL", arquivo="app/routes.py", linha=42, trecho="db.execute(query)", cwe="CWE-89", owasp="A03:2021 - Injection", descricao="Entrada externa alcança SQL.", remediacao="Use parâmetros.", ferramentas="ast,taint", falso_positivo=False, remediacao_ia="Use consulta parametrizada.", severidade_ia="CRITICAL", ia_origem="fallback"),
            Finding(scan_id=scans[0].id, rule_id="command_injection", titulo="Command injection", severidade="HIGH", arquivo="app/runner.py", linha=18, trecho="subprocess.run(command)", cwe="CWE-78", owasp="A03:2021 - Injection", descricao="Comando controlado por entrada.", remediacao="Remova shell=True.", ferramentas="ast", falso_positivo=False, remediacao_ia="Use lista de argumentos.", severidade_ia="HIGH", ia_origem="llm"),
            Finding(scan_id=scans[0].id, rule_id="weak_crypto", titulo="Criptografia fraca", severidade="MEDIUM", arquivo="app/auth.py", linha=9, trecho="hashlib.md5(value)", cwe="CWE-327", owasp="A02:2021 - Cryptographic Failures", descricao="Algoritmo fraco.", remediacao="Use Argon2id.", ferramentas="ast", falso_positivo=True, remediacao_ia="Revisar contexto.", severidade_ia="LOW", ia_origem="llm"),
            Finding(scan_id=scans[1].id, rule_id="path_traversal", titulo="Path traversal", severidade="HIGH", arquivo="services/files.py", linha=31, trecho="open(path)", cwe="CWE-22", owasp="A01:2021 - Broken Access Control", descricao="Caminho sem validação.", remediacao="Restrinja a raiz.", ferramentas="bandit", falso_positivo=False, remediacao_ia="Normalize o caminho.", severidade_ia="HIGH", ia_origem="fallback"),
        ]
        session.add_all(findings)
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    seed()
