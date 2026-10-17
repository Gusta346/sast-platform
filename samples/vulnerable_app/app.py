"""Aplicação fictícia e propositalmente vulnerável para testes SAST."""

import hashlib
import pickle
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

# Credencial fictícia exclusiva para esta amostra de treinamento.
DEMO_PASSWORD = "fictitious-demo-password"


@app.route("/login", methods=["POST"])
def login() -> str:
    """Demonstra armazenamento e comparação inseguros de senha."""
    password = request.form.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()
    if password == DEMO_PASSWORD and password_hash:
        return "logged in"
    return "unauthorized", 401


@app.route("/calculate")
def calculate() -> str:
    """Demonstra execução de expressão controlada pelo usuário."""
    return str(eval(request.args.get("expression", "0")))  # noqa: S307


@app.route("/user")
def user() -> str:
    """Demonstra concatenação insegura em uma consulta SQL."""
    username = request.args.get("name", "")
    connection = sqlite3.connect(":memory:")
    query = "SELECT username FROM users WHERE username = '" + username + "'"
    connection.execute(query)
    return username


@app.route("/run")
def run_command() -> str:
    """Demonstra execução de comando com shell habilitado."""
    command = request.args.get("command", "echo demo")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/restore", methods=["POST"])
def restore() -> str:
    """Demonstra desserialização insegura de entrada do usuário."""
    payload = request.get_data()
    restored = pickle.loads(payload)  # noqa: S301
    return str(restored)


@app.route("/download")
def download() -> str:
    """Demonstra acesso a arquivo sem validação de caminho."""
    requested_path = request.args.get("path", "README.md")
    return Path(requested_path).read_text(encoding="utf-8")


if __name__ == "__main__":
    app.run(debug=True)
