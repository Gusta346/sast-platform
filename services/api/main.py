"""Ponto de entrada da API SAST."""

from fastapi import FastAPI

app = FastAPI(title="SAST Platform", version="0.1.0")


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Retorna o estado da API."""
    return {"status": "ok"}


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    """Retorna informações básicas da plataforma."""
    return {"name": "sast-platform", "status": "ready"}
