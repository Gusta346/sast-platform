"""Ponto de entrada da API SAST."""

from __future__ import annotations

import os
import io
import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from services.worker import tasks

from .database import create_tables, get_db
from .models import Finding, Scan
from .schemas import FindingResponse, ScanResponse

app = FastAPI(title="SAST Platform", version="0.1.0")

MAX_UPLOAD_BYTES = int(os.getenv("SAST_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))


@app.on_event("startup")
def startup() -> None:
    """Cria o banco e o diretório de uploads."""
    create_tables()
    tasks.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Retorna o estado da API."""
    return {"status": "ok"}


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    """Retorna informações básicas da plataforma."""
    return {"name": "sast-platform", "status": "ready"}


@app.post("/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    file: Annotated[UploadFile, File(...)],
    db: Annotated[Session, Depends(get_db)],
) -> Scan:
    """Recebe um ZIP e agenda uma análise."""
    if not file.filename or Path(file.filename).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="O upload deve ser um arquivo .zip")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="O arquivo excede o tamanho máximo permitido")
    if not _valid_zip(content):
        raise HTTPException(status_code=400, detail="O upload não é um ZIP válido")

    scan = Scan(nome=Path(file.filename).name, status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    tasks.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (tasks.UPLOAD_DIR / f"{scan.id}.zip").write_bytes(content)
    try:
        tasks.run_scan.delay(scan.id)
    except Exception as exc:
        scan.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=503, detail="Não foi possível enfileirar a análise") from exc
    return scan


@app.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Annotated[Session, Depends(get_db)]) -> Scan:
    """Retorna uma análise pelo identificador."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return scan


@app.get("/scans", response_model=list[ScanResponse])
def list_scans(db: Annotated[Session, Depends(get_db)]) -> list[Scan]:
    """Lista as análises mais recentes."""
    return list(db.scalars(select(Scan).order_by(Scan.criado_em.desc())))


@app.get("/findings", response_model=list[FindingResponse])
def list_findings(
    db: Annotated[Session, Depends(get_db)],
    severidade: str | None = Query(default=None),
    arquivo: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
) -> list[Finding]:
    """Lista findings com filtros opcionais."""
    query = select(Finding)
    if severidade:
        query = query.where(Finding.severidade == severidade.upper())
    if arquivo:
        query = query.where(Finding.arquivo == arquivo)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    return list(db.scalars(query.order_by(Finding.id)))


def _valid_zip(content: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return archive.testzip() is None and all(_safe_member(name) for name in archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def _safe_member(name: str) -> bool:
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts
