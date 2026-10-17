"""Ponto de entrada da API SAST."""

from __future__ import annotations

import os
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from services.worker import tasks

from .database import create_tables, get_db
from .models import Finding, Scan
from .schemas import FindingResponse, ScanResponse

app = FastAPI(title="SAST Platform", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
        result = tasks.run_scan.delay(scan.id)
        scan.celery_task_id = result.id
        db.commit()
        if _cancel_previous_enabled():
            _cancel_previous_scans(db, scan.id)
    except Exception as exc:
        scan.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=503, detail="Não foi possível enfileirar a análise") from exc
    return scan


def _cancel_previous_scans(db: Session, current_scan_id: str) -> None:
    """Cancela scans anteriores ainda pendentes ou em execução."""
    previous = list(
        db.scalars(
            select(Scan).where(
                Scan.id != current_scan_id,
                or_(
                    Scan.status.in_(("PENDING", "RUNNING")),
                    (Scan.status == "DONE") & Scan.ia_pendente.is_(True),
                ),
            )
        )
    )
    for scan in previous:
        scan.status = "CANCELLED"
        if scan.celery_task_id:
            tasks.celery_app.control.revoke(
                scan.celery_task_id,
                terminate=True,
                signal="SIGTERM",
            )
    if previous:
        db.commit()


def _cancel_previous_enabled() -> bool:
    """Lê a flag de cancelamento com padrão habilitado."""
    return os.getenv("SAST_CANCEL_PREVIOUS", "true").lower() in {"1", "true", "yes", "on"}


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


@app.get("/metrics/severity", tags=["metrics"])
def severity_metrics(
    db: Annotated[Session, Depends(get_db)],
    scan_id: str | None = Query(default=None),
) -> dict[str, int]:
    """Retorna a distribuição de findings por severidade."""
    query = select(Finding.severidade, func.count(Finding.id))
    query = _filter_findings(query, scan_id).group_by(Finding.severidade)
    rows = db.execute(query)
    values = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    values.update({str(severity): int(total) for severity, total in rows})
    return values


@app.get("/metrics/trend", tags=["metrics"])
def trend_metrics(
    db: Annotated[Session, Depends(get_db)],
    scan_id: str | None = Query(default=None),
) -> list[dict[str, int | str]]:
    """Retorna findings agrupados pela semana de criação do scan."""
    query = select(Scan.criado_em).join(Finding, Finding.scan_id == Scan.id)
    rows = db.execute(_filter_findings(query, scan_id))
    totals: dict[str, int] = {}
    for created_at, in rows:
        created_at = _as_utc(created_at).astimezone(ZoneInfo("America/Sao_Paulo"))
        iso = created_at.isocalendar()
        week = f"{iso.year:04d}-W{iso.week:02d}"
        totals[week] = totals.get(week, 0) + 1
    return [{"semana": week, "total": totals[week]} for week in sorted(totals)]


@app.get("/metrics/top-files", tags=["metrics"])
def top_files_metrics(
    db: Annotated[Session, Depends(get_db)],
    scan_id: str | None = Query(default=None),
) -> list[dict[str, int | str]]:
    """Retorna os cinco arquivos com mais findings críticos."""
    query = select(Finding.arquivo, func.count(Finding.id).label("total"))
    query = (
        _filter_findings(query, scan_id)
        .where(Finding.severidade == "CRITICAL")
        .group_by(Finding.arquivo)
        .order_by(func.count(Finding.id).desc(), Finding.arquivo)
        .limit(5)
    )
    rows = db.execute(query)
    return [{"arquivo": str(filename), "total": int(total)} for filename, total in rows]


@app.get("/metrics/summary", tags=["metrics"])
def summary_metrics(
    db: Annotated[Session, Depends(get_db)],
    scan_id: str | None = Query(default=None),
) -> dict[str, int]:
    """Retorna totais gerais do dashboard."""
    total = db.scalar(_filter_findings(select(func.count(Finding.id)), scan_id)) or 0
    critical = db.scalar(
        _filter_findings(
            select(func.count(Finding.id)).where(Finding.severidade == "CRITICAL"),
            scan_id,
        )
    ) or 0
    dismissed = db.scalar(
        _filter_findings(
            select(func.count(Finding.id)).where(Finding.falso_positivo.is_(True)),
            scan_id,
        )
    ) or 0
    return {
        "total": int(total),
        "criticos": int(critical),
        "falsos_positivos_descartados_ia": int(dismissed),
    }


def _filter_findings(query, scan_id: str | None):
    """Aplica o escopo opcional de um scan à consulta de findings."""
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    return query


def _as_utc(value: datetime) -> datetime:
    """Interpreta datas sem fuso como UTC e normaliza datas para UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _valid_zip(content: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return archive.testzip() is None and all(_safe_member(name) for name in archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def _safe_member(name: str) -> bool:
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts
