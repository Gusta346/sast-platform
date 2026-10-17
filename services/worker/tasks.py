"""Tarefas assíncronas de análise SAST."""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from services.api import database
from services.api.models import Finding as FindingModel
from services.api.models import Scan
from services.engine.sast_engine.ai import classify_and_remediate
from services.engine.sast_engine.scanner import scan_directory

from .celery_app import celery_app

UPLOAD_DIR = Path(os.getenv("SAST_UPLOAD_DIR", "/app/data/scans"))


@celery_app.task(name="services.worker.tasks.run_scan")
def run_scan(scan_id: str) -> str:
    """Extrai o ZIP, analisa o código e persiste os findings."""
    session = database.SessionLocal()
    extraction_dir: Path | None = None
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan não encontrado: {scan_id}")
        scan.status = "RUNNING"
        session.commit()

        archive = UPLOAD_DIR / f"{scan_id}.zip"
        extraction_dir = Path(tempfile.mkdtemp(prefix=f"sast-{scan_id}-", dir=UPLOAD_DIR))
        _safe_extract(archive, extraction_dir)
        findings = scan_directory(extraction_dir)

        for finding in findings:
            source = _read_context(extraction_dir / finding.arquivo)
            ai_result = classify_and_remediate(finding, source)
            session.add(
                FindingModel(
                    scan_id=scan_id,
                    rule_id=finding.rule_id,
                    titulo=finding.titulo,
                    severidade=finding.severidade.value,
                    arquivo=finding.arquivo,
                    linha=finding.linha,
                    trecho=finding.trecho,
                    cwe=finding.cwe,
                    owasp=finding.owasp,
                    descricao=finding.descricao,
                    remediacao=finding.remediacao,
                    ferramentas=",".join(finding.ferramentas),
                    falso_positivo=bool(ai_result["falso_positivo"]),
                    remediacao_ia=str(ai_result["codigo_corrigido"]),
                    severidade_ia=str(ai_result["severidade"]),
                    ia_origem=str(ai_result["ia_origem"]),
                )
            )
        scan.status = "DONE"
        session.commit()
        return scan_id
    except Exception:
        session.rollback()
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "FAILED"
            session.commit()
        raise
    finally:
        session.close()
        if extraction_dir is not None:
            shutil.rmtree(extraction_dir, ignore_errors=True)


def _safe_extract(archive: Path, destination: Path) -> None:
    """Extrai somente membros que permanecem dentro do destino."""
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(archive) as zip_file:
        for member in zip_file.infolist():
            if _is_symlink(member):
                raise ValueError("ZIP inválido: links simbólicos não são permitidos")
            member_path = (destination / member.filename).resolve()
            if member_path != destination_resolved and destination_resolved not in member_path.parents:
                raise ValueError("ZIP inválido: caminho fora do diretório de extração")
            if member.is_dir():
                continue
            member_path.parent.mkdir(parents=True, exist_ok=True)
            with zip_file.open(member) as source, member_path.open("wb") as target:
                shutil.copyfileobj(source, target)


def _is_symlink(member: zipfile.ZipInfo) -> bool:
    """Detecta links simbólicos codificados no modo Unix do ZIP."""
    return (member.external_attr >> 16) & 0o170000 == 0o120000


def _read_context(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
