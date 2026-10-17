"""Tarefas assíncronas de análise SAST."""

from __future__ import annotations

import os
import logging
import shutil
import tempfile
import time
import zipfile
from pathlib import Path

from services.api import database
from services.api.models import Finding as FindingModel
from services.api.models import Scan
from services.engine.sast_engine.ai import classify_and_remediate, fallback_result
from services.engine.sast_engine.models import Finding, Severity
from services.engine.sast_engine.scanner import scan_directory

from .celery_app import celery_app

UPLOAD_DIR = Path(os.getenv("SAST_UPLOAD_DIR", "/app/data/scans"))
LOGGER = logging.getLogger(__name__)
_DEFAULT_AI_BUDGET = 90.0
_DEFAULT_AI_MAX_FINDINGS = 5
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@celery_app.task(name="services.worker.tasks.run_scan")
def run_scan(scan_id: str) -> str:
    """Extrai o ZIP, analisa o código e persiste os findings."""
    scan_started_at = time.monotonic()
    session = database.SessionLocal()
    extraction_dir: Path | None = None
    llm_count = 0
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan não encontrado: {scan_id}")
        if scan.status == "CANCELLED":
            return scan_id
        scan.status = "RUNNING"
        session.commit()

        archive = UPLOAD_DIR / f"{scan_id}.zip"
        extraction_dir = Path(tempfile.mkdtemp(prefix=f"sast-{scan_id}-", dir=UPLOAD_DIR))
        _safe_extract(archive, extraction_dir)
        findings = scan_directory(extraction_dir)
        model_findings = _persist_fallback_findings(session, scan_id, findings)
        if _is_cancelled(session, scan_id):
            session.rollback()
            return scan_id
        scan.status = "DONE"
        scan.ia_pendente = bool(_select_ai_findings(findings, model_findings))
        session.commit()

        selected = _select_ai_findings(findings, model_findings)
        for finding, model_finding in selected:
            if _is_cancelled(session, scan_id):
                return scan_id
            started_at = time.perf_counter()
            source = _read_context(extraction_dir / finding.arquivo)
            if time.monotonic() - scan_started_at >= _ai_budget():
                break
            llm_count += 1
            ai_result = classify_and_remediate(finding, source, use_llm=True)
            if _is_cancelled(session, scan_id):
                return scan_id
            elapsed_ms = (time.perf_counter() - started_at) * 1000
            LOGGER.info(
                "Finding enriquecido: arquivo=%s linha=%s regra=%s "
                "severidade=%s ia_origem=%s tempo_ms=%.2f",
                finding.arquivo,
                finding.linha,
                finding.rule_id,
                finding.severidade.value,
                ai_result["ia_origem"],
                elapsed_ms,
            )
            if ai_result["ia_origem"] == "llm":
                model_finding.falso_positivo = bool(ai_result["falso_positivo"])
                model_finding.remediacao_ia = str(ai_result["codigo_corrigido"])
                model_finding.severidade_ia = str(ai_result["severidade"])
                model_finding.ia_origem = "llm"
                session.commit()
        if not _is_cancelled(session, scan_id):
            scan = session.get(Scan, scan_id)
            scan.ia_pendente = False
            session.commit()
        return scan_id
    except Exception:
        session.rollback()
        scan = session.get(Scan, scan_id)
        if scan is not None and scan.status != "CANCELLED":
            scan.status = "FAILED"
            session.commit()
        raise
    finally:
        session.close()
        if extraction_dir is not None:
            shutil.rmtree(extraction_dir, ignore_errors=True)
        LOGGER.info(
            "Scan finalizado: scan_id=%s achados=%s chamadas_llm=%s tempo_total_ms=%.2f",
            scan_id,
            len(findings) if "findings" in locals() else 0,
            llm_count,
            (time.monotonic() - scan_started_at) * 1000,
        )


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


def _persist_fallback_findings(
    session,
    scan_id: str,
    findings: list[Finding],
) -> list[FindingModel]:
    """Grava todos os findings inicialmente com a remediação determinística."""
    models = []
    for finding in findings:
        fallback = fallback_result(finding)
        model = FindingModel(
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
            falso_positivo=False,
            remediacao_ia=str(fallback["codigo_corrigido"]),
            severidade_ia=str(fallback["severidade"]),
            ia_origem="fallback",
        )
        session.add(model)
        models.append(model)
    session.flush()
    session.commit()
    return models


def _select_ai_findings(
    findings: list[Finding],
    models: list[FindingModel],
) -> list[tuple[Finding, FindingModel]]:
    """Seleciona os achados mais críticos, priorizando regras distintas."""
    eligible = [
        finding
        for finding in findings
        if finding.severidade in {Severity.CRITICAL, Severity.HIGH}
    ]
    limit = _ai_max_findings()
    selected: list[Finding] = []
    seen_rules: set[str] = set()
    ordered = sorted(eligible, key=lambda item: _SEVERITY_ORDER[item.severidade])
    for finding in ordered:
        if finding.rule_id not in seen_rules and len(selected) < limit:
            selected.append(finding)
            seen_rules.add(finding.rule_id)
    for finding in ordered:
        if finding not in selected and len(selected) < limit:
            selected.append(finding)
    model_by_finding = {id(finding): model for finding, model in zip(findings, models)}
    return [(finding, model_by_finding[id(finding)]) for finding in selected]


def _is_cancelled(session, scan_id: str) -> bool:
    """Consulta o status atual para impedir gravações após cancelamento."""
    session.expire_all()
    scan = session.get(Scan, scan_id)
    return scan is None or scan.status == "CANCELLED"


def _ai_budget() -> float:
    """Retorna o orçamento de IA do scan em segundos."""
    try:
        return max(0.0, float(os.getenv("SAST_AI_BUDGET", str(_DEFAULT_AI_BUDGET))))
    except ValueError:
        return _DEFAULT_AI_BUDGET


def _ai_max_findings() -> int:
    """Retorna o limite configurável de findings enviados ao LLM."""
    try:
        return max(0, int(os.getenv("SAST_AI_MAX_FINDINGS", str(_DEFAULT_AI_MAX_FINDINGS))))
    except ValueError:
        return _DEFAULT_AI_MAX_FINDINGS


def _should_use_llm(
    finding: Finding,
    llm_count: int,
    elapsed_seconds: float,
    budget_seconds: float,
) -> bool:
    """Decide se um finding ainda pode consumir orçamento do LLM."""
    return (
        finding.severidade in {Severity.HIGH, Severity.CRITICAL}
        and llm_count < _ai_max_findings()
        and elapsed_seconds < budget_seconds
    )
