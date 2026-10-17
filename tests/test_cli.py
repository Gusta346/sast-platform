"""Testes da interface de linha de comando do scanner."""

from pathlib import Path
from shutil import copytree

from services.engine.sast_engine.cli import main


SAMPLE_DIR = Path(__file__).parents[1] / "samples" / "vulnerable_app"


def test_missing_path_returns_two(tmp_path: Path, capsys) -> None:
    """Caminho inexistente deve falhar explicitamente."""
    missing = tmp_path / "does-not-exist"

    result = main(
        [
            "scan",
            str(missing),
            "--fail-on",
            "HIGH",
            "--format",
            "json",
            "--output",
            str(tmp_path / "report"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert f"Caminho não encontrado: {missing}" in captured.err


def test_copied_sample_outside_ignore_returns_one(tmp_path: Path) -> None:
    """Uma amostra vulnerável fora do ignore deve bloquear o gate."""
    copied_sample = tmp_path / "copied-sample"
    copytree(SAMPLE_DIR, copied_sample)

    result = main(
        [
            "scan",
            str(copied_sample),
            "--fail-on",
            "HIGH",
            "--format",
            "json",
            "--output",
            str(tmp_path / "report"),
        ]
    )

    assert result == 1


def test_clean_directory_returns_zero(tmp_path: Path) -> None:
    """Um diretório com Python limpo deve passar o gate."""
    (tmp_path / "clean.py").write_text("value = 1\n", encoding="utf-8")

    result = main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "HIGH",
            "--format",
            "json",
            "--output",
            str(tmp_path / "report"),
        ]
    )

    assert result == 0
