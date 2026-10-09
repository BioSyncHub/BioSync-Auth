"""Caminhos absolutos do projeto, independentes do diretório de execução."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"
LOCAL_CONFIG_DIR = PROJECT_ROOT / "config" / "local"
REPORTS_DIR = PROJECT_ROOT / "reports"
