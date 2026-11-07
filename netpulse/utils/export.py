"""
Módulo de exportação de resultados para JSON e Markdown.
"""

import json
from pathlib import Path

from netpulse.models.results import DiscoveryResult, QualityResult
from netpulse.utils.formatting import print_success, print_error, print_info


def export_result(result, filepath: str):
    """
    Exporta um resultado (DiscoveryResult ou QualityResult) para arquivo.

    O formato é detectado pela extensão:
    - .json → JSON
    - .md → Markdown

    Args:
        result: DiscoveryResult ou QualityResult.
        filepath: Caminho do arquivo de saída.
    """
    path = Path(filepath)
    extension = path.suffix.lower()

    if extension == ".json":
        _export_json(result, path)
    elif extension == ".md":
        _export_markdown(result, path)
    else:
        print_error(
            f"Formato não suportado: '{extension}'. "
            "Use .json ou .md"
        )


def _export_json(result, path: Path):
    """Exporta resultado para JSON."""
    try:
        if hasattr(result, 'to_dict'):
            data = result.to_dict()
        else:
            print_error("Este resultado não suporta exportação para JSON.")
            return

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print_success(f"Resultado exportado para: [bold]{path}[/bold]")
        print_info(f"Formato: JSON | Tamanho: {path.stat().st_size} bytes")

    except OSError as e:
        print_error(f"Erro ao salvar arquivo: {e}")


def _export_markdown(result, path: Path):
    """Exporta resultado para Markdown."""
    try:
        if hasattr(result, 'to_markdown'):
            content = result.to_markdown()
        else:
            print_error("Este resultado não suporta exportação para Markdown.")
            return

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        print_success(f"Resultado exportado para: [bold]{path}[/bold]")
        print_info(f"Formato: Markdown | Tamanho: {path.stat().st_size} bytes")

    except OSError as e:
        print_error(f"Erro ao salvar arquivo: {e}")
