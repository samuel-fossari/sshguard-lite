"""Módulo de Interface CLI.

Ponto de entrada: interpreta os argumentos, orquestra
parsing → detecção → relatório e trata erros de alto nível.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sshguard_lite.parser import LogFileError, parse_log
from sshguard_lite.report import (
    ProcessingMetadata,
    format_json_report,
    format_text_report,
)
from sshguard_lite.rules import detect


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser que devolve código 1 em erro de uso (seção 10.3)."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"erro: {message}", file=sys.stderr)
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    """Executa o pipeline completo. Devolve o código de saída do processo."""
    parser = _ArgumentParser(
        prog="sshguard_lite",
        description="Detecta força bruta SSH em arquivos auth.log.",
    )
    parser.add_argument(
        "logfile",
        help="caminho para o arquivo auth.log a ser analisado",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="ano dos timestamps syslog (padrão: ano corrente do sistema)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="imprime o relatório em JSON em vez de texto",
    )
    args = parser.parse_args(argv)

    log_path = Path(args.logfile)
    try:
        events = (
            parse_log(log_path, year=args.year)
            if args.year is not None
            else parse_log(log_path)
        )
        alerts = detect(events)
        metadata = _processing_metadata(log_path, events)
        formatter = format_json_report if args.json else format_text_report
        sys.stdout.write(formatter(alerts, metadata))
        return 0
    except LogFileError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"erro inesperado: {exc}", file=sys.stderr)
        return 2


def _processing_metadata(log_path: Path, events) -> ProcessingMetadata:
    """Calcula metadados na CLI, sem alterar o parser (seção 9)."""
    with log_path.open(encoding="utf-8", errors="replace") as handle:
        total_linhas = sum(1 for _ in handle)
    if events:
        periodo_inicio = min(event.timestamp for event in events)
        periodo_fim = max(event.timestamp for event in events)
    else:
        periodo_inicio = None
        periodo_fim = None
    return ProcessingMetadata(
        total_linhas_lidas=total_linhas,
        total_eventos_extraidos=len(events),
        periodo_inicio=periodo_inicio,
        periodo_fim=periodo_fim,
    )


if __name__ == "__main__":
    raise SystemExit(main())
