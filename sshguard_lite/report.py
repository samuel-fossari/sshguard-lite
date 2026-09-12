"""Módulo de Relatório.

Recebe a lista de alertas e os metadados de processamento e formata a
saída em texto ou JSON. Não calcula totais, períodos nem alertas — só
formata o que recebe. Não sabe nada sobre como os alertas foram
calculados.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from sshguard_lite.rules import Alert

_ALERT_LABELS = {
    "forca_bruta": "FORÇA BRUTA",
    "scanning": "SCANNING",
    "comprometimento": "COMPROMETIMENTO",
}

_TIPO_ORDER = {
    "forca_bruta": 0,
    "scanning": 1,
    "comprometimento": 2,
}


@dataclass(frozen=True)
class ProcessingMetadata:
    """Metadados de processamento do cabeçalho (contrato da seção 9)."""

    total_linhas_lidas: int
    total_eventos_extraidos: int
    periodo_inicio: datetime | None
    periodo_fim: datetime | None


def format_text_report(
    alerts: Sequence[Alert], metadata: ProcessingMetadata
) -> str:
    """Formata o relatório em texto conforme a seção 10.1."""
    ordered = _sorted_alerts(alerts)
    lines = [
        "Análise de auth.log concluída",
        f"Linhas processadas: {metadata.total_linhas_lidas}",
        f"Período: {_format_period(metadata)}",
        f"Alertas encontrados: {len(ordered)}",
        "",
    ]
    if not ordered:
        lines.append("Nenhum alerta gerado.")
    else:
        lines.extend(_format_alert(alert) for alert in ordered)
    return "\n".join(lines) + "\n"


def format_json_report(
    alerts: Sequence[Alert], metadata: ProcessingMetadata
) -> str:
    """Formata o relatório em JSON conforme a seção 10.2."""
    ordered = _sorted_alerts(alerts)
    payload = {
        "linhas_processadas": metadata.total_linhas_lidas,
        "eventos_extraidos": metadata.total_eventos_extraidos,
        "periodo_inicio": _isoformat(metadata.periodo_inicio),
        "periodo_fim": _isoformat(metadata.periodo_fim),
        "alertas_encontrados": len(ordered),
        "alertas": [_alert_as_dict(alert) for alert in ordered],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _sorted_alerts(alerts: Sequence[Alert]) -> list[Alert]:
    """Ordena por tentativas ↓, IP e tipo (seção 10.1) — compartilhado texto/JSON."""
    return sorted(
        alerts,
        key=lambda alert: (
            -alert.numero_tentativas,
            alert.ip_origem,
            _TIPO_ORDER.get(alert.tipo_alerta, 99),
        ),
    )


def _isoformat(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _alert_as_dict(alert: Alert) -> dict:
    return {
        "tipo_alerta": alert.tipo_alerta,
        "ip_origem": alert.ip_origem,
        "usuarios_envolvidos": list(alert.usuarios_envolvidos),
        "numero_tentativas": alert.numero_tentativas,
        "janela_inicio": alert.janela_inicio.isoformat(),
        "janela_fim": alert.janela_fim.isoformat(),
    }


def _format_period(metadata: ProcessingMetadata) -> str:
    if metadata.periodo_inicio is None or metadata.periodo_fim is None:
        return "não determinado (nenhum evento de autenticação encontrado)"
    inicio = metadata.periodo_inicio.strftime("%Y-%m-%d %H:%M:%S")
    fim = metadata.periodo_fim.strftime("%Y-%m-%d %H:%M:%S")
    return f"{inicio} a {fim}"


def _format_alert(alert: Alert) -> str:
    label = _ALERT_LABELS.get(alert.tipo_alerta, alert.tipo_alerta.upper())
    usuarios = ", ".join(alert.usuarios_envolvidos)
    inicio = alert.janela_inicio.strftime("%H:%M:%S")
    fim = alert.janela_fim.strftime("%H:%M:%S")
    return (
        f"[{label}] IP {alert.ip_origem} — {alert.numero_tentativas} tentativas "
        f"— usuários: {usuarios} — {inicio} a {fim}"
    )
