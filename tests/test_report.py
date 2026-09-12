"""Testes unitários do relatório em texto (Fase 3)."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sshguard_lite.parser import parse_log
from sshguard_lite.report import (
    ProcessingMetadata,
    format_json_report,
    format_text_report,
)
from sshguard_lite.rules import Alert, detect_brute_force

SAMPLE_LOG = ROOT / "data" / "samples" / "auth.log"


def _alert(
    ip: str,
    tentativas: int,
    usuarios: tuple[str, ...],
    inicio: datetime,
    fim: datetime,
) -> Alert:
    return Alert(
        tipo_alerta="forca_bruta",
        ip_origem=ip,
        usuarios_envolvidos=usuarios,
        numero_tentativas=tentativas,
        janela_inicio=inicio,
        janela_fim=fim,
    )


class FormatTextReportTests(unittest.TestCase):
    def test_multiple_alerts_sorted_by_attempts_desc(self) -> None:
        metadata = ProcessingMetadata(
            total_linhas_lidas=4213,
            total_eventos_extraidos=80,
            periodo_inicio=datetime(2024, 3, 6, 0, 0, 0),
            periodo_fim=datetime(2024, 3, 6, 23, 59, 0),
        )
        alerts = [
            _alert(
                "139.155.14.86",
                12,
                ("www", "ftp"),
                datetime(2024, 3, 6, 8, 2, 10),
                datetime(2024, 3, 6, 8, 4, 33),
            ),
            _alert(
                "65.2.161.68",
                47,
                ("root", "admin"),
                datetime(2024, 3, 6, 6, 18, 1),
                datetime(2024, 3, 6, 6, 19, 52),
            ),
        ]
        text = format_text_report(alerts, metadata)
        self.assertEqual(
            text,
            "Análise de auth.log concluída\n"
            "Linhas processadas: 4213\n"
            "Período: 2024-03-06 00:00:00 a 2024-03-06 23:59:00\n"
            "Alertas encontrados: 2\n"
            "\n"
            "[FORÇA BRUTA] IP 65.2.161.68 — 47 tentativas — "
            "usuários: root, admin — 06:18:01 a 06:19:52\n"
            "[FORÇA BRUTA] IP 139.155.14.86 — 12 tentativas — "
            "usuários: www, ftp — 08:02:10 a 08:04:33\n",
        )

    def test_events_without_alerts(self) -> None:
        metadata = ProcessingMetadata(
            total_linhas_lidas=50,
            total_eventos_extraidos=3,
            periodo_inicio=datetime(2022, 1, 24, 3, 0, 0),
            periodo_fim=datetime(2022, 1, 24, 4, 0, 0),
        )
        text = format_text_report([], metadata)
        self.assertEqual(
            text,
            "Análise de auth.log concluída\n"
            "Linhas processadas: 50\n"
            "Período: 2022-01-24 03:00:00 a 2022-01-24 04:00:00\n"
            "Alertas encontrados: 0\n"
            "\n"
            "Nenhum alerta gerado.\n",
        )

    def test_zero_events(self) -> None:
        metadata = ProcessingMetadata(
            total_linhas_lidas=10,
            total_eventos_extraidos=0,
            periodo_inicio=None,
            periodo_fim=None,
        )
        text = format_text_report([], metadata)
        self.assertEqual(
            text,
            "Análise de auth.log concluída\n"
            "Linhas processadas: 10\n"
            "Período: não determinado (nenhum evento de autenticação encontrado)\n"
            "Alertas encontrados: 0\n"
            "\n"
            "Nenhum alerta gerado.\n",
        )

    def test_tie_breaks_by_alert_type_order(self) -> None:
        inicio = datetime(2022, 1, 24, 3, 10, 1)
        fim = datetime(2022, 1, 24, 3, 10, 33)
        metadata = ProcessingMetadata(
            total_linhas_lidas=296,
            total_eventos_extraidos=24,
            periodo_inicio=inicio,
            periodo_fim=datetime(2022, 1, 24, 3, 10, 37),
        )
        alerts = [
            Alert(
                tipo_alerta="comprometimento",
                ip_origem="203.0.113.88",
                usuarios_envolvidos=("root",),
                numero_tentativas=22,
                janela_inicio=inicio,
                janela_fim=datetime(2022, 1, 24, 3, 10, 37),
            ),
            Alert(
                tipo_alerta="scanning",
                ip_origem="203.0.113.88",
                usuarios_envolvidos=("admin", "root"),
                numero_tentativas=22,
                janela_inicio=inicio,
                janela_fim=fim,
            ),
            Alert(
                tipo_alerta="forca_bruta",
                ip_origem="203.0.113.88",
                usuarios_envolvidos=("admin", "root"),
                numero_tentativas=22,
                janela_inicio=inicio,
                janela_fim=fim,
            ),
        ]
        text = format_text_report(alerts, metadata)
        labels = [
            line.split("]", 1)[0] + "]"
            for line in text.splitlines()
            if line.startswith("[")
        ]
        self.assertEqual(labels, ["[FORÇA BRUTA]", "[SCANNING]", "[COMPROMETIMENTO]"])


class FormatJsonReportTests(unittest.TestCase):
    def test_multiple_alerts_roundtrip(self) -> None:
        metadata = ProcessingMetadata(
            total_linhas_lidas=4213,
            total_eventos_extraidos=58,
            periodo_inicio=datetime(2024, 3, 6, 0, 0, 0),
            periodo_fim=datetime(2024, 3, 6, 23, 59, 0),
        )
        alerts = [
            _alert(
                "139.155.14.86",
                12,
                ("www", "ftp"),
                datetime(2024, 3, 6, 8, 2, 10),
                datetime(2024, 3, 6, 8, 4, 33),
            ),
            _alert(
                "65.2.161.68",
                47,
                ("root", "admin"),
                datetime(2024, 3, 6, 6, 18, 1),
                datetime(2024, 3, 6, 6, 19, 52),
            ),
        ]
        payload = json.loads(format_json_report(alerts, metadata))
        self.assertEqual(payload["linhas_processadas"], 4213)
        self.assertEqual(payload["eventos_extraidos"], 58)
        self.assertEqual(payload["periodo_inicio"], "2024-03-06T00:00:00")
        self.assertEqual(payload["periodo_fim"], "2024-03-06T23:59:00")
        self.assertEqual(payload["alertas_encontrados"], 2)
        self.assertEqual(
            [item["ip_origem"] for item in payload["alertas"]],
            ["65.2.161.68", "139.155.14.86"],
        )
        first = payload["alertas"][0]
        self.assertEqual(first["tipo_alerta"], "forca_bruta")
        self.assertEqual(first["usuarios_envolvidos"], ["root", "admin"])
        self.assertEqual(first["numero_tentativas"], 47)
        self.assertEqual(first["janela_inicio"], "2024-03-06T06:18:01")
        self.assertEqual(first["janela_fim"], "2024-03-06T06:19:52")

    def test_zero_events_uses_null_period(self) -> None:
        metadata = ProcessingMetadata(
            total_linhas_lidas=10,
            total_eventos_extraidos=0,
            periodo_inicio=None,
            periodo_fim=None,
        )
        payload = json.loads(format_json_report([], metadata))
        self.assertIsNone(payload["periodo_inicio"])
        self.assertIsNone(payload["periodo_fim"])
        self.assertEqual(payload["eventos_extraidos"], 0)
        self.assertEqual(payload["alertas"], [])
        self.assertEqual(payload["alertas_encontrados"], 0)

    def test_events_without_alerts_uses_empty_list(self) -> None:
        metadata = ProcessingMetadata(
            total_linhas_lidas=50,
            total_eventos_extraidos=3,
            periodo_inicio=datetime(2022, 1, 24, 3, 0, 0),
            periodo_fim=datetime(2022, 1, 24, 4, 0, 0),
        )
        payload = json.loads(format_json_report([], metadata))
        self.assertEqual(payload["alertas"], [])
        self.assertIsInstance(payload["alertas"], list)
        self.assertIsNotNone(payload["periodo_inicio"])
        self.assertEqual(payload["alertas_encontrados"], 0)


class SampleLogReportTests(unittest.TestCase):
    def test_sample_log_matches_phase2_alert(self) -> None:
        with SAMPLE_LOG.open(encoding="utf-8") as handle:
            line_count = sum(1 for _ in handle)
        events = parse_log(SAMPLE_LOG, year=2022)
        alerts = detect_brute_force(events)
        metadata = ProcessingMetadata(
            total_linhas_lidas=line_count,
            total_eventos_extraidos=len(events),
            periodo_inicio=min(event.timestamp for event in events),
            periodo_fim=max(event.timestamp for event in events),
        )
        text = format_text_report(alerts, metadata)
        self.assertEqual(
            text,
            "Análise de auth.log concluída\n"
            "Linhas processadas: 296\n"
            "Período: 2022-01-24 03:10:01 a 2022-01-24 03:10:37\n"
            "Alertas encontrados: 1\n"
            "\n"
            "[FORÇA BRUTA] IP 203.0.113.88 — 22 tentativas — "
            "usuários: admin, ubuntu, test, oracle, guest, root — "
            "03:10:01 a 03:10:33\n",
        )


if __name__ == "__main__":
    unittest.main()
