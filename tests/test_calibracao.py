"""Validação formal do corpus sintético dirigido (Fase 8 / seção 11)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sshguard_lite.parser import parse_log
from sshguard_lite.report import ProcessingMetadata, format_json_report
from sshguard_lite.rules import detect

CALIBRACAO = ROOT / "data" / "samples" / "calibracao"
YEAR = 2024


def _pipeline(filename: str):
    path = CALIBRACAO / filename
    events = parse_log(path, year=YEAR)
    alerts = detect(events)
    with path.open(encoding="utf-8") as handle:
        total_linhas = sum(1 for _ in handle)
    metadata = ProcessingMetadata(
        total_linhas_lidas=total_linhas,
        total_eventos_extraidos=len(events),
        periodo_inicio=min((e.timestamp for e in events), default=None),
        periodo_fim=max((e.timestamp for e in events), default=None),
    )
    payload = json.loads(format_json_report(alerts, metadata))
    return events, alerts, payload


def _types_by_ip(alerts):
    by_ip: dict[str, list[str]] = {}
    for alert in alerts:
        by_ip.setdefault(alert.ip_origem, []).append(alert.tipo_alerta)
    return by_ip


class CorpusCalibracaoTests(unittest.TestCase):
    def test_01_limiar_exato_dispara_rd1_e_rd2(self) -> None:
        events, alerts, payload = _pipeline("01_limiar_exato.log")
        self.assertEqual(len(events), 8)
        by_ip = _types_by_ip(alerts)
        self.assertEqual(by_ip["203.0.113.10"], ["forca_bruta"])
        self.assertEqual(by_ip["203.0.113.11"], ["scanning"])
        brute = next(a for a in alerts if a.ip_origem == "203.0.113.10")
        scanning = next(a for a in alerts if a.ip_origem == "203.0.113.11")
        self.assertEqual(brute.numero_tentativas, 5)
        self.assertEqual(scanning.usuarios_envolvidos, ("admin", "ubuntu", "test"))
        self.assertEqual(payload["alertas_encontrados"], 2)

    def test_02_abaixo_limiar_nao_gera_alerta(self) -> None:
        events, alerts, payload = _pipeline("02_abaixo_limiar.log")
        self.assertEqual(len(events), 6)
        self.assertEqual(alerts, [])
        self.assertEqual(payload["alertas"], [])

    def test_03_trafego_normal_nao_gera_alerta(self) -> None:
        _events, alerts, payload = _pipeline("03_trafego_normal.log")
        self.assertEqual(alerts, [])
        self.assertEqual(payload["alertas_encontrados"], 0)

    def test_04_multiplos_ips_nao_misturam_contagens(self) -> None:
        _events, alerts, payload = _pipeline("04_multiplos_ips.log")
        brute = [a for a in alerts if a.tipo_alerta == "forca_bruta"]
        self.assertEqual({a.ip_origem for a in brute}, {"203.0.113.30", "203.0.113.40"})
        self.assertTrue(all(a.numero_tentativas == 5 for a in brute))
        self.assertFalse(any(a.tipo_alerta == "scanning" for a in alerts))
        self.assertEqual(payload["alertas_encontrados"], 2)

    def test_05_rd3_dentro_e_fora_da_janela(self) -> None:
        _events, alerts, payload = _pipeline("05_rd3_janela.log")
        by_ip = _types_by_ip(alerts)
        self.assertIn("forca_bruta", by_ip["203.0.113.50"])
        self.assertIn("comprometimento", by_ip["203.0.113.50"])
        self.assertEqual(by_ip["203.0.113.60"], ["forca_bruta"])
        compromise = next(a for a in alerts if a.tipo_alerta == "comprometimento")
        self.assertEqual(compromise.ip_origem, "203.0.113.50")
        self.assertEqual(compromise.usuarios_envolvidos, ("root",))
        self.assertEqual(payload["alertas_encontrados"], 3)


if __name__ == "__main__":
    unittest.main()
