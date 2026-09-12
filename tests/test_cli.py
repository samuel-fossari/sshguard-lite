"""Testes de integração da CLI (Fase 4)."""

from __future__ import annotations

import io
import json
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sshguard_lite.cli import main

SAMPLE_LOG = ROOT / "data" / "samples" / "auth.log"

EXPECTED_SAMPLE_2022 = (
    "Análise de auth.log concluída\n"
    "Linhas processadas: 296\n"
    "Período: 2022-01-24 03:10:01 a 2022-01-24 03:10:37\n"
    "Alertas encontrados: 3\n"
    "\n"
    "[FORÇA BRUTA] IP 203.0.113.88 — 22 tentativas — "
    "usuários: admin, ubuntu, test, oracle, guest, root — "
    "03:10:01 a 03:10:33\n"
    "[SCANNING] IP 203.0.113.88 — 22 tentativas — "
    "usuários: admin, ubuntu, test, oracle, guest, root — "
    "03:10:01 a 03:10:33\n"
    "[COMPROMETIMENTO] IP 203.0.113.88 — 22 tentativas — "
    "usuários: root — 03:10:01 a 03:10:37\n"
)


class CliIntegrationTests(unittest.TestCase):
    def test_sample_log_with_year_2022(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = main([str(SAMPLE_LOG), "--year", "2022"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue(), EXPECTED_SAMPLE_2022)

    def test_missing_file_returns_usage_error(self) -> None:
        missing = ROOT / "data" / "samples" / "nao-existe.log"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = main([str(missing), "--year", "2022"])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        message = stderr.getvalue().lower()
        self.assertIn("erro:", message)
        self.assertIn("não encontrado", message)
        self.assertNotIn("traceback", message)

    def test_missing_year_uses_current_year_without_crash(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = main([str(SAMPLE_LOG)])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        text = stdout.getvalue()
        self.assertIn("Análise de auth.log concluída", text)
        self.assertIn("[FORÇA BRUTA] IP 203.0.113.88 — 22 tentativas", text)
        current_year = datetime.now().year
        self.assertIn(f"Período: {current_year}-01-24", text)
        if current_year != 2022:
            self.assertNotIn("2022-01-24", text)

    def test_json_flag_returns_parseable_json(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = main([str(SAMPLE_LOG), "--year", "2022", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["linhas_processadas"], 296)
        self.assertEqual(payload["eventos_extraidos"], 24)
        self.assertEqual(payload["alertas_encontrados"], 3)
        self.assertEqual(
            [item["tipo_alerta"] for item in payload["alertas"]],
            ["forca_bruta", "scanning", "comprometimento"],
        )
        self.assertNotIn("Análise de auth.log concluída", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
