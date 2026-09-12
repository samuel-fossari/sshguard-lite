"""Testes unitários do módulo de parsing (Fase 1)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sshguard_lite.parser import AuthEvent, LogFileError, parse_line, parse_lines, parse_log

SAMPLE_LOG = ROOT / "data" / "samples" / "auth.log"
SAMPLE_YEAR = 2022

FAILED_ROOT = (
    "Mar  6 06:19:52 ip-172-31-35-28 sshd[1465]: "
    "Failed password for root from 65.2.161.68 port 51452 ssh2"
)
INVALID_ADMIN = (
    "Mar  6 06:20:01 ip-172-31-35-28 sshd[1471]: "
    "Invalid user admin from 65.2.161.68 port 51460"
)
ACCEPTED_ROOT = (
    "Mar  6 06:32:45 ip-172-31-35-28 sshd[1502]: "
    "Accepted password for root from 65.2.161.68 port 51488 ssh2"
)
FAILED_INVALID = (
    "Jan 24 03:10:02 intranet-server sshd[27001]: "
    "Failed password for invalid user admin from 203.0.113.88 port 41001 ssh2"
)
FAILED_IPV6 = (
    "Jan 24 03:10:35 intranet-server sshd[27018]: "
    "Failed password for root from 2001:db8::88 port 41018 ssh2"
)
PAM_SESSION = (
    "Jan 23 16:30:46 intranet-server sshd[25184]: "
    "pam_unix(sshd:session): session opened for user jhall by (uid=0)"
)
PUBLICKEY = (
    "Jan 23 16:30:46 intranet-server sshd[25184]: "
    "Accepted publickey for jhall from 172.19.131.174 port 49828 ssh2: "
    "RSA SHA256:8wFbiaYPevKS/wYKnePO20v0iymTcrRh4Kr+1uRS1UM"
)
CRON = (
    "Jan 24 03:09:01 intranet-server CRON[27597]: "
    "pam_unix(cron:session): session opened for user root by (uid=0)"
)
NO_IDENT = (
    "Jan 24 03:56:47 intranet-server sshd[27751]: "
    "Did not receive identification string from 172.19.131.174 port 40876"
)


class ParseLineTests(unittest.TestCase):
    def test_failed_password_spec_example(self) -> None:
        event = parse_line(FAILED_ROOT, year=2024)
        self.assertEqual(
            event,
            AuthEvent(
                timestamp=datetime(2024, 3, 6, 6, 19, 52),
                hostname="ip-172-31-35-28",
                pid=1465,
                tipo_evento="failed_password",
                usuario="root",
                ip_origem="65.2.161.68",
                porta_origem=51452,
            ),
        )

    def test_invalid_user_spec_example(self) -> None:
        event = parse_line(INVALID_ADMIN, year=2024)
        self.assertEqual(event.tipo_evento, "invalid_user")
        self.assertEqual(event.usuario, "admin")
        self.assertEqual(event.ip_origem, "65.2.161.68")
        self.assertEqual(event.porta_origem, 51460)

    def test_accepted_password_spec_example(self) -> None:
        event = parse_line(ACCEPTED_ROOT, year=2024)
        self.assertEqual(event.tipo_evento, "accepted_password")
        self.assertEqual(event.usuario, "root")
        self.assertEqual(event.porta_origem, 51488)

    def test_failed_password_for_invalid_user(self) -> None:
        event = parse_line(FAILED_INVALID, year=SAMPLE_YEAR)
        self.assertIsNotNone(event)
        self.assertEqual(event.tipo_evento, "failed_password")
        self.assertEqual(event.usuario, "admin")
        self.assertEqual(event.ip_origem, "203.0.113.88")

    def test_ipv6_source_address(self) -> None:
        event = parse_line(FAILED_IPV6, year=SAMPLE_YEAR)
        self.assertIsNotNone(event)
        self.assertEqual(event.ip_origem, "2001:db8::88")
        self.assertEqual(event.porta_origem, 41018)

    def test_ignores_pam_sshd_without_auth_pattern(self) -> None:
        self.assertIsNone(parse_line(PAM_SESSION, year=SAMPLE_YEAR))

    def test_ignores_accepted_publickey(self) -> None:
        self.assertIsNone(parse_line(PUBLICKEY, year=SAMPLE_YEAR))

    def test_ignores_cron_and_unrelated_lines(self) -> None:
        self.assertIsNone(parse_line(CRON, year=SAMPLE_YEAR))
        self.assertIsNone(parse_line(NO_IDENT, year=SAMPLE_YEAR))
        self.assertIsNone(parse_line("", year=SAMPLE_YEAR))
        self.assertIsNone(parse_line("not a syslog line", year=SAMPLE_YEAR))

    def test_syslog_day_without_leading_zero(self) -> None:
        line = (
            "Mar  6 06:19:52 host sshd[1]: "
            "Failed password for root from 10.0.0.1 port 22 ssh2"
        )
        event = parse_line(line, year=2024)
        self.assertEqual(event.timestamp.day, 6)


class ParseLinesAndFileTests(unittest.TestCase):
    def test_parse_lines_keeps_only_relevant_events(self) -> None:
        events = parse_lines(
            [CRON, FAILED_ROOT, PAM_SESSION, INVALID_ADMIN, PUBLICKEY],
            year=2024,
        )
        self.assertEqual([e.tipo_evento for e in events], ["failed_password", "invalid_user"])

    def test_parse_log_sample_extracts_fixture_burst(self) -> None:
        events = parse_log(SAMPLE_LOG, year=SAMPLE_YEAR)
        types = [e.tipo_evento for e in events]
        self.assertEqual(types.count("invalid_user"), 5)
        self.assertEqual(types.count("failed_password"), 18)
        self.assertEqual(types.count("accepted_password"), 1)
        self.assertEqual(len(events), 24)
        self.assertTrue(all(e.hostname == "intranet-server" for e in events))
        self.assertIn("203.0.113.88", {e.ip_origem for e in events})
        self.assertIn("2001:db8::88", {e.ip_origem for e in events})

    def test_missing_file_raises_clear_error(self) -> None:
        missing = ROOT / "data" / "samples" / "nao-existe.log"
        with self.assertRaises(LogFileError) as ctx:
            parse_log(missing)
        self.assertIn("não encontrado", str(ctx.exception).lower())

    def test_empty_file_raises_clear_error(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
            empty_path = Path(tmp.name)
        try:
            with self.assertRaises(LogFileError) as ctx:
                parse_log(empty_path)
            self.assertIn("vazio", str(ctx.exception).lower())
        finally:
            empty_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
