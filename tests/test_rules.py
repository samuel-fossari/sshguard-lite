"""Testes unitários da RD1 — força bruta (Fase 2)."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sshguard_lite.parser import AuthEvent, parse_log
from sshguard_lite.rules import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    COMPROMISE_WINDOW_SECONDS,
    SCANNING_THRESHOLD,
    detect,
    detect_brute_force,
    detect_compromise,
    detect_scanning,
)

SAMPLE_LOG = ROOT / "data" / "samples" / "auth.log"
T0 = datetime(2022, 1, 24, 3, 10, 0)


def _event(
    offset_s: int,
    *,
    ip: str = "203.0.113.88",
    usuario: str = "root",
    tipo: str = "failed_password",
    pid: int = 1000,
) -> AuthEvent:
    return AuthEvent(
        timestamp=T0 + timedelta(seconds=offset_s),
        hostname="intranet-server",
        pid=pid,
        tipo_evento=tipo,  # type: ignore[arg-type]
        usuario=usuario,
        ip_origem=ip,
        porta_origem=41000,
    )


def _failures(count: int, *, gap_s: int = 2, ip: str = "203.0.113.88") -> list[AuthEvent]:
    return [_event(i * gap_s, ip=ip, pid=1000 + i) for i in range(count)]


class BruteForceThresholdTests(unittest.TestCase):
    def test_exactly_threshold_generates_one_alert(self) -> None:
        alerts = detect_brute_force(_failures(BRUTE_FORCE_THRESHOLD))
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.tipo_alerta, "forca_bruta")
        self.assertEqual(alert.ip_origem, "203.0.113.88")
        self.assertEqual(alert.numero_tentativas, BRUTE_FORCE_THRESHOLD)
        self.assertEqual(alert.usuarios_envolvidos, ("root",))
        self.assertEqual(alert.janela_inicio, T0)
        self.assertEqual(
            alert.janela_fim,
            T0 + timedelta(seconds=2 * (BRUTE_FORCE_THRESHOLD - 1)),
        )

    def test_below_threshold_generates_no_alert(self) -> None:
        alerts = detect_brute_force(_failures(BRUTE_FORCE_THRESHOLD - 1))
        self.assertEqual(alerts, [])


class BruteForceIsolationTests(unittest.TestCase):
    def test_different_ips_are_not_pooled(self) -> None:
        events = _failures(4, ip="203.0.113.10") + _failures(4, ip="203.0.113.20")
        self.assertEqual(detect_brute_force(events), [])

    def test_accepted_password_does_not_count_or_break_burst(self) -> None:
        events = [
            _event(0),
            _event(2),
            _event(4, tipo="accepted_password", usuario="root"),
            _event(6),
            _event(8),
            _event(10),
        ]
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].numero_tentativas, 5)
        self.assertEqual(alerts[0].janela_inicio, T0)
        self.assertEqual(alerts[0].janela_fim, T0 + timedelta(seconds=10))


class BruteForceBurstGroupingTests(unittest.TestCase):
    def test_long_continuous_burst_is_single_alert(self) -> None:
        # 20 falhas a cada 10s = 190s de duração total, todos os gaps < 60s
        events = _failures(20, gap_s=10)
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].numero_tentativas, 20)
        self.assertEqual(alerts[0].janela_inicio, T0)
        self.assertEqual(alerts[0].janela_fim, T0 + timedelta(seconds=190))
        self.assertGreater(
            alerts[0].janela_fim - alerts[0].janela_inicio,
            timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS),
        )

    def test_gap_over_window_splits_into_two_alerts(self) -> None:
        first = _failures(5, gap_s=2)
        # último da 1ª rajada em t=8; gap > 60s até o início da 2ª
        second_start = 8 + BRUTE_FORCE_WINDOW_SECONDS + 1
        second = [
            _event(second_start + i * 2, pid=2000 + i, usuario="admin")
            for i in range(5)
        ]
        alerts = detect_brute_force(first + second)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0].numero_tentativas, 5)
        self.assertEqual(alerts[0].usuarios_envolvidos, ("root",))
        self.assertEqual(alerts[1].numero_tentativas, 5)
        self.assertEqual(alerts[1].usuarios_envolvidos, ("admin",))
        self.assertLess(alerts[0].janela_fim, alerts[1].janela_inicio)

    def test_users_listed_in_first_seen_order_without_duplicates(self) -> None:
        events = [
            _event(0, usuario="admin", tipo="invalid_user"),
            _event(1, usuario="admin", tipo="failed_password"),
            _event(2, usuario="root"),
            _event(3, usuario="admin"),
            _event(4, usuario="guest", tipo="invalid_user"),
        ]
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].usuarios_envolvidos, ("admin", "root", "guest"))


class ScanningRuleTests(unittest.TestCase):
    def test_distinct_users_only_fires_scanning(self) -> None:
        events = [
            _event(0, usuario="admin"),
            _event(2, usuario="ubuntu"),
            _event(4, usuario="test"),
        ]
        self.assertEqual(len(events), SCANNING_THRESHOLD)
        self.assertLess(len(events), BRUTE_FORCE_THRESHOLD)
        self.assertEqual(detect_brute_force(events), [])
        alerts = detect_scanning(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].tipo_alerta, "scanning")
        self.assertEqual(alerts[0].numero_tentativas, 3)
        self.assertEqual(alerts[0].usuarios_envolvidos, ("admin", "ubuntu", "test"))

    def test_volume_only_fires_brute_force(self) -> None:
        events = _failures(6)
        self.assertEqual(detect_scanning(events), [])
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].tipo_alerta, "forca_bruta")
        self.assertEqual(alerts[0].usuarios_envolvidos, ("root",))

    def test_both_thresholds_emit_two_separate_alerts(self) -> None:
        events = [
            _event(0, usuario="admin"),
            _event(2, usuario="ubuntu"),
            _event(4, usuario="test"),
            _event(6, usuario="admin"),
            _event(8, usuario="ubuntu"),
        ]
        alerts = detect(events)
        types = [alert.tipo_alerta for alert in alerts]
        self.assertEqual(types, ["forca_bruta", "scanning"])
        brute, scanning = alerts
        self.assertEqual(brute.numero_tentativas, 5)
        self.assertEqual(scanning.numero_tentativas, 5)
        self.assertEqual(brute.usuarios_envolvidos, ("admin", "ubuntu", "test"))
        self.assertEqual(scanning.usuarios_envolvidos, ("admin", "ubuntu", "test"))

    def test_different_ips_are_not_pooled_for_scanning(self) -> None:
        events = [
            _event(0, ip="203.0.113.10", usuario="admin"),
            _event(2, ip="203.0.113.10", usuario="ubuntu"),
            _event(0, ip="203.0.113.20", usuario="test"),
            _event(2, ip="203.0.113.20", usuario="oracle"),
        ]
        self.assertEqual(detect_scanning(events), [])
        self.assertEqual(detect(events), [])


class CompromiseRuleTests(unittest.TestCase):
    def test_accepted_within_window_generates_alert(self) -> None:
        failures = _failures(5)
        accepted = _event(20, tipo="accepted_password", usuario="root")
        brute = detect_brute_force(failures)
        alerts = detect_compromise(failures + [accepted], brute)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.tipo_alerta, "comprometimento")
        self.assertEqual(alert.ip_origem, "203.0.113.88")
        self.assertEqual(alert.usuarios_envolvidos, ("root",))
        self.assertEqual(alert.numero_tentativas, 5)
        self.assertEqual(alert.janela_inicio, brute[0].janela_inicio)
        self.assertEqual(alert.janela_fim, accepted.timestamp)

    def test_accepted_after_window_generates_nothing(self) -> None:
        failures = _failures(5)
        brute = detect_brute_force(failures)
        late = brute[0].janela_fim + timedelta(seconds=COMPROMISE_WINDOW_SECONDS + 1)
        offset = int((late - T0).total_seconds())
        accepted = _event(offset, tipo="accepted_password", usuario="root")
        self.assertEqual(detect_compromise(failures + [accepted], brute), [])

    def test_no_accepted_generates_nothing(self) -> None:
        failures = _failures(5)
        brute = detect_brute_force(failures)
        self.assertEqual(detect_compromise(failures, brute), [])

    def test_multiple_accepted_uses_the_first(self) -> None:
        failures = _failures(5)
        first = _event(20, tipo="accepted_password", usuario="root")
        second = _event(40, tipo="accepted_password", usuario="admin")
        brute = detect_brute_force(failures)
        alerts = detect_compromise(failures + [second, first], brute)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].usuarios_envolvidos, ("root",))
        self.assertEqual(alerts[0].janela_fim, first.timestamp)


class SampleLogValidationTests(unittest.TestCase):
    def test_sample_synthetic_burst_raises_expected_alert(self) -> None:
        events = parse_log(SAMPLE_LOG, year=2022)
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.tipo_alerta, "forca_bruta")
        self.assertEqual(alert.ip_origem, "203.0.113.88")
        self.assertEqual(alert.numero_tentativas, 22)
        self.assertEqual(
            alert.usuarios_envolvidos,
            ("admin", "ubuntu", "test", "oracle", "guest", "root"),
        )
        self.assertEqual(alert.janela_inicio, datetime(2022, 1, 24, 3, 10, 1))
        self.assertEqual(alert.janela_fim, datetime(2022, 1, 24, 3, 10, 33))

    def test_sample_fires_brute_force_scanning_and_compromise(self) -> None:
        events = parse_log(SAMPLE_LOG, year=2022)
        alerts = detect(events)
        self.assertEqual(
            [alert.tipo_alerta for alert in alerts],
            ["comprometimento", "forca_bruta", "scanning"],
        )
        compromise = next(alert for alert in alerts if alert.tipo_alerta == "comprometimento")
        brute = next(alert for alert in alerts if alert.tipo_alerta == "forca_bruta")
        scanning = next(alert for alert in alerts if alert.tipo_alerta == "scanning")
        users = ("admin", "ubuntu", "test", "oracle", "guest", "root")
        for alert in (brute, scanning):
            self.assertEqual(alert.ip_origem, "203.0.113.88")
            self.assertEqual(alert.numero_tentativas, 22)
            self.assertEqual(alert.usuarios_envolvidos, users)
            self.assertEqual(alert.janela_inicio, datetime(2022, 1, 24, 3, 10, 1))
            self.assertEqual(alert.janela_fim, datetime(2022, 1, 24, 3, 10, 33))
        self.assertGreaterEqual(len(scanning.usuarios_envolvidos), SCANNING_THRESHOLD)
        self.assertEqual(compromise.ip_origem, "203.0.113.88")
        self.assertEqual(compromise.usuarios_envolvidos, ("root",))
        self.assertEqual(compromise.numero_tentativas, 22)
        self.assertEqual(compromise.janela_inicio, datetime(2022, 1, 24, 3, 10, 1))
        self.assertEqual(compromise.janela_fim, datetime(2022, 1, 24, 3, 10, 37))


if __name__ == "__main__":
    unittest.main()
