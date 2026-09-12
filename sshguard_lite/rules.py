"""Módulo de Regras (engine de detecção).

Recebe a lista de eventos estruturados produzida pelo parsing e aplica as
regras de detecção, produzindo uma lista de alertas. Não sabe nada sobre
formato de arquivo nem sobre como o relatório será exibido.

Regras ativas: RD1 (força bruta), RD2 (scanning) e RD3 (comprometimento).
RD1 e RD2 são passagens independentes e não se suprimem (seção 7.2).
RD3 depende dos alertas da RD1 (seção 7.3).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Literal

from sshguard_lite.parser import AuthEvent

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

SCANNING_THRESHOLD = 3
SCANNING_WINDOW_SECONDS = 120

COMPROMISE_WINDOW_SECONDS = 300

_FAILURE_TYPES = frozenset({"failed_password", "invalid_user"})

AlertType = Literal["forca_bruta", "scanning", "comprometimento"]


@dataclass(frozen=True)
class Alert:
    """Alerta produzido pelo engine de regras (contrato da seção 9)."""

    tipo_alerta: AlertType
    ip_origem: str
    usuarios_envolvidos: tuple[str, ...]
    numero_tentativas: int
    janela_inicio: datetime
    janela_fim: datetime


def detect(events: Iterable[AuthEvent]) -> list[Alert]:
    """Aplica RD1, RD2 e RD3. RD1 e RD2 não se suprimem; RD3 parte da RD1."""
    event_list = list(events)
    brute_alerts = detect_brute_force(event_list)
    alerts = (
        brute_alerts
        + detect_scanning(event_list)
        + detect_compromise(event_list, brute_alerts)
    )
    alerts.sort(key=lambda alert: (alert.janela_inicio, alert.ip_origem, alert.tipo_alerta))
    return alerts


def detect_brute_force(events: Iterable[AuthEvent]) -> list[Alert]:
    """RD1: agrupa falhas do mesmo IP em rajadas (seção 7.1).

    Dispara quando a rajada tem ``BRUTE_FORCE_THRESHOLD`` ou mais eventos.
    ``accepted_password`` é ignorado e não quebra a rajada.
    """
    alerts: list[Alert] = []
    for ip_events in _failures_by_ip(events).values():
        for burst in _iter_bursts(ip_events, BRUTE_FORCE_WINDOW_SECONDS):
            if len(burst) >= BRUTE_FORCE_THRESHOLD:
                alerts.append(_alert_from_burst(burst, "forca_bruta"))
    alerts.sort(key=lambda alert: (alert.janela_inicio, alert.ip_origem))
    return alerts


def detect_compromise(
    events: Iterable[AuthEvent], brute_alerts: Iterable[Alert]
) -> list[Alert]:
    """RD3: login aceito após uma rajada de força bruta (seção 7.3).

    Para cada alerta de RD1, usa o primeiro ``accepted_password`` do mesmo
    IP após ``janela_fim``, se estiver dentro de
    ``COMPROMISE_WINDOW_SECONDS``. No máximo um alerta de RD3 por rajada.
    """
    window = timedelta(seconds=COMPROMISE_WINDOW_SECONDS)
    accepted = [
        event
        for event in events
        if event.tipo_evento == "accepted_password"
    ]
    alerts: list[Alert] = []
    for brute in brute_alerts:
        if brute.tipo_alerta != "forca_bruta":
            continue
        chosen = _first_accepted_after(accepted, brute, window)
        if chosen is None:
            continue
        alerts.append(
            Alert(
                tipo_alerta="comprometimento",
                ip_origem=brute.ip_origem,
                usuarios_envolvidos=(chosen.usuario,),
                numero_tentativas=brute.numero_tentativas,
                janela_inicio=brute.janela_inicio,
                janela_fim=chosen.timestamp,
            )
        )
    alerts.sort(key=lambda alert: (alert.janela_inicio, alert.ip_origem))
    return alerts


def _first_accepted_after(
    accepted: list[AuthEvent],
    brute: Alert,
    window: timedelta,
) -> AuthEvent | None:
    candidates = [
        event
        for event in accepted
        if event.ip_origem == brute.ip_origem
        and event.timestamp > brute.janela_fim
        and event.timestamp - brute.janela_fim <= window
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda event: event.timestamp)


def detect_scanning(events: Iterable[AuthEvent]) -> list[Alert]:
    """RD2: enumeração de usuários (seção 7.2).

    Mesmo agrupamento por gap da 7.1, com janela de
    ``SCANNING_WINDOW_SECONDS``. Dispara quando a rajada tem
    ``SCANNING_THRESHOLD`` ou mais usuários distintos. ``numero_tentativas``
    é o total de eventos da rajada, não a contagem de usuários.
    """
    alerts: list[Alert] = []
    for ip_events in _failures_by_ip(events).values():
        for burst in _iter_bursts(ip_events, SCANNING_WINDOW_SECONDS):
            users = _distinct_users(burst)
            if len(users) >= SCANNING_THRESHOLD:
                alerts.append(_alert_from_burst(burst, "scanning", users))
    alerts.sort(key=lambda alert: (alert.janela_inicio, alert.ip_origem))
    return alerts


def _failures_by_ip(events: Iterable[AuthEvent]) -> dict[str, list[AuthEvent]]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.tipo_evento in _FAILURE_TYPES:
            by_ip[event.ip_origem].append(event)
    return by_ip


def _iter_bursts(
    ip_events: list[AuthEvent], window_seconds: int
) -> Iterator[list[AuthEvent]]:
    window = timedelta(seconds=window_seconds)
    ordered = sorted(ip_events, key=lambda item: item.timestamp)
    burst: list[AuthEvent] = []
    for event in ordered:
        if burst and (event.timestamp - burst[-1].timestamp) > window:
            yield burst
            burst = []
        burst.append(event)
    if burst:
        yield burst


def _distinct_users(burst: list[AuthEvent]) -> tuple[str, ...]:
    seen: set[str] = set()
    users: list[str] = []
    for event in burst:
        if event.usuario not in seen:
            seen.add(event.usuario)
            users.append(event.usuario)
    return tuple(users)


def _alert_from_burst(
    burst: list[AuthEvent],
    tipo: AlertType,
    users: tuple[str, ...] | None = None,
) -> Alert:
    return Alert(
        tipo_alerta=tipo,
        ip_origem=burst[0].ip_origem,
        usuarios_envolvidos=users if users is not None else _distinct_users(burst),
        numero_tentativas=len(burst),
        janela_inicio=burst[0].timestamp,
        janela_fim=burst[-1].timestamp,
    )
