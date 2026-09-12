"""Módulo de Parsing.

Lê um arquivo de log linha a linha e converte cada linha relevante em um
evento estruturado de autenticação SSH. Não sabe nada sobre regras de
detecção.

Linhas que não batem com os padrões sshd da especificação (seção 5) são
ignoradas silenciosamente — inclusive PAM auxiliar, cron, publickey e
mensagens sshd sem IP.

Limitação conhecida: o formato syslog tradicional não inclui o ano. Por
padrão usa-se o ano corrente do sistema; o chamador pode informar `year`
explicitamente (recomendado ao processar recortes históricos como o
AIT-LDS de 2022).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Literal, TextIO

EventType = Literal["failed_password", "invalid_user", "accepted_password"]

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_SYSLOG_SSHD = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<msg>.*)$"
)

# IPv4, IPv6 (com ou sem colchetes) — o endereço vai até " port"
_IP = r"\[?(?P<ip>[0-9a-fA-F:.]+)\]?"

_FAILED_PASSWORD = re.compile(
    rf"^Failed password for (?:invalid user )?(?P<user>\S+) from {_IP} port (?P<port>\d+)\b"
)
_INVALID_USER = re.compile(
    rf"^Invalid user (?P<user>\S+) from {_IP}(?: port (?P<port>\d+))?\b"
)
_ACCEPTED_PASSWORD = re.compile(
    rf"^Accepted password for (?P<user>\S+) from {_IP} port (?P<port>\d+)\b"
)


class LogFileError(Exception):
    """Erro de leitura do arquivo de log, com mensagem clara para o usuário."""


@dataclass(frozen=True)
class AuthEvent:
    """Evento de autenticação SSH extraído de uma linha de auth.log."""

    timestamp: datetime
    hostname: str
    pid: int
    tipo_evento: EventType
    usuario: str
    ip_origem: str
    porta_origem: int | None


def parse_line(line: str, *, year: int | None = None) -> AuthEvent | None:
    """Converte uma linha de log em evento, ou None se irrelevante/malformada."""
    match = _SYSLOG_SSHD.match(line.rstrip("\n\r"))
    if match is None:
        return None

    timestamp = _parse_timestamp(
        match.group("mon"),
        match.group("day"),
        match.group("time"),
        _resolve_year(year),
    )
    if timestamp is None:
        return None

    hostname = match.group("host")
    pid = int(match.group("pid"))
    msg = match.group("msg").strip()

    failed = _FAILED_PASSWORD.match(msg)
    if failed:
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            pid=pid,
            tipo_evento="failed_password",
            usuario=failed.group("user"),
            ip_origem=failed.group("ip"),
            porta_origem=int(failed.group("port")),
        )

    invalid = _INVALID_USER.match(msg)
    if invalid:
        port = invalid.group("port")
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            pid=pid,
            tipo_evento="invalid_user",
            usuario=invalid.group("user"),
            ip_origem=invalid.group("ip"),
            porta_origem=int(port) if port else None,
        )

    accepted = _ACCEPTED_PASSWORD.match(msg)
    if accepted:
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            pid=pid,
            tipo_evento="accepted_password",
            usuario=accepted.group("user"),
            ip_origem=accepted.group("ip"),
            porta_origem=int(accepted.group("port")),
        )

    return None


def parse_lines(lines: Iterable[str], *, year: int | None = None) -> list[AuthEvent]:
    """Extrai eventos de um iterável de linhas, ignorando as irrelevantes."""
    events: list[AuthEvent] = []
    for line in lines:
        event = parse_line(line, year=year)
        if event is not None:
            events.append(event)
    return events


def parse_log(path: str | Path, *, year: int | None = None) -> list[AuthEvent]:
    """Lê um arquivo auth.log e devolve os eventos de autenticação SSH."""
    log_path = Path(path)
    if not log_path.exists():
        raise LogFileError(f"Arquivo não encontrado: {log_path}")
    if not log_path.is_file():
        raise LogFileError(f"Caminho não é um arquivo: {log_path}")
    if log_path.stat().st_size == 0:
        raise LogFileError(f"Arquivo de log vazio: {log_path}")

    with log_path.open(encoding="utf-8", errors="replace") as handle:
        return _parse_stream(handle, year=_resolve_year(year))


def _parse_stream(handle: TextIO, *, year: int) -> list[AuthEvent]:
    return parse_lines(handle, year=year)


def _resolve_year(year: int | None) -> int:
    return datetime.now().year if year is None else year


def _parse_timestamp(
    mon: str, day: str, time_str: str, year: int
) -> datetime | None:
    month = _MONTHS.get(mon)
    if month is None:
        return None
    try:
        hour, minute, second = (int(part) for part in time_str.split(":"))
        return datetime(year, month, int(day), hour, minute, second)
    except ValueError:
        return None
