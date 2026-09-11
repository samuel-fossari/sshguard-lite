"""Smoke test da Fase 0.

Confirma que o ambiente Python está funcional e que o recorte de auth.log
de exemplo pode ser aberto e lido linha a linha — sem extração de eventos.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = ROOT / "data" / "samples" / "auth.log"


def test_python_version() -> None:
    assert sys.version_info >= (3, 10), (
        f"Python 3.10+ é obrigatório; encontrado {sys.version}"
    )


def test_package_importable() -> None:
    sys.path.insert(0, str(ROOT))
    import sshguard_lite  # noqa: F401


def test_sample_log_readable() -> None:
    assert SAMPLE_LOG.is_file(), f"Arquivo de exemplo ausente: {SAMPLE_LOG}"
    line_count = 0
    with SAMPLE_LOG.open(encoding="utf-8", errors="replace") as handle:
        for _line in handle:
            line_count += 1
    assert line_count >= 100, (
        f"O recorte de exemplo deveria ter algumas centenas de linhas; obtido {line_count}"
    )


def main() -> int:
    checks = (
        test_python_version,
        test_package_importable,
        test_sample_log_readable,
    )
    for check in checks:
        check()
        print(f"OK  {check.__name__}")
    with SAMPLE_LOG.open(encoding="utf-8", errors="replace") as handle:
        line_count = sum(1 for _ in handle)
    print(f"Smoke test passou. Linhas no exemplo: {line_count}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
