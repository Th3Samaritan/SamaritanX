"""Structured logging tied to the rich console used by the dashboard."""
from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True, soft_wrap=True)


def get_console() -> Console:
    return _console


def configure_logging(verbose: bool = False, log_file: str | Path | None = None) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [
        RichHandler(
            console=_console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
    ]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        handlers.append(fh)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )
    return logging.getLogger("samaritanx")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"samaritanx.{name}")
