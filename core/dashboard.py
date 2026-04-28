"""Live CLI dashboard built on rich.Live.

Renders agent status, queue depth, asset/finding counters and a scrolling log
of significant events. Agents push state via .update(...) and .event(...).
"""
from __future__ import annotations

import time
from collections import deque
from threading import RLock

import pyfiglet
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .logger import get_console


class Dashboard:
    def __init__(self, target: str, operator: str = "th3Samaritan") -> None:
        self.console: Console = get_console()
        self.target = target
        self.operator = operator
        self.start_time = time.time()
        self._lock = RLock()
        self._agents: dict[str, dict] = {}
        self._counters: dict[str, int] = {
            "subdomains": 0, "endpoints": 0, "params": 0,
            "requests": 0, "findings": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0,
        }
        self._events: deque[tuple[float, str, str]] = deque(maxlen=18)
        self._live: Live | None = None
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self._tasks: dict[str, int] = {}

    # ---------- lifecycle ----------
    def __enter__(self) -> "Dashboard":
        layout = self._render()
        self._live = Live(layout, console=self.console, refresh_per_second=4, screen=False)
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.__exit__(*exc)
            self._live = None

    # ---------- public API used by agents ----------
    def update_agent(self, name: str, status: str, detail: str = "") -> None:
        with self._lock:
            self._agents[name] = {"status": status, "detail": detail, "ts": time.time()}
            self._refresh()

    def add_count(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + n
            self._refresh()

    def event(self, level: str, message: str) -> None:
        with self._lock:
            self._events.appendleft((time.time(), level, message))
            self._refresh()

    def task(self, name: str, total: int) -> None:
        with self._lock:
            if name in self._tasks:
                self._progress.update(self._tasks[name], total=total)
            else:
                self._tasks[name] = self._progress.add_task(name, total=total)
            self._refresh()

    def advance(self, name: str, n: int = 1) -> None:
        with self._lock:
            tid = self._tasks.get(name)
            if tid is not None:
                self._progress.advance(tid, n)
                self._refresh()

    # ---------- rendering ----------
    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    def _banner(self) -> Panel:
        art = pyfiglet.figlet_format("SamaritanX", font="slant")
        sub = Text.assemble(
            ("operator: ", "dim"), (self.operator, "bold green"),
            ("   target: ", "dim"), (self.target, "bold cyan"),
            ("   uptime: ", "dim"), (f"{int(time.time()-self.start_time)}s", "bold"),
        )
        body = Group(Text(art.rstrip(), style="bold magenta"), Align.center(sub))
        return Panel(body, border_style="magenta", padding=(0, 1))

    def _agents_table(self) -> Panel:
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column("agent", style="cyan", no_wrap=True)
        t.add_column("status", style="green", no_wrap=True)
        t.add_column("detail", style="white")
        for name in sorted(self._agents):
            a = self._agents[name]
            color = {
                "running": "green", "idle": "yellow", "done": "blue",
                "error": "red", "queued": "magenta",
            }.get(a["status"], "white")
            t.add_row(name, Text(a["status"], style=color), a["detail"][:80])
        return Panel(t, title="agents", border_style="cyan")

    def _counters_panel(self) -> Panel:
        t = Table.grid(expand=True)
        t.add_column(style="dim", no_wrap=True)
        t.add_column(style="bold", justify="right")
        for k in ("subdomains", "endpoints", "params", "requests", "findings",
                  "critical", "high", "medium", "low", "info"):
            color = {
                "critical": "red", "high": "magenta",
                "medium": "yellow", "low": "cyan", "info": "white",
            }.get(k, "green")
            t.add_row(k, Text(str(self._counters.get(k, 0)), style=color))
        return Panel(t, title="metrics", border_style="green")

    def _events_panel(self) -> Panel:
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(no_wrap=True, style="dim", width=8)
        t.add_column(no_wrap=True, width=8)
        t.add_column()
        for ts, level, msg in list(self._events):
            color = {"crit": "red", "high": "magenta", "med": "yellow",
                     "low": "cyan", "info": "white", "ok": "green",
                     "err": "red"}.get(level, "white")
            t.add_row(time.strftime("%H:%M:%S", time.localtime(ts)),
                      Text(level.upper(), style=color), msg[:200])
        return Panel(t, title="event log", border_style="white")

    def _render(self) -> Layout:
        root = Layout()
        root.split(
            Layout(self._banner(), name="banner", size=8),
            Layout(name="body"),
            Layout(Panel(self._progress, title="task progress", border_style="blue"),
                   name="progress", size=10),
        )
        root["body"].split_row(
            Layout(self._agents_table(), name="agents", ratio=2),
            Layout(self._counters_panel(), name="counters", ratio=1),
            Layout(self._events_panel(), name="events", ratio=3),
        )
        return root
