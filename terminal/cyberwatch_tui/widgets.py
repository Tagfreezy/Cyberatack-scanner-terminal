"""Panels and formatting helpers for the dashboard."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from rich.console import Group
from rich.text import Text
from textual.widget import Widget
from textual.widgets import Static

from .model import SEVERITY_LABEL, SEVERITY_STYLE, TYPE_SHORT, source_label
from .worldmap import legend, render_map

SPARK = "▁▂▃▄▅▆▇█"
ACCENT = "#33ff66"


def fmt_time(ms: int, tz: ZoneInfo, now: datetime | None = None) -> str:
    """HH:MM for today (local), 'Mon 03' otherwise."""
    if not ms:
        return "--:--"
    t = datetime.fromtimestamp(ms / 1000, tz)
    now = now or datetime.now(tz)
    return t.strftime("%H:%M") if t.date() == now.date() else t.strftime("%b %d")


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    hi = max(values)
    if hi == 0:
        return SPARK[0] * len(values)
    return "".join(SPARK[min(7, round(v / hi * 7))] for v in values)


def bar(n: int, max_n: int, width: int) -> str:
    if max_n <= 0 or width <= 0:
        return ""
    full = n / max_n * width
    return "█" * int(full) + ("▌" if full - int(full) >= 0.5 else "")


def severity_cell(sev: int) -> Text:
    return Text(f" {SEVERITY_LABEL.get(sev, '?'):<4}", style=SEVERITY_STYLE.get(sev, ""))


def trend_text(cur: int, prev: int) -> Text:
    if prev == 0:
        return Text(" new" if cur else "", style="grey50")
    pct = round((cur - prev) / prev * 100)
    if pct == 0:
        return Text(" =", style="grey50")
    return Text(f" ▲{pct}%" if pct > 0 else f" ▼{-pct}%", style="red" if pct > 0 else "green")


class HeaderBar(Static):
    """Clock (local), last update, source health dots, AI status."""

    def __init__(self, tz: ZoneInfo, **kw: Any) -> None:
        super().__init__(**kw)
        self.tz = tz
        self.last_update: datetime | None = None
        self.sources: list[dict[str, Any]] = []
        self.ai_paused = False
        self.queue = 0
        self.error: str | None = None
        self.filter_desc = "all"

    def refresh_header(self) -> None:
        now = datetime.now(self.tz)
        t = Text(no_wrap=True, overflow="ellipsis")
        t.append(" ▌CYBERWATCH▐ ", style=f"bold black on {ACCENT}")
        t.append(f"  {now:%H:%M:%S} ", style="bold white")
        t.append(f"{self.tz.key.split('/')[-1]}", style="grey50")
        t.append("  │ updated ", style="grey35")
        t.append(f"{self.last_update:%H:%M:%S}" if self.last_update else "never", style="white")
        t.append("  │ ", style="grey35")
        if self.error:
            t.append(f"⚠ {self.error}", style="bold red")
        else:
            for s in self.sources:
                t.append("● ", style="bold green" if s.get("ok") else "bold red")
                t.append(f"{source_label(s.get('source', '?'))}  ", style="grey70")
            t.append("│ AI ", style="grey35")
            t.append("paused" if self.ai_paused else "on", style="dark_orange" if self.ai_paused else "green")
            if self.queue:
                t.append(f" · {self.queue} queued", style="grey50")
        if self.filter_desc != "all":
            t.append(f"  │ filter: {self.filter_desc}", style="bold yellow")
        self.update(t)


class MapPanel(Widget):
    """World map sized to the panel; re-renders on resize or new counts."""

    DEFAULT_CSS = "MapPanel { height: 1fr; }"

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.counts: dict[str, int] = {}

    def set_counts(self, counts: dict[str, int]) -> None:
        self.counts = counts
        self.refresh()

    def render(self) -> Group:
        w, h = self.content_size.width, self.content_size.height
        return Group(render_map(w, max(4, h - 1), self.counts), legend(self.counts))


class StatsPanel(Static):
    def show_stats(self, s: dict[str, Any]) -> None:
        width = max(10, self.content_size.width - 18)
        t = Text(no_wrap=True, overflow="ellipsis")
        t.append("TODAY ", style="grey50")
        t.append(f"{s.get('today', 0)}", style=f"bold {ACCENT}")
        t.append("   7 DAYS ", style="grey50")
        t.append(f"{s.get('week', 0)}", style=f"bold {ACCENT}")
        t.append_text(trend_text(int(s.get("week", 0)), int(s.get("prev_week", 0))))
        t.append(f"\nhigh/critical {s.get('week_high', 0)} · multi-source {s.get('week_multi', 0)}\n", style="grey62")
        t.append("24h ", style="grey50")
        t.append(sparkline(list(s.get("hourly", []))), style=ACCENT)
        t.append("\n")

        by_type = s.get("by_type", [])
        if by_type:
            t.append("\nBY TYPE (7d)\n", style="bold grey70")
            mx = max(r["n"] for r in by_type)
            for r in by_type[:7]:
                t.append(f"{TYPE_SHORT.get(r['key'], r['key'][:6]):<7}", style="grey70")
                t.append(f"{bar(r['n'], mx, width):<{width}}", style="#e0a000")
                t.append(f" {r['n']}\n")
        for title, key in (("RANSOMWARE GROUPS", "groups"), ("SECTORS", "by_sector")):
            rows = s.get(key, [])[:5]
            if rows:
                t.append(f"\n{title} (7d)\n", style="bold grey70")
                for i, r in enumerate(rows, 1):
                    t.append(f"{i}. ", style="grey50")
                    t.append(f"{str(r['key'])[:28]}", style="white")
                    t.append(f"  {r['n']}\n", style="#e0a000")
        self.update(t)


class SensorPanel(Static):
    def show_sensors(self, d: dict[str, Any]) -> None:
        t = Text(no_wrap=True, overflow="ellipsis")
        if not d.get("available"):
            t.append("SANS ISC SENSORS\n\n", style="bold grey70")
            t.append(d.get("note") or "no sensor data yet", style="grey50")
            self.update(t)
            return
        # Phase 5 fills this in: infocon, top ports, spikes.
        infocon = str(d.get("infocon", "?"))
        colour = {"green": "green", "yellow": "yellow", "orange": "dark_orange", "red": "red"}.get(infocon, "white")
        t.append("INFOCON ", style="grey50")
        t.append(f" {infocon.upper()} ", style=f"bold black on {colour}")
        t.append("\n\nTOP ATTACKED PORTS\n", style="bold grey70")
        ports = d.get("top_ports", [])[:8]
        mx = max((p.get("records", 0) for p in ports), default=0)
        width = max(6, self.content_size.width - 16)
        for p in ports:
            t.append(f"{p.get('port', '?'):>6} ", style="white")
            t.append(f"{bar(p.get('records', 0), mx, width):<{width}}", style="#e0a000")
            t.append("\n")
        for spike in d.get("spikes", [])[:3]:
            t.append(f"⚠ spike: port {spike.get('port')} ×{spike.get('factor', '?')}\n", style="bold red")
        self.update(t)
