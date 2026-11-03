"""CyberWatch dashboard app."""

from __future__ import annotations

import asyncio
import webbrowser
from datetime import datetime
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer

from .config import Config
from .model import TYPE_SHORT, Filter, Incident, IncidentStore
from .screens import DetailScreen, FilterScreen
from .widgets import ACCENT, HeaderBar, MapPanel, SensorPanel, StatsPanel, fmt_time, severity_cell


class Api(Protocol):
    async def feed(self, since: int = 0, limit: int = 200) -> dict[str, Any]: ...
    async def stats(self) -> dict[str, Any]: ...
    async def sensors(self) -> dict[str, Any]: ...
    async def explain(self, incident_id: int) -> dict[str, Any]: ...
    async def aclose(self) -> None: ...


# Fixed-width columns; the title column gets whatever width is left.
FIXED_COLS = [("time", "Time", 6), ("sev", "Sev", 5), ("type", "Type", 7), ("cty", "Cty", 3), ("src", "Src", 3)]


class CyberWatchApp(App[None]):
    TITLE = "CyberWatch"
    CSS = f"""
    Screen {{ background: #070b08; color: #c8d3c8; }}
    HeaderBar {{ height: 1; background: #0d1a10; }}
    #body {{ height: 1fr; }}
    #feed {{ width: 58%; border: round #1f6f3f; border-title-color: {ACCENT}; background: #070b08; }}
    #right {{ width: 42%; }}
    #map {{ height: 55%; border: round #1f6f3f; border-title-color: {ACCENT}; padding: 0 1; }}
    #bottom {{ height: 1fr; }}
    #stats {{ width: 60%; border: round #1f6f3f; border-title-color: {ACCENT}; padding: 0 1; overflow-y: auto; }}
    #sensors {{ width: 40%; border: round #1f6f3f; border-title-color: {ACCENT}; padding: 0 1; }}
    DataTable {{ background: #070b08; }}
    DataTable > .datatable--header {{ background: #0d1a10; color: {ACCENT}; text-style: bold; }}
    DataTable > .datatable--cursor {{ background: #1f6f3f; color: white; }}
    DataTable > .datatable--even-row {{ background: #0a100b; }}
    Footer {{ background: #0d1a10; }}
    #dialog {{ width: 90; max-width: 95%; height: auto; max-height: 85%; border: thick {ACCENT};
               background: #0b130d; padding: 1 2; }}
    #dialog VerticalScroll {{ height: auto; max-height: 30; }}
    #hint {{ color: grey; margin-top: 1; }}
    #filter-row {{ height: auto; }}
    #filter-row RadioSet {{ width: 1fr; margin: 1 1 0 0; }}
    #buttons {{ height: auto; margin-top: 1; }}
    #buttons Button {{ margin-right: 2; }}
    DetailScreen, FilterScreen {{ align: center middle; background: rgba(0,0,0,0.6); }}
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("enter", "details", "Details", show=True),
        Binding("f", "filter", "Filter"),
        Binding("o", "open_link", "Open link"),
        Binding("r", "refresh_now", "Refresh"),
    ]

    def __init__(self, config: Config, api: Api) -> None:
        super().__init__()
        self.config = config
        self.api = api
        self.tz = ZoneInfo(config.timezone)
        self.store = IncidentStore()
        self.flt = Filter()
        self._row_order: list[int] = []
        self._was_flashing = False

    # ------------------------------------------------------------------ layout
    def compose(self) -> ComposeResult:
        yield HeaderBar(self.tz, id="header")
        with Horizontal(id="body"):
            feed = DataTable(id="feed", cursor_type="row", zebra_stripes=True)
            feed.border_title = "LIVE INCIDENT FEED"
            yield feed
            with Vertical(id="right"):
                m = MapPanel(id="map")
                m.border_title = "ATTACK MAP · 7 DAYS"
                yield m
                with Horizontal(id="bottom"):
                    s = StatsPanel("loading…", id="stats")
                    s.border_title = "STATS"
                    yield s
                    sensors = SensorPanel("loading…", id="sensors")
                    sensors.border_title = "SENSORS"
                    yield sensors
        yield Footer()

    def on_mount(self) -> None:
        self._setup_columns(self._title_width())
        self.query_one(HeaderBar).refresh_header()
        self.set_interval(1, self._tick)
        self.set_interval(self.config.poll_seconds, self.poll)
        self.poll()

    async def on_unmount(self) -> None:
        await self.api.aclose()

    def _setup_columns(self, title_width: int) -> None:
        table = self.query_one("#feed", DataTable)
        table.clear(columns=True)
        for key, label, width in FIXED_COLS[:3]:
            table.add_column(label, key=key, width=width)
        table.add_column("Incident", key="title", width=title_width)
        for key, label, width in FIXED_COLS[3:]:
            table.add_column(label, key=key, width=width)
        self._title_w = title_width

    def _title_width(self) -> int:
        table = self.query_one("#feed", DataTable)
        fixed = sum(w for *_, w in FIXED_COLS) + 2 * (len(FIXED_COLS) + 1) + 4
        return max(20, (table.size.width or 100) - fixed)

    def on_resize(self) -> None:
        self.call_after_refresh(self._rebuild_table)

    # ------------------------------------------------------------------ data
    @work(exclusive=True, group="poll")
    async def poll(self) -> None:
        header = self.query_one(HeaderBar)
        feed, stats, sensors = await asyncio.gather(
            self.api.feed(since=self.store.cursor),
            self.api.stats(),
            self.api.sensors(),
            return_exceptions=True,
        )
        errors = [r for r in (feed, stats, sensors) if isinstance(r, BaseException)]
        if isinstance(feed, dict):
            self.store.apply_feed(feed)
            self._rebuild_table()
        if isinstance(stats, dict):
            self.query_one(StatsPanel).show_stats(stats)
            self.query_one(MapPanel).set_counts({r["key"]: int(r["n"]) for r in stats.get("by_country", [])})
            header.sources = stats.get("sources", [])
            header.ai_paused = bool(stats.get("ai_paused"))
            header.queue = int(stats.get("queue") or 0)
        if isinstance(sensors, dict):
            self.query_one(SensorPanel).show_sensors(sensors)
        header.error = str(errors[0]) if errors else None
        if not errors:
            header.last_update = datetime.now(self.tz)
        header.refresh_header()

    def _tick(self) -> None:
        self.query_one(HeaderBar).refresh_header()
        flashing = self.store.any_flashing()
        if flashing or self._was_flashing:  # redraw once more when a flash ends
            self._rebuild_table()
        self._was_flashing = flashing

    def _rebuild_table(self) -> None:
        table = self.query_one("#feed", DataTable)
        selected = self._selected_id()
        visible = self.store.visible(self.flt)
        title_w = self._title_width()
        if title_w != getattr(self, "_title_w", None):
            self._setup_columns(title_w)  # terminal was resized
        else:
            table.clear()
        now = datetime.now(self.tz)
        for inc in visible:
            flash = self.store.is_flashing(inc.id)
            title = Text(inc.title if len(inc.title) <= title_w else inc.title[: title_w - 1] + "…")
            if flash:
                title.stylize("bold black on #e0a000")
            elif inc.source_count > 1:
                title.stylize("bold")
            table.add_row(
                Text(fmt_time(inc.first_seen, self.tz, now), style="grey62"),
                severity_cell(inc.severity),
                Text(TYPE_SHORT.get(inc.attack_type, inc.attack_type), style="#e0a000"),
                title,
                Text(inc.country or "", style="white"),
                Text(str(inc.source_count), style="bold" if inc.source_count > 1 else "grey50"),
                key=str(inc.id),
            )
        self._row_order = [i.id for i in visible]
        table.border_subtitle = (
            f"{len(visible)} shown" + (f" · filter: {self.flt.describe()}" if self.flt.active else "") + " · ⏎ details"
        )
        if selected in self._row_order:
            table.move_cursor(row=self._row_order.index(selected), animate=False)

    def _selected_id(self) -> int | None:
        table = self.query_one("#feed", DataTable)
        if not table.row_count:
            return None
        row = table.cursor_row
        return self._row_order[row] if 0 <= row < len(self._row_order) else None

    def _selected(self) -> Incident | None:
        i = self._selected_id()
        return self.store.items.get(i) if i is not None else None

    # ------------------------------------------------------------------ actions
    def on_data_table_row_selected(self, _event: DataTable.RowSelected) -> None:
        self.action_details()

    def action_details(self) -> None:
        inc = self._selected()
        if inc:
            self.push_screen(DetailScreen(inc, self.tz, self._explain))

    async def _explain(self, incident_id: int) -> str | None:
        res = await self.api.explain(incident_id)
        return res.get("details")

    def action_filter(self) -> None:
        def apply(result: Filter | None) -> None:
            if result is not None:
                self.flt = result
                self.query_one(HeaderBar).filter_desc = result.describe()
                self._rebuild_table()
                self.query_one(HeaderBar).refresh_header()

        self.push_screen(FilterScreen(self.flt), apply)

    def action_open_link(self) -> None:
        inc = self._selected()
        if inc and inc.url:
            webbrowser.open(inc.url)
            self.notify(f"Opened {inc.url[:60]}", timeout=3)
        else:
            self.notify("No link for this incident", severity="warning", timeout=3)

    def action_refresh_now(self) -> None:
        self.poll()
