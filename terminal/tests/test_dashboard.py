import os
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from textual.widgets import DataTable

from cyberwatch_tui.app import CyberWatchApp
from cyberwatch_tui.config import Config, ConfigError, load_config
from cyberwatch_tui.model import Filter, Incident, IncidentStore
from cyberwatch_tui.screens import DetailScreen, FilterScreen
from cyberwatch_tui.widgets import bar, fmt_time, sparkline
from cyberwatch_tui.worldmap import heat_level, load_map, render_map

TZ = ZoneInfo("Europe/Zurich")
NOW_MS = 1793738119758


def inc(i: int, **kw) -> dict:
    d = {
        "id": i,
        "title": f"Incident {i}",
        "severity": 3,
        "attack_type": "ransomware",
        "first_seen": NOW_MS - i * 60_000,
        "last_seen": NOW_MS - i * 60_000,
        "country": "US",
        "source_count": 1,
        "sources": ["therecord"],
        "url": f"https://example.com/{i}",
    }
    d.update(kw)
    return d


# ---------------------------------------------------------------- world map
def test_map_data_is_consistent():
    w, h, codes, grid = load_map()
    assert (w, h) == (180, 56) and len(grid) == h and all(len(r) == w for r in grid)
    for code in ("US", "CH", "DE", "KR", "FR", "NO", "SG", "LU"):  # incl. fixed-up and tiny countries
        assert code in codes, code


def test_render_map_size_and_heat():
    t = render_map(60, 20, {"US": 10, "CH": 1})
    lines = t.plain.split("\n")
    assert len(lines) == 20 and all(len(line) == 60 for line in lines)
    assert "█" in t.plain  # US = max → brightest level
    assert "·" in t.plain  # unlit land
    assert "█" not in render_map(60, 20, {}).plain


def test_small_country_survives_downsampling():
    # Switzerland is a few source cells; at 40x12 it must still light up.
    assert any(ch in render_map(40, 12, {"CH": 5}).plain for ch in "░▒▓█")


def test_heat_level_log_scale():
    assert heat_level(0, 10) == 0
    assert heat_level(10, 10) == 4
    assert 1 <= heat_level(1, 100) < heat_level(50, 100) <= 4
    assert heat_level(1, 1) == 4


# ---------------------------------------------------------------- model
def test_store_flashes_only_after_first_load():
    s = IncidentStore()
    assert s.apply_feed({"cursor": 5, "incidents": [inc(1), inc(2)]}, now=0) == []
    assert not s.is_flashing(1, now=1)
    changed = s.apply_feed({"cursor": 9, "incidents": [inc(3), inc(1, source_count=2)]}, now=10)
    assert sorted(changed) == [1, 3]  # new incident + merged one (new source)
    assert s.is_flashing(3, now=11) and s.is_flashing(1, now=11)
    assert not s.is_flashing(3, now=10 + IncidentStore.FLASH_SECONDS + 1)
    assert s.cursor == 9


def test_store_sorts_newest_first_and_filters():
    s = IncidentStore()
    s.apply_feed({"incidents": [inc(3), inc(1, severity=5, attack_type="breach"), inc(2)]})
    assert [i.id for i in s.visible(Filter())] == [1, 2, 3]
    assert [i.id for i in s.visible(Filter(types=frozenset({"breach"})))] == [1]
    assert [i.id for i in s.visible(Filter(min_severity=4))] == [1]
    assert Filter(types=frozenset({"breach"}), min_severity=4).describe() == "BREACH sev≥4"


def test_incident_from_api_is_defensive():
    i = Incident.from_api({"id": "7", "severity": 9, "first_seen": 1})
    assert (i.id, i.severity, i.attack_type, i.sources, i.last_seen) == (7, 5, "other", [], 1)


# ---------------------------------------------------------------- helpers
def test_formatting_helpers():
    now = datetime(2026, 11, 3, 21, 0, tzinfo=TZ)
    assert fmt_time(int(datetime(2026, 11, 3, 20, 15, tzinfo=TZ).timestamp() * 1000), TZ, now) == "20:15"
    assert fmt_time(int(datetime(2026, 11, 1, 9, 0, tzinfo=TZ).timestamp() * 1000), TZ, now) == "Nov 01"
    assert sparkline([0, 5, 10]) == "▁▅█"
    assert sparkline([0, 0]) == "▁▁"
    assert bar(5, 10, 10) == "█████"


def test_config_requires_url_and_token(tmp_path, monkeypatch):
    for k in ("CYBERWATCH_API_URL", "CYBERWATCH_API_TOKEN", "CYBERWATCH_POLL_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "none.env"
    empty.write_text("")
    with pytest.raises(ConfigError):
        load_config(empty)
    env = tmp_path / ".env"
    env.write_text("CYBERWATCH_API_URL=https://x.workers.dev/\nCYBERWATCH_API_TOKEN=abc\nCYBERWATCH_POLL_SECONDS=5\n")
    cfg = load_config(env)
    assert cfg.api_url == "https://x.workers.dev" and cfg.poll_seconds == 15  # clamped
    for k in ("CYBERWATCH_API_URL", "CYBERWATCH_API_TOKEN", "CYBERWATCH_POLL_SECONDS"):
        os.environ.pop(k, None)


# ---------------------------------------------------------------- the app, end to end
class FakeApi:
    def __init__(self):
        self.calls = 0
        self.explained = []

    async def feed(self, since=0, limit=200):
        self.calls += 1
        if since == 0:
            return {"cursor": NOW_MS, "incidents": [inc(i) for i in range(1, 6)]}
        return {"cursor": NOW_MS + 1, "incidents": [inc(99, title="Brand new", first_seen=NOW_MS + 1, last_seen=NOW_MS + 1)]}

    async def stats(self):
        return {
            "today": 5, "week": 5, "prev_week": 2, "week_high": 1, "week_multi": 0, "hourly": [0] * 23 + [5],
            "by_type": [{"key": "ransomware", "n": 5}], "by_country": [{"key": "US", "n": 5}],
            "groups": [{"key": "Qilin", "n": 3}], "by_sector": [{"key": "Healthcare", "n": 2}],
            "sources": [{"source": "therecord", "ok": True}, {"source": "cisa-kev", "ok": False}],
            "queue": 0, "ai_paused": False,
        }

    async def sensors(self):
        return {"available": False, "note": "phase 5"}

    async def explain(self, incident_id):
        self.explained.append(incident_id)
        return {"details": "What happened: test."}

    async def aclose(self):
        pass


async def test_app_end_to_end():
    api = FakeApi()
    app = CyberWatchApp(Config("https://x", "t", poll_seconds=300), api)
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause(0.5)
        table = app.query_one("#feed", DataTable)
        assert table.row_count == 5
        assert app._row_order[0] == 1  # newest first

        # second poll brings a new incident: it goes on top and flashes
        app.poll()
        await pilot.pause(0.5)
        assert table.row_count == 6 and app._row_order[0] == 99
        assert app.store.is_flashing(99)

        # the selection stays on the incident the user had selected (id 1, now row 2)
        assert app._selected_id() == 1
        # up → the new incident, enter → details, m → AI explanation, esc → back
        await pilot.press("up")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert isinstance(app.screen, DetailScreen) and app.screen.inc.id == 99
        await pilot.press("m")
        await pilot.pause(0.3)
        assert api.explained == [99]
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailScreen)

        # f → filter screen, cancel
        await pilot.press("f")
        await pilot.pause(0.2)
        assert isinstance(app.screen, FilterScreen)
        await pilot.press("escape")
        await pilot.pause(0.2)

        # programmatic filter: severity ≥ 4 hides all test incidents
        app.flt = Filter(min_severity=4)
        app._rebuild_table()
        assert table.row_count == 0
