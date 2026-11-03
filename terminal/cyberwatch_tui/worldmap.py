"""ASCII world map: countries with incidents light up, brighter = more incidents."""

from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path

from rich.text import Text

MAP_FILE = Path(__file__).with_name("map_data.json")

OCEAN = " "
LAND = "·"
LAND_STYLE = "#1f6f3f"
# 4 heat levels: glyph + colour (dim amber → red)
LEVELS = [("░", "#a07800"), ("▒", "#e0a000"), ("▓", "#ff6a00"), ("█", "bold #ff2020")]


@lru_cache(maxsize=1)
def load_map() -> tuple[int, int, list[str], list[list[int]]]:
    d = json.loads(MAP_FILE.read_text(encoding="utf-8"))
    grid = [[ord(ch) - 48 for ch in row] for row in d["rows"]]
    return d["width"], d["height"], d["codes"], grid


def heat_level(n: int, max_n: int) -> int:
    """1..4 on a log scale, so one country with 50 incidents doesn't wash out all others."""
    if n <= 0 or max_n <= 0:
        return 0
    if max_n == 1:
        return 4
    return max(1, min(4, math.ceil(math.log1p(n) / math.log1p(max_n) * 4)))


def render_map(width: int, height: int, counts: dict[str, int]) -> Text:
    """Render to exactly width x height characters (downsampled from the source grid)."""
    W, H, codes, grid = load_map()
    width = max(10, width)
    height = max(4, height)
    counts = {k.upper(): v for k, v in counts.items() if v > 0}
    max_n = max(counts.values(), default=0)
    level_of = {i: heat_level(counts.get(code, 0), max_n) for i, code in enumerate(codes) if code}

    text = Text(no_wrap=True, overflow="crop")
    for y in range(height):
        r0 = int(y * H / height)
        r1 = max(r0 + 1, int((y + 1) * H / height))
        for x in range(width):
            c0 = int(x * W / width)
            c1 = max(c0 + 1, int((x + 1) * W / width))
            best = -1  # -1 ocean, 0 land, 1..4 heat
            for r in range(r0, min(r1, H)):
                row = grid[r]
                for c in range(c0, min(c1, W)):
                    v = row[c]
                    if v:
                        lvl = level_of.get(v, 0)
                        if lvl > best:
                            best = lvl
            if best < 0:
                text.append(OCEAN)
            elif best == 0:
                text.append(LAND, style=LAND_STYLE)
            else:
                glyph, style = LEVELS[best - 1]
                text.append(glyph, style=style)
        if y < height - 1:
            text.append("\n")
    return text


def legend(counts: dict[str, int], top: int = 5) -> Text:
    t = Text(no_wrap=True, overflow="ellipsis")
    for glyph, style in LEVELS:
        t.append(glyph, style=style)
    t.append(" low→high  ", style="grey50")
    ranked = sorted(((v, k) for k, v in counts.items() if v > 0), reverse=True)[:top]
    if not ranked:
        t.append("no located incidents in the last 7 days", style="grey50")
    for i, (n, code) in enumerate(ranked):
        if i:
            t.append(" · ", style="grey35")
        t.append(code, style="bold")
        t.append(f" {n}", style="#e0a000")
    return t
