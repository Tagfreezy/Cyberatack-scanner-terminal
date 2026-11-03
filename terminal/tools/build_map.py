"""Build cyberwatch_tui/map_data.json from Natural Earth (public domain) country polygons.

Each cell of a W x H equirectangular grid gets the ISO-3166 alpha-2 code of the country
covering its centre, so the dashboard can light up whole countries. Tiny countries that
cover no cell at this scale (Singapore, Luxembourg, ...) get the cell at their location.

Usage (data from https://github.com/nvkelso/natural-earth-vector, 110m admin-0 countries):
    python -I tools/build_map.py path/to/ne_110m_admin_0_countries.geojson
"""

import json
import sys
from pathlib import Path

W, H = 180, 56
LAT_TOP, LAT_BOTTOM = 83.0, -57.0  # Antarctica cut off: no attacks to show there

# Countries absent or too small at 110m scale: (lat, lon)
SMALL = {
    "SG": (1.35, 103.82), "HK": (22.32, 114.17), "MO": (22.20, 113.55), "LU": (49.61, 6.13),
    "MT": (35.90, 14.50), "BH": (26.07, 50.55), "MC": (43.74, 7.42), "LI": (47.14, 9.52),
    "AD": (42.50, 1.52), "SM": (43.94, 12.46), "VA": (41.90, 12.45), "MV": (3.20, 73.22),
    "MU": (-20.30, 57.58), "BB": (13.19, -59.54), "SC": (-4.68, 55.49), "CV": (16.00, -24.00),
    "KM": (-11.70, 43.30), "GI": (36.14, -5.35), "AG": (17.06, -61.80), "LC": (13.91, -60.98),
    "GD": (12.12, -61.68), "KN": (17.30, -62.72), "DM": (15.41, -61.37), "VC": (13.25, -61.20),
    "TO": (-21.18, -175.20), "WS": (-13.76, -172.10), "PW": (7.51, 134.58), "MH": (7.13, 171.18),
    "FM": (6.92, 158.16), "KI": (1.87, -157.36), "TV": (-7.11, 177.65), "NR": (-0.52, 166.93),
    "ST": (0.19, 6.61), "BM": (32.32, -64.76), "KY": (19.31, -81.25), "AW": (12.52, -69.97),
    "CW": (12.17, -68.99), "MQ": (14.64, -61.02), "GP": (16.27, -61.55), "RE": (-21.12, 55.54),
}

# Natural Earth uses -99 where the ISO code is disputed.
FIXUPS = {"Somaliland": "SO", "N. Cyprus": "CY"}


def code_of(props: dict) -> str | None:
    for key in ("ISO_A2_EH", "ISO_A2"):
        v = props.get(key)
        if v and v != "-99":
            return v
    return FIXUPS.get(props.get("NAME", ""))


def point_in_ring(x: float, y: float, ring: list) -> bool:
    inside = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i][0], ring[i][1]
        xj, yj = ring[j][0], ring[j][1]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi + 1e-12) + xi:
            inside = not inside
        j = i
    return inside


def point_in_polygon(x: float, y: float, poly: list) -> bool:
    # poly = [outer ring, hole, hole, ...]
    return point_in_ring(x, y, poly[0]) and not any(point_in_ring(x, y, h) for h in poly[1:])


def cell_of(lat: float, lon: float) -> tuple[int, int]:
    col = int((lon + 180.0) / 360.0 * W)
    row = int((LAT_TOP - lat) / (LAT_TOP - LAT_BOTTOM) * H)
    return min(W - 1, max(0, col)), min(H - 1, max(0, row))


def main(src: str) -> None:
    data = json.loads(Path(src).read_text(encoding="utf-8"))
    shapes = []  # (code, bbox, polygons)
    for f in data["features"]:
        code = code_of(f["properties"])
        if not code:
            continue
        g = f["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        for poly in polys:
            xs = [p[0] for p in poly[0]]
            ys = [p[1] for p in poly[0]]
            shapes.append((code, (min(xs), min(ys), max(xs), max(ys)), poly))

    codes = [""]  # index 0 = ocean
    index = {}
    grid = []
    for r in range(H):
        lat = LAT_TOP - (r + 0.5) * (LAT_TOP - LAT_BOTTOM) / H
        row = []
        for c in range(W):
            lon = -180.0 + (c + 0.5) * 360.0 / W
            hit = 0
            for code, (x0, y0, x1, y1), poly in shapes:
                if x0 <= lon <= x1 and y0 <= lat <= y1 and point_in_polygon(lon, lat, poly):
                    if code not in index:
                        index[code] = len(codes)
                        codes.append(code)
                    hit = index[code]
                    break
            row.append(hit)
        grid.append(row)

    present = set(index)
    for code, (lat, lon) in SMALL.items():
        if code in present:
            continue
        c, r = cell_of(lat, lon)
        index[code] = len(codes)
        codes.append(code)
        grid[r][c] = index[code]

    # Compact encoding: one character per cell, chr(48 + index).
    out = {
        "source": "Natural Earth 110m admin-0 countries (public domain), rasterised by tools/build_map.py",
        "width": W,
        "height": H,
        "lat_top": LAT_TOP,
        "lat_bottom": LAT_BOTTOM,
        "codes": codes,
        "rows": ["".join(chr(48 + v) for v in row) for row in grid],
    }
    dest = Path(__file__).resolve().parent.parent / "cyberwatch_tui" / "map_data.json"
    dest.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    land = sum(1 for row in grid for v in row if v)
    print(f"wrote {dest} ({W}x{H}, {len(codes) - 1} countries, {land} land cells)")


if __name__ == "__main__":
    main(sys.argv[1])
