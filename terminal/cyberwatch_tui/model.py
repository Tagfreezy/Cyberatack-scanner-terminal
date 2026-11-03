"""Incident model + in-memory store (pure Python, unit-tested)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

ATTACK_TYPES = ["ransomware", "breach", "ddos", "zero-day", "supply-chain", "wiper", "other"]

TYPE_SHORT = {
    "ransomware": "RANSOM",
    "breach": "BREACH",
    "ddos": "DDOS",
    "zero-day": "0-DAY",
    "supply-chain": "SUPPLY",
    "wiper": "WIPER",
    "other": "OTHER",
}

SEVERITY_LABEL = {5: "CRIT", 4: "HIGH", 3: "MED", 2: "LOW", 1: "INFO"}
SEVERITY_STYLE = {5: "bold white on red", 4: "bold dark_orange", 3: "yellow", 2: "dodger_blue1", 1: "grey50"}

SOURCE_LABEL = {
    "darkreading": "Dark Reading",
    "therecord": "The Record",
    "thehackernews": "The Hacker News",
    "securityweek": "SecurityWeek",
    "cisa-kev": "CISA KEV",
    "ransomware.live": "ransomware.live",
    "bleepingcomputer": "BleepingComputer",
}


def source_label(s: str) -> str:
    return SOURCE_LABEL.get(s, s)


@dataclass
class Incident:
    id: int
    title: str
    severity: int
    attack_type: str
    first_seen: int  # epoch ms
    last_seen: int
    summary: str = ""
    url: str | None = None
    victim: str | None = None
    group_name: str | None = None
    vendor: str | None = None
    sector: str | None = None
    country: str | None = None
    source_count: int = 1
    sources: list[str] = field(default_factory=list)
    alert_state: str = ""
    classified_by: str = ""
    details: str | None = None

    @classmethod
    def from_api(cls, d: dict[str, Any]) -> Incident:
        sev = int(d.get("severity") or 1)
        return cls(
            id=int(d["id"]),
            title=str(d.get("title") or "(untitled)"),
            severity=max(1, min(5, sev)),
            attack_type=str(d.get("attack_type") or "other"),
            first_seen=int(d.get("first_seen") or 0),
            last_seen=int(d.get("last_seen") or d.get("first_seen") or 0),
            summary=str(d.get("summary") or ""),
            url=d.get("url") or None,
            victim=d.get("victim"),
            group_name=d.get("group_name"),
            vendor=d.get("vendor"),
            sector=d.get("sector"),
            country=(d.get("country") or None),
            source_count=int(d.get("source_count") or 1),
            sources=list(d.get("sources") or []),
            alert_state=str(d.get("alert_state") or ""),
            classified_by=str(d.get("classified_by") or ""),
            details=d.get("details"),
        )


@dataclass
class Filter:
    types: frozenset[str] = frozenset()  # empty = all
    min_severity: int = 1

    def matches(self, inc: Incident) -> bool:
        return inc.severity >= self.min_severity and (not self.types or inc.attack_type in self.types)

    @property
    def active(self) -> bool:
        return bool(self.types) or self.min_severity > 1

    def describe(self) -> str:
        parts = []
        if self.types:
            parts.append("/".join(TYPE_SHORT.get(t, t) for t in sorted(self.types)))
        if self.min_severity > 1:
            parts.append(f"sev≥{self.min_severity}")
        return " ".join(parts) or "all"


class IncidentStore:
    """Keeps incidents by id; tracks which arrived after the first load so they can flash."""

    FLASH_SECONDS = 10.0

    def __init__(self, max_items: int = 400) -> None:
        self.items: dict[int, Incident] = {}
        self.cursor = 0
        self.loaded = False
        self.max_items = max_items
        self._flash_until: dict[int, float] = {}

    def apply_feed(self, payload: dict[str, Any], now: float | None = None) -> list[int]:
        """Merge a /api/feed response. Returns ids that are new (or got a new source)."""
        now = time.monotonic() if now is None else now
        first_load = not self.loaded
        changed: list[int] = []
        for raw in payload.get("incidents", []):
            inc = Incident.from_api(raw)
            old = self.items.get(inc.id)
            if old is None or inc.source_count > old.source_count or inc.severity > old.severity:
                changed.append(inc.id)
            self.items[inc.id] = inc
        self.cursor = max(self.cursor, int(payload.get("cursor") or 0))
        if not first_load:  # don't flash the whole table on the first load
            for i in changed:
                self._flash_until[i] = now + self.FLASH_SECONDS
        self.loaded = True
        if len(self.items) > self.max_items:
            for inc in sorted(self.items.values(), key=lambda x: x.first_seen)[: len(self.items) - self.max_items]:
                del self.items[inc.id]
        return [] if first_load else changed

    def is_flashing(self, incident_id: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return self._flash_until.get(incident_id, 0) > now

    def any_flashing(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        self._flash_until = {k: v for k, v in self._flash_until.items() if v > now}
        return bool(self._flash_until)

    def visible(self, flt: Filter) -> list[Incident]:
        """Filtered, newest first."""
        return sorted((i for i in self.items.values() if flt.matches(i)), key=lambda i: (i.first_seen, i.id), reverse=True)
