"""Modal screens: incident details (enter) and filter (f)."""

from __future__ import annotations

import webbrowser
from datetime import datetime
from typing import Awaitable, Callable
from zoneinfo import ZoneInfo

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, RadioButton, RadioSet, Static

from .model import ATTACK_TYPES, SEVERITY_LABEL, SEVERITY_STYLE, TYPE_SHORT, Filter, Incident, source_label


def detail_text(inc: Incident, tz: ZoneInfo, explanation: str | None = None, status: str = "") -> Text:
    t = Text()
    t.append(f" {SEVERITY_LABEL.get(inc.severity, '?')} ", style=SEVERITY_STYLE.get(inc.severity, ""))
    t.append(f"  {TYPE_SHORT.get(inc.attack_type, inc.attack_type)}", style="bold #e0a000")
    t.append(f"   #{inc.id}\n\n", style="grey50")
    t.append(inc.title + "\n\n", style="bold white")
    facts = [
        ("Victim", inc.victim),
        ("Group", inc.group_name),
        ("Vendor", inc.vendor),
        ("Sector", inc.sector),
        ("Country", inc.country),
    ]
    for k, v in facts:
        if v:
            t.append(f"{k:<9}", style="grey50")
            t.append(f"{v}\n")
    first = datetime.fromtimestamp(inc.first_seen / 1000, tz).strftime("%Y-%m-%d %H:%M")
    last = datetime.fromtimestamp(inc.last_seen / 1000, tz).strftime("%Y-%m-%d %H:%M")
    t.append(f"{'Seen':<9}", style="grey50")
    t.append(f"{first}  (updated {last})\n")
    t.append(f"{'Sources':<9}", style="grey50")
    t.append(f"{inc.source_count}: {', '.join(source_label(s) for s in inc.sources) or '?'}\n")
    t.append(f"{'Rated by':<9}", style="grey50")
    t.append(("AI" if inc.classified_by == "ai" else "keyword rules") + "\n")
    if inc.summary:
        t.append("\nSummary\n", style="bold grey70")
        t.append(inc.summary + "\n")
    text = explanation or inc.details
    if text:
        t.append("\nAI explanation\n", style="bold grey70")
        t.append(text + "\n")
    if status:
        t.append(f"\n{status}\n", style="italic yellow")
    if inc.url:
        t.append("\n" + inc.url, style="underline dodger_blue1")
    return t


class DetailScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape,q,enter", "dismiss", "Close"),
        Binding("o", "open_link", "Open link"),
        Binding("m", "explain", "AI explain"),
    ]

    def __init__(self, inc: Incident, tz: ZoneInfo, explain: Callable[[int], Awaitable[str | None]]) -> None:
        super().__init__()
        self.inc = inc
        self.tz = tz
        self._explain = explain
        self.explanation: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            with VerticalScroll():
                yield Static(detail_text(self.inc, self.tz), id="detail-body")
            hint = "[o] open link   [m] AI explanation   [esc] close" if not self.inc.details else "[o] open link   [esc] close"
            yield Label(hint, id="hint")

    def _update_body(self, status: str = "") -> None:
        self.query_one("#detail-body", Static).update(detail_text(self.inc, self.tz, self.explanation, status))

    def action_dismiss(self) -> None:  # type: ignore[override]
        self.dismiss(None)

    def action_open_link(self) -> None:
        if self.inc.url:
            webbrowser.open(self.inc.url)

    async def action_explain(self) -> None:
        if self.inc.details or self.explanation:
            return
        self._update_body("Asking the AI… (a few seconds)")
        try:
            self.explanation = await self._explain(self.inc.id)
            self.inc.details = self.explanation
            self._update_body("" if self.explanation else "No explanation available.")
        except Exception as e:  # network/API errors are shown, never crash the dashboard
            self._update_body(f"AI explanation failed: {e}")


class FilterScreen(ModalScreen[Filter | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, current: Filter) -> None:
        super().__init__()
        self.current = current

    def compose(self) -> ComposeResult:
        selected_type = next(iter(self.current.types)) if len(self.current.types) == 1 else None
        with Vertical(id="dialog"):
            yield Label("[b]Filter incidents[/b]")
            with Horizontal(id="filter-row"):
                with RadioSet(id="types"):
                    yield RadioButton("All types", value=selected_type is None)
                    for t in ATTACK_TYPES:
                        yield RadioButton(TYPE_SHORT[t], value=selected_type == t, name=t)
                with RadioSet(id="sev"):
                    for s in range(1, 6):
                        label = "All severities" if s == 1 else f"{SEVERITY_LABEL[s]} and above"
                        yield RadioButton(label, value=self.current.min_severity == s, name=str(s))
            with Horizontal(id="buttons"):
                yield Button("Apply", variant="success", id="apply")
                yield Button("Reset", id="reset")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        elif event.button.id == "reset":
            self.dismiss(Filter())
        else:
            t = self.query_one("#types", RadioSet).pressed_button
            s = self.query_one("#sev", RadioSet).pressed_button
            types = frozenset([t.name]) if t is not None and t.name else frozenset()
            sev = int(s.name) if s is not None and s.name else 1
            self.dismiss(Filter(types=types, min_severity=sev))

    def action_cancel(self) -> None:
        self.dismiss(None)
