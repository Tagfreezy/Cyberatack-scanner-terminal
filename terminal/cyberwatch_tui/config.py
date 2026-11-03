"""Settings from environment / .env (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

TERMINAL_DIR = Path(__file__).resolve().parent.parent


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    api_url: str
    api_token: str
    poll_seconds: int = 45
    timezone: str = "Europe/Zurich"


def load_config(env_file: Path | None = None) -> Config:
    if env_file is not None:
        load_dotenv(env_file, override=False)  # explicit file: nothing else
    else:
        # .env next to the app wins; a .env in the current directory is also picked up.
        load_dotenv(TERMINAL_DIR / ".env", override=False)
        load_dotenv(Path.cwd() / ".env", override=False)

    url = os.environ.get("CYBERWATCH_API_URL", "").strip().rstrip("/")
    token = os.environ.get("CYBERWATCH_API_TOKEN", "").strip()
    missing = [n for n, v in (("CYBERWATCH_API_URL", url), ("CYBERWATCH_API_TOKEN", token)) if not v]
    if missing:
        raise ConfigError(
            f"Missing {', '.join(missing)}. Copy .env.example to .env in {TERMINAL_DIR} and fill it in."
        )
    if not url.startswith(("https://", "http://")):
        raise ConfigError("CYBERWATCH_API_URL must start with https:// (or http:// for local testing)")

    try:
        poll = int(os.environ.get("CYBERWATCH_POLL_SECONDS", "45"))
    except ValueError:
        poll = 45
    # 30-60 s is plenty: the Worker only gets new data every 5 minutes.
    poll = max(15, min(300, poll))
    tz = os.environ.get("CYBERWATCH_TIMEZONE", "Europe/Zurich").strip() or "Europe/Zurich"
    return Config(api_url=url, api_token=token, poll_seconds=poll, timezone=tz)
