"""Entry point: python -m cyberwatch_tui"""

import sys

from .api import ApiClient
from .config import ConfigError, load_config


def main() -> int:
    try:
        cfg = load_config()
    except ConfigError as e:
        print(f"CyberWatch: {e}", file=sys.stderr)
        return 2
    from .app import CyberWatchApp  # imported late so config errors print fast

    CyberWatchApp(cfg, ApiClient(cfg.api_url, cfg.api_token)).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
