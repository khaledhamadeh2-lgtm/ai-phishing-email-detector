import json
import logging
import time
from dataclasses import asdict

from .config import settings
from .mailbox import scan_mailbox_once

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


def run(max_cycles: int | None = None) -> None:
    logger.info("Starting read-only mailbox monitor.")
    cycles = 0
    while True:
        try:
            alerts = scan_mailbox_once()
            for alert in alerts:
                logger.warning("PHISHING_ALERT %s", json.dumps(asdict(alert)))
        except Exception as exc:
            logger.error("Mailbox scan failed safely: %s", type(exc).__name__)
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            return
        time.sleep(max(30, settings.mailbox_poll_seconds))


if __name__ == "__main__":
    run()
