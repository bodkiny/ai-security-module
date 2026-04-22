import logging
from datetime import datetime

logger = logging.getLogger("audit")


def save_event(event: dict) -> None:
    # MVP: log-only; replace with PostgreSQL insert later
    event["timestamp"] = datetime.utcnow().isoformat()
    logger.info("AUDIT_EVENT %s", event)