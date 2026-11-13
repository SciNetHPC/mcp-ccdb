"""Logging setup shared by the MCP server and the documentation sync script.

One JSON object per line, on stdout, and nothing on the container filesystem:
the runtime captures stdout, while files inside the image are ephemeral and
unrotated.  JSON keeps the lines machine-parseable whatever the log backend
turns out to be.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - zoneinfo ships with Python 3.9+
    ZoneInfo = None

# Attributes every LogRecord carries.  Anything else on a record was passed in
# via ``extra=`` and belongs in the JSON payload.
_RESERVED = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"message", "asctime"}

# Which zone the `ts` field is rendered in.  Defaults to America/Toronto
# (Eastern, with automatic DST handling); override with LOG_TIME_ZONE.  Falls
# back to UTC when zoneinfo is unavailable or the name is unknown (e.g. the
# container ships no tzdata).
_TS_ZONE_NAME = os.environ.get("LOG_TIME_ZONE", "America/Toronto")
_TS_ZONE = timezone.utc
if _TS_ZONE_NAME != "UTC" and ZoneInfo is not None:
    try:
        _TS_ZONE = ZoneInfo(_TS_ZONE_NAME)
    except Exception:  # pragma: no cover - unknown zone / missing tzdata
        _TS_ZONE = timezone.utc


class JsonFormatter(logging.Formatter):
    """Render a record as a single line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            # Aware datetimes serialize with their UTC offset (e.g.
            # 2026-09-30T12:22:22.581235-04:00), so the instant stays
            # unambiguous while reading in Eastern time.
            "ts": datetime.fromtimestamp(record.created, _TS_ZONE).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str | None = None) -> None:
    """Install the JSON handler on the root logger.  Safe to call more than once."""
    level = (level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    root = logging.getLogger()
    for existing in root.handlers:
        if isinstance(existing.formatter, JsonFormatter):
            root.setLevel(level)
            return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
