"""
LogParser -- parse common log formats, extract error events,
group by configurable time windows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class LogEvent:
    timestamp: Optional[datetime]
    level: str          # ERROR, WARN, INFO, DEBUG, UNKNOWN
    message: str
    raw_line: str
    source_file: str = ""
    line_number: int = 0

    def is_error(self) -> bool:
        return self.level in ("ERROR", "CRITICAL", "FATAL", "WARN", "WARNING")


# ---------------------------------------------------------------------------
# Timestamp patterns
# ---------------------------------------------------------------------------

# Each entry: (compiled_regex, strptime_format_or_None)
# If strptime_format is None the regex groups must be named and we parse them
# manually.

_TS_PATTERNS: list[tuple[re.Pattern, str | None]] = [
    # ISO-8601 / RFC-3339  2024-01-15T14:23:01.123Z
    (
        re.compile(
            r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
        ),
        None,
    ),
    # nginx/Apache CLF  15/Jan/2024:14:23:01 +0000
    (
        re.compile(
            r"(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})"
        ),
        "%d/%b/%Y:%H:%M:%S %z",
    ),
    # Syslog  Jan 15 14:23:01
    (
        re.compile(r"(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
        "%b %d %H:%M:%S",
    ),
    # k8s / Docker  2024-01-15T14:23:01.123456789Z  (nanosecond)
    (
        re.compile(
            r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z)"
        ),
        None,
    ),
    # epoch seconds  1705329781
    (
        re.compile(r"^(?P<ts>\d{10})(?:\.\d+)?\s"),
        "epoch",
    ),
]

_LEVEL_RE = re.compile(
    r"\b(?P<level>DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRITICAL|FATAL|SEVERE)\b",
    re.IGNORECASE,
)


def _parse_timestamp(line: str) -> Optional[datetime]:
    for pattern, fmt in _TS_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        ts_str = m.group("ts")
        if fmt == "epoch":
            try:
                return datetime.fromtimestamp(float(ts_str))
            except ValueError:
                continue
        if fmt is None:
            # ISO-8601 variants
            ts_str = ts_str.rstrip("Z").replace("T", " ")
            # strip timezone offset for simplicity
            ts_str = re.sub(r"[+-]\d{2}:?\d{2}$", "", ts_str).strip()
            # strip sub-second beyond microseconds
            ts_str = re.sub(r"(\.\d{6})\d+", r"\1", ts_str)
            for f in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(ts_str, f)
                except ValueError:
                    pass
            continue
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def _parse_level(line: str) -> str:
    m = _LEVEL_RE.search(line)
    if not m:
        return "UNKNOWN"
    lvl = m.group("level").upper()
    if lvl == "WARNING":
        return "WARN"
    return lvl


# ---------------------------------------------------------------------------
# LogParser
# ---------------------------------------------------------------------------


class LogParser:
    """
    Parse common log formats and extract structured LogEvent objects.

    Usage
    -----
    parser = LogParser()
    events = parser.parse_file("/var/log/app.log", since=datetime(...))
    errors = parser.filter_errors(events)
    windows = parser.group_by_window(errors, window_minutes=5)
    """

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def parse_file(
        self,
        path: str | Path,
        since: Optional[datetime] = None,
        max_lines: int = 50_000,
    ) -> list[LogEvent]:
        """
        Parse a log file and return a list of LogEvent objects.

        Parameters
        ----------
        path:
            Path to the log file.
        since:
            Only include events whose timestamp is >= this value.
            Lines with unparseable timestamps are always included.
        max_lines:
            Read at most this many lines from the tail of the file.
        """
        p = Path(path)
        if not p.exists():
            return []

        try:
            text = p.read_text(errors="replace")
        except OSError:
            return []

        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        events: list[LogEvent] = []
        for lineno, raw in enumerate(
            lines, start=max(1, len(text.splitlines()) - max_lines + 1)
        ):
            ts = _parse_timestamp(raw)
            if since is not None and ts is not None and ts < since:
                continue
            level = _parse_level(raw)
            # message = everything after the first recognised level token
            msg_match = _LEVEL_RE.search(raw)
            message = raw[msg_match.end():].strip() if msg_match else raw.strip()
            events.append(
                LogEvent(
                    timestamp=ts,
                    level=level,
                    message=message,
                    raw_line=raw,
                    source_file=str(p),
                    line_number=lineno,
                )
            )
        return events

    def parse_text(
        self,
        text: str,
        source_label: str = "<string>",
        since: Optional[datetime] = None,
    ) -> list[LogEvent]:
        """Parse log content from a raw string."""
        events: list[LogEvent] = []
        for lineno, raw in enumerate(text.splitlines(), 1):
            ts = _parse_timestamp(raw)
            if since is not None and ts is not None and ts < since:
                continue
            level = _parse_level(raw)
            msg_match = _LEVEL_RE.search(raw)
            message = raw[msg_match.end():].strip() if msg_match else raw.strip()
            events.append(
                LogEvent(
                    timestamp=ts,
                    level=level,
                    message=message,
                    raw_line=raw,
                    source_file=source_label,
                    line_number=lineno,
                )
            )
        return events

    # ------------------------------------------------------------------

    @staticmethod
    def filter_errors(events: list[LogEvent]) -> list[LogEvent]:
        """Return only ERROR / WARN / CRITICAL / FATAL events."""
        return [e for e in events if e.is_error()]

    @staticmethod
    def group_by_window(
        events: list[LogEvent],
        window_minutes: int = 5,
    ) -> dict[datetime, list[LogEvent]]:
        """
        Bucket events into fixed time windows.

        Events without a parseable timestamp go into a special
        bucket keyed by datetime.min.

        Returns a dict ordered by window start time.
        """
        if not events:
            return {}
        window = timedelta(minutes=window_minutes)
        buckets: dict[datetime, list[LogEvent]] = {}

        for event in events:
            if event.timestamp is None:
                key = datetime.min
            else:
                # Floor to the nearest window
                epoch = datetime(1970, 1, 1)
                delta = event.timestamp - epoch
                floored = epoch + (delta // window) * window
                key = floored
            buckets.setdefault(key, []).append(event)

        return dict(sorted(buckets.items()))

    @staticmethod
    def summarize(
        events: list[LogEvent],
        max_events: int = 100,
    ) -> str:
        """
        Return a compact text summary of the events suitable for
        pasting into a prompt or report.
        """
        if not events:
            return "(no events)"
        lines: list[str] = []
        shown = events[:max_events]
        for e in shown:
            ts = e.timestamp.isoformat(timespec="seconds") if e.timestamp else "??:??:??"
            lines.append(f"[{ts}] {e.level:8s} {e.message[:160]}")
        if len(events) > max_events:
            lines.append(f"... and {len(events) - max_events} more events")
        return "\n".join(lines)
