# incident-agent-ai

AI-powered on-call incident response agent built on **Claude** (`claude-sonnet-4-6`).

Given a set of log files (nginx, application, Kubernetes) it:

1. Builds a **timeline** of events.
2. Identifies the most likely **root cause** with confidence level.
3. Recommends **immediate mitigation** steps.
4. Lists structured **follow-up actions**.

---

## Installation

```bash
pip install incident-agent-ai
```

or from source:

```bash
git clone https://github.com/example/incident-agent-ai
cd incident-agent-ai
pip install -e .
```

Requires Python 3.10+.

---

## Prerequisites

Set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## CLI Usage

### One-shot analysis

```bash
# Single log file, last 1 hour
incident-agent analyze --logs /var/log/app.log --since "1 hour ago"

# Multiple log files with extra alert context
incident-agent analyze \
  --logs /var/log/nginx/error.log \
  --logs /var/log/app.log \
  --since "30 minutes ago" \
  --context "PagerDuty: p0 -- high 5xx rate on /api/checkout since 14:32 UTC"

# Verbose mode shows every tool call
incident-agent analyze --logs /var/log/app.log --since "2 hours ago" --verbose
```

### Watch mode (continuous monitoring)

```bash
# Re-analyse every 60 s, looking at the last 5 minutes of logs
incident-agent watch --logs /var/log/app.log --interval 60 --window 5
```

---

## Python API

```python
from incident_agent import IncidentAgent

agent = IncidentAgent(verbose=True)

report = agent.analyze(
    log_paths=["/var/log/nginx/error.log", "/var/log/app.log"],
    since="1 hour ago",
    extra_context="High CPU on web-01, deployed v2.3.1 at 14:00 UTC.",
)

print(report.timeline)
print(report.root_cause)
print(report.mitigation)
print(report.follow_up)
```

### Streaming callback

```python
def on_text(chunk: str):
    print(chunk, end="", flush=True)

report = agent.analyze(
    log_paths=["/var/log/app.log"],
    since="30 minutes ago",
    stream_callback=on_text,
)
```

---

## LogParser

You can use `LogParser` independently:

```python
from datetime import datetime, timedelta
from incident_agent import LogParser

parser = LogParser()
since = datetime.now() - timedelta(hours=1)

events = parser.parse_file("/var/log/app.log", since=since)
errors = parser.filter_errors(events)
windows = parser.group_by_window(errors, window_minutes=5)

for window_start, evts in windows.items():
    print(f"{window_start}: {len(evts)} error events")
    print(parser.summarize(evts, max_events=10))
```

### Supported log formats

| Format | Example timestamp |
|--------|------------------|
| ISO-8601 / RFC-3339 | `2024-01-15T14:23:01.123Z` |
| nginx Combined Log | `15/Jan/2024:14:23:01 +0000` |
| Syslog | `Jan 15 14:23:01` |
| Kubernetes / Docker | `2024-01-15T14:23:01.123456789Z` |
| Unix epoch | `1705329781 ...` |

---

## Architecture

```
+-------------------------------------------------+
|                   IncidentAgent                 |
|                                                 |
|  User message --> Streaming agentic loop        |
|                       |                         |
|                  +----v----+                    |
|                  | Claude  | claude-sonnet-4-6  |
|                  +----+----+                    |
|                       | tool_use blocks         |
|              +--------+---------+               |
|              v        v         v               |
|       read_log  grep_logs  get_recent_deploys   |
|             (LogParser helpers)                 |
+-------------------------------------------------+
```

The agent runs a **manual tool-use loop** with `messages.stream()` on every call, so it never times out on large log files. The loop continues until `stop_reason == end_turn` or a 20-iteration safety cap is reached.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | -- | **Required.** Your Anthropic API key. |
| `DEPLOY_LOG_PATH` | `deploy.log` | Override path for deployment log used by `get_recent_deploys`. |

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

---

## License

MIT
