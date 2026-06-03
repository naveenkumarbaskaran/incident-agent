"""
IncidentAgent — reads logs, correlates alerts, suggests RCA.

Uses claude-sonnet-4-6 with a manual tool-use loop and streaming
so long analyses don't time out.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import anthropic

from .log_parser import LogParser

MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 8192

SYSTEM_PROMPT = """
You are an expert on-call incident response assistant.

Given log excerpts, alert data, and deployment history you will:
1. Build a concise chronological TIMELINE of events.
2. Identify the most likely SUSPECTED ROOT CAUSE with a confidence level
   (High / Medium / Low) and your supporting evidence.
3. Recommend IMMEDIATE MITIGATION steps the on-call engineer can execute
   right now to restore service.
4. List structured FOLLOW-UP ACTIONS (owner, priority, description) to
   prevent recurrence.

Always be concise, technically precise, and prioritise actionability.
When evidence is ambiguous, say so explicitly rather than speculating.

Respond in this exact structure:

## Timeline
...

## Suspected Root Cause
**Confidence**: High | Medium | Low
...

## Immediate Mitigation
...

## Follow-up Actions
...
""".strip()

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_log_file",
        "description": (
            "Read a log file from disk, optionally returning only the last"
            " N lines.  Returns the file contents as a string."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the log file.",
                },
                "tail_lines": {
                    "type": "integer",
                    "description": (
                        "If set, return only the last N lines of the file."
                        " Defaults to the full file (capped at 5000 lines)."
                    ),
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "grep_logs",
        "description": (
            "Search for a regex pattern inside a log file."
            " Returns up to 200 matching lines with their line numbers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Python-compatible regular expression to search for.",
                },
                "path": {
                    "type": "string",
                    "description": "Path to the log file to search.",
                },
            },
            "required": ["pattern", "path"],
        },
    },
    {
        "name": "get_recent_deploys",
        "description": (
            "Return a JSON list of recent deployments from common CI/CD"
            " artefacts on disk (git log, CHANGELOG, deploy.log, etc.)."
            " Pass an optional 'since_hours' to limit the window."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "since_hours": {
                    "type": "number",
                    "description": "Look back this many hours.  Defaults to 24.",
                }
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

_MAX_LINES = 5_000
_MAX_GREP_HITS = 200


def _read_log_file(path: str, tail_lines: int | None = None) -> str:
    p = Path(path)
    if not p.exists():
        return f"ERROR: file not found: {path}"
    try:
        text = p.read_text(errors="replace")
    except OSError as exc:
        return f"ERROR reading {path}: {exc}"

    lines = text.splitlines()
    if tail_lines is not None:
        lines = lines[-tail_lines:]
    elif len(lines) > _MAX_LINES:
        lines = lines[-_MAX_LINES:]
        lines.insert(0, f"[truncated — showing last {_MAX_LINES} lines]")
    return "\n".join(lines)


def _grep_logs(pattern: str, path: str) -> str:
    p = Path(path)
    if not p.exists():
        return f"ERROR: file not found: {path}"
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return f"ERROR: invalid regex '{pattern}': {exc}"
    try:
        text = p.read_text(errors="replace")
    except OSError as exc:
        return f"ERROR reading {path}: {exc}"

    hits: list[str] = []
    for i, line in enumerate(text.splitlines(), 1):
        if compiled.search(line):
            hits.append(f"{i:6d}: {line}")
        if len(hits) >= _MAX_GREP_HITS:
            hits.append(f"[truncated — first {_MAX_GREP_HITS} matches shown]")
            break
    if not hits:
        return f"No matches for '{pattern}' in {path}"
    return "\n".join(hits)


def _get_recent_deploys(since_hours: float = 24.0) -> str:
    cutoff = datetime.now() - timedelta(hours=since_hours)
    deploys: list[dict[str, str]] = []

    # --- git log ---
    try:
        since_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
        result = subprocess.run(
            [
                "git", "log",
                f"--since={since_str}",
                "--oneline",
                "--no-walk=unsorted",
                "-50",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(" ", 1)
            deploys.append(
                {
                    "source": "git",
                    "sha": parts[0],
                    "message": parts[1] if len(parts) > 1 else "",
                }
            )
    except Exception:  # noqa: BLE001
        pass

    # --- deploy.log / DEPLOY_LOG env override ---
    deploy_log_candidates = [
        os.environ.get("DEPLOY_LOG_PATH", ""),
        "deploy.log",
        "/var/log/deploy.log",
        "/tmp/deploy.log",
    ]
    for candidate in deploy_log_candidates:
        if not candidate:
            continue
        dp = Path(candidate)
        if dp.exists():
            try:
                for line in dp.read_text(errors="replace").splitlines():
                    deploys.append({"source": str(dp), "line": line})
            except OSError:
                pass
            break

    if not deploys:
        return json.dumps(
            {"message": f"No deployment records found in the last {since_hours}h"}
        )
    return json.dumps(deploys, indent=2)


def _dispatch_tool(name: str, tool_input: dict[str, Any]) -> str:
    if name == "read_log_file":
        return _read_log_file(
            tool_input["path"],
            tool_input.get("tail_lines"),
        )
    if name == "grep_logs":
        return _grep_logs(tool_input["pattern"], tool_input["path"])
    if name == "get_recent_deploys":
        return _get_recent_deploys(tool_input.get("since_hours", 24.0))
    return f"ERROR: unknown tool '{name}'"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class IncidentReport:
    timeline: str = ""
    root_cause: str = ""
    mitigation: str = ""
    follow_up: str = ""
    raw_response: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    # ---- parsing helpers ----

    def _extract_section(self, header: str) -> str:
        """Pull text between ## header and the next ## header (or EOF)."""
        pattern = rf"(?m)^##\s*{re.escape(header)}\s*\n(.*?)(?=^##\s|\Z)"
        m = re.search(pattern, self.raw_response, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def parse(self) -> "IncidentReport":
        self.timeline = self._extract_section("Timeline")
        self.root_cause = self._extract_section("Suspected Root Cause")
        self.mitigation = self._extract_section("Immediate Mitigation")
        self.follow_up = self._extract_section("Follow-up Actions")
        return self


# ---------------------------------------------------------------------------
# IncidentAgent
# ---------------------------------------------------------------------------


class IncidentAgent:
    """
    On-call incident response agent.

    Parameters
    ----------
    api_key:
        Anthropic API key.  Falls back to the ANTHROPIC_API_KEY env var.
    model:
        Claude model string.  Defaults to claude-sonnet-4-6.
    verbose:
        If True, print tool calls to stderr while running.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = MODEL,
        verbose: bool = False,
    ) -> None:
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        )
        self.model = model
        self.verbose = verbose
        self._parser = LogParser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        log_paths: list[str],
        since: str | None = None,
        extra_context: str | None = None,
        stream_callback=None,
    ) -> IncidentReport:
        """
        Run a full incident analysis.

        Parameters
        ----------
        log_paths:
            List of log file paths to analyse.
        since:
            Human-readable time specification, e.g. "1 hour ago",
            "30 minutes ago", "2024-01-15 14:00".
        extra_context:
            Any free-form text (alert body, Slack thread, PagerDuty
            details) to prepend to the prompt.
        stream_callback:
            Optional callable(text_delta: str) invoked for each streamed
            text chunk from the final answer.

        Returns
        -------
        IncidentReport
        """
        user_message = self._build_user_message(
            log_paths, since, extra_context
        )
        report = self._run_agent_loop(user_message, stream_callback)
        return report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_user_message(self, log_paths, since, extra_context) -> str:
        parts: list[str] = []
        if extra_context:
            parts.append(f"## Alert / Context\n{extra_context}\n")

        parts.append("## Log Files to Investigate")
        for p in log_paths:
            parts.append(f"- {p}")

        if since:
            parts.append(f"\n**Time window**: events since {since}")

        parts.append(
            "\nPlease investigate these logs using the available tools,"
            " then produce a full incident report."
        )
        return "\n".join(parts)

    def _run_agent_loop(
        self, user_message: str, stream_callback=None
    ) -> IncidentReport:
        """
        Manual agentic loop: call => tool use => call => ... => end_turn.
        Uses streaming only on the final (non-tool) response.
        """
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": user_message}
        ]
        report = IncidentReport()
        iteration = 0
        MAX_ITERATIONS = 20  # safety cap

        while iteration < MAX_ITERATIONS:
            iteration += 1
            is_last = False  # will be set True when stop_reason == end_turn

            # Use streaming on every call so large responses don't time out
            with self._client.messages.stream(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            ) as stream:
                # Stream text deltas if a callback is provided
                for event in stream:
                    if (
                        stream_callback is not None
                        and event.type == "content_block_delta"
                        and hasattr(event.delta, "text")
                    ):
                        stream_callback(event.delta.text)

                response = stream.get_final_message()

            stop_reason = response.stop_reason

            # Collect tool_use blocks
            tool_use_blocks = [
                b for b in response.content if b.type == "tool_use"
            ]

            # Append assistant turn to history
            messages.append(
                {"role": "assistant", "content": response.content}
            )

            if stop_reason == "end_turn" or not tool_use_blocks:
                # Extract final text
                text_parts = [
                    b.text
                    for b in response.content
                    if b.type == "text"
                ]
                report.raw_response = "\n".join(text_parts)
                is_last = True

            if tool_use_blocks:
                # Execute all requested tools and feed results back
                tool_results: list[dict[str, Any]] = []
                for block in tool_use_blocks:
                    if self.verbose:
                        import sys
                        print(
                            f"[tool] {block.name}({json.dumps(block.input)})",
                            file=sys.stderr,
                        )
                    result = _dispatch_tool(block.name, block.input)
                    report.tool_calls.append(
                        {
                            "tool": block.name,
                            "input": block.input,
                            "result_preview": result[:200],
                        }
                    )
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        }
                    )
                messages.append({"role": "user", "content": tool_results})

            if is_last:
                break

        report.parse()
        return report
