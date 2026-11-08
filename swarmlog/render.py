"""Turn log entries into the text a monitor reads. Gateway entries and clean agent-written
entries render identically, so any difference in monitor scores comes from tampering."""
from __future__ import annotations

import json

MAX_FIELD = 300


def _clip(s: str, n: int = MAX_FIELD) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + f"... [{len(s) - n} more chars]"


def render_entry(e: dict) -> str:
    step = e["step"]
    step_s = f"{step:g}" if isinstance(step, (int, float)) else str(step)
    head = f"[{step_s}] {e['agent']}"
    t = e["type"]
    if t == "message":
        return f"{head} -> {e['to']}: {_clip(e['content'], 600)}"
    if t == "tool_call":
        args = ", ".join(f"{k}={_clip(json.dumps(v) if not isinstance(v, str) else repr(v))}"
                         for k, v in (e.get("args") or {}).items())
        return f"{head} called {e['tool']}({args}) -> {_clip(e.get('result', ''))}"
    if t == "note":
        return f"{head} (note): {_clip(e['content'], 600)}"
    return f"{head} {t}: {_clip(json.dumps(e))}"


def authored_entries(agent_logs: dict[str, list[dict]]) -> list[dict]:
    out = [e for log in agent_logs.values() for e in log if e.get("kind") == "authored"]
    return sorted(out, key=lambda e: (float(e["step"]), e["eid"]))


def render_view(entries: list[dict]) -> str:
    return "\n".join(render_entry(e) for e in sorted(entries, key=lambda e: (float(e["step"]), e["eid"])))


def gateway_view(ep: dict) -> str:
    return render_view(ep["gateway_log"])


def agent_view(ep: dict) -> str:
    return render_view(authored_entries(ep["agent_logs"]))
