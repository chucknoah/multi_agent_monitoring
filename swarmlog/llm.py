"""LLM backends: Adaption (default), any OpenAI-compatible endpoint, and an offline mock.

Every call is cached on disk, keyed by (backend, model, system, user, seed), so reruns
are free and an interrupted run resumes where it stopped.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import threading
import time
from pathlib import Path
import sys
from typing import Any

VERBOSE = False  # set by run_pipeline --verbose: print every successful call with its latency

FATAL_STATUS = {  # errors that retrying cannot fix: stop the whole run immediately
    400: "The request was rejected; check the model name and parameters.",
    401: "Authentication failed: check ADAPTION_API_KEY (Adaption app > Settings > API keys).",
    402: "Payment required: check your credit balance in the Adaption app.",
    403: "Permission denied: this key cannot use this model or endpoint.",
    404: "Not found: the model name is probably wrong. Run `python run_pipeline.py models`.",
    422: "The request was rejected as invalid; check the model name and parameters.",
}


MAX_RATE_WAITS = 30  # up to ~30 min of rate-limit pauses per call before giving up
_RATE_LOCK = threading.Lock()
_LAST_RATE_NOTE = 0.0


class NotCached(Exception):
    """Raised in cache-only mode when a call has not been made yet."""


class FatalLLMError(RuntimeError):
    pass


class UsageCounter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls = 0
        self.cache_hits = 0
        self.chars_in = 0
        self.chars_out = 0
        self.errors = 0

    def add(self, cached: bool, cin: int, cout: int) -> None:
        with self.lock:
            if cached:
                self.cache_hits += 1
            else:
                self.calls += 1
                self.chars_in += cin
                self.chars_out += cout

    def summary(self) -> str:
        return (
            f"{self.calls} API calls, {self.cache_hits} cache hits, "
            f"~{self.chars_in // 4:,} input tokens, ~{self.chars_out // 4:,} output tokens, "
            f"{self.errors} failed calls"
        )


class BaseLLM:
    backend_name = "base"

    def __init__(self, model: str, cache_dir: str | None = None, temperature: float | None = None,
                 max_retries: int = 5) -> None:
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.usage = UsageCounter()

    # -- subclasses implement this -------------------------------------------------
    def _call(self, system: str, user: str, meta: dict | None, seed: int) -> str:
        raise NotImplementedError

    # -- public API -----------------------------------------------------------------
    def complete(self, system: str, user: str, meta: dict | None = None, seed: int = 0) -> str:
        key = hashlib.sha256(
            json.dumps([self.backend_name, self.model, system, user, seed, self.temperature]).encode()
        ).hexdigest()
        path = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if path and path.exists():
            try:
                text = json.loads(path.read_text(encoding="utf-8"))["text"]
                self.usage.add(True, 0, 0)
                return text
            except Exception:
                pass
        if getattr(self, "cache_only", False):
            raise NotCached()
        last_err: Exception | None = None
        t0 = time.time()
        attempt = rate_waits = 0
        while True:
            try:
                text = self._call(system, user, meta, seed) or ""
                break
            except Exception as e:  # network, rate limit, 5xx ...
                last_err = e
                status = getattr(e, "status_code", None)
                detail = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(e))).strip()
                msg = f"{type(e).__name__}{f' {status}' if status else ''}: {detail[:160]}"
                if status in FATAL_STATUS:
                    raise FatalLLMError(f"{self.backend_name}:{self.model} -> {msg}\n{FATAL_STATUS[status]}") from e
                if (status == 429 or "rate limit" in detail.lower()) and rate_waits < MAX_RATE_WAITS:
                    # Rate limited: wait as long as the server asks (default 60 s) and don't use up a retry.
                    rate_waits += 1
                    m = re.search(r"retry after (\d+(?:\.\d+)?)\s*s", detail, re.I)
                    wait = (float(m.group(1)) if m else 60.0) + random.uniform(1, 10)
                    with _RATE_LOCK:
                        global _LAST_RATE_NOTE
                        if time.time() - _LAST_RATE_NOTE > 30:
                            _LAST_RATE_NOTE = time.time()
                            print(f"  [{self.model}] rate limited; pausing ~{wait:.0f}s and retrying "
                                  "(not counted as a failure)", file=sys.stderr, flush=True)
                    time.sleep(wait)
                    continue
                attempt += 1
                if attempt >= self.max_retries:
                    with self.usage.lock:
                        self.usage.errors += 1
                    raise RuntimeError(f"{self.backend_name}:{self.model} failed after retries: {last_err}")
                print(f"  [{self.model}] call failed (attempt {attempt}/{self.max_retries}), retrying: {msg}",
                      file=sys.stderr, flush=True)
                time.sleep(min(30, 2 ** (attempt - 1) + random.random()))
        if VERBOSE:
            print(f"  [{self.model}] ok in {time.time() - t0:.1f}s ({len(text)} chars)", flush=True)
        self.usage.add(False, len(system) + len(user), len(text))
        if path:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"model": self.model, "text": text}), encoding="utf-8")
            os.replace(tmp, path)
        return text

    def complete_json(self, system: str, user: str, meta: dict | None = None, seed: int = 0,
                      retries: int = 2) -> dict | None:
        prompt = user
        for i in range(retries + 1):
            text = self.complete(system, prompt, meta=meta, seed=seed + i)
            obj = extract_json(text)
            if isinstance(obj, dict):
                return obj
            prompt = user + "\n\nYour previous reply was not a valid JSON object. Reply with ONE JSON object only, no prose."
        return None


class AdaptionLLM(BaseLLM):
    """Adaption Responses API. Needs `pip install adaption` (>=0.16) and ADAPTION_API_KEY."""

    backend_name = "adaption"

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        from adaption import Adaption  # imported lazily so mock runs need no SDK
        if not os.environ.get("ADAPTION_API_KEY"):
            raise SystemExit("Set ADAPTION_API_KEY (Adaption app > Settings > API keys).")
        # Big models can take minutes on long replies: allow a long read timeout, and let our own
        # loop (which reports each failure) do the retrying instead of the SDK's silent retries.
        timeout = float(os.environ.get("SWARMLOG_TIMEOUT", "300"))
        self.client = Adaption(timeout=timeout, max_retries=0)

    def _call(self, system: str, user: str, meta: dict | None, seed: int) -> str:
        kwargs: dict[str, Any] = dict(model=self.model, instructions=system, input=user, store=False)
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if os.environ.get("SWARMLOG_STREAM", "1") == "0":
            resp = self.client.responses.create(**kwargs)
            return resp.output_text or ""
        # Streaming keeps the connection busy while the model thinks, which avoids gateway 504 timeouts
        # on long prompts or long replies.
        parts: list[str] = []
        final = ""
        for event in self.client.responses.create(stream=True, **kwargs):
            et = getattr(event, "type", "")
            if et == "response.output_text.delta":
                parts.append(getattr(event, "delta", "") or "")
            elif et == "response.completed":
                final = getattr(getattr(event, "response", None), "output_text", "") or ""
            elif et == "error":
                raise RuntimeError(f"stream error: {getattr(event, 'message', '') or event}")
        return "".join(parts) or final


class OpenAICompatLLM(BaseLLM):
    """Any OpenAI-compatible chat endpoint (OpenRouter, vLLM, OpenAI ...).
    Env: OPENAI_API_KEY, optional OPENAI_BASE_URL."""

    backend_name = "openai"

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        from openai import OpenAI
        self.client = OpenAI(base_url=os.environ.get("OPENAI_BASE_URL") or None)

    def _call(self, system: str, user: str, meta: dict | None, seed: int) -> str:
        kwargs: dict[str, Any] = dict(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        resp = self.client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""


class MockLLM(BaseLLM):
    """Offline stand-in that returns plausible scripted outputs. ONLY for testing the plumbing:
    its numbers mean nothing."""

    backend_name = "mock"

    def __init__(self, *a: Any, **kw: Any) -> None:
        kw["cache_dir"] = None
        super().__init__(*a, **kw)

    def _call(self, system: str, user: str, meta: dict | None, seed: int) -> str:
        from . import mock
        return mock.respond(system, user, meta or {}, seed)


def make_llm(backend: str, model: str, cache_dir: str | None, temperature: float | None = None) -> BaseLLM:
    backend = backend.lower()
    if backend == "adaption":
        return AdaptionLLM(model, cache_dir=cache_dir, temperature=temperature)
    if backend in ("openai", "openai-compatible"):
        return OpenAICompatLLM(model, cache_dir=cache_dir, temperature=temperature)
    if backend == "mock":
        return MockLLM(model, temperature=temperature)
    raise SystemExit(f"Unknown backend {backend!r}; use adaption, openai or mock")


# ---------------------------------------------------------------------------------
_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)


def extract_json(text: str) -> Any:
    """Return the first JSON object found in a model reply (tolerates prose, fences, <think>)."""
    if not text:
        return None
    text = _THINK.sub("", text)
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", text, re.S)
    for chunk in fenced + [text]:
        start = chunk.find("{")
        while start != -1:
            end = _balanced_end(chunk, start)
            if end is not None:
                try:
                    return json.loads(chunk[start:end + 1])
                except json.JSONDecodeError:
                    pass
            start = chunk.find("{", start + 1)
    return None


def _balanced_end(s: str, start: int) -> int | None:
    depth, in_str, esc = 0, False, False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None
