#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
N100 Privacy Gateway
- Layer 0: high-precision regex tokenization into an in-memory vault
- Layer 1: Qwen2.5-0.5B residual classifier on leftover secret-shaped spans
- Recursive redaction of Chat Completions + Responses API trees
  (instructions / tools / function_call.arguments / function_call_output.output)
- Outbound restore: non-stream JSON walk + SSE per-path DFA
- Reverse proxy to cli-proxy-api (127.0.0.1:8316)
"""

import os
import re
import json
import time
import math
import hashlib
import logging
import asyncio
from collections import Counter
from typing import Dict, Tuple, Optional, Any, List, Callable, Set
from dataclasses import dataclass
from contextlib import asynccontextmanager
from threading import RLock

from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse, JSONResponse
import httpx
import uvicorn

# ============================================================================
# Config
# ============================================================================
GATEWAY_HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8317"))
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8316").rstrip("/")
VAULT_TTL_SECONDS = int(os.getenv("VAULT_TTL_SECONDS", "7200"))
MAX_HOLD_BYTES = int(os.getenv("MAX_HOLD_BYTES", "96"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

LAYER1_ENABLED = os.getenv("LAYER1_ENABLED", "1").strip() not in ("0", "false", "False", "no")
LAYER1_URL = os.getenv("LAYER1_URL", "http://127.0.0.1:8319").rstrip("/")
LAYER1_TIMEOUT = float(os.getenv("LAYER1_TIMEOUT", "1.2"))
LAYER1_BUDGET = float(os.getenv("LAYER1_BUDGET", "2.5"))
LAYER1_MAX_CANDIDATES = int(os.getenv("LAYER1_MAX_CANDIDATES", "8"))
LAYER1_CONCURRENCY = int(os.getenv("LAYER1_CONCURRENCY", "1"))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("PrivacyGateway")

http_client: Optional[httpx.AsyncClient] = None
layer1_client: Optional[httpx.AsyncClient] = None

HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
}

# Protocol identity fields must not be rewritten (breaks tool-call matching).
PASSTHROUGH_KEYS = {
    "id",
    "call_id",
    "tool_call_id",
    "model",
    "object",
    "type",
    "role",
    "name",
    "status",
    "stream",
    "previous_response_id",
    "response_id",
    "conversation_id",
    "created",
    "created_at",
}

INTERCEPT_PATHS = {
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/messages",
    "/v1/completions",
}


# ============================================================================
# 1. Memory Vault
# ============================================================================
@dataclass
class VaultEntry:
    placeholder: str
    secret: str
    secret_type: str
    created_at: float
    last_accessed_at: float


class MemoryVault:
    def __init__(self, ttl_seconds: int = 7200):
        self.ttl = ttl_seconds
        self._lock = RLock()
        self._placeholder_to_entry: Dict[str, VaultEntry] = {}
        self._secret_to_placeholder: Dict[str, str] = {}
        self._type_counters: Dict[str, int] = {}
        self.total_redacted_count = 0
        self.total_restored_count = 0

    def get_or_create(self, secret: str, secret_type: str) -> str:
        now = time.time()
        with self._lock:
            if secret in self._secret_to_placeholder:
                placeholder = self._secret_to_placeholder[secret]
                entry = self._placeholder_to_entry.get(placeholder)
                if entry:
                    entry.last_accessed_at = now
                    return placeholder

            h8 = hashlib.blake2b(secret.encode("utf-8"), digest_size=4).hexdigest()
            self._type_counters[secret_type] = self._type_counters.get(secret_type, 0) + 1
            idx = self._type_counters[secret_type]
            placeholder = f"<PRIV_{h8}_{secret_type}_{idx}>"
            entry = VaultEntry(
                placeholder=placeholder,
                secret=secret,
                secret_type=secret_type,
                created_at=now,
                last_accessed_at=now,
            )
            self._placeholder_to_entry[placeholder] = entry
            self._secret_to_placeholder[secret] = placeholder
            self.total_redacted_count += 1
            logger.info("Vault Intercept: Redacted %s -> %s", secret_type, placeholder)
            return placeholder

    def get_secret(self, placeholder: str) -> Optional[str]:
        with self._lock:
            entry = self._placeholder_to_entry.get(placeholder)
            if entry:
                entry.last_accessed_at = time.time()
                self.total_restored_count += 1
                return entry.secret
            return None

    def cleanup_expired(self) -> int:
        now = time.time()
        expired_placeholders = []
        with self._lock:
            for p, entry in self._placeholder_to_entry.items():
                if now - entry.last_accessed_at > self.ttl:
                    expired_placeholders.append(p)
            for p in expired_placeholders:
                entry = self._placeholder_to_entry.pop(p, None)
                if entry and entry.secret in self._secret_to_placeholder:
                    self._secret_to_placeholder.pop(entry.secret, None)
        if expired_placeholders:
            logger.info("Vault Cleanup: Evicted %d expired mappings.", len(expired_placeholders))
        return len(expired_placeholders)

    def active_count(self) -> int:
        with self._lock:
            return len(self._placeholder_to_entry)


vault = MemoryVault(ttl_seconds=VAULT_TTL_SECONDS)


# ============================================================================
# 2. Layer 0 — high-precision patterns
# ============================================================================
RE_PLACEHOLDER = re.compile(r"<PRIV_[0-9a-f]{8}_[A-Z0-9_]+_\d+>")

RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----",
    re.MULTILINE,
)

RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# (pattern, type, mode)  mode=full replaces whole match; password=group2 of URI; bearer=keep prefix
RE_DB_URI = re.compile(
    r"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|mssql|clickhouse|amqp(?:s)?|"
    r"https?)://[^\s:/@'\"<>]+:)([^@\s/'\"]+)(@[^\s'\"<>]+)"
)

RE_BEARER = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._\-+=/]{20,512})")

# High-precision vendor prefixes. sk- covers OpenAI / Anthropic / generic sk-*.
RE_FULL_SECRETS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "API_KEY"),
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), "STRIPE"),
    (re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b"), "STRIPE"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "API_KEY"),
    (re.compile(r"\bxai-[A-Za-z0-9]{20,}\b"), "API_KEY"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GITHUB_KEY"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GITHUB_KEY"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "GITLAB_KEY"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS_AKIA"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "AWS_ASIA"),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "HF_TOKEN"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "NPM_TOKEN"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "SLACK_TOKEN"),
    (re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b"), "TELEGRAM_TOKEN"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{32,}\b"), "GOOGLE_API"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"), "SENDGRID"),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{24,}\b"), "WEBHOOK_SECRET"),
    (re.compile(r"\bxapp-[A-Za-z0-9-]{20,}\b"), "X_APP_TOKEN"),
]

# Residual candidate extractors (Layer 1). Applied after Layer 0.
RE_ASSIGN = re.compile(
    r"(?i)(?:^|[\s{,;])(?:['\"]?(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|"
    r"auth(?:orization|_token)?|password|passwd|pwd|private[_-]?key|credentials?|token)"
    r"['\"]?\s*[:=]\s*)(['\"]?)([^'\"\s,;]{8,256})\1"
)
RE_TOKENISH = re.compile(r"\b[A-Za-z0-9_\-]{16,96}\b")
RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
RE_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

ASSIGN_SKIP_VALUES = {
    "true", "false", "none", "null", "undefined", "password", "secret",
    "changeme", "placeholder", "example", "xxxxxx", "********", "your_password",
    "your-token", "redacted", "n/a", "na",
}

LAYER1_PROMPT = (
    "判断以下词或短语是否为需要保密的隐私敏感信息"
    "（包括密码、API密钥、访问令牌、私钥等），仅回答 SECRET 或 SAFE：\n"
    "{text}\n答案："
)


def _should_skip_string(text: str) -> bool:
    if not text:
        return True
    if text.startswith("data:") and ";base64," in text[:96]:
        return True
    return False


class Layer0Redactor:
    @staticmethod
    def freeze_existing_placeholders(text: str) -> Tuple[str, Dict[str, str]]:
        freeze_map: Dict[str, str] = {}

        def _freeze(match: re.Match) -> str:
            raw = match.group(0)
            token = f"__VAULT_FROZEN_{hashlib.md5(raw.encode()).hexdigest()[:12]}__"
            freeze_map[token] = raw
            return token

        return RE_PLACEHOLDER.sub(_freeze, text), freeze_map

    @staticmethod
    def unfreeze_placeholders(text: str, freeze_map: Dict[str, str]) -> str:
        for token, raw in freeze_map.items():
            text = text.replace(token, raw)
        return text

    @classmethod
    def redact_text(cls, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        if _should_skip_string(text):
            return text

        frozen_text, freeze_map = cls.freeze_existing_placeholders(text)

        if "-----BEGIN" in frozen_text and "PRIVATE KEY" in frozen_text:
            frozen_text = RE_PRIVATE_KEY.sub(
                lambda m: vault.get_or_create(m.group(0), "PRIVATE_KEY"),
                frozen_text,
            )

        if "://" in frozen_text and "@" in frozen_text:
            def _sub_db(m: re.Match) -> str:
                return f"{m.group(1)}{vault.get_or_create(m.group(2), 'DB_PASS')}{m.group(3)}"
            frozen_text = RE_DB_URI.sub(_sub_db, frozen_text)

        if "eyJ" in frozen_text:
            frozen_text = RE_JWT.sub(
                lambda m: vault.get_or_create(m.group(0), "JWT"),
                frozen_text,
            )

        for pattern, key_type in RE_FULL_SECRETS:
            frozen_text = pattern.sub(
                lambda m, t=key_type: vault.get_or_create(m.group(0), t),
                frozen_text,
            )

        if "Bearer" in frozen_text or "bearer" in frozen_text:
            def _sub_bearer(m: re.Match) -> str:
                return f"{m.group(1)}{vault.get_or_create(m.group(2), 'BEARER')}"
            frozen_text = RE_BEARER.sub(_sub_bearer, frozen_text)

        return cls.unfreeze_placeholders(frozen_text, freeze_map)

    @classmethod
    def redact_tree(cls, obj: Any, key: Optional[str] = None) -> Any:
        if isinstance(obj, str):
            if key in PASSTHROUGH_KEYS:
                return obj
            return cls.redact_text(obj)
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = cls.redact_tree(item)
            return obj
        if isinstance(obj, dict):
            for k, v in obj.items():
                obj[k] = cls.redact_tree(v, key=k)
            return obj
        return obj


# ============================================================================
# 3. Layer 1 — residual classifier (fail-open)
# ============================================================================
def _shannon(s: str) -> float:
    n = len(s)
    if n <= 1:
        return 0.0
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_boring_token(s: str) -> bool:
    if not s or RE_PLACEHOLDER.search(s):
        return True
    if s.lower() in ASSIGN_SKIP_VALUES:
        return True
    if RE_UUID.match(s):
        return True
    if RE_HOSTNAME.match(s):
        return True
    if "/" in s or "://" in s or s.startswith("."):
        return True
    if RE_HEX.match(s) and len(s) in (32, 40, 64):
        return True
    if s.isalpha():
        return True
    return False


def extract_layer1_candidates(text: str) -> List[str]:
    """Secret-shaped leftovers after Layer 0. Conservative to limit FPs / latency."""
    if not text or _should_skip_string(text):
        return []

    found: List[str] = []
    seen: Set[str] = set()

    def _add(val: str) -> None:
        if not val or val in seen or _is_boring_token(val):
            return
        seen.add(val)
        found.append(val)

    for m in RE_ASSIGN.finditer(text):
        val = m.group(2)
        if val.startswith("<PRIV_"):
            continue
        _add(val)

    for m in RE_BEARER.finditer(text):
        _add(m.group(2))

    tokenish_added = 0
    for m in RE_TOKENISH.finditer(text):
        if tokenish_added >= 4:
            break
        tok = m.group(0)
        if tok.startswith("PRIV_") or tok.startswith("<PRIV"):
            continue
        if not any(ch.isdigit() for ch in tok) or not any(ch.isalpha() for ch in tok):
            continue
        if len(tok) < 24 and not (any(ch.isupper() for ch in tok) and any(ch.islower() for ch in tok)):
            continue
        if _shannon(tok) < 3.3:
            continue
        before = len(found)
        _add(tok)
        if len(found) > before:
            tokenish_added += 1

    return found


class Layer1Classifier:
    def __init__(self):
        self.classified = 0
        self.hits = 0
        self.failures = 0
        self.last_ok: Optional[bool] = None
        self.last_check_at = 0.0
        self._cache: Dict[str, Tuple[bool, float]] = {}
        self._cache_lock = RLock()

    def _cache_get(self, secret: str) -> Optional[bool]:
        key = hashlib.blake2b(secret.encode("utf-8"), digest_size=8).hexdigest()
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            flag, ts = item
            if time.time() - ts > 3600:
                self._cache.pop(key, None)
                return None
            return flag

    def _cache_put(self, secret: str, flag: bool) -> None:
        key = hashlib.blake2b(secret.encode("utf-8"), digest_size=8).hexdigest()
        with self._cache_lock:
            if len(self._cache) > 4096:
                # drop oldest half
                items = sorted(self._cache.items(), key=lambda kv: kv[1][1])
                for k, _ in items[: len(items) // 2]:
                    self._cache.pop(k, None)
            self._cache[key] = (flag, time.time())

    async def reachable(self) -> bool:
        now = time.time()
        if now - self.last_check_at < 15 and self.last_ok is not None:
            return self.last_ok
        client = layer1_client
        if client is None:
            self.last_ok = False
            self.last_check_at = now
            return False
        try:
            resp = await client.get("/health")
            self.last_ok = resp.status_code == 200
        except Exception:
            self.last_ok = False
        self.last_check_at = now
        return self.last_ok

    async def classify(self, text: str) -> bool:
        cached = self._cache_get(text)
        if cached is not None:
            return cached
        client = layer1_client
        if client is None:
            return False
        snippet = text[:180]
        payload = {
            "prompt": LAYER1_PROMPT.format(text=snippet),
            "n_predict": 1,
            "temperature": 0.0,
            "top_k": 1,
            "top_p": 1.0,
            "min_p": 0.0,
            "repeat_penalty": 1.0,
            "cache_prompt": True,
        }
        try:
            resp = await client.post("/completion", json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = str(data.get("content") or "").strip()
            is_secret = content.upper().startswith("SECRET")
            self.classified += 1
            if is_secret:
                self.hits += 1
            self._cache_put(text, is_secret)
            self.last_ok = True
            return is_secret
        except Exception as exc:
            self.failures += 1
            self.last_ok = False
            logger.warning("Layer1 classify failed: %s", exc)
            return False

    async def redact_tree(self, obj: Any) -> Any:
        if not LAYER1_ENABLED:
            return obj
        if not await self.reachable():
            return obj
        strings: List[str] = []
        self._collect_strings(obj, strings)
        candidates: List[str] = []
        seen: Set[str] = set()
        for s in strings:
            for c in extract_layer1_candidates(s):
                if c not in seen:
                    seen.add(c)
                    candidates.append(c)
        if not candidates:
            return obj
        candidates = candidates[:LAYER1_MAX_CANDIDATES]
        secrets = await self._classify_budgeted(candidates)
        if not secrets:
            return obj
        return self._replace_tree(obj, secrets)

    async def _classify_budgeted(self, candidates: List[str]) -> Set[str]:
        secrets: Set[str] = set()
        deadline = time.monotonic() + LAYER1_BUDGET
        sem = asyncio.Semaphore(max(1, LAYER1_CONCURRENCY))

        async def _one(cand: str) -> Tuple[str, bool]:
            async with sem:
                remaining = deadline - time.monotonic()
                if remaining <= 0.02:
                    return cand, False
                try:
                    flag = await asyncio.wait_for(self.classify(cand), timeout=min(LAYER1_TIMEOUT, remaining))
                except Exception:
                    flag = False
                return cand, flag

        tasks = [asyncio.create_task(_one(c)) for c in candidates]
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=LAYER1_BUDGET + 0.2)
        except asyncio.TimeoutError:
            for t in tasks:
                t.cancel()
            results = []
        for item in results:
            if isinstance(item, tuple) and item[1]:
                secrets.add(item[0])
        return secrets

    def _collect_strings(self, obj: Any, out: List[str], key: Optional[str] = None) -> None:
        if isinstance(obj, str):
            if key not in PASSTHROUGH_KEYS and not _should_skip_string(obj):
                out.append(obj)
            return
        if isinstance(obj, list):
            for item in obj:
                self._collect_strings(item, out)
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                self._collect_strings(v, out, key=k)

    def _replace_tree(self, obj: Any, secrets: Set[str], key: Optional[str] = None) -> Any:
        if isinstance(obj, str):
            if key in PASSTHROUGH_KEYS or _should_skip_string(obj):
                return obj
            for secret in sorted(secrets, key=len, reverse=True):
                if secret in obj:
                    holder = vault.get_or_create(secret, "LLM_SECRET")
                    obj = obj.replace(secret, holder)
            return obj
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = self._replace_tree(item, secrets)
            return obj
        if isinstance(obj, dict):
            for k, v in obj.items():
                obj[k] = self._replace_tree(v, secrets, key=k)
            return obj
        return obj


layer1 = Layer1Classifier()


# ============================================================================
# 4. Outbound DFA restorer
# ============================================================================
class DFAStreamRestorer:
    PREFIX = "<PRIV_"
    MAX_HOLD = MAX_HOLD_BYTES

    def __init__(self, vault_lookup: Callable[[str], Optional[str]]):
        self.vault_lookup = vault_lookup
        self.buf = ""

    def feed(self, text: str) -> str:
        if not text:
            return ""
        out: List[str] = []
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if not self.buf:
                if ch == "<":
                    self.buf = "<"
                    i += 1
                else:
                    out.append(ch)
                    i += 1
            else:
                self.buf += ch
                i += 1
                if len(self.buf) <= len(self.PREFIX):
                    if not self.PREFIX.startswith(self.buf):
                        out.append(self._flush_mismatch())
                else:
                    if ch == ">":
                        token = self.buf
                        self.buf = ""
                        restored = self.vault_lookup(token)
                        out.append(restored if restored is not None else token)
                    elif ch.isalnum() or ch == "_":
                        if len(self.buf) >= self.MAX_HOLD:
                            out.append(self.buf)
                            self.buf = ""
                    else:
                        out.append(self._flush_mismatch())
        return "".join(out)

    def _flush_mismatch(self) -> str:
        out = []
        while self.buf:
            first = self.buf[0]
            rest = self.buf[1:]
            out.append(first)
            self.buf = rest
            if rest:
                if len(rest) <= len(self.PREFIX) and self.PREFIX.startswith(rest):
                    break
                elif len(rest) > len(self.PREFIX) and rest.startswith(self.PREFIX):
                    if all(c.isalnum() or c == "_" for c in rest[len(self.PREFIX):]):
                        break
        return "".join(out)

    def flush(self) -> str:
        remaining = self.buf
        self.buf = ""
        return remaining


def restore_text_all(text: str) -> str:
    if not text or "<PRIV_" not in text:
        return text
    return RE_PLACEHOLDER.sub(lambda m: vault.get_secret(m.group(0)) or m.group(0), text)


def restore_json_object(obj: Any) -> Any:
    if isinstance(obj, str):
        return restore_text_all(obj)
    if isinstance(obj, list):
        return [restore_json_object(x) for x in obj]
    if isinstance(obj, dict):
        return {k: restore_json_object(v) for k, v in obj.items()}
    return obj


def restore_stream_obj(obj: Any, path: str, restorers: Dict[str, DFAStreamRestorer], key: Optional[str] = None) -> Any:
    if isinstance(obj, str):
        if key in PASSTHROUGH_KEYS:
            return obj
        restorer = restorers.get(path)
        if restorer is None:
            restorer = DFAStreamRestorer(vault.get_secret)
            restorers[path] = restorer
        return restorer.feed(obj)
    if isinstance(obj, list):
        return [restore_stream_obj(v, f"{path}[{i}]", restorers) for i, v in enumerate(obj)]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = restore_stream_obj(v, f"{path}.{k}", restorers, key=k)
        return out
    return obj


# ============================================================================
# 5. FastAPI lifespan
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, layer1_client
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100, keepalive_expiry=30.0)
    http_client = httpx.AsyncClient(
        base_url=BACKEND_URL,
        limits=limits,
        timeout=httpx.Timeout(connect=10.0, read=180.0, write=30.0, pool=10.0),
    )
    layer1_client = httpx.AsyncClient(
        base_url=LAYER1_URL,
        timeout=httpx.Timeout(connect=0.4, read=LAYER1_TIMEOUT, write=0.5, pool=0.4),
    )
    logger.info(
        "Privacy Gateway started. backend=%s layer1=%s enabled=%s",
        BACKEND_URL, LAYER1_URL, LAYER1_ENABLED,
    )

    async def _cleanup_loop():
        while True:
            await asyncio.sleep(600)
            try:
                vault.cleanup_expired()
            except Exception as e:
                logger.error("Error during vault cleanup: %s", e)

    cleanup_task = asyncio.create_task(_cleanup_loop())
    yield
    cleanup_task.cancel()
    await http_client.aclose()
    await layer1_client.aclose()
    logger.info("Privacy Gateway stopped.")


app = FastAPI(title="N100 Privacy Gateway", lifespan=lifespan)
START_TIME = time.time()


@app.post("/privacy/dry-run")
async def privacy_dry_run(request: Request):
    """Redact a JSON body without forwarding. For local verification only."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid json"})
    data = Layer0Redactor.redact_tree(data)
    layer1_applied = False
    if LAYER1_ENABLED:
        try:
            data = await layer1.redact_tree(data)
            layer1_applied = True
        except Exception as exc:
            logger.error("Layer1 dry-run failed: %s", exc)
    return {
        "redacted": data,
        "vault_active": vault.active_count(),
        "layer1_applied": layer1_applied,
    }


@app.get("/privacy/health")
async def privacy_health():
    layer1_ok = False
    if LAYER1_ENABLED:
        layer1_ok = await layer1.reachable()
    return {
        "status": "ok",
        "uptime_seconds": int(time.time() - START_TIME),
        "total_redacted_secrets": vault.total_redacted_count,
        "total_restored_secrets": vault.total_restored_count,
        "active_vault_mappings": vault.active_count(),
        "backend_url": BACKEND_URL,
        "layer1": {
            "enabled": LAYER1_ENABLED,
            "url": LAYER1_URL,
            "reachable": layer1_ok,
            "classified": layer1.classified,
            "hits": layer1.hits,
            "failures": layer1.failures,
            "cache_size": len(layer1._cache),
        },
    }


def should_intercept(path: str, data: Any) -> bool:
    if path in INTERCEPT_PATHS:
        return True
    if not isinstance(data, dict):
        return False
    return any(k in data for k in ("messages", "input", "instructions", "prompt"))


def filter_request_headers(src: Dict[str, str], content_length: Optional[int] = None) -> Dict[str, str]:
    headers = {k: v for k, v in src.items() if k.lower() not in HOP_BY_HOP}
    if content_length is not None:
        headers["content-length"] = str(content_length)
    return headers


# ============================================================================
# 6. Proxy
# ============================================================================
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def gateway_proxy(request: Request, path: str):
    full_path = "/" + path.lstrip("/")
    if full_path.startswith("/privacy"):
        return JSONResponse(status_code=404, content={"error": "not found"})

    if request.method in ("GET", "HEAD", "OPTIONS"):
        return await transparent_proxy(request, full_path)

    body_bytes = await request.body()
    if not body_bytes:
        return await transparent_proxy(request, full_path, body=body_bytes)

    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return await transparent_proxy(request, full_path, body=body_bytes)

    if not should_intercept(full_path, data):
        return await transparent_proxy(request, full_path, body=body_bytes)

    data = Layer0Redactor.redact_tree(data)
    if LAYER1_ENABLED:
        try:
            data = await layer1.redact_tree(data)
        except Exception as exc:
            logger.error("Layer1 redact failed (fail-open): %s", exc)

    is_stream = bool(isinstance(data, dict) and data.get("stream", False))
    redacted_body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    headers = filter_request_headers(dict(request.headers), content_length=len(redacted_body))

    try:
        upstream_req = http_client.build_request(
            method=request.method,
            url=full_path,
            params=request.query_params,
            headers=headers,
            content=redacted_body,
        )
        upstream_resp = await http_client.send(upstream_req, stream=True)
    except Exception as exc:
        logger.error("Upstream connection failed: %s", exc)
        return JSONResponse(
            status_code=502,
            content={"error": {"message": "Privacy Gateway: Cannot connect to upstream backend.", "type": "bad_gateway"}},
        )

    content_type = upstream_resp.headers.get("content-type", "")
    if upstream_resp.status_code >= 400 or not is_stream or "text/event-stream" not in content_type:
        return await handle_non_streaming_response(upstream_resp)

    return StreamingResponse(
        sse_stream_generator(upstream_resp),
        status_code=upstream_resp.status_code,
        headers={
            "content-type": "text/event-stream",
            "cache-control": "no-cache",
            "connection": "keep-alive",
            "x-accel-buffering": "no",
        },
    )


async def transparent_proxy(request: Request, path: str, body: Optional[bytes] = None):
    if body is None:
        body = await request.body()
    headers = filter_request_headers(dict(request.headers), content_length=len(body) if body else 0)
    try:
        req = http_client.build_request(
            method=request.method,
            url=path,
            params=request.query_params,
            headers=headers,
            content=body,
        )
        res = await http_client.send(req, stream=True)
    except Exception as exc:
        logger.error("Transparent proxy failed for %s: %s", path, exc)
        return JSONResponse(status_code=502, content={"error": "Bad Gateway"})

    async def _body_stream():
        try:
            async for chunk in res.aiter_raw():
                yield chunk
        finally:
            await res.aclose()

    resp_headers = {k: v for k, v in res.headers.items() if k.lower() not in HOP_BY_HOP}
    return StreamingResponse(_body_stream(), status_code=res.status_code, headers=resp_headers)


async def handle_non_streaming_response(upstream_resp: httpx.Response) -> Response:
    try:
        raw_body = await upstream_resp.aread()
        if not raw_body:
            headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in HOP_BY_HOP}
            return Response(content=raw_body, status_code=upstream_resp.status_code, headers=headers)

        try:
            resp_json = json.loads(raw_body.decode("utf-8"))
            restored_json = restore_json_object(resp_json)
            new_bytes = json.dumps(restored_json, ensure_ascii=False).encode("utf-8")
        except Exception:
            new_bytes = restore_text_all(raw_body.decode("utf-8", errors="replace")).encode("utf-8")

        headers = {k: v for k, v in upstream_resp.headers.items() if k.lower() not in HOP_BY_HOP}
        headers.pop("content-encoding", None)
        headers["content-length"] = str(len(new_bytes))
        return Response(content=new_bytes, status_code=upstream_resp.status_code, headers=headers)
    finally:
        await upstream_resp.aclose()


async def sse_stream_generator(upstream_resp: httpx.Response):
    restorers: Dict[str, DFAStreamRestorer] = {}
    try:
        async for line in upstream_resp.aiter_lines():
            if not line:
                yield "\n"
                continue
            if not line.startswith("data:"):
                yield f"{line}\n"
                continue

            payload_str = line[5:].strip()
            if payload_str == "[DONE]":
                leftovers: List[Tuple[str, str]] = []
                for path, restorer in restorers.items():
                    flushed = restorer.flush()
                    if flushed:
                        leftovers.append((path, flushed))
                for path, flushed in leftovers:
                    if ".choices" in path or path.startswith("choices"):
                        dummy = {"choices": [{"index": 0, "delta": {"content": flushed}}]}
                    else:
                        dummy = {"type": "response.output_text.delta", "delta": flushed}
                    yield f"data: {json.dumps(dummy, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
                break

            try:
                chunk_data = json.loads(payload_str)
                chunk_data = restore_stream_obj(chunk_data, "$", restorers)
                yield f"data: {json.dumps(chunk_data, ensure_ascii=False)}\n\n"
            except Exception:
                yield f"{line}\n\n"
    finally:
        await upstream_resp.aclose()


if __name__ == "__main__":
    logger.info("Starting Privacy Gateway on %s:%d ...", GATEWAY_HOST, GATEWAY_PORT)
    uvicorn.run(
        app,
        host=GATEWAY_HOST,
        port=GATEWAY_PORT,
        log_level=LOG_LEVEL.lower(),
        access_log=False,
    )
