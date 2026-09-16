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
import sqlite3
from pathlib import Path
from collections import Counter, OrderedDict
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
# Cloud-bound requests are always tagged <SECRET_TYPE_idx>.
# User-facing outbound echo restores original credentials from the vault
# (ChatGPT project: UI display restore). Set 0 to keep tags in the reply.
RESTORE_OUTBOUND = os.getenv("RESTORE_OUTBOUND", "1").strip() not in ("0", "false", "False", "no")

LAYER1_ENABLED = os.getenv("LAYER1_ENABLED", "1").strip() not in ("0", "false", "False", "no")
LAYER1_URL = os.getenv("LAYER1_URL", "http://127.0.0.1:8319").rstrip("/")
LAYER1_TIMEOUT = float(os.getenv("LAYER1_TIMEOUT", "3.8"))
LAYER1_BUDGET = float(os.getenv("LAYER1_BUDGET", "3.5"))
LAYER1_MAX_CANDIDATES = int(os.getenv("LAYER1_MAX_CANDIDATES", "8"))
LAYER1_CONCURRENCY = int(os.getenv("LAYER1_CONCURRENCY", "1"))
# Long residual spans dominate a mixed batch on N100 (~145 tok / 180 chars).
# Passwords / emails / usernames fit in 80 chars; Layer0 already owns JWT/PEM/sk-.
LAYER1_SPAN_MAX = int(os.getenv("LAYER1_SPAN_MAX", "80"))
VAULT_PERSIST = os.getenv("VAULT_PERSIST", "1").strip() not in ("0", "false", "False", "no")
VAULT_DB_PATH = os.getenv("VAULT_DB_PATH", "/var/lib/privacy-gateway/store.sqlite")
VAULT_KEY_FILE = os.getenv("VAULT_KEY_FILE", "/etc/privacy-gateway/master.key")
VAULT_PASSWORD = os.getenv("VAULT_PASSWORD", "").strip()
VAULT_MASTER_KEY = os.getenv("VAULT_MASTER_KEY", "").strip()
VAULT_KEY_SOURCE = "file"
VAULT_MEM_MAX = int(os.getenv("VAULT_MEM_MAX", "8192"))
VAULT_DISK_TTL_SECONDS = int(os.getenv("VAULT_DISK_TTL_SECONDS", str(90 * 24 * 3600)))
LAYER1_CACHE_MEM_MAX = int(os.getenv("LAYER1_CACHE_MEM_MAX", "16384"))
LAYER1_CACHE_TTL = int(os.getenv("LAYER1_CACHE_TTL", str(30 * 24 * 3600)))
CUSTOM_SECRETS_ENV = [s.strip() for s in os.getenv("CUSTOM_SECRETS", "").split(",") if s.strip()]
CUSTOM_SECRETS_FILE = os.getenv("CUSTOM_SECRETS_FILE", "/etc/privacy-gateway/custom_secrets.txt")

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
# 1. Encrypted SQLite (WAL) + memory LRU
# ============================================================================
@dataclass
class VaultEntry:
    placeholder: str
    secret: str
    secret_type: str
    created_at: float
    last_accessed_at: float


def _load_or_create_key(path: str) -> bytes:
    global VAULT_KEY_SOURCE
    if VAULT_PASSWORD:
        VAULT_KEY_SOURCE = "password"
        logger.info("Using user-customized master password for vault encryption (PBKDF2-SHA256)")
        return hashlib.pbkdf2_hmac("sha256", VAULT_PASSWORD.encode("utf-8"), b"dsh-privacy-gateway-v4-master-salt", 100000)

    if VAULT_MASTER_KEY:
        VAULT_KEY_SOURCE = "master_key"
        logger.info("Using user-customized master key for vault encryption")
        if len(VAULT_MASTER_KEY) == 64:
            try:
                return bytes.fromhex(VAULT_MASTER_KEY)
            except ValueError:
                pass
        return hashlib.blake2b(VAULT_MASTER_KEY.encode("utf-8"), digest_size=32).digest()

    VAULT_KEY_SOURCE = "file"
    key_path = Path(path)
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if key_path.exists():
        key = key_path.read_bytes()
        if len(key) < 32:
            raise ValueError("vault key file too short")
        return key[:32] if len(key) == 32 else hashlib.blake2b(key, digest_size=32).digest()
    key = os.urandom(32)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    os.chmod(str(key_path), 0o600)
    logger.info("Generated new vault master key at %s (mode 0600)", path)
    return key


def _load_custom_secrets() -> List[str]:
    env_str = os.getenv("CUSTOM_SECRETS", "")
    secrets = [s.strip() for s in env_str.split(",") if s.strip()] + list(CUSTOM_SECRETS_ENV)
    p = Path(CUSTOM_SECRETS_FILE)
    if p.exists():
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    secrets.append(line)
        except Exception as exc:
            logger.warning("Failed to read %s: %s", CUSTOM_SECRETS_FILE, exc)
    return sorted(set(secrets), key=len, reverse=True)


class EncryptedStore:
    """SQLite WAL store. Secrets are AES-GCM encrypted; spans in layer1 cache are hashed."""

    def __init__(self, db_path: str, key_file: str):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.db_path = db_path
        Path(db_path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._aes = AESGCM(_load_or_create_key(key_file))
        self._lock = RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        os.chmod(db_path, 0o600)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vault (
                placeholder TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL UNIQUE,
                secret_enc BLOB NOT NULL,
                secret_type TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_accessed_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS type_counters (
                secret_type TEXT PRIMARY KEY,
                last_idx INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS layer1_cache (
                cache_hash TEXT PRIMARY KEY,
                is_secret INTEGER NOT NULL,
                created_at REAL NOT NULL,
                last_accessed_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            """
        )

    def _encrypt(self, plaintext: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, plaintext.encode("utf-8"), b"vault-v1")

    def _decrypt(self, blob: bytes) -> str:
        return self._aes.decrypt(blob[:12], blob[12:], b"vault-v1").decode("utf-8")

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()

    def vault_get_by_secret(self, secret: str) -> Optional[VaultEntry]:
        h = self._hash(secret)
        with self._lock:
            row = self._conn.execute(
                "SELECT placeholder, secret_enc, secret_type, created_at, last_accessed_at FROM vault WHERE secret_hash=?",
                (h,),
            ).fetchone()
        if not row:
            return None
        now = time.time()
        with self._lock:
            self._conn.execute("UPDATE vault SET last_accessed_at=? WHERE secret_hash=?", (now, h))
        return VaultEntry(row[0], self._decrypt(row[1]), row[2], row[3], now)

    def vault_get_by_placeholder(self, placeholder: str) -> Optional[VaultEntry]:
        with self._lock:
            row = self._conn.execute(
                "SELECT placeholder, secret_enc, secret_type, created_at, last_accessed_at FROM vault WHERE placeholder=?",
                (placeholder,),
            ).fetchone()
        if not row:
            return None
        now = time.time()
        with self._lock:
            self._conn.execute("UPDATE vault SET last_accessed_at=? WHERE placeholder=?", (now, placeholder))
        return VaultEntry(row[0], self._decrypt(row[1]), row[2], row[3], now)

    def vault_put(self, entry: VaultEntry) -> None:
        h = self._hash(entry.secret)
        enc = self._encrypt(entry.secret)
        with self._lock:
            self._conn.execute(
                """INSERT INTO vault(placeholder, secret_hash, secret_enc, secret_type, created_at, last_accessed_at)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(placeholder) DO UPDATE SET
                     last_accessed_at=excluded.last_accessed_at""",
                (entry.placeholder, h, enc, entry.secret_type, entry.created_at, entry.last_accessed_at),
            )

    def vault_next_idx(self, secret_type: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT last_idx FROM type_counters WHERE secret_type=?", (secret_type,)
            ).fetchone()
            nxt = (row[0] + 1) if row else 1
            self._conn.execute(
                "INSERT INTO type_counters(secret_type, last_idx) VALUES(?,?) ON CONFLICT(secret_type) DO UPDATE SET last_idx=?",
                (secret_type, nxt, nxt),
            )
            return nxt

    def vault_load_all(self) -> List[VaultEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT placeholder, secret_enc, secret_type, created_at, last_accessed_at FROM vault"
            ).fetchall()
        out = []
        for row in rows:
            try:
                out.append(VaultEntry(row[0], self._decrypt(row[1]), row[2], row[3], row[4]))
            except Exception as exc:
                logger.error("Skipping undecryptable vault row %s: %s", row[0], exc)
        return out

    def vault_delete_idle(self, ttl: float) -> int:
        cutoff = time.time() - ttl
        with self._lock:
            cur = self._conn.execute("DELETE FROM vault WHERE last_accessed_at < ?", (cutoff,))
            return cur.rowcount or 0

    def vault_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM vault").fetchone()
            return int(row[0] if row else 0)

    def cache_get(self, cache_key: str, ttl: float) -> Optional[bool]:
        h = self._hash(cache_key)
        with self._lock:
            row = self._conn.execute(
                "SELECT is_secret, last_accessed_at FROM layer1_cache WHERE cache_hash=?", (h,)
            ).fetchone()
        if not row:
            return None
        if time.time() - row[1] > ttl:
            with self._lock:
                self._conn.execute("DELETE FROM layer1_cache WHERE cache_hash=?", (h,))
            return None
        with self._lock:
            self._conn.execute("UPDATE layer1_cache SET last_accessed_at=? WHERE cache_hash=?", (time.time(), h))
        return bool(row[0])

    def cache_put(self, cache_key: str, is_secret: bool) -> None:
        h = self._hash(cache_key)
        now = time.time()
        with self._lock:
            self._conn.execute(
                """INSERT INTO layer1_cache(cache_hash, is_secret, created_at, last_accessed_at)
                   VALUES(?,?,?,?)
                   ON CONFLICT(cache_hash) DO UPDATE SET is_secret=excluded.is_secret, last_accessed_at=excluded.last_accessed_at""",
                (h, 1 if is_secret else 0, now, now),
            )

    def cache_load_all(self, ttl: float) -> List[Tuple[str, bool, float]]:
        cutoff = time.time() - ttl
        with self._lock:
            rows = self._conn.execute(
                "SELECT cache_hash, is_secret, last_accessed_at FROM layer1_cache WHERE last_accessed_at >= ?",
                (cutoff,),
            ).fetchall()
        return [(r[0], bool(r[1]), r[2]) for r in rows]

    def cache_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM layer1_cache").fetchone()
            return int(row[0] if row else 0)

    def cache_delete_idle(self, ttl: float) -> int:
        cutoff = time.time() - ttl
        with self._lock:
            cur = self._conn.execute("DELETE FROM layer1_cache WHERE last_accessed_at < ?", (cutoff,))
            return cur.rowcount or 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class MemoryVault:
    def __init__(self, ttl_seconds: int = 7200, store: Optional[EncryptedStore] = None, mem_max: int = 8192):
        self.ttl = ttl_seconds
        self.store = store
        self.mem_max = mem_max
        self._lock = RLock()
        self._placeholder_to_entry: "OrderedDict[str, VaultEntry]" = OrderedDict()
        self._secret_to_placeholder: Dict[str, str] = {}
        self._type_counters: Dict[str, int] = {}
        self.total_redacted_count = 0
        self.total_restored_count = 0
        if store is not None:
            self._hydrate()

    def _hydrate(self) -> None:
        assert self.store is not None
        entries = self.store.vault_load_all()
        with self._lock:
            for entry in entries:
                if entry.secret.startswith("__VAULT_FROZEN_"):
                    continue
                self._remember(entry)
                self._type_counters[entry.secret_type] = max(
                    self._type_counters.get(entry.secret_type, 0),
                    _placeholder_idx(entry.placeholder, entry.secret_type),
                )
            self.total_redacted_count = len(self._placeholder_to_entry)
        logger.info("Vault hydrated %d encrypted mappings from disk", len(self._placeholder_to_entry))

    def _remember(self, entry: VaultEntry) -> None:
        self._placeholder_to_entry[entry.placeholder] = entry
        self._placeholder_to_entry.move_to_end(entry.placeholder)
        self._secret_to_placeholder[entry.secret] = entry.placeholder
        while len(self._placeholder_to_entry) > self.mem_max:
            old_ph, old = self._placeholder_to_entry.popitem(last=False)
            if self._secret_to_placeholder.get(old.secret) == old_ph:
                self._secret_to_placeholder.pop(old.secret, None)

    def get_or_create(self, secret: str, secret_type: str) -> str:
        if secret.startswith("__VAULT_FROZEN_"):
            return secret
        now = time.time()
        with self._lock:
            if secret in self._secret_to_placeholder:
                placeholder = self._secret_to_placeholder[secret]
                entry = self._placeholder_to_entry.get(placeholder)
                if entry:
                    entry.last_accessed_at = now
                    self._placeholder_to_entry.move_to_end(placeholder)
                    if self.store:
                        self.store.vault_put(entry)
                    return placeholder

            if self.store is not None:
                disk = self.store.vault_get_by_secret(secret)
                if disk:
                    disk.last_accessed_at = now
                    self._remember(disk)
                    return disk.placeholder

            if self.store is not None:
                idx = self.store.vault_next_idx(secret_type)
                self._type_counters[secret_type] = idx
            else:
                self._type_counters[secret_type] = self._type_counters.get(secret_type, 0) + 1
                idx = self._type_counters[secret_type]
            placeholder = f"<SECRET_{secret_type}_{idx}>"
            entry = VaultEntry(
                placeholder=placeholder,
                secret=secret,
                secret_type=secret_type,
                created_at=now,
                last_accessed_at=now,
            )
            self._remember(entry)
            self.total_redacted_count += 1
            if self.store is not None:
                self.store.vault_put(entry)
            logger.info("Vault Intercept: Redacted %s -> %s", secret_type, placeholder)
            return placeholder

    def get_secret(self, placeholder: str) -> Optional[str]:
        with self._lock:
            entry = self._placeholder_to_entry.get(placeholder)
            if entry:
                entry.last_accessed_at = time.time()
                self._placeholder_to_entry.move_to_end(placeholder)
                self.total_restored_count += 1
                if self.store:
                    self.store.vault_put(entry)
                return entry.secret
            if self.store is not None:
                disk = self.store.vault_get_by_placeholder(placeholder)
                if disk:
                    self._remember(disk)
                    self.total_restored_count += 1
                    return disk.secret
            return None

    def cleanup_expired(self) -> int:
        n = 0
        if self.store is not None:
            n = self.store.vault_delete_idle(VAULT_DISK_TTL_SECONDS)
            n += self.store.cache_delete_idle(LAYER1_CACHE_TTL)
        now = time.time()
        expired = []
        with self._lock:
            for p, entry in list(self._placeholder_to_entry.items()):
                if now - entry.last_accessed_at > self.ttl and self.store is None:
                    expired.append(p)
            for p in expired:
                entry = self._placeholder_to_entry.pop(p, None)
                if entry and entry.secret in self._secret_to_placeholder:
                    self._secret_to_placeholder.pop(entry.secret, None)
                n += 1
        if n:
            logger.info("Vault Cleanup: Evicted %d expired mappings.", n)
        return n

    def active_count(self) -> int:
        if self.store is not None:
            return self.store.vault_count()
        with self._lock:
            return len(self._placeholder_to_entry)

    def persist_stats(self) -> Dict[str, Any]:
        if self.store is None:
            return {"enabled": False}
        return {
            "enabled": True,
            "db_path": self.store.db_path,
            "vault_rows": self.store.vault_count(),
            "layer1_rows": self.store.cache_count(),
            "mem_mappings": len(self._placeholder_to_entry),
            "key_source": VAULT_KEY_SOURCE,
            "custom_secrets_count": len(_load_custom_secrets()),
        }


def _placeholder_idx(placeholder: str, secret_type: str) -> int:
    prefix = f"<SECRET_{secret_type}_"
    if placeholder.startswith(prefix) and placeholder.endswith(">"):
        try:
            return int(placeholder[len(prefix):-1])
        except ValueError:
            return 0
    return 0


def _open_store() -> Optional[EncryptedStore]:
    if not VAULT_PERSIST:
        return None
    try:
        return EncryptedStore(VAULT_DB_PATH, VAULT_KEY_FILE)
    except Exception as exc:
        logger.error("Persistent vault disabled (init failed): %s", exc)
        return None


store = _open_store()
vault = MemoryVault(ttl_seconds=VAULT_TTL_SECONDS, store=store, mem_max=VAULT_MEM_MAX)


# ============================================================================
# 2. Layer 0 — high-precision patterns
# ============================================================================
# Accept v4 user-facing tags and legacy PRIV_hash tags.
RE_PLACEHOLDER = re.compile(r"<(?:SECRET_[A-Z0-9_]+_\d+|PRIV_[0-9a-f]{8}_[A-Z0-9_]+_\d+)>")

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
    r"(?i)(?:^|[\s{,;])(?:['\"]?(?P<key>api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|"
    r"auth(?:orization|_token)?|password|passwd|pwd|private[_-]?key|credentials?|token)"
    r"['\"]?\s*[:=]\s*)(?P<q>['\"]?)(?P<val>[^'\"\s,;\\{{}}]{8,256})(?P=q)"
)
SPAN_STRIP = " \t\n\r'\"`<>:,;()[]{}\\"
RE_TOKENISH = re.compile(r"\b[A-Za-z0-9_\-]{16,96}\b")
RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
RE_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
RE_SYSTEM_ID = re.compile(r"^(?:session|task|run|job|step|user|item|goal|event)-[0-9a-zA-Z_\-]{12,}$")
RE_MODEL_LIKE = re.compile(
    r"(?i)^(?:"
    r"(?:claude|gpt|grok|gemini|gemma|deepseek|qwen\d*|llama|mistral|mixtral|"
    r"kimi|glm|commandr?|codex|doubao|yi|baichuan|internlm|phi|falcon|olmo|"
    r"smol|o[1-4])"
    r"(?:[-._][A-Za-z0-9._-]+)+"
    r"|(?:ccswitch-aggregator|deepseek-official|openai|anthropic|google|xai|meta)"
    r"/[A-Za-z0-9._-]+"
    r")$"
)

KNOWN_CODE_IDENTIFIERS: Set[str] = {
    # Gateway constants and functions
    "LAYER1_MAX_CANDIDATES", "LAYER1_CONCURRENCY", "LAYER1_ENABLED", "LAYER1_URL",
    "LAYER1_TIMEOUT", "LAYER1_BUDGET", "LAYER1_SPAN_MAX", "MAX_HOLD_BYTES", "VAULT_TTL_SECONDS",
    "BACKEND_URL", "GATEWAY_HOST", "GATEWAY_PORT", "LOG_LEVEL",
    "TOTAL_REDACTED_SECRETS", "TOTAL_RESTORED_SECRETS", "ACTIVE_VAULT_MAPPINGS",
    "extract_layer1_candidates", "extract_layer1_items", "Layer1Classifier",
    "Layer0Redactor", "DFAStreamRestorer", "MemoryVault",
    "PASSTHROUGH_KEYS", "INTERCEPT_PATHS", "HOP_BY_HOP",
    "RE_TOKENISH", "RE_ASSIGN", "RE_PLACEHOLDER", "RE_PRIVATE_KEY", "RE_DB_URI", "RE_BEARER",
    # System & environment variables
    "DSH_HOME", "DSH_SESSION", "DSH_WEB_URL", "DSH_SHELL", "DSH_SESSION_ID",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "PYTHONPATH", "PYTHONUNBUFFERED",
    "NODE_ENV", "PATH", "LANG", "SHELL", "USER", "HOME", "TERM", "HOSTNAME",
    # Common headers / protocol tokens
    "Content-Type", "application/json", "Authorization", "Bearer", "text/event-stream",
    # LLM providers / routes (must not be rewritten or subagent allowlists break)
    "ccswitch-aggregator", "deepseek-official", "openai-responses",
}
KNOWN_CODE_IDENTIFIERS_CF = {x.casefold() for x in KNOWN_CODE_IDENTIFIERS}

ASSIGN_SKIP_VALUES = {
    "true", "false", "none", "null", "undefined", "password", "secret",
    "changeme", "placeholder", "example", "xxxxxx", "********", "your_password",
    "your-token", "redacted", "n/a", "na",
}

# Train == serve (v4). Empty ctx collapses to SAFE; keyed secrets use "env file",
# keyless residual tokenish uses "bearer token".
LAYER1_PROMPT_K = "Secret? k={key} v={span} c={ctx} ->"
LAYER1_PROMPT_V = "Secret? v={span} c={ctx} ->"
LAYER1_CTX_SECRET = "env file"
LAYER1_CTX_SAFE = "example docs"
LAYER1_CTX_TOKENISH = "bearer token"
LAYER1_SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "client_secret", "api_secret",
    "token", "access_token", "refresh_token", "private_key", "signing_key",
    "webhook_secret", "cookie_secret", "session_secret", "api_key",
    "auth_token", "db_password", "mysql_password", "postgres_password",
}


def _should_skip_string(text: str) -> bool:
    if not text:
        return True
    if text.startswith("data:") and ";base64," in text[:96]:
        return True
    return False


def _try_json(text: str):
    """Parse nested JSON strings (e.g. function_call.arguments) so replacements
    run on decoded values instead of escaped JSON text. That prevents eating
    `}` / `\\` before `\"` and breaking the arguments object."""
    if not isinstance(text, str) or len(text) < 2:
        return None
    lead = text.lstrip()
    if not lead or lead[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


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

        # 0. User-defined custom secrets / tokens (highest deterministic priority)
        for cs in _load_custom_secrets():
            if cs and cs in frozen_text:
                frozen_text = frozen_text.replace(cs, vault.get_or_create(cs, "CUSTOM_SECRET"))

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
            inner = _try_json(obj)
            if inner is not None:
                return json.dumps(cls.redact_tree(inner), ensure_ascii=False)
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


def _is_boring_token(s: str, is_assign: bool = False) -> bool:
    s = s.strip(SPAN_STRIP)
    if not s or len(s) < 8 or RE_PLACEHOLDER.search(s):
        return True
    if any(ch in s for ch in "\\\"{}"):
        return True
    if s.startswith("__VAULT_FROZEN_"):
        return True
    if s.lower() in ASSIGN_SKIP_VALUES:
        return True
    if RE_UUID.match(s) or RE_SYSTEM_ID.match(s) or RE_HOSTNAME.match(s):
        return True
    if "/" in s or "://" in s or s.startswith("."):
        return True
    if RE_HEX.match(s) and len(s) in (32, 40, 64):
        return True
    if s.isalpha():
        return True
    clean_id = s.lstrip("n") if s.startswith("n") and s[1:].isupper() else s
    # Only skip *known* function/constant names. Unknown snake_case may be a secret.
    if s in KNOWN_CODE_IDENTIFIERS or clean_id in KNOWN_CODE_IDENTIFIERS:
        return True
    if s.casefold() in KNOWN_CODE_IDENTIFIERS_CF or clean_id.casefold() in KNOWN_CODE_IDENTIFIERS_CF:
        return True
    if RE_MODEL_LIKE.match(s) or RE_MODEL_LIKE.match(clean_id):
        return True
    return False


def _layer1_ctx(key: str, kind: str) -> str:
    if kind in ("tokenish", "bearer"):
        return LAYER1_CTX_TOKENISH
    k = (key or "").lower()
    if k in LAYER1_SECRET_KEYS or any(sk in k for sk in LAYER1_SECRET_KEYS):
        return LAYER1_CTX_SECRET
    if k:
        return LAYER1_CTX_SAFE
    return LAYER1_CTX_TOKENISH


def extract_layer1_items(text: str) -> List[Dict[str, str]]:
    """Secret-shaped leftovers after Layer 0, with v4 prompt fields."""
    if not text or _should_skip_string(text):
        return []

    found: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def _add(span: str, key: str, kind: str) -> None:
        span = span.strip(SPAN_STRIP)
        is_assign = (kind == "assign")
        if not span or span in seen or _is_boring_token(span, is_assign=is_assign):
            return
        seen.add(span)
        found.append({"span": span, "key": key or "", "ctx": _layer1_ctx(key, kind)})

    for m in RE_ASSIGN.finditer(text):
        val = m.group("val")
        if val.startswith("<PRIV_") or val.startswith("<SECRET_") or val.startswith("__VAULT_"):
            continue
        _add(val, m.group("key") or "", "assign")

    for m in RE_BEARER.finditer(text):
        _add(m.group(2), "token", "bearer")

    tokenish_added = 0
    for m in RE_TOKENISH.finditer(text):
        if tokenish_added >= 4:
            break
        tok = m.group(0).strip(SPAN_STRIP)
        if tok.startswith("PRIV_") or tok.startswith("SECRET_") or tok.startswith("<PRIV") or tok.startswith("<SECRET") or tok.startswith("__VAULT_"):
            continue
        if not any(ch.isdigit() for ch in tok) or not any(ch.isalpha() for ch in tok):
            continue
        if len(tok) < 24 and not (any(ch.isupper() for ch in tok) and any(ch.islower() for ch in tok)):
            continue
        if _shannon(tok) < 3.3:
            continue
        before = len(found)
        _add(tok, "", "tokenish")
        if len(found) > before:
            tokenish_added += 1

    return found


def extract_layer1_candidates(text: str) -> List[str]:
    return [item["span"] for item in extract_layer1_items(text)]


class Layer1Classifier:
    def __init__(self, store: Optional[EncryptedStore] = None):
        self.classified = 0
        self.hits = 0
        self.failures = 0
        self.last_ok: Optional[bool] = None
        self.last_check_at = 0.0
        self.store = store
        self._cache: "OrderedDict[str, Tuple[bool, float]]" = OrderedDict()
        self._cache_lock = RLock()
        if store is not None:
            logger.info("Layer1 disk cache rows=%d", store.cache_count())

    def _cache_get(self, secret: str) -> Optional[bool]:
        key = hashlib.blake2b(secret.encode("utf-8"), digest_size=8).hexdigest()
        with self._cache_lock:
            item = self._cache.get(key)
            if item:
                flag, ts = item
                if time.time() - ts <= LAYER1_CACHE_TTL:
                    self._cache.move_to_end(key)
                    return flag
                self._cache.pop(key, None)
        if self.store is not None:
            disk = self.store.cache_get(secret, LAYER1_CACHE_TTL)
            if disk is not None:
                with self._cache_lock:
                    self._cache[key] = (disk, time.time())
                    self._cache.move_to_end(key)
                    self._trim_mem()
                return disk
        return None

    def _trim_mem(self) -> None:
        while len(self._cache) > LAYER1_CACHE_MEM_MAX:
            self._cache.popitem(last=False)

    def _cache_put(self, secret: str, flag: bool) -> None:
        key = hashlib.blake2b(secret.encode("utf-8"), digest_size=8).hexdigest()
        with self._cache_lock:
            self._cache[key] = (flag, time.time())
            self._cache.move_to_end(key)
            self._trim_mem()
        if self.store is not None:
            try:
                self.store.cache_put(secret, flag)
            except Exception as exc:
                logger.error("Layer1 cache persist failed: %s", exc)

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

    def _prompt_for(self, span: str, key: str = "", ctx: str = "") -> Tuple[str, str]:
        span_s = (span or "")[:LAYER1_SPAN_MAX]
        key_s = (key or "")[:64]
        ctx_s = (ctx or "")[:48]
        if key_s:
            prompt = LAYER1_PROMPT_K.format(key=key_s, span=span_s, ctx=ctx_s)
        else:
            prompt = LAYER1_PROMPT_V.format(span=span_s, ctx=ctx_s)
        return prompt, span_s

    def _remember(self, item: Dict[str, str], content: str, span_s: str) -> bool:
        is_secret = str(content or "").strip().upper().startswith("SECRET")
        self.classified += 1
        if is_secret:
            self.hits += 1
        span = item.get("span") or ""
        key = item.get("key") or ""
        ctx = item.get("ctx") or ""
        self._cache_put(f"{key}\n{span}\n{ctx}", is_secret)
        self._cache_put("span\n" + span_s, is_secret)
        return is_secret

    async def classify(self, span: str, key: str = "", ctx: str = "") -> bool:
        cache_key = f"{key}\n{span}\n{ctx}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        flags = await self.classify_batch(
            [{"span": span, "key": key, "ctx": ctx}],
            timeout=LAYER1_TIMEOUT,
        )
        return span in flags

    async def classify_batch(self, items: List[Dict[str, str]], timeout: float) -> Set[str]:
        """One llama-server /completion with prompt: [p1, p2, ...]. Fail-open."""
        secrets: Set[str] = set()
        if not items:
            return secrets
        client = layer1_client
        if client is None:
            return secrets
        prompts: List[str] = []
        span_ss: List[str] = []
        for item in items:
            prompt, span_s = self._prompt_for(
                item.get("span") or "",
                item.get("key") or "",
                item.get("ctx") or "",
            )
            prompts.append(prompt)
            span_ss.append(span_s)
        payload = {
            "prompt": prompts if len(prompts) > 1 else prompts[0],
            "n_predict": 1,
            "temperature": 0.0,
            "top_k": 1,
            "top_p": 1.0,
            "min_p": 0.0,
            "repeat_penalty": 1.0,
            "cache_prompt": True,
        }
        t0 = time.perf_counter()
        try:
            resp = await client.post(
                "/completion",
                json=payload,
                timeout=max(0.15, timeout),
            )
            resp.raise_for_status()
            data = resp.json()
            rows = data if isinstance(data, list) else [data]
            if len(rows) != len(items):
                logger.warning(
                    "Layer1 batch size mismatch: sent %d got %d", len(items), len(rows)
                )
            n = min(len(rows), len(items))
            for i in range(n):
                content = str(rows[i].get("content") or "")
                if self._remember(items[i], content, span_ss[i]):
                    secrets.add(items[i]["span"])
            self.last_ok = True
            logger.info(
                "Layer1 batch n=%d secrets=%d ms=%.0f",
                n, len(secrets), (time.perf_counter() - t0) * 1000,
            )
            return secrets
        except Exception as exc:
            self.failures += 1
            self.last_ok = False
            logger.warning("Layer1 batch classify failed: %s", exc)
            return secrets

    async def redact_tree(self, obj: Any) -> Any:
        if not LAYER1_ENABLED:
            return obj
        if not await self.reachable():
            return obj
        strings: List[str] = []
        self._collect_strings(obj, strings)

        # 1. Reverse traversal: latest user message and tool outputs come first!
        all_items: List[Dict[str, str]] = []
        seen: Set[str] = set()
        for s in reversed(strings):
            for item in extract_layer1_items(s):
                span = item["span"]
                if span not in seen:
                    seen.add(span)
                    all_items.append(item)

        if not all_items:
            return obj

        # 2. Retain historical judgments without consuming candidate quota!
        known_secrets: Set[str] = set()
        needs_eval: List[Dict[str, str]] = []

        for item in all_items:
            span = item["span"]
            cache_key = f"{item.get('key','')}\n{span}\n{item.get('ctx','')}"
            cached = self._cache_get(cache_key)
            if cached is None:
                cached = self._cache_get("span\n" + span)
            if cached is True:
                known_secrets.add(span)
            elif cached is False:
                continue  # Already known as SAFE, skip without spending quota
            else:
                needs_eval.append(item)

        # 3. Only unseen candidates consume the LAYER1_MAX_CANDIDATES quota!
        # Short prompts first so a mixed-length queue does not stall passwords
        # behind a 180-char residual token.
        needs_eval.sort(key=lambda it: len(it.get("span") or ""))
        candidates = needs_eval[:LAYER1_MAX_CANDIDATES]
        if candidates:
            new_secrets = await self._classify_budgeted(candidates)
            known_secrets.update(new_secrets)

        if not known_secrets:
            return obj
        return self._replace_tree(obj, known_secrets)

    async def _classify_budgeted(self, candidates: List[Dict[str, str]]) -> Set[str]:
        remaining = max(0.05, LAYER1_BUDGET)
        try:
            return await asyncio.wait_for(
                self.classify_batch(candidates, timeout=remaining),
                timeout=remaining + 0.15,
            )
        except Exception as exc:
            logger.warning("Layer1 batch failed; fail-open: %s", exc)
            return set()

    def _collect_strings(self, obj: Any, out: List[str], key: Optional[str] = None) -> None:
        if isinstance(obj, str):
            if key in PASSTHROUGH_KEYS or _should_skip_string(obj):
                return
            inner = _try_json(obj)
            if inner is not None:
                self._collect_strings(inner, out)
                return
            out.append(obj)
            return
        if isinstance(obj, list):
            seq = reversed(obj) if key in ("input", "messages", "output") else obj
            for item in seq:
                self._collect_strings(item, out)
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                self._collect_strings(v, out, key=k)

    def _replace_tree(self, obj: Any, secrets: Set[str], key: Optional[str] = None) -> Any:
        if isinstance(obj, str):
            if key in PASSTHROUGH_KEYS or _should_skip_string(obj):
                return obj
            inner = _try_json(obj)
            if inner is not None:
                return json.dumps(self._replace_tree(inner, secrets), ensure_ascii=False)
            for secret in sorted(secrets, key=len, reverse=True):
                if not secret or any(ch in secret for ch in "\\\"{}"):
                    continue
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


layer1 = Layer1Classifier(store=store)


# ============================================================================
# 4. Outbound DFA restorer
# ============================================================================
class DFAStreamRestorer:
    PREFIXES = ("<SECRET_", "<PRIV_")
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
                if not any(p.startswith(self.buf) or self.buf.startswith(p) for p in self.PREFIXES):
                    out.append(self._flush_mismatch())
                elif ch == ">":
                    token = self.buf
                    self.buf = ""
                    restored = self.vault_lookup(token)
                    out.append(restored if restored is not None else token)
                elif not (ch.isalnum() or ch == "_"):
                    out.append(self._flush_mismatch())
                elif len(self.buf) >= self.MAX_HOLD:
                    out.append(self.buf)
                    self.buf = ""
        return "".join(out)

    def _flush_mismatch(self) -> str:
        out = []
        while self.buf:
            first = self.buf[0]
            rest = self.buf[1:]
            out.append(first)
            self.buf = rest
            if rest:
                if any(p.startswith(rest) for p in self.PREFIXES):
                    break
                hit = next((p for p in self.PREFIXES if rest.startswith(p)), None)
                if hit and all(c.isalnum() or c == "_" for c in rest[len(hit):]):
                    break
        return "".join(out)

    def flush(self) -> str:
        remaining = self.buf
        self.buf = ""
        return remaining


def restore_text_all(text: str) -> str:
    if not text or ("<PRIV_" not in text and "<SECRET_" not in text):
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


@app.post("/privacy/restore")
async def privacy_restore(request: Request):
    """Trusted local restore. Loopback only — never expose this on WAN."""
    peer = request.client.host if request.client else ""
    if peer not in ("127.0.0.1", "::1"):
        return JSONResponse(status_code=403, content={"error": "restore is loopback-only"})
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid json"})
    if isinstance(data, dict) and "text" in data:
        return {"text": restore_text_all(str(data["text"]))}
    return restore_json_object(data)


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
        "restore_outbound": RESTORE_OUTBOUND,
        "placeholder_prefix": "<SECRET_",
        "persist": vault.persist_stats(),
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
            if RESTORE_OUTBOUND:
                resp_json = restore_json_object(resp_json)
            new_bytes = json.dumps(resp_json, ensure_ascii=False).encode("utf-8")
        except Exception:
            raw_text = raw_body.decode("utf-8", errors="replace")
            new_bytes = (restore_text_all(raw_text) if RESTORE_OUTBOUND else raw_text).encode("utf-8")

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
                if RESTORE_OUTBOUND:
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
