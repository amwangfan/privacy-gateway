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
import sys
import json
import time
import math
import hashlib
import logging
import asyncio
import sqlite3
import tempfile
from pathlib import Path
from collections import Counter, OrderedDict
from typing import Dict, Tuple, Optional, Any, List, Callable, Set
from dataclasses import dataclass
from contextlib import asynccontextmanager
from threading import RLock

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import httpx
import uvicorn

# ============================================================================
# Config
# ============================================================================
GATEWAY_HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8317"))
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8316").rstrip("/")

# Extra upstreams, addressed by a path prefix on this same gateway so one instance
# can protect more than one backend. Format: `/prefix=url` entries separated by
# commas or semicolons, e.g.
#   GATEWAY_UPSTREAMS="/deepseek=https://api.deepseek.com"
# A request to /deepseek/v1/chat/completions is forwarded to
# <url>/v1/chat/completions. The prefix is consumed, so the client's provider
# baseURL carries it (e.g. http://127.0.0.1:8317/deepseek/v1).
def _parse_upstreams(raw: str) -> "OrderedDict[str, str]":
    table: "OrderedDict[str, str]" = OrderedDict()
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        prefix, url = chunk.split("=", 1)
        prefix = "/" + prefix.strip().strip("/")
        url = url.strip().rstrip("/")
        if prefix != "/" and url:
            table[prefix] = url
    return table


UPSTREAM_ROUTES = _parse_upstreams(os.getenv("GATEWAY_UPSTREAMS", ""))
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
# The operator-managed key source, written by scripts/vault-key.py through the
# plugin panel. Read here (not baked into the unit) so switching between the
# generated key file and a custom passphrase needs no unit edit.
VAULT_KEY_PASSWORD_FILE = os.getenv("VAULT_KEY_PASSWORD_FILE", "/etc/privacy-gateway/vault.password")
VAULT_KEY_MODE_FILE = os.getenv("VAULT_KEY_MODE_FILE", "/etc/privacy-gateway/vault.key-mode")
# Legacy: a passphrase handed in directly through the environment.
VAULT_KEY_SOURCE = "file"
VAULT_MEM_MAX = int(os.getenv("VAULT_MEM_MAX", "8192"))
VAULT_DISK_TTL_SECONDS = int(os.getenv("VAULT_DISK_TTL_SECONDS", str(90 * 24 * 3600)))
LAYER1_CACHE_MEM_MAX = int(os.getenv("LAYER1_CACHE_MEM_MAX", "16384"))
LAYER1_CACHE_TTL = int(os.getenv("LAYER1_CACHE_TTL", str(30 * 24 * 3600)))
# Which residual decision Layer 1 uses:
#   off  — deterministic rules only, the model is never called;
#   auto — rules only until the model passes LAYER1_PROBE_CASES (see model_ready);
#   on   — force the model (experiments; a failed probe is logged, not obeyed).
# The v4 LoRA reads the `ctx` field instead of the value and answers SECRET for
# every production candidate, so `auto` keeps it disabled until a model proves
# itself on the same prompts the gateway really sends.
LAYER1_MODEL_MODE = os.getenv("LAYER1_MODEL_MODE", "auto").strip().lower()
LAYER1_MODEL_PROBE_TTL = int(os.getenv("LAYER1_MODEL_PROBE_TTL", "900"))
# Rules cost nothing per candidate, so they are not limited like model calls are.
LAYER1_RULES_MAX_CANDIDATES = int(os.getenv("LAYER1_RULES_MAX_CANDIDATES", "256"))
CUSTOM_SECRETS_ENV = [s.strip() for s in os.getenv("CUSTOM_SECRETS", "").split(",") if s.strip()]
CUSTOM_SECRETS_FILE = os.getenv("CUSTOM_SECRETS_FILE", "/etc/privacy-gateway/custom_secrets.txt")

# --- Exemption (allowlist) controls -----------------------------------------
# Default posture: filtering is ALWAYS on. An exemption suspends redaction for
# one literal term, or for one vault secret addressed by its placeholder alias
# (never by plaintext). Exemptions persist until revoked: there is no mandatory
# expiry, though a caller may supply an optional `expires_at`.
EXEMPTIONS_FILE = os.getenv("EXEMPTIONS_FILE", "/etc/privacy-gateway/exemptions.json")
EXEMPTION_AUDIT_FILE = os.getenv("EXEMPTION_AUDIT_FILE", "/var/log/privacy-gateway/exemptions.jsonl")
EXEMPTION_MIN_TERM = int(os.getenv("EXEMPTION_MIN_TERM", "4"))
EXEMPTION_MAX_TERM = int(os.getenv("EXEMPTION_MAX_TERM", "256"))
EXEMPTION_SCOPES = ("layer0", "layer1", "all")
# EXEMPT_TERMS=term1,term2: seed terms that exist only for the life of the
# process and are never written to disk (emergency/temporary escape hatch).
EXEMPT_TERMS_ENV = [s.strip() for s in os.getenv("EXEMPT_TERMS", "").split(",") if s.strip()]

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("PrivacyGateway")

http_client: Optional[httpx.AsyncClient] = None
layer1_client: Optional[httpx.AsyncClient] = None
# One client per extra upstream, keyed by prefix ("" is the default backend).
upstream_clients: Dict[str, httpx.AsyncClient] = {}


def resolve_upstream(path: str):
    """Map a request path to (client, url, prefix_used).

    Falls back to the default backend with the untouched path.
    """
    for prefix, base in UPSTREAM_ROUTES.items():
        if path == prefix or path.startswith(prefix + "/"):
            rest = path[len(prefix):] or "/"
            return upstream_clients.get(prefix), base + rest, prefix
    return http_client, path, ""

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


def _read_password_file(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8").strip()
    except Exception as exc:
        logger.error("Cannot read vault password file %s: %s", path, exc)
        return ""


def vault_key_mode() -> str:
    """The operator-selected key source: ``password`` or ``file``."""
    mode = ""
    try:
        mode = Path(VAULT_KEY_MODE_FILE).read_text(encoding="utf-8").strip().lower()
    except Exception:
        mode = ""
    if mode in ("password", "file"):
        return mode
    # No mode file yet: a configured password (file or legacy env) implies password mode.
    if _read_password_file(VAULT_KEY_PASSWORD_FILE) or VAULT_PASSWORD:
        return "password"
    return "file"


def vault_key_source() -> str:
    """The key source actually in force, mirroring ``_load_or_create_key``."""
    if VAULT_PASSWORD:
        return "env-password"
    if VAULT_MASTER_KEY:
        return "env-master-key"
    if vault_key_mode() == "password":
        return "password" if _read_password_file(VAULT_KEY_PASSWORD_FILE) else "file"
    return "file"


def _load_or_create_key(path: str) -> bytes:
    global VAULT_KEY_SOURCE
    if VAULT_PASSWORD:
        VAULT_KEY_SOURCE = "password"
        logger.info("Using VAULT_PASSWORD from the environment for vault encryption (PBKDF2-SHA256)")
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

    # Operator-managed custom passphrase, stored 0600 and read at startup.
    if vault_key_mode() == "password":
        password = _read_password_file(VAULT_KEY_PASSWORD_FILE)
        if password:
            VAULT_KEY_SOURCE = "password"
            logger.info("Using the operator-set vault passphrase (PBKDF2-SHA256, %s)", VAULT_KEY_PASSWORD_FILE)
            return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b"dsh-privacy-gateway-v4-master-salt", 100000)
        logger.warning(
            "Vault key mode is 'password' but %s is empty; falling back to the key file",
            VAULT_KEY_PASSWORD_FILE,
        )

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


# ============================================================================
# 1b. Exemption registry (scoped allowlist, permanent until revoked)
# ============================================================================
class ExemptReasonError(ValueError):
    """Raised when an exemption request violates a constraint."""


@dataclass
class ExemptionEntry:
    term: str
    scope: str            # layer0 | layer1 | all
    reason: str           # may be empty for a human-set exemption
    actor: str
    created_at: float
    expires_at: float = 0.0   # 0 == no expiry, stays until revoked
    source: str = "plain"     # plain | secret-alias
    placeholder: str = ""     # set when the term came from a vault alias
    hits: int = 0
    last_hit_at: float = 0.0

    def to_public(self, now: Optional[float] = None) -> Dict[str, Any]:
        now = time.time() if now is None else now
        permanent = not self.expires_at
        return {
            "term": self.term,
            "scope": self.scope,
            "reason": self.reason,
            "actor": self.actor,
            "source": self.source,
            "placeholder": self.placeholder,
            "created_at": int(self.created_at),
            "expires_at": int(self.expires_at),
            "permanent": permanent,
            "remaining_seconds": 0 if permanent else max(0, int(self.expires_at - now)),
            "hits": self.hits,
            "last_hit_at": int(self.last_hit_at) if self.last_hit_at else 0,
            "expired": bool(self.expires_at) and self.expires_at <= now,
        }


class ExemptRegistry:
    """File-backed exemption list with hot reload.

    Constraints enforced here, in code, so neither the CLI nor the HTTP API can
    bypass them:

    * a term is a literal of 4..256 chars, matched case-sensitively against whole
      candidates only;
    * a term may instead be given as a vault placeholder alias (``<SECRET_...>``),
      in which case the gateway resolves the alias to its secret internally and
      never requires the plaintext;
    * exemptions are permanent until revoked. An optional ``expires_at`` is
      honoured when a caller supplies one, but nothing forces an expiry;
    * ``reason`` is optional at this layer so a human can set an exemption
      without one; a caller that must justify itself (an AI agent) is held to
      that by its own entry point.
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = RLock()
        self._entries: Dict[str, ExemptionEntry] = {}
        self._mtime: Optional[float] = None
        self._env_entries: Dict[str, ExemptionEntry] = {}
        self._last_hit_log: Dict[str, float] = {}
        self._session_hits: int = 0
        self._adds: int = 0
        self._revokes: int = 0
        self._api_calls: int = 0
        self._load_env()
        self.reload(force=True)

    # -- validation ---------------------------------------------------------
    @staticmethod
    def validate(term: str, scope: str, expires_at: Optional[float]) -> Tuple[str, str, float]:
        term = (term or "").strip()
        scope = (scope or "all").strip().lower()
        if len(term) < EXEMPTION_MIN_TERM:
            raise ExemptReasonError(f"term must be at least {EXEMPTION_MIN_TERM} characters")
        if len(term) > EXEMPTION_MAX_TERM:
            raise ExemptReasonError(f"term must be at most {EXEMPTION_MAX_TERM} characters")
        if any(ch in term for ch in "\r\n\t"):
            raise ExemptReasonError("term must be a single literal without whitespace control characters")
        if scope not in EXEMPTION_SCOPES:
            raise ExemptReasonError(f"scope must be one of {', '.join(EXEMPTION_SCOPES)}")
        expiry = 0.0
        if expires_at:
            expiry = float(expires_at)
            if expiry <= time.time():
                raise ExemptReasonError("expires_at is in the past")
        return term, scope, expiry

    @staticmethod
    def resolve_term(term: str) -> Tuple[str, str, str]:
        """Resolve a vault placeholder alias to its secret.

        Returns ``(term, source, placeholder)``. A plain literal passes through
        unchanged. An unknown alias is rejected: silently treating
        ``<SECRET_API_KEY_9>`` as a literal would create an exemption that can
        never match.
        """
        raw = (term or "").strip()
        if not RE_PLACEHOLDER.match(raw):
            return raw, "plain", ""
        secret = vault.get_secret(raw)
        if not secret:
            raise ExemptReasonError(
                f"{raw} is not a known vault placeholder alias; pass the literal term instead"
            )
        return secret, "secret-alias", raw

    # -- persistence --------------------------------------------------------
    def _load_env(self) -> None:
        now = time.time()
        for term in EXEMPT_TERMS_ENV:
            if len(term) < EXEMPTION_MIN_TERM:
                continue
            self._env_entries[term] = ExemptionEntry(
                term=term,
                scope="all",
                reason="EXEMPT_TERMS environment seed (process-scoped, not persisted)",
                actor="env",
                created_at=now,
            )
        if self._env_entries:
            logger.warning("EXEMPT_TERMS seed active for %d term(s)", len(self._env_entries))

    def _read_file(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Exemptions file %s is unreadable (%s); ignoring it", self.path, exc)
            return []
        entries = raw.get("entries") if isinstance(raw, dict) else raw
        return entries if isinstance(entries, list) else []

    def _write_file(self) -> None:
        payload = {
            "schema": "privacy-gateway/exemptions/v2",
            "updated_at": int(time.time()),
            "note": "Entries here suspend redaction for one exact term until it is revoked (expires_at=0 means no expiry). Delete a record to revoke it.",
            "entries": [
                {
                    "term": e.term,
                    "scope": e.scope,
                    "reason": e.reason,
                    "actor": e.actor,
                    "source": e.source,
                    "placeholder": e.placeholder,
                    "created_at": int(e.created_at),
                    "expires_at": int(e.expires_at),
                }
                for e in self._entries.values()
            ],
        }
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".exemptions-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, str(self.path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def reload(self, force: bool = False) -> None:
        try:
            mtime = self.path.stat().st_mtime if self.path.exists() else None
        except OSError:
            mtime = None
        with self._lock:
            if not force and mtime == self._mtime:
                return
            self._mtime = mtime
            loaded: Dict[str, ExemptionEntry] = {}
            for raw in self._read_file():
                try:
                    term = str(raw["term"]).strip()
                    if len(term) < EXEMPTION_MIN_TERM:
                        continue
                    scope = str(raw.get("scope") or "all").lower()
                    if scope not in EXEMPTION_SCOPES:
                        scope = "all"
                    loaded[term] = ExemptionEntry(
                        term=term,
                        scope=scope,
                        reason=str(raw.get("reason") or ""),
                        actor=str(raw.get("actor") or "unknown"),
                        created_at=float(raw.get("created_at") or 0),
                        expires_at=float(raw.get("expires_at") or 0),
                        source=str(raw.get("source") or "plain"),
                        placeholder=str(raw.get("placeholder") or ""),
                    )
                except Exception as exc:
                    logger.warning("Skipping malformed exemption record: %s", exc)
            self._entries = loaded

    # -- mutation -----------------------------------------------------------
    def add(self, term: str, scope: str = "all", reason: str = "",
            expires_at: Optional[float] = None, actor: str = "unknown") -> ExemptionEntry:
        """Add (or replace) an exemption for one term.

        ``term`` may be a vault placeholder alias. ``reason`` is recorded but not
        required at this layer; ``expires_at`` is optional — omit it for a
        permanent exemption.
        """
        resolved, source, placeholder = self.resolve_term(term)
        resolved, scope, expiry = self.validate(resolved, scope, expires_at)
        now = time.time()
        with self._lock:
            entry = ExemptionEntry(
                term=resolved,
                scope=scope,
                reason=(reason or "").strip(),
                actor=(actor or "unknown").strip() or "unknown",
                created_at=now,
                expires_at=expiry,
                source=source,
                placeholder=placeholder,
            )
            self._entries[resolved] = entry
            self._write_file()
            self._adds += 1
        logger.warning(
            "EXEMPTION ADDED term=%r scope=%s actor=%s permanent=%s source=%s reason=%r",
            resolved, scope, entry.actor, not expiry, source, entry.reason,
        )
        audit.append({
            "action": "add",
            "dedupe_key": f"exemption:{resolved}",
            "title": resolved,
            "detail": entry.reason,
            "term": resolved,
            "scope": scope,
            "reason": entry.reason,
            "actor": entry.actor,
            "source": source,
            "placeholder": placeholder,
            "expires_at": int(expiry),
            "permanent": not expiry,
            "active_count": self.active_count(),
        })
        return entry

    def revoke(self, term: str, reason: str = "", actor: str = "unknown") -> ExemptionEntry:
        """Revoke by literal term or by vault placeholder alias."""
        resolved, _source, _placeholder = self.resolve_term(term)
        with self._lock:
            entry = self._entries.pop(resolved, None)
            if entry is not None:
                self._write_file()
                self._revokes += 1
        if entry is None:
            raise ExemptReasonError(f"no active exemption for term {resolved!r}")
        logger.warning("EXEMPTION REVOKED term=%r actor=%s reason=%r", resolved, actor, reason)
        audit.append({
            "action": "revoke",
            "dedupe_key": f"exemption:{resolved}",
            "title": resolved,
            "detail": (reason or "").strip(),
            "term": resolved,
            "scope": entry.scope,
            "reason": (reason or "").strip(),
            "actor": actor,
            "created_at": int(entry.created_at),
            "active_count": self.active_count(),
        })
        entry.reason = (reason or "").strip()
        return entry

    # -- queries ------------------------------------------------------------
    def prune(self, now: Optional[float] = None) -> List[str]:
        """Drop entries whose optional expiry has passed. Permanent entries never age out."""
        now = time.time() if now is None else now
        with self._lock:
            expired = [t for t, e in self._entries.items() if e.expires_at and e.expires_at <= now]
            for term in expired:
                e = self._entries.pop(term)
                audit.append({
                    "action": "expire",
                    "term": term,
                    "scope": e.scope,
                    "reason": e.reason,
                    "actor": e.actor,
                    "active_count": self.active_count(),
                })
            if expired:
                try:
                    self._write_file()
                except Exception as exc:
                    logger.error("Failed to persist expired exemptions: %s", exc)
        return expired

    def entries(self, include_expired: bool = False) -> List[ExemptionEntry]:
        now = time.time()
        with self._lock:
            merged = dict(self._env_entries)
            merged.update(self._entries)
            out = [
                e for e in merged.values()
                if include_expired or not e.expires_at or e.expires_at > now
            ]
        # Permanent entries first, then soonest expiry, then by creation.
        return sorted(out, key=lambda e: (0 if not e.expires_at else 1, e.expires_at, e.created_at))

    def terms(self) -> List[str]:
        return [e.term for e in self.entries()]

    def active_count(self) -> int:
        return len(self.entries())

    def matching(self, text: str, scope: str) -> List[Tuple[str, str]]:
        """Return (matched_text, term) for every exempted term present in text."""
        if not text:
            return []
        hits: List[Tuple[str, str]] = []
        for entry in self.entries():
            if entry.scope not in (scope, "all"):
                continue
            if entry.term not in text:
                continue
            entry.hits += 1
            entry.last_hit_at = time.time()
            self._session_hits += 1
            hits.append((entry.term, entry.term))
            self._maybe_log_hit(entry)
        hits.sort(key=lambda item: len(item[0]), reverse=True)
        return hits

    def _maybe_log_hit(self, entry: ExemptionEntry) -> None:
        now = time.time()
        last = self._last_hit_log.get(entry.term, 0.0)
        if now - last < 60:
            return
        self._last_hit_log[entry.term] = now
        audit.append({
            "action": "hit",
            "term": entry.term,
            "scope": entry.scope,
            "reason": entry.reason,
            "actor": entry.actor,
            "hits": entry.hits,
            "active_count": self.active_count(),
        })

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        entries = self.entries(include_expired=True)
        active = [e for e in entries if not e.expires_at or e.expires_at > now]
        expiring = [e.expires_at for e in active if e.expires_at]
        return {
            "enabled": True,
            "file": str(self.path),
            "active_count": len(active),
            "total_count": len(entries),
            "permanent_count": sum(1 for e in active if not e.expires_at),
            "session_hits": self._session_hits,
            "adds": self._adds,
            "revokes": self._revokes,
            "api_calls": self._api_calls,
            "next_expiry_at": int(min(expiring)) if expiring else 0,
            "terms": sorted(e.term for e in active),
            "min_term_chars": EXEMPTION_MIN_TERM,
        }

    # -- redaction integration ---------------------------------------------
    _RE_ESCAPE = re.compile(r"[.*+?^${}()|\[\]\\]")

    def _pattern_for(self, term: str) -> "re.Pattern[str]":
        escaped = self._RE_ESCAPE.sub(lambda m: "\\" + m.group(0), term)
        return re.compile(r"(?<![A-Za-z0-9_])" + escaped + r"(?![A-Za-z0-9_])")

    def protect(self, text: str, scope: str) -> Tuple[str, Dict[str, str]]:
        """Replace exempted terms with opaque tokens.

        The tokens are inert to Layer 0 (already-frozen-placeholder guard) and to
        Layer 1 (``_is_boring_token`` rejects the ``__VAULT_`` prefix), so they
        pass through the whole redaction pipeline untouched and are restored
        verbatim afterwards. That is what "stop filtering this term" means here.
        """
        if not text or not EXEMPTION_SCOPES:
            return text, {}
        protected: Dict[str, str] = {}
        for entry in self.entries():
            if entry.scope not in (scope, "all"):
                continue
            term = entry.term
            pattern = self._pattern_for(term)
            if not pattern.search(text):
                continue
            token = "__VAULT_EXEMPT_" + hashlib.md5(
                (term + scope).encode("utf-8")
            ).hexdigest()[:12] + "__"
            text = pattern.sub(token, text)
            protected[token] = term
            entry.hits += 1
            entry.last_hit_at = time.time()
            self._session_hits += 1
            self._maybe_log_hit(entry)
        return text, protected

    @staticmethod
    def unprotect(text: str, protected: Dict[str, str]) -> str:
        for token, term in protected.items():
            text = text.replace(token, term)
        return text

    @staticmethod
    def unprotect_tree(obj: Any, protected: Dict[str, str]) -> Any:
        if not protected:
            return obj
        if isinstance(obj, str):
            return ExemptRegistry.unprotect(obj, protected)
        if isinstance(obj, list):
            return [ExemptRegistry.unprotect_tree(v, protected) for v in obj]
        if isinstance(obj, dict):
            return {k: ExemptRegistry.unprotect_tree(v, protected) for k, v in obj.items()}
        return obj


class ExemptionAuditLog:
    """Append-only JSONL audit trail for every exemption decision and hit."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = RLock()
        self._disabled = False
        self._fallback: List[Dict[str, Any]] = []
        self._last_prune = 0.0

    def append(self, record: Dict[str, Any]) -> None:
        record = {"ts": time.time(), "source": "privacy-gateway", **record}
        if self._disabled:
            self._fallback.append(record)
            del self._fallback[:-200]
            return
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with self._lock, open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            self._disabled = True
            logger.error("Exemption audit log disabled (%s); keeping in-memory only", exc)

    def tail(self, since: float = 0.0, limit: int = 50) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if self.path.exists():
            try:
                with self._lock, open(self.path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except Exception:
                            continue
                        out.append(rec)
            except Exception as exc:
                logger.error("Failed to read exemption audit log: %s", exc)
        out.extend(self._fallback)
        if since:
            out = [r for r in out if float(r.get("ts") or 0) > since]
        return out[-limit:]

    def notifications(self) -> Dict[str, Any]:
        """Cheap change summary for UI polling.

        Records carrying a ``dedupe_key`` are folded by that key so a retried
        operation never shows up twice, and the caller gets a stable list of
        still-actionable notifications plus the newest change timestamp.
        """
        records = self.tail(limit=400)
        folded: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        changed_at = 0.0
        for rec in records:
            ts = float(rec.get("ts") or 0)
            if ts > changed_at:
                changed_at = ts
            if rec.get("action") == "hit":
                continue
            key = rec.get("dedupe_key")
            if not key:
                continue
            prior = folded.get(key)
            if prior is not None and float(prior.get("ts") or 0) >= ts:
                continue
            folded[key] = rec
        items = [
            {
                "kind": rec.get("action"),
                "dedupe_key": rec.get("dedupe_key"),
                "ts": rec.get("ts"),
                "title": rec.get("title") or "",
                "detail": rec.get("detail") or rec.get("reason") or "",
                "actor": rec.get("actor") or "",
                "severity": rec.get("severity") or "info",
            }
            for rec in folded.values()
        ]
        return {"changed_at": changed_at, "items": items[-20:]}


exemptions = ExemptRegistry(EXEMPTIONS_FILE)
audit = ExemptionAuditLog(EXEMPTION_AUDIT_FILE)


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
            "key_mode": vault_key_mode(),
            # Never the passphrase itself: only whether one is set and where it lives.
            "password_set": bool(_read_password_file(VAULT_KEY_PASSWORD_FILE)),
            "password_file": VAULT_KEY_PASSWORD_FILE,
            "key_file": VAULT_KEY_FILE,
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

# A model may only classify traffic after it clears this suite, and the suite uses
# the prompts and `ctx` values the gateway really sends. That matters: the v4 LoRA
# reads `ctx` instead of the value (`c=bearer token` / `c=env file` -> SECRET,
# anything else -> SAFE), so it reports SECRET for every production candidate
# while scoring 100% on an eval that feeds safe rows a different ctx.
LAYER1_PROBE_CASES: Tuple[Tuple[Dict[str, str], bool], ...] = (
    ({"span": "sk-proj-9f3aB21cD45eF67gH89iJ01k", "key": "", "ctx": LAYER1_CTX_TOKENISH}, True),
    ({"span": "ZY8OLIYeP6-UdwquM2P2L", "key": "", "ctx": LAYER1_CTX_TOKENISH}, True),
    ({"span": "mysql_root_password_2026", "key": "password", "ctx": LAYER1_CTX_SECRET}, True),
    ({"span": "README.md", "key": "", "ctx": LAYER1_CTX_TOKENISH}, False),
    ({"span": "VAULT_KEY_SOURCE", "key": "", "ctx": LAYER1_CTX_TOKENISH}, False),
    ({"span": "privacy-gateway-v4-qwen2", "key": "", "ctx": LAYER1_CTX_TOKENISH}, False),
    ({"span": "cudart-llama-b10991-bin-ubuntu-cuda-12", "key": "", "ctx": LAYER1_CTX_TOKENISH}, False),
    ({"span": "1.2.3", "key": "", "ctx": LAYER1_CTX_TOKENISH}, False),
    ({"span": "hello world", "key": "", "ctx": LAYER1_CTX_TOKENISH}, False),
)


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
    def redact_with_map(cls, text: str) -> Tuple[str, Dict[str, str]]:
        """Redact one string and return the exemption map that was masked into it.

        The map maps opaque tokens to the exempted literal terms; the caller must
        restore them with ``ExemptRegistry.unprotect`` once every redaction layer
        has run over the same value.
        """
        if not text or not isinstance(text, str):
            return text, {}
        if _should_skip_string(text):
            return text, {}

        # Exempted terms are masked with inert tokens *before* the freeze step so
        # that every later layer (custom secrets, regexes, Bearer, JWT) and the
        # Layer 1 candidate extraction see an opaque placeholder instead of the
        # real term. The caller restores them from the returned map.
        safe_text, protected = exemptions.protect(text, "layer0")

        frozen_text, freeze_map = cls.freeze_existing_placeholders(safe_text)

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

        return cls.unfreeze_placeholders(frozen_text, freeze_map), protected

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Single-string redaction. Exempted terms come back restored."""
        redacted, protected = cls.redact_with_map(text)
        return ExemptRegistry.unprotect(redacted, protected)

    @classmethod
    def redact_tree(cls, obj: Any, key: Optional[str] = None,
                    _protected: Optional[Dict[str, str]] = None) -> Any:
        if _protected is None:
            _protected = {}
        if isinstance(obj, str):
            if key in PASSTHROUGH_KEYS:
                return obj
            inner = _try_json(obj)
            if inner is not None:
                return json.dumps(
                    cls.redact_tree(inner, _protected=_protected), ensure_ascii=False
                )
            redacted, protected = cls.redact_with_map(obj)
            _protected.update(protected)
            return redacted
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = cls.redact_tree(item, _protected=_protected)
            return obj
        if isinstance(obj, dict):
            for k, v in obj.items():
                obj[k] = cls.redact_tree(v, key=k, _protected=_protected)
            return obj
        return obj

    @classmethod
    def redact_tree_with_map(cls, obj: Any,
                             key: Optional[str] = None) -> Tuple[Any, Dict[str, str]]:
        """Redact a whole request/response tree and hand back the exemption map.

        The exemption map must be applied to the outbound echo as well, otherwise
        an exempted term would be masked on the way out and never restored.
        """
        protected: Dict[str, str] = {}
        redacted = cls.redact_tree(obj, key=key, _protected=protected)
        return redacted, protected


# ============================================================================
# 3. Layer 1 — residual classifier (fail-open)
# ============================================================================
def _shannon(s: str) -> float:
    n = len(s)
    if n <= 1:
        return 0.0
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


RE_WORD_SEGMENT = re.compile(
    r"^(?:"
    r"[A-Za-z]{2,24}"                        # a word: privacy, cudart, LoRA
    r"|\d{1,6}"                              # a number: 12, 2026
    r"|[A-Za-z]{1,6}\d{1,6}[A-Za-z]{0,4}"    # qwen2, v4, n100, b10991
    r"|\d{1,6}[A-Za-z]{1,6}"                 # 5B, 3d
    r")$"
)
RE_IDENT_SPLIT = re.compile(r"[-._]")
RE_DATEISH = re.compile(
    r"^\d{4}[-/.]\d{1,2}(?:[-/.]\d{1,2})?(?:[T ]\d{2}:\d{2}(?::\d{2})?Z?)?$"
)
RE_SEMVER = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.]+)?$")
RE_BASE64ISH = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
RE_CODE_PUNCT = re.compile(r"[()\[\]{}<>=,;|&\\'\"`]")

# Anything starting with one of these is a credential by construction, so no name
# heuristic below may claim it. Kept in sync with the Layer 0 provider patterns.
CREDENTIAL_PREFIXES: Tuple[str, ...] = (
    "sk-", "sk_", "rk_", "pk_", "ghp_", "gho_", "ghs_", "ghu_", "github_pat_",
    "glpat-", "glrt-", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
    "AKIA", "ASIA", "AIza", "ya29.", "hf_", "npm_", "pypi-", "dop_v1_",
    "shpat_", "SG.", "whsec_", "xapp-", "eyJ", "atlasv1.", "-----BEGIN",
)


# Base64 payloads of files (images, archives, documents) are data, not credentials.
# Without this, a pasted screenshot or PDF body was redacted as an opaque token.
BASE64_DOCUMENT_PREFIXES: Tuple[str, ...] = (
    "iVBORw0KGgo",      # PNG
    "/9j/",             # JPEG
    "R0lGOD",           # GIF
    "UklGR",            # WebP
    "JVBERi",           # PDF
    "UEsDB",            # ZIP
    "H4sI",             # gzip
    "AAAAIGZ0eXB",      # MP4 (ftyp)
)


def _is_document_blob(s: str) -> bool:
    return s.startswith(BASE64_DOCUMENT_PREFIXES)


def _is_base64_secret(s: str) -> bool:
    """Base64/hex-ish high-entropy blob: the shape of a real opaque token."""
    if len(s) < 16 or not RE_BASE64ISH.match(s):
        return False
    if _shannon(s) < 3.9:
        return False
    return any(ch.isdigit() for ch in s) or (
        any(ch.isupper() for ch in s) and any(ch.islower() for ch in s)
    )


def _has_credential_texture(s: str) -> bool:
    """Does a *bare* token look like a credential rather than a word or a name?"""
    if not s or _is_document_blob(s):
        return False
    if s.startswith(CREDENTIAL_PREFIXES) or _is_base64_secret(s):
        return True
    if RE_HEX.match(s) and len(s) in (32, 40, 64):
        return True
    has_digit = any(ch.isdigit() for ch in s)
    has_upper = any(ch.isupper() for ch in s)
    has_lower = any(ch.islower() for ch in s)
    return (
        len(s) >= 14
        and has_digit
        and has_upper
        and has_lower
        and _shannon(s) >= 3.6
    )


def _ident_segments(s: str) -> List[str]:
    return [part for part in RE_IDENT_SPLIT.split(s) if part]


def _is_screaming_snake(s: str) -> bool:
    """`VAULT_KEY_SOURCE`: the constant-naming convention, i.e. always a name."""
    parts = _ident_segments(s)
    if len(parts) < 2:
        return False
    words = [p for p in parts if p.isalpha()]
    numbers = [p for p in parts if p.isdigit()]
    if len(words) < 2 or len(words) + len(numbers) != len(parts):
        return False
    return all(p.isupper() and len(p) >= 2 for p in words)


def _is_benign_name(s: str, keyed: bool = False) -> bool:
    """True when the span is a name people write *about* code, not a credential.

    `VAULT_KEY_SOURCE`, `privacy-gateway-v4-qwen2`, `5B-Privacy-Gateway-v3-LoRA`,
    `cudart-llama-b10991-bin-ubuntu-cuda-12`, `discovery-compatibility-v1`,
    `README.md`, `2026-09-16`, `1.2.3`, `_atomic_write(Path(PASSWORD_FILE),`.

    Deciding this deterministically matters: a residual classifier that answers
    SECRET for everything (which is exactly what the v4 model does) would
    otherwise rewrite ordinary words into placeholders. Names are decided here; a
    value that merely *looks* like a word under a secret-ish key still goes to the
    classifier, so `password=mysql_root_password_2026` keeps being redacted.
    """
    if not s:
        return False
    if _is_document_blob(s):
        return True                       # image/archive payload, not a credential
    if len(s) < 8 or len(s) > 64:
        return False
    if s.startswith(CREDENTIAL_PREFIXES) or _is_base64_secret(s):
        return False
    if RE_CODE_PUNCT.search(s):
        return True                       # code fragment, not a value
    if s[0] in "._-":
        # `_atomic_write`, `--flag`, `.env` are code-shaped, but a random token that
        # merely starts with `_` is still a credential.
        return not _has_credential_texture(s)
    if RE_DATEISH.match(s) or RE_SEMVER.match(s):
        return True
    parts = _ident_segments(s)
    if len(parts) < 2 or not all(RE_WORD_SEGMENT.match(part) for part in parts):
        return False
    if _is_screaming_snake(s):
        return True                       # constant name, in any context
    return not keyed                      # a bare slug/hostname/project name


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
    # Structural shapes: a name is not a credential (see _is_benign_name).
    if _is_benign_name(s, keyed=is_assign):
        return True
    # A bare token in prose must carry credential texture to be worth a model call.
    # Without this, any long-ish slug or identifier reached the classifier, and a
    # classifier that answers SECRET for everything rewrote ordinary words.
    if not is_assign and not _has_credential_texture(s):
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
        found.append({"span": span, "key": key or "", "ctx": _layer1_ctx(key, kind), "kind": kind})

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
        self.rules_redacted = 0
        self.last_ok: Optional[bool] = None
        self.last_check_at = 0.0
        self.store = store
        self._cache: "OrderedDict[str, Tuple[bool, float]]" = OrderedDict()
        self._cache_lock = RLock()
        self._ready_cache: Tuple[bool, float] = (False, 0.0)
        self.probe_result: Optional[Dict[str, Any]] = None
        self.probe_checked_at = 0.0
        self.used_model = False
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

    # ---------------------------------------------------------- decision path ---
    @staticmethod
    def _rule_verdicts(candidates: List[Dict[str, str]]) -> Set[str]:
        """Deterministic residual decision: the structural gate *is* the verdict.

        Extraction already dropped plain words, identifiers, slugs, filenames,
        versions and code fragments. What is left is either an assignment under a
        secret-ish key whose value is not a name (a value to protect) or a bare
        token that carries credential texture. No model call is involved.
        """
        verdicts: Set[str] = set()
        for item in candidates:
            span = item.get("span") or ""
            kind = item.get("kind") or ""
            if not span:
                continue
            if kind == "assign":
                verdicts.add(span)
            elif _has_credential_texture(span):
                verdicts.add(span)
        return verdicts

    async def _probe_once(self) -> Dict[str, Any]:
        """Ask the model the production-shaped probe cases and score them."""
        items = [dict(case) for case, _ in LAYER1_PROBE_CASES]
        verdicts = await self._infer(items, timeout=LAYER1_TIMEOUT)
        if verdicts is None:
            return {"ok": False, "error": "model unavailable", "cases": []}
        details = []
        positives_caught = negatives_kept = 0
        for (case, expected), said_secret in zip(LAYER1_PROBE_CASES, verdicts):
            hit = said_secret == expected
            positives_caught += int(expected and said_secret)
            negatives_kept += int(not expected and not said_secret)
            details.append({
                "span": case["span"], "expected": "SECRET" if expected else "SAFE",
                "said": "SECRET" if said_secret else "SAFE", "ok": hit,
            })
        n_pos = sum(1 for _, expected in LAYER1_PROBE_CASES if expected)
        n_neg = len(LAYER1_PROBE_CASES) - n_pos
        ok = positives_caught == n_pos and negatives_kept == n_neg
        return {
            "ok": ok,
            "positives_caught": positives_caught, "positives_total": n_pos,
            "negatives_kept": negatives_kept, "negatives_total": n_neg,
            "failed": [d["span"] for d in details if not d["ok"]],
            "cases": details,
        }

    async def probe(self, force: bool = False) -> Dict[str, Any]:
        """Cached model readiness check (see LAYER1_MODEL_MODE)."""
        if (
            not force
            and self.probe_result is not None
            and time.time() - self.probe_checked_at < LAYER1_MODEL_PROBE_TTL
        ):
            return self.probe_result
        try:
            result = await asyncio.wait_for(
                self._probe_once(), timeout=max(0.5, LAYER1_TIMEOUT * len(LAYER1_PROBE_CASES) + 1.0)
            )
        except Exception as exc:
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "cases": []}
        result["checked_at"] = time.time()
        self.probe_result = result
        self.probe_checked_at = time.time()
        if not result.get("ok"):
            logger.warning(
                "Layer1 model failed its readiness probe; using deterministic rules only: %s",
                {k: v for k, v in result.items() if k != "cases"},
            )
        return result

    async def model_ready(self) -> bool:
        """May the residual model classify anything at all?

        `off`  — never (rules only).
        `on`   — yes, the operator takes responsibility.
        `auto` — only after the model passes the probe on the production prompts.
        """
        mode = LAYER1_MODEL_MODE
        if mode == "off":
            return False
        if mode == "on":
            return True
        ready, checked_at = self._ready_cache
        if time.time() - checked_at < LAYER1_MODEL_PROBE_TTL:
            return ready
        result = await self.probe()
        ready = bool(result.get("ok"))
        self._ready_cache = (ready, time.time())
        return ready

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

    async def _infer(self, items: List[Dict[str, str]], timeout: float) -> Optional[List[bool]]:
        """Raw model verdicts, one per item. None when the model is unusable.

        Kept apart from classify_batch so the readiness probe can ask the model
        without touching the counters or the decision cache.
        """
        client = layer1_client
        if client is None:
            return None
        prompts: List[str] = []
        for item in items:
            prompt, _ = self._prompt_for(
                item.get("span") or "",
                item.get("key") or "",
                item.get("ctx") or "",
            )
            prompts.append(prompt)
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
        resp = await client.post(
            "/completion",
            json=payload,
            timeout=max(0.15, timeout),
        )
        resp.raise_for_status()
        data = resp.json()
        rows = data if isinstance(data, list) else [data]
        if len(rows) != len(items):
            logger.warning("Layer1 batch size mismatch: sent %d got %d", len(items), len(rows))
        n = min(len(rows), len(items))
        return [
            str(rows[i].get("content") or "").strip().upper().startswith("SECRET")
            for i in range(n)
        ]

    async def classify_batch(self, items: List[Dict[str, str]], timeout: float) -> Set[str]:
        """One llama-server /completion with prompt: [p1, p2, ...]. Fail-open."""
        secrets: Set[str] = set()
        if not items:
            return secrets
        if layer1_client is None:
            return secrets
        t0 = time.perf_counter()
        try:
            verdicts = await self._infer(items, timeout)
            if verdicts is None:
                return secrets
            n = len(verdicts)
            for i in range(n):
                span_s = (items[i].get("span") or "")[:LAYER1_SPAN_MAX]
                if self._remember(items[i], "SECRET" if verdicts[i] else "SAFE", span_s):
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

    async def redact_tree(self, obj: Any,
                          _protected: Optional[Dict[str, str]] = None) -> Any:
        if _protected is None:
            _protected = {}
        if not LAYER1_ENABLED:
            return obj
        # The model is optional now: deterministic rules handle the residual layer
        # on their own, and an unreachable or unproven model must not disable it.
        use_model = await self.model_ready()
        self.used_model = use_model
        # The vault records which residual decision produced a mapping.
        secret_type = "LLM_SECRET" if use_model else "RULES_SECRET"
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
        # Only model verdicts are cached, so only a model-backed run may read it:
        # a cached "SECRET" from a model that answered SECRET for everything would
        # otherwise keep rewriting benign words that the rules now reject.
        known_secrets: Set[str] = set()
        needs_eval: List[Dict[str, str]] = []

        for item in all_items:
            span = item["span"]
            if not use_model:
                needs_eval.append(item)
                continue
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

        # 3. Only unseen candidates consume the model quota; rules have no per-call
        # cost, so they only need a sanity bound. Short prompts first so a
        # mixed-length queue does not stall passwords behind a 180-char token.
        needs_eval.sort(key=lambda it: len(it.get("span") or ""))
        limit = LAYER1_MAX_CANDIDATES if use_model else LAYER1_RULES_MAX_CANDIDATES
        candidates = needs_eval[:limit]
        if candidates:
            if use_model:
                new_secrets = await self._classify_budgeted(candidates)
            else:
                new_secrets = self._rule_verdicts(candidates)
                self.rules_redacted += len(new_secrets)
            known_secrets.update(new_secrets)

        if not known_secrets:
            # Nothing to substitute, but exemption shielding may still be needed
            # for a term the classifier would otherwise flag as secret-shaped.
            self._replace_tree(obj, set(), _protected=_protected, secret_type=secret_type)
            return obj
        return self._replace_tree(obj, known_secrets, _protected=_protected, secret_type=secret_type)

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

    def _replace_tree(self, obj: Any, secrets: Set[str], key: Optional[str] = None,
                      _protected: Optional[Dict[str, str]] = None,
                      secret_type: str = "LLM_SECRET") -> Any:
        if _protected is None:
            _protected = {}
        if isinstance(obj, str):
            if key in PASSTHROUGH_KEYS or _should_skip_string(obj):
                return obj
            inner = _try_json(obj)
            if inner is not None:
                return json.dumps(
                    self._replace_tree(inner, secrets, _protected=_protected,
                                       secret_type=secret_type),
                    ensure_ascii=False,
                )
            # Layer 1 hits also consult the exemption list, so a term scoped to
            # `layer1` that Layer 0 could not match is still shielded from the
            # residual classifier.
            safe_obj, protected = exemptions.protect(obj, "layer1")
            _protected.update(protected)
            return self._replace_plain(safe_obj, secrets, secret_type)
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = self._replace_tree(item, secrets, _protected=_protected,
                                            secret_type=secret_type)
            return obj
        if isinstance(obj, dict):
            for k, v in obj.items():
                obj[k] = self._replace_tree(v, secrets, key=k, _protected=_protected,
                                            secret_type=secret_type)
            return obj
        return obj

    @staticmethod
    def _replace_plain(obj: str, secrets: Set[str], secret_type: str = "LLM_SECRET") -> str:
        for secret in sorted(secrets, key=len, reverse=True):
            if not secret or any(ch in secret for ch in "\\\"{}"):
                continue
            if secret in obj:
                holder = vault.get_or_create(secret, secret_type)
                obj = obj.replace(secret, holder)
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
    for prefix, base in UPSTREAM_ROUTES.items():
        upstream_clients[prefix] = httpx.AsyncClient(base_url=base, limits=limits, timeout=httpx.Timeout(connect=10.0, read=180.0, write=30.0, pool=10.0))
    logger.info(
        "Privacy Gateway started. backend=%s layer1=%s enabled=%s extra_upstreams=%s",
        BACKEND_URL, LAYER1_URL, LAYER1_ENABLED, dict(UPSTREAM_ROUTES) or "none",
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
    for client in upstream_clients.values():
        await client.aclose()
    logger.info("Privacy Gateway stopped.")


app = FastAPI(title="N100 Privacy Gateway", lifespan=lifespan)

# The DSH GUI panel runs on a different origin (the DSH web port) and needs to
# call the loopback control plane from the browser, so allow CORS for local
# origins only. Every control route still enforces loopback at the request level;
# this only governs which page may read the response.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$|^https?://[A-Za-z0-9.-]*\.ts\.net(:\d+)?$",
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["content-type"],
    max_age=600,
)

START_TIME = time.time()


@app.post("/privacy/dry-run")
async def privacy_dry_run(request: Request):
    """Redact a JSON body without forwarding. For local verification only."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid json"})
    data, protected = Layer0Redactor.redact_tree_with_map(data)
    layer1_applied = False
    if LAYER1_ENABLED:
        try:
            data = await layer1.redact_tree(data, _protected=protected)
            layer1_applied = True
        except Exception as exc:
            logger.error("Layer1 dry-run failed: %s", exc)
    data = ExemptRegistry.unprotect_tree(data, protected)
    return {
        "redacted": data,
        "vault_active": vault.active_count(),
        "layer1_applied": layer1_applied,
        "layer1_decision": "model" if layer1.used_model else "rules",
        "exempt_spans": len(protected),
        "exempt_terms": sorted(set(protected.values())),
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


# ============================================================================
# 5b. Exemption control plane (loopback only, reason mandatory, always expires)
# ============================================================================
def _loopback_only(request: Request) -> bool:
    peer = request.client.host if request.client else ""
    return peer in ("127.0.0.1", "::1")


# ============================================================================
# 5c. Vault key configuration (loopback only, never returns the passphrase)
# ============================================================================
VAULT_KEY_MANAGER = os.getenv("VAULT_KEY_MANAGER", "/root/privacy-gateway/scripts/vault-key.py")


def _key_config_public() -> Dict[str, Any]:
    stats = vault.persist_stats()
    return {
        "mode": vault_key_mode(),
        "effective_source": vault_key_source(),
        "password_set": bool(stats.get("password_set")),
        "password_file": VAULT_KEY_PASSWORD_FILE,
        "mode_file": VAULT_KEY_MODE_FILE,
        "key_file": VAULT_KEY_FILE,
        "key_file_exists": Path(VAULT_KEY_FILE).exists(),
        "db_path": VAULT_DB_PATH,
        "vault_rows": stats.get("vault_rows", 0),
        "manager": VAULT_KEY_MANAGER,
        "manager_available": Path(VAULT_KEY_MANAGER).exists(),
        "note": "The passphrase is never returned; only whether one is set.",
    }


@app.get("/privacy/key")
async def privacy_key_get(request: Request):
    if not _loopback_only(request):
        return JSONResponse(status_code=403, content={"error": "key config is loopback-only"})
    return {"ok": True, "config": _key_config_public()}


@app.post("/privacy/key")
async def privacy_key_set(request: Request):
    """Switch the vault key source through scripts/vault-key.py.

    The manager re-encrypts every stored mapping under the new key first, so the
    vault survives the change; the gateway only restarts when it succeeded.
    """
    if not _loopback_only(request):
        return JSONResponse(status_code=403, content={"error": "key config is loopback-only"})
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid json body"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"ok": False, "error": "body must be a JSON object"})

    mode = str(payload.get("mode") or "").strip().lower()
    if mode not in ("password", "file"):
        return JSONResponse(status_code=400, content={
            "ok": False, "error": "mode must be 'password' or 'file'",
        })
    manager = Path(VAULT_KEY_MANAGER)
    if not manager.exists():
        return JSONResponse(status_code=503, content={
            "ok": False, "error": f"key manager not found at {VAULT_KEY_MANAGER}",
        })

    args = [sys.executable, str(manager), "--json", "--allow-live", "set", "--mode", mode]
    password = payload.get("password")
    if mode == "password":
        if not isinstance(password, str) or len(password) < 8:
            return JSONResponse(status_code=400, content={
                "ok": False, "error": "a passphrase of at least 8 characters is required",
            })
        # Feed the secret on stdin, never on argv: argv is visible in ps.
        stdin_payload = json.dumps({"password": password})
    else:
        stdin_payload = "{}"

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(stdin_payload.encode("utf-8")), timeout=180)
    except asyncio.TimeoutError:
        return JSONResponse(status_code=504, content={"ok": False, "error": "key manager timed out"})
    except Exception as exc:
        logger.error("Vault key manager failed to start: %s", exc)
        return JSONResponse(status_code=500, content={"ok": False, "error": f"key manager failed: {exc}"})

    raw = (out or b"").decode("utf-8", "replace").strip()
    try:
        result = json.loads(raw.splitlines()[-1]) if raw else {}
    except Exception:
        result = {"ok": False, "error": raw or (err or b"").decode("utf-8", "replace").strip()}

    if proc.returncode != 0 or not result.get("ok", proc.returncode == 0):
        message = result.get("error") or (err or b"").decode("utf-8", "replace").strip() or "key change failed"
        logger.error("Vault key change rejected: %s", message)
        return JSONResponse(status_code=400, content={"ok": False, "error": message})

    audit.append({
        "action": "key-change",
        "dedupe_key": "vault-key",
        "title": result.get("mode", mode),
        "detail": result.get("detail", ""),
        "actor": str(payload.get("actor") or "unknown"),
        "severity": "warn",
    })
    logger.warning("VAULT KEY CHANGED mode=%s reencrypted=%s", mode, result.get("reencrypted"))

    restarted = False
    if payload.get("restart", True):
        try:
            proc2 = await asyncio.create_subprocess_exec(
                "systemctl", "restart", "privacy-gateway.service",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc2.wait(), timeout=30)
            restarted = proc2.returncode == 0
        except Exception as exc:
            logger.warning("Could not restart the gateway after the key change: %s", exc)

    return {
        "ok": True,
        "result": result,
        "restarted": restarted,
        "config": _key_config_public(),
    }


def _exemption_denied(request: Request, error: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "error": error,
            "hint": "Pass `term` as either a literal or a vault placeholder alias such as "
                    "<SECRET_API_KEY_1>. Add `expires_at` only if the exemption should expire; "
                    "omit it for a permanent exemption.",
        },
    )


@app.get("/privacy/exemptions")
async def privacy_exemptions_list(request: Request, include_expired: bool = False):
    if not _loopback_only(request):
        return JSONResponse(status_code=403, content={"error": "exemptions are loopback-only"})
    exemptions._api_calls += 1
    exemptions.reload()
    exemptions.prune()
    now = time.time()
    entries = [e.to_public(now) for e in exemptions.entries(include_expired=include_expired)]
    return {
        "ok": True,
        "count": len(entries),
        "stats": exemptions.stats(),
        "entries": entries,
    }


@app.post("/privacy/exemptions")
async def privacy_exemptions_add(request: Request):
    if not _loopback_only(request):
        return JSONResponse(status_code=403, content={"error": "exemptions are loopback-only"})
    exemptions._api_calls += 1
    try:
        payload = await request.json()
    except Exception:
        return _exemption_denied(request, "invalid json body")
    if not isinstance(payload, dict):
        return _exemption_denied(request, "body must be a JSON object")
    try:
        expires_at = payload.get("expires_at")
        if expires_at is None and payload.get("ttl_seconds") is not None:
            expires_at = time.time() + float(payload["ttl_seconds"])
        entry = exemptions.add(
            term=str(payload.get("term") or ""),
            scope=str(payload.get("scope") or "all"),
            reason=str(payload.get("reason") or ""),
            expires_at=expires_at,
            actor=str(payload.get("actor") or "unknown"),
        )
    except ExemptReasonError as exc:
        return _exemption_denied(request, str(exc))
    except Exception as exc:
        logger.error("Failed to add exemption: %s", exc)
        return _exemption_denied(request, f"failed to persist exemption: {exc}", status=500)
    return {"ok": True, "entry": entry.to_public(), "stats": exemptions.stats()}


@app.delete("/privacy/exemptions")
async def privacy_exemptions_revoke(request: Request, term: str = "", reason: str = "",
                                    actor: str = "unknown"):
    if not _loopback_only(request):
        return JSONResponse(status_code=403, content={"error": "exemptions are loopback-only"})
    exemptions._api_calls += 1
    # A JSON body is accepted as well as query parameters, so a UI that sends a
    # body does not have to URL-encode the term.
    if not term:
        try:
            body = await request.json()
            if isinstance(body, dict):
                term = str(body.get("term") or term)
                reason = str(body.get("reason") or reason)
                actor = str(body.get("actor") or actor)
        except Exception:
            pass
    try:
        entry = exemptions.revoke(term=term, reason=reason, actor=actor)
    except ExemptReasonError as exc:
        return _exemption_denied(request, str(exc))
    except Exception as exc:
        logger.error("Failed to revoke exemption: %s", exc)
        return _exemption_denied(request, f"failed to persist revoke: {exc}", status=500)
    return {"ok": True, "revoked": entry.to_public(), "stats": exemptions.stats()}


@app.get("/privacy/exemptions/audit")
async def privacy_exemptions_audit(request: Request, since: float = 0.0, limit: int = 50):
    if not _loopback_only(request):
        return JSONResponse(status_code=403, content={"error": "exemptions are loopback-only"})
    limit = max(1, min(500, limit))
    records = audit.tail(since=since, limit=limit)
    return {"ok": True, "count": len(records), "records": records}


@app.get("/privacy/health")
async def privacy_health():
    layer1_ok = False
    model_ready = False
    if LAYER1_ENABLED:
        model_ready = await layer1.model_ready()
        # Only ask the model service whether it is alive when it is actually used.
        if LAYER1_MODEL_MODE != "off":
            layer1_ok = await layer1.reachable()
    exemptions.reload()
    exemptions.prune()
    return {
        "status": "ok",
        "uptime_seconds": int(time.time() - START_TIME),
        "total_redacted_secrets": vault.total_redacted_count,
        "total_restored_secrets": vault.total_restored_count,
        "active_vault_mappings": vault.active_count(),
        "backend_url": BACKEND_URL,
        "upstream_routes": dict(UPSTREAM_ROUTES),
        "restore_outbound": RESTORE_OUTBOUND,
        "placeholder_prefix": "<SECRET_",
        "persist": vault.persist_stats(),
        "exemptions": exemptions.stats(),
        "notifications": audit.notifications(),
        "layer1": {
            "enabled": LAYER1_ENABLED,
            "url": LAYER1_URL,
            "reachable": layer1_ok,
            # Which residual decision is in force: rules always, the model only
            # after it clears LAYER1_PROBE_CASES on the production prompts.
            "model_mode": LAYER1_MODEL_MODE,
            "model_ready": model_ready,
            "decision": "model" if model_ready else "rules",
            "rules_redacted": layer1.rules_redacted,
            "classified": layer1.classified,
            "hits": layer1.hits,
            "failures": layer1.failures,
            "cache_size": len(layer1._cache),
            "probe": layer1.probe_result,
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

    data, exempt_map = Layer0Redactor.redact_tree_with_map(data)
    if LAYER1_ENABLED:
        try:
            data = await layer1.redact_tree(data, _protected=exempt_map)
        except Exception as exc:
            logger.error("Layer1 redact failed (fail-open): %s", exc)
    data = ExemptRegistry.unprotect_tree(data, exempt_map)

    is_stream = bool(isinstance(data, dict) and data.get("stream", False))
    redacted_body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    headers = filter_request_headers(dict(request.headers), content_length=len(redacted_body))

    client, target, _prefix = resolve_upstream(full_path)
    if client is None:
        return JSONResponse(status_code=502, content={"error": "upstream not configured"})
    try:
        upstream_req = client.build_request(
            method=request.method,
            url=target,
            params=request.query_params,
            headers=headers,
            content=redacted_body,
        )
        upstream_resp = await client.send(upstream_req, stream=True)
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
    client, target, _prefix = resolve_upstream(path)
    if client is None:
        return JSONResponse(status_code=502, content={"error": "upstream not configured"})
    try:
        req = client.build_request(
            method=request.method,
            url=target,
            params=request.query_params,
            headers=headers,
            content=body,
        )
        res = await client.send(req, stream=True)
    except Exception as exc:
        logger.error("Transparent proxy failed for %s: %s", target, exc)
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
