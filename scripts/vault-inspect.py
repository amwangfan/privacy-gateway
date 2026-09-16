#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vault-inspect — read-only view of the mappings the gateway has saved.

When redaction replaces a credential with a placeholder such as
``<SECRET_API_KEY_7>``, the placeholder -> plaintext mapping is stored in the
encrypted vault so the gateway can restore it on the way back. This tool shows
what is in that vault. It is strictly read-only:

* the live database is never written: the rows, their ciphertext and their
  ``last_accessed_at`` timestamps are untouched. The current rows are read from a
  consistent snapshot produced with ``VACUUM INTO``, which folds in the
  write-ahead log. Opening a live WAL database read-only may still let SQLite
  refresh the ``-shm`` WAL index, which is a shared-memory cache: neither the
  database file nor the ``-wal`` frames are modified;
* a missing key file is an error — unlike the gateway, this tool never creates one.

Secrets are masked by default: a listing shows the placeholder, the secret type,
the length and a short fingerprint, which is enough to tell two entries apart
without putting a credential on the screen (or into a chat log). The plaintext is
printed only when it is asked for explicitly:

    vault-inspect.py status                     # key source, row counts, per-type totals
    vault-inspect.py list                       # masked listing, newest first
    vault-inspect.py list --sort accessed --limit 20
    vault-inspect.py list --json                # machine-readable, still masked
    vault-inspect.py show '<SECRET_API_KEY_7>'  # reveal exactly one entry
    vault-inspect.py list --reveal-all          # reveal everything (deliberate)

Exit codes: 0 ok · 1 failed · 2 usage error.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

# Must match EncryptedStore / _load_or_create_key in gateway.py or every row
# fails to decrypt: the AAD is bound into the AEAD tag, and the PBKDF2 salt is
# part of the passphrase-derived key.
AAD = b"vault-v1"
SALT = b"dsh-privacy-gateway-v4-master-salt"
HASH_DIGEST_SIZE = 16

DEFAULT_DB_PATH = "/var/lib/privacy-gateway/store.sqlite"

DB_PATH = os.environ.get("VAULT_DB_PATH", DEFAULT_DB_PATH)
KEY_FILE = os.environ.get("VAULT_KEY_FILE", "/etc/privacy-gateway/master.key")
PASSWORD_FILE = os.environ.get("VAULT_KEY_PASSWORD_FILE", "/etc/privacy-gateway/vault.password")
MODE_FILE = os.environ.get("VAULT_KEY_MODE_FILE", "/etc/privacy-gateway/vault.key-mode")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

MASK_STYLES = ("fingerprint", "prefix", "none")


def _fail(error: str, **extra) -> None:
    """Report a failure as one JSON object and exit non-zero."""
    print(json.dumps({"ok": False, "error": error, **extra}, ensure_ascii=False))
    raise SystemExit(EXIT_FAILED)


def _warn(message: str) -> None:
    print(message, file=sys.stderr)


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except Exception:
        return ""


# ------------------------------------------------------------------- keys ---
def _key_mode() -> str:
    mode = _read_text(MODE_FILE).lower()
    if mode in ("password", "file"):
        return mode
    if _read_text(PASSWORD_FILE) or os.environ.get("VAULT_PASSWORD", "").strip():
        return "password"
    return "file"


def _key_source() -> str:
    """Mirror gateway.vault_key_source() so the report names the real key."""
    if os.environ.get("VAULT_PASSWORD", "").strip():
        return "env-password"
    if os.environ.get("VAULT_MASTER_KEY", "").strip():
        return "env-master-key"
    if _key_mode() == "password":
        return "password" if _read_text(PASSWORD_FILE) else "file"
    return "file"


def _derive_key() -> bytes:
    env_password = os.environ.get("VAULT_PASSWORD", "").strip()
    if env_password:
        return hashlib.pbkdf2_hmac("sha256", env_password.encode("utf-8"), SALT, 100000)

    master = os.environ.get("VAULT_MASTER_KEY", "").strip()
    if master:
        if len(master) == 64:
            try:
                return bytes.fromhex(master)
            except ValueError:
                pass
        return hashlib.blake2b(master.encode("utf-8"), digest_size=32).digest()

    if _key_mode() == "password":
        password = _read_text(PASSWORD_FILE)
        if password:
            return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), SALT, 100000)

    path = Path(KEY_FILE)
    if not path.exists():
        _fail(
            f"key file {KEY_FILE} does not exist",
            key_source=_key_source(),
            hint="the gateway generates it on first start; this tool never creates one",
        )
    raw = path.read_bytes()
    if len(raw) < 32:
        _fail("vault key file is too short", key_file=KEY_FILE)
    return raw[:32] if len(raw) == 32 else hashlib.blake2b(raw, digest_size=32).digest()


# ------------------------------------------------------------- connection ---
class VaultView:
    """A read-only view of the vault: the connection, and how it was obtained."""

    def __init__(self, conn: sqlite3.Connection, note: str):
        self.conn = conn
        self.note = note


def _open_readonly(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.execute("SELECT COUNT(*) FROM vault").fetchone()  # prove it is readable
    return conn


def _snapshot_via_vacuum(source: sqlite3.Connection) -> tuple[sqlite3.Connection, str]:
    """Copy the database with VACUUM INTO: one consistent read transaction."""
    tempdir = tempfile.mkdtemp(prefix="vault-inspect-")
    try:
        path = os.path.join(tempdir, "snapshot.sqlite")
        source.execute("VACUUM INTO ?", (path,))
        return sqlite3.connect(path), tempdir
    except BaseException:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise


def _snapshot_by_copy(db: Path) -> tuple[sqlite3.Connection, str]:
    """Last resort: copy the database files, including the write-ahead log."""
    tempdir = tempfile.mkdtemp(prefix="vault-inspect-")
    try:
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(db) + suffix)
            if src.exists():
                shutil.copy2(str(src), os.path.join(tempdir, src.name))
        return sqlite3.connect(os.path.join(tempdir, db.name)), tempdir
    except BaseException:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise


@contextlib.contextmanager
def _open_vault(live: bool = False):
    db = Path(DB_PATH)
    if not db.exists():
        _fail(
            f"vault database {DB_PATH} does not exist",
            hint="nothing has been persisted yet, or VAULT_DB_PATH points elsewhere",
        )

    conn: sqlite3.Connection | None = None
    tempdir: str | None = None
    source: sqlite3.Connection | None = None
    note = ""
    try:
        error: Exception | None = None
        try:
            source = _open_readonly(db)
        except sqlite3.Error as exc:
            error = exc

        if source is not None:
            if live:
                conn, note = source, "direct read-only open of the live database (may refresh WAL index metadata)"
                source = None
            else:
                try:
                    conn, tempdir = _snapshot_via_vacuum(source)
                    note = "consistent snapshot of the live database (no row written)"
                except sqlite3.Error as exc:
                    error = exc
                finally:
                    source.close()
                    source = None

        if conn is None:
            if live:
                _fail(f"cannot read {DB_PATH} read-only: {error}", db_path=str(db))
            _warn(f"[vault-inspect] consistent snapshot unavailable ({error}); copying the database files")
            conn, tempdir = _snapshot_by_copy(db)
            note = "file-level copy of the live database (live file untouched)"

        yield VaultView(conn, note)
    finally:
        if source is not None:
            try:
                source.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        if tempdir:
            shutil.rmtree(tempdir, ignore_errors=True)


def _rows(conn: sqlite3.Connection) -> list[dict]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(_derive_key())
    rows = list(
        conn.execute(
            "SELECT placeholder, secret_enc, secret_type, created_at, last_accessed_at "
            "FROM vault ORDER BY created_at"
        )
    )
    out: list[dict] = []
    for placeholder, blob, secret_type, created_at, last_accessed_at in rows:
        try:
            secret = aes.decrypt(bytes(blob[:12]), bytes(blob[12:]), AAD).decode("utf-8")
        except Exception as exc:
            _fail(
                "cannot decrypt the vault with the active key",
                detail=f"{type(exc).__name__}: {exc}",
                key_source=_key_source(),
                key_file=KEY_FILE,
                hint="the key source does not match the one that wrote these rows; "
                     "compare `vault-inspect.py status` with `vault-key.py status`",
            )
        out.append(
            {
                "placeholder": placeholder,
                "secret": secret,
                "secret_type": secret_type,
                "length": len(secret),
                "fingerprint": hashlib.blake2b(
                    secret.encode("utf-8"), digest_size=HASH_DIGEST_SIZE
                ).hexdigest()[:8],
                "created_at": created_at,
                "last_accessed_at": last_accessed_at,
            }
        )
    return out


# -------------------------------------------------------------- rendering ---
def _fingerprint(secret: str) -> str:
    return hashlib.blake2b(secret.encode("utf-8"), digest_size=HASH_DIGEST_SIZE).hexdigest()[:8]


def _mask(secret: str, style: str) -> str:
    if style == "none":
        return secret
    if style == "prefix":
        head = secret[:4] if len(secret) > 8 else ""
        return f"{head}… ({len(secret)} chars)"
    return f"[{len(secret)} chars fp={_fingerprint(secret)}]"


def _stamp(ts: float) -> str:
    if not ts:
        return "-"
    age = max(0.0, time.time() - ts)
    if age < 60:
        rel = f"{int(age)}s ago"
    elif age < 3600:
        rel = f"{int(age // 60)}m ago"
    elif age < 86400:
        rel = f"{int(age // 3600)}h ago"
    else:
        rel = f"{int(age // 86400)}d ago"
    return f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} ({rel})"


def _sort_rows(rows: list[dict], sort: str, ascending: bool) -> list[dict]:
    if sort == "placeholder":
        key = lambda r: r["placeholder"]  # noqa: E731
    elif sort == "type":
        key = lambda r: (r["secret_type"], r["created_at"])  # noqa: E731
    elif sort == "accessed":
        key = lambda r: r["last_accessed_at"]  # noqa: E731
    else:
        key = lambda r: r["created_at"]  # noqa: E731
    return sorted(rows, key=key, reverse=not ascending)


def _public_row(row: dict, reveal: bool = False) -> dict:
    data = {
        "placeholder": row["placeholder"],
        "secret_type": row["secret_type"],
        "length": row["length"],
        "fingerprint": row["fingerprint"],
        "created_at": row["created_at"],
        "last_accessed_at": row["last_accessed_at"],
    }
    if reveal:
        data["secret"] = row["secret"]
    return data


def _vault_summary(conn: sqlite3.Connection) -> dict:
    try:
        vault_rows = conn.execute("SELECT COUNT(*) FROM vault").fetchone()[0]
        row = conn.execute("SELECT MIN(created_at), MAX(created_at) FROM vault").fetchone()
    except sqlite3.Error as exc:
        _fail(f"cannot read the vault table: {exc}", db_path=DB_PATH)
    summary = {
        "vault_rows": vault_rows,
        "layer1_rows": 0,
        "oldest_created_at": row[0] if row else None,
        "newest_created_at": row[1] if row else None,
    }
    try:
        summary["layer1_rows"] = conn.execute("SELECT COUNT(*) FROM layer1_cache").fetchone()[0]
    except sqlite3.Error:
        pass
    summary["by_type"] = {
        secret_type: count
        for secret_type, count in conn.execute(
            "SELECT secret_type, COUNT(*) FROM vault GROUP BY secret_type ORDER BY COUNT(*) DESC"
        )
    }
    return summary


# --------------------------------------------------------------- commands ---
def cmd_status(args: argparse.Namespace) -> int:
    with _open_vault(live=args.live) as view:
        summary = _vault_summary(view.conn)
        note = view.note

    payload = {
        "ok": True,
        "db_path": DB_PATH,
        "key_source": _key_source(),
        "key_mode": _key_mode(),
        "key_file": KEY_FILE,
        "key_file_exists": Path(KEY_FILE).exists(),
        "password_file": PASSWORD_FILE,
        "password_set": bool(_read_text(PASSWORD_FILE)),
        "read_mode": "live" if args.live else "snapshot",
        "read_note": note,
        **summary,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK

    by_type = ", ".join(f"{k}={v}" for k, v in summary["by_type"].items()) or "-"
    print(f"vault       : {DB_PATH}")
    print(f"rows        : {summary['vault_rows']} mapping(s), {summary['layer1_rows']} layer-1 cache row(s)")
    print(f"key source  : {_key_source()}  (mode {_key_mode()})")
    print(f"key file    : {KEY_FILE}{'' if payload['key_file_exists'] else '  [missing]'}")
    print(f"passphrase  : {'set' if payload['password_set'] else 'not set'}  ({PASSWORD_FILE})")
    print(f"read        : {note}")
    print(f"oldest      : {_stamp(summary['oldest_created_at'] or 0)}")
    print(f"newest      : {_stamp(summary['newest_created_at'] or 0)}")
    print(f"by type     : {by_type}")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    if args.reveal_all:
        args.mask = "none"
    with _open_vault(live=args.live) as view:
        rows = _rows(view.conn)

    rows = _sort_rows(rows, args.sort, args.ascending)
    total = len(rows)
    if args.limit is not None:
        rows = rows[: args.limit]

    if args.mask == "none" and rows:
        _warn("[vault-inspect] revealing plaintext secrets on stdout — handle this output carefully")

    if args.json:
        print(json.dumps({
            "ok": True,
            "db_path": DB_PATH,
            "key_source": _key_source(),
            "mask": args.mask,
            "total": total,
            "returned": len(rows),
            "rows": [_public_row(r, reveal=args.mask == "none") for r in rows],
        }, ensure_ascii=False, indent=2))
        return EXIT_OK

    if not rows:
        if total:
            print(f"nothing to show: --limit {args.limit} hides all {total} mapping(s)")
        else:
            print(f"vault is empty ({DB_PATH})")
        return EXIT_OK

    headers = ("PLACEHOLDER", "TYPE", "SECRET", "CREATED", "LAST USED")
    table = [
        (
            r["placeholder"],
            r["secret_type"],
            _mask(r["secret"], args.mask),
            _stamp(r["created_at"]),
            _stamp(r["last_accessed_at"]),
        )
        for r in rows
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in table)) for i in range(len(headers))]
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip())
    print("  ".join("-" * w for w in widths))
    for row in table:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))).rstrip())
    if len(rows) < total:
        print(f"\n{len(rows)} of {total} mapping(s); raise --limit or drop it to see the rest")
    else:
        print(f"\n{total} mapping(s)")
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    with _open_vault(live=args.live) as view:
        rows = _rows(view.conn)

    wanted = args.placeholder.strip()
    matches = [r for r in rows if r["placeholder"] == wanted]
    if not matches:
        matches = [r for r in rows if wanted and wanted in r["placeholder"]]
    if not matches:
        _fail(
            f"no mapping for {wanted!r}",
            available=", ".join(sorted(r["placeholder"] for r in rows)) or "(vault empty)",
        )
    if len(matches) > 1:
        _fail(
            f"{wanted!r} matches {len(matches)} mappings; pass the full placeholder",
            matches=[r["placeholder"] for r in matches],
        )

    row = matches[0]
    reveal = not args.fingerprint
    if args.json:
        print(json.dumps({"ok": True, **_public_row(row, reveal=reveal)}, ensure_ascii=False, indent=2))
        return EXIT_OK

    if reveal:
        _warn("[vault-inspect] revealing one plaintext secret on stdout — handle this output carefully")
    print(f"placeholder : {row['placeholder']}")
    print(f"type        : {row['secret_type']}")
    print(f"length      : {row['length']}")
    print(f"fingerprint : {row['fingerprint']}")
    print(f"created     : {_stamp(row['created_at'])}")
    print(f"last used   : {_stamp(row['last_accessed_at'])}")
    if reveal:
        print(f"secret      : {row['secret']}")
    return EXIT_OK


# ----------------------------------------------------------------- parser ---
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault-inspect", description=__doc__.splitlines()[0])
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--live", action="store_true",
        help="read the live database in place instead of a snapshot copy. Read-only either way; "
             "the default snapshot is the recommended choice because it reads a consistent copy "
             "and holds no read transaction on the live database",
    )
    common.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", parents=[common], help="key source, row counts and per-type totals")
    p_status.set_defaults(func=cmd_status)

    p_list = sub.add_parser("list", parents=[common], help="list saved mappings with secrets masked")
    p_list.add_argument("--sort", default="created", choices=["created", "accessed", "placeholder", "type"])
    p_list.add_argument("--asc", dest="ascending", action="store_true", help="oldest/smallest first")
    p_list.add_argument("--limit", type=int, default=None, help="show at most N rows")
    p_list.add_argument("--mask", default="fingerprint", choices=list(MASK_STYLES))
    p_list.add_argument("--reveal-all", action="store_true", help="print every plaintext secret")
    p_list.set_defaults(func=cmd_list, ascending=False)

    p_show = sub.add_parser("show", parents=[common], help="reveal the one mapping named by a placeholder")
    p_show.add_argument("placeholder", help="placeholder, or any unique substring of it")
    p_show.add_argument("--fingerprint", action="store_true", help="show metadata only, not the secret")
    p_show.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "limit", None) is not None and args.limit < 0:
        print("--limit must not be negative", file=sys.stderr)
        return EXIT_USAGE
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
