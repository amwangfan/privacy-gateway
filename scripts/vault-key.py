#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vault-key — switch or rotate the passphrase that encrypts the persistence DB.

The vault holds the placeholder <-> credential mappings that make outbound
redaction reversible. It is encrypted with an AES-GCM key derived from either:

  * the generated key file   (``VAULT_KEY_FILE``, mode 0600, default), or
  * an operator passphrase   (``VAULT_KEY_PASSWORD_FILE``, mode 0600, PBKDF2).

Switching between them, or changing the passphrase, MUST re-encrypt every stored
mapping — otherwise the gateway would start with a key that cannot read the old
rows, and previously redacted placeholders would never be restorable. This tool
performs that re-encryption and only then flips the mode.

    vault-key.py status
    vault-key.py set --mode password   # passphrase on stdin as {"password": "..."}
    vault-key.py set --mode file       # back to the generated key file

Every invocation prints one JSON object on its last stdout line. The passphrase is
only ever read from stdin, never from argv (argv is world-visible in ps).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

# Must match EncryptedStore in gateway.py or a re-encrypted row stops being
# readable and lookup-able: the AAD is bound into the AEAD tag, and secret_hash
# is the index used for "have I seen this secret already".
AAD = b"vault-v1"
HASH_DIGEST_SIZE = 16

DEFAULT_DB_PATH = "/var/lib/privacy-gateway/store.sqlite"
DB_PATH = os.environ.get("VAULT_DB_PATH", DEFAULT_DB_PATH)
KEY_FILE = os.environ.get("VAULT_KEY_FILE", "/etc/privacy-gateway/master.key")
PASSWORD_FILE = os.environ.get("VAULT_KEY_PASSWORD_FILE", "/etc/privacy-gateway/vault.password")
MODE_FILE = os.environ.get("VAULT_KEY_MODE_FILE", "/etc/privacy-gateway/vault.key-mode")
SALT = b"dsh-privacy-gateway-v4-master-salt"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAILED = 1


def _fail(error: str, **extra) -> None:
    print(json.dumps({"ok": False, "error": error, **extra}, ensure_ascii=False))
    raise SystemExit(EXIT_FAILED)


def _derive_key(mode: str, password: str = "") -> bytes:
    if mode == "password":
        if not password:
            _fail("no passphrase supplied")
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), SALT, 100000)
    path = Path(KEY_FILE)
    if not path.exists():
        _fail(f"key file {KEY_FILE} does not exist; run the gateway once to generate it")
    raw = path.read_bytes()
    if len(raw) < 32:
        _fail("vault key file is too short")
    return raw[:32] if len(raw) == 32 else hashlib.blake2b(raw, digest_size=32).digest()


def _current_mode() -> str:
    try:
        mode = Path(MODE_FILE).read_text(encoding="utf-8").strip().lower()
    except Exception:
        mode = ""
    if mode in ("password", "file"):
        return mode
    return "password" if Path(PASSWORD_FILE).exists() and Path(PASSWORD_FILE).read_text().strip() else "file"


def _current_password() -> str:
    try:
        return Path(PASSWORD_FILE).read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _load_rows(db: Path, key: bytes) -> list[tuple]:
    """Decrypt every mapping, proving the key is the one that wrote them."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(key)
    conn = sqlite3.connect(str(db))
    try:
        rows = list(conn.execute(
            "SELECT placeholder, secret_enc, secret_type, created_at, last_accessed_at FROM vault"
        ))
    finally:
        conn.close()
    plain = []
    for placeholder, blob, secret_type, created_at, last_accessed in rows:
        try:
            secret = aes.decrypt(blob[:12], blob[12:], AAD).decode("utf-8")
        except Exception as exc:
            _fail(
                "cannot decrypt the current vault with the active key; refusing to "
                "change the key (the existing mappings would be lost)",
                detail=f"{type(exc).__name__}: {exc}",
            )
        plain.append((placeholder, secret, secret_type, created_at, last_accessed))
    return plain


def _write_rows(db: Path, key: bytes, rows: list[tuple]) -> int:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(key)
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("BEGIN IMMEDIATE")
        for placeholder, secret, secret_type, created_at, last_accessed in rows:
            nonce = os.urandom(12)
            blob = nonce + aes.encrypt(nonce, secret.encode("utf-8"), AAD)
            secret_hash = hashlib.blake2b(
                secret.encode("utf-8"), digest_size=HASH_DIGEST_SIZE
            ).hexdigest()
            conn.execute(
                "INSERT OR REPLACE INTO vault "
                "(placeholder, secret_hash, secret_enc, secret_type, created_at, last_accessed_at) "
                "VALUES (?,?,?,?,?,?)",
                (placeholder, secret_hash, blob, secret_type, created_at, last_accessed),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return len(rows)


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(str(tmp), mode)
    os.replace(str(tmp), str(path))


def cmd_status(args: argparse.Namespace) -> int:
    mode = _current_mode()
    out = {
        "ok": True,
        "mode": mode,
        "password_set": bool(_current_password()),
        "password_file": PASSWORD_FILE,
        "key_file": KEY_FILE,
        "key_file_exists": Path(KEY_FILE).exists(),
        "mode_file": MODE_FILE,
        "db_path": DB_PATH,
        "db_exists": Path(DB_PATH).exists(),
        "vault_rows": 0,
    }
    if Path(DB_PATH).exists():
        try:
            conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
            out["vault_rows"] = conn.execute("SELECT COUNT(*) FROM vault").fetchone()[0]
            conn.close()
        except Exception as exc:
            out["db_error"] = str(exc)
    print(json.dumps(out, ensure_ascii=False))
    return EXIT_OK


def cmd_set(args: argparse.Namespace) -> int:
    raw = sys.stdin.read() if not sys.stdin.isatty() else "{}"
    try:
        payload = json.loads(raw or "{}")
    except Exception:
        payload = {}
    new_password = str(payload.get("password") or "")

    target = args.mode
    if target == "password" and len(new_password) < 8:
        _fail("a passphrase of at least 8 characters is required")

    old_mode = _current_mode()
    old_password = _current_password()
    db = Path(DB_PATH)

    # Refuse a no-op early: re-encrypting with the same key is pure risk.
    if target == old_mode and (target != "password" or new_password == old_password):
        print(json.dumps({
            "ok": True, "mode": target, "reencrypted": 0, "changed": False,
            "detail": "already using this key source; nothing to do",
        }, ensure_ascii=False))
        return EXIT_OK

    if not db.exists():
        # No vault yet: just record the choice.
        if target == "password":
            _atomic_write(Path(PASSWORD_FILE), (new_password + "\n").encode("utf-8"))
        _atomic_write(Path(MODE_FILE), (target + "\n").encode("utf-8"))
        print(json.dumps({
            "ok": True, "mode": target, "reencrypted": 0, "changed": True,
            "detail": "no existing vault; key source recorded",
        }, ensure_ascii=False))
        return EXIT_OK

    backup = db.with_suffix(db.suffix + f".keychange-{int(time.time())}.bak")
    shutil.copy2(db, backup)

    try:
        old_key = _derive_key(old_mode, old_password)
        rows = _load_rows(db, old_key)
        new_key = _derive_key(target, new_password)
        count = _write_rows(db, new_key, rows)
    except SystemExit:
        raise
    except Exception as exc:
        # Restore the pre-change database so the gateway still starts.
        try:
            shutil.copy2(backup, db)
        except Exception:
            pass
        _fail(f"re-encryption failed: {exc}", restored_from=str(backup))

    # Only after every row is readable under the new key do we flip the key source.
    if target == "password":
        _atomic_write(Path(PASSWORD_FILE), (new_password + "\n").encode("utf-8"))
    else:
        try:
            Path(PASSWORD_FILE).unlink()
        except FileNotFoundError:
            pass
    _atomic_write(Path(MODE_FILE), (target + "\n").encode("utf-8"))

    # Integrity check with the new key, on the live file.
    verify = _load_rows(db, _derive_key(target, new_password))
    if len(verify) != count:
        _fail("post-change verification failed", expected=count, found=len(verify))

    print(json.dumps({
        "ok": True,
        "mode": target,
        "changed": True,
        "reencrypted": count,
        "backup": str(backup),
        "detail": f"re-encrypted {count} vault mapping(s) under the new key source",
    }, ensure_ascii=False))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault-key", description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="accepted for symmetry; output is always JSON")
    parser.add_argument(
        "--allow-live", action="store_true",
        help="required to modify the live vault at the default VAULT_DB_PATH; "
             "a test that points VAULT_DB_PATH elsewhere never needs it",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="show the active key source")
    p_status.set_defaults(func=cmd_status)

    p_set = sub.add_parser("set", help="switch the key source, re-encrypting the vault")
    p_set.add_argument("--mode", required=True, choices=["password", "file"])
    p_set.set_defaults(func=cmd_set)

    return parser


def _guard_live(args: argparse.Namespace) -> None:
    """Refuse to re-encrypt the production vault unless explicitly asked.

    Re-encryption is destructive on failure and touches live placeholder
    restorability, so a test run that forgets to redirect VAULT_DB_PATH must fail
    loudly instead of quietly rotating the real database.
    """
    if args.command != "set" or getattr(args, "allow_live", False):
        return
    try:
        same_as_default = Path(DB_PATH).resolve() == Path(DEFAULT_DB_PATH).resolve()
    except Exception:
        same_as_default = DB_PATH == DEFAULT_DB_PATH
    if same_as_default:
        _fail(
            "refusing to re-encrypt the live vault without --allow-live "
            f"(VAULT_DB_PATH={DB_PATH}). Point VAULT_DB_PATH at a copy to test, "
            "or pass --allow-live to change the real key source."
        )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _guard_live(args)
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
