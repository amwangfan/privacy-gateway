#!/usr/bin/env python3
# Local unit tests — no upstream LLM, no llama-server required.
import asyncio
import copy
import json
import os
import sys

os.environ["LAYER1_ENABLED"] = "0"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["VAULT_PERSIST"] = "0"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from gateway import (  # noqa: E402
    Layer0Redactor,
    extract_layer1_candidates,
    extract_layer1_items,
    restore_json_object,
    restore_text_all,
    DFAStreamRestorer,
    vault,
    layer1,
    RE_PLACEHOLDER,
    _is_boring_token,
)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def is_redacted(s: str) -> bool:
    return "<SECRET_" in s or "<PRIV_" in s


def fake(*parts):
    """Join fragments so GitHub push protection does not treat fixtures as live secrets."""
    return "".join(parts)


SK_OPENAI = fake("sk-proj-", "abcdefghijklmnopqrstuvwxyz", "123456")
SK_ANT = fake("sk-ant-api03-", "x" * 20, "-", "y" * 20)
SK_ANT_SHORT = fake("sk-ant-", "exampleonlytokenvalue0001")
XAI = fake("xai-", "A" * 48)
GHP = fake("ghp_", "A" * 36)
HF = fake("hf_", "abcdefghijklmnopqrstuvwxyz", "ABCDEF")
STRIPE = fake("sk_live_", "abcdefghijklmnopqrstuvwxyz", "012345")
SLACK = fake("xoxb-", "123456789012-", "123456789012-", "abcdefghijklmnopqrstuvwx")
TELEGRAM = fake("123456789:", "AA", "A" * 33)
JWT = fake(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
)
AKIA = fake("AKIA", "TESTTESTTESTTEST")  # exactly 16 chars after prefix
PEM = fake(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIIEowIBAAKCAQEA0TESTKEY1234567890\n",
    "-----END RSA PRIVATE KEY-----",
)
NPM = fake("npm_", "A" * 36)
BEARER = fake("ya29.", "a" * 40)
DB_URI = fake("postgres://user:", "SuperSecretPassw0rd", "@db.internal:5432/app")


def test_layer0_patterns():
    samples = {
        "sk_openai": (f"please use {SK_OPENAI} now", True),
        "sk_ant": (f"key={SK_ANT}", True),
        "xai": (XAI, True),
        "ghp": (GHP, True),
        "hf": (HF, True),
        "stripe": (STRIPE, True),
        "slack": (SLACK, True),
        "telegram": (TELEGRAM, True),
        "jwt": (JWT, True),
        "akia": (AKIA, True),
        "pem": (PEM, True),
        "db": (DB_URI, True),
        "npm": (NPM, True),
        "bearer": (f"Authorization: Bearer {BEARER}", True),
        "plain": ("hello world office-N100", False),
    }
    for name, (text, expect_hit) in samples.items():
        out = Layer0Redactor.redact_text(text)
        hit = out != text or is_redacted(out)
        check(hit is expect_hit, f"{name}: expect_hit={expect_hit} got {out!r}")
        if name == "db":
            check(is_redacted(out) and "postgres://user:" in out, f"db password not tokenized: {out}")
            check("SuperSecretPassw0rd" not in out, f"db password leaked: {out}")
        if name == "bearer":
            check("Bearer " in out and is_redacted(out), f"bearer not tokenized: {out}")
    print("ok layer0 patterns")


def test_dsh_responses_payload():
    payload = {
        "model": "grok-4.6",
        "instructions": f"You may see secrets like {SK_OPENAI} in tools.",
        "tools": [
            {
                "type": "function",
                "name": "bash",
                "description": f"run commands. token={SK_ANT_SHORT}",
                "parameters": {},
            }
        ],
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": f"check this {GHP}"}],
            },
            {
                "type": "function_call",
                "name": "read",
                "call_id": "call_keep_me",
                "arguments": json.dumps({"file": "x", "token": SK_ANT_SHORT}),
            },
            {
                "type": "function_call_output",
                "call_id": "call_keep_me",
                "output": (
                    f"secret-key: {SK_OPENAI}\n"
                    f"postgres://u:DbPassw0rdSECRET@127.0.0.1:5432/x\n"
                    f"{PEM}\n"
                    f"{HF}\n"
                    f"{STRIPE}\n"
                ),
            },
        ],
        "stream": True,
    }
    data = Layer0Redactor.redact_tree(copy.deepcopy(payload))
    blob = json.dumps(data)
    leaked = [
        SK_OPENAI,
        SK_ANT_SHORT,
        GHP,
        "DbPassw0rdSECRET",
        "BEGIN RSA PRIVATE KEY",
        HF,
        STRIPE,
    ]
    for s in leaked:
        check(s not in blob, f"LEAK {s!r} still in payload")
    check(data["input"][1]["call_id"] == "call_keep_me", "call_id rewritten")
    check(data["input"][1]["name"] == "read", "tool name rewritten")
    check(data["model"] == "grok-4.6", "model rewritten")
    check(is_redacted(data["instructions"]), "instructions not redacted")
    check(is_redacted(data["tools"][0]["description"]), "tools description not redacted")
    check(is_redacted(data["input"][2]["output"]), "function_call_output.output not redacted")
    print("ok dsh responses payload")


def test_passthrough_and_images():
    data = {
        "id": SK_OPENAI,
        "call_id": "call_abc",
        "image_url": "data:image/png;base64," + ("A" * 80),
        "content": SK_OPENAI,
    }
    out = Layer0Redactor.redact_tree(copy.deepcopy(data))
    check(out["id"] == data["id"], "id should passthrough")
    check(out["call_id"] == "call_abc", "call_id should passthrough")
    check(out["image_url"].startswith("data:image/png;base64,"), "image data uri rewritten")
    check(is_redacted(out["content"]), "content not redacted")
    print("ok passthrough and images")


def test_restore_roundtrip():
    original = f"use {SK_OPENAI} please"
    red = Layer0Redactor.redact_text(original)
    check(is_redacted(red), "not redacted")
    back = restore_text_all(red)
    check(back == original, f"roundtrip failed: {back!r}")
    obj = {"choices": [{"message": {"content": red}}]}
    restored = restore_json_object(copy.deepcopy(obj))
    check(restored["choices"][0]["message"]["content"] == original, "json restore failed")
    print("ok restore roundtrip")


def test_dfa_split_placeholder():
    original = SK_OPENAI
    red = Layer0Redactor.redact_text(original)
    check(red.startswith("<") and red.endswith(">"), red)
    restorer = DFAStreamRestorer(vault.get_secret)
    parts = [red[:3], red[3:9], red[9:14], red[14:]]
    out = "".join(restorer.feed(p) for p in parts) + restorer.flush()
    check(out == original, f"DFA failed: {out!r} from parts {parts!r} red={red!r}")
    print("ok dfa split placeholder")


def test_layer1_candidates():
    sixteen = fake("Ab3d", "Ef9h", "Jk2m", "Np7r")  # 16 mixed alnum
    text = (
        "password=mysql_root_password_2026\n"
        "hello world\n"
        "office-N100\n"
        f"bare {sixteen} in a sentence\n"
        "token: a8f3Kq92LmN0pQwErTyUiOpAsDfGhJkLzXcVbNm12\n"
    )
    cands = extract_layer1_candidates(text)
    check("mysql_root_password_2026" in cands, f"assignment not extracted: {cands}")
    check(sixteen in cands, f"16-char mixed token not extracted: {cands}")
    check("office-N100" not in cands, f"hostname false positive: {cands}")
    check("hello" not in cands and "world" not in cands, f"plain words extracted: {cands}")
    print("ok layer1 candidates")


def test_placeholder_not_double_redacted():
    text = SK_OPENAI
    once = Layer0Redactor.redact_text(text)
    twice = Layer0Redactor.redact_text(once)
    check(once == twice, f"double redact: {once!r} vs {twice!r}")
    check(len(RE_PLACEHOLDER.findall(twice)) == 1, twice)
    print("ok placeholder freeze")


def test_code_identifier_filtering_and_uppercase_keys():
    check(_is_boring_token("LAYER1_MAX_CANDIDATES") is True, "Known constant should be boring")
    check(_is_boring_token("extract_layer1_candidates") is True, "Known function should be boring")
    check(_is_boring_token("session-3cd9278a-8cc6-46ab-bfb9-3b783d") is True, "Session ID should be boring")
    check(_is_boring_token("self.buf\n", is_assign=True) is True, "Stripped short token should be boring")

    check(_is_boring_token("MY_CUSTOM_SECRET_KEY_123") is False, "Unknown UPPER_SNAKE may be a secret")
    check(_is_boring_token("ZY8OLIYeP6-UdwquM2P2L") is False, "Target token must NOT be boring")
    check(_is_boring_token("goal-481c877f-00be-4b59-a51b-3a673684d02e") is True, "goal id should be boring")
    check(_is_boring_token("claude-sonnet-4-6") is True, "claude model id should be boring")
    check(_is_boring_token("claude-" + "opus-4-6-thinking") is True, "long claude model id should be boring")
    check(_is_boring_token("grok-4.20-multi-agent-0309") is True, "grok model id should be boring")
    check(_is_boring_token("ccswitch-aggregator/claude-sonnet-4-6") is True, "provider/model route should be boring")
    check(_is_boring_token("gemini-3.8-flash-high") is True, "gemini model id should be boring")
    check(_is_boring_token("deepseek-v4-flash") is True, "deepseek model id should be boring")

    code_snippet = """
    LAYER1_MAX_CANDIDATES = 8
    target = "ZY8OLIYeP6-UdwquM2P2L"
    def extract_layer1_candidates(): pass
    custom_key = "MY_CUSTOM_SECRET_KEY_123"
    password=mysql_root_password_2026
    """
    items = extract_layer1_items(code_snippet)
    spans = [it["span"] for it in items]
    check("ZY8OLIYeP6-UdwquM2P2L" in spans, "Target secret should be extracted")
    check("MY_CUSTOM_SECRET_KEY_123" in spans, "Unknown uppercase secret should be extracted")
    check("LAYER1_MAX_CANDIDATES" not in spans, "Known constant must NOT be extracted")
    check("extract_layer1_candidates" not in spans, "Known function must NOT be extracted")
    check("mysql_root_password_2026" in spans, "password= assignment should be extracted")
    model_blob = "route ccswitch-aggregator/claude-sonnet-4-6 and grok-4.20-multi-agent-0309"
    model_spans = [it["span"] for it in extract_layer1_items(model_blob)]
    check("claude-sonnet-4-6" not in model_spans, f"model id leaked into candidates: {model_spans}")
    check("grok-4.20-multi-agent-0309" not in model_spans, f"grok id leaked: {model_spans}")
    print("ok code identifier filtering and uppercase keys")


def test_nested_arguments_json_stays_valid():
    src = (
        '                "description": f"run commands. token={SK_ANT_SHORT}",\n'
        '                "parameters": {},\n'
    )
    payload = {
        "input": [
            {
                "type": "function_call",
                "name": "write",
                "call_id": "call_keep",
                "arguments": json.dumps({"file_path": "/tmp/x.py", "content": src}),
            }
        ]
    }
    out = layer1._replace_tree(copy.deepcopy(payload), {"SK_ANT_SHORT"})
    parsed = json.loads(out["input"][0]["arguments"])
    check("SK_ANT_SHORT" not in parsed["content"], parsed["content"][:240])
    check("{<" in parsed["content"] or "{<SECRET_" in parsed["content"] or is_redacted(parsed["content"]), parsed["content"][:240])
    # f-string closing brace must survive (the 400 was `token={<SECRET...>"` missing `}`)
    check("{<SECRET_" in parsed["content"] and '}",' in parsed["content"], parsed["content"][:240])
    print("ok nested arguments json stays valid")


def test_reverse_traversal_and_cache_reuse():
    async def run():
        token_secret = "SecCacheTok16Aa9x"
        token_safe = "SafeCacheTok16Bb8y"
        target_token = "NewCacheTok16Cc7z"
        layer1._cache.clear()

        layer1._cache_put(f"\n{token_safe}\nbearer token", False)
        layer1._cache_put(f"\n{token_secret}\nbearer token", True)

        payload = {
            "input": [
                {"role": "assistant", "content": [{"type": "text", "text": f"History with {token_safe} and {token_secret}"}]},
                {"role": "user", "content": [{"type": "text", "text": f"Latest message with {target_token}"}]},
            ]
        }

        evaluated = []
        async def mock_classify_batch(items, timeout):
            for it in items:
                evaluated.append(it["span"])
            return {it["span"] for it in items}

        orig_classify_batch = layer1.classify_batch
        orig_reachable = layer1.reachable
        import gateway
        orig_enabled = gateway.LAYER1_ENABLED
        gateway.LAYER1_ENABLED = True
        layer1.classify_batch = mock_classify_batch
        layer1.reachable = lambda: asyncio.sleep(0, result=True)
        try:
            res = await layer1.redact_tree(payload)
        finally:
            gateway.LAYER1_ENABLED = orig_enabled
            layer1.classify_batch = orig_classify_batch
            layer1.reachable = orig_reachable

        check(target_token in evaluated, "Target must be evaluated")
        check(token_safe not in evaluated, "Cached safe token must NOT be re-evaluated")
        check(token_secret not in evaluated, "Cached secret token must NOT be re-evaluated")

        user_txt = res["input"][1]["content"][0]["text"]
        asst_txt = res["input"][0]["content"][0]["text"]
        check(is_redacted(user_txt), "User secret must be redacted")
        check(is_redacted(asst_txt), "Assistant cached secret must be redacted")

    asyncio.run(run())
    print("ok reverse traversal and cache reuse")


def test_encrypted_persist_survives_new_instance():
    import tempfile
    from gateway import EncryptedStore, MemoryVault, Layer1Classifier

    td = tempfile.mkdtemp()
    db = os.path.join(td, "store.sqlite")
    key = os.path.join(td, "master.key")
    st = EncryptedStore(db, key)
    v1 = MemoryVault(store=st, mem_max=16)
    ph = v1.get_or_create("persist-secret-value-xyz", "API_KEY")
    l1 = Layer1Classifier(store=st)
    l1._cache_put("span\nPersistTok16Abcd", True)
    st.close()

    raw = open(db, "rb").read()
    check(b"persist-secret-value-xyz" not in raw, "plaintext leaked into sqlite")
    check(os.stat(key).st_mode & 0o777 == 0o600, "key file mode")

    st2 = EncryptedStore(db, key)
    v2 = MemoryVault(store=st2, mem_max=16)
    check(v2.get_secret(ph) == "persist-secret-value-xyz", "restore after reopen failed")
    check(v2.get_or_create("persist-secret-value-xyz", "API_KEY") == ph, "placeholder not idempotent")
    l2 = Layer1Classifier(store=st2)
    check(l2._cache_get("span\nPersistTok16Abcd") is True, "layer1 cache did not persist")
    st2.close()
    print("ok encrypted persist survives new instance")


def test_custom_secrets_and_vault_password():
    import gateway
    custom_tok = fake("my_custom_", "secret_token_", "12345")
    os.environ["CUSTOM_SECRETS"] = custom_tok
    red = gateway.Layer0Redactor.redact_text(f"test with {custom_tok} token")
    check(is_redacted(red) and custom_tok not in red, f"custom secret not redacted: {red}")

    # Test custom password derivation
    pw = fake("my_vault_", "custom_password_", "98765")
    os.environ["VAULT_PASSWORD"] = pw
    gateway.VAULT_PASSWORD = pw
    key = gateway._load_or_create_key("/tmp/dummy_vault_key_test")
    check(gateway.VAULT_KEY_SOURCE == "password", f"unexpected key source: {gateway.VAULT_KEY_SOURCE}")
    check(len(key) == 32, f"key length {len(key)} != 32")
    os.environ.pop("VAULT_PASSWORD", None)
    os.environ.pop("CUSTOM_SECRETS", None)
    gateway.VAULT_PASSWORD = ""
    print("ok custom secrets and vault password")


def test_vault_inspect_read_only_view():
    """The shipped inspector lists saved mappings, masks them, and never writes."""
    import hashlib
    import shutil
    import sqlite3
    import subprocess
    import tempfile
    from pathlib import Path

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    script = Path(ROOT) / "scripts" / "vault-inspect.py"
    check(script.exists(), f"inspector missing at {script}")

    td = tempfile.mkdtemp()
    try:
        db = os.path.join(td, "store.sqlite")
        key_path = os.path.join(td, "master.key")
        key = os.urandom(32)
        with open(key_path, "wb") as fh:
            fh.write(key)
        secret = fake("sk-fixture-", "inspector_probe_", "99887766")

        # Keep this connection OPEN and idle in WAL mode: the row then lives only in
        # the -wal, so a reader that ignores the WAL would not see it, and any write
        # by the inspector would show up as a changed mtime on these files.
        conn = sqlite3.connect(db, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE vault (placeholder TEXT PRIMARY KEY, secret_hash TEXT NOT NULL UNIQUE,"
            " secret_enc BLOB NOT NULL, secret_type TEXT NOT NULL, created_at REAL NOT NULL,"
            " last_accessed_at REAL NOT NULL)"
        )
        aes = AESGCM(key)
        nonce = os.urandom(12)
        conn.execute(
            "INSERT INTO vault VALUES (?,?,?,?,?,?)",
            (
                "<SECRET_API_KEY_1>",
                hashlib.blake2b(secret.encode("utf-8"), digest_size=16).hexdigest(),
                nonce + aes.encrypt(nonce, secret.encode("utf-8"), b"vault-v1"),
                "API_KEY",
                1000.0,
                1000.0,
            ),
        )
        check(os.path.exists(db + "-wal"), "fixture is not in WAL mode; test would be weaker")
        mtimes = {p: os.stat(p).st_mtime_ns for p in (db, db + "-wal", db + "-shm")}

        env = os.environ.copy()
        env.update({
            "VAULT_DB_PATH": db,
            "VAULT_KEY_FILE": key_path,
            "VAULT_KEY_MODE_FILE": os.path.join(td, "vault.key-mode"),
            "VAULT_KEY_PASSWORD_FILE": os.path.join(td, "vault.password"),
        })
        env.pop("VAULT_PASSWORD", None)
        env.pop("VAULT_MASTER_KEY", None)

        def run(*args, _env=None):
            return subprocess.run(
                [sys.executable, str(script), *args],
                env=_env or env, capture_output=True, text=True,
            )

        before = open(db, "rb").read()

        listed = run("list")
        check(listed.returncode == 0, f"list failed: {listed.stdout}{listed.stderr}")
        check("<SECRET_API_KEY_1>" in listed.stdout, "placeholder missing from the listing")
        check(secret not in listed.stdout, "the masked listing leaked the plaintext secret")
        check(f"[{len(secret)} chars fp=" in listed.stdout, "the masked listing lacks length/fingerprint")

        shown = run("show", "<SECRET_API_KEY_1>")
        check(shown.returncode == 0, f"show failed: {shown.stdout}{shown.stderr}")
        check(secret in shown.stdout, "show did not reveal the requested secret")

        status = run("status", "--json")
        check(status.returncode == 0, f"status failed: {status.stdout}{status.stderr}")
        check(json.loads(status.stdout)["vault_rows"] == 1, "status miscounted the rows")

        # A key that did not write the rows must fail loudly instead of showing nothing.
        other_key = os.path.join(td, "other.key")
        with open(other_key, "wb") as fh:
            fh.write(os.urandom(32))
        wrong = run("list", _env=dict(env, VAULT_KEY_FILE=other_key))
        check(wrong.returncode == 1, f"wrong key should fail, got {wrong.returncode}")
        check("cannot decrypt" in wrong.stdout, f"wrong key gave an unclear error: {wrong.stdout}")

        # Missing key: this tool must never create one.
        missing = run("list", _env=dict(env, VAULT_KEY_FILE=os.path.join(td, "absent.key")))
        check(missing.returncode == 1, "a missing key file must fail")
        check(not Path(os.path.join(td, "absent.key")).exists(), "the inspector created a key file")

        check(open(db, "rb").read() == before, "the inspector modified the vault database")
        # The default (snapshot) path must not touch the live files at all — not even
        # the WAL index — otherwise an idle inspection shows up as database activity.
        touched = [p for p, mt in mtimes.items() if os.stat(p).st_mtime_ns != mt]
        check(not touched, f"the inspector touched live files: {touched}")
        conn.close()
    finally:
        shutil.rmtree(td, ignore_errors=True)
    print("ok vault inspector is read-only and masks by default")


if __name__ == "__main__":
    tests = [
        test_layer0_patterns,
        test_dsh_responses_payload,
        test_passthrough_and_images,
        test_restore_roundtrip,
        test_dfa_split_placeholder,
        test_layer1_candidates,
        test_placeholder_not_double_redacted,
        test_code_identifier_filtering_and_uppercase_keys,
        test_nested_arguments_json_stays_valid,
        test_reverse_traversal_and_cache_reuse,
        test_encrypted_persist_survives_new_instance,
        test_custom_secrets_and_vault_password,
        test_vault_inspect_read_only_view,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
        except Exception as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    if failed:
        print(f"{failed} failed")
        sys.exit(1)
    print(f"all {len(tests)} passed")
