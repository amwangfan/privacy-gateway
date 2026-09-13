#!/usr/bin/env python3
# Local unit tests — no upstream LLM, no llama-server required.
import copy
import json
import os
import sys

os.environ["LAYER1_ENABLED"] = "0"
os.environ["LOG_LEVEL"] = "WARNING"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from gateway import (  # noqa: E402
    Layer0Redactor,
    extract_layer1_candidates,
    restore_json_object,
    restore_text_all,
    DFAStreamRestorer,
    vault,
    RE_PLACEHOLDER,
)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


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
        hit = out != text or "<PRIV_" in out
        check(hit is expect_hit, f"{name}: expect_hit={expect_hit} got {out!r}")
        if name == "db":
            check("postgres://user:<PRIV_" in out, f"db password not tokenized: {out}")
            check("SuperSecretPassw0rd" not in out, f"db password leaked: {out}")
        if name == "bearer":
            check("Bearer <PRIV_" in out, f"bearer not tokenized: {out}")
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
    check("<PRIV_" in data["instructions"], "instructions not redacted")
    check("<PRIV_" in data["tools"][0]["description"], "tools description not redacted")
    check("<PRIV_" in data["input"][2]["output"], "function_call_output.output not redacted")
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
    check("<PRIV_" in out["content"], "content not redacted")
    print("ok passthrough and images")


def test_restore_roundtrip():
    original = f"use {SK_OPENAI} please"
    red = Layer0Redactor.redact_text(original)
    check("<PRIV_" in red, "not redacted")
    back = restore_text_all(red)
    check(back == original, f"roundtrip failed: {back!r}")
    obj = {"choices": [{"message": {"content": red}}]}
    restored = restore_json_object(copy.deepcopy(obj))
    check(restored["choices"][0]["message"]["content"] == original, "json restore failed")
    print("ok restore roundtrip")


def test_dfa_split_placeholder():
    original = SK_OPENAI
    red = Layer0Redactor.redact_text(original)
    check(red.startswith("<PRIV_") and red.endswith(">"), red)
    restorer = DFAStreamRestorer(vault.get_secret)
    parts = [red[:3], red[3:9], red[9:14], red[14:]]
    out = "".join(restorer.feed(p) for p in parts) + restorer.flush()
    check(out == original, f"DFA failed: {out!r} from parts {parts!r} red={red!r}")
    print("ok dfa split placeholder")


def test_layer1_candidates():
    text = (
        "password=mysql_root_password_2026\n"
        "hello world\n"
        "office-N100\n"
        "token: a8f3Kq92LmN0pQwErTyUiOpAsDfGhJkLzXcVbNm12\n"
    )
    cands = extract_layer1_candidates(text)
    check("mysql_root_password_2026" in cands, f"assignment not extracted: {cands}")
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


if __name__ == "__main__":
    tests = [
        test_layer0_patterns,
        test_dsh_responses_payload,
        test_passthrough_and_images,
        test_restore_roundtrip,
        test_dfa_split_placeholder,
        test_layer1_candidates,
        test_placeholder_not_double_redacted,
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
