#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""privacy-exempt — pause redaction for one exact term, with a mandatory reason.

The gateway keeps filtering ON by default. This tool is the supported control
surface for an AI agent (or a human) to create a scoped, justified,
self-expiring exemption for one literal term.

Design guarantees enforced here *and* server-side:

* ``--reason`` is mandatory and must be a real sentence. There is no flag to
  skip it, and the gateway rejects a request without one.
* every exemption expires (default 1h, hard cap 7 days); nothing is permanent.
* each allow / revoke / expiry / hit is appended to the gateway audit log.

Exit codes: 0 ok · 2 usage or validation error · 3 gateway unreachable ·
4 gateway rejected the request.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

GATEWAY = os.environ.get("PRIVACY_GATEWAY_URL", "http://127.0.0.1:8317").rstrip("/")
DEFAULT_TTL = int(os.environ.get("PRIVACY_EXEMPT_TTL", "3600"))
DEFAULT_ACTOR = os.environ.get("PRIVACY_EXEMPT_ACTOR", "ai")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_OFFLINE = 3
EXIT_REJECTED = 4


def _request(method: str, path: str, body: dict | None = None) -> dict:
    url = GATEWAY + path
    data = None
    headers = {"accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"ok": False, "error": raw or f"HTTP {exc.code}"}
        payload.setdefault("ok", False)
        payload["http_status"] = exc.code
        return payload
    except (urllib.error.URLError, OSError) as exc:
        print(f"privacy-exempt: cannot reach the gateway at {GATEWAY} ({exc})", file=sys.stderr)
        print("privacy-exempt: is privacy-gateway.service running? "
              "systemctl status privacy-gateway", file=sys.stderr)
        raise SystemExit(EXIT_OFFLINE)


def _fail(payload: dict) -> None:
    print(f"privacy-exempt: {payload.get('error') or 'request rejected'}", file=sys.stderr)
    if payload.get("hint"):
        print(f"privacy-exempt: {payload['hint']}", file=sys.stderr)
    raise SystemExit(EXIT_REJECTED)


def _human_delta(seconds: int) -> str:
    if seconds <= 0:
        return "expired"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d{(seconds % 86400) // 3600:02d}h"


def cmd_allow(args: argparse.Namespace) -> int:
    reason = (args.reason or "").strip()
    if not reason:
        print("privacy-exempt: --reason is required.\n"
              "  State in one sentence why this term is safe to stop filtering, e.g.\n"
              '  --reason "the link is already public in the upstream ticket"\n'
              "  The reason is written to the audit log and shown to the user.",
              file=sys.stderr)
        return EXIT_USAGE
    if len(reason) < 8:
        print("privacy-exempt: --reason must be at least 8 characters.", file=sys.stderr)
        return EXIT_USAGE
    payload = _request("POST", "/privacy/exemptions", {
        "term": args.term,
        "scope": args.scope,
        "reason": reason,
        "ttl_seconds": args.ttl,
        "actor": args.actor,
    })
    if not payload.get("ok"):
        _fail(payload)
    entry = payload["entry"]
    stats = payload.get("stats", {})
    print(f"exemption active for {entry['term']!r}")
    print(f"  scope            : {entry['scope']}")
    print(f"  expires in       : {_human_delta(entry['remaining_seconds'])} "
          f"(at {_dt.datetime.fromtimestamp(entry['expires_at']):%Y-%m-%d %H:%M:%S})")
    print(f"  actor            : {entry['actor']}")
    print(f"  reason           : {entry['reason']}")
    print(f"  active exemptions: {stats.get('active_count')}")
    print()
    print("Filtering is paused for this term only; every other secret is still redacted.")
    print("Tell the user what you exempted and why." if args.actor.startswith("ai")
          else "Remember to revoke it when the task is done.")
    return EXIT_OK


def cmd_revoke(args: argparse.Namespace) -> int:
    reason = (args.reason or "").strip()
    if len(reason) < 8:
        print("privacy-exempt: --reason (>= 8 chars) is required to revoke an exemption.",
              file=sys.stderr)
        return EXIT_USAGE
    query = urllib.parse.urlencode({
        "term": args.term, "reason": reason, "actor": args.actor,
    })
    payload = _request("DELETE", f"/privacy/exemptions?{query}")
    if not payload.get("ok"):
        _fail(payload)
    revoked = payload["revoked"]
    print(f"exemption revoked for {revoked['term']!r} — redaction is back on for it")
    print(f"  reason           : {revoked['reason']}")
    print(f"  active exemptions: {payload.get('stats', {}).get('active_count')}")
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    query = "?include_expired=true" if args.all else ""
    payload = _request("GET", f"/privacy/exemptions{query}")
    if not payload.get("ok"):
        _fail(payload)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK
    stats = payload.get("stats", {})
    print(f"active exemptions: {payload.get('count', 0)}"
          f"  (session hits {stats.get('session_hits', 0)},"
          f" adds {stats.get('adds', 0)}, revokes {stats.get('revokes', 0)})")
    print(f"default ttl {_human_delta(stats.get('default_ttl_seconds', 0))} ·"
          f" hard cap {_human_delta(stats.get('max_ttl_seconds', 0))} ·"
          f" min reason {stats.get('min_reason_chars')} chars")
    entries = payload.get("entries") or []
    if not entries:
        print("  (none — filtering is fully on)")
    for entry in entries:
        state = "EXPIRED" if entry.get("expired") else f"{_human_delta(entry['remaining_seconds'])} left"
        print(f"  · {entry['term']}  scope={entry['scope']}  {state}"
              f"  hits={entry['hits']}  by {entry['actor']}")
        print(f"      reason: {entry['reason']}")
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    query = urllib.parse.urlencode({"since": args.since, "limit": args.limit})
    payload = _request("GET", f"/privacy/exemptions/audit?{query}")
    if not payload.get("ok"):
        _fail(payload)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK
    records = payload.get("records") or []
    if not records:
        print("(no audit records)")
    for rec in records:
        ts = _dt.datetime.fromtimestamp(rec.get("ts", 0)).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts}  {str(rec.get('action')):7s} {str(rec.get('term'))[:44]:46s}"
              f" actor={rec.get('actor')}")
        if rec.get("reason"):
            print(f"{'':21s}reason: {rec['reason']}")
    return EXIT_OK


def cmd_health(args: argparse.Namespace) -> int:
    payload = _request("GET", "/privacy/health")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return EXIT_OK
    ex = payload.get("exemptions") or {}
    print(f"gateway        : {payload.get('status')}  uptime {_human_delta(payload.get('uptime_seconds', 0))}")
    print(f"backend        : {payload.get('backend_url')}")
    print(f"redacted total : {payload.get('total_redacted_secrets')}")
    print(f"vault active   : {payload.get('active_vault_mappings')}")
    layer1 = payload.get("layer1") or {}
    print(f"layer1 (0.5B)  : reachable={layer1.get('reachable')} hits={layer1.get('hits')}"
          f" cache={layer1.get('cache_size')}")
    print(f"exemptions     : {ex.get('active_count', 'n/a')} active"
          f"  terms={ex.get('terms')}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-exempt",
        description="Scoped, justified, self-expiring pause of redaction for one term.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_allow = sub.add_parser("allow", help="pause redaction for one exact term")
    p_allow.add_argument("--term", required=True, help="the exact literal to stop filtering")
    p_allow.add_argument("--reason", required=True,
                         help="MANDATORY: why this term is safe to stop filtering")
    p_allow.add_argument("--scope", default="all", choices=["all", "layer0", "layer1"],
                         help="layer0=regex, layer1=residual 0.5B classifier (default: all)")
    p_allow.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                         help=f"seconds until redaction resumes (default {DEFAULT_TTL}, max 604800)")
    p_allow.add_argument("--actor", default=DEFAULT_ACTOR, help="who asked (default: %(default)s)")
    p_allow.set_defaults(func=cmd_allow)

    p_revoke = sub.add_parser("revoke", help="put redaction back on for a term")
    p_revoke.add_argument("--term", required=True)
    p_revoke.add_argument("--reason", required=True, help="MANDATORY: why it is safe to re-enable")
    p_revoke.add_argument("--actor", default=DEFAULT_ACTOR)
    p_revoke.set_defaults(func=cmd_revoke)

    p_list = sub.add_parser("list", help="list active exemptions")
    p_list.add_argument("--all", action="store_true", help="include expired entries")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_audit = sub.add_parser("audit", help="show the exemption audit trail")
    p_audit.add_argument("--since", type=float, default=0.0, help="epoch seconds")
    p_audit.add_argument("--limit", type=int, default=50)
    p_audit.add_argument("--json", action="store_true")
    p_audit.set_defaults(func=cmd_audit)

    p_health = sub.add_parser("health", help="gateway + exemption summary")
    p_health.add_argument("--json", action="store_true")
    p_health.set_defaults(func=cmd_health)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
