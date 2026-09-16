#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""privacy-exempt — allow one exact term through the redaction gateway.

Filtering is ON for everything by default. An exemption suspends redaction for
one literal term, or for one stored secret named by its ``<SECRET_...>`` alias so
the agent never has to handle the plaintext.

Rules enforced here and server-side:

* ``--reason`` is mandatory for this entry point and may not be blank. The
  gateway itself does not require one, so an operator can set an exemption by hand.
* there is no expiry requirement: exemptions persist until revoked. Pass
  ``--expires-at`` only when you deliberately want one to lapse.
* every allow / revoke / expiry / hit is appended to the gateway audit log.

Exit codes: 0 ok · 2 usage error · 3 gateway unreachable · 4 gateway rejected.
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
        print("privacy-exempt: systemctl status privacy-gateway", file=sys.stderr)
        raise SystemExit(EXIT_OFFLINE)


def _fail(payload: dict) -> None:
    print(f"privacy-exempt: {payload.get('error') or 'request rejected'}", file=sys.stderr)
    if payload.get("hint"):
        print(f"privacy-exempt: {payload['hint']}", file=sys.stderr)
    raise SystemExit(EXIT_REJECTED)


def _clock(epoch: int) -> str:
    if not epoch:
        return "-"
    return _dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


def _term_cell(entry: dict) -> str:
    """Show the vault alias when the exemption was created from one."""
    if entry.get("placeholder"):
        return f"{entry['placeholder']} -> {entry['term']}"
    return entry["term"]


def cmd_allow(args: argparse.Namespace) -> int:
    reason = (args.reason or "").strip()
    if not reason:
        print(
            "privacy-exempt: --reason is required (it may not be blank).\n"
            "  Say why this term may leave the network unfiltered, e.g.\n"
            '  --reason "the link is already public in the upstream ticket"',
            file=sys.stderr,
        )
        return EXIT_USAGE
    body = {
        "term": args.term,
        "scope": args.scope,
        "reason": reason,
        "actor": args.actor,
    }
    if args.expires_at:
        body["expires_at"] = args.expires_at
    payload = _request("POST", "/privacy/exemptions", body)
    if not payload.get("ok"):
        _fail(payload)
    entry = payload["entry"]
    print(f"exemption active for {_term_cell(entry)}")
    print(f"  scope  : {entry['scope']}")
    print(f"  expiry : {'never (until revoked)' if entry['permanent'] else _clock(entry['expires_at'])}")
    print(f"  actor  : {entry['actor']}")
    print(f"  reason : {entry['reason']}")
    print(f"  active : {payload.get('stats', {}).get('active_count')}")
    if args.actor.startswith("ai"):
        print()
        print("Tell the user which term you allowed through and why.")
    return EXIT_OK


def cmd_revoke(args: argparse.Namespace) -> int:
    reason = (args.reason or "").strip()
    if not reason:
        print("privacy-exempt: --reason is required (it may not be blank).", file=sys.stderr)
        return EXIT_USAGE
    query = urllib.parse.urlencode({"term": args.term, "reason": reason, "actor": args.actor})
    payload = _request("DELETE", f"/privacy/exemptions?{query}")
    if not payload.get("ok"):
        _fail(payload)
    revoked = payload["revoked"]
    print(f"exemption revoked for {_term_cell(revoked)} - redaction is back on for it")
    print(f"  reason : {revoked['reason']}")
    print(f"  active : {payload.get('stats', {}).get('active_count')}")
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
    print(
        f"active exemptions: {payload.get('count', 0)}"
        f"  (permanent {stats.get('permanent_count', 0)}"
        f" / hits {stats.get('session_hits', 0)}"
        f" / adds {stats.get('adds', 0)}"
        f" / revokes {stats.get('revokes', 0)})"
    )
    entries = payload.get("entries") or []
    if not entries:
        print("  (none - everything is filtered)")
    for entry in entries:
        expiry = "never" if entry.get("permanent") else f"until {_clock(entry['expires_at'])}"
        print(f"  - {_term_cell(entry)}  scope={entry['scope']}  {expiry}"
              f"  hits={entry['hits']}  by {entry['actor']}")
        if entry.get("reason"):
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
    layer1 = payload.get("layer1") or {}
    print(f"gateway   : {payload.get('status')}")
    print(f"backend   : {payload.get('backend_url')}")
    print(f"layer1    : reachable={layer1.get('reachable')} hits={layer1.get('hits')}")
    print(f"redacted  : {payload.get('total_redacted_secrets')} total, "
          f"{payload.get('active_vault_mappings')} in vault")
    print(f"exemptions: {ex.get('active_count', 'n/a')} active"
          f" ({ex.get('permanent_count', 0)} permanent)")
    for term in ex.get("terms") or []:
        print(f"  - {term}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-exempt",
        description="Allow one exact term through the redaction gateway.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_allow = sub.add_parser("allow", help="stop filtering one exact term")
    p_allow.add_argument("--term", required=True,
                         help="the literal, or a vault alias such as <SECRET_API_KEY_1>")
    p_allow.add_argument("--reason", required=True,
                         help="MANDATORY: why this term may go out unfiltered")
    p_allow.add_argument("--scope", default="all", choices=["all", "layer0", "layer1"],
                         help="layer0=regex, layer1=residual 0.5B classifier (default: all)")
    p_allow.add_argument("--expires-at", type=float, default=None, dest="expires_at",
                         help="optional epoch seconds; omit for a permanent exemption")
    p_allow.add_argument("--actor", default=DEFAULT_ACTOR, help="who asked (default: %(default)s)")
    p_allow.set_defaults(func=cmd_allow)

    p_revoke = sub.add_parser("revoke", help="put redaction back on for a term")
    p_revoke.add_argument("--term", required=True, help="the literal or vault alias used to allow it")
    p_revoke.add_argument("--reason", required=True, help="MANDATORY: why it can be filtered again")
    p_revoke.add_argument("--actor", default=DEFAULT_ACTOR)
    p_revoke.set_defaults(func=cmd_revoke)

    p_list = sub.add_parser("list", help="list active exemptions")
    p_list.add_argument("--all", action="store_true", help="include already-expired entries")
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
