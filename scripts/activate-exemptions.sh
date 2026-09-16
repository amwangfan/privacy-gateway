#!/usr/bin/env bash
# activate-exemptions.sh — turn the staged exemption build on, verify it, and
# roll the deployment back automatically if verification fails.
#
# The repo was changed and staged into /opt already; the running privacy-gateway
# process still holds the previous code in memory. This script performs the
# switch in one auditable step:
#
#   1. back up the deployed gateway.py
#   2. restart privacy-gateway.service
#   3. verify: /privacy/health exposes the exemptions block,
#              /privacy/exemptions answers, reason/TTL validation still rejects
#   4. on failure: restore the backup, restart, report — leaving you where you were
#
#   ./scripts/activate-exemptions.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="${PRIVACY_DEPLOY_DIR:-/opt/privacy-gateway}"
TS=$(date +%Y%m%d-%H%M%S)
BACKUP="${PRIVACY_BACKUP_DIR:-/root/privacy-backup-$TS}"
GATEWAY="http://127.0.0.1:8317"
CURL=(curl -sS --noproxy '*' --max-time 8)

say()  { printf '\033[1m[activate]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[activate] %s\033[0m\n' "$*" >&2; }

rollback() {
  fail "verification failed — rolling back to the previous deployment"
  if [ -f "$BACKUP/gateway.py" ]; then
    install -m 0755 "$BACKUP/gateway.py" "$DEPLOY/gateway.py"
    systemctl restart privacy-gateway.service
    sleep 2
    if "${CURL[@]}" "$GATEWAY/privacy/health" >/dev/null 2>&1; then
      say "rolled back; the previously running code is active again"
      say "backup kept at $BACKUP (restore with: install -m0755 $BACKUP/gateway.py $DEPLOY/gateway.py)"
    else
      fail "rollback restart did not come up healthy — check: journalctl -u privacy-gateway -n 50"
    fi
  else
    fail "no backup at $BACKUP/gateway.py; nothing restored"
  fi
  exit 1
}

say "repo   : $REPO"
say "deploy : $DEPLOY"

[ -f "$DEPLOY/gateway.py" ] || { fail "no $DEPLOY/gateway.py"; exit 1; }
if ! cmp -s "$REPO/gateway.py" "$DEPLOY/gateway.py"; then
  fail "$DEPLOY/gateway.py differs from the repo — run scripts/deploy-local.sh --dry-run first"
  exit 1
fi

mkdir -p "$BACKUP"
cp -a "$DEPLOY/gateway.py" "$BACKUP/gateway.py"
say "backup : $BACKUP/gateway.py"

say "restarting privacy-gateway.service"
systemctl restart privacy-gateway.service

for _ in $(seq 1 30); do
  "${CURL[@]}" "$GATEWAY/privacy/health" >/dev/null 2>&1 && break
  sleep 0.5
done

health=$("${CURL[@]}" "$GATEWAY/privacy/health" 2>/dev/null)
[ -n "$health" ] || rollback
echo "$health" > "$BACKUP/health-after.json"

printf '%s' "$health" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if "exemptions" not in d:
    raise SystemExit(1)
ex = d["exemptions"]
print(f"  exemptions block: active={ex[\"active_count\"]} file={ex[\"file\"]}")
print(f"  layer1 reachable: {(d.get(\"layer1\") or {}).get(\"reachable\")}")
' && ok "health exposes the exemptions block" || rollback

list=$("${CURL[@]}" "$GATEWAY/privacy/exemptions" 2>/dev/null)
printf '%s' "$list" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if not d.get("ok"):
    raise SystemExit(1)
print(f"  exemptions endpoint: count={d[\"count\"]}")
' && ok "GET /privacy/exemptions answers" || rollback

code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$GATEWAY/privacy/exemptions" \
  -H 'content-type: application/json' -d '{"term":"activate-selftest","reason":"short"}')
[ "$code" = "400" ] && ok "reason validation still rejects bad input (400)" \
  || { bad "validation accepted a bad request ($code)"; rollback; }

code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$GATEWAY/privacy/exemptions" \
  -H 'content-type: application/json' \
  -d '{"term":"activate-selftest","reason":"self-test entry, revoked immediately","actor":"activate-script"}')
if [ "$code" = "200" ]; then
  ok "allow works (permanent, no expiry required)"
  "${CURL[@]}" -X DELETE "$GATEWAY/privacy/exemptions?term=activate-selftest&reason=self-test%20cleanup%20revoke&actor=activate-script" >/dev/null
  ok "self-test entry revoked (exemption list left clean)"
else
  bad "allow returned $code"; rollback
fi

say "done. Exemptions are live. CLI: $REPO/scripts/privacy-exempt.sh list"
say "DSH still needs its own restart to load the plugin: systemctl restart deepseek-harness"
