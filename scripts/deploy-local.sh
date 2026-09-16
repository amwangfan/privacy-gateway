#!/usr/bin/env bash
# deploy-local.sh — publish this git checkout to the deployed gateway tree.
#
# The git repository at /root/privacy-gateway is the single source of truth.
# /opt/privacy-gateway is a *deployment* directory: it holds the venv, the
# llama.cpp build and the GGUF models, and it is what systemd actually runs.
# Never edit /opt/privacy-gateway/gateway.py by hand — edit the repo and deploy.
#
#   ./scripts/deploy-local.sh            # compile check, sync, restart, verify
#   ./scripts/deploy-local.sh --dry-run  # show what would change, touch nothing
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="${PRIVACY_DEPLOY_DIR:-/opt/privacy-gateway}"
VENV_PY="$DEPLOY/venv/bin/python"
BACKUP_ROOT="${PRIVACY_BACKUP_DIR:-/root/privacy-backup-$(date +%Y%m%d-%H%M%S)}"

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

FILES=(gateway.py)
SCRIPTS=(privacy-exempt.sh privacy-exempt.py)
SERVICES=(privacy-gateway.service)

say() { printf '\033[1m[deploy]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[deploy] %s\033[0m\n' "$*" >&2; exit 1; }

[ -f "$REPO/gateway.py" ] || fail "no gateway.py in $REPO"
[ -d "$DEPLOY" ] || fail "deploy dir $DEPLOY does not exist"
[ -x "$VENV_PY" ] || fail "no venv python at $VENV_PY"

say "repo    : $REPO"
say "deploy  : $DEPLOY"
say "python  : $VENV_PY"

# 1. Static validation before anything is copied.
say "byte-compiling $REPO/gateway.py"
"$VENV_PY" -m py_compile "$REPO/gateway.py" || fail "gateway.py does not compile; nothing deployed"

# 2. Show the diff.
changed=()
for f in "${FILES[@]}"; do
  if ! cmp -s "$REPO/$f" "$DEPLOY/$f" 2>/dev/null; then
    changed+=("$f")
  fi
done
if [ ${#changed[@]} -eq 0 ]; then
  say "already in sync (${FILES[*]})"
else
  say "files to update: ${changed[*]}"
  for f in "${changed[@]}"; do
    diff -u "$DEPLOY/$f" "$REPO/$f" | head -60 || true
  done
fi

if [ "$DRY_RUN" = "1" ]; then
  say "--dry-run: stopping here, nothing changed"
  exit 0
fi

# 3. Back up what is about to be replaced.
mkdir -p "$BACKUP_ROOT"
for f in "${FILES[@]}"; do
  [ -f "$DEPLOY/$f" ] && cp -a "$DEPLOY/$f" "$BACKUP_ROOT/$f.$(date +%Y%m%d-%H%M%S)"
done
for s in "${SERVICES[@]}"; do
  [ -f "/etc/systemd/system/$s" ] && cp -a "/etc/systemd/system/$s" "$BACKUP_ROOT/"
done
say "backup  : $BACKUP_ROOT"

# 4. Copy and restart.
for f in "${changed[@]}"; do
  install -m 0755 "$REPO/$f" "$DEPLOY/$f"
  say "installed $f"
done

# Ship the CLI next to the deployment so operators find it without the repo.
for s in "${SCRIPTS[@]}"; do
  if [ -f "$REPO/scripts/$s" ]; then
    install -m 0755 "$REPO/scripts/$s" "$DEPLOY/scripts/$s" 2>/dev/null || {
      mkdir -p "$DEPLOY/scripts" && install -m 0755 "$REPO/scripts/$s" "$DEPLOY/scripts/$s"
    }
  fi
done
say "installed CLI wrappers into $DEPLOY/scripts"

say "restarting privacy-gateway.service"
systemctl restart privacy-gateway.service

# 5. Verify.
for i in $(seq 1 20); do
  if curl -sS --noproxy '*' --max-time 3 http://127.0.0.1:8317/privacy/health >/tmp/deploy-health.json 2>/dev/null; then
    break
  fi
  sleep 0.5
done

say "health:"
python3 - <<'PY' || fail "health check failed"
import json
d = json.load(open("/tmp/deploy-health.json"))
ex = d.get("exemptions") or {}
print(f"  status={d.get('status')} backend={d.get('backend_url')}")
print(f"  layer1 reachable={ (d.get('layer1') or {}).get('reachable') }")
print(f"  exemptions active={ex.get('active_count')} file={ex.get('file')}")
if "exemptions" not in d:
    raise SystemExit("health payload has no exemptions block — old code still running?")
PY

say "exemption API:"
curl -sS --noproxy '*' --max-time 3 http://127.0.0.1:8317/privacy/exemptions | python3 - <<'PY'
import json, sys
d = json.load(sys.stdin)
print(f"  ok={d.get('ok')} count={d.get('count')}")
if not d.get("ok"):
    raise SystemExit("exemption API not answering as expected")
PY

say "done. CLI: $REPO/scripts/privacy-exempt.sh list"
