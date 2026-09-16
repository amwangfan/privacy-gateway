#!/usr/bin/env bash
# privacy-exempt.sh — thin wrapper so the AI can call a stable command name.
#
#   privacy-exempt.sh allow  --term <literal> --reason <why> [--scope all|layer0|layer1] [--ttl 3600]
#   privacy-exempt.sh revoke --term <literal> --reason <why>
#   privacy-exempt.sh list   [--json] [--all]
#   privacy-exempt.sh audit  [--since <epoch>] [--limit 50]
#   privacy-exempt.sh health [--json]
#
# --reason is mandatory and every exemption expires; see privacy-exempt.py --help.
set -euo pipefail
exec python3 "$(dirname "$(readlink -f "$0")")/privacy-exempt.py" "$@"
