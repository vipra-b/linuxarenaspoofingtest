#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "$ROOT" submodule update --init control-tower

(
  cd "$ROOT/control-tower"
  uv sync
  uv run ct settings pull linuxarena
)

"$ROOT/scripts/install_task.sh"

cat <<EOF

Bootstrap complete.

1. Configure a model provider in:
   $ROOT/control-tower/.env
2. Ensure Docker Desktop is running.
3. Run the honest baseline or attack evaluation from RUNBOOK.md.
EOF
