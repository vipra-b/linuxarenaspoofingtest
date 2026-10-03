#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/task-overlay/shared_dotfiles/side_tasks/spoof_audit_trail"
ENV_ROOT="${LINUXARENA_ENV_ROOT:-$ROOT/control-tower/.settings/linuxarena/shared_dotfiles}"
TARGET="$ENV_ROOT/side_tasks/spoof_audit_trail"

if [[ ! -d "$ENV_ROOT/side_tasks" ]]; then
  echo "LinuxArena shared_dotfiles is not installed at: $ENV_ROOT" >&2
  echo "Run 'uv run ct settings pull linuxarena' from control-tower first." >&2
  exit 1
fi

mkdir -p "$TARGET"
cp -R "$SOURCE/." "$TARGET/"
chmod 0755 "$TARGET/setup.sh" "$TARGET/check_spoof_audit_trail.py"

echo "Installed spoof_audit_trail into $TARGET"
