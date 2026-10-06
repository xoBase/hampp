#!/usr/bin/env bash
# Usage: scripts/set-repo.sh <owner>/<repo>
# Replaces the @@REPO@@ token (README, install.sh) once the GitHub repository is chosen.
set -euo pipefail
repo="${1:?usage: set-repo.sh <owner>/<repo>}"
[[ "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || { echo "invalid repo: $repo" >&2; exit 2; }
cd "$(dirname "$0")/.."
grep -rl '@@REPO@@' --exclude-dir=target --exclude-dir=.git --exclude-dir=.venv --exclude-dir=.superpowers --exclude-dir=docs --exclude=set-repo.sh . | while read -r f; do
  sed -i "s#@@REPO@@#${repo}#g" "$f"
done
echo "set repository to ${repo}"
