#!/usr/bin/env bash
# Installs from THIS directory - for local development, or if you cloned the repo.
# To install the published version instead:
#   claude plugin marketplace add josewashingtonjr-crypto/my-error
#   claude plugin install my-error@my-error-local --scope user
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v claude >/dev/null 2>&1; then
  echo "ERROR: Claude Code CLI ('claude') was not found in PATH." >&2
  echo "Install/authenticate Claude Code first, then rerun this installer." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required by my-error hooks." >&2
  exit 1
fi

claude plugin validate "$ROOT" --strict
claude plugin marketplace add "$ROOT" --scope user
claude plugin install my-error@my-error-local --scope user

echo
echo "my-error installed for the current user (all projects)."
echo "Restart Claude Code, then run /my-error:doctor."
echo
echo "It starts in SHADOW mode: guards record what they would have blocked and"
echo "block nothing. See README.md before changing that."
