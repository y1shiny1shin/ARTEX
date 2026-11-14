#!/usr/bin/env bash
# Local P0 runner. Reads secrets from ignored ./tmp files; never commit them.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${ARTEX_BASE_URL:?set ARTEX_BASE_URL (e.g. http://host:22255)}"
: "${RYAGENT_OWNER_PASSWORD:=dev-password}"
TOKEN_FILE="${ARTEX_TOKEN_FILE:-$ROOT/tmp/artex-token}"
CREDS_FILE="${CREDS_FILE:-$ROOT/tmp/creds.txt}"
if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "missing ARTEX token file: $TOKEN_FILE" >&2
  echo "Generate a service JWT on the ARTEX host or set ARTEX_PASSWORD instead." >&2
  exit 1
fi
export RYAGENT_ADDR="${RYAGENT_ADDR:-:8788}"
export RYAGENT_DATA="${RYAGENT_DATA:-$ROOT/bff/data}"
export RYAGENT_OWNER_PASSWORD
export ARTEX_BASE_URL
export ARTEX_TOKEN="${ARTEX_TOKEN:-$(cat "$TOKEN_FILE")}"
export ARTEX_USERNAME="${ARTEX_USERNAME:-ARTEX}"
export ARTEX_PASSWORD="${ARTEX_PASSWORD:-}"
if [[ -z "${HTTP_PROXY:-}" && -s "$CREDS_FILE" ]]; then
  PROXY="$(grep -m1 '^squid_proxy' "$CREDS_FILE" | cut -d= -f2- || true)"
  if [[ -n "$PROXY" ]]; then
    export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
  fi
fi
cd "$ROOT/bff"
exec ./bin/ryagent-bff
