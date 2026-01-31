#!/usr/bin/env bash
#
# Full rebuild: tear down everything, reset data, rebuild images,
# and bring the stack back up.
#
# Usage:
#   ./vast/full_rebuild.sh          # rebuild everything (--no-cache)
#   ./vast/full_rebuild.sh --vast   # only --no-cache the vast services
#
set -euo pipefail
cd "$(dirname "$0")/.."

VAST_SERVICES=(
  observability-agent
  observability-ingester
  observability-aggregator
  observability-topology
  observability-predictive
)

vast_only=false
if [[ "${1:-}" == "--vast" ]]; then
  vast_only=true
fi

echo "=== Full Rebuild ==="
echo ""

# --- 1. Tear down all containers and volumes ---
echo "--- Stopping containers and removing volumes ---"
docker compose down -v

# --- 2. Reset VastDB tables and Kafka topics (ephemeral containers, no services needed) ---
echo ""
echo "--- Running data reset ---"
./vast/reset_data.sh

# --- 3. Rebuild images ---
echo ""
if $vast_only; then
  echo "--- Building vast services (--no-cache) ---"
  docker compose build --no-cache "${VAST_SERVICES[@]}"
else
  echo "--- Building all images (--no-cache) ---"
  docker compose build --no-cache
fi

# --- 4. Bring everything up ---
echo ""
echo "--- Starting all services ---"
docker compose up -d

echo ""
echo "=== Full rebuild complete. Services are starting up. ==="
echo "    Run 'docker compose logs -f' to follow logs."
