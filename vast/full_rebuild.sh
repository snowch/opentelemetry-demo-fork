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

# --- 2. Rebuild images ---
echo ""
if $vast_only; then
  echo "--- Building vast services (--no-cache) ---"
  docker compose build --no-cache "${VAST_SERVICES[@]}"
else
  echo "--- Building all images (--no-cache) ---"
  docker compose build --no-cache
fi

# --- 3. Bring everything up ---
echo ""
echo "--- Starting all services ---"
docker compose up -d

# --- 4. Wait for Trino to be healthy, then reset data ---
echo ""
echo "--- Waiting for Trino to be healthy ---"
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' trino 2>/dev/null || echo "missing")
  if [ "$STATUS" = "healthy" ]; then
    echo "  Trino is healthy (${ELAPSED}s)"
    break
  fi
  echo "  Trino status: ${STATUS} (${ELAPSED}s elapsed, waiting...)"
  sleep 5
  ELAPSED=$((ELAPSED + 5))
done
if [ "$STATUS" != "healthy" ]; then
  echo "  WARNING: Trino not healthy after ${MAX_WAIT}s, proceeding anyway..."
fi

echo ""
echo "--- Running data reset ---"
./vast/reset_data.sh

# --- 5. Restart services that started before tables were ready ---
echo ""
echo "--- Restarting observability services ---"
docker compose restart "${VAST_SERVICES[@]}"

echo ""
echo "=== Full rebuild complete. Services are starting up. ==="
echo "    Run 'docker compose logs -f' to follow logs."
