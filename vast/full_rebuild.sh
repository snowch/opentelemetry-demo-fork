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

# --- 0. Download OTel Java agent for Trino JVM metrics ---
OTEL_AGENT_JAR="vast/opentelemetry-javaagent.jar"
if [ ! -s "$OTEL_AGENT_JAR" ]; then
  echo "--- Downloading OpenTelemetry Java agent ---"
  curl -sSL -o "$OTEL_AGENT_JAR" \
    "https://repo1.maven.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/2.12.0/opentelemetry-javaagent-2.12.0.jar"
  echo "  Downloaded $(du -h "$OTEL_AGENT_JAR" | cut -f1) to $OTEL_AGENT_JAR"
else
  echo "--- OTel Java agent already present ($(du -h "$OTEL_AGENT_JAR" | cut -f1)) ---"
fi
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
source .env.override 2>/dev/null || true
TRINO_HOST="${TRINO_HOST:-10.143.11.241}"
TRINO_PORT="${TRINO_PORT:-8443}"
TRINO_HTTP_SCHEME="${TRINO_HTTP_SCHEME:-https}"
echo ""
echo "--- Waiting for Trino at ${TRINO_HOST}:${TRINO_PORT} ---"
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
  if curl -sf -k -o /dev/null "${TRINO_HTTP_SCHEME}://${TRINO_HOST}:${TRINO_PORT}/v1/info" 2>/dev/null; then
    echo "  Trino is healthy (${ELAPSED}s)"
    break
  fi
  echo "  Trino not ready (${ELAPSED}s elapsed, waiting...)"
  sleep 5
  ELAPSED=$((ELAPSED + 5))
done
if [ $ELAPSED -ge $MAX_WAIT ]; then
  echo "  WARNING: Trino not reachable after ${MAX_WAIT}s, proceeding anyway..."
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
