#!/usr/bin/env bash
#
# Reset all OTEL data: drop/recreate VastDB tables and Kafka topics,
# then restart the ingester and collector.
#
# Uses ephemeral containers so no running services are required.
#
# Usage: ./vast/reset_data.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."


# Load config from .env.override
source .env.override 2>/dev/null || true
KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-172.200.204.97:9092}"
TRINO_HOST="${TRINO_HOST:-10.143.11.241}"
TRINO_PORT="${TRINO_PORT:-8443}"
TRINO_HTTP_SCHEME="${TRINO_HTTP_SCHEME:-https}"
TRINO_CATALOG="${TRINO_CATALOG:-vast}"
TRINO_SCHEMA="${TRINO_SCHEMA:-csnow-db|otel}"

TOPICS=("otel-logs" "otel-traces" "otel-metrics")
KAFKA_BIN="/opt/kafka/bin/kafka-topics.sh"

echo "=== Resetting OTEL Data ==="

# --- 1. Drop and recreate VastDB tables via ephemeral container ---
echo ""
echo "--- Dropping and recreating VastDB tables via Trino ---"

# Determine docker network — use compose network if it exists, otherwise host networking
DOCKER_NET_ARGS=()
if docker network inspect opentelemetry-demo >/dev/null 2>&1; then
    DOCKER_NET_ARGS=(--network opentelemetry-demo)
fi

# Wait for Trino to accept connections before running DDL
echo "  Waiting for Trino at ${TRINO_HOST}:${TRINO_PORT} ..."
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    if docker run --rm "${DOCKER_NET_ARGS[@]}" python:3.12-slim \
        python3 -c "
import urllib.request, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = urllib.request.urlopen('${TRINO_HTTP_SCHEME}://${TRINO_HOST}:${TRINO_PORT}/v1/info', timeout=5, context=ctx)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        echo "  Trino is accepting connections (${ELAPSED}s)"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "  ... not ready yet (${ELAPSED}s elapsed)"
done
if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "  WARNING: Trino not reachable after ${MAX_WAIT}s, attempting DDL anyway..."
fi

docker run --rm \
    "${DOCKER_NET_ARGS[@]}" \
    -e TRINO_HOST="${TRINO_HOST}" \
    -e TRINO_PORT="${TRINO_PORT}" \
    -e TRINO_HTTP_SCHEME="${TRINO_HTTP_SCHEME}" \
    -e TRINO_CATALOG="${TRINO_CATALOG}" \
    -e TRINO_SCHEMA="${TRINO_SCHEMA}" \
    -v "$(pwd)/vast/ddl.sql:/ddl.sql:ro" \
    -v "$(pwd)/vast/run_ddl.py:/run_ddl.py:ro" \
    python:3.12-slim \
    bash -c "pip install -q 'trino>=0.330.0' && python3 -u /run_ddl.py"

# --- 2. Delete and recreate Kafka topics (via ephemeral container) ---
KAFKA_IMAGE="apache/kafka:3.7.0"
echo ""
echo "--- Deleting Kafka topics ---"
for topic in "${TOPICS[@]}"; do
    echo -n "  Deleting ${topic}... "
    docker run --rm "${KAFKA_IMAGE}" ${KAFKA_BIN} --bootstrap-server "${KAFKA_BOOTSTRAP}" \
        --delete --topic "${topic}" 2>/dev/null && echo "OK" || echo "SKIP (not found)"
done

echo ""
echo "--- Creating Kafka topics ---"
for topic in "${TOPICS[@]}"; do
    echo -n "  Creating ${topic}... "
    docker run --rm "${KAFKA_IMAGE}" ${KAFKA_BIN} --bootstrap-server "${KAFKA_BOOTSTRAP}" \
        --create --topic "${topic}" --partitions 1 --replication-factor 1 2>/dev/null && echo "OK" || echo "FAILED"
done

# --- 3. Restart services (if running) ---
if docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -q .; then
    echo ""
    echo "--- Restarting otel-collector and observability-ingester ---"
    docker compose restart otel-collector observability-ingester 2>/dev/null || true
fi

echo ""
echo "=== Reset complete. New data will start flowing shortly. ==="
