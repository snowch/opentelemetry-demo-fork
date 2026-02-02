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

TOPICS=("otel-logs" "otel-traces" "otel-metrics")
KAFKA_BIN="/opt/kafka/bin/kafka-topics.sh"

echo "=== Resetting OTEL Data ==="

# --- 1. Drop and recreate VastDB tables via ephemeral container ---
echo ""
echo "--- Dropping and recreating VastDB tables via Trino ---"
docker run --rm \
    -e TRINO_HOST="${TRINO_HOST}" \
    -e TRINO_PORT="${TRINO_PORT}" \
    -e TRINO_HTTP_SCHEME="${TRINO_HTTP_SCHEME}" \
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
