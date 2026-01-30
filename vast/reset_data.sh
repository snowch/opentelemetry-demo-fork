#!/usr/bin/env bash
#
# Reset all OTEL data: drop/recreate VastDB tables and Kafka topics,
# then restart the ingester and collector.
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

TOPICS=("otel-logs" "otel-traces" "otel-metrics")
KAFKA_BIN="/opt/kafka/bin/kafka-topics.sh"

echo "=== Resetting OTEL Data ==="

# --- 0. Ensure observability-agent container is running ---
if ! docker compose ps --status running --format '{{.Service}}' | grep -q '^observability-agent$'; then
    echo "--- Starting observability-agent container ---"
    docker compose up -d observability-agent
    echo "Waiting for container to be ready..."
    sleep 5
fi

# --- 1. Drop and recreate VastDB tables via Trino ---
echo ""
echo "--- Dropping and recreating VastDB tables via Trino ---"
docker compose exec -T observability-agent python3 -u -c "
import trino, sys

import requests
import urllib3

# This line silences the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

conn = trino.dbapi.connect(
    host='${TRINO_HOST}', port=${TRINO_PORT},
    user='trino', catalog='vast', schema='\"csnow-db|otel\"',
    http_scheme='https', verify=False
)
cur = conn.cursor()

with open('/app/ddl.sql') as f:
    ddl = f.read()

for stmt in ddl.split(';'):
    stmt = stmt.strip()
    if not stmt or all(l.strip().startswith('--') or not l.strip() for l in stmt.split('\n')):
        continue
    lines = [l for l in stmt.split('\n') if l.strip() and not l.strip().startswith('--')]
    sql = '\n'.join(lines)
    try:
        cur.execute(sql)
        cur.fetchall()
        first_line = sql.split('\n')[0][:70]
        print(f'  OK: {first_line}...')
    except Exception as e:
        print(f'  ERROR: {e}', file=sys.stderr)

print('VastDB tables reset complete.')
"

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

# --- 3. Restart services ---
echo ""
echo "--- Restarting otel-collector and observability-ingester ---"
docker compose restart otel-collector observability-ingester

echo ""
echo "=== Reset complete. New data will start flowing shortly. ==="
